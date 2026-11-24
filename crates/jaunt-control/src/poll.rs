use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_limits::Decision;
use jaunt_proto::{EnrollmentApproved, NodeCertificates, PollRequest, PollResponse};
use jaunt_store::{Enrollment, EnrollmentState};

use crate::clock::Moment;
use crate::control::Control;
use crate::enroll_secrets;
use crate::http::{error_response, json_body, json_response, server_error};
use crate::issuance::{self, Bundle};
use crate::limits;
use crate::node_audit::{self, Delivered};
use crate::node_keys;

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found")
}

fn state_response(response: PollResponse) -> Response {
    json_response(StatusCode::OK, &response)
}

enum Delivery {
    Delivered(Box<PollResponse>),
    NodeGone,
}

#[derive(Debug, thiserror::Error)]
enum DeliveryError {
    #[error("the enrollment names no node")]
    NoNode,
    #[error("the stored node keys are not valid")]
    StoredKeys,
    #[error("the database failed: {0}")]
    Store(#[source] jaunt_store::StoreError),
    #[error("issuing the certificates failed: {0}")]
    Issue(#[source] issuance::IssueError),
    #[error(
        "the enrollment left the delivering state or its node was removed before the certificates were recorded"
    )]
    LostClaim,
}

pub(crate) async fn handle(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request = match json_body::<PollRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let Some(handle_hash) = enroll_secrets::hash_handle(&request.handle) else {
        return not_found();
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let enrollment = match control
        .store
        .enrollments()
        .get_by_handle_hash(&handle_hash)
        .await
    {
        Ok(Some(enrollment)) => enrollment,
        Ok(None) => return not_found(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the enrollment failed");
            return server_error();
        }
    };
    if let Decision::Limited { retry_after } =
        control.poll_limiter.check(&handle_hash, control.tick())
    {
        return limits::too_many_requests(retry_after);
    }

    let expired = enrollment.expires_at <= now.secs;
    match enrollment.state {
        EnrollmentState::Pending | EnrollmentState::Approved | EnrollmentState::Delivering
            if expired =>
        {
            report_expiry(&control, &enrollment, now).await;
            state_response(PollResponse::Expired)
        }
        EnrollmentState::Pending | EnrollmentState::Delivering => {
            state_response(PollResponse::Pending)
        }
        EnrollmentState::Rejected => state_response(PollResponse::Rejected),
        EnrollmentState::Delivered => state_response(PollResponse::AlreadyDelivered),
        EnrollmentState::Approved => deliver(&control, &enrollment.id, now).await,
    }
}

async fn report_expiry(control: &Control, enrollment: &Enrollment, now: Moment) {
    if enrollment.expired_reported_at.is_some() {
        return;
    }
    match control
        .store
        .enrollments()
        .mark_expiry_reported(&enrollment.id, now.secs)
        .await
    {
        Ok(true) => node_audit::enroll_expired(&enrollment.id, &enrollment.name),
        Ok(false) => {}
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "recording the reported expiry failed");
            node_audit::enroll_expired(&enrollment.id, &enrollment.name);
        }
    }
}

enum Outcome {
    Delivered(Box<PollResponse>),
    Rejected,
    Busy,
    Failed,
}

async fn deliver(control: &Control, enrollment_id: &str, now: Moment) -> Response {
    let task_control = control.clone();
    let task_id = enrollment_id.to_owned();
    let task = tokio::spawn(async move { run_delivery(&task_control, &task_id, now).await });
    match task.await {
        Ok(Outcome::Delivered(response)) => state_response(*response),
        Ok(Outcome::Rejected) => state_response(PollResponse::Rejected),
        Ok(Outcome::Busy) => state_response(PollResponse::Pending),
        Ok(Outcome::Failed) => server_error(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "the delivery task ended abnormally");
            server_error()
        }
    }
}

async fn run_delivery(control: &Control, enrollment_id: &str, now: Moment) -> Outcome {
    let enrollments = control.store.enrollments();
    let started = match enrollments.begin_delivery(enrollment_id, now.secs).await {
        Ok(Some(started)) => started,
        Ok(None) => return Outcome::Busy,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "claiming the delivery failed");
            return Outcome::Failed;
        }
    };
    match issue_and_record(control, &started, now).await {
        Ok(Delivery::Delivered(response)) => Outcome::Delivered(response),
        Ok(Delivery::NodeGone) => {
            if let Err(err) = enrollments.reject_delivery(&started.id).await {
                tracing::error!(target: "jaunt::control", error = %err, "rejecting the delivery of a removed node failed");
                return Outcome::Failed;
            }
            Outcome::Rejected
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "delivering the certificates failed");
            if let Err(release) = enrollments.release_delivery(&started.id).await {
                tracing::error!(target: "jaunt::control", error = %release, "returning the enrollment to approved failed");
            }
            Outcome::Failed
        }
    }
}

async fn issue_and_record(
    control: &Control,
    started: &Enrollment,
    now: Moment,
) -> Result<Delivery, DeliveryError> {
    let node_id = started.node_id.as_deref().ok_or(DeliveryError::NoNode)?;
    let node = control
        .store
        .nodes()
        .get_active(node_id)
        .await
        .map_err(DeliveryError::Store)?;
    let Some(node) = node else {
        return Ok(Delivery::NodeGone);
    };
    let tls = node_keys::parse_tls(&node.tls_public_key).ok_or(DeliveryError::StoredKeys)?;
    let ssh = node_keys::parse_ssh(&node.ssh_host_public_key).ok_or(DeliveryError::StoredKeys)?;
    let bundle = issuance::issue(control, &node.id, &node.name, &tls, &ssh, now)
        .await
        .map_err(DeliveryError::Issue)?;
    let recorded = control
        .store
        .enrollments()
        .complete_delivery(&started.id, &node.id, &bundle.records(now.secs))
        .await
        .map_err(DeliveryError::Store)?;
    if !recorded {
        return Err(DeliveryError::LostClaim);
    }
    node_audit::enroll_delivered(&Delivered {
        enrollment_id: &started.id,
        node_id: &node.id,
        name: &node.name,
        x509_serial: &bundle.x509_serial,
        ssh_serial: &bundle.ssh_serial,
    });
    Ok(Delivery::Delivered(Box::new(PollResponse::Approved(
        EnrollmentApproved {
            node_id: node.id,
            certificates: certificates_of(&bundle),
            internal_ca_root_der: STANDARD.encode(control.internal_ca.root_der()),
            agent_endpoint: control.agent_endpoint.as_str().to_owned(),
        },
    ))))
}

pub(crate) fn certificates_of(bundle: &Bundle) -> NodeCertificates {
    NodeCertificates {
        x509_certificate_der: STANDARD.encode(&bundle.x509_der),
        x509_not_after: bundle.x509_not_after,
        ssh_host_certificate: bundle.ssh_line.clone(),
        ssh_not_after: bundle.ssh_not_after,
    }
}
