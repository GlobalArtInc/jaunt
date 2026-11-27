use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::{CaError, fingerprint_hex};
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_proto::{ServiceCertificateRequest, ServiceCertificateResponse};
use jaunt_store::{NewServiceCertificate, Service, ServiceKind, ServiceState};

use crate::agent::{AuthenticatedNode, Refusal, active_node};
use crate::cert_audit::{self, ServiceIssued};
use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::limits::too_many_requests;
use crate::node_keys::{self, TlsKey};
use crate::revocation::is_identifier;
use crate::server_cert::{self, ServerIssueError};

pub(crate) const ISSUANCE_PER_NODE: Rate = Rate::clamped(64, 6);
const NODES_TRACKED: usize = 10_000;

pub(crate) fn issuance_limiter() -> RateLimiter<String> {
    RateLimiter::new(ISSUANCE_PER_NODE, NODES_TRACKED)
}

pub(crate) const fn kind_label(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Kubernetes => "kube",
        ServiceKind::Postgres => "db",
        ServiceKind::Tcp => "tcp",
    }
}

pub(crate) fn dns_name(service: &Service, domain: &str) -> String {
    format!("{}.{}.{domain}", service.name, kind_label(service.kind))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    InvalidPublicKey,
    NodeRemoved,
    NotConfigured,
    InvalidServiceId,
    UnknownService,
    OtherNode,
    NotApproved,
    NotAnnounced,
    Changed,
}

impl Refused {
    const fn reason(self) -> &'static str {
        match self {
            Refused::InvalidPublicKey => "invalid_public_key",
            Refused::NodeRemoved => "node_removed",
            Refused::NotConfigured => "not_configured",
            Refused::InvalidServiceId => "invalid_service_id",
            Refused::UnknownService => "unknown_service",
            Refused::OtherNode => "other_node",
            Refused::NotApproved => "not_approved",
            Refused::NotAnnounced => "not_announced",
            Refused::Changed => "service_changed",
        }
    }

    fn response(self) -> Response {
        match self {
            Refused::InvalidPublicKey => {
                error_response(StatusCode::BAD_REQUEST, "invalid_public_key")
            }
            Refused::NodeRemoved => error_response(StatusCode::FORBIDDEN, "node_removed"),
            Refused::NotConfigured => error_response(StatusCode::NOT_FOUND, "not_configured"),
            Refused::InvalidServiceId
            | Refused::UnknownService
            | Refused::OtherNode
            | Refused::NotApproved
            | Refused::NotAnnounced
            | Refused::Changed => error_response(StatusCode::NOT_FOUND, "unknown_service"),
        }
    }
}

fn refuse(node_id: &str, service_id: Option<&str>, refused: Refused) -> Response {
    cert_audit::service_refused(node_id, service_id, refused.reason());
    refused.response()
}

fn issuable(node_id: &str, service: &Service) -> Result<(), Refused> {
    if service.node_id != node_id {
        return Err(Refused::OtherNode);
    }
    if service.state != ServiceState::Approved {
        return Err(Refused::NotApproved);
    }
    if !service.announced {
        return Err(Refused::NotAnnounced);
    }
    Ok(())
}

pub(crate) async fn handle(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Decision::Limited { retry_after } =
        control.service_issuance.check(&node_id, control.tick())
    {
        return too_many_requests(retry_after);
    }
    let request = match json_body::<ServiceCertificateRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if !is_identifier(&request.service_id) {
        return refuse(&node_id, None, Refused::InvalidServiceId);
    }
    let service_id = request.service_id.as_str();
    let Some(key) = node_keys::parse_tls(&request.public_key) else {
        return refuse(&node_id, Some(service_id), Refused::InvalidPublicKey);
    };
    match active_node(&control, &node_id).await {
        Ok(_) => {}
        Err(Refusal::NodeRemoved) => {
            return refuse(&node_id, Some(service_id), Refused::NodeRemoved);
        }
        Err(Refusal::StoreFailed) => return server_error(),
    }
    let Some(domain) = control.services_domain.clone() else {
        return refuse(&node_id, Some(service_id), Refused::NotConfigured);
    };
    let service = match control.store.services().get(service_id).await {
        Ok(Some(service)) => service,
        Ok(None) => return refuse(&node_id, Some(service_id), Refused::UnknownService),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the service failed");
            return server_error();
        }
    };
    if let Err(refused) = issuable(&node_id, &service) {
        return refuse(&node_id, Some(service_id), refused);
    }
    let task =
        tokio::spawn(
            async move { issue(&control, &node_id, &service, &key, domain.as_str()).await },
        );
    task.await.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the service certificate task did not finish");
        server_error()
    })
}

async fn issue(
    control: &Control,
    node_id: &str,
    service: &Service,
    key: &TlsKey,
    domain: &str,
) -> Response {
    let dns_name = dns_name(service, domain);
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let issued = match server_cert::issue(control, &key.subject, &dns_name, now).await {
        Ok(issued) => issued,
        Err(ServerIssueError::Signing(CaError::InvalidSubjectKey)) => {
            return refuse(node_id, Some(&service.id), Refused::InvalidPublicKey);
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "issuing the service certificate failed");
            return server_error();
        }
    };
    let recorded = control
        .store
        .service_certificates()
        .record(&NewServiceCertificate {
            serial: issued.serial,
            node_id: node_id.to_owned(),
            service_id: service.id.clone(),
            kind: service.kind,
            name: service.name.clone(),
            domain: domain.to_owned(),
            signed_dns_name: dns_name.clone(),
            valid_after: issued.valid_after,
            valid_before: issued.valid_before,
            issued_at: now.secs,
            root_sha256: control.internal_ca.root_sha256_hex(),
            subject_fingerprint: fingerprint_hex(&key.subject.to_ssh_key()),
        })
        .await;
    match recorded {
        Ok(true) => {}
        Ok(false) => return refuse(node_id, Some(&service.id), Refused::Changed),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "recording the service certificate failed");
            return server_error();
        }
    }
    cert_audit::service_issued(&ServiceIssued {
        node_id,
        service_id: &service.id,
        kind: service.kind.as_str(),
        name: &service.name,
        serial: issued.serial,
        valid_before: issued.valid_before,
    });
    json_response(
        StatusCode::OK,
        &ServiceCertificateResponse {
            certificate_der: STANDARD.encode(&issued.certificate_der),
            serial: issued.serial,
            dns_name,
            valid_after: issued.valid_after,
            valid_before: issued.valid_before,
        },
    )
}

#[cfg(test)]
mod tests {
    use jaunt_store::ServiceKind;

    use super::{ISSUANCE_PER_NODE, kind_label};

    #[test]
    fn each_service_kind_has_its_own_name_label() {
        assert_eq!(kind_label(ServiceKind::Kubernetes), "kube");
        assert_eq!(kind_label(ServiceKind::Postgres), "db");
        assert_eq!(kind_label(ServiceKind::Tcp), "tcp");
    }

    #[test]
    fn the_node_burst_covers_every_service_an_agent_may_declare() {
        assert_eq!(
            usize::try_from(ISSUANCE_PER_NODE.burst()).unwrap(),
            jaunt_proto::MAX_SERVICES_PER_AGENT
        );
        assert_eq!(ISSUANCE_PER_NODE.per_minute(), 6);
    }
}
