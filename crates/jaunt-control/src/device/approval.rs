use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_store::{LoginRequest, User};

use crate::audit::{self, DenyReason};
use crate::control::Control;

use super::browser;
use super::forms::{Form, FormFailure};
use super::page::{self, RequestFacts};
use super::tokens::IssueError;
use super::verify::form_failure;
use super::{DEVICE_KIND, net};

pub(crate) struct Approval {
    user_id: String,
    email: String,
}

enum Refusal {
    Forbidden,
    Form(FormFailure),
    Invalid,
    Internal,
}

impl Refusal {
    fn into_response(self) -> Response {
        match self {
            Refusal::Forbidden => page::forbidden(),
            Refusal::Form(failure) => form_failure(failure),
            Refusal::Invalid => page::invalid_request(StatusCode::BAD_REQUEST),
            Refusal::Internal => page::server_error(),
        }
    }
}

struct Redeemed {
    login_id: String,
    approval: Approval,
    now: i64,
}

pub(crate) fn offer(control: &Control, request: &LoginRequest, user: &User, now: i64) -> Response {
    let approval = Approval {
        user_id: user.id.clone(),
        email: user.email.clone(),
    };
    let issued = control
        .device
        .approvals
        .issue(&request.id, approval, request.expires_at, now);
    match issued {
        Ok(token) => {
            let mut response = page::approval(
                &RequestFacts {
                    label: request.client_label.as_deref(),
                    ip: request.requester_ip.as_deref().unwrap_or("unknown"),
                    requested_at: request.created_at,
                },
                &user.email,
                &request.id,
                &token,
            );
            browser::clear(&mut response);
            response
        }
        Err(IssueError::Full) => {
            audit::login_denied(Some(&request.id), DenyReason::Internal);
            page::busy()
        }
        Err(IssueError::Entropy) => {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            audit::login_denied(Some(&request.id), DenyReason::Internal);
            page::server_error()
        }
    }
}

fn redeem(
    control: &Control,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<Redeemed, Refusal> {
    if !net::origin_allowed(headers, &control.device.origin) {
        return Err(Refusal::Forbidden);
    }
    let form = Form::parse(headers, body).map_err(Refusal::Form)?;
    let Some(flow) = form.flow() else {
        return Err(Refusal::Invalid);
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(Refusal::Internal);
    };
    match control
        .device
        .approvals
        .redeem(&flow.login_id, &flow.token, now.secs)
    {
        Some(approval) => Ok(Redeemed {
            login_id: flow.login_id,
            approval,
            now: now.secs,
        }),
        None => {
            audit::login_denied(Some(&flow.login_id), DenyReason::ApprovalRejected);
            Err(Refusal::Invalid)
        }
    }
}

pub(super) async fn approve(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let redeemed = match redeem(&control, &headers, body) {
        Ok(redeemed) => redeemed,
        Err(refusal) => return refusal.into_response(),
    };
    let Redeemed {
        login_id,
        approval,
        now,
    } = redeemed;
    let outcome = control
        .store
        .login_requests()
        .approve(&login_id, &approval.user_id, None, now)
        .await;
    match outcome {
        Ok(true) => {
            audit::login_approved(&login_id, &approval.user_id, &approval.email, DEVICE_KIND);
            let mut response = page::approved();
            browser::clear(&mut response);
            response
        }
        Ok(false) => {
            audit::login_denied(Some(&login_id), DenyReason::RequestNotPending);
            page::invalid_request(StatusCode::BAD_REQUEST)
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "approving the device request failed");
            page::server_error()
        }
    }
}

pub(super) async fn deny(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let redeemed = match redeem(&control, &headers, body) {
        Ok(redeemed) => redeemed,
        Err(refusal) => return refusal.into_response(),
    };
    let outcome = control
        .store
        .login_requests()
        .deny(&redeemed.login_id, redeemed.now)
        .await;
    match outcome {
        Ok(true) => {
            audit::login_denied(Some(&redeemed.login_id), DenyReason::UserDenied);
            let mut response = page::denied();
            browser::clear(&mut response);
            response
        }
        Ok(false) => {
            audit::login_denied(Some(&redeemed.login_id), DenyReason::RequestNotPending);
            page::invalid_request(StatusCode::BAD_REQUEST)
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "denying the device request failed");
            page::server_error()
        }
    }
}
