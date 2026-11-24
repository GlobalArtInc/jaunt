use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_store::LoginRequest;

use crate::audit;
use crate::clock::whole_secs;
use crate::control::Control;

use super::forms::{Form, FormFailure};
use super::limiter::Verdict;
use super::net::ClientAddress;
use super::page::{self, RequestFacts};
use super::tokens::IssueError;
use super::{code, net};

pub(super) async fn show() -> Response {
    page::entry(false)
}

pub(super) fn form_failure(failure: FormFailure) -> Response {
    match failure {
        FormFailure::TooLarge => page::invalid_request(StatusCode::PAYLOAD_TOO_LARGE),
        FormFailure::Malformed => page::invalid_request(StatusCode::BAD_REQUEST),
    }
}

pub(super) async fn submit(
    State(control): State<Control>,
    Extension(ClientAddress(ip)): Extension<ClientAddress>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    if !net::origin_allowed(&headers, &control.device.origin) {
        return page::forbidden();
    }
    let form = match Form::parse(&headers, body) {
        Ok(form) => form,
        Err(failure) => return form_failure(failure),
    };
    let Some(typed) = form.get("user_code") else {
        return page::invalid_request(StatusCode::BAD_REQUEST);
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return page::server_error();
    };

    if let Verdict::Limited {
        retry_after_secs,
        newly_locked,
    } = control
        .device
        .failures
        .admit(ip, whole_secs(control.tick()))
    {
        if newly_locked {
            audit::device_locked_out(ip);
        }
        return page::too_many_attempts(retry_after_secs);
    }

    let Some(normalized) = code::normalize(typed) else {
        audit::device_code_failed(ip);
        return page::entry(true);
    };
    let found = control
        .store
        .login_requests()
        .find_pending_device(&code::hash(&normalized), now.secs)
        .await;
    match found {
        Ok(Some(request)) => {
            control.device.failures.refund(ip);
            confirm(&control, &request, &normalized, now.secs)
        }
        Ok(None) => {
            audit::device_code_failed(ip);
            page::entry(true)
        }
        Err(err) => {
            control.device.failures.refund(ip);
            tracing::error!(target: "jaunt::control", error = %err, "looking up the device code failed");
            page::server_error()
        }
    }
}

fn confirm(control: &Control, request: &LoginRequest, normalized: &str, now: i64) -> Response {
    let issued = control
        .device
        .continue_tokens
        .issue(&request.id, (), request.expires_at, now);
    match issued {
        Ok(token) => page::confirmation(
            &RequestFacts {
                label: request.client_label.as_deref(),
                ip: request.requester_ip.as_deref().unwrap_or("unknown"),
                requested_at: request.created_at,
            },
            &code::display(normalized),
            &request.id,
            &token,
        ),
        Err(IssueError::Full) => page::busy(),
        Err(IssueError::Entropy) => {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            page::server_error()
        }
    }
}
