use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use jaunt_store::LoginRequestState;

use crate::audit;
use crate::control::Control;
use crate::pending::{InsertError, PendingKind, PendingLogin};

use super::browser;
use super::forms::Form;
use super::verify::form_failure;
use super::{DEVICE_KIND, net, page};

pub(super) async fn handle(
    State(control): State<Control>,
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
    let Some(flow) = form.flow() else {
        return page::invalid_request(StatusCode::BAD_REQUEST);
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return page::server_error();
    };

    let redeemed = control
        .device
        .continue_tokens
        .redeem(&flow.login_id, &flow.token, now.secs);
    if redeemed.is_none() {
        return page::invalid_request(StatusCode::BAD_REQUEST);
    }

    let request = match control.store.login_requests().get(&flow.login_id).await {
        Ok(Some(request)) => request,
        Ok(None) => return page::invalid_request(StatusCode::BAD_REQUEST),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the device request failed");
            return page::server_error();
        }
    };
    if request.kind != DEVICE_KIND || request.state != LoginRequestState::Pending {
        return page::invalid_request(StatusCode::BAD_REQUEST);
    }

    let Some(binding) = browser::issue() else {
        tracing::error!(target: "jaunt::control", "the browser binding could not be issued");
        return page::server_error();
    };
    let auth = control.oidc.begin();
    let authorize_url = auth.authorize_url.clone();
    let state = auth.state.clone();
    let Some(mut response) = page::continue_page(&authorize_url) else {
        tracing::error!(target: "jaunt::control", "the provider authorize url cannot be shown safely");
        return page::server_error();
    };
    let entry = PendingLogin {
        auth,
        login_id: request.id.clone(),
        kind: PendingKind::Device {
            browser_hash: binding.hash,
        },
        expires_at: request.expires_at,
    };
    match control.pending.insert(state, entry, now.secs) {
        Ok(()) => {}
        Err(InsertError::Full) => return page::busy(),
        Err(InsertError::Duplicate) => {
            tracing::error!(target: "jaunt::control", "the provider state collided with a pending login");
            return page::server_error();
        }
    }

    audit::device_continued(&request.id);
    response
        .headers_mut()
        .append(header::SET_COOKIE, binding.set_cookie);
    response
}
