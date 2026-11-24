use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::{StartRequest, StartResponse};
use jaunt_store::NewLoginRequest;

use crate::audit;
use crate::control::Control;
use crate::http::{error_response, json_body, json_response, server_error};
use crate::pending::{InsertError, PendingLogin};
use crate::pkce;

pub(crate) const LOGIN_KIND: &str = "loopback";
pub(crate) const LOGIN_TTL_SECS: i64 = 300;

const CHALLENGE_METHOD: &str = "S256";
const MIN_PORT: u32 = 1024;
const MAX_PORT: u32 = 65535;
const MAX_LABEL_LEN: usize = 64;

struct ValidStart {
    challenge: String,
    port: u16,
    label: Option<String>,
}

fn validate(request: StartRequest) -> Option<ValidStart> {
    if request.code_challenge_method != CHALLENGE_METHOD
        || !pkce::is_valid_challenge(&request.code_challenge)
        || !(MIN_PORT..=MAX_PORT).contains(&request.redirect_port)
    {
        return None;
    }
    if let Some(label) = &request.client_label
        && !is_valid_label(label)
    {
        return None;
    }
    Some(ValidStart {
        challenge: request.code_challenge,
        port: u16::try_from(request.redirect_port).ok()?,
        label: request.client_label,
    })
}

fn is_valid_label(label: &str) -> bool {
    (1..=MAX_LABEL_LEN).contains(&label.len())
        && label.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

fn busy() -> Response {
    error_response(StatusCode::SERVICE_UNAVAILABLE, "busy")
}

pub(crate) async fn handle(
    State(control): State<Control>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let request = match json_body::<StartRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    let Some(valid) = validate(request) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    if !control.pending.has_room(now.secs) {
        return busy();
    }

    let auth = control.oidc.begin();
    let authorize_url = auth.authorize_url.clone();
    let state = auth.state.clone();
    let created = control
        .store
        .login_requests()
        .create(
            &NewLoginRequest {
                kind: LOGIN_KIND.to_owned(),
                pkce_challenge: valid.challenge,
                client_label: valid.label,
                ttl_secs: LOGIN_TTL_SECS,
            },
            now.secs,
        )
        .await;
    let request = match created {
        Ok(request) => request,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "creating the login request failed");
            return server_error();
        }
    };

    let entry = PendingLogin {
        auth,
        login_id: request.id.clone(),
        redirect_port: valid.port,
        expires_at: request.expires_at,
    };
    match control.pending.insert(state, entry, now.secs) {
        Ok(()) => {}
        Err(InsertError::Full) => return busy(),
        Err(InsertError::Duplicate) => {
            tracing::error!(target: "jaunt::control", "the provider state collided with a pending login");
            return server_error();
        }
    }

    audit::login_started(&request.id);
    json_response(
        StatusCode::OK,
        &StartResponse {
            login_id: request.id,
            authorize_url,
        },
    )
}
