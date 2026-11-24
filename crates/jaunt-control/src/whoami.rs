use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_proto::WhoamiResponse;
use jaunt_store::ValidApiToken;

use crate::control::Control;
use crate::http::{empty_response, json_response, server_error};
use crate::token;

fn unauthorized() -> Response {
    let mut response = empty_response(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok()?,
        _ => return None,
    };
    let (scheme, presented) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("Bearer").then_some(presented)
}

pub(crate) enum AuthFailure {
    Rejected,
    Unavailable,
}

impl AuthFailure {
    pub(crate) fn into_response(self) -> Response {
        match self {
            AuthFailure::Rejected => unauthorized(),
            AuthFailure::Unavailable => server_error(),
        }
    }
}

pub(crate) async fn authenticate(
    control: &Control,
    headers: &HeaderMap,
) -> Result<ValidApiToken, AuthFailure> {
    let Some(token_hash) = bearer_token(headers).and_then(token::hash_presented) else {
        return Err(AuthFailure::Rejected);
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(AuthFailure::Unavailable);
    };
    match control
        .store
        .api_tokens()
        .find_valid(&token_hash, now.secs)
        .await
    {
        Ok(Some(valid)) => Ok(valid),
        Ok(None) => Err(AuthFailure::Rejected),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the api token failed");
            Err(AuthFailure::Unavailable)
        }
    }
}

pub(crate) async fn handle(State(control): State<Control>, headers: HeaderMap) -> Response {
    match authenticate(&control, &headers).await {
        Ok(valid) => json_response(
            StatusCode::OK,
            &WhoamiResponse {
                user_id: valid.user.id,
                email: valid.user.email,
                groups: valid.user.groups,
                cert_serial: valid.token.cert_serial,
                token_expires_at: valid.token.expires_at,
            },
        ),
        Err(failure) => failure.into_response(),
    }
}
