use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_proto::WhoamiResponse;

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

pub(crate) async fn handle(State(control): State<Control>, headers: HeaderMap) -> Response {
    let Some(token_hash) = bearer_token(&headers).and_then(token::hash_presented) else {
        return unauthorized();
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    match control
        .store
        .api_tokens()
        .find_valid(&token_hash, now.secs)
        .await
    {
        Ok(Some(valid)) => json_response(
            StatusCode::OK,
            &WhoamiResponse {
                user_id: valid.user.id,
                email: valid.user.email,
                groups: valid.user.groups,
                cert_serial: valid.token.cert_serial,
                token_expires_at: valid.token.expires_at,
            },
        ),
        Ok(None) => unauthorized(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the api token failed");
            server_error()
        }
    }
}
