use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use jaunt_proto::ErrorBody;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::control::Control;
use crate::{callback, device, enroll, finish, poll, renew, start, whoami};

pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024;

pub(crate) fn router(control: Control) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/login/start", post(start::handle))
        .route("/v1/login/callback", get(callback::handle))
        .route("/v1/login/finish", post(finish::handle))
        .route("/v1/whoami", get(whoami::handle))
        .route("/v1/agent/enroll", post(enroll::handle))
        .route("/v1/agent/enroll/poll", post(poll::handle));
    device::mount(routes, &control)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(response_headers))
        .with_state(control)
}

pub(crate) fn agent_router(control: Control) -> Router {
    Router::new()
        .route("/v1/agent/renew", post(renew::handle))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(response_headers))
        .with_state(control)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers
        .entry(header::REFERRER_POLICY)
        .or_insert(HeaderValue::from_static("no-referrer"));
    response
}

pub(crate) fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            *response.status_mut() = status;
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            response
        }
        Err(_) => empty_response(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

pub(crate) fn error_response(status: StatusCode, code: &'static str) -> Response {
    json_response(
        status,
        &ErrorBody {
            error: code.to_owned(),
        },
    )
}

pub(crate) fn empty_response(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(crate) fn server_error() -> Response {
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BodyFailure {
    TooLarge,
    Malformed,
}

impl BodyFailure {
    pub(crate) fn into_response(self) -> Response {
        match self {
            BodyFailure::TooLarge => {
                error_response(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
            }
            BodyFailure::Malformed => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        }
    }
}

pub(crate) fn json_body<T: DeserializeOwned>(
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<T, BodyFailure> {
    let bytes = match body {
        Ok(bytes) => bytes,
        Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            return Err(BodyFailure::TooLarge);
        }
        Err(_) => return Err(BodyFailure::Malformed),
    };
    if !is_json_content_type(headers) {
        return Err(BodyFailure::Malformed);
    }
    serde_json::from_slice(&bytes).map_err(|_| BodyFailure::Malformed)
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|text| text.split(';').next())
            .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json")),
        _ => false,
    }
}
