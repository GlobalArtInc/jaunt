use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use http_body_util::BodyExt;
use jaunt_proto::ErrorBody;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::control::Control;
use crate::recordings::{self, MAX_COMPLETE_BODY_BYTES};
use crate::{
    agent_trust, callback, client_config, device, enroll, finish, limits, nodes, poll, renew,
    session_http, start, web, whoami,
};

pub(crate) const MAX_BODY_BYTES: usize = 16 * 1024;
pub(crate) const BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) fn router(control: Control, extra_web_routes: Router<Control>) -> Router {
    let routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/login/start", post(start::handle))
        .route("/v1/login/callback", get(callback::handle))
        .route("/v1/login/finish", post(finish::handle))
        .route("/v1/whoami", get(whoami::handle))
        .route("/v1/client-config", get(client_config::handle))
        .route("/v1/nodes", get(nodes::handle))
        .route("/v1/agent/enroll", post(enroll::handle))
        .route("/v1/agent/enroll/poll", post(poll::handle));
    let routes = device::mount(routes, &control);
    web::mount(routes, &control, extra_web_routes)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(read_body_in_time))
        .layer(middleware::from_fn_with_state(
            control.clone(),
            limits::enforce,
        ))
        .layer(middleware::from_fn(response_headers))
        .with_state(control)
}

pub(crate) fn agent_router(control: Control) -> Router {
    Router::new()
        .route("/v1/agent/renew", post(renew::handle))
        .route("/v1/agent/authorize", post(session_http::authorize))
        .route("/v1/agent/session/end", post(session_http::end))
        .route("/v1/agent/trust", get(agent_trust::handle))
        .route(
            "/v1/agent/recordings/{session_id}/chunks",
            post(recordings::chunk).layer(DefaultBodyLimit::max(recordings::chunk_route_limit(
                &control,
            ))),
        )
        .route(
            "/v1/agent/recordings/{session_id}/complete",
            post(recordings::complete).layer(DefaultBodyLimit::max(MAX_COMPLETE_BODY_BYTES)),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn(response_headers))
        .with_state(control)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn collect(mut body: Body, limit: usize) -> Result<Vec<u8>, axum::Error> {
    let mut buffer = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            let room = limit.saturating_sub(buffer.len());
            buffer.extend_from_slice(&data[..data.len().min(room)]);
            if data.len() > room {
                break;
            }
        }
    }
    Ok(buffer)
}

async fn read_body_in_time(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let collected =
        tokio::time::timeout(BODY_READ_TIMEOUT, collect(body, MAX_BODY_BYTES + 1)).await;
    let bytes = match collected {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => return error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        Err(_) => {
            let mut response = error_response(StatusCode::REQUEST_TIMEOUT, "request_timeout");
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            return response;
        }
    };
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

async fn response_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
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

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, Bytes};
    use axum::extract::DefaultBodyLimit;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::post;
    use http_body_util::channel::Channel;
    use tokio::time::Instant;
    use tower::ServiceExt;

    use super::{BODY_READ_TIMEOUT, MAX_BODY_BYTES, read_body_in_time};

    fn app() -> Router {
        Router::new()
            .route(
                "/",
                post(|body: Bytes| async move { body.len().to_string() }),
            )
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .layer(middleware::from_fn(read_body_in_time))
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_stops_arriving_is_answered_with_408_at_the_deadline() {
        let (mut sender, body) = Channel::<Bytes, std::io::Error>::new(1);
        sender.send_data(Bytes::from_static(b"{")).await.unwrap();
        let started = Instant::now();

        let response = app()
            .oneshot(Request::post("/").body(Body::new(body)).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()["connection"], "close");
        assert!(started.elapsed() >= BODY_READ_TIMEOUT);
        drop(sender);
    }

    #[tokio::test]
    async fn a_body_at_the_limit_passes_and_one_byte_more_is_too_large() {
        for (len, status) in [
            (0, StatusCode::OK),
            (MAX_BODY_BYTES, StatusCode::OK),
            (MAX_BODY_BYTES + 1, StatusCode::PAYLOAD_TOO_LARGE),
            (4 * MAX_BODY_BYTES, StatusCode::PAYLOAD_TOO_LARGE),
        ] {
            let request = Request::post("/")
                .body(Body::from(vec![b'x'; len]))
                .unwrap();
            let response = app().oneshot(request).await.unwrap();
            assert_eq!(response.status(), status, "{len}");
        }
    }

    #[tokio::test]
    async fn a_streamed_body_is_cut_at_the_limit_while_its_source_is_still_sending() {
        let (mut sender, body) = Channel::<Bytes, std::io::Error>::new(1);
        let feeder = tokio::spawn(async move {
            let chunk = Bytes::from(vec![b'x'; 4 * 1024]);
            let mut sent = 0_usize;
            while sender.send_data(chunk.clone()).await.is_ok() {
                sent += chunk.len();
            }
            sent
        });

        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app().oneshot(Request::post("/").body(Body::new(body)).unwrap()),
        )
        .await
        .expect("the oversized body was read to its end")
        .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        drop(response);
        let sent = feeder.await.unwrap();
        assert!(sent < 4 * MAX_BODY_BYTES, "{sent}");
    }

    #[test]
    fn the_body_limits_stay_tight() {
        assert_eq!(MAX_BODY_BYTES, 16 * 1024);
        assert!(BODY_READ_TIMEOUT <= std::time::Duration::from_secs(30));
        assert!(BODY_READ_TIMEOUT >= std::time::Duration::from_secs(5));
    }
}
