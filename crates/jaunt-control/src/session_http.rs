use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::{
    AuthorizeRequest, AuthorizeResponse, ControlError as PlaneError, ControlPlane, NodeCaller,
    SessionEnd,
};

use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};

pub(crate) async fn authorize(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let request = match json_body::<AuthorizeRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    match control.authorize(NodeCaller(node_id), request).await {
        Ok(decision) => json_response(StatusCode::OK, &AuthorizeResponse::from(&decision)),
        Err(err) => failure_response(err),
    }
}

pub(crate) async fn end(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let request = match json_body::<SessionEnd>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if let Some(refused) = refuse_unless_active(&control, &node_id).await {
        return refused;
    }
    match control.session_end(NodeCaller(node_id), request).await {
        Ok(outcome) => json_response(StatusCode::OK, &outcome),
        Err(err) => failure_response(err),
    }
}

pub(crate) fn failure_response(err: PlaneError) -> Response {
    match err {
        PlaneError::InvalidRequest => error_response(StatusCode::BAD_REQUEST, "invalid_request"),
        PlaneError::Store | PlaneError::Clock => server_error(),
    }
}
