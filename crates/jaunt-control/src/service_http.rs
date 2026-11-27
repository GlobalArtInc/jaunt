use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_proto::{
    ControlPlane, NodeCaller, ServiceAuthorizeRequest, ServiceAuthorizeResponse, ServiceEnd,
};

use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::control::Control;
use crate::http::{empty_response, json_body, json_response};
use crate::session_http::failure_response;

pub(crate) async fn authorize(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    let request = match json_body::<ServiceAuthorizeRequest>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    match control
        .authorize_service(NodeCaller(node_id), request)
        .await
    {
        Ok(decision) => json_response(StatusCode::OK, &ServiceAuthorizeResponse::from(&decision)),
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
    let request = match json_body::<ServiceEnd>(&headers, body) {
        Ok(request) => request,
        Err(failure) => return failure.into_response(),
    };
    if let Some(refused) = refuse_unless_active(&control, &node_id).await {
        return refused;
    }
    match control.service_end(NodeCaller(node_id), request).await {
        Ok(outcome) => json_response(StatusCode::OK, &outcome),
        Err(err) => failure_response(err),
    }
}
