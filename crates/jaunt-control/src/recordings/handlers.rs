use axum::Extension;
use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_proto::{RecordingChunk, RecordingComplete, RecordingRefusal};
use jaunt_store::is_recording_id;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::task::JoinError;

use super::audit::Reason;
use super::flow::{self, Failure};
use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};

const RETRY_AFTER_SECS: &str = "60";

pub(crate) async fn chunk(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let (node_id, session_id, request) =
        match admit::<RecordingChunk>(&control, authenticated, path, &headers, body).await {
            Ok(admitted) => admitted,
            Err(response) => return *response,
        };
    respond(tokio::spawn(flow::chunk(control, node_id, session_id, request)).await)
}

pub(crate) async fn complete(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let (node_id, session_id, request) =
        match admit::<RecordingComplete>(&control, authenticated, path, &headers, body).await {
            Ok(admitted) => admitted,
            Err(response) => return *response,
        };
    respond(tokio::spawn(flow::complete(control, node_id, session_id, request)).await)
}

async fn admit<T: DeserializeOwned>(
    control: &Control,
    authenticated: Option<Extension<AuthenticatedNode>>,
    path: Result<Path<String>, PathRejection>,
    headers: &HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Result<(String, String, T), Box<Response>> {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return Err(Box::new(empty_response(StatusCode::UNAUTHORIZED)));
    };
    if control.recordings.is_none() {
        flow::reject(control, &node_id, None, Reason::Disabled);
        return Err(Box::new(refusal_response(RecordingRefusal::Disabled)));
    }
    if let Some(refused) = refuse_unless_active(control, &node_id).await {
        return Err(Box::new(refused));
    }
    let session_id = match path {
        Ok(Path(session_id)) if is_recording_id(&session_id) => session_id,
        _ => {
            flow::reject(control, &node_id, None, Reason::UnknownSession);
            return Err(Box::new(refusal_response(RecordingRefusal::SessionUnknown)));
        }
    };
    match json_body::<T>(headers, body) {
        Ok(request) => Ok((node_id, session_id, request)),
        Err(failure) => {
            flow::reject(control, &node_id, Some(&session_id), Reason::BadChunk);
            Err(Box::new(failure.into_response()))
        }
    }
}

fn respond<T: Serialize>(joined: Result<Result<T, Failure>, JoinError>) -> Response {
    match joined {
        Ok(Ok(value)) => json_response(StatusCode::OK, &value),
        Ok(Err(Failure::Refused { refusal, .. })) => refusal_response(refusal),
        Ok(Err(Failure::Unavailable)) => refusal_response(RecordingRefusal::StorageUnavailable),
        Ok(Err(Failure::Internal)) | Err(_) => server_error(),
    }
}

fn refusal_response(refusal: RecordingRefusal) -> Response {
    let status =
        StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = error_response(status, refusal.code());
    if refusal.retry_later() {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_static(RETRY_AFTER_SECS),
        );
    }
    response
}
