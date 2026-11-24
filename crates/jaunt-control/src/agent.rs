use axum::http::StatusCode;
use axum::response::Response;
use jaunt_store::Node;

use crate::control::Control;
use crate::http::{error_response, server_error};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedNode(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    NodeRemoved,
    StoreFailed,
}

impl Refusal {
    pub(crate) fn into_response(self) -> Response {
        match self {
            Refusal::NodeRemoved => node_removed(),
            Refusal::StoreFailed => server_error(),
        }
    }
}

pub(crate) fn node_removed() -> Response {
    error_response(StatusCode::FORBIDDEN, "node_removed")
}

pub(crate) async fn active_node(control: &Control, node_id: &str) -> Result<Node, Refusal> {
    match control.store.nodes().get_active(node_id).await {
        Ok(Some(node)) => Ok(node),
        Ok(None) => Err(Refusal::NodeRemoved),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the node failed");
            Err(Refusal::StoreFailed)
        }
    }
}

pub(crate) async fn refuse_unless_active(control: &Control, node_id: &str) -> Option<Response> {
    active_node(control, node_id)
        .await
        .err()
        .map(Refusal::into_response)
}
