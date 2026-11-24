use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use jaunt_proto::AgentTrust;

use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::control::Control;
use crate::http::{empty_response, json_response};
use crate::node_audit;

pub(crate) async fn handle(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Some(refused) = refuse_unless_active(&control, &node_id).await {
        return refused;
    }
    node_audit::trust_served(&node_id, control.user_ca_keys.len());
    json_response(
        StatusCode::OK,
        &AgentTrust {
            user_ca_keys: control.user_ca_keys.clone(),
        },
    )
}
