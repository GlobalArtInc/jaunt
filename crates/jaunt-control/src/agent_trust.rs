use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use jaunt_proto::{AgentTrust, AgentTrustV2};

use crate::agent::{AuthenticatedNode, refuse_unless_active};
use crate::ca_snapshot::CaSnapshot;
use crate::control::Control;
use crate::http::{empty_response, json_response};
use crate::node_audit;

pub(crate) const TRUST_SERVED_INTERVAL_SECS: i64 = 5 * 60;

pub(crate) async fn handle(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
) -> Response {
    serve(&control, authenticated, |ca| {
        json_response(
            StatusCode::OK,
            &AgentTrust {
                user_ca_keys: ca.user_ca_keys().to_vec(),
            },
        )
    })
    .await
}

pub(crate) async fn handle_v2(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
) -> Response {
    serve(&control, authenticated, |ca| {
        json_response(
            StatusCode::OK,
            &AgentTrustV2 {
                trust_id: ca.user_trust_id().to_owned(),
                user_ca_keys: ca.user_ca_keys().to_vec(),
                host_ca_active: ca.host_ca_active().to_owned(),
            },
        )
    })
    .await
}

async fn serve(
    control: &Control,
    authenticated: Option<Extension<AuthenticatedNode>>,
    answer: impl FnOnce(&CaSnapshot) -> Response,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Some(refused) = refuse_unless_active(control, &node_id).await {
        return refused;
    }
    let ca = control.ca_snapshot();
    record_served(control, &node_id, ca.user_trust_id()).await;
    node_audit::trust_served(&node_id, ca.user_ca_keys().len(), ca.user_trust_id());
    answer(&ca)
}

async fn record_served(control: &Control, node_id: &str, trust_id: &str) {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch: the served trust set is not recorded");
        return;
    };
    if let Err(err) = control
        .store
        .nodes()
        .record_trust_served(node_id, trust_id, now.secs, TRUST_SERVED_INTERVAL_SECS)
        .await
    {
        tracing::error!(target: "jaunt::control", error = %err, node_id, "recording the served trust set failed");
    }
}
