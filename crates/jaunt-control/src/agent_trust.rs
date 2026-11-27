use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::{ClientSlot, KeyRole};
use jaunt_proto::{AgentTrust, AgentTrustV2, AgentTrustV3, TrustRole, TrustedX509Root};

use crate::agent::{AuthenticatedNode, Refusal, active_node};
use crate::ca_snapshot::CaSnapshot;
use crate::control::Control;
use crate::http::{empty_response, json_response, server_error};
use crate::node_audit;
use crate::server_cert::unix_secs;
use crate::token::hex_digest;

const V3_TRUST_ID_DOMAIN: &[u8] = b"jaunt-agent-trust-v3";

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

pub(crate) async fn handle_v3(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
) -> Response {
    let node_id = match active_caller(&control, authenticated).await {
        Ok(node_id) => node_id,
        Err(refused) => return refused.into_response(),
    };
    let user_x509_roots = match control.user_x509() {
        Some(slot) => match x509_roots(&slot) {
            Some(roots) => roots,
            None => {
                tracing::error!(target: "jaunt::control", "a user-x509 root has a validity the wire format cannot carry");
                return server_error();
            }
        },
        None => Vec::new(),
    };
    let ca = control.ca_snapshot();
    mark_served(&control, &node_id, &ca).await;
    json_response(
        StatusCode::OK,
        &AgentTrustV3 {
            trust_id: v3_trust_id(ca.user_trust_id(), &user_x509_roots),
            user_ca_keys: ca.user_ca_keys().to_vec(),
            host_ca_active: ca.host_ca_active().to_owned(),
            user_x509_roots,
        },
    )
}

pub(crate) fn v3_trust_id(user_trust_id: &str, roots: &[TrustedX509Root]) -> String {
    let mut input = V3_TRUST_ID_DOMAIN.to_vec();
    input.push(0);
    input.extend_from_slice(user_trust_id.as_bytes());
    for root in roots {
        let role = match root.role {
            TrustRole::Active => "active",
            TrustRole::Next => "next",
            TrustRole::Previous => "previous",
        };
        input.push(0);
        input.extend_from_slice(role.as_bytes());
        input.push(b':');
        input.extend_from_slice(root.fingerprint.as_bytes());
    }
    hex_digest(&input)
}

const fn trust_role(role: KeyRole) -> TrustRole {
    match role {
        KeyRole::Active => TrustRole::Active,
        KeyRole::Next => TrustRole::Next,
        KeyRole::Previous => TrustRole::Previous,
    }
}

pub(crate) fn x509_roots(slot: &ClientSlot) -> Option<Vec<TrustedX509Root>> {
    slot.roots
        .iter()
        .map(|root| {
            Some(TrustedX509Root {
                role: trust_role(root.role),
                fingerprint: root.fingerprint.clone(),
                certificate_der: STANDARD.encode(&root.certificate_der),
                not_before: unix_secs(root.not_before)?,
                not_after: unix_secs(root.not_after)?,
            })
        })
        .collect()
}

async fn serve(
    control: &Control,
    authenticated: Option<Extension<AuthenticatedNode>>,
    answer: impl FnOnce(&CaSnapshot) -> Response,
) -> Response {
    let node_id = match active_caller(control, authenticated).await {
        Ok(node_id) => node_id,
        Err(refused) => return refused.into_response(),
    };
    let ca = control.ca_snapshot();
    mark_served(control, &node_id, &ca).await;
    answer(&ca)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotServed {
    Unauthenticated,
    Refused(Refusal),
}

impl NotServed {
    fn into_response(self) -> Response {
        match self {
            NotServed::Unauthenticated => empty_response(StatusCode::UNAUTHORIZED),
            NotServed::Refused(refusal) => refusal.into_response(),
        }
    }
}

async fn active_caller(
    control: &Control,
    authenticated: Option<Extension<AuthenticatedNode>>,
) -> Result<String, NotServed> {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return Err(NotServed::Unauthenticated);
    };
    active_node(control, &node_id)
        .await
        .map_err(NotServed::Refused)?;
    Ok(node_id)
}

async fn mark_served(control: &Control, node_id: &str, ca: &CaSnapshot) {
    record_served(control, node_id, ca.user_trust_id()).await;
    node_audit::trust_served(node_id, ca.user_ca_keys().len(), ca.user_trust_id());
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

#[cfg(test)]
mod tests {
    use jaunt_proto::{TrustRole, TrustedX509Root};

    use super::v3_trust_id;

    fn root(role: TrustRole, fingerprint: &str) -> TrustedX509Root {
        TrustedX509Root {
            role,
            fingerprint: fingerprint.to_owned(),
            certificate_der: "MIIB".to_owned(),
            not_before: 1,
            not_after: 2,
        }
    }

    #[test]
    fn the_v3_trust_id_changes_with_the_user_set_and_with_every_x509_root_and_role() {
        let base = v3_trust_id("u1", &[root(TrustRole::Active, "a")]);
        assert_eq!(base.len(), 64);
        assert_ne!(base, "u1");
        assert_eq!(base, v3_trust_id("u1", &[root(TrustRole::Active, "a")]));
        for other in [
            v3_trust_id("u2", &[root(TrustRole::Active, "a")]),
            v3_trust_id("u1", &[root(TrustRole::Active, "b")]),
            v3_trust_id("u1", &[root(TrustRole::Previous, "a")]),
            v3_trust_id(
                "u1",
                &[root(TrustRole::Active, "a"), root(TrustRole::Next, "b")],
            ),
            v3_trust_id("u1", &[]),
        ] {
            assert_ne!(other, base);
        }
        assert_ne!(
            v3_trust_id(
                "u1",
                &[root(TrustRole::Active, "a"), root(TrustRole::Next, "b")]
            ),
            v3_trust_id(
                "u1",
                &[root(TrustRole::Active, "a"), root(TrustRole::Previous, "b")]
            )
        );
    }
}
