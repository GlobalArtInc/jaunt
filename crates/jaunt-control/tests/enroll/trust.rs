use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use jaunt_ca::ssh_key::{PrivateKey, PublicKey};
use jaunt_control::{AuthenticatedNode, ControlError};
use serde_json::json;

use crate::audit::{start_recording, take_recording};
use crate::session_support::{NODE_NAME, audit_events, node};
use crate::support::{Harness, Options, Reply, UserTrust, send};

const TRUST: &str = "/v1/agent/trust";
const UNKNOWN_NODE: &str = "00000000-0000-4000-8000-000000000000";

async fn fetch_trust(router: &Router, node_id: Option<&str>) -> Reply {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(TRUST)
        .body(Body::empty())
        .unwrap();
    if let Some(node_id) = node_id {
        request
            .extensions_mut()
            .insert(AuthenticatedNode(node_id.to_owned()));
    }
    send(router.clone(), request).await
}

#[tokio::test]
async fn an_active_node_receives_only_the_public_user_ca_keys_active_first() {
    let harness = Harness::with(Options {
        user_trust: UserTrust::RetiredKeyFirst,
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    let active = harness.user_trust.active().clone();
    let retired = harness.user_trust.keys()[0].clone();
    assert_ne!(retired.key_data(), active.key_data());
    start_recording();

    let reply = fetch_trust(&harness.agent_router, Some(&node_id)).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        reply.json(),
        json!({"user_ca_keys": [active.to_openssh().unwrap(), retired.to_openssh().unwrap()]})
    );
    for line in reply.json()["user_ca_keys"].as_array().unwrap() {
        let line = line.as_str().unwrap();
        assert!(PublicKey::from_openssh(line).is_ok(), "{line}");
        assert!(PrivateKey::from_openssh(line).is_err(), "{line}");
        assert!(!line.contains("PRIVATE"), "{line}");
        assert_ne!(
            PublicKey::from_openssh(line).unwrap().key_data(),
            harness.host_ca.key_data()
        );
    }

    let events = audit_events(take_recording());
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "agent.trust.served");
    assert_eq!(events[0]["node_id"], node_id);
    assert_eq!(events[0]["keys"], "2");
    let active_base64 = active.to_openssh().unwrap();
    let active_base64 = active_base64.split(' ').nth(1).unwrap();
    for value in events[0].values() {
        assert!(!value.contains("ssh-ed25519"), "{value}");
        assert!(!value.contains(active_base64), "{value}");
    }
}

#[tokio::test]
async fn the_trust_route_needs_an_authenticated_active_node_on_the_agent_router() {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let before = fetch_trust(&harness.agent_router, Some(&node_id)).await;
    assert_eq!(before.status, StatusCode::OK);

    let anonymous = fetch_trust(&harness.agent_router, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert!(anonymous.body.is_empty());

    let public = fetch_trust(&harness.router, Some(&node_id)).await;
    assert_eq!(public.status, StatusCode::NOT_FOUND);
    assert!(!public.text().contains("ssh-ed25519"));

    harness.admin.remove_node(NODE_NAME).await.unwrap();
    for id in [node_id.as_str(), UNKNOWN_NODE, ""] {
        let refused = fetch_trust(&harness.agent_router, Some(id)).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{id:?}");
        assert_eq!(refused.json(), json!({"error": "node_removed"}));
    }
}

#[tokio::test]
async fn control_refuses_a_user_trust_set_whose_active_key_is_not_the_signing_key() {
    let refused = Harness::try_with(Options {
        user_trust: UserTrust::NotTheSigningKey,
        ..Options::default()
    })
    .await;
    assert!(matches!(
        refused,
        Err(ControlError::UserAuthorityNotTrusted)
    ));
}
