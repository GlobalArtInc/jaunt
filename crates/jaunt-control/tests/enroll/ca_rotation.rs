use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use jaunt_ca::ssh_key::{Certificate, HashAlg};
use jaunt_ca::{AgeIdentity, CaKind, CaLock, FileBackend, fingerprint_hex};
use jaunt_control::{AuthenticatedNode, CaSnapshot};
use jaunt_store::NodeCertificateKind;
use serde_json::json;

use crate::audit::{start_recording, take_recording};
use crate::session_support::{NODE_NAME, audit_events, node};
use crate::sign_hook::SignHook;
use crate::support::{Harness, Options, Reply, UserTrust, send};

const TRUST_V1: &str = "/v1/agent/trust";
const TRUST_V2: &str = "/v2/agent/trust";
const SERVED_INTERVAL_SECS: u64 = 300;

async fn fetch(router: &Router, path: &str, node_id: Option<&str>) -> Reply {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    if let Some(node_id) = node_id {
        request
            .extensions_mut()
            .insert(AuthenticatedNode(node_id.to_owned()));
    }
    send(router.clone(), request).await
}

fn add_next(harness: &Harness, kind: CaKind) {
    let lock = CaLock::acquire(&harness.ca_root).unwrap();
    FileBackend::add_next(&lock, kind, &harness.identity).unwrap();
}

fn promote(harness: &Harness, kind: CaKind) {
    let lock = CaLock::acquire(&harness.ca_root).unwrap();
    let (trust, _) =
        FileBackend::load_with_next(&harness.ca_root, kind, &harness.identity).unwrap();
    let next = trust.next().unwrap().fingerprint(HashAlg::Sha256);
    FileBackend::promote(&lock, kind, &harness.identity, &next).unwrap();
}

fn reload(harness: &Harness) -> Arc<CaSnapshot> {
    let (user_trust, user) =
        FileBackend::load_with_next(&harness.ca_root, CaKind::User, &harness.identity).unwrap();
    let (host_trust, host) =
        FileBackend::load_with_next(&harness.ca_root, CaKind::Host, &harness.identity).unwrap();
    let snapshot = CaSnapshot::new(Arc::new(user), user_trust, Arc::new(host), host_trust).unwrap();
    harness.control.replace_snapshot(snapshot);
    harness.control.ca_snapshot()
}

async fn served(harness: &Harness) -> (Option<String>, Option<i64>) {
    let nodes = harness.store.ca_counters().node_trust().await.unwrap();
    assert_eq!(nodes.len(), 1);
    (nodes[0].trust_id.clone(), nodes[0].served_at)
}

fn line(key: &jaunt_ca::ssh_key::PublicKey) -> String {
    key.to_openssh().unwrap()
}

#[tokio::test]
async fn the_first_trust_version_answers_byte_for_byte_as_before() {
    let harness = Harness::with(Options {
        user_trust: UserTrust::RetiredKeyFirst,
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    let active = line(harness.user_trust.active());
    let retired = line(&harness.user_trust.keys()[0]);

    let reply = fetch(&harness.agent_router, TRUST_V1, Some(&node_id)).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(
        reply.text(),
        format!("{{\"user_ca_keys\":[\"{active}\",\"{retired}\"]}}")
    );

    add_next(&harness, CaKind::User);
    let snapshot = reload(&harness);
    let next = line(snapshot.user_trust().next().unwrap());
    let active = line(snapshot.user_trust().active());

    let reply = fetch(&harness.agent_router, TRUST_V1, Some(&node_id)).await;

    assert_eq!(
        reply.text(),
        format!("{{\"user_ca_keys\":[\"{active}\",\"{next}\"]}}")
    );
}

#[tokio::test]
async fn the_second_trust_version_needs_an_authenticated_active_node_and_names_the_set() {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let snapshot = harness.control.ca_snapshot();

    let anonymous = fetch(&harness.agent_router, TRUST_V2, None).await;
    let public = fetch(&harness.router, TRUST_V2, Some(&node_id)).await;
    start_recording();
    let reply = fetch(&harness.agent_router, TRUST_V2, Some(&node_id)).await;
    let events = audit_events(take_recording());

    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert!(anonymous.body.is_empty());
    assert_eq!(public.status, StatusCode::NOT_FOUND);
    assert!(!public.text().contains("ssh-ed25519"));
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        reply.json(),
        json!({
            "trust_id": snapshot.user_trust_id(),
            "user_ca_keys": [line(snapshot.user_trust().active())],
            "host_ca_active": line(snapshot.host_trust().active()),
        })
    );
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["event"], "agent.trust.served");
    assert_eq!(events[0]["trust_id"], snapshot.user_trust_id());

    harness
        .admin
        .remove_node(NODE_NAME, "cli:tester")
        .await
        .unwrap();
    let removed = fetch(&harness.agent_router, TRUST_V2, Some(&node_id)).await;
    assert_eq!(removed.status, StatusCode::FORBIDDEN);
    assert_eq!(removed.json(), json!({"error": "node_removed"}));
}

async fn host_ca_active(harness: &Harness, node_id: &str) -> String {
    let reply = fetch(&harness.agent_router, TRUST_V2, Some(node_id)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()["host_ca_active"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_second_trust_version_names_the_active_host_key_through_a_rotation() {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let first = line(harness.control.ca_snapshot().host_trust().active());

    add_next(&harness, CaKind::Host);
    let next = line(reload(&harness).host_trust().next().unwrap());
    assert_ne!(next, first);
    assert_eq!(host_ca_active(&harness, &node_id).await, first);

    promote(&harness, CaKind::Host);
    let promoted = reload(&harness);
    assert_eq!(
        promoted
            .host_trust()
            .previous()
            .map(line)
            .collect::<Vec<_>>(),
        std::slice::from_ref(&first)
    );
    assert_eq!(host_ca_active(&harness, &node_id).await, next);
}

#[tokio::test]
async fn the_served_set_is_written_when_it_changes_or_once_five_minutes_have_passed() {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let first = harness.control.ca_snapshot().user_trust_id().to_owned();
    let start = harness.clock.now_secs();
    assert_eq!(served(&harness).await, (None, None));

    fetch(&harness.agent_router, TRUST_V1, Some(&node_id)).await;
    assert_eq!(served(&harness).await, (Some(first.clone()), Some(start)));

    harness.clock.advance(SERVED_INTERVAL_SECS - 1);
    fetch(&harness.agent_router, TRUST_V2, Some(&node_id)).await;
    assert_eq!(served(&harness).await, (Some(first.clone()), Some(start)));

    harness.clock.advance(1);
    let window = start + i64::try_from(SERVED_INTERVAL_SECS).unwrap();
    fetch(&harness.agent_router, TRUST_V1, Some(&node_id)).await;
    assert_eq!(served(&harness).await, (Some(first.clone()), Some(window)));

    add_next(&harness, CaKind::User);
    let second = reload(&harness).user_trust_id().to_owned();
    assert_ne!(second, first);
    harness.clock.advance(1);
    fetch(&harness.agent_router, TRUST_V2, Some(&node_id)).await;
    assert_eq!(
        served(&harness).await,
        (Some(second.clone()), Some(window + 1))
    );

    harness.clock.advance(1);
    fetch(&harness.agent_router, TRUST_V1, Some(&node_id)).await;
    assert_eq!(served(&harness).await, (Some(second), Some(window + 1)));
}

#[tokio::test]
async fn node_host_certificates_record_the_host_key_that_signed_them() {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let first_signer = fingerprint_hex(harness.control.ca_snapshot().host_trust().active());
    let delivered = harness.store.nodes().certificates(&node_id).await.unwrap();
    let signer_of = |kind| {
        delivered
            .iter()
            .filter(|certificate| certificate.kind == kind)
            .map(|certificate| certificate.ca_fingerprint.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        signer_of(NodeCertificateKind::SshHost),
        [Some(first_signer.clone())]
    );
    assert_eq!(signer_of(NodeCertificateKind::X509), [None]);

    add_next(&harness, CaKind::Host);
    promote(&harness, CaKind::Host);
    let snapshot = reload(&harness);
    let second_signer = fingerprint_hex(snapshot.host_trust().active());
    assert_ne!(second_signer, first_signer);
    harness.clock.advance(1);

    let reply = harness.renew(Some(&node_id), &json!({})).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let renewed =
        Certificate::from_openssh(reply.json()["ssh_host_certificate"].as_str().unwrap()).unwrap();
    assert_eq!(
        renewed.signature_key(),
        snapshot.host_trust().active().key_data()
    );
    let latest = harness
        .store
        .ca_counters()
        .latest_node_host_certificates()
        .await
        .unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].ca_fingerprint, Some(second_signer));
}

fn fresh_snapshot() -> CaSnapshot {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    for kind in [CaKind::User, CaKind::Host] {
        FileBackend::init(dir.path(), kind, &identity.recipient()).unwrap();
    }
    let (user_trust, user) = FileBackend::load(dir.path(), CaKind::User, &identity).unwrap();
    let (host_trust, host) = FileBackend::load(dir.path(), CaKind::Host, &identity).unwrap();
    CaSnapshot::new(Arc::new(user), user_trust, Arc::new(host), host_trust).unwrap()
}

async fn renewed_host_certificate(
    harness: &Harness,
    node_id: &str,
) -> (Certificate, Option<String>) {
    let reply = harness.renew(Some(node_id), &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let certificate =
        Certificate::from_openssh(reply.json()["ssh_host_certificate"].as_str().unwrap()).unwrap();
    let latest = harness
        .store
        .ca_counters()
        .latest_node_host_certificates()
        .await
        .unwrap();
    assert_eq!(latest.len(), 1);
    (certificate, latest[0].ca_fingerprint.clone())
}

#[tokio::test]
async fn a_snapshot_swapped_while_a_host_certificate_is_signed_does_not_split_that_issuance() {
    let hook = SignHook::default();
    let harness = Harness::with(Options {
        host_sign_hook: Some(hook.clone()),
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    let before = harness.control.ca_snapshot().host_trust().active().clone();
    let after = fresh_snapshot();
    let after_host = after.host_trust().active().clone();
    let control = harness.control.clone();
    hook.arm(move || {
        control.replace_snapshot(after);
    });
    harness.clock.advance(1);

    let (first, recorded) = renewed_host_certificate(&harness, &node_id).await;

    assert!(hook.fired());
    assert_eq!(
        harness
            .control
            .ca_snapshot()
            .host_trust()
            .active()
            .key_data(),
        after_host.key_data()
    );
    assert_eq!(first.signature_key(), before.key_data());
    assert_eq!(recorded, Some(fingerprint_hex(&before)));

    harness.clock.advance(1);
    let (second, recorded) = renewed_host_certificate(&harness, &node_id).await;

    assert_eq!(second.signature_key(), after_host.key_data());
    assert_eq!(recorded, Some(fingerprint_hex(&after_host)));
}

#[tokio::test]
async fn client_config_lists_the_host_keys_active_then_next_then_previous() {
    let harness = Harness::with(Options {
        gate_endpoint: Some("gate.example.com:22"),
        ..Options::default()
    })
    .await;
    let host_keys = async || {
        let reply = fetch(&harness.router, "/v1/client-config", None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        reply.json()["host_ca_keys"].clone()
    };
    let first = line(harness.control.ca_snapshot().host_trust().active());

    assert_eq!(host_keys().await, json!([first]));

    add_next(&harness, CaKind::Host);
    let next = line(reload(&harness).host_trust().next().unwrap());
    assert_eq!(host_keys().await, json!([first, next]));

    promote(&harness, CaKind::Host);
    reload(&harness);
    assert_eq!(host_keys().await, json!([next, first]));
}
