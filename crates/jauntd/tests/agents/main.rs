mod ca_reload;
mod client;
mod frames;
mod kill;
mod limits;
mod oidc;
mod recorder;
mod recordings;
mod removal;
mod stand;
mod subject_key;
mod support;

use std::time::Duration;

use client::ApiClient;
use http::{Method, StatusCode};
use jaunt_ca::{Uuid, parse_node_identity};
use jaunt_tunnel::{ALPN_AGENT_API, NodeId};
use rcgen::{KeyPair, PKCS_ED25519};
use serde_json::json;
use support::*;
use tokio::net::TcpStream;

const GRACE: Duration = Duration::from_secs(5);

fn rejection_from(remote: &str) -> impl FnMut(&recorder::Captured) -> bool + '_ {
    move |event| field(event, "event") == "agent.rejected" && field(event, "remote_addr") == remote
}

#[tokio::test]
async fn an_active_node_gets_a_tunnel_and_loses_it_for_good_after_node_rm() {
    let harness = Harness::start(Options::default()).await;
    let agent = harness.enroll("web-01").await;
    let node = NodeId::new(agent.node_id.clone()).unwrap();
    let running = spawn_agent(&harness, &agent);
    eventually("the tunnel", || {
        harness.server.registry().is_connected(&node)
    })
    .await;
    let connected = audited("agent.connected", |event| {
        field(event, "event") == "agent.connected" && field(event, "node_id") == agent.node_id
    })
    .await;
    assert_eq!(field(&connected, "alpn"), "jaunt-tunnel/1");

    harness
        .admin
        .remove_node(&agent.name, "cli:tester")
        .await
        .unwrap();

    eventually("the removed node to lose its tunnel", || {
        !harness.server.registry().is_connected(&node)
    })
    .await;
    let disconnected = audited("agent.disconnected", |event| {
        field(event, "event") == "agent.disconnected" && field(event, "node_id") == agent.node_id
    })
    .await;
    assert_eq!(field(&disconnected, "reason"), "removed");
    let rejected = audited("the reconnect to be rejected", |event| {
        field(event, "event") == "agent.rejected" && field(event, "reason") == "inactive"
    })
    .await;
    assert_eq!(field(&rejected, "node_id"), agent.node_id);
    assert!(!harness.server.registry().is_connected(&node));
    assert_eq!(harness.server.stats().snapshot().tunnels_established, 1);

    running.stop().await;
    let addr = harness.addr();
    let report = harness.server.shutdown(GRACE).await;
    assert!(report.tunnels_closed && report.api_sessions_ended);
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn certificates_that_do_not_belong_to_an_active_node_key_are_refused() {
    let harness = Harness::start(Options::default()).await;
    let agent = harness.enroll("web-01").await;
    let removed = harness.enroll("web-02").await;
    harness
        .admin
        .remove_node(&removed.name, "cli:tester")
        .await
        .unwrap();
    let other_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let stranger = Uuid::new_v4().hyphenated().to_string();

    let cases = [
        (
            "key_mismatch",
            agent.node_id.as_str(),
            harness.issue_for(&agent.node_id, &other_key),
            private_key(&other_key),
        ),
        (
            "unknown_node",
            stranger.as_str(),
            harness.issue_for(&stranger, &other_key),
            private_key(&other_key),
        ),
        (
            "inactive",
            removed.node_id.as_str(),
            removed.chain.clone(),
            removed.key(),
        ),
    ];
    for (reason, node_id, chain, key) in cases {
        let dialed = dial_tunnel(&harness, chain, key).await;
        let remote = dialed.local_addr.to_string();
        assert!(refused(dialed).await, "{reason}");
        let rejected = audited(reason, rejection_from(&remote)).await;
        assert_eq!(field(&rejected, "reason"), reason);
        assert_eq!(field(&rejected, "node_id"), node_id, "{reason}");
    }
    assert_eq!(harness.server.stats().snapshot().auth_rejections, 3);

    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = foreign_ca(foreign_dir.path());
    let own_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let forged = issue_node(&foreign, &agent.node_id, &own_key);
    let failures_before = harness.server.stats().snapshot().handshake_failures;
    assert!(refused(dial_tunnel(&harness, forged, private_key(&own_key)).await).await);
    eventually("the forged certificate to fail the handshake", || {
        harness.server.stats().snapshot().handshake_failures > failures_before
    })
    .await;
    assert_eq!(harness.server.stats().snapshot().auth_rejections, 3);
    assert!(harness.server.registry().connected_nodes().is_empty());
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn a_failing_store_rejects_the_agent_and_registers_nothing() {
    let harness = Harness::start(Options::default()).await;
    let agent = harness.enroll("web-01").await;
    harness.break_node_table().await;

    let dialed = dial_tunnel(&harness, agent.chain.clone(), agent.key()).await;
    let remote = dialed.local_addr.to_string();

    assert!(refused(dialed).await);
    let rejected = audited("unavailable", rejection_from(&remote)).await;
    assert_eq!(field(&rejected, "reason"), "unavailable");
    assert_eq!(field(&rejected, "node_id"), agent.node_id);
    assert_eq!(harness.server.stats().snapshot().auth_rejections, 1);
    assert_eq!(harness.server.stats().snapshot().tunnels_established, 0);
    assert!(harness.server.registry().connected_nodes().is_empty());
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn the_agent_api_serves_only_the_agent_router_as_the_authenticated_node() {
    let harness = Harness::start(Options {
        reconcile_interval: Some(Duration::from_secs(60 * 60)),
        ..Options::default()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let other = harness.enroll("web-02").await;
    let other_certificates = harness
        .store
        .nodes()
        .certificates(&other.node_id)
        .await
        .unwrap()
        .len();
    let mut client = ApiClient::open(&harness, &agent).await;

    let spoofing = [
        ("x-authenticated-node", other.node_id.as_str()),
        ("x-node-id", other.node_id.as_str()),
        ("content-type", "application/json"),
    ];
    let renewed = api_request(
        &mut client.sender,
        Method::POST,
        "/v1/agent/renew",
        &spoofing,
        Some(&json!({})),
    )
    .await;
    assert_eq!(renewed.status, StatusCode::OK);
    let issued = parse_node_identity(&certificate_of(&renewed.json())).unwrap();
    assert_eq!(issued.node_id.hyphenated().to_string(), agent.node_id);
    assert_eq!(client.sender.current_max_send_streams(), 32);

    let in_body = api_request(
        &mut client.sender,
        Method::POST,
        "/v1/agent/renew",
        &[("content-type", "application/json")],
        Some(&json!({"node_id": other.node_id})),
    )
    .await;
    assert_eq!(in_body.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&other.node_id)
            .await
            .unwrap()
            .len(),
        other_certificates
    );

    for (method, path) in [
        (Method::GET, "/healthz"),
        (Method::POST, "/v1/agent/enroll"),
        (Method::POST, "/v1/login/start"),
    ] {
        let reply = api_request(&mut client.sender, method, path, &[], None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }

    harness
        .admin
        .remove_node(&agent.name, "cli:tester")
        .await
        .unwrap();
    let after_removal = api_request(
        &mut client.sender,
        Method::POST,
        "/v1/agent/renew",
        &[("content-type", "application/json")],
        Some(&json!({})),
    )
    .await;
    assert_eq!(after_removal.status, StatusCode::FORBIDDEN);
    assert_eq!(after_removal.json()["error"], "node_removed");

    client.ended.abort();
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn an_idle_api_session_ends_with_goaway_when_the_server_stops() {
    let harness = Harness::start(Options::default()).await;
    let agent = harness.enroll("web-01").await;
    let mut client = ApiClient::open(&harness, &agent).await;
    let reply = api_request(&mut client.sender, Method::GET, "/healthz", &[], None).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);

    let report = harness.server.shutdown(GRACE).await;

    assert!(report.api_sessions_ended);
    within("the api connection to end", &mut client.ended)
        .await
        .unwrap();
    assert!(client.saw_only_graceful_goaway());
}

#[tokio::test]
async fn a_rotated_server_certificate_reaches_new_connections_while_tunnels_stay_up() {
    let harness = Harness::start(Options {
        clock_days_behind: 21,
        ..Options::default()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let node = NodeId::new(agent.node_id.clone()).unwrap();
    let running = spawn_agent(&harness, &agent);
    eventually("the tunnel", || {
        harness.server.registry().is_connected(&node)
    })
    .await;
    let first = server_certificate(&harness, &agent).await;
    let first_not_after = harness.server.certificate_not_after();

    harness.clock.advance_days(21);

    eventually("the rotation", || {
        harness.server.certificate_not_after() > first_not_after
    })
    .await;
    let second = server_certificate(&harness, &agent).await;
    assert_ne!(first, second);
    let rotated = audited("agent.cert.rotated", |event| {
        field(event, "event") == "agent.cert.rotated"
    })
    .await;
    assert_eq!(
        field(&rotated, "not_after"),
        unix_secs(harness.server.certificate_not_after()).to_string()
    );
    assert!(harness.server.registry().is_connected(&node));
    assert_eq!(harness.server.stats().snapshot().tunnels_established, 1);

    running.stop().await;
    harness.server.shutdown(GRACE).await;
}

async fn server_certificate(harness: &Harness, agent: &EnrolledAgent) -> Vec<u8> {
    let dialed = dial(harness, agent.chain.clone(), agent.key(), ALPN_AGENT_API).await;
    let stream = dialed.stream.unwrap();
    let (_, connection) = stream.get_ref();
    connection.peer_certificates().unwrap()[0].as_ref().to_vec()
}
