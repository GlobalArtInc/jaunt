mod support;

use std::sync::Arc;
use std::time::Duration;

use jaunt_gate::{AgentHub, AgentHubConfig, DisconnectReason, HubError};
use jaunt_tunnel::agent_server_config;
use jaunt_tunnel::{ALPN_AGENT_API, ALPN_TUNNEL, RejectReason};
use rustls::pki_types::ServerName;
use support::*;
use tokio::net::{TcpListener, TcpStream};

const GRACE: Duration = Duration::from_secs(5);

fn is_event(event: &Captured, name: &str) -> bool {
    field(event, "event") == name
}

fn allowing(pki: &Pki, nodes: &[&str]) -> (Arc<Verdicts>, Vec<Leaf>) {
    let verdicts = Arc::new(Verdicts::default());
    let leaves = nodes
        .iter()
        .map(|name| {
            let leaf = pki.client_leaf(name);
            verdicts.allow(&leaf, name);
            leaf
        })
        .collect();
    (verdicts, leaves)
}

#[tokio::test]
async fn an_accepted_agent_gets_a_tunnel_and_a_planned_disconnect_keeps_its_reason() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a"]);
    let test = start_hub(&pki, verdicts, HubOptions::default()).await;
    let agent = spawn_agent(test.addr, &pki, &leaves[0]);

    eventually("the tunnel", || {
        test.hub.registry().is_connected(&node("node-a"))
    })
    .await;
    let connected = audited("agent.connected", |event| {
        is_event(event, "agent.connected") && field(event, "node_id") == "node-a"
    })
    .await;
    assert_eq!(field(&connected, "alpn"), "jaunt-tunnel/1");
    assert_eq!(field(&connected, "replaced"), "false");
    assert!(field(&connected, "remote_addr").starts_with("127.0.0.1:"));

    let agents = test.hub.agents();
    assert!(agents.disconnect(&node("node-a"), DisconnectReason::Removed));
    assert!(!agents.disconnect(&node("node-b"), DisconnectReason::Removed));
    let disconnected = audit_events()
        .into_iter()
        .find(|event| is_event(event, "agent.disconnected"))
        .unwrap();
    assert_eq!(field(&disconnected, "node_id"), "node-a");
    assert_eq!(field(&disconnected, "reason"), "removed");

    agent.stop().await;
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn a_second_tunnel_of_the_same_node_is_audited_as_a_replacement() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a"]);
    let test = start_hub(&pki, verdicts, HubOptions::default()).await;
    let _first = connect_fake_agent(test.addr, &pki, &leaves[0]).await;
    audited("the first tunnel", |event| {
        is_event(event, "agent.connected") && field(event, "replaced") == "false"
    })
    .await;

    let _second = connect_fake_agent(test.addr, &pki, &leaves[0]).await;

    let connected = audited("the replacing tunnel", |event| {
        is_event(event, "agent.connected") && field(event, "replaced") == "true"
    })
    .await;
    assert_eq!(field(&connected, "node_id"), "node-a");
    let ended = audited("the replaced tunnel", |event| {
        is_event(event, "agent.disconnected")
    })
    .await;
    assert_eq!(field(&ended, "node_id"), "node-a");
    assert_eq!(field(&ended, "reason"), "replaced");
    assert_eq!(test.hub.registry().connected_nodes(), [node("node-a")]);
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn server_names_match_without_case_or_a_trailing_dot() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a"]);
    let mut test = start_hub(&pki, verdicts, HubOptions::default()).await;

    for name in ["AGENTS.TEST", "Agents.Test.", "agents.test."] {
        let dialed = dial(
            test.addr,
            &pki,
            Some(&leaves[0]),
            ServerName::try_from(name).unwrap(),
            &[ALPN_AGENT_API],
        )
        .await;
        let stream = dialed.stream.unwrap();
        let session = within(name, test.sessions.recv()).await.unwrap();
        assert_eq!(session.node, node("node-a"), "{name}");
        drop(stream);
    }
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn other_names_other_protocols_and_missing_certificates_never_reach_the_authenticator() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a"]);
    let test = start_hub(&pki, verdicts, HubOptions::default()).await;
    let cases: [(&str, ServerName<'static>, &[u8]); 3] = [
        (
            "another server name",
            ServerName::try_from(OTHER_SNI).unwrap(),
            ALPN_TUNNEL,
        ),
        (
            "no server name",
            ServerName::IpAddress(test.addr.ip().into()),
            ALPN_TUNNEL,
        ),
        ("h2 on the agents' name", agent_name(), b"h2"),
    ];
    for (label, name, alpn) in cases {
        let dialed = dial(test.addr, &pki, Some(&leaves[0]), name, &[alpn]).await;
        assert!(refused(dialed).await, "{label}");
    }

    let anonymous = dial(test.addr, &pki, None, agent_name(), &[ALPN_TUNNEL]).await;
    let remote = anonymous.local_addr.to_string();
    assert!(refused(anonymous).await);
    let rejected = audited("agent.rejected", |event| {
        is_event(event, "agent.rejected") && field(event, "remote_addr") == remote
    })
    .await;
    assert_eq!(field(&rejected, "reason"), "no_certificate");
    assert_eq!(field(&rejected, "level"), "DEBUG");
    assert_eq!(test.hub.hub_stats().no_certificate, 1);

    eventually("every refusal to be counted", || {
        let stats = test.hub.stats().snapshot();
        stats.handshake_failures + stats.no_application_protocol == 4
    })
    .await;
    assert_eq!(test.hub.stats().snapshot().auth_rejections, 0);
    assert!(test.hub.registry().connected_nodes().is_empty());
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn authenticator_rejections_and_timeouts_are_audited_with_the_remote_address() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let verdicts = Arc::new(Verdicts::default());
    verdicts.refuse_node(&leaf, "node-a", RejectReason::KeyMismatch);
    let mut refusing = start_hub(&pki, verdicts, HubOptions::default()).await;
    let hanging = start_hub(
        &pki,
        Arc::new(Hanging),
        HubOptions {
            handshake_timeout: Duration::from_secs(1),
            ..HubOptions::default()
        },
    )
    .await;

    for (addr, alpn, reason, node_id) in [
        (refusing.addr, ALPN_TUNNEL, "key_mismatch", "node-a"),
        (refusing.addr, ALPN_AGENT_API, "key_mismatch", "node-a"),
        (hanging.addr, ALPN_TUNNEL, "timeout", ""),
    ] {
        let dialed = dial(addr, &pki, Some(&leaf), agent_name(), &[alpn]).await;
        let remote = dialed.local_addr.to_string();
        assert!(refused(dialed).await, "{reason}");
        let rejected = audited(reason, |event| {
            is_event(event, "agent.rejected") && field(event, "remote_addr") == remote
        })
        .await;
        assert_eq!(field(&rejected, "reason"), reason);
        assert_eq!(field(&rejected, "node_id"), node_id);
        assert_eq!(field(&rejected, "level"), "INFO");
    }

    assert_eq!(refusing.hub.stats().snapshot().auth_rejections, 2);
    assert!(refusing.sessions.try_recv().is_err());
    assert!(refusing.hub.registry().connected_nodes().is_empty());
    refusing.hub.shutdown(GRACE).await;
    hanging.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn api_sessions_are_capped_per_node_and_in_total_without_touching_other_nodes() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a", "node-b", "node-c"]);
    let mut test = start_hub(
        &pki,
        verdicts,
        HubOptions {
            sessions_per_node: 2,
            sessions: 3,
            ..HubOptions::default()
        },
    )
    .await;
    let mut open = Vec::new();
    for leaf in [&leaves[0], &leaves[0]] {
        let dialed = dial(test.addr, &pki, Some(leaf), agent_name(), &[ALPN_AGENT_API]).await;
        open.push(dialed.stream.unwrap());
        within("a session of node-a", test.sessions.recv()).await;
    }

    let third = dial(
        test.addr,
        &pki,
        Some(&leaves[0]),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    let remote = third.local_addr.to_string();
    assert!(refused(third).await);
    let rejected = audited("the per-node cap", |event| {
        is_event(event, "agent.rejected") && field(event, "remote_addr") == remote
    })
    .await;
    assert_eq!(field(&rejected, "reason"), "too_many_sessions");
    assert_eq!(field(&rejected, "node_id"), "node-a");
    assert_eq!(field(&rejected, "level"), "DEBUG");

    let other = dial(
        test.addr,
        &pki,
        Some(&leaves[1]),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    let _other_stream = other.stream.unwrap();
    let session = within("a session of node-b", test.sessions.recv())
        .await
        .unwrap();
    assert_eq!(session.node, node("node-b"));

    let over = dial(
        test.addr,
        &pki,
        Some(&leaves[2]),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    assert!(refused(over).await);
    let stats = test.hub.hub_stats();
    assert_eq!(stats.api_sessions_refused_per_node, 1);
    assert_eq!(stats.api_sessions_refused_global, 1);
    assert_eq!(stats.api_sessions_open, 3);

    drop(open.pop());
    eventually("the closed session to free its slot", || {
        test.hub.hub_stats().api_sessions_open == 2
    })
    .await;
    let reopened = dial(
        test.addr,
        &pki,
        Some(&leaves[0]),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    let _reopened_stream = reopened.stream.unwrap();
    let session = within("a new session of node-a", test.sessions.recv())
        .await
        .unwrap();
    assert_eq!(session.node, node("node-a"));
    assert_eq!(test.hub.hub_stats().api_sessions_open, 3);
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn session_limits_of_zero_are_refused() {
    let pki = Pki::new("ca");
    let server = pki.client_leaf("gate");
    let tls =
        Arc::new(agent_server_config(server.chain.clone(), server.key(), pki.roots()).unwrap());
    for (per_node, total) in [(0, 8), (2, 0)] {
        let mut config = AgentHubConfig::new(AGENT_SNI, tls.clone());
        config.max_api_sessions_per_node = per_node;
        config.max_api_sessions = total;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let started = AgentHub::start(
            listener,
            config,
            Arc::new(Verdicts::default()),
            Arc::new(Unused),
        );
        assert!(
            matches!(started, Err(HubError::SessionLimits)),
            "{per_node} {total}"
        );
    }
}

#[tokio::test]
async fn shutdown_closes_tunnels_before_it_returns_and_ends_api_sessions() {
    let pki = Pki::new("ca");
    let (verdicts, leaves) = allowing(&pki, &["node-a", "node-b"]);
    let mut test = start_hub(&pki, verdicts, HubOptions::default()).await;
    let watched = connect_fake_agent(test.addr, &pki, &leaves[0]).await;
    let drained = connect_fake_agent(test.addr, &pki, &leaves[1]).await;
    eventually("both tunnels", || {
        test.hub.registry().connected_nodes().len() == 2
    })
    .await;
    let api = dial(
        test.addr,
        &pki,
        Some(&leaves[0]),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    let _api_stream = api.stream.unwrap();
    let session = within("the api session", test.sessions.recv())
        .await
        .unwrap();
    assert_eq!(session.node, node("node-a"));
    assert!(session.keepalive);

    let report = test.hub.shutdown(GRACE).await;

    assert!(drained.peer_closed_now());
    assert!(report.tunnels_closed && report.api_sessions_ended);
    assert!(session.shutdown.is_cancelled());
    eventually("goaway", || {
        !watched.goaway_codes.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(*watched.goaway_codes.lock().unwrap(), [0]);
    assert!(TcpStream::connect(test.addr).await.is_err());
    let ended: Vec<(String, String)> = audit_events()
        .iter()
        .filter(|event| is_event(event, "agent.disconnected"))
        .map(|event| {
            (
                field(event, "alpn").to_owned(),
                field(event, "reason").to_owned(),
            )
        })
        .collect();
    for alpn in ["jaunt-tunnel/1", "jaunt-agent/1"] {
        assert!(
            ended.contains(&(alpn.to_owned(), "shutdown".to_owned())),
            "{ended:?}"
        );
    }
}
