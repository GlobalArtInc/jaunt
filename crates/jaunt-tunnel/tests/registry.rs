mod support;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jaunt_tunnel::{
    ALPN_AGENT_API, ALPN_TUNNEL, ConnectionId, NodeId, OpenError, RegistryEvent, SendError,
    SessionId,
};
use rustls::version::TLS13;
use support::*;
use tokio::io::AsyncReadExt;

async fn started() -> (Pki, Leaf, TestGate) {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let auth = MapAuthenticator::new();
    auth.allow(&leaf, "node-a");
    let gate = TestGate::start(&pki, auth, GateOptions::default()).await;
    (pki, leaf, gate)
}

async fn registered_fake(
    gate: &mut TestGate,
    pki: &Pki,
    leaf: &Leaf,
) -> (FakeAgent, jaunt_tunnel::ConnectionId) {
    let mut fake = connect_fake_agent(gate.addr, pki, leaf, &[ALPN_TUNNEL]).await;
    let mut control = fake.accept_control().await;
    control.say_hello().await;
    assert_eq!(
        control.next_line().await.as_deref(),
        Some(r#"{"type":"welcome"}"#)
    );
    let id = wait_connected(gate, "node-a").await;
    fake.control = Some(control);
    (fake, id)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_peer_is_closed_and_registers_nothing() {
    let pki = Pki::new("ca");
    let stranger = pki.client_leaf("stranger");
    for alpn in [ALPN_TUNNEL, ALPN_AGENT_API] {
        let mut gate = TestGate::start(&pki, MapAuthenticator::new(), GateOptions::default()).await;
        let config = raw_client_config(pki.roots(), Some(&stranger), &[&TLS13], &[alpn]);
        let mut client = tls_connect(gate.addr, config, dns_name(AGENT_SNI))
            .await
            .unwrap();
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), client.read(&mut byte))
            .await
            .unwrap();
        assert!(!matches!(read, Ok(count) if count > 0), "{alpn:?}");
        assert_eq!(gate.stats.snapshot().auth_rejections, 1);
        assert!(gate.registry.connected_nodes().is_empty());
        assert!(gate.api.try_recv().is_err());
        assert_eq!(gate.stats.snapshot().tunnels_established, 0);
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_connection_of_the_same_node_replaces_the_first_with_goaway() {
    let (pki, leaf, mut gate) = started().await;
    let (first, first_id) = registered_fake(&mut gate, &pki, &leaf).await;
    let (mut second, second_id) = registered_fake(&mut gate, &pki, &leaf).await;
    assert_ne!(first_id, second_id);

    eventually("goaway on the replaced connection", || first.goaway_seen()).await;
    assert_eq!(*first.goaway_codes.lock().unwrap(), [0]);
    eventually("the replaced connection to close", || {
        first.closed.load(Ordering::SeqCst)
    })
    .await;
    assert_eq!(gate.registry.connected_nodes(), [node("node-a")]);
    assert!(!second.goaway_seen());

    let registry = gate.registry.clone();
    let opening =
        tokio::spawn(async move { registry.open_stream(&node("node-a"), &meta("s1")).await });
    let (request, mut respond) = second.next_request().await;
    assert_eq!(request.uri().path(), "/v1/stream");
    let _send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    opening.await.unwrap().unwrap();
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_ends_open_streams_and_closes_with_goaway() {
    let (pki, leaf, mut gate) = started().await;
    let (mut fake, id) = registered_fake(&mut gate, &pki, &leaf).await;
    let registry = gate.registry.clone();
    let opening =
        tokio::spawn(async move { registry.open_stream(&node("node-a"), &meta("s1")).await });
    let (_request, mut respond) = fake.next_request().await;
    let _send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    let mut io = opening.await.unwrap().unwrap();

    assert!(gate.registry.disconnect(&node("node-a")));
    assert!(!gate.registry.disconnect(&node("node-a")));
    let mut byte = [0_u8; 1];
    let error = io.read(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

    eventually("goaway after disconnect", || fake.goaway_seen()).await;
    eventually("the connection to close", || {
        fake.closed.load(Ordering::SeqCst)
    })
    .await;
    next_event(&mut gate.events, "the disconnect to be reported", |event| {
        matches!(event, RegistryEvent::Disconnected { connection, .. } if *connection == id)
    })
    .await;
    assert!(gate.registry.connected_nodes().is_empty());
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutting_the_gate_down_sends_goaway_to_connected_agents() {
    let (pki, leaf, mut gate) = started().await;
    let (fake, _) = registered_fake(&mut gate, &pki, &leaf).await;
    let registry = gate.registry.clone();
    gate.stop().await;
    eventually("goaway on shutdown", || fake.goaway_seen()).await;
    eventually("the connection to close", || {
        fake.closed.load(Ordering::SeqCst)
    })
    .await;
    eventually("the registry to empty", || {
        registry.connected_nodes().is_empty()
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn operations_on_an_unknown_node_fail_without_side_effects() {
    let (_pki, _leaf, gate) = started().await;
    let missing = node("nobody");
    let session = SessionId::new("s1").unwrap();
    let opened = gate.registry.open_stream(&missing, &meta("s1")).await;
    assert_eq!(opened.unwrap_err(), OpenError::NotConnected);
    assert_eq!(
        gate.registry.terminate_session(&missing, &session),
        Err(SendError::NotConnected)
    );
    assert_eq!(
        gate.registry.send_trust_update(&missing),
        Err(SendError::NotConnected)
    );
    assert!(!gate.registry.disconnect(&missing));
    assert!(gate.registry.connected_nodes().is_empty());
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn subscribers_see_replacements_and_endings_in_a_consistent_per_node_order() {
    let (pki, leaf, mut gate) = started().await;
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut events = gate.registry.subscribe();
    let sink = log.clone();
    let observer = tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            sink.lock().unwrap().push(event);
        }
    });
    let (first, a) = registered_fake(&mut gate, &pki, &leaf).await;
    let (second, b) = registered_fake(&mut gate, &pki, &leaf).await;
    let (third, c) = registered_fake(&mut gate, &pki, &leaf).await;
    eventually("the replaced connections to close", || {
        first.closed.load(Ordering::SeqCst) && second.closed.load(Ordering::SeqCst)
    })
    .await;
    assert!(gate.registry.disconnect(&node("node-a")));
    eventually("the last event", || log.lock().unwrap().len() == 4).await;
    eventually("the last connection to close", || {
        third.closed.load(Ordering::SeqCst)
    })
    .await;

    let events = log.lock().unwrap().clone();
    let node_a = node("node-a");
    assert_eq!(
        events,
        [
            RegistryEvent::Connected {
                node: node_a.clone(),
                connection: a
            },
            RegistryEvent::Replaced {
                node: node_a.clone(),
                previous: a,
                connection: b
            },
            RegistryEvent::Replaced {
                node: node_a.clone(),
                previous: b,
                connection: c
            },
            RegistryEvent::Disconnected {
                node: node_a,
                connection: c
            },
        ]
    );

    let mut tracked: HashMap<NodeId, ConnectionId> = HashMap::new();
    for event in events {
        match event {
            RegistryEvent::Connected { node, connection } => {
                assert_eq!(tracked.insert(node, connection), None);
            }
            RegistryEvent::Replaced {
                node,
                previous,
                connection,
            } => assert_eq!(tracked.insert(node, connection), Some(previous)),
            RegistryEvent::Disconnected { node, connection } => {
                assert_eq!(tracked.remove(&node), Some(connection));
            }
        }
    }
    assert!(tracked.is_empty());
    observer.abort();
    gate.stop().await;
}
