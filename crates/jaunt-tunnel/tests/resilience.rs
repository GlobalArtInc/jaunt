mod support;

use std::time::{Duration, Instant};

use jaunt_tunnel::{ClientEvent, Keepalive, RegistryEvent, TunnelOptions};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DETECTION_SLACK: Duration = Duration::from_secs(5);

fn tunnel_options(keepalive: Keepalive) -> TunnelOptions {
    TunnelOptions {
        keepalive,
        close_grace: Duration::from_millis(100),
        ..TunnelOptions::default()
    }
}

fn known_node() -> (Pki, Leaf, std::sync::Arc<MapAuthenticator>) {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let auth = MapAuthenticator::new();
    auth.allow(&leaf, "node-a");
    (pki, leaf, auth)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_stops_answering_pings_is_removed_from_the_registry() {
    let keepalive = Keepalive {
        interval: Duration::from_millis(100),
        timeout: Duration::from_millis(200),
    };
    let (pki, leaf, auth) = known_node();
    let gate_options = GateOptions {
        tunnel: tunnel_options(keepalive),
        ..GateOptions::default()
    };
    let mut gate = TestGate::start(&pki, auth, gate_options).await;
    let proxy = PausableProxy::start(gate.addr).await;
    let agent_options = AgentOptions {
        tunnel: tunnel_options(Keepalive::default()),
        ..AgentOptions::default()
    };
    let agent = spawn_agent(proxy.addr, &pki, &leaf, idle_handler(), agent_options);
    let id = wait_connected(&mut gate, "node-a").await;

    let paused_at = Instant::now();
    proxy.pause();
    next_event(&mut gate.events, "the silent peer to be dropped", |event| {
        matches!(event, RegistryEvent::Disconnected { connection, .. } if *connection == id)
    })
    .await;
    let detected_in = paused_at.elapsed();
    assert!(
        detected_in <= keepalive.interval + keepalive.timeout + DETECTION_SLACK,
        "detection took {detected_in:?}"
    );
    assert!(gate.registry.connected_nodes().is_empty());
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_reconnects_after_the_gate_drops_its_connection() {
    let (pki, leaf, auth) = known_node();
    let mut gate = TestGate::start(&pki, auth, GateOptions::default()).await;
    let mut agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        idle_handler(),
        AgentOptions::default(),
    );
    let first = wait_connected(&mut gate, "node-a").await;

    assert!(gate.registry.disconnect(&node("node-a")));
    next_event(&mut agent.events, "the agent to notice the drop", |event| {
        matches!(event, ClientEvent::Disconnected { .. })
    })
    .await;
    let second = wait_connected(&mut gate, "node-a").await;
    assert_ne!(first, second);
    assert_eq!(gate.registry.connected_nodes(), [node("node-a")]);
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_reconnects_after_the_gate_restarts_on_the_same_port() {
    let (pki, leaf, auth) = known_node();
    let mut gate = TestGate::start(&pki, auth.clone(), GateOptions::default()).await;
    let mut agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        idle_handler(),
        AgentOptions::default(),
    );
    wait_connected(&mut gate, "node-a").await;

    let addr = gate.stop().await;
    next_event(&mut agent.events, "the agent to lose the gate", |event| {
        matches!(event, ClientEvent::Disconnected { .. })
    })
    .await;
    next_event(
        &mut agent.events,
        "a retry against the dead port",
        |event| matches!(event, ClientEvent::ConnectFailed(_)),
    )
    .await;

    let mut restarted = TestGate::start_at(addr, &pki, auth, GateOptions::default()).await;
    wait_connected(&mut restarted, "node-a").await;
    assert_eq!(restarted.registry.connected_nodes(), [node("node-a")]);
    agent.stop().await;
    restarted.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn no_task_outlives_a_closed_tunnel() {
    let (pki, leaf, auth) = known_node();
    let mut gate = TestGate::start(&pki, auth, GateOptions::default()).await;
    let agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        echo_handler(),
        AgentOptions::default(),
    );
    wait_connected(&mut gate, "node-a").await;
    let mut io = gate
        .registry
        .open_stream(&node("node-a"), &meta("s1"))
        .await
        .unwrap();
    io.write_all(b"x").await.unwrap();
    let mut echoed = [0_u8; 1];
    io.read_exact(&mut echoed).await.unwrap();
    let metrics = tokio::runtime::Handle::current().metrics();
    assert!(metrics.num_alive_tasks() > 0);

    agent.stop().await;
    gate.stop().await;
    drop(io);
    eventually("every spawned task to finish", || {
        metrics.num_alive_tasks() == 0
    })
    .await;
}
