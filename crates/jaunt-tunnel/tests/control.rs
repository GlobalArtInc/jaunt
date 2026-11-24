mod support;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jaunt_tunnel::{
    ALPN_TUNNEL, BoxFuture, IncomingStream, MAX_CONTROL_MESSAGE_BYTES, RegistryEvent, SessionId,
    StreamHandler, TunnelOptions,
};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn gate_options(hello_timeout: Duration) -> GateOptions {
    GateOptions {
        tunnel: TunnelOptions {
            hello_timeout,
            ..TunnelOptions::default()
        },
        ..GateOptions::default()
    }
}

async fn started(options: GateOptions) -> (Pki, Leaf, TestGate) {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let auth = MapAuthenticator::new();
    auth.allow(&leaf, "node-a");
    let gate = TestGate::start(&pki, auth, options).await;
    (pki, leaf, gate)
}

#[tokio::test(flavor = "multi_thread")]
async fn hello_is_answered_with_welcome_and_only_then_the_agent_is_registered() {
    let (pki, leaf, mut gate) = started(GateOptions::default()).await;
    let mut fake = connect_fake_agent(gate.addr, &pki, &leaf, &[ALPN_TUNNEL]).await;
    let mut control = fake.accept_control().await;
    assert!(gate.registry.connected_nodes().is_empty());
    control.say_hello().await;
    assert_eq!(
        control.next_line().await.as_deref(),
        Some(r#"{"type":"welcome"}"#)
    );
    wait_connected(&mut gate, "node-a").await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_hello_closes_the_connection_and_registers_nothing() {
    let (pki, leaf, gate) = started(gate_options(Duration::from_millis(300))).await;
    let mut fake = connect_fake_agent(gate.addr, &pki, &leaf, &[ALPN_TUNNEL]).await;
    let _silent = fake.accept_control().await;
    eventually("the connection to be closed", || {
        fake.closed.load(Ordering::SeqCst)
    })
    .await;
    eventually("the setup failure to be counted", || {
        gate.stats.snapshot().tunnel_setup_failures == 1
    })
    .await;
    assert!(gate.registry.connected_nodes().is_empty());
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_first_messages_close_the_connection_and_register_nothing() {
    let oversized = format!(
        r#"{{"type":"hello","version":1,"agent_version":"{}"}}"#,
        "v".repeat(MAX_CONTROL_MESSAGE_BYTES)
    );
    let cases: [(&str, String); 7] = [
        ("not json", "not json".to_owned()),
        ("oversized", oversized),
        (
            "unsupported version",
            r#"{"type":"hello","version":2,"agent_version":"fake/1"}"#.to_owned(),
        ),
        (
            "unknown field",
            r#"{"type":"hello","version":1,"agent_version":"fake/1","extra":1}"#.to_owned(),
        ),
        (
            "bad agent version",
            r#"{"type":"hello","version":1,"agent_version":"has space"}"#.to_owned(),
        ),
        ("unknown type", r#"{"type":"goodbye"}"#.to_owned()),
        (
            "welcome instead of hello",
            r#"{"type":"welcome"}"#.to_owned(),
        ),
    ];
    for (name, line) in cases {
        let (pki, leaf, gate) = started(GateOptions::default()).await;
        let mut fake = connect_fake_agent(gate.addr, &pki, &leaf, &[ALPN_TUNNEL]).await;
        let mut control = fake.accept_control().await;
        control.send_line(&line).await;
        eventually("the connection to be closed", || {
            fake.closed.load(Ordering::SeqCst)
        })
        .await;
        eventually(
            &format!("the setup failure of {name} to be counted"),
            || gate.stats.snapshot().tunnel_setup_failures == 1,
        )
        .await;
        assert!(gate.registry.connected_nodes().is_empty(), "{name}");
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bad_message_after_hello_closes_a_registered_connection() {
    let cases: [(&str, &[u8]); 3] = [
        (
            "second hello",
            br#"{"type":"hello","version":1,"agent_version":"fake/1"}"#,
        ),
        ("malformed", b"{broken"),
        ("unknown type", br#"{"type":"nope"}"#),
    ];
    for (name, line) in cases {
        let (pki, leaf, mut gate) = started(GateOptions::default()).await;
        let mut fake = connect_fake_agent(gate.addr, &pki, &leaf, &[ALPN_TUNNEL]).await;
        let mut control = fake.accept_control().await;
        control.say_hello().await;
        let id = wait_connected(&mut gate, "node-a").await;
        control.send_raw(line).await;
        control.send_raw(b"\n").await;
        next_event(&mut gate.events, "the connection to be dropped", |event| {
            matches!(event, RegistryEvent::Disconnected { connection, .. } if *connection == id)
        })
        .await;
        assert!(gate.registry.connected_nodes().is_empty(), "{name}");
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_message_after_hello_closes_a_registered_connection() {
    let (pki, leaf, mut gate) = started(GateOptions::default()).await;
    let mut fake = connect_fake_agent(gate.addr, &pki, &leaf, &[ALPN_TUNNEL]).await;
    let mut control = fake.accept_control().await;
    control.say_hello().await;
    let id = wait_connected(&mut gate, "node-a").await;
    control
        .send_raw("x".repeat(MAX_CONTROL_MESSAGE_BYTES + 1).as_bytes())
        .await;
    control.send_raw(b"\n").await;
    next_event(&mut gate.events, "the connection to be dropped", |event| {
        matches!(event, RegistryEvent::Disconnected { connection, .. } if *connection == id)
    })
    .await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminate_session_resets_exactly_that_stream() {
    let (pki, leaf, mut gate) = started(GateOptions::default()).await;
    let agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        echo_handler(),
        AgentOptions::default(),
    );
    wait_connected(&mut gate, "node-a").await;
    let mut doomed = gate
        .registry
        .open_stream(&node("node-a"), &meta("doomed"))
        .await
        .unwrap();
    let mut spared = gate
        .registry
        .open_stream(&node("node-a"), &meta("spared"))
        .await
        .unwrap();
    for (io, text) in [(&mut doomed, "one"), (&mut spared, "two")] {
        io.write_all(text.as_bytes()).await.unwrap();
        let mut echoed = vec![0_u8; text.len()];
        io.read_exact(&mut echoed).await.unwrap();
    }

    gate.registry
        .terminate_session(&node("node-a"), &SessionId::new("doomed").unwrap())
        .unwrap();
    let mut byte = [0_u8; 1];
    let error = doomed.read(&mut byte).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    eventually("only the spared session to remain", || {
        agent.sessions.active() == [SessionId::new("spared").unwrap()]
    })
    .await;

    spared.write_all(b"still here").await.unwrap();
    let mut echoed = vec![0_u8; 10];
    spared.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"still here");
    assert_eq!(gate.registry.connected_nodes(), [node("node-a")]);
    agent.stop().await;
    gate.stop().await;
}

struct TrustCounter(Arc<AtomicUsize>);

impl StreamHandler for TrustCounter {
    fn handle(&self, _stream: IncomingStream) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn trust_update(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trust_update_reaches_the_agent_handler() {
    let (pki, leaf, mut gate) = started(GateOptions::default()).await;
    let updates = Arc::new(AtomicUsize::new(0));
    let agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        Arc::new(TrustCounter(updates.clone())),
        AgentOptions::default(),
    );
    wait_connected(&mut gate, "node-a").await;
    gate.registry.send_trust_update(&node("node-a")).unwrap();
    eventually("the trust update to arrive", || {
        updates.load(Ordering::SeqCst) == 1
    })
    .await;
    agent.stop().await;
    gate.stop().await;
}
