mod support;

use std::sync::Arc;
use std::time::Duration;

use jaunt_tunnel::{
    AcceptorConfig, AgentRegistry, BackoffPolicy, ClientError, Gate, GateAcceptor, GateStats,
    Keepalive, MAX_HANDSHAKING_LIMIT, MAX_TIMER, OptionsError, RegisterError, TunnelClient,
    TunnelClientConfig, TunnelConnection, TunnelError, TunnelOptions, agent_client_config,
    agent_server_config, main_server_config,
};
use support::*;
use tokio_util::sync::CancellationToken;

fn acceptor_config(pki: &Pki) -> AcceptorConfig {
    let server = pki.server_leaf();
    let agent = agent_server_config(server.chain.clone(), server.key(), pki.roots()).unwrap();
    let main = main_server_config(server.chain.clone(), server.key()).unwrap();
    AcceptorConfig::new(vec![AGENT_SNI.to_owned()], Arc::new(agent), Arc::new(main))
}

fn client_config(pki: &Pki) -> TunnelClientConfig {
    let leaf = pki.client_leaf("node-a");
    let tls = agent_client_config(pki.roots(), leaf.chain.clone(), leaf.key()).unwrap();
    TunnelClientConfig::new(Arc::new(tls), "127.0.0.1:1", AGENT_SNI, "agent/1")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_acceptor_rejects_unusable_handshake_settings() {
    let pki = Pki::new("ca");
    let cases: [(&str, Duration, usize, OptionsError); 4] = [
        (
            "zero timeout",
            Duration::ZERO,
            8,
            OptionsError::HandshakeTimeout,
        ),
        (
            "endless timeout",
            Duration::MAX,
            8,
            OptionsError::HandshakeTimeout,
        ),
        (
            "no slots",
            Duration::from_secs(1),
            0,
            OptionsError::HandshakeLimit,
        ),
        (
            "absurd slots",
            Duration::from_secs(1),
            MAX_HANDSHAKING_LIMIT + 1,
            OptionsError::HandshakeLimit,
        ),
    ];
    for (name, timeout, slots, expected) in cases {
        let mut config = acceptor_config(&pki);
        config.handshake_timeout = timeout;
        config.max_handshaking = slots;
        let outcome = GateAcceptor::new(config, Arc::new(GateStats::default()));
        assert_eq!(outcome.err(), Some(expected), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_gate_rejects_invalid_tunnel_options() {
    let pki = Pki::new("ca");
    let cases: [(&str, TunnelOptions, OptionsError); 3] = [
        (
            "zero keepalive interval",
            TunnelOptions {
                keepalive: Keepalive {
                    interval: Duration::ZERO,
                    ..Keepalive::default()
                },
                ..TunnelOptions::default()
            },
            OptionsError::KeepaliveInterval,
        ),
        (
            "zero stream window",
            TunnelOptions {
                stream_window: 0,
                ..TunnelOptions::default()
            },
            OptionsError::StreamWindow,
        ),
        (
            "endless hello timeout",
            TunnelOptions {
                hello_timeout: MAX_TIMER + Duration::from_secs(1),
                ..TunnelOptions::default()
            },
            OptionsError::HelloTimeout,
        ),
    ];
    for (name, options, expected) in cases {
        let acceptor =
            GateAcceptor::new(acceptor_config(&pki), Arc::new(GateStats::default())).unwrap();
        let outcome = Gate::new(
            acceptor,
            AgentRegistry::new(),
            Arc::new(HangingAuthenticator),
            Arc::new(NoHandover),
            options,
        );
        assert_eq!(outcome.err(), Some(expected), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn establishing_a_tunnel_rejects_invalid_options() {
    let (gate_io, _agent_io) = tokio::io::duplex(1024);
    let options = TunnelOptions {
        max_concurrent_streams: 0,
        ..TunnelOptions::default()
    };
    let outcome = TunnelConnection::establish(gate_io, &options, &CancellationToken::new()).await;
    assert_eq!(
        outcome.err(),
        Some(TunnelError::InvalidOptions(OptionsError::StreamLimit))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_rejects_invalid_options_before_connecting() {
    let pki = Pki::new("ca");
    let mut zero_window = client_config(&pki);
    zero_window.options.connection_window = 0;
    let mut zero_backoff = client_config(&pki);
    zero_backoff.backoff = BackoffPolicy {
        initial: Duration::ZERO,
        ..BackoffPolicy::default()
    };
    let mut endless_backoff = client_config(&pki);
    endless_backoff.backoff = BackoffPolicy {
        max: Duration::MAX,
        ..BackoffPolicy::default()
    };
    let cases = [
        ("zero window", zero_window, OptionsError::ConnectionWindow),
        ("zero backoff", zero_backoff, OptionsError::BackoffInitial),
        ("endless backoff", endless_backoff, OptionsError::BackoffMax),
    ];
    for (name, config, expected) in cases {
        let outcome = TunnelClient::run(config, idle_handler(), CancellationToken::new()).await;
        assert_eq!(
            outcome,
            Err(ClientError::InvalidOptions(expected)),
            "{name}"
        );
    }
}

#[test]
fn registering_outside_a_runtime_returns_an_error_instead_of_panicking() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let connection = runtime.block_on(async {
        let (gate_io, agent_io) = tokio::io::duplex(64 * 1024);
        spawn_duplex_agent(agent_io);
        TunnelConnection::establish(
            gate_io,
            &TunnelOptions::default(),
            &CancellationToken::new(),
        )
        .await
        .unwrap()
    });
    let registry = AgentRegistry::new();
    let outcome = registry.register(node("node-a"), connection);
    assert_eq!(outcome, Err(RegisterError::NoRuntime));
    assert!(registry.connected_nodes().is_empty());
}

#[test]
fn establishing_outside_a_runtime_returns_an_error_instead_of_panicking() {
    let (gate_io, _agent_io) = tokio::io::duplex(1024);
    let outcome = block_on_without_runtime(TunnelConnection::establish(
        gate_io,
        &TunnelOptions::default(),
        &CancellationToken::new(),
    ));
    assert_eq!(outcome.err(), Some(TunnelError::NoRuntime));
}

#[test]
fn the_client_returns_an_error_outside_a_runtime_instead_of_panicking() {
    let pki = Pki::new("ca");
    let outcome = block_on_without_runtime(TunnelClient::run(
        client_config(&pki),
        idle_handler(),
        CancellationToken::new(),
    ));
    assert_eq!(outcome, Err(ClientError::NoRuntime));
}
