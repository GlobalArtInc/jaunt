mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jaunt_tunnel::{ALPN_AGENT_API, ALPN_TUNNEL, agent_client_config};
use rustls::HandshakeKind;
use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::{ClientConfig, SignatureScheme};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug)]
struct CertificateRequestRecorder(Arc<AtomicBool>);

impl ResolvesClientCert for CertificateRequestRecorder {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.0.store(true, Ordering::SeqCst);
        None
    }

    fn has_certs(&self) -> bool {
        true
    }
}

async fn gate_for(pki: &Pki, nodes: &[(&Leaf, &str)]) -> TestGate {
    let auth = MapAuthenticator::new();
    for (leaf, name) in nodes {
        auth.allow(leaf, name);
    }
    TestGate::start(pki, auth, GateOptions::default()).await
}

fn assert_nothing_handed_over(gate: &mut TestGate) {
    assert!(gate.registry.connected_nodes().is_empty());
    assert!(gate.main.try_recv().is_err());
    assert!(gate.api.try_recv().is_err());
    assert_eq!(gate.stats.snapshot().tunnels_established, 0);
}

async fn read_is_refused(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> bool {
    let mut byte = [0_u8; 1];
    !matches!(stream.read(&mut byte).await, Ok(count) if count > 0)
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_sni_with_a_valid_certificate_reaches_the_tunnel_path() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let mut gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
    let agent = spawn_agent(
        gate.addr,
        &pki,
        &leaf,
        idle_handler(),
        AgentOptions::default(),
    );
    wait_connected(&mut gate, "node-a").await;
    assert_eq!(gate.registry.connected_nodes(), [node("node-a")]);
    assert_eq!(gate.stats.snapshot().tunnels_established, 1);
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_sni_with_an_api_alpn_hands_over_the_stream_and_identity() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let mut gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
    let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_AGENT_API]);
    let _client = tls_connect(gate.addr, config, dns_name(AGENT_SNI))
        .await
        .unwrap();
    let handed = tokio::time::timeout(Duration::from_secs(10), gate.api.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(handed.node, node("node-a"));
    assert_eq!(handed.peer_cert.as_ref(), leaf.der().as_slice());
    assert!(gate.registry.connected_nodes().is_empty());
    assert_eq!(gate.stats.snapshot().agent_api_handed_over, 1);
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_sni_without_a_valid_client_certificate_is_refused() {
    let pki = Pki::new("ca");
    let foreign_pki = Pki::new("foreign ca");
    let known = pki.client_leaf("node-a");
    let foreign = foreign_pki.client_leaf("node-a");
    let cases: [(&str, Option<&Leaf>); 2] =
        [("no certificate", None), ("foreign ca", Some(&foreign))];
    for (name, leaf) in cases {
        let mut gate = gate_for(&pki, &[(&known, "node-a")]).await;
        let config = raw_client_config(pki.roots(), leaf, &[&TLS13], &[ALPN_TUNNEL]);
        if let Ok(mut stream) = tls_connect(gate.addr, config, dns_name(AGENT_SNI)).await {
            assert!(read_is_refused(&mut stream).await, "{name}");
        }
        eventually("handshake failure to be counted", || {
            gate.stats.snapshot().handshake_failures == 1
        })
        .await;
        assert_nothing_handed_over(&mut gate);
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn other_sni_reaches_the_main_path_and_requests_no_client_certificate() {
    let pki = Pki::new("ca");
    let names = [dns_name(MAIN_SNI), ip_name("127.0.0.1".parse().unwrap())];
    for name in names {
        let mut gate = gate_for(&pki, &[]).await;
        let requested = Arc::new(AtomicBool::new(false));
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_root_certificates(pki.roots())
                .with_client_cert_resolver(Arc::new(CertificateRequestRecorder(requested.clone())));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let _client = tls_connect(gate.addr, Arc::new(config), name.clone())
            .await
            .unwrap();
        let handed = tokio::time::timeout(Duration::from_secs(10), gate.main.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(handed.stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        assert!(!requested.load(Ordering::SeqCst), "{name:?}");
        assert!(gate.registry.connected_nodes().is_empty());
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_1_2_clients_are_refused_on_both_paths() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    for sni in [AGENT_SNI, MAIN_SNI] {
        let mut gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
        let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS12], &[ALPN_TUNNEL]);
        let result = tls_connect(gate.addr, config, dns_name(sni)).await;
        assert!(result.is_err(), "{sni}");
        eventually("handshake failure to be counted", || {
            gate.stats.snapshot().handshake_failures == 1
        })
        .await;
        assert_nothing_handed_over(&mut gate);
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_sni_without_a_usable_alpn_is_closed() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let cases: [(&str, &[&[u8]]); 2] = [("h2 only", &[b"h2"]), ("no alpn", &[])];
    for (name, alpn) in cases {
        let mut gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
        let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], alpn);
        if let Ok(mut stream) = tls_connect(gate.addr, config, dns_name(AGENT_SNI)).await {
            assert!(read_is_refused(&mut stream).await, "{name}");
        }
        eventually("refusal to be counted", || {
            let stats = gate.stats.snapshot();
            stats.handshake_failures + stats.no_application_protocol == 1
        })
        .await;
        assert_nothing_handed_over(&mut gate);
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_beyond_the_handshake_cap_are_dropped() {
    let pki = Pki::new("ca");
    let options = GateOptions {
        handshake_timeout: Duration::from_secs(30),
        max_handshaking: 1,
        ..GateOptions::default()
    };
    let gate = TestGate::start(&pki, MapAuthenticator::new(), options).await;
    let _silent = TcpStream::connect(gate.addr).await.unwrap();
    eventually("the silent connection to occupy the slot", || {
        gate.gate.handshaking() == 1
    })
    .await;
    let mut extra = TcpStream::connect(gate.addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), extra.read(&mut byte))
        .await
        .unwrap();
    assert!(!matches!(read, Ok(count) if count > 0));
    assert_eq!(gate.stats.snapshot().refused_busy, 1);
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_connection_is_dropped_at_the_handshake_deadline() {
    let pki = Pki::new("ca");
    let options = GateOptions {
        handshake_timeout: Duration::from_millis(200),
        ..GateOptions::default()
    };
    let gate = TestGate::start(&pki, MapAuthenticator::new(), options).await;
    let mut silent = TcpStream::connect(gate.addr).await.unwrap();
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(10), silent.read(&mut byte))
        .await
        .unwrap();
    assert!(!matches!(read, Ok(count) if count > 0));
    assert_eq!(gate.stats.snapshot().handshake_timeouts, 1);
    eventually("the handshake slot to be released", || {
        gate.gate.handshaking() == 0
    })
    .await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_names_match_without_regard_to_case_or_a_trailing_dot() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_TUNNEL]);
    let hello = client_hello_bytes(config, dns_name(AGENT_SNI));
    let cases: [(&[u8], bool); 5] = [
        (b"agents.test", true),
        (b"AGENTS.TEST", true),
        (b"agents.test.", true),
        (b"Agents.Test.", true),
        (b"other.test", false),
    ];
    for (name, reaches_agent_path) in cases {
        let gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
        let mut tcp = TcpStream::connect(gate.addr).await.unwrap();
        tcp.write_all(&with_server_name(&hello, name))
            .await
            .unwrap();
        let mut flight = Vec::new();
        let outcome =
            tokio::time::timeout(Duration::from_millis(500), tcp.read_to_end(&mut flight)).await;
        let label = String::from_utf8_lossy(name);
        if reaches_agent_path {
            assert!(
                outcome.is_err(),
                "{label} was closed after {} bytes",
                flight.len()
            );
            assert_eq!(gate.stats.snapshot().handshake_failures, 0, "{label}");
        } else {
            assert!(outcome.is_ok(), "{label} was left waiting for a client");
            assert_eq!(gate.stats.snapshot().handshake_failures, 1, "{label}");
        }
        gate.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_goes_silent_after_the_client_hello_hits_the_deadline() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let options = GateOptions {
        handshake_timeout: Duration::from_secs(1),
        ..GateOptions::default()
    };
    let gate = TestGate::start(&pki, MapAuthenticator::new(), options).await;
    let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_TUNNEL]);
    let hello = client_hello_bytes(config, dns_name(AGENT_SNI));
    let mut tcp = TcpStream::connect(gate.addr).await.unwrap();
    tcp.write_all(&hello).await.unwrap();
    eventually("the server to start the handshake", || {
        gate.gate.handshaking() == 1
    })
    .await;
    eventually("the timeout to be counted", || {
        gate.stats.snapshot().handshake_timeouts == 1
    })
    .await;
    eventually("the handshake slot to be released", || {
        gate.gate.handshaking() == 0
    })
    .await;
    soon("the server to close the socket", async {
        let mut sink = [0_u8; 4096];
        while matches!(tcp.read(&mut sink).await, Ok(count) if count > 0) {}
    })
    .await;
    assert_eq!(gate.stats.snapshot().handshake_failures, 0);
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_authenticator_that_never_answers_is_cut_off_at_the_handshake_timeout() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let options = GateOptions {
        handshake_timeout: Duration::from_millis(300),
        ..GateOptions::default()
    };
    let gate = TestGate::start(&pki, Arc::new(HangingAuthenticator), options).await;
    let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_TUNNEL]);
    let mut client = tls_connect(gate.addr, config, dns_name(AGENT_SNI))
        .await
        .unwrap();
    let started = Instant::now();
    let mut byte = [0_u8; 1];
    let read = soon("the server to give up", client.read(&mut byte)).await;
    assert!(!matches!(read, Ok(count) if count > 0));
    assert!(started.elapsed() >= Duration::from_millis(250));
    eventually("the rejection to be counted", || {
        gate.stats.snapshot().auth_rejections == 1
    })
    .await;
    eventually("the handshake slot to be released", || {
        gate.gate.handshaking() == 0
    })
    .await;
    assert!(gate.registry.connected_nodes().is_empty());
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_stuck_in_authentication_keep_their_handshake_slots() {
    const CAP: usize = 3;
    const PEERS: usize = 20;
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let options = GateOptions {
        handshake_timeout: Duration::from_secs(60),
        max_handshaking: CAP,
        ..GateOptions::default()
    };
    let gate = TestGate::start(&pki, Arc::new(HangingAuthenticator), options).await;
    let config = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_TUNNEL]);
    let mut admitted = Vec::new();
    let mut refused = 0;
    for _ in 0..PEERS {
        let attempt = tls_connect(gate.addr, config.clone(), dns_name(AGENT_SNI));
        match soon("a connection attempt", attempt).await {
            Ok(stream) => admitted.push(stream),
            Err(_) => refused += 1,
        }
    }
    assert_eq!(admitted.len(), CAP);
    assert_eq!(refused, PEERS - CAP);
    eventually("the refusals to be counted", || {
        gate.stats.snapshot().refused_busy == (PEERS - CAP) as u64
    })
    .await;
    assert_eq!(gate.gate.handshaking(), CAP);
    assert_eq!(gate.stats.snapshot().auth_rejections, 0);
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_helper_never_resumes_a_session_the_client_offers() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let mut gate = gate_for(&pki, &[(&leaf, "node-a")]).await;
    let offering = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_AGENT_API]);
    for round in 0..2 {
        let mut client = tls_connect(gate.addr, offering.clone(), dns_name(AGENT_SNI))
            .await
            .unwrap();
        let mut handed = soon("the hand over", gate.api.recv()).await.unwrap();
        let server_kind = handed.stream.get_ref().1.handshake_kind();
        assert_eq!(server_kind, Some(HandshakeKind::Full), "round {round}");
        handed.stream.write_all(b"x").await.unwrap();
        handed.stream.flush().await.unwrap();
        let mut greeting = [0_u8; 1];
        soon("the greeting", client.read_exact(&mut greeting))
            .await
            .unwrap();
        let client_kind = client.get_ref().1.handshake_kind();
        assert_eq!(client_kind, Some(HandshakeKind::Full), "round {round}");
    }
    let ticketing = start_ticket_server(&pki).await;
    let kinds = client_handshake_kinds(ticketing, offering, 2).await;
    assert_eq!(kinds, [HandshakeKind::Full, HandshakeKind::Resumed]);
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_helper_never_offers_a_session_for_resumption() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let ticketing = start_ticket_server(&pki).await;
    let mut helper = agent_client_config(pki.roots(), leaf.chain.clone(), leaf.key()).unwrap();
    helper.alpn_protocols = vec![ALPN_AGENT_API.to_vec()];
    let kinds = client_handshake_kinds(ticketing, Arc::new(helper), 2).await;
    assert_eq!(kinds, [HandshakeKind::Full, HandshakeKind::Full]);
    let offering = raw_client_config(pki.roots(), Some(&leaf), &[&TLS13], &[ALPN_AGENT_API]);
    let kinds = client_handshake_kinds(ticketing, offering, 2).await;
    assert_eq!(kinds, [HandshakeKind::Full, HandshakeKind::Resumed]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_main_helper_does_not_resume_sessions_and_negotiates_h2() {
    let pki = Pki::new("ca");
    let mut gate = gate_for(&pki, &[]).await;
    let offering = raw_client_config(pki.roots(), None, &[&TLS13], &[b"h2"]);
    for round in 0..2 {
        let mut client = tls_connect(gate.addr, offering.clone(), dns_name(MAIN_SNI))
            .await
            .unwrap();
        let mut handed = soon("the hand over", gate.main.recv()).await.unwrap();
        assert_eq!(handed.stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let server_kind = handed.stream.get_ref().1.handshake_kind();
        assert_eq!(server_kind, Some(HandshakeKind::Full), "round {round}");
        handed.stream.write_all(b"x").await.unwrap();
        handed.stream.flush().await.unwrap();
        let mut greeting = [0_u8; 1];
        soon("the greeting", client.read_exact(&mut greeting))
            .await
            .unwrap();
    }
    gate.stop().await;
}
