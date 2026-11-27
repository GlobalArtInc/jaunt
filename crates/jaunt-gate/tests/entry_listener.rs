mod support;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use jaunt_gate::{ALPN_SSH, AgentHub, AgentHubConfig, HubError, ServicesEntry, TlsRefusal};
use jaunt_limits::{AddressLimits, Rate};
use jaunt_tunnel::{ALPN_AGENT_API, ALPN_TUNNEL, GateStatsSnapshot};
use rustls::pki_types::ServerName;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const GRACE: Duration = Duration::from_secs(5);
const DOMAIN: &str = "svc.test";
const PROXY_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

fn allowing(pki: &Pki) -> (Arc<Verdicts>, Leaf) {
    let verdicts = Arc::new(Verdicts::default());
    let leaf = pki.client_leaf("node-a");
    verdicts.allow(&leaf, "node-a");
    (verdicts, leaf)
}

fn name(text: &str) -> ServerName<'static> {
    ServerName::try_from(text.to_owned()).unwrap()
}

fn tls_refusals() -> Vec<String> {
    audit_events()
        .into_iter()
        .filter(|event| field(event, "event") == "gate.tls.refused")
        .map(|event| field(&event, "reason").to_owned())
        .collect()
}

async fn closed_after_garbage(addr: SocketAddr) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: agents.test\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    drop(within("the garbage to be closed", tcp.read_to_end(&mut rest)).await);
}

async fn run_the_same_connections(test: &mut TestHub, pki: &Pki, leaf: &Leaf) -> String {
    let api = dial(test.addr, pki, Some(leaf), agent_name(), &[ALPN_AGENT_API]).await;
    let stream = api.stream.unwrap();
    let session = within("the api session", test.sessions.recv())
        .await
        .unwrap();
    assert_eq!(session.node, node("node-a"));
    drop(stream);
    let refusals: [(ServerName<'static>, &[u8]); 3] = [
        (name(OTHER_SNI), ALPN_TUNNEL),
        (ServerName::IpAddress(test.addr.ip().into()), ALPN_TUNNEL),
        (agent_name(), b"h2"),
    ];
    for (server_name, alpn) in refusals {
        let dialed = dial(test.addr, pki, Some(leaf), server_name.clone(), &[alpn]).await;
        assert!(refused(dialed).await, "{server_name:?}");
    }
    let anonymous = dial(test.addr, pki, None, agent_name(), &[ALPN_TUNNEL]).await;
    let remote = anonymous.local_addr.to_string();
    assert!(refused(anonymous).await);
    let rejected = audited("agent.rejected", |event| {
        field(event, "event") == "agent.rejected" && field(event, "remote_addr") == remote
    })
    .await;
    closed_after_garbage(test.addr).await;
    field(&rejected, "reason").to_owned()
}

#[tokio::test]
async fn without_a_services_domain_the_listener_keeps_its_old_answers_counters_and_events() {
    let pki = Pki::new("ca");
    let (verdicts, leaf) = allowing(&pki);
    let mut test = start_hub(&pki, verdicts, HubOptions::default()).await;
    assert_eq!(test.hub.services_domain(), None);
    let rejected = run_the_same_connections(&mut test, &pki, &leaf).await;
    assert_eq!(rejected, "no_certificate");
    let expected = GateStatsSnapshot {
        handshake_failures: 5,
        agent_api_handed_over: 1,
        ..GateStatsSnapshot::default()
    };
    eventually("the old counters", || {
        test.hub.stats().snapshot() == expected
    })
    .await;
    assert_eq!(test.hub.hub_stats().no_certificate, 1);
    for reason in TlsRefusal::ALL {
        assert_eq!(test.hub.tls_refused(reason), 0, "{reason:?}");
    }
    assert!(tls_refusals().is_empty());
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn with_a_services_domain_agents_keep_their_path_and_other_names_are_refused_at_the_entry() {
    let pki = Pki::new("ca");
    let (verdicts, leaf) = allowing(&pki);
    let options = HubOptions {
        services: Some(ServicesEntry::new(DOMAIN)),
        ..HubOptions::default()
    };
    let mut test = start_hub(&pki, verdicts, options).await;
    assert_eq!(test.hub.services_domain(), Some(DOMAIN));
    let rejected = run_the_same_connections(&mut test, &pki, &leaf).await;
    assert_eq!(rejected, "no_certificate");
    let expected = GateStatsSnapshot {
        handshake_failures: 2,
        agent_api_handed_over: 1,
        ..GateStatsSnapshot::default()
    };
    eventually("the entry refusals", || {
        test.hub.tls_refused(TlsRefusal::BadHello) == 1
    })
    .await;
    assert_eq!(test.hub.stats().snapshot(), expected);
    assert_eq!(test.hub.tls_refused(TlsRefusal::UnknownSni), 1);
    assert_eq!(test.hub.tls_refused(TlsRefusal::NoSni), 1);
    assert_eq!(tls_refusals(), ["unknown_sni", "no_sni", "bad_hello"]);

    for (server_name, alpn) in [
        (DOMAIN.to_owned(), ALPN_SSH),
        (format!("prod.kube.{DOMAIN}"), &b"h2"[..]),
        (DOMAIN.to_owned(), &b"h2"[..]),
    ] {
        let dialed = dial(test.addr, &pki, None, name(&server_name), &[alpn]).await;
        assert!(refused(dialed).await, "{server_name}");
    }
    assert_eq!(test.hub.tls_refused(TlsRefusal::UnsupportedClass), 2);
    assert_eq!(test.hub.tls_refused(TlsRefusal::AlpnUnsupported), 1);
    assert_eq!(test.hub.stats().snapshot(), expected);

    let agent = spawn_agent(test.addr, &pki, &leaf);
    eventually("the tunnel through the entry", || {
        test.hub.registry().is_connected(&node("node-a"))
    })
    .await;
    assert_eq!(test.hub.stats().snapshot().tunnels_established, 1);
    agent.stop().await;
    test.hub.shutdown(GRACE).await;
}

fn proxy_header(client: [u8; 4], port: u16) -> Vec<u8> {
    let mut payload = client.to_vec();
    payload.extend([127, 0, 0, 1]);
    payload.extend(port.to_be_bytes());
    payload.extend(8444_u16.to_be_bytes());
    let len = u16::try_from(payload.len()).unwrap().to_be_bytes();
    [PROXY_SIGNATURE, &[0x21, 0x11], &len, &payload].concat()
}

async fn proxied(addr: SocketAddr, client: [u8; 4], port: u16) -> TcpStream {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&proxy_header(client, port)).await.unwrap();
    tcp
}

fn behind_proxies(networks: &str, concurrent: usize) -> HubOptions {
    HubOptions {
        services: Some(ServicesEntry {
            proxy_protocol: true,
            trusted_proxies: vec![networks.parse().unwrap()],
            ..ServicesEntry::new(DOMAIN)
        }),
        client_limits: AddressLimits {
            rate: Rate::new(100, 100).unwrap(),
            concurrent,
            tracked: 16,
        },
        ..HubOptions::default()
    }
}

#[tokio::test]
async fn behind_a_trusted_proxy_the_header_names_the_agent_and_feeds_the_per_address_limit() {
    let pki = Pki::new("ca");
    let (verdicts, leaf) = allowing(&pki);
    let mut test = start_hub(&pki, verdicts, behind_proxies("127.0.0.0/8", 1)).await;

    let tcp = proxied(test.addr, [203, 0, 113, 7], 51000).await;
    let api = dial_over(tcp, &pki, Some(&leaf), agent_name(), &[ALPN_AGENT_API]).await;
    let stream = api.stream.unwrap();
    within("the api session", test.sessions.recv())
        .await
        .unwrap();
    let connected = audited("agent.connected", |event| {
        field(event, "event") == "agent.connected"
    })
    .await;
    assert_eq!(field(&connected, "remote_addr"), "203.0.113.7:51000");
    drop(stream);

    let bare = dial(
        test.addr,
        &pki,
        Some(&leaf),
        agent_name(),
        &[ALPN_AGENT_API],
    )
    .await;
    assert!(refused(bare).await);
    assert_eq!(test.hub.tls_refused(TlsRefusal::ProxyMalformed), 1);

    let _silent = proxied(test.addr, [203, 0, 113, 9], 52000).await;
    eventually("the silent client to hold its slot", || {
        test.hub.entry_handshaking() == 1
    })
    .await;
    let mut same = proxied(test.addr, [203, 0, 113, 9], 52001).await;
    let mut rest = Vec::new();
    within("the second connection of one client to close", async {
        drop(same.read_to_end(&mut rest).await);
    })
    .await;
    assert_eq!(test.hub.tls_refused(TlsRefusal::Limit), 1);
    let other = proxied(test.addr, [203, 0, 113, 10], 52002).await;
    let api = dial_over(other, &pki, Some(&leaf), agent_name(), &[ALPN_AGENT_API]).await;
    assert!(api.stream.is_ok());
    within("the other client's session", test.sessions.recv())
        .await
        .unwrap();
    assert_eq!(test.hub.tls_refused(TlsRefusal::Limit), 1);
    test.hub.shutdown(GRACE).await;

    let untrusting = start_hub(
        &pki,
        Arc::new(Verdicts::default()),
        behind_proxies("10.0.0.0/8", 8),
    )
    .await;
    let tcp = proxied(untrusting.addr, [203, 0, 113, 7], 51000).await;
    let refused_peer = dial_over(tcp, &pki, Some(&leaf), agent_name(), &[ALPN_AGENT_API]).await;
    assert!(refused(refused_peer).await);
    assert_eq!(untrusting.hub.tls_refused(TlsRefusal::ProxyUntrusted), 1);
    untrusting.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn an_invalid_services_entry_stops_the_hub_before_it_serves() {
    let invalid = [
        ServicesEntry::new(AGENT_SNI),
        ServicesEntry::new("*.svc.test"),
        ServicesEntry {
            proxy_protocol: true,
            ..ServicesEntry::new(DOMAIN)
        },
    ];
    for services in invalid {
        let mut config = AgentHubConfig::new(
            AGENT_SNI,
            Arc::new(jaunt_tunnel::refusing_server_config().unwrap()),
        );
        config.services = Some(services.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let started = AgentHub::start(
            listener,
            config,
            Arc::new(Verdicts::default()),
            Arc::new(Unused),
        );
        assert!(
            matches!(started, Err(HubError::Entry(_))),
            "{}",
            services.domain
        );
    }
}

#[tokio::test]
async fn the_hub_hands_its_handshake_budget_and_timeout_to_the_entry() {
    let pki = Pki::new("ca");
    let options = HubOptions {
        services: Some(ServicesEntry::new(DOMAIN)),
        max_handshaking: 1,
        handshake_timeout: Duration::from_secs(4),
        ..HubOptions::default()
    };
    let test = start_hub(&pki, Arc::new(Verdicts::default()), options).await;
    let started = tokio::time::Instant::now();
    let _silent = TcpStream::connect(test.addr).await.unwrap();
    eventually("the silent client to hold the only handshake", || {
        test.hub.entry_handshaking() == 1
    })
    .await;
    let _second = TcpStream::connect(test.addr).await.unwrap();
    eventually("the second client to be refused", || {
        test.hub.tls_refused(TlsRefusal::Limit) == 1
    })
    .await;
    eventually_within(
        "the silent client to time out",
        Duration::from_secs(20),
        || test.hub.tls_refused(TlsRefusal::HelloTimeout) == 1,
    )
    .await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(30),
        "{elapsed:?}"
    );
    test.hub.shutdown(GRACE).await;
}

#[tokio::test]
async fn the_hub_hands_the_kube_limits_to_the_entry() {
    let pki = Pki::new("ca");
    let options = HubOptions {
        services: Some(ServicesEntry {
            kube_limits: AddressLimits {
                rate: Rate::new(1, 1).unwrap(),
                concurrent: 8,
                tracked: 16,
            },
            ..ServicesEntry::new(DOMAIN)
        }),
        ..HubOptions::default()
    };
    let test = start_hub(&pki, Arc::new(Verdicts::default()), options).await;
    for _ in 0..2 {
        let cluster = name(&format!("prod.kube.{DOMAIN}"));
        let dialed = dial(test.addr, &pki, None, cluster, &[b"h2"]).await;
        assert!(refused(dialed).await);
    }
    assert_eq!(test.hub.tls_refused(TlsRefusal::UnsupportedClass), 1);
    assert_eq!(test.hub.tls_refused(TlsRefusal::Limit), 1);
    test.hub.shutdown(GRACE).await;
}
