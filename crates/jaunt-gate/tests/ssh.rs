mod support;

#[path = "ssh/fixture.rs"]
mod fixture;

use std::sync::Arc;
use std::time::{Duration, Instant};

use fixture::{
    Client, DENIED_TEXT, FakeControl, Fixture, GATE_NAME, LIMIT_TEXT, STEP, TestClock, USER_ID,
    Verdict, echo_once, key,
};
use jaunt_gate::{
    HostCertError, HostCertIssuer, IssueError, SshGate, SshGateConfig, SshGateError,
    TerminationReason, TrustedProxyProblem,
};
use jaunt_proto::BoxFuture;
use jaunt_ssh::{UserCaKeys, UserCaSource};
use jaunt_tunnel::AgentRegistry;
use russh::Disconnect;
use support::{audited, eventually, field};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

fn proxy_tcp4(client: [u8; 4], port: u16) -> Vec<u8> {
    let mut header = SIGNATURE.to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&client);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&2222_u16.to_be_bytes());
    header
}

fn proxy_local() -> Vec<u8> {
    let mut header = SIGNATURE.to_vec();
    header.extend_from_slice(&[0x20, 0x00, 0, 0]);
    header
}

async fn closed_without_a_word(mut tcp: TcpStream) -> bool {
    let mut buffer = [0_u8; 256];
    let read = tokio::time::timeout(STEP, tcp.read(&mut buffer))
        .await
        .expect("the gate kept the connection open");
    !matches!(read, Ok(count) if count > 0)
}

async fn banner(tcp: &mut TcpStream) -> String {
    let mut buffer = [0_u8; 64];
    let read = tokio::time::timeout(STEP, tcp.read(&mut buffer))
        .await
        .expect("no banner arrived")
        .unwrap();
    String::from_utf8_lossy(&buffer[..read]).into_owned()
}

fn behind_proxy(config: &mut SshGateConfig) {
    config.proxy_protocol = true;
    config.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
}

#[tokio::test(flavor = "multi_thread")]
async fn streams_per_user_and_node_stop_at_eight_and_every_end_returns_its_slot() {
    let fixture = Fixture::start(|_| {}).await;
    let first = fixture.login().await;
    let (second, socket) = {
        let tcp = TcpStream::connect(fixture.addr).await.unwrap();
        let socket = tcp.into_std().unwrap();
        let killer = socket.try_clone().unwrap();
        let mut client = Client::over(TcpStream::from_std(socket).unwrap())
            .await
            .unwrap();
        assert!(client.login(&fixture.user_ca).await);
        (client, killer)
    };
    let mut on_first = Vec::new();
    for _ in 0..5 {
        on_first.push(first.open_node().await.unwrap());
    }
    let mut on_second = Vec::new();
    for _ in 0..3 {
        on_second.push(second.open_node().await.unwrap());
    }
    assert_eq!(fixture.gate.open_streams(), 8);
    let refused = second.open_node().await.unwrap_err();
    assert_eq!(refused.1, LIMIT_TEXT);
    assert_eq!(fixture.control.seen().len(), 8);

    let mut closing = on_first.remove(0);
    echo_once(&mut closing, b"ping").await;
    closing.close().await.unwrap();
    eventually("a closed channel to return its slot", || {
        fixture.gate.open_streams() == 7
    })
    .await;

    socket.shutdown(std::net::Shutdown::Both).unwrap();
    eventually("a killed client to return its slots", || {
        fixture.gate.open_streams() == 4
    })
    .await;
    drop((on_second, second));

    let mut replacement = first.open_node().await.unwrap();
    echo_once(&mut replacement, b"again").await;
    assert_eq!(fixture.gate.open_streams(), 5);
    first
        .handle
        .disconnect(Disconnect::ByApplication, "bye", "en")
        .await
        .unwrap();
    eventually("a disconnected client to return its slots", || {
        fixture.gate.open_streams() == 0
    })
    .await;
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn deny_failure_and_an_absent_node_look_the_same_to_the_user() {
    let fixture = Fixture::start(|_| {}).await;
    let client = fixture.login().await;
    let mut seen = Vec::new();
    for verdict in [Verdict::Deny, Verdict::Fail, Verdict::AllowAbsentNode] {
        fixture.control.set(verdict);
        let (code, text) = client.open_node().await.unwrap_err();
        assert_eq!(text, DENIED_TEXT, "{verdict:?}");
        seen.push(format!("{code:?}"));
        assert_eq!(fixture.gate.open_streams(), 0, "{verdict:?}");
    }
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]), "{seen:?}");
    fixture.control.set(Verdict::Allow);
    let mut channel = client.open_node().await.unwrap();
    echo_once(&mut channel, b"through").await;
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trusted_proxy_header_sets_the_client_address_seen_by_route() {
    let fixture = Fixture::start(behind_proxy).await;
    fixture.control.set(Verdict::Deny);
    for (header, expected) in [
        (
            proxy_tcp4([203, 0, 113, 9], 40_000),
            Some("203.0.113.9:40000"),
        ),
        (proxy_local(), None),
    ] {
        let mut tcp = TcpStream::connect(fixture.addr).await.unwrap();
        let local = tcp.local_addr().unwrap().to_string();
        tcp.write_all(&header).await.unwrap();
        let mut client = Client::over(tcp).await.unwrap();
        assert!(client.login(&fixture.user_ca).await);
        let (_, text) = client.open_node().await.unwrap_err();
        assert_eq!(text, DENIED_TEXT);
        let seen = fixture.control.seen();
        let routed = seen.last().unwrap();
        assert_eq!(routed.client_addr, expected.unwrap_or(&local));
    }
    fixture.stop().await;
}

async fn connect_event_for(
    addr: std::net::SocketAddr,
    header: Option<Vec<u8>>,
    client: Option<&str>,
) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    let local = tcp.local_addr().unwrap().to_string();
    if let Some(header) = header {
        tcp.write_all(&header).await.unwrap();
    }
    let expected = client.map_or(local, str::to_owned);
    let event = audited("the connect event", |event| {
        field(event, "event") == "gate.ssh.connect" && field(event, "client_addr") == expected
    })
    .await;
    assert_eq!(
        field(&event, "peer_addr"),
        tcp.local_addr().unwrap().to_string()
    );
    field(&event, "proxied").to_owned()
}

#[tokio::test]
async fn the_connect_event_says_proxied_only_after_a_real_proxy_header() {
    let plain = Fixture::start(|_| {}).await;
    assert_eq!(connect_event_for(plain.addr, None, None).await, "false");
    plain.stop().await;

    let proxied = Fixture::start(behind_proxy).await;
    assert_eq!(
        connect_event_for(proxied.addr, Some(proxy_local()), None).await,
        "false"
    );
    assert_eq!(
        connect_event_for(
            proxied.addr,
            Some(proxy_tcp4([203, 0, 113, 9], 40_000)),
            Some("203.0.113.9:40000"),
        )
        .await,
        "true"
    );
    proxied.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn connections_without_a_valid_proxy_preamble_are_closed_silently() {
    let untrusted = Fixture::start(|config| {
        config.proxy_protocol = true;
        config.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
    })
    .await;
    let mut tcp = TcpStream::connect(untrusted.addr).await.unwrap();
    tcp.write_all(&proxy_tcp4([203, 0, 113, 9], 40_000))
        .await
        .unwrap();
    assert!(closed_without_a_word(tcp).await, "an untrusted peer");
    untrusted.stop().await;

    let fixture = Fixture::start(|config| {
        behind_proxy(config);
        config.proxy_header_timeout = Duration::from_millis(200);
    })
    .await;
    let mut plain = TcpStream::connect(fixture.addr).await.unwrap();
    plain.write_all(b"SSH-2.0-OpenSSH_10.0\r\n").await.unwrap();
    assert!(closed_without_a_word(plain).await, "a missing header");
    let silent = TcpStream::connect(fixture.addr).await.unwrap();
    assert!(closed_without_a_word(silent).await, "a silent peer");
    let mut version_one = TcpStream::connect(fixture.addr).await.unwrap();
    version_one
        .write_all(b"PROXY TCP4 203.0.113.9 127.0.0.1 40000 2222\r\n")
        .await
        .unwrap();
    assert!(
        closed_without_a_word(version_one).await,
        "a version 1 header"
    );
    eventually("the permits to return", || {
        fixture.gate.unauthenticated() == 0
    })
    .await;
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_header_without_the_proxy_protocol_breaks_the_ssh_handshake() {
    let fixture = Fixture::start(|_| {}).await;
    let mut tcp = TcpStream::connect(fixture.addr).await.unwrap();
    tcp.write_all(&proxy_tcp4([203, 0, 113, 9], 40_000))
        .await
        .unwrap();
    assert!(Client::over(tcp).await.is_err());
    assert!(fixture.control.seen().is_empty());
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn unauthenticated_connections_beyond_the_limit_are_closed() {
    let fixture = Fixture::start(|config| config.max_unauthenticated = 2).await;
    let mut first = TcpStream::connect(fixture.addr).await.unwrap();
    let mut second = TcpStream::connect(fixture.addr).await.unwrap();
    assert!(banner(&mut first).await.starts_with("SSH-2.0-Jaunt"));
    assert!(banner(&mut second).await.starts_with("SSH-2.0-Jaunt"));
    assert_eq!(fixture.gate.unauthenticated(), 2);
    let third = TcpStream::connect(fixture.addr).await.unwrap();
    assert!(closed_without_a_word(third).await);

    drop(first);
    eventually("a closed connection to return its permit", || {
        fixture.gate.unauthenticated() == 1
    })
    .await;
    let client = fixture.login().await;
    eventually("a login to return its permit", || {
        fixture.gate.unauthenticated() == 1
    })
    .await;
    drop((client, second));
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reissued_certificate_reaches_new_connections_while_old_ones_keep_working() {
    let fixture = Fixture::start(|_| {}).await;
    let old = fixture.login().await;
    let mut channel = old.open_node().await.unwrap();
    let before = old.host_certificate();
    assert_eq!(before.valid_principals(), [GATE_NAME]);
    assert_eq!(
        before.signature_key(),
        fixture.host_ca.public_key().key_data()
    );

    fixture.gate.reissue_host_certificate().await.unwrap();
    let new = fixture.login().await;
    let after = new.host_certificate();
    assert_eq!(fixture.issuer.calls(), 2);
    assert_eq!((before.serial(), after.serial()), (1, 2));
    assert_ne!(before.public_key(), after.public_key());
    assert_eq!(after.valid_principals(), [GATE_NAME]);

    echo_once(&mut channel, b"still here").await;
    let mut fresh = new.open_node().await.unwrap();
    echo_once(&mut fresh, b"new hop").await;
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_certificate_is_renewed_at_half_life_and_a_failed_renewal_is_retried() {
    let clock = TestClock::new();
    let fixture = Fixture::start_with(
        |config| {
            config.renewal_check = Duration::from_millis(20);
            config.renewal_retry = Duration::from_millis(20);
        },
        clock.clone(),
    )
    .await;
    assert_eq!(fixture.issuer.calls(), 1);
    fixture.issuer.fail_next(2);
    clock.advance(Duration::from_secs(4 * 24 * 3600));
    let deadline = Instant::now() + STEP;
    loop {
        let client = fixture.connect().await;
        if client.host_certificate().serial() == 4 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the renewed certificate never arrived"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fixture.issuer.calls(), 4);
    fixture.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_closes_live_connections_within_the_grace() {
    let fixture = Fixture::start(|config| config.shutdown_grace = Duration::from_secs(5)).await;
    let client = fixture.login().await;
    let _channel = client.open_node().await.unwrap();
    let mut idle = TcpStream::connect(fixture.addr).await.unwrap();
    assert!(banner(&mut idle).await.starts_with("SSH-2.0-Jaunt"));
    let addr = fixture.addr;
    let gate = Arc::clone(&fixture.gate);
    let started = Instant::now();
    fixture.shutdown.cancel();
    tokio::time::timeout(STEP, fixture.serve)
        .await
        .expect("the gate did not stop")
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(gate.open_streams(), 0);
    assert_eq!(gate.unauthenticated(), 0);
    eventually("the client to see the end", || client.handle.is_closed()).await;
    assert!(closed_without_a_word(idle).await);
    assert!(TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn terminate_closes_only_the_matching_connections_and_their_forwards() {
    let fixture = Fixture::start(|_| {}).await;
    let first = fixture.login_with_serial(42).await;
    let mut channel = first.open_node().await.unwrap();
    echo_once(&mut channel, b"before").await;
    let second = fixture.login_with_serial(43).await;
    let gate = Arc::clone(&fixture.gate);
    eventually("both connections to be indexed", || {
        gate.authenticated() == 2
    })
    .await;
    assert_eq!(gate.open_streams(), 1);

    assert_eq!(
        gate.terminate("someone-else", None, TerminationReason::Revoked),
        0
    );
    assert_eq!(
        gate.terminate(USER_ID, Some(7), TerminationReason::Revoked),
        0
    );
    let started = Instant::now();
    assert_eq!(
        gate.terminate(USER_ID, Some(42), TerminationReason::Revoked),
        1
    );

    eventually("the terminated client to see the end", || {
        first.handle.is_closed()
    })
    .await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    eventually("the forward to be released", || gate.open_streams() == 0).await;
    assert!(!second.handle.is_closed());
    let terminated = audited("the termination", |event| {
        field(event, "event") == "gate.ssh.terminated" && field(event, "serial") == "42"
    })
    .await;
    assert_eq!(field(&terminated, "reason"), "revoked");
    assert_eq!(field(&terminated, "connections"), "1");
    audited("the terminated disconnect", |event| {
        field(event, "event") == "gate.ssh.disconnect" && field(event, "reason") == "terminated"
    })
    .await;

    assert_eq!(gate.terminate(USER_ID, None, TerminationReason::Revoked), 1);
    eventually("the second client to see the end", || {
        second.handle.is_closed()
    })
    .await;
    eventually("the index to empty", || gate.authenticated() == 0).await;
    fixture.stop().await;
}

struct Refusing;

impl HostCertIssuer for Refusing {
    fn issue<'a>(
        &'a self,
        _public_key_openssh: &'a str,
        _hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        Box::pin(async { Err(IssueError::Unavailable) })
    }
}

#[tokio::test]
async fn the_gate_does_not_start_without_a_certificate_or_with_a_bad_configuration() {
    let user_ca = key();
    let cas = Arc::new(UserCaSource::new(
        UserCaKeys::from_openssh_lines([user_ca.public_key().to_openssh().unwrap()]).unwrap(),
    ));
    let base = || SshGateConfig::new(vec![GATE_NAME.to_owned()], "nodes.test");
    type Mutation = fn(&mut SshGateConfig);
    type Expected = fn(&SshGateError) -> bool;
    let cases: [(Mutation, Expected); 9] = [
        (
            |_| {},
            |error| {
                matches!(
                    error,
                    SshGateError::HostCertificate(HostCertError::Issue(IssueError::Unavailable))
                )
            },
        ),
        (
            |config| config.hostnames.clear(),
            |error| matches!(error, SshGateError::NoHostnames),
        ),
        (
            |config| config.ssh_suffix = "bad suffix".to_owned(),
            |error| matches!(error, SshGateError::InvalidSuffix),
        ),
        (
            |config| config.proxy_protocol = true,
            |error| matches!(error, SshGateError::NoTrustedProxies),
        ),
        (
            |config| config.max_unauthenticated = 0,
            |error| matches!(error, SshGateError::UnauthenticatedLimit),
        ),
        (
            |config| config.max_streams_per_user_node = 0,
            |error| matches!(error, SshGateError::StreamLimit),
        ),
        (
            |config| config.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()],
            |error| matches!(error, SshGateError::TrustedProxiesWithoutProxyProtocol),
        ),
        (
            |config| {
                config.proxy_protocol = true;
                config.trusted_proxies = vec!["::/0".parse().unwrap()];
            },
            |error| {
                matches!(
                    error,
                    SshGateError::TrustedProxy {
                        index: 0,
                        problem: TrustedProxyProblem::Everything
                    }
                )
            },
        ),
        (
            |config| {
                config.hostnames = (0..65)
                    .map(|index| format!("g{index}.example.com"))
                    .collect();
            },
            |error| matches!(error, SshGateError::TooManyHostnames),
        ),
    ];
    for (index, (mutate, expected)) in cases.into_iter().enumerate() {
        let mut config = base();
        mutate(&mut config);
        let control = Arc::new(FakeControl::default());
        let started = SshGate::new(
            config,
            Arc::new(Refusing),
            Arc::clone(&cas),
            control,
            AgentRegistry::new(),
        )
        .await;
        let error = started.err().expect("the gate started");
        assert!(expected(&error), "case {index}: {error:?}");
    }
}
