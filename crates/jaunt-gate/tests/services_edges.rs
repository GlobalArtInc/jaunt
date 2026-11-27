mod support;

#[allow(dead_code)]
#[path = "services/fixture.rs"]
mod fixture;

#[allow(dead_code)]
#[path = "ssh/fixture.rs"]
mod ssh_fixture;

use std::any::Any;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use fixture::{
    ALPN_SVC, AgentEvent, CLUSTER, DOMAIN, FakeControl, FixedRoots, Fixture, IssuerMode, Options,
    Reply, RouteAnswer, TestClock, TestIssuer, USER, closed_without_bytes, gate_with, hello,
    hello_with_alpn, noise, proxy_header, proxy_local, read_all, unix,
};
use jaunt_gate::{
    ClassConnection, ClassHandler, ClassHandlers, EntryIo, GateCertificateError, ServiceGate,
    ServiceGateConfig, ServiceGateError, ServiceGateParts, ServicesEntry, StreamRefusal,
    TlsRefusal,
};
use jaunt_tunnel::BoxFuture;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, HandshakeKind};
use socket2::SockRef;
use support::{HubOptions, Pki, TestHub, Verdicts, audited, eventually, field, start_hub, within};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

const LOCAL: [u8; 4] = [127, 0, 0, 1];
const ALPN_SSH: &[u8] = b"jaunt-ssh/1";

fn kube_name(cluster: &str) -> String {
    format!("{cluster}.kube.{DOMAIN}")
}

fn db_name() -> String {
    format!("lk.db.{DOMAIN}")
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[tokio::test]
async fn a_silent_client_after_the_agent_closes_its_side_frees_every_slot_after_the_grace() {
    let mut fixture = Fixture::start(Options {
        reply: Reply::CloseAfterOneByte,
        entry_kube_per_address: Some(1),
        configure: |config| config.half_close_grace = Duration::from_secs(1),
        ..Options::default()
    })
    .await;
    let mut kube = fixture.tcp(LOCAL).await;
    kube.write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let user = fixture.users.user(USER, 7);
    let mut svc = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    svc.write_all(&hello(Some(&db_name()))).await.unwrap();
    assert!(closed_without_bytes(&mut kube).await);
    assert!(closed_without_bytes(&mut svc).await);
    let held = fixture.gate.stats();
    assert_eq!((held.kube_streams, held.svc_streams), (1, 1));
    fixture.idle().await;
    for kind in ["gate.kube.stream", "gate.svc.stream"] {
        audited(kind, |event| {
            field(event, "event") == kind && field(event, "reason") == "half_close_timeout"
        })
        .await;
    }
    for _ in 0..4 {
        fixture.next_event().await;
    }
    let mut next = fixture.tcp(LOCAL).await;
    next.write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the entry kube slot was not given back");
    };
    drop((kube, svc, next));
    fixture.idle().await;
    fixture.stop().await;
}

type Probed = (bool, Duration, Duration, u32);

struct KeepaliveProbe(mpsc::UnboundedSender<Probed>);

impl ClassHandler for KeepaliveProbe {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let io: &dyn EntryIo = &**connection.stream.get_ref();
        let any: &dyn Any = io;
        let tcp = any
            .downcast_ref::<TcpStream>()
            .expect("the entry hands over the accepted tcp socket");
        let socket = SockRef::from(tcp);
        self.0
            .send((
                socket.keepalive().unwrap(),
                socket.tcp_keepalive_time().unwrap(),
                socket.tcp_keepalive_interval().unwrap(),
                socket.tcp_keepalive_retries().unwrap(),
            ))
            .unwrap();
        Box::pin(async move { drop(connection) })
    }
}

#[tokio::test]
async fn the_accepted_sockets_of_ssh_svc_and_kube_clients_have_tcp_keepalive() {
    let hub = start_hub(
        &Pki::new("entry ca"),
        Arc::new(Verdicts::default()),
        HubOptions {
            services: Some(ServicesEntry::new(DOMAIN)),
            ..HubOptions::default()
        },
    )
    .await;
    let (sender, mut probed) = mpsc::unbounded_channel();
    let probe: Arc<dyn ClassHandler> = Arc::new(KeepaliveProbe(sender));
    assert!(hub.hub.install_class_handlers(ClassHandlers {
        gate: Some(Arc::clone(&probe)),
        kube: Some(probe),
    }));
    for client_hello in [
        hello_with_alpn(Some(DOMAIN), &[ALPN_SSH]),
        hello_with_alpn(Some(DOMAIN), &[ALPN_SVC]),
        hello(Some(&kube_name(CLUSTER))),
    ] {
        let mut tcp = TcpStream::connect(hub.addr).await.unwrap();
        tcp.write_all(&client_hello).await.unwrap();
        let seen = within("the probe", probed.recv()).await.unwrap();
        assert_eq!(
            seen,
            (true, Duration::from_secs(60), Duration::from_secs(20), 3)
        );
    }
}

#[tokio::test]
async fn a_client_limited_to_tls_1_2_is_refused_by_the_outer_handshake() {
    let fixture = Fixture::start(Options::default()).await;
    let user = fixture.users.user(USER, 7);
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(fixture.issuer.roots())
        .with_client_auth_cert(
            user.chain.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(user.key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![ALPN_SVC.to_vec()];
    assert!(fixture.svc_with(LOCAL, Arc::new(config)).await.is_err());
    eventually("the tls 1.2 refusal", || {
        fixture.hub.hub.tls_refused(TlsRefusal::TlsHandshake) == 1
    })
    .await;
    assert!(fixture.control.routes().is_empty());
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn every_outer_connection_does_a_full_handshake() {
    let fixture = Fixture::start(Options::default()).await;
    let user = fixture.users.user(USER, 7);
    let config = fixture.outer_config(Some(&user));
    for _ in 0..2 {
        let mut tls = fixture.svc_with(LOCAL, Arc::clone(&config)).await.unwrap();
        assert_eq!(tls.get_ref().1.handshake_kind(), Some(HandshakeKind::Full));
        tls.write_all(&hello(Some(&db_name()))).await.unwrap();
        tls.shutdown().await.unwrap();
        assert_eq!(read_all(&mut tls).await.unwrap(), b"from the agent");
    }
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn a_large_reply_reaches_a_slow_reader_whole() {
    let burst = noise(21, 2 * 1024 * 1024);
    let fixture = Fixture::start(Options {
        reply: Reply::Burst(Arc::new(burst.clone())),
        ..Options::default()
    })
    .await;
    let user = fixture.users.user(USER, 7);
    let mut tls = fixture.svc_small_window(&user).await;
    tls.write_all(&hello(Some(&db_name()))).await.unwrap();
    let mut received = Vec::with_capacity(burst.len());
    let mut chunk = vec![0_u8; 8 * 1024];
    while received.len() < burst.len() {
        let read = within("the next part of the reply", tls.read(&mut chunk))
            .await
            .unwrap();
        assert!(read > 0, "the reply ended after {} bytes", received.len());
        received.extend_from_slice(&chunk[..read]);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(received == burst);
    tls.shutdown().await.unwrap();
    drop(tls);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn proxy_local_health_checks_are_exempt_from_the_per_address_kube_and_svc_limits() {
    let mut fixture = Fixture::start(Options {
        proxied: true,
        configure: |config| {
            config.kube_streams_per_address = 1;
            config.svc_streams_per_address = 1;
        },
        ..Options::default()
    })
    .await;
    let user = fixture.users.user(USER, 7);
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut kube = fixture.tcp_local().await;
        kube.write_all(&hello(Some(&kube_name(CLUSTER))))
            .await
            .unwrap();
        let AgentEvent::Opened(_) = fixture.next_event().await else {
            panic!("a local kube stream did not open");
        };
        let mut svc = fixture.svc_local(&user).await.unwrap();
        svc.write_all(&hello(Some(&db_name()))).await.unwrap();
        let AgentEvent::Opened(_) = fixture.next_event().await else {
            panic!("a local svc stream did not open");
        };
        held.push((kube, svc));
    }
    assert_eq!(fixture.gate.kube_refused(StreamRefusal::AddressLimit), 0);
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::Limit), 0);
    let stats = fixture.gate.stats();
    assert_eq!((stats.kube_addresses, stats.svc_addresses), (0, 0));
    drop(held);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn refusals_of_authenticated_svc_clients_are_thinned_per_reason() {
    let fixture = Fixture::start(Options::default()).await;
    fixture.control.answer(RouteAnswer::Deny);
    let user = fixture.users.user(USER, 7);
    let before = support::audit_events().len();
    for _ in 0..3 {
        let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
        tls.write_all(&hello(Some(&db_name()))).await.unwrap();
        assert!(closed_without_bytes(&mut tls).await);
    }
    let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    tls.write_all(&hello(Some("x.kube.svc.test")))
        .await
        .unwrap();
    assert!(closed_without_bytes(&mut tls).await);
    assert_eq!(fixture.gate.svc_refused(StreamRefusal::Denied), 3);
    let refused: Vec<_> = support::audit_events()
        .into_iter()
        .skip(before)
        .filter(|event| field(event, "event") == "gate.svc.stream")
        .collect();
    let reasons: Vec<(&str, &str)> = refused
        .iter()
        .map(|event| (field(event, "reason"), field(event, "suppressed")))
        .collect();
    assert_eq!(reasons, [("denied", "0"), ("service_name", "0")]);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn the_inner_hello_timeout_is_configurable() {
    let fixture = Fixture::start(Options {
        configure: |config| config.inner_hello_timeout = Duration::from_millis(200),
        ..Options::default()
    })
    .await;
    let user = fixture.users.user(USER, 7);
    let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    let started = Instant::now();
    assert!(closed_without_bytes(&mut tls).await);
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(fixture.gate.svc_refused(StreamRefusal::InnerHello), 1);
    let mut zero = ServiceGateConfig::new(DOMAIN);
    zero.inner_hello_timeout = Duration::ZERO;
    let clock = TestClock::new();
    assert!(matches!(
        gate_with(TestIssuer::new(DOMAIN, clock.clone()), zero, &clock).await,
        Err(ServiceGateError::Timers)
    ));
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn the_gate_takes_only_a_certificate_for_its_key_and_name_and_reads_the_window_from_it() {
    for mode in [
        IssuerMode::OtherName,
        IssuerMode::OtherKey,
        IssuerMode::Expired,
    ] {
        let clock = TestClock::new();
        let issuer = TestIssuer::new(DOMAIN, clock.clone());
        issuer.set_mode(mode);
        assert!(
            matches!(
                gate_with(issuer, ServiceGateConfig::new(DOMAIN), &clock).await,
                Err(ServiceGateError::Certificate(
                    GateCertificateError::Unusable
                ))
            ),
            "{mode:?}"
        );
    }
    let clock = TestClock::new();
    let issuer = TestIssuer::new(DOMAIN, clock.clone());
    issuer.set_mode(IssuerMode::ClaimsAnotherWindow);
    let gate = gate_with(issuer.clone(), ServiceGateConfig::new(DOMAIN), &clock)
        .await
        .unwrap();
    let issued = issuer.last_issued();
    let (_, certificate) = x509_parser::parse_x509_certificate(&issued).unwrap();
    let not_after = u64::try_from(certificate.validity().not_after.timestamp()).unwrap();
    assert_eq!(gate.certificate_valid_before(), not_after);
    assert!(not_after < unix(SystemTime::now()) + 8 * 24 * 3600);
}

#[tokio::test]
async fn an_expired_gate_certificate_is_never_presented() {
    let mut fixture = Fixture::start(Options::default()).await;
    fixture.issuer.set_mode(IssuerMode::Failing);
    fixture.clock.advance(Duration::from_secs(8 * 24 * 3600));
    assert!(fixture.gate.renew_if_due().await.is_err());
    let now = unix(SystemTime::now());
    let user = fixture
        .users
        .user_valid(USER, 7, now - 60, now + 9 * 24 * 3600);
    assert!(fixture.svc(LOCAL, Some(&user)).await.is_err());
    let mut ssh = fixture.tcp(LOCAL).await;
    ssh.write_all(&hello_with_alpn(Some(DOMAIN), &[ALPN_SSH]))
        .await
        .unwrap();
    assert!(closed_without_bytes(&mut ssh).await);
    assert_eq!(
        fixture
            .hub
            .hub
            .tls_refused(TlsRefusal::GateCertificateExpired),
        2
    );
    let mut kube = fixture.tcp(LOCAL).await;
    kube.write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("kubernetes pass-through needs no gate certificate");
    };
    drop(kube);

    fixture.issuer.set_mode(IssuerMode::Normal);
    assert!(fixture.gate.renew_if_due().await.unwrap());
    let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    tls.write_all(&hello(Some(&db_name()))).await.unwrap();
    tls.shutdown().await.unwrap();
    assert_eq!(read_all(&mut tls).await.unwrap(), b"from the agent");
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn client_certificates_are_checked_again_on_the_gate_clock() {
    let fixture = Fixture::start(Options::default()).await;
    let user = fixture.users.user(USER, 7);
    fixture.clock.advance(Duration::from_secs(2 * 3600));
    let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    drop(tls.write_all(&hello(Some(&db_name()))).await);
    let mut buffer = [0_u8; 16];
    let read = within("the gate to close", tls.read(&mut buffer)).await;
    assert!(matches!(read, Ok(0)), "{read:?}");
    assert_eq!(
        fixture.hub.hub.tls_refused(TlsRefusal::ClientCertificate),
        1
    );
    assert!(fixture.control.routes().is_empty());
    fixture.idle().await;
    fixture.stop().await;
}

struct SshEntry {
    hub: TestHub,
    gate: ServiceGate,
    connector: TlsConnector,
}

impl SshEntry {
    async fn start(ssh: &ssh_fixture::Fixture, proxied: bool) -> Self {
        let mut services = ServicesEntry::new(DOMAIN);
        if proxied {
            services.proxy_protocol = true;
            services.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        }
        let hub = start_hub(
            &Pki::new("entry ca"),
            Arc::new(Verdicts::default()),
            HubOptions {
                services: Some(services),
                ..HubOptions::default()
            },
        )
        .await;
        let clock = TestClock::new();
        let issuer = TestIssuer::new(DOMAIN, clock.clone());
        let gate = ServiceGate::new(ServiceGateParts {
            config: ServiceGateConfig::new(DOMAIN),
            issuer: issuer.clone(),
            user_x509: Arc::new(FixedRoots(Mutex::new(None))),
            control: FakeControl::new(),
            registry: hub.hub.registry().clone(),
            ssh: Some(Arc::clone(&ssh.gate)),
            clock: clock.clock(),
        })
        .await
        .unwrap();
        assert!(hub.hub.install_class_handlers(gate.handlers()));
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(issuer.roots())
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN_SSH.to_vec()];
        Self {
            hub,
            gate,
            connector: TlsConnector::from(Arc::new(config)),
        }
    }

    async fn dial(&self, header: Option<Vec<u8>>) -> Option<ssh_fixture::Client> {
        let mut tcp = TcpStream::connect(self.hub.addr).await.unwrap();
        if let Some(header) = header {
            tcp.write_all(&header).await.unwrap();
        }
        let tls = within(
            "the tls handshake",
            self.connector
                .connect(ServerName::try_from(DOMAIN).unwrap(), tcp),
        )
        .await
        .ok()?;
        ssh_fixture::Client::over(tls).await.ok()
    }
}

#[tokio::test]
async fn ssh_through_443_honours_max_unauthenticated() {
    let ssh = ssh_fixture::Fixture::start(|config| config.max_unauthenticated = 1).await;
    let entry = SshEntry::start(&ssh, false).await;
    let mut waiting = ssh.connect().await;
    assert!(entry.dial(None).await.is_none());
    assert_eq!(ssh.gate.unauthenticated(), 1);
    assert!(waiting.login(&ssh.user_ca).await);
    let mut over_tls = entry.dial(None).await.expect("a free unauthenticated slot");
    assert!(over_tls.login(&ssh.user_ca).await);
    drop((waiting, over_tls));
    eventually("the ssh connections to end", || {
        ssh.gate.authenticated() == 0
    })
    .await;
    assert_eq!(entry.gate.stats().handshaking, 0);
    ssh.stop().await;
}

#[tokio::test]
async fn ssh_through_443_does_not_charge_proxy_local_connections_to_an_address() {
    let ssh = ssh_fixture::Fixture::start(|config| {
        config.client_limits = jaunt_limits::AddressLimits {
            rate: jaunt_limits::Rate::clamped(1000, 1000),
            concurrent: 1,
            tracked: 16,
        };
    })
    .await;
    let entry = SshEntry::start(&ssh, true).await;
    let waiting = ssh.connect().await;
    assert!(entry.dial(Some(proxy_header(LOCAL))).await.is_none());
    let mut local = entry
        .dial(Some(proxy_local()))
        .await
        .expect("a proxy local connection needs no address slot");
    assert!(local.login(&ssh.user_ca).await);
    drop((waiting, local));
    eventually("the ssh connections to end", || {
        ssh.gate.authenticated() == 0
    })
    .await;
    ssh.stop().await;
}

#[test]
fn the_handshake_and_stream_timers_default_to_the_documented_values() {
    let config = ServiceGateConfig::new(DOMAIN);
    assert_eq!(config.inner_hello_timeout, Duration::from_secs(10));
    assert_eq!(config.half_close_grace, Duration::from_secs(30));
    assert_eq!(jaunt_gate::KUBE_MISS_CACHE, Duration::from_secs(2));
    assert_eq!(jaunt_gate::KUBE_LOCATION_CACHE, Duration::from_secs(10));
}
