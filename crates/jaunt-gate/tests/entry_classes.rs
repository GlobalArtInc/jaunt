mod entry_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use entry_support::*;
use jaunt_gate::{
    ALPN_SSH, ALPN_SVC, ClassConnection, ClassHandler, ClassHandlers, EntryClass, EntryIo,
    GateProtocol, HelloInfo, MAX_CLIENT_HELLO_BYTES, Route, TlsEntry, TlsEntryConfig, TlsRefusal,
};
use jaunt_tunnel::BoxFuture;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::Acceptor;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex};
use tokio::time::timeout;
use tokio_rustls::{LazyConfigAcceptor, TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn server_names_and_offered_protocols_pick_the_class_or_the_refusal() {
    let entry = TlsEntry::new(config()).unwrap();
    let peer = addr("198.51.100.9:40000");
    let kube = |cluster: &str| Ok(EntryClass::Kube(cluster.to_owned()));
    let no_sni = records(&hello_message(None, &[ALPN_SSH], 0), SINGLE_RECORD);
    let ip_sni = records(&hello_message(Some(b"192.0.2.7"), &[], 0), SINGLE_RECORD);
    let cases: Vec<(Vec<u8>, Result<EntryClass, TlsRefusal>)> = vec![
        (hello(AGENTS, &[b"jaunt-tunnel/1"]), Ok(EntryClass::Agents)),
        (hello("AGENTS.example.COM", &[]), Ok(EntryClass::Agents)),
        (
            hello(DOMAIN, &[ALPN_SSH]),
            Ok(EntryClass::Gate(GateProtocol::Ssh)),
        ),
        (
            hello(DOMAIN, &[ALPN_SVC]),
            Ok(EntryClass::Gate(GateProtocol::Svc)),
        ),
        (
            hello(DOMAIN, &[ALPN_SVC, ALPN_SSH]),
            Ok(EntryClass::Gate(GateProtocol::Ssh)),
        ),
        (
            hello(DOMAIN, &[ALPN_SSH, b"h2"]),
            Ok(EntryClass::Gate(GateProtocol::Ssh)),
        ),
        (
            hello(DOMAIN, &[b"h2", ALPN_SSH, b"x"]),
            Ok(EntryClass::Gate(GateProtocol::Ssh)),
        ),
        (
            hello(DOMAIN, &[ALPN_SVC, b"x"]),
            Ok(EntryClass::Gate(GateProtocol::Svc)),
        ),
        (
            hello(DOMAIN, &[b"x", ALPN_SVC, ALPN_SSH]),
            Ok(EntryClass::Gate(GateProtocol::Ssh)),
        ),
        (hello(DOMAIN, &[b"h2"]), Err(TlsRefusal::AlpnUnsupported)),
        (hello(DOMAIN, &[]), Err(TlsRefusal::AlpnUnsupported)),
        (
            hello(&format!("prod-eu.kube.{DOMAIN}"), &[b"h2"]),
            kube("prod-eu"),
        ),
        (
            hello(&format!("prod-eu.kube.{DOMAIN}"), &[]),
            kube("prod-eu"),
        ),
        (
            hello(&format!("kube.{DOMAIN}"), &[b"h2"]),
            Err(TlsRefusal::UnknownSni),
        ),
        (
            hello(&format!("a.b.kube.{DOMAIN}"), &[]),
            Err(TlsRefusal::UnknownSni),
        ),
        (
            hello(&format!("evilkube.{DOMAIN}"), &[]),
            Err(TlsRefusal::UnknownSni),
        ),
        (
            hello(&format!("{DOMAIN}.evil"), &[ALPN_SSH]),
            Err(TlsRefusal::UnknownSni),
        ),
        (hello("example.com", &[]), Err(TlsRefusal::UnknownSni)),
        (no_sni, Err(TlsRefusal::NoSni)),
        (ip_sni, Err(TlsRefusal::NoSni)),
    ];
    for (bytes, expected) in cases {
        let (near, _far) = sent(&[&bytes]).await;
        let outcome = entry.admit(near, peer).await.map(|admitted| {
            assert_eq!(admitted.stream.pending(), bytes.as_slice());
            assert_eq!(admitted.route.client_addr, peer);
            admitted.route.class
        });
        assert_eq!(outcome, expected);
    }
    assert_eq!(entry.refused(TlsRefusal::AlpnUnsupported), 2);
    assert_eq!(entry.refused(TlsRefusal::UnknownSni), 5);
    assert_eq!(entry.refused(TlsRefusal::NoSni), 2);
}

#[tokio::test]
async fn thousands_of_offered_protocols_leave_only_the_two_routing_flags_behind() {
    let mut alpn: Vec<&[u8]> = vec![b"x"; 8000];
    alpn.push(ALPN_SSH);
    let bytes = hello(DOMAIN, &alpn);
    assert!(bytes.len() <= MAX_CLIENT_HELLO_BYTES);
    let entry = TlsEntry::new(config()).unwrap();
    let (near, _far) = sent(&[&bytes]).await;
    let admitted = entry.admit(near, addr("198.51.100.9:4000")).await.unwrap();
    assert_eq!(admitted.route.class, EntryClass::Gate(GateProtocol::Ssh));
    let kept = &admitted.route.hello;
    assert!(kept.offers_ssh() && !kept.offers_svc());
    assert_eq!(kept.server_name(), Some(DOMAIN));
    assert!(
        std::mem::size_of::<HelloInfo>() <= std::mem::size_of::<Option<String>>() + 8,
        "{}",
        std::mem::size_of::<HelloInfo>()
    );
}

#[tokio::test(start_paused = true)]
async fn without_a_services_domain_every_hello_goes_where_it_went_before() {
    let mut config = config();
    config.domain = None;
    let entry = TlsEntry::new(config).unwrap();
    let no_sni = records(&hello_message(None, &[], 0), SINGLE_RECORD);
    let cases = [
        (hello(AGENTS, &[b"jaunt-agent/1"]), EntryClass::Agents),
        (hello(DOMAIN, &[ALPN_SSH]), EntryClass::Main),
        (
            hello(&format!("prod.kube.{DOMAIN}"), &[b"h2"]),
            EntryClass::Main,
        ),
        (hello("example.com", &[b"h2"]), EntryClass::Main),
        (no_sni, EntryClass::Main),
    ];
    for (bytes, expected) in cases {
        let (near, mut far) = sent(&[&bytes, TRAILING]).await;
        far.shutdown().await.unwrap();
        let admitted = entry.admit(near, addr("198.51.100.9:40000")).await.unwrap();
        assert_eq!(admitted.route.class, expected);
        let admitted = entry
            .serve_class(admitted, CancellationToken::new())
            .await
            .unwrap();
        let mut stream = admitted.stream;
        let expected = [bytes.as_slice(), TRAILING].concat();
        assert_eq!(read_exactly(&mut stream, expected.len()).await, expected);
        assert!(at_end(&mut stream).await);
    }
    for reason in TlsRefusal::ALL {
        assert_eq!(entry.refused(reason), 0, "{reason:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_class_without_a_handler_is_refused_and_closed() {
    install_recorder();
    let entry = TlsEntry::new(config()).unwrap();
    for name in [DOMAIN.to_owned(), format!("prod.kube.{DOMAIN}")] {
        let (near, mut far) = sent(&[&hello(&name, &[ALPN_SSH])]).await;
        let admitted = entry.admit(near, addr("198.51.100.9:4000")).await.unwrap();
        assert!(
            entry
                .serve_class(admitted, CancellationToken::new())
                .await
                .is_none()
        );
        assert!(at_end(&mut far).await);
    }
    assert_eq!(entry.refused(TlsRefusal::UnsupportedClass), 2);
    assert_eq!(
        refusals().first(),
        Some(&("unsupported_class".to_owned(), "0".to_owned()))
    );
}

struct Holding {
    release: CancellationToken,
    fail: bool,
}

impl ClassHandler for Holding {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let release = self.release.clone();
        let fail = self.fail;
        Box::pin(async move {
            let held = connection;
            release.cancelled().await;
            assert!(!fail, "the handler failed on purpose");
            drop(held);
        })
    }
}

fn holding(release: &CancellationToken, fail: bool) -> Option<Arc<dyn ClassHandler>> {
    Some(Arc::new(Holding {
        release: release.clone(),
        fail,
    }))
}

async fn handled(entry: &Arc<TlsEntry>, bytes: Vec<u8>) -> tokio::task::JoinHandle<()> {
    let (near, far) = sent(&[&bytes]).await;
    let admitted = entry.admit(near, addr("198.51.100.9:4000")).await.unwrap();
    let serving = Arc::clone(entry);
    let task = tokio::spawn(async move {
        let _far = far;
        assert!(
            serving
                .serve_class(admitted, CancellationToken::new())
                .await
                .is_none()
        );
    });
    for _ in 0..1000 {
        if entry.handshaking() == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    task
}

#[tokio::test]
async fn running_handlers_keep_only_the_kube_slot_not_the_handshake_budget() {
    let release = CancellationToken::new();
    let mut config = config();
    config.max_handshaking = 1;
    config.front_limits = limits(1);
    config.kube_limits = limits(1);
    config.handlers = ClassHandlers {
        gate: holding(&release, false),
        kube: holding(&release, false),
    };
    let entry = Arc::new(TlsEntry::new(config).unwrap());
    let peer = addr("198.51.100.9:4000");
    let kube = hello(&format!("prod.kube.{DOMAIN}"), &[b"h2"]);
    let gate = handled(&entry, hello(DOMAIN, &[ALPN_SSH])).await;
    let pass_through = handled(&entry, kube.clone()).await;
    assert_eq!(entry.handshaking(), 0);

    let (near, _far) = sent(&[&hello(AGENTS, &[])]).await;
    let agent = entry.admit(near, peer).await.unwrap();
    assert_eq!(agent.route.class, EntryClass::Agents);
    drop(agent);
    let (near, _far) = sent(&[&kube]).await;
    assert_eq!(entry.admit(near, peer).await.err(), Some(TlsRefusal::Limit));

    release.cancel();
    gate.await.unwrap();
    pass_through.await.unwrap();
    let (near, _far) = sent(&[&kube]).await;
    assert!(entry.admit(near, peer).await.is_ok());
}

#[tokio::test]
async fn a_failing_handler_still_gives_the_kube_slot_back() {
    let release = CancellationToken::new();
    let mut config = config();
    config.kube_limits = limits(1);
    config.handlers = ClassHandlers {
        gate: None,
        kube: holding(&release, true),
    };
    let entry = Arc::new(TlsEntry::new(config).unwrap());
    let kube = hello(&format!("prod.kube.{DOMAIN}"), &[b"h2"]);
    let failing = handled(&entry, kube.clone()).await;
    let (near, _far) = sent(&[&kube]).await;
    assert_eq!(
        entry.admit(near, addr("198.51.100.9:4000")).await.err(),
        Some(TlsRefusal::Limit)
    );
    release.cancel();
    assert!(failing.await.unwrap_err().is_panic());
    let (near, _far) = sent(&[&kube]).await;
    assert!(entry.admit(near, addr("198.51.100.9:4000")).await.is_ok());
}

struct Terminating {
    config: Arc<ServerConfig>,
    routes: Arc<Mutex<Vec<Route>>>,
}

impl ClassHandler for Terminating {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        self.routes.lock().unwrap().push(connection.route.clone());
        let config = self.config.clone();
        Box::pin(async move {
            let start = LazyConfigAcceptor::new(Acceptor::default(), connection.stream)
                .await
                .unwrap();
            echo_once(start.into_stream(config).await.unwrap()).await;
        })
    }
}

struct PassThrough {
    agent: TlsAcceptor,
}

impl ClassHandler for PassThrough {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let agent = self.agent.clone();
        Box::pin(async move {
            let (mut toward_agent, agent_side) = duplex(64 * 1024);
            let mut client = connection.stream;
            let agent = async move { echo_once(agent.accept(agent_side).await.unwrap()).await };
            let pipe = async move { copy_bidirectional(&mut client, &mut toward_agent).await };
            let ((), piped) = tokio::join!(agent, pipe);
            piped.unwrap();
        })
    }
}

async fn echo_once<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut tls: S) {
    let mut ping = [0_u8; 4];
    tls.read_exact(&mut ping).await.unwrap();
    tls.write_all(&ping).await.unwrap();
    tls.shutdown().await.unwrap();
}

fn tls_pair(name: &str, alpn: &[u8]) -> (Arc<ServerConfig>, TlsConnector) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert: CertificateDer<'static> = rcgen::CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .der()
        .clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    server.alpn_protocols = vec![alpn.to_vec()];
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![alpn.to_vec()];
    (Arc::new(server), TlsConnector::from(Arc::new(client)))
}

async fn ping_through(entry: &TlsEntry, connector: &TlsConnector, name: &str) -> Vec<u8> {
    let (client_io, server_io) = duplex(64 * 1024);
    let server = async {
        let admitted = entry
            .admit(server_io, addr("198.51.100.9:4000"))
            .await
            .unwrap();
        assert!(
            entry
                .serve_class(admitted, CancellationToken::new())
                .await
                .is_none()
        );
    };
    let client = async {
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let mut tls = connector.connect(name, client_io).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut answer = Vec::new();
        tls.read_to_end(&mut answer).await.unwrap();
        answer
    };
    let ((), answer) = timeout(Duration::from_secs(10), async {
        tokio::join!(server, client)
    })
    .await
    .unwrap();
    answer
}

#[tokio::test]
async fn a_registered_handler_terminates_tls_on_the_replayed_stream() {
    let (server, connector) = tls_pair(DOMAIN, ALPN_SSH);
    let routes = Arc::new(Mutex::new(Vec::new()));
    let mut config = config();
    config.handlers = ClassHandlers {
        gate: Some(Arc::new(Terminating {
            config: server,
            routes: routes.clone(),
        })),
        kube: None,
    };
    let entry = TlsEntry::new(config).unwrap();
    assert_eq!(ping_through(&entry, &connector, DOMAIN).await, b"ping");
    let routes = routes.lock().unwrap();
    assert_eq!(routes[0].class, EntryClass::Gate(GateProtocol::Ssh));
    assert_eq!(routes[0].hello.server_name(), Some(DOMAIN));
}

#[tokio::test]
async fn a_pass_through_handler_replays_the_hello_so_the_agent_completes_the_handshake() {
    let cluster = format!("prod.kube.{DOMAIN}");
    let (agent, connector) = tls_pair(&cluster, b"h2");
    let mut config = config();
    config.handlers = ClassHandlers {
        gate: None,
        kube: Some(Arc::new(PassThrough {
            agent: TlsAcceptor::from(agent),
        })),
    };
    let entry = TlsEntry::new(config).unwrap();
    assert_eq!(ping_through(&entry, &connector, &cluster).await, b"ping");
}

#[test]
fn admission_and_class_dispatch_can_run_on_spawned_tasks() {
    fn spawnable<F: std::future::Future + Send + 'static>(_: F) {}
    let entry = Arc::new(TlsEntry::new(config()).unwrap());
    let (near, _far) = duplex(64);
    spawnable(async move {
        if let Ok(admitted) = entry.admit(near, addr("198.51.100.9:4000")).await {
            drop(entry.serve_class(admitted, CancellationToken::new()).await);
        }
    });
}

#[test]
fn the_entry_configuration_follows_the_ssh_gate_rules() {
    type Change = fn(&mut TlsEntryConfig);
    let invalid: Vec<(&str, Change)> = vec![
        ("proxy without networks", |config| {
            config.proxy_protocol = true
        }),
        ("networks without proxy", |config| {
            config.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        }),
        ("everything trusted", |config| {
            config.proxy_protocol = true;
            config.trusted_proxies = vec!["0.0.0.0/0".parse().unwrap()];
        }),
        ("zero proxy timeout", |config| {
            config.proxy_header_timeout = Duration::ZERO;
        }),
        ("zero handshake timeout", |config| {
            config.handshake_timeout = Duration::ZERO;
        }),
        ("no handshakes", |config| config.max_handshaking = 0),
        ("no concurrent kube", |config| {
            config.kube_limits = limits(0)
        }),
        ("bad domain", |config| {
            config.domain = Some("*.svc".to_owned())
        }),
        ("agents under the domain", |config| {
            config.agent_names = vec![DOMAIN.to_owned()];
        }),
    ];
    for (name, change) in invalid {
        let mut config = config();
        change(&mut config);
        assert!(TlsEntry::new(config).is_err(), "{name}");
    }
    assert!(TlsEntry::new(proxied(config())).is_ok());
}
