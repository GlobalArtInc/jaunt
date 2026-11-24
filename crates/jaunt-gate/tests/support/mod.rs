#![allow(dead_code)]

mod frames;
mod recorder;

pub use frames::FrameTap;
pub use recorder::{Captured, audit_events, install_recorder};

use std::collections::HashMap;
use std::future::Future;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::RecvStream;
use jaunt_gate::{
    AgentApiHandler, AgentHub, AgentHubConfig, DEFAULT_MAX_API_SESSIONS,
    DEFAULT_MAX_API_SESSIONS_PER_NODE,
};
use jaunt_tunnel::{
    ALPN_TUNNEL, BackoffPolicy, BoxFuture, IncomingStream, NodeId, PeerAuthenticator, RejectReason,
    Rejection, StreamHandler, TunnelClient, TunnelClientConfig, agent_client_config,
    agent_server_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

pub const AGENT_SNI: &str = "agents.test";
pub const OTHER_SNI: &str = "app.test";
const WAIT_LIMIT: Duration = Duration::from_secs(10);
const HELLO: &[u8] = b"{\"type\":\"hello\",\"version\":1,\"agent_version\":\"fake/1\"}\n";

pub struct Pki {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Leaf {
    pub fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

impl Pki {
    pub fn new(common_name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().unwrap();
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).unwrap(),
        }
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    pub fn client_leaf(&self, node: &str) -> Leaf {
        self.issue(
            &format!("{node}.node.test"),
            ExtendedKeyUsagePurpose::ClientAuth,
        )
    }

    fn issue(&self, name: &str, purpose: ExtendedKeyUsagePurpose) -> Leaf {
        let names = if purpose == ExtendedKeyUsagePurpose::ServerAuth {
            vec![AGENT_SNI.to_owned(), OTHER_SNI.to_owned()]
        } else {
            vec![name.to_owned()]
        };
        let mut params = CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![purpose];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        Leaf {
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }
}

#[derive(Default)]
pub struct Verdicts {
    known: Mutex<HashMap<Vec<u8>, Result<NodeId, Rejection>>>,
}

impl Verdicts {
    pub fn allow(&self, leaf: &Leaf, node: &str) {
        self.set(leaf, Ok(NodeId::new(node).unwrap()));
    }

    pub fn refuse(&self, leaf: &Leaf, reason: RejectReason) {
        self.set(leaf, Err(Rejection::new(reason)));
    }

    pub fn refuse_node(&self, leaf: &Leaf, node: &str, reason: RejectReason) {
        self.set(
            leaf,
            Err(Rejection::of_node(reason, NodeId::new(node).unwrap())),
        );
    }

    fn set(&self, leaf: &Leaf, verdict: Result<NodeId, Rejection>) {
        self.known
            .lock()
            .unwrap()
            .insert(leaf.chain[0].as_ref().to_vec(), verdict);
    }
}

impl PeerAuthenticator for Verdicts {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        let verdict = self
            .known
            .lock()
            .unwrap()
            .get(peer_cert_der)
            .cloned()
            .unwrap_or(Err(Rejection::new(RejectReason::UnknownNode)));
        Box::pin(async move { verdict })
    }
}

pub struct Hanging;

impl PeerAuthenticator for Hanging {
    fn authenticate<'a>(
        &'a self,
        _peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(std::future::pending())
    }
}

pub struct Session {
    pub node: NodeId,
    pub shutdown: CancellationToken,
    pub keepalive: bool,
}

pub struct HeldSessions {
    opened: mpsc::UnboundedSender<Session>,
}

impl AgentApiHandler for HeldSessions {
    fn serve(
        &self,
        node: NodeId,
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let opened = self.opened.clone();
        Box::pin(async move {
            let keepalive = socket2::SockRef::from(stream.get_ref().0)
                .keepalive()
                .unwrap();
            opened
                .send(Session {
                    node,
                    shutdown: shutdown.clone(),
                    keepalive,
                })
                .unwrap();
            let mut stream = stream;
            let mut buffer = [0_u8; 64];
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    read = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer) => {
                        if !matches!(read, Ok(count) if count > 0) {
                            break;
                        }
                    }
                }
            }
        })
    }
}

pub struct Unused;

impl AgentApiHandler for Unused {
    fn serve(
        &self,
        _node: NodeId,
        _stream: tokio_rustls::server::TlsStream<TcpStream>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

pub struct TestHub {
    pub hub: AgentHub,
    pub addr: SocketAddr,
    pub sessions: mpsc::UnboundedReceiver<Session>,
}

pub struct HubOptions {
    pub handshake_timeout: Duration,
    pub sessions_per_node: usize,
    pub sessions: usize,
    pub client_limits: jaunt_limits::AddressLimits,
}

impl Default for HubOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            sessions_per_node: DEFAULT_MAX_API_SESSIONS_PER_NODE,
            sessions: DEFAULT_MAX_API_SESSIONS,
            client_limits: jaunt_gate::DEFAULT_AGENT_CLIENT_LIMITS,
        }
    }
}

pub async fn start_hub<A>(pki: &Pki, auth: Arc<A>, options: HubOptions) -> TestHub
where
    A: PeerAuthenticator + 'static,
{
    install_recorder();
    let server = pki.issue("gate", ExtendedKeyUsagePurpose::ServerAuth);
    let tls = agent_server_config(server.chain.clone(), server.key(), pki.roots()).unwrap();
    let mut config = AgentHubConfig::new(AGENT_SNI, Arc::new(tls));
    config.handshake_timeout = options.handshake_timeout;
    config.max_api_sessions_per_node = options.sessions_per_node;
    config.max_api_sessions = options.sessions;
    config.client_limits = options.client_limits;
    let (opened, sessions) = mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hub = AgentHub::start(listener, config, auth, Arc::new(HeldSessions { opened })).unwrap();
    TestHub {
        addr: hub.local_addr(),
        hub,
        sessions,
    }
}

struct Idle;

impl StreamHandler for Idle {
    fn handle(&self, _stream: IncomingStream) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

pub struct TestAgent {
    shutdown: CancellationToken,
    join: JoinHandle<()>,
}

impl TestAgent {
    pub async fn stop(self) {
        self.shutdown.cancel();
        self.join.await.unwrap();
    }
}

pub fn spawn_agent(addr: SocketAddr, pki: &Pki, leaf: &Leaf) -> TestAgent {
    spawn_agent_with(addr, pki, leaf, Arc::new(Idle))
}

pub fn spawn_agent_with(
    addr: SocketAddr,
    pki: &Pki,
    leaf: &Leaf,
    handler: Arc<dyn StreamHandler>,
) -> TestAgent {
    let tls = agent_client_config(pki.roots(), leaf.chain.clone(), leaf.key()).unwrap();
    let mut config =
        TunnelClientConfig::new(Arc::new(tls), addr.to_string(), AGENT_SNI, "test-agent/1");
    config.backoff = BackoffPolicy {
        initial: Duration::from_millis(20),
        max: Duration::from_millis(200),
        reset_after: Duration::from_secs(30),
    };
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let join = tokio::spawn(async move {
        TunnelClient::run(config, handler, token).await.unwrap();
    });
    TestAgent { shutdown, join }
}

pub struct Dialed {
    pub local_addr: SocketAddr,
    pub stream: io::Result<TlsStream<TcpStream>>,
}

pub async fn dial(
    addr: SocketAddr,
    pki: &Pki,
    leaf: Option<&Leaf>,
    name: ServerName<'static>,
    alpn: &[&[u8]],
) -> Dialed {
    let tcp = TcpStream::connect(addr).await.unwrap();
    dial_over(tcp, pki, leaf, name, alpn).await
}

async fn dial_over(
    tcp: TcpStream,
    pki: &Pki,
    leaf: Option<&Leaf>,
    name: ServerName<'static>,
    alpn: &[&[u8]],
) -> Dialed {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(pki.roots());
    let mut config = match leaf {
        Some(leaf) => builder
            .with_client_auth_cert(leaf.chain.clone(), leaf.key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let local_addr = tcp.local_addr().unwrap();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await;
    Dialed { local_addr, stream }
}

pub fn agent_name() -> ServerName<'static> {
    ServerName::try_from(AGENT_SNI).unwrap()
}

pub async fn refused(dialed: Dialed) -> bool {
    let Ok(mut stream) = dialed.stream else {
        return true;
    };
    let mut byte = [0_u8; 1];
    let read = within(
        "the server to close",
        tokio::io::AsyncReadExt::read(&mut stream, &mut byte),
    )
    .await;
    !matches!(read, Ok(count) if count > 0)
}

pub struct FakeAgent {
    pub goaway_codes: Arc<Mutex<Vec<u32>>>,
    pub closed: Arc<AtomicBool>,
    socket: std::net::TcpStream,
    _control: (h2::SendStream<Bytes>, RecvStream),
    _driver: JoinHandle<()>,
}

impl FakeAgent {
    pub fn peer_closed_now(&self) -> bool {
        let mut buffer = [0_u8; 4096];
        loop {
            match (&self.socket).read(&mut buffer) {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return false,
                Err(_) => return true,
            }
        }
    }
}

pub async fn connect_fake_agent(addr: SocketAddr, pki: &Pki, leaf: &Leaf) -> FakeAgent {
    let connected = std::net::TcpStream::connect(addr).unwrap();
    let socket = connected.try_clone().unwrap();
    connected.set_nonblocking(true).unwrap();
    let tcp = TcpStream::from_std(connected).unwrap();
    let dialed = dial_over(tcp, pki, Some(leaf), agent_name(), &[ALPN_TUNNEL]).await;
    let (tap, goaway_codes) = FrameTap::new(dialed.stream.unwrap());
    let mut connection = h2::server::handshake(tap).await.unwrap();
    let (request, mut respond) = within("the control stream", connection.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.uri().path(), "/v1/control");
    let mut send = respond
        .send_response(http::Response::new(()), false)
        .unwrap();
    send.send_data(Bytes::from_static(HELLO), false).unwrap();
    let closed = Arc::new(AtomicBool::new(false));
    let flag = closed.clone();
    let driver = tokio::spawn(async move {
        while let Some(Ok(_)) = connection.accept().await {}
        flag.store(true, Ordering::SeqCst);
    });
    FakeAgent {
        goaway_codes,
        closed,
        socket,
        _control: (send, request.into_body()),
        _driver: driver,
    }
}

pub fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}

pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn audited(what: &str, mut matches: impl FnMut(&Captured) -> bool) -> Captured {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(found) = audit_events().into_iter().find(|event| matches(event)) {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub fn field<'a>(event: &'a Captured, name: &str) -> &'a str {
    event.get(name).map_or("", String::as_str)
}

pub async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT_LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}
