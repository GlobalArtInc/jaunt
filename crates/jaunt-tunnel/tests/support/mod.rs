#![allow(dead_code, unused_imports)]

mod raw;

pub use raw::*;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use http::Request;
use jaunt_tunnel::{
    AcceptorConfig, AgentApiConnection, AgentRegistry, BackoffPolicy, BoxFuture, ClientError,
    ClientEvent, Gate, GateAcceptor, GateStats, H2Io, Handover, IncomingStream, MainConnection,
    NodeId, PeerAuthenticator, RejectReason, Rejection, SessionId, SessionRegistry, StreamHandler,
    StreamKind, StreamMeta, TunnelClient, TunnelClientConfig, TunnelOptions, agent_client_config,
    agent_server_config, main_server_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader, ReadBuf, ReadHalf,
    WriteHalf,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

pub const AGENT_SNI: &str = "agents.test";
pub const MAIN_SNI: &str = "app.test";
const WAIT_LIMIT: Duration = Duration::from_secs(10);

pub struct Pki {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

pub struct Leaf {
    pub chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Leaf {
    pub fn der(&self) -> Vec<u8> {
        self.chain[0].as_ref().to_vec()
    }

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

    pub fn server_leaf(&self) -> Leaf {
        self.issue(
            &[AGENT_SNI, MAIN_SNI, "127.0.0.1"],
            ExtendedKeyUsagePurpose::ServerAuth,
            "gate",
        )
    }

    pub fn client_leaf(&self, node: &str) -> Leaf {
        self.issue(
            &[&format!("{node}.node.test")],
            ExtendedKeyUsagePurpose::ClientAuth,
            node,
        )
    }

    fn issue(&self, names: &[&str], purpose: ExtendedKeyUsagePurpose, common_name: &str) -> Leaf {
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let mut params = CertificateParams::new(names).unwrap();
        params.extended_key_usages = vec![purpose];
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        Leaf {
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        }
    }
}

#[derive(Default)]
pub struct MapAuthenticator {
    known: Mutex<HashMap<Vec<u8>, NodeId>>,
}

impl MapAuthenticator {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn allow(&self, leaf: &Leaf, node: &str) {
        self.known
            .lock()
            .unwrap()
            .insert(leaf.der(), NodeId::new(node).unwrap());
    }
}

impl PeerAuthenticator for MapAuthenticator {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(async move {
            self.known
                .lock()
                .unwrap()
                .get(peer_cert_der)
                .cloned()
                .ok_or(Rejection::new(RejectReason::UnknownNode))
        })
    }
}

pub struct HangingAuthenticator;

impl PeerAuthenticator for HangingAuthenticator {
    fn authenticate<'a>(
        &'a self,
        _peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(std::future::pending())
    }
}

pub struct NoHandover;

impl Handover for NoHandover {
    fn main(&self, _connection: MainConnection) {}

    fn agent_api(&self, _connection: AgentApiConnection) {}
}

struct Collector {
    main: mpsc::UnboundedSender<MainConnection>,
    api: mpsc::UnboundedSender<AgentApiConnection>,
}

impl Handover for Collector {
    fn main(&self, connection: MainConnection) {
        self.main.send(connection).unwrap();
    }

    fn agent_api(&self, connection: AgentApiConnection) {
        self.api.send(connection).unwrap();
    }
}

#[derive(Clone)]
pub struct GateOptions {
    pub tunnel: TunnelOptions,
    pub handshake_timeout: Duration,
    pub max_handshaking: usize,
}

impl Default for GateOptions {
    fn default() -> Self {
        Self {
            tunnel: TunnelOptions::default(),
            handshake_timeout: Duration::from_secs(10),
            max_handshaking: 1024,
        }
    }
}

pub struct TestGate {
    pub addr: SocketAddr,
    pub gate: Gate,
    pub registry: AgentRegistry,
    pub stats: Arc<GateStats>,
    pub shutdown: CancellationToken,
    pub main: mpsc::UnboundedReceiver<MainConnection>,
    pub api: mpsc::UnboundedReceiver<AgentApiConnection>,
    pub events: broadcast::Receiver<jaunt_tunnel::RegistryEvent>,
    serve: JoinHandle<()>,
}

impl TestGate {
    pub async fn start(pki: &Pki, auth: Arc<dyn PeerAuthenticator>, options: GateOptions) -> Self {
        Self::start_at("127.0.0.1:0".parse().unwrap(), pki, auth, options).await
    }

    pub async fn start_at(
        addr: SocketAddr,
        pki: &Pki,
        auth: Arc<dyn PeerAuthenticator>,
        options: GateOptions,
    ) -> Self {
        let server = pki.server_leaf();
        let agent = agent_server_config(server.chain.clone(), server.key(), pki.roots()).unwrap();
        let main = main_server_config(server.chain.clone(), server.key()).unwrap();
        let mut acceptor_config =
            AcceptorConfig::new(vec![AGENT_SNI.to_owned()], Arc::new(agent), Arc::new(main));
        acceptor_config.handshake_timeout = options.handshake_timeout;
        acceptor_config.max_handshaking = options.max_handshaking;
        let stats = Arc::new(GateStats::default());
        let acceptor = GateAcceptor::new(acceptor_config, stats.clone()).unwrap();
        let registry = AgentRegistry::new();
        let events = registry.subscribe();
        let (main_tx, main_rx) = mpsc::unbounded_channel();
        let (api_tx, api_rx) = mpsc::unbounded_channel();
        let gate = Gate::new(
            acceptor,
            registry.clone(),
            auth,
            Arc::new(Collector {
                main: main_tx,
                api: api_tx,
            }),
            options.tunnel,
        )
        .unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = gate.clone();
        let token = shutdown.clone();
        let serve = tokio::spawn(async move { serving.serve(listener, token).await.unwrap() });
        Self {
            addr,
            gate,
            registry,
            stats,
            shutdown,
            main: main_rx,
            api: api_rx,
            events,
            serve,
        }
    }

    pub async fn stop(self) -> SocketAddr {
        self.shutdown.cancel();
        self.serve.await.unwrap();
        self.addr
    }
}

pub struct AgentOptions {
    pub tunnel: TunnelOptions,
    pub backoff: BackoffPolicy,
}

impl Default for AgentOptions {
    fn default() -> Self {
        Self {
            tunnel: TunnelOptions::default(),
            backoff: BackoffPolicy {
                initial: Duration::from_millis(20),
                max: Duration::from_millis(200),
                reset_after: Duration::from_secs(30),
            },
        }
    }
}

pub struct TestAgent {
    pub shutdown: CancellationToken,
    pub events: broadcast::Receiver<ClientEvent>,
    pub sessions: SessionRegistry,
    pub join: JoinHandle<Result<(), ClientError>>,
}

impl TestAgent {
    pub async fn stop(self) {
        self.shutdown.cancel();
        self.join.await.unwrap().unwrap();
    }
}

pub fn spawn_agent(
    addr: SocketAddr,
    pki: &Pki,
    leaf: &Leaf,
    handler: Arc<dyn StreamHandler>,
    options: AgentOptions,
) -> TestAgent {
    let tls = agent_client_config(pki.roots(), leaf.chain.clone(), leaf.key()).unwrap();
    let mut config =
        TunnelClientConfig::new(Arc::new(tls), addr.to_string(), AGENT_SNI, "test-agent/1");
    config.options = options.tunnel;
    config.backoff = options.backoff;
    let events = config.subscribe();
    let sessions = config.sessions.clone();
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();
    let join = tokio::spawn(TunnelClient::run(config, handler, token));
    TestAgent {
        shutdown,
        events,
        sessions,
        join,
    }
}

struct ClosureHandler<F>(F);

impl<F> StreamHandler for ClosureHandler<F>
where
    F: Fn(IncomingStream) -> BoxFuture<'static, ()> + Send + Sync,
{
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        (self.0)(stream)
    }
}

pub fn handler<F, Fut>(function: F) -> Arc<dyn StreamHandler>
where
    F: Fn(IncomingStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    Arc::new(ClosureHandler(move |stream| {
        Box::pin(function(stream)) as BoxFuture<'static, ()>
    }))
}

pub fn echo_handler() -> Arc<dyn StreamHandler> {
    handler(|stream: IncomingStream| async move {
        let (mut reader, mut writer) = tokio::io::split(stream.io);
        if tokio::io::copy(&mut reader, &mut writer).await.is_ok() {
            tokio::io::AsyncWriteExt::shutdown(&mut writer).await.ok();
        }
    })
}

pub fn idle_handler() -> Arc<dyn StreamHandler> {
    handler(|_stream: IncomingStream| async move {})
}

pub fn meta(session: &str) -> StreamMeta {
    StreamMeta::new(
        SessionId::new(session).unwrap(),
        StreamKind::Ssh,
        "203.0.113.5:40000",
    )
    .unwrap()
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

pub async fn next_event<T: Clone>(
    events: &mut broadcast::Receiver<T>,
    what: &str,
    mut accept: impl FnMut(&T) -> bool,
) -> T {
    let wait = async {
        loop {
            match events.recv().await {
                Ok(event) if accept(&event) => return event,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("event stream closed"),
            }
        }
    };
    tokio::time::timeout(WAIT_LIMIT, wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

pub async fn wait_connected(gate: &mut TestGate, name: &str) -> jaunt_tunnel::ConnectionId {
    let expected = node(name);
    let event = next_event(&mut gate.events, "agent connection", |event| match event {
        jaunt_tunnel::RegistryEvent::Connected { node, .. }
        | jaunt_tunnel::RegistryEvent::Replaced { node, .. } => *node == expected,
        jaunt_tunnel::RegistryEvent::Disconnected { .. } => false,
    })
    .await;
    match event {
        jaunt_tunnel::RegistryEvent::Connected { connection, .. }
        | jaunt_tunnel::RegistryEvent::Replaced { connection, .. } => connection,
        jaunt_tunnel::RegistryEvent::Disconnected { .. } => unreachable!(),
    }
}

pub async fn within<T>(what: &str, limit: Duration, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(limit, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

pub async fn soon<T>(what: &str, future: impl Future<Output = T>) -> T {
    within(what, WAIT_LIMIT, future).await
}

pub fn raw_client_config(
    roots: RootCertStore,
    leaf: Option<&Leaf>,
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> Arc<ClientConfig> {
    let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match leaf {
        Some(leaf) => builder
            .with_client_auth_cert(leaf.chain.clone(), leaf.key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Arc::new(config)
}

pub fn dns_name(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).unwrap()
}

pub fn ip_name(address: IpAddr) -> ServerName<'static> {
    ServerName::IpAddress(address.into())
}

pub async fn tls_connect(
    addr: SocketAddr,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(config).connect(name, tcp).await
}
