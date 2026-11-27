use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_gate::{
    Clock, ServiceGate, ServiceGateConfig, ServiceGateError, ServiceGateParts, ServicesEntry,
    SshGate, UserX509Roots, UserX509Source,
};
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, BoxFuture, ControlError, ControlPlane, DenyReason,
    GateTlsCertificate, GateTlsIssueError, GateTlsIssuer, LocateServiceRequest, NodeCaller,
    RouteDecision, RouteRequest, ServiceKind, ServiceLocation, ServiceRouteRequest, SessionEnd,
    SessionEndOutcome,
};
use jaunt_tunnel::{IncomingStream, ServedKinds, StreamHandler, StreamKind, StreamMeta};
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PKCS_ED25519, PublicKeyData, SanType, SerialNumber,
    SubjectPublicKeyInfo, date_time_ymd,
};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::support::{
    HubOptions, Pki, TestAgent, TestHub, Verdicts, eventually, node, spawn_agent_serving,
    start_hub, within,
};

pub const DOMAIN: &str = "svc.test";
pub const CLUSTER: &str = "prod";
pub const NODE: &str = "node-a";
pub const USER: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
pub const OTHER_USER: &str = "3f2c1d4e-5b6a-4c7d-8e9f-0a1b2c3d4e5f";
pub const SESSION: &str = "0b6c8f9e-6b1c-4f3e-9d65-6d3c1f4e8a21";
pub const ALPN_SVC: &[u8] = b"jaunt-svc/1";
const WEEK: u64 = 7 * 24 * 3600;
const PROXY_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

pub fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_secs(), Ordering::SeqCst);
    }

    pub fn now(&self) -> SystemTime {
        SystemTime::now() + Duration::from_secs(self.0.load(Ordering::SeqCst))
    }

    pub fn clock(&self) -> Clock {
        let clock = self.clone();
        Arc::new(move || clock.now())
    }
}

fn set_window(params: &mut CertificateParams, not_before: u64, not_after: u64) {
    params.not_before = date_time_ymd(1970, 1, 1) + Duration::from_secs(not_before);
    params.not_after = date_time_ymd(1970, 1, 1) + Duration::from_secs(not_after);
}

fn ed25519_root(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    params.distinguished_name.push(DnType::CommonName, name);
    CertifiedIssuer::self_signed(params, KeyPair::generate_for(&PKCS_ED25519).unwrap()).unwrap()
}

fn roots_of(issuer: &CertifiedIssuer<'static, KeyPair>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(issuer.der().clone()).unwrap();
    roots
}

fn pkcs8(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerMode {
    Normal,
    Failing,
    OtherName,
    OtherKey,
    Expired,
    ClaimsAnotherWindow,
}

pub struct TestIssuer {
    ca: CertifiedIssuer<'static, KeyPair>,
    domain: String,
    clock: TestClock,
    serial: AtomicU64,
    pub mode: Mutex<IssuerMode>,
    pub asked: Mutex<Vec<String>>,
    pub issued: Mutex<Vec<CertificateDer<'static>>>,
}

impl TestIssuer {
    pub fn new(domain: &str, clock: TestClock) -> Arc<Self> {
        Arc::new(Self {
            ca: ed25519_root("gate test ca"),
            domain: domain.to_owned(),
            clock,
            serial: AtomicU64::new(100),
            mode: Mutex::new(IssuerMode::Normal),
            asked: Mutex::new(Vec::new()),
            issued: Mutex::new(Vec::new()),
        })
    }

    pub fn set_mode(&self, mode: IssuerMode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn roots(&self) -> RootCertStore {
        roots_of(&self.ca)
    }

    pub fn last_issued(&self) -> CertificateDer<'static> {
        self.issued.lock().unwrap().last().unwrap().clone()
    }
}

impl GateTlsIssuer for TestIssuer {
    fn issue<'a>(
        &'a self,
        subject_public_key_der: &'a [u8],
        server_name: &'a str,
    ) -> BoxFuture<'a, Result<GateTlsCertificate, GateTlsIssueError>> {
        Box::pin(async move {
            self.asked.lock().unwrap().push(server_name.to_owned());
            if server_name != self.domain {
                return Err(GateTlsIssueError::NameRefused);
            }
            let mode = *self.mode.lock().unwrap();
            if mode == IssuerMode::Failing {
                return Err(GateTlsIssueError::Unavailable);
            }
            let requested = SubjectPublicKeyInfo::from_der(subject_public_key_der)
                .map_err(|_| GateTlsIssueError::InvalidKey)?;
            let foreign = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let real = unix(SystemTime::now());
            let now = unix(self.clock.now());
            let serial = self.serial.fetch_add(1, Ordering::SeqCst);
            let name = match mode {
                IssuerMode::OtherName => "other.test".to_owned(),
                _ => server_name.to_owned(),
            };
            let mut params = CertificateParams::new(vec![name]).unwrap();
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            params.serial_number = Some(SerialNumber::from(serial));
            let (valid_after, valid_before) = match mode {
                IssuerMode::Expired => (real - 7200, real - 3600),
                _ => (real - 60, now - 60 + WEEK),
            };
            set_window(&mut params, valid_after, valid_before);
            let (valid_after, valid_before) = match mode {
                IssuerMode::Expired | IssuerMode::ClaimsAnotherWindow => {
                    (real - 60, real + 30 * WEEK)
                }
                _ => (valid_after, valid_before),
            };
            let certificate = match mode {
                IssuerMode::OtherKey => params.signed_by(&foreign, &*self.ca),
                _ => params.signed_by(&requested, &*self.ca),
            }
            .unwrap()
            .der()
            .clone();
            self.issued.lock().unwrap().push(certificate.clone());
            Ok(GateTlsCertificate {
                certificate_der: certificate.to_vec(),
                serial,
                valid_after,
                valid_before,
            })
        })
    }
}

pub struct UserCert {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: KeyPair,
}

impl UserCert {
    pub fn raw_key(&self) -> [u8; 32] {
        self.key.der_bytes().try_into().unwrap()
    }
}

pub struct UserCa {
    pub issuer: CertifiedIssuer<'static, KeyPair>,
}

impl UserCa {
    pub fn new() -> Self {
        Self {
            issuer: ed25519_root("Jaunt User X.509 CA"),
        }
    }

    pub fn roots(&self) -> Arc<UserX509Roots> {
        Arc::new(UserX509Roots::from_der([self.issuer.der().to_vec()]).unwrap())
    }

    pub fn raw_key(&self) -> [u8; 32] {
        self.issuer.key().der_bytes().try_into().unwrap()
    }

    pub fn user(&self, user: &str, serial: u64) -> UserCert {
        let now = unix(SystemTime::now());
        self.user_valid(user, serial, now - 60, now + 3600)
    }

    pub fn user_valid(&self, user: &str, serial: u64, not_before: u64, not_after: u64) -> UserCert {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = vec![SanType::URI(
            Ia5String::try_from(format!("urn:jaunt:user:{user}")).unwrap(),
        )];
        params
            .distinguished_name
            .push(DnType::CommonName, "alice@example.com");
        params.serial_number = Some(SerialNumber::from(serial));
        set_window(&mut params, not_before, not_after);
        let certificate = params.signed_by(&key, &*self.issuer).unwrap().der().clone();
        UserCert {
            chain: vec![certificate],
            key,
        }
    }
}

pub struct FixedRoots(pub Mutex<Option<Arc<UserX509Roots>>>);

impl UserX509Source for FixedRoots {
    fn current(&self) -> Option<Arc<UserX509Roots>> {
        self.0.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAnswer {
    Allow,
    Deny,
    Fail,
}

pub struct FakeControl {
    pub clusters: Mutex<HashMap<String, String>>,
    pub locates: Mutex<Vec<LocateServiceRequest>>,
    pub answer: Mutex<RouteAnswer>,
    pub routes: Mutex<Vec<ServiceRouteRequest>>,
    sessions: AtomicUsize,
}

impl FakeControl {
    pub fn new() -> Arc<Self> {
        let mut clusters = HashMap::new();
        clusters.insert(CLUSTER.to_owned(), NODE.to_owned());
        clusters.insert("orphan".to_owned(), "node-gone".to_owned());
        Arc::new(Self {
            clusters: Mutex::new(clusters),
            locates: Mutex::new(Vec::new()),
            answer: Mutex::new(RouteAnswer::Allow),
            routes: Mutex::new(Vec::new()),
            sessions: AtomicUsize::new(0),
        })
    }

    pub fn answer(&self, answer: RouteAnswer) {
        *self.answer.lock().unwrap() = answer;
    }

    pub fn routes(&self) -> Vec<ServiceRouteRequest> {
        self.routes.lock().unwrap().clone()
    }

    pub fn locates(&self) -> usize {
        self.locates.lock().unwrap().len()
    }

    pub fn locates_of(&self, name: &str) -> usize {
        self.locates
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.name == name)
            .count()
    }
}

impl ControlPlane for FakeControl {
    fn route(&self, _request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn authorize(
        &self,
        _node: NodeCaller,
        _request: AuthorizeRequest,
    ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn session_end(
        &self,
        _node: NodeCaller,
        _request: SessionEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn locate_service(
        &self,
        request: LocateServiceRequest,
    ) -> BoxFuture<'_, Result<Option<ServiceLocation>, ControlError>> {
        let found = self.clusters.lock().unwrap().get(&request.name).cloned();
        self.locates.lock().unwrap().push(request);
        Box::pin(async move {
            Ok(found.map(|node_id| ServiceLocation {
                node_id,
                kind: ServiceKind::Kubernetes,
            }))
        })
    }

    fn route_service(
        &self,
        request: ServiceRouteRequest,
    ) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        self.routes.lock().unwrap().push(request);
        let answer = self.answer.lock().unwrap().clone();
        let count = self.sessions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            match answer {
                RouteAnswer::Allow => Ok(RouteDecision::Allow {
                    session_id: if count == 0 {
                        SESSION.to_owned()
                    } else {
                        format!("session-{count}")
                    },
                    node_id: NODE.to_owned(),
                }),
                RouteAnswer::Deny => Ok(RouteDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                }),
                RouteAnswer::Fail => Err(ControlError::Store),
            }
        })
    }
}

#[derive(Debug)]
pub enum AgentEvent {
    Opened(StreamMeta),
    Received(Vec<u8>),
}

#[derive(Clone)]
pub enum Reply {
    AfterEnd(Arc<Vec<u8>>),
    Tls(TlsAcceptor),
    CloseAfterOneByte,
    Burst(Arc<Vec<u8>>),
}

struct RecordingAgent {
    events: mpsc::UnboundedSender<AgentEvent>,
    reply: Reply,
}

impl StreamHandler for RecordingAgent {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let events = self.events.clone();
        let reply = self.reply.clone();
        Box::pin(async move {
            let IncomingStream { meta, mut io, .. } = stream;
            events.send(AgentEvent::Opened(meta)).unwrap();
            match reply {
                Reply::AfterEnd(answer) => {
                    let mut received = Vec::new();
                    if io.read_to_end(&mut received).await.is_err() {
                        return;
                    }
                    events.send(AgentEvent::Received(received)).unwrap();
                    if io.write_all(&answer).await.is_ok() {
                        drop(io.shutdown().await);
                    }
                }
                Reply::CloseAfterOneByte => {
                    let mut one = [0_u8; 1];
                    if io.read_exact(&mut one).await.is_err() || io.shutdown().await.is_err() {
                        return;
                    }
                    events.send(AgentEvent::Received(one.to_vec())).unwrap();
                    let mut sink = Vec::new();
                    drop(io.read_to_end(&mut sink).await);
                }
                Reply::Burst(burst) => {
                    if io.write_all(&burst).await.is_err() {
                        return;
                    }
                    let mut sink = Vec::new();
                    drop(io.read_to_end(&mut sink).await);
                }
                Reply::Tls(acceptor) => {
                    let Ok(mut tls) = acceptor.accept(io).await else {
                        return;
                    };
                    let mut ping = [0_u8; 4];
                    if tls.read_exact(&mut ping).await.is_err() {
                        return;
                    }
                    events.send(AgentEvent::Received(ping.to_vec())).unwrap();
                    if tls.write_all(b"pong").await.is_ok() {
                        drop(tls.shutdown().await);
                    }
                }
            }
        })
    }
}

pub struct AgentTls {
    pub acceptor: TlsAcceptor,
    pub client: Arc<ClientConfig>,
}

pub fn agent_tls(name: &str, alpn: &[u8]) -> AgentTls {
    let agent_ca = ed25519_root("agent service ca");
    let people = ed25519_root("people ca");
    let server_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut server = CertificateParams::new(vec![name.to_owned()]).unwrap();
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server
        .signed_by(&server_key, &*agent_ca)
        .unwrap()
        .der()
        .clone();
    let client_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client
        .signed_by(&client_key, &*people)
        .unwrap()
        .der()
        .clone();
    let provider = Arc::new(default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots_of(&people)), provider.clone())
            .build()
            .unwrap();
    let mut server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server_cert], pkcs8(&server_key))
        .unwrap();
    server_config.alpn_protocols = vec![alpn.to_vec()];
    let mut client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(roots_of(&agent_ca))
        .with_client_auth_cert(vec![client_cert], pkcs8(&client_key))
        .unwrap();
    client_config.alpn_protocols = vec![alpn.to_vec()];
    AgentTls {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        client: Arc::new(client_config),
    }
}

pub struct Options {
    pub served: Vec<StreamKind>,
    pub proxied: bool,
    pub entry_kube_per_address: Option<usize>,
    pub reply: Reply,
    pub configure: fn(&mut ServiceGateConfig),
    pub ssh: Option<Arc<SshGate>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            served: vec![StreamKind::Kube, StreamKind::Db, StreamKind::Tcp],
            proxied: false,
            entry_kube_per_address: None,
            reply: Reply::AfterEnd(Arc::new(b"from the agent".to_vec())),
            configure: |_| {},
            ssh: None,
        }
    }
}

pub struct Fixture {
    pub hub: TestHub,
    pub addr: SocketAddr,
    pub gate: Arc<ServiceGate>,
    pub control: Arc<FakeControl>,
    pub issuer: Arc<TestIssuer>,
    pub users: UserCa,
    pub roots: Arc<FixedRoots>,
    pub clock: TestClock,
    pub events: mpsc::UnboundedReceiver<AgentEvent>,
    pub proxied: bool,
    pub pki: Pki,
    agent: TestAgent,
    _agents: Option<TestHub>,
}

pub async fn gate_with(
    issuer: Arc<TestIssuer>,
    config: ServiceGateConfig,
    clock: &TestClock,
) -> Result<ServiceGate, ServiceGateError> {
    ServiceGate::new(ServiceGateParts {
        config,
        issuer,
        user_x509: Arc::new(FixedRoots(Mutex::new(None))),
        control: FakeControl::new(),
        registry: jaunt_tunnel::AgentRegistry::new(),
        ssh: None,
        clock: clock.clock(),
    })
    .await
}

impl Fixture {
    pub async fn start(options: Options) -> Self {
        let pki = Pki::new("tunnel ca");
        let leaf = pki.client_leaf(NODE);
        let verdicts = Arc::new(Verdicts::default());
        verdicts.allow(&leaf, NODE);
        let mut services = ServicesEntry::new(DOMAIN);
        if options.proxied {
            services.proxy_protocol = true;
            services.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        }
        if let Some(concurrent) = options.entry_kube_per_address {
            services.kube_limits = jaunt_limits::AddressLimits {
                rate: jaunt_limits::Rate::clamped(10_000, 10_000),
                concurrent,
                tracked: jaunt_limits::DEFAULT_CAPACITY,
            };
        }
        let hub = start_hub(
            &pki,
            verdicts.clone(),
            HubOptions {
                services: Some(services),
                ..HubOptions::default()
            },
        )
        .await;
        let agents = if options.proxied {
            Some(start_hub(&pki, verdicts, HubOptions::default()).await)
        } else {
            None
        };
        let agents_addr = agents.as_ref().map_or(hub.addr, |agents| agents.addr);
        let registry = agents.as_ref().map_or_else(
            || hub.hub.registry().clone(),
            |agents| agents.hub.registry().clone(),
        );
        let (sender, events) = mpsc::unbounded_channel();
        let agent = spawn_agent_serving(
            agents_addr,
            &pki,
            &leaf,
            Arc::new(RecordingAgent {
                events: sender,
                reply: options.reply,
            }),
            ServedKinds::new(options.served).unwrap(),
        );
        eventually("the agent tunnel", || registry.is_connected(&node(NODE))).await;
        let clock = TestClock::new();
        let issuer = TestIssuer::new(DOMAIN, clock.clone());
        let users = UserCa::new();
        let roots = Arc::new(FixedRoots(Mutex::new(Some(users.roots()))));
        let control = FakeControl::new();
        let mut config = ServiceGateConfig::new(DOMAIN);
        (options.configure)(&mut config);
        let gate = Arc::new(
            ServiceGate::new(ServiceGateParts {
                config,
                issuer: issuer.clone(),
                user_x509: roots.clone(),
                control: control.clone(),
                registry,
                ssh: options.ssh,
                clock: clock.clock(),
            })
            .await
            .unwrap(),
        );
        assert!(hub.hub.install_class_handlers(gate.handlers()));
        Self {
            addr: hub.addr,
            hub,
            gate,
            control,
            issuer,
            users,
            roots,
            clock,
            events,
            proxied: options.proxied,
            pki,
            agent,
            _agents: agents,
        }
    }

    pub async fn tcp(&self, client: [u8; 4]) -> TcpStream {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        if self.proxied {
            tcp.write_all(&proxy_header(client)).await.unwrap();
        }
        tcp
    }

    pub async fn tcp_local(&self) -> TcpStream {
        let mut tcp = TcpStream::connect(self.addr).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        tcp.write_all(&proxy_local()).await.unwrap();
        tcp
    }

    pub async fn svc_local(&self, user: &UserCert) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = self.tcp_local().await;
        within(
            "the outer handshake",
            TlsConnector::from(self.outer_config(Some(user)))
                .connect(ServerName::try_from(DOMAIN).unwrap(), tcp),
        )
        .await
    }

    pub async fn svc_small_window(&self, user: &UserCert) -> TlsStream<TcpStream> {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(16 * 1024).unwrap();
        let tcp = socket.connect(self.addr).await.unwrap();
        within(
            "the outer handshake",
            TlsConnector::from(self.outer_config(Some(user)))
                .connect(ServerName::try_from(DOMAIN).unwrap(), tcp),
        )
        .await
        .unwrap()
    }

    pub fn outer_config(&self, user: Option<&UserCert>) -> Arc<ClientConfig> {
        let builder = ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(self.issuer.roots());
        let mut config = match user {
            Some(user) => builder
                .with_client_auth_cert(user.chain.clone(), pkcs8(&user.key))
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![ALPN_SVC.to_vec()];
        Arc::new(config)
    }

    pub async fn svc(
        &self,
        client: [u8; 4],
        user: Option<&UserCert>,
    ) -> std::io::Result<TlsStream<TcpStream>> {
        self.svc_with(client, self.outer_config(user)).await
    }

    pub async fn svc_with(
        &self,
        client: [u8; 4],
        config: Arc<ClientConfig>,
    ) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = self.tcp(client).await;
        within(
            "the outer handshake",
            TlsConnector::from(config).connect(ServerName::try_from(DOMAIN).unwrap(), tcp),
        )
        .await
    }

    pub async fn next_event(&mut self) -> AgentEvent {
        within("an agent event", self.events.recv()).await.unwrap()
    }

    pub async fn idle(&self) {
        eventually("every gate slot to be released", || {
            self.gate.stats() == jaunt_gate::ServiceGateStats::default()
                && self.hub.hub.entry_handshaking() == 0
        })
        .await;
    }

    pub async fn stop(self) {
        self.agent.stop().await;
    }

    pub async fn stop_entry(self) -> Arc<ServiceGate> {
        self.hub.hub.shutdown(Duration::from_secs(5)).await;
        self.agent.stop().await;
        self.gate
    }
}

pub fn proxy_local() -> Vec<u8> {
    let mut header = PROXY_SIGNATURE.to_vec();
    header.extend_from_slice(&[0x20, 0x00, 0, 0]);
    header
}

pub fn proxy_header(client: [u8; 4]) -> Vec<u8> {
    let mut header = PROXY_SIGNATURE.to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&client);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&40_000_u16.to_be_bytes());
    header.extend_from_slice(&443_u16.to_be_bytes());
    header
}

fn be16(len: usize) -> [u8; 2] {
    u16::try_from(len).unwrap().to_be_bytes()
}

fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend(kind.to_be_bytes());
    out.extend(be16(data.len()));
    out.extend(data);
}

pub fn hello(server_name: Option<&str>) -> Vec<u8> {
    hello_with_alpn(server_name, &[])
}

pub fn hello_with_alpn(server_name: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(name) = server_name {
        let mut list = vec![0];
        list.extend(be16(name.len()));
        list.extend(name.as_bytes());
        let mut data = be16(list.len()).to_vec();
        data.extend(list);
        extension(&mut extensions, 0x0000, &data);
    }
    extension(&mut extensions, 0x002b, &[2, 3, 4]);
    extension(&mut extensions, 0x000d, &[0, 2, 8, 7]);
    if !alpn.is_empty() {
        let mut list = Vec::new();
        for protocol in alpn {
            list.push(u8::try_from(protocol.len()).unwrap());
            list.extend(*protocol);
        }
        let mut data = be16(list.len()).to_vec();
        data.extend(list);
        extension(&mut extensions, 0x0010, &data);
    }
    let mut body = vec![3, 3];
    body.extend([0x11; 32]);
    body.push(32);
    body.extend([0x22; 32]);
    body.extend([0, 2, 0x13, 0x01, 1, 0]);
    body.extend(be16(extensions.len()));
    body.extend(extensions);
    let mut message = vec![1, 0];
    message.extend(be16(body.len()));
    message.extend(body);
    [&[22, 3, 1][..], &be16(message.len()), &message].concat()
}

pub fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

pub async fn read_all<R: AsyncRead + Unpin>(stream: &mut R) -> std::io::Result<Vec<u8>> {
    let mut all = Vec::new();
    within("the stream to end", stream.read_to_end(&mut all))
        .await
        .map(|_| all)
}

pub async fn closed_without_bytes<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> bool {
    let mut buffer = [0_u8; 64];
    let read = within("the gate to close", stream.read(&mut buffer)).await;
    !matches!(read, Ok(count) if count > 0)
}
