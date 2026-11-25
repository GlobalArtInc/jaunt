use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::ConnectInfo;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{Method, Request, StatusCode, header};
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, PrivateKey};
use jaunt_ca::{
    AgeIdentity, CaKind, DEFAULT_NODE_VALIDITY, FileBackend, InternalCa, NodeCertParams, Signer,
    SubjectPublicKey, Uuid,
};
use jaunt_control::{
    AgentEndpoint, Clock, Control, ControlParts, DeviceSettings, NodeAdmin, SshSuffix,
};
use jaunt_policy::PolicyHandle;
use jaunt_store::Store;
use jaunt_tunnel::{
    ALPN_TUNNEL, BackoffPolicy, BoxFuture, IncomingStream, StreamHandler, TunnelClient,
    TunnelClientConfig, agent_client_config,
};
use jauntd::agents::{AgentServer, AgentServerParts, AgentsSettings, ApiLimits};
use jauntd::recordings::{PreparedRecordings, RecordingsSettings};
use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::version::TLS13;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::oidc::FakeDiscovery;
use crate::recorder::{Captured, audit_events, install_recorder};

pub const AGENTS_NAME: &str = "agents.jaunt.test";
pub const APPROVER: &str = "cli:tester";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const DAY: u64 = 24 * 60 * 60;

#[derive(Clone)]
pub struct TestClock {
    base: SystemTime,
    offset_secs: Arc<AtomicU64>,
}

impl TestClock {
    fn starting_days_ago(days: u64) -> Self {
        Self {
            base: SystemTime::now() - Duration::from_secs(days * DAY),
            offset_secs: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn advance_days(&self, days: u64) {
        self.offset_secs.fetch_add(days * DAY, Ordering::SeqCst);
    }

    fn clock(&self) -> Clock {
        let clock = self.clone();
        Arc::new(move || clock.base + Duration::from_secs(clock.offset_secs.load(Ordering::SeqCst)))
    }
}

#[derive(Default)]
pub struct Options {
    pub clock_days_behind: u64,
    pub api_limits: Option<ApiLimits>,
    pub reconcile_interval: Option<Duration>,
    pub session_sweep_interval: Option<Duration>,
    pub agent_gone_after: Option<Duration>,
    pub recordings: Option<RecordingsSettings>,
    pub web: bool,
}

pub struct Authorities {
    pub user: Arc<dyn Signer>,
    pub host: Arc<dyn Signer>,
    pub user_lines: Vec<String>,
}

pub struct Harness {
    pub control: Control,
    pub admin: NodeAdmin,
    pub store: Store,
    pub server: AgentServer,
    pub clock: TestClock,
    pub authorities: Authorities,
    pub db_path: PathBuf,
    pub recordings: Option<PreparedRecordings>,
    issuer: InternalCa,
    _discovery: FakeDiscovery,
    _dir: TempDir,
}

pub struct EnrolledAgent {
    pub name: String,
    pub node_id: String,
    pub chain: Vec<CertificateDer<'static>>,
    key: Vec<u8>,
}

impl EnrolledAgent {
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.clone()))
    }
}

impl Harness {
    pub async fn start(options: Options) -> Harness {
        install_recorder();
        let dir = tempfile::tempdir().unwrap();
        let ca_root = dir.path().join("ca");
        let identity = AgeIdentity::generate();
        for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
            FileBackend::init(&ca_root, kind, &identity.recipient()).unwrap();
        }
        let (user_trust, user) = FileBackend::load(&ca_root, CaKind::User, &identity).unwrap();
        let (host_trust, host) = FileBackend::load(&ca_root, CaKind::Host, &identity).unwrap();
        let (internal_ca, issuer) = internal_cas(&ca_root, &identity);
        let authorities = Authorities {
            user: Arc::new(
                FileBackend::load(&ca_root, CaKind::User, &identity)
                    .unwrap()
                    .1,
            ),
            host: Arc::new(
                FileBackend::load(&ca_root, CaKind::Host, &identity)
                    .unwrap()
                    .1,
            ),
            user_lines: user_trust.to_authorized_lines().unwrap(),
        };
        let db_path = dir.path().join("jaunt.db");
        let store = Store::open(&db_path).await.unwrap();
        store.migrate().await.unwrap();
        let discovery = FakeDiscovery::start().await;
        let recordings = options
            .recordings
            .as_ref()
            .map(|settings| jauntd::recordings::prepare(settings).unwrap());
        let control = Control::new(ControlParts {
            store: store.clone(),
            oidc: discovery.client().await,
            user_authority: Arc::new(user),
            user_trust,
            host_trust,
            host_authority: Arc::new(host),
            ca_dir: ca_root.clone(),
            internal_ca,
            ssh_suffix: SshSuffix::parse("jaunt.test").unwrap(),
            gate_endpoint: None,
            agent_endpoint: AgentEndpoint::parse(&format!("{AGENTS_NAME}:443")).unwrap(),
            cert_ttl: Duration::from_secs(8 * 60 * 60),
            pending_capacity: 100,
            device: DeviceSettings {
                enabled: false,
                public_origin: "https://jaunt.example.test".to_owned(),
                client_ip_header: None,
                client_ip_trusted_proxies: Vec::new(),
            },
            policy: PolicyHandle::empty(),
            web_enabled: options.web,
            clock: Arc::new(SystemTime::now),
            recordings: recordings
                .as_ref()
                .map(|prepared| prepared.settings.clone()),
        })
        .unwrap();
        let clock = TestClock::starting_days_ago(options.clock_days_behind);
        let mut parts = AgentServerParts::new(
            AgentsSettings {
                listen: "127.0.0.1:0".parse().unwrap(),
                server_name: AGENTS_NAME.to_owned(),
            },
            control.clone(),
            store.clone(),
            clock.clock(),
        );
        parts.reconcile_interval = options
            .reconcile_interval
            .unwrap_or(Duration::from_millis(100));
        parts.certificate_check_interval = Duration::from_millis(20);
        if let Some(limits) = options.api_limits {
            parts.api_limits = limits;
        }
        if let Some(every) = options.session_sweep_interval {
            parts.session_sweep_interval = every;
        }
        if let Some(after) = options.agent_gone_after {
            parts.agent_gone_after = after;
        }
        let server = AgentServer::start(parts).await.unwrap();
        Harness {
            admin: control.node_admin(),
            control,
            store,
            server,
            clock,
            authorities,
            issuer,
            db_path,
            recordings,
            _discovery: discovery,
            _dir: dir,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                self.control.internal_root_der().to_vec(),
            ))
            .unwrap();
        roots
    }

    pub async fn enroll(&self, name: &str) -> EnrolledAgent {
        let tls_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let ssh_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let enrolled = self
            .post(
                "/v1/agent/enroll",
                &json!({
                    "name": name,
                    "labels": {"env": "test"},
                    "hostname": format!("{name}.internal.test"),
                    "tls_public_key": STANDARD.encode(tls_key.subject_public_key_info()),
                    "ssh_host_public_key": ssh_key.public_key().to_openssh().unwrap(),
                    "replace": false,
                    "agent_version": "0.1.0",
                }),
            )
            .await;
        let code = enrolled["code"].as_str().unwrap();
        self.admin.approve(code, APPROVER, None).await.unwrap();
        let polled = self
            .post(
                "/v1/agent/enroll/poll",
                &json!({"handle": enrolled["handle"]}),
            )
            .await;
        assert_eq!(polled["state"], "approved", "{polled}");
        EnrolledAgent {
            name: name.to_owned(),
            node_id: polled["node_id"].as_str().unwrap().to_owned(),
            chain: vec![certificate_of(&polled)],
            key: tls_key.serialize_der(),
        }
    }

    pub fn issue_for(&self, node_id: &str, key: &KeyPair) -> Vec<CertificateDer<'static>> {
        issue_node(&self.issuer, node_id, key)
    }

    pub async fn break_node_table(&self) {
        let options = SqliteConnectOptions::new().filename(&self.db_path);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::query("ALTER TABLE nodes RENAME TO nodes_gone")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    async fn post(&self, path: &str, body: &Value) -> Value {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = self.control.router().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn internal_cas(ca_root: &std::path::Path, identity: &AgeIdentity) -> (InternalCa, InternalCa) {
    let (_, signer) = FileBackend::load(ca_root, CaKind::Internal, identity).unwrap();
    let root_time = SystemTime::now() - Duration::from_secs(30 * DAY);
    let root = InternalCa::create_root(&signer, root_time).unwrap();
    let signer: Arc<dyn Signer> = Arc::new(signer);
    (
        InternalCa::new(signer.clone(), root.certificate_der.clone()).unwrap(),
        InternalCa::new(signer, root.certificate_der).unwrap(),
    )
}

pub fn foreign_ca(dir: &std::path::Path) -> InternalCa {
    let identity = AgeIdentity::generate();
    FileBackend::init(dir, CaKind::Internal, &identity.recipient()).unwrap();
    internal_cas(dir, &identity).0
}

pub fn issue_node(ca: &InternalCa, node_id: &str, key: &KeyPair) -> Vec<CertificateDer<'static>> {
    let issued = ca
        .issue_node_certificate(
            NodeCertParams {
                subject_public_key: SubjectPublicKey::from_spki_der(&key.subject_public_key_info())
                    .unwrap(),
                node_id: Uuid::parse_str(node_id).unwrap(),
                validity: DEFAULT_NODE_VALIDITY,
            },
            SystemTime::now(),
        )
        .unwrap();
    vec![CertificateDer::from(issued.certificate_der)]
}

pub fn private_key(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

pub fn certificate_of(body: &Value) -> CertificateDer<'static> {
    CertificateDer::from(
        STANDARD
            .decode(body["x509_certificate_der"].as_str().unwrap())
            .unwrap(),
    )
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

pub fn spawn_agent(harness: &Harness, agent: &EnrolledAgent) -> TestAgent {
    spawn_agent_with(harness, agent, Arc::new(Idle))
}

pub fn spawn_agent_with(
    harness: &Harness,
    agent: &EnrolledAgent,
    handler: Arc<dyn StreamHandler>,
) -> TestAgent {
    let tls = agent_client_config(harness.roots(), agent.chain.clone(), agent.key()).unwrap();
    let mut config = TunnelClientConfig::new(
        Arc::new(tls),
        harness.addr().to_string(),
        AGENTS_NAME,
        "test-agent/1",
    );
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
    pub stream: std::io::Result<TlsStream<TcpStream>>,
}

pub async fn dial(
    harness: &Harness,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    alpn: &[u8],
) -> Dialed {
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13])
        .unwrap()
        .with_root_certificates(harness.roots())
        .with_client_auth_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    let tcp = TcpStream::connect(harness.addr()).await.unwrap();
    let local_addr = tcp.local_addr().unwrap();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(AGENTS_NAME).unwrap(), tcp)
        .await;
    Dialed { local_addr, stream }
}

pub async fn dial_tunnel(
    harness: &Harness,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Dialed {
    dial(harness, chain, key, ALPN_TUNNEL).await
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

pub async fn closed_by_server(dialed: Dialed) -> bool {
    let Ok(mut stream) = dialed.stream else {
        return true;
    };
    let mut buffer = [0_u8; 1024];
    within("the server to close", async {
        loop {
            match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
                Ok(0) | Err(_) => return true,
                Ok(_) => {}
            }
        }
    })
    .await
}

pub struct Reply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

pub async fn api_request(
    sender: &mut h2::client::SendRequest<Bytes>,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("https://{AGENTS_NAME}{path}"));
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).unwrap();
    let mut ready = within("the api connection", sender.clone().ready())
        .await
        .unwrap();
    let (response, mut send) = ready.send_request(request, body.is_none()).unwrap();
    if let Some(body) = body {
        send.send_data(Bytes::from(serde_json::to_vec(body).unwrap()), true)
            .unwrap();
    }
    let response = within("the api response", response).await.unwrap();
    let status = response.status();
    let mut received = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = within("the api body", received.data()).await {
        let chunk = chunk.unwrap();
        received
            .flow_control()
            .release_capacity(chunk.len())
            .unwrap();
        body.extend_from_slice(&chunk);
    }
    Reply { status, body }
}

pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn audited(what: &str, mut matches: impl FnMut(&Captured) -> bool) -> Captured {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(found) = audit_events().into_iter().find(|event| matches(event)) {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
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

pub fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}
