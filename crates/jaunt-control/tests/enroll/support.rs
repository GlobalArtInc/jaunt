use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingSink};
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use jaunt_ca::{AgeIdentity, CaKind, ClientCa, FileBackend, InternalCa, Signer, TrustSet};
use jaunt_control::{
    AgentEndpoint, AgentEventLimits, ApprovedNode, AuthenticatedNode, Clock, Control, ControlError,
    ControlParts, DeviceSettings, GateEndpoint, NodeAdmin, RecordingLimits, RecordingSettings,
    RequestLimits, SshSuffix, Ticker,
};
use jaunt_policy::PolicyHandle;
use jaunt_proto::ClientTransport;
use jaunt_store::Store;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{Error as TlsError, RootCertStore};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

use crate::audit;
use crate::provider::FakeProvider;
use crate::sign_hook::SignHook;

pub const SUFFIX: &str = "jaunt.test";
pub const AGENT_ENDPOINT: &str = "agents.example.com:443";
pub const DEFAULT_PEER: &str = "203.0.113.10";
pub const APPROVER: &str = "cli:tester";
pub const PUBLIC_ORIGIN: &str = "https://jaunt.example.test";

const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone)]
pub struct TestClock {
    base: SystemTime,
    offset_secs: Arc<AtomicU64>,
}

impl TestClock {
    fn new() -> TestClock {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        TestClock {
            base: UNIX_EPOCH + Duration::from_secs(secs),
            offset_secs: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn advance(&self, secs: u64) {
        self.offset_secs.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn now_secs(&self) -> i64 {
        let now = self.base + Duration::from_secs(self.offset_secs.load(Ordering::SeqCst));
        i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
    }

    fn clock(&self) -> Clock {
        let clock = self.clone();
        Arc::new(move || clock.base + Duration::from_secs(clock.offset_secs.load(Ordering::SeqCst)))
    }

    fn ticker(&self) -> Ticker {
        let offset = Arc::clone(&self.offset_secs);
        Arc::new(move || Duration::from_secs(offset.load(Ordering::SeqCst)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostAuthority {
    Matching,
    WrongKind,
    NotTheTrustedKey,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UserTrust {
    Matching,
    RetiredKeyFirst,
    NotTheSigningKey,
}

pub type SinkWrapper = Arc<dyn Fn(Arc<dyn RecordingSink>) -> Arc<dyn RecordingSink> + Send + Sync>;

#[derive(Clone, Default)]
pub struct RecordingOptions {
    pub limits: RecordingLimits,
    pub min_free_bytes: u64,
    pub wrap: Option<SinkWrapper>,
}

pub struct Options {
    pub host_authority: HostAuthority,
    pub user_trust: UserTrust,
    pub empty_policy: bool,
    pub gate_endpoint: Option<&'static str>,
    pub client_ip_header: Option<&'static str>,
    pub trusted_proxies: &'static [&'static str],
    pub recordings: Option<RecordingOptions>,
    pub host_sign_hook: Option<SignHook>,
    pub web: bool,
    pub user_x509_root_age: Option<Duration>,
    pub db_client_root_age: Option<Duration>,
    pub internal_root_age: Duration,
    pub services_domain: Option<&'static str>,
    pub client_transport: Option<ClientTransport>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            host_authority: HostAuthority::Matching,
            user_trust: UserTrust::Matching,
            empty_policy: false,
            gate_endpoint: None,
            client_ip_header: None,
            trusted_proxies: &[],
            recordings: None,
            host_sign_hook: None,
            web: false,
            user_x509_root_age: None,
            db_client_root_age: None,
            internal_root_age: Duration::ZERO,
            services_domain: None,
            client_transport: None,
        }
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }

    pub fn error_code(&self) -> String {
        self.json()["error"].as_str().unwrap().to_owned()
    }

    pub fn state(&self) -> String {
        assert_eq!(self.status, StatusCode::OK, "{}", self.text());
        self.json()["state"].as_str().unwrap().to_owned()
    }
}

pub struct Agent {
    pub tls_public_key: String,
    pub tls_der: Vec<u8>,
    pub ssh_public_key: PublicKey,
    pub ssh_line: String,
}

pub fn new_agent() -> Agent {
    let tls_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let raw = tls_private.public_key().key_data().ed25519().unwrap().0;
    let tls_der = [SPKI_PREFIX.as_slice(), raw.as_slice()].concat();
    let ssh_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ssh_public_key = PublicKey::from(ssh_private.public_key().key_data().clone());
    let mut commented = ssh_public_key.clone();
    commented.set_comment("root@agent");
    Agent {
        tls_public_key: STANDARD.encode(&tls_der),
        tls_der,
        ssh_line: commented.to_openssh().unwrap(),
        ssh_public_key,
    }
}

impl Agent {
    pub fn enroll_body(&self, name: &str) -> Value {
        json!({
            "name": name,
            "labels": {"env": "prod"},
            "hostname": format!("{name}.internal.example.com"),
            "tls_public_key": self.tls_public_key,
            "ssh_host_public_key": self.ssh_line,
            "replace": false,
            "agent_version": "0.1.0",
        })
    }
}

pub struct Enrolled {
    pub handle: String,
    pub code: String,
    pub agent: Agent,
}

impl Enrolled {
    pub fn handle_hash(&self) -> String {
        sha256_hex(&self.handle)
    }
}

pub struct Harness {
    pub router: Router,
    pub agent_router: Router,
    pub control: Control,
    pub admin: NodeAdmin,
    pub policy: PolicyHandle,
    pub store: Store,
    pub clock: TestClock,
    pub root_der: Vec<u8>,
    pub host_ca: PublicKey,
    pub user_trust: TrustSet,
    pub db_path: PathBuf,
    pub recordings_dir: PathBuf,
    pub ca_root: PathBuf,
    pub identity: AgeIdentity,
    _provider: FakeProvider,
    _dir: TempDir,
}

pub fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn sha256_hex_of_bytes(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn request(path: &str, body: &Value, peer: Option<&str>, node: Option<&str>) -> Request<Body> {
    request_raw(
        path,
        "application/json",
        serde_json::to_vec(body).unwrap(),
        peer,
        node,
    )
}

pub fn request_raw(
    path: &str,
    content_type: &str,
    body: Vec<u8>,
    peer: Option<&str>,
    node: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(body))
        .unwrap();
    if let Some(ip) = peer {
        let text = if ip.contains(':') {
            format!("[{ip}]:40000")
        } else {
            format!("{ip}:40000")
        };
        let addr: SocketAddr = text.parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(addr));
    }
    if let Some(node_id) = node {
        request
            .extensions_mut()
            .insert(AuthenticatedNode(node_id.to_owned()));
    }
    request
}

pub async fn send(router: Router, mut request: Request<Body>) -> Reply {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_none()
    {
        let peer: SocketAddr = format!("{DEFAULT_PEER}:40000").parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
    }
    send_without_peer(router, request).await
}

pub async fn send_without_peer(router: Router, request: Request<Body>) -> Reply {
    let response = router.oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

pub fn verify_node_certificate(
    root_der: &[u8],
    cert_der: &[u8],
    at_secs: i64,
) -> Result<(), TlsError> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der.to_vec())).unwrap();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(default_provider()))
            .build()
            .unwrap();
    let at = UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(at_secs).unwrap()));
    verifier
        .verify_client_cert(&CertificateDer::from(cert_der), &[], at)
        .map(|_| ())
}

pub fn host_certificate_is_valid(line: &str, host_ca: &PublicKey, at_secs: i64) -> Certificate {
    let certificate = Certificate::from_openssh(line).unwrap();
    let fingerprint = host_ca.fingerprint(HashAlg::Sha256);
    certificate
        .validate_at(u64::try_from(at_secs).unwrap(), [&fingerprint])
        .unwrap();
    certificate
}

fn loaded_policy(policy_dir: &Path) -> PolicyHandle {
    std::fs::create_dir(policy_dir).unwrap();
    std::fs::write(
        policy_dir.join("roles.yaml"),
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: approvers }\nspec:\n  members: { users: [alice@example.com] }\n  admin: [nodes.approve]\n",
    )
    .unwrap();
    let handle = PolicyHandle::empty();
    let outcome = handle.reload(policy_dir);
    assert!(outcome.applied, "{:?}", outcome.errors);
    handle
}

impl Harness {
    pub async fn new() -> Harness {
        Harness::with(Options::default()).await
    }

    pub async fn with(options: Options) -> Harness {
        match Harness::try_with(options).await {
            Ok(harness) => harness,
            Err(err) => panic!("the harness could not be built: {err}"),
        }
    }

    pub async fn try_with(options: Options) -> Result<Harness, ControlError> {
        audit::install_recorder();
        let dir = tempfile::tempdir().unwrap();
        let ca_root = dir.path().join("ca");
        let identity = AgeIdentity::generate();
        for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
            FileBackend::init(&ca_root, kind, &identity.recipient()).unwrap();
        }
        let (loaded_user_trust, user_authority) =
            FileBackend::load(&ca_root, CaKind::User, &identity).unwrap();
        let user_trust = user_trust_for(options.user_trust, loaded_user_trust);
        let (host_trust, host_signer) =
            FileBackend::load(&ca_root, CaKind::Host, &identity).unwrap();
        let (_, internal_signer) =
            FileBackend::load(&ca_root, CaKind::Internal, &identity).unwrap();
        let host_authority: Arc<dyn Signer> = match options.host_authority {
            HostAuthority::Matching => Arc::new(host_signer),
            HostAuthority::WrongKind => Arc::new(user_authority_clone(&ca_root, &identity)),
            HostAuthority::NotTheTrustedKey => {
                let other = dir.path().join("other-ca");
                FileBackend::init(&other, CaKind::Host, &identity.recipient()).unwrap();
                let (_, foreign) = FileBackend::load(&other, CaKind::Host, &identity).unwrap();
                Arc::new(foreign)
            }
        };
        let host_authority = match options.host_sign_hook {
            Some(hook) => hook.wrap(host_authority),
            None => host_authority,
        };
        let host_ca = host_trust.active().clone();
        let root = InternalCa::create_root(
            &internal_signer,
            SystemTime::now() - options.internal_root_age,
        )
        .unwrap();
        let user_x509 = options.user_x509_root_age.map(|age| {
            ClientCa::init(
                &ca_root,
                CaKind::UserX509,
                &identity.recipient(),
                SystemTime::now() - age,
            )
            .unwrap();
            ClientCa::load(&ca_root, CaKind::UserX509, &identity).unwrap()
        });
        let db_client = options.db_client_root_age.map(|age| {
            ClientCa::init(
                &ca_root,
                CaKind::DbClient,
                &identity.recipient(),
                SystemTime::now() - age,
            )
            .unwrap();
            ClientCa::load(&ca_root, CaKind::DbClient, &identity).unwrap()
        });
        let root_der = root.certificate_der.clone();
        let internal_ca = InternalCa::new(Arc::new(internal_signer), root.certificate_der).unwrap();

        let db_path = dir.path().join("jaunt.db");
        let store = Store::open(&db_path).await.unwrap();
        store.migrate().await.unwrap();

        let provider = FakeProvider::start().await;
        let clock = TestClock::new();
        let policy = if options.empty_policy {
            PolicyHandle::empty()
        } else {
            loaded_policy(&dir.path().join("policy"))
        };
        let recordings_dir = dir.path().join("recordings");
        let recordings = options.recordings.map(|recording| {
            let sink: Arc<dyn RecordingSink> = Arc::new(
                DirectorySink::create(
                    &recordings_dir,
                    DirectoryLimits {
                        min_free_bytes: recording.min_free_bytes,
                        max_total_raw: recording.limits.chunk.max_total_raw,
                    },
                )
                .unwrap(),
            );
            RecordingSettings {
                sink: recording.wrap.map_or(sink.clone(), |wrap| wrap(sink)),
                limits: recording.limits,
            }
        });
        let control = Control::with_limits_and_ticker(
            ControlParts {
                store: store.clone(),
                oidc: provider.oidc_client().await,
                user_authority: Arc::new(user_authority),
                user_trust: user_trust.clone(),
                host_trust,
                host_authority,
                ca_dir: ca_root.clone(),
                internal_ca,
                ssh_suffix: SshSuffix::parse(SUFFIX).unwrap(),
                gate_endpoint: options
                    .gate_endpoint
                    .map(|text| GateEndpoint::parse(text).unwrap()),
                agent_endpoint: AgentEndpoint::parse(AGENT_ENDPOINT).unwrap(),
                cert_ttl: Duration::from_secs(8 * 60 * 60),
                pending_capacity: 100,
                device: DeviceSettings {
                    enabled: false,
                    public_origin: "https://jaunt.example.test".to_owned(),
                    client_ip_header: options.client_ip_header.map(str::to_owned),
                    client_ip_trusted_proxies: options
                        .trusted_proxies
                        .iter()
                        .map(|network| network.parse().unwrap())
                        .collect(),
                },
                policy: policy.clone(),
                web_enabled: options.web,
                clock: clock.clock(),
                recordings,
                user_x509,
                services_domain: options.services_domain.map(str::to_owned),
                client_transport: options.client_transport,
                db_client,
                agent_events: AgentEventLimits::default(),
            },
            RequestLimits::default(),
            clock.ticker(),
        )?;
        Ok(Harness {
            router: control.router(),
            agent_router: control.agent_router(),
            admin: control.node_admin(),
            policy,
            control,
            store,
            clock,
            root_der,
            host_ca,
            user_trust,
            db_path,
            recordings_dir,
            ca_root,
            identity,
            _provider: provider,
            _dir: dir,
        })
    }

    pub async fn enroll_from(&self, peer: &str, body: &Value) -> Reply {
        send(
            self.router.clone(),
            request("/v1/agent/enroll", body, Some(peer), None),
        )
        .await
    }

    pub async fn enroll_body(&self, body: &Value) -> Reply {
        self.enroll_from(DEFAULT_PEER, body).await
    }

    pub async fn enroll(&self, name: &str) -> Enrolled {
        self.enroll_from_peer(DEFAULT_PEER, name).await
    }

    pub async fn enroll_from_peer(&self, peer: &str, name: &str) -> Enrolled {
        let agent = new_agent();
        let reply = self.enroll_from(peer, &agent.enroll_body(name)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let body = reply.json();
        Enrolled {
            handle: body["handle"].as_str().unwrap().to_owned(),
            code: body["code"].as_str().unwrap().to_owned(),
            agent,
        }
    }

    pub async fn poll(&self, handle: &str) -> Reply {
        send(
            self.router.clone(),
            request(
                "/v1/agent/enroll/poll",
                &json!({"handle": handle}),
                Some(DEFAULT_PEER),
                None,
            ),
        )
        .await
    }

    pub async fn renew(&self, node_id: Option<&str>, body: &Value) -> Reply {
        send(
            self.agent_router.clone(),
            request("/v1/agent/renew", body, None, node_id),
        )
        .await
    }

    pub async fn approve(&self, enrolled: &Enrolled) -> ApprovedNode {
        self.admin
            .approve(&enrolled.code, APPROVER, None)
            .await
            .unwrap()
    }

    pub async fn enrolled_node(&self, name: &str) -> (Enrolled, Value) {
        let enrolled = self.enroll(name).await;
        self.approve(&enrolled).await;
        let reply = self.poll(&enrolled.handle).await;
        assert_eq!(reply.state(), "approved", "{}", reply.text());
        let body = reply.json();
        (enrolled, body)
    }
}

fn user_trust_for(choice: UserTrust, loaded: TrustSet) -> TrustSet {
    let signing = loaded.active().clone();
    let stranger = PublicKey::from(
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .key_data()
            .clone(),
    );
    match choice {
        UserTrust::Matching => loaded,
        UserTrust::RetiredKeyFirst => TrustSet::new(
            vec![stranger, signing.clone()],
            signing.fingerprint(HashAlg::Sha256),
        )
        .unwrap(),
        UserTrust::NotTheSigningKey => TrustSet::new(
            vec![signing, stranger.clone()],
            stranger.fingerprint(HashAlg::Sha256),
        )
        .unwrap(),
    }
}

fn user_authority_clone(ca_root: &std::path::Path, identity: &AgeIdentity) -> FileBackend {
    FileBackend::load(ca_root, CaKind::User, identity)
        .unwrap()
        .1
}
