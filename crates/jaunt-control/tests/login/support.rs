use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::net::SocketAddr;
use std::path::Path;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, PrivateKey};
use jaunt_ca::{AgeIdentity, CaKind, FileBackend, InternalCa, Signer};
use jaunt_control::{
    AgentEndpoint, Clock, Control, ControlError, ControlParts, DeviceSettings, SshSuffix,
};
use jaunt_policy::PolicyHandle;
use jaunt_store::Store;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

use crate::provider::{FakeProvider, Identity, form_pairs};

pub const DEFAULT_CERT_TTL_SECS: u64 = 8 * 60 * 60;
pub const LOGIN_TTL_SECS: u64 = 300;
pub const PUBLIC_ORIGIN: &str = "https://jaunt.example";
pub const DEFAULT_PEER: &str = "198.51.100.7:50000";
pub const UNISSUED_CODE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const POLICY_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [\"{username}\"] }\n";

fn loaded_policy(dir: &Path) -> PolicyHandle {
    let policy_dir = dir.join("policy");
    std::fs::create_dir(&policy_dir).unwrap();
    std::fs::write(policy_dir.join("roles.yaml"), POLICY_ROLE).unwrap();
    let handle = PolicyHandle::empty();
    let outcome = handle.reload(&policy_dir);
    assert!(outcome.applied, "{:?}", outcome.errors);
    handle
}

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
}

pub struct Options {
    pub cert_ttl_secs: u64,
    pub pending_capacity: usize,
    pub authority: CaKind,
    pub device_login: bool,
    pub client_ip_header: Option<&'static str>,
    pub public_origin: &'static str,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            cert_ttl_secs: DEFAULT_CERT_TTL_SECS,
            pending_capacity: 100,
            authority: CaKind::User,
            device_login: true,
            client_ip_header: None,
            public_origin: PUBLIC_ORIGIN,
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

    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).unwrap().to_str().unwrap()
    }

    pub fn location(&self) -> &str {
        assert_eq!(self.status, StatusCode::FOUND);
        self.header("location")
    }

    pub fn refresh_target(&self) -> String {
        assert_eq!(self.status, StatusCode::OK, "{}", self.text());
        assert!(self.headers.get("location").is_none());
        self.header("refresh")
            .strip_prefix("0; url=")
            .unwrap()
            .to_owned()
    }

    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all("set-cookie")
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect()
    }

    pub fn error_code(&self) -> String {
        self.json()["error"].as_str().unwrap().to_owned()
    }
}

pub struct Session {
    pub login_id: String,
    pub verifier: String,
    pub authorize_url: String,
    pub state: String,
    pub port: u16,
    completion: OnceLock<String>,
}

impl Session {
    pub fn completion_code(&self) -> &str {
        self.completion.get().map_or(UNISSUED_CODE, String::as_str)
    }

    pub fn record_completion(&self, location: &str) -> &str {
        let code = completion_code_in(location, self);
        self.completion
            .set(code)
            .expect("the session was approved twice");
        self.completion_code()
    }
}

pub struct Harness {
    pub router: Router,
    pub control: Control,
    pub store: Store,
    pub provider: FakeProvider,
    pub clock: TestClock,
    pub host_keys: Vec<String>,
    counter: AtomicU64,
    _dir: TempDir,
}

pub fn completion_code_in(location: &str, session: &Session) -> String {
    let prefix = format!(
        "http://127.0.0.1:{}/callback?login_id={}&code=",
        session.port, session.login_id
    );
    let code = location
        .strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("unexpected redirect {location}"));
    assert_eq!(code.len(), 43, "{location}");
    assert!(
        code.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "{location}"
    );
    code.to_owned()
}

pub fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn ed25519_public_key_line(comment: &str) -> String {
    let private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut public = private.public_key().clone();
    public.set_comment(comment);
    public.to_openssh().unwrap()
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
        crate::audit::install_recorder();
        let dir = tempfile::tempdir().unwrap();
        let ca_root = dir.path().join("ca");
        let identity = AgeIdentity::generate();
        for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
            FileBackend::init(&ca_root, kind, &identity.recipient()).unwrap();
        }
        let (_user_trust, user_authority) =
            FileBackend::load(&ca_root, CaKind::User, &identity).unwrap();
        let (host_trust, host_authority) =
            FileBackend::load(&ca_root, CaKind::Host, &identity).unwrap();
        let (_internal_trust, internal_authority) =
            FileBackend::load(&ca_root, CaKind::Internal, &identity).unwrap();
        let authority: Arc<dyn Signer> = match options.authority {
            CaKind::User => Arc::new(user_authority),
            CaKind::Host => Arc::new(host_authority),
            CaKind::Internal => Arc::new(internal_authority),
        };
        let host_keys = host_trust.to_authorized_lines().unwrap();
        let (_, host_signer) = FileBackend::load(&ca_root, CaKind::Host, &identity).unwrap();
        let (_, internal_signer) =
            FileBackend::load(&ca_root, CaKind::Internal, &identity).unwrap();
        let root = InternalCa::create_root(&internal_signer, SystemTime::now()).unwrap();
        let internal_ca = InternalCa::new(Arc::new(internal_signer), root.certificate_der).unwrap();

        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();

        let provider = FakeProvider::start().await;
        let clock = TestClock::new();
        let control = Control::new(ControlParts {
            store: store.clone(),
            oidc: provider.oidc_client().await,
            user_authority: authority,
            host_trust,
            host_authority: Arc::new(host_signer),
            internal_ca,
            ssh_suffix: SshSuffix::parse("jaunt.test").unwrap(),
            gate_endpoint: None,
            agent_endpoint: AgentEndpoint::parse("agents.example.com:443").unwrap(),
            cert_ttl: Duration::from_secs(options.cert_ttl_secs),
            pending_capacity: options.pending_capacity,
            device: DeviceSettings {
                enabled: options.device_login,
                public_origin: options.public_origin.to_owned(),
                client_ip_header: options.client_ip_header.map(str::to_owned),
            },
            policy: loaded_policy(dir.path()),
            clock: clock.clock(),
        })?;
        Ok(Harness {
            router: control.router(),
            control,
            store,
            provider,
            clock,
            host_keys,
            counter: AtomicU64::new(0),
            _dir: dir,
        })
    }

    pub async fn send(&self, mut request: Request<Body>) -> Reply {
        if request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_none()
        {
            let peer: SocketAddr = DEFAULT_PEER.parse().unwrap();
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let response = self.router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: body.to_vec(),
        }
    }

    pub async fn post_raw(&self, path: &str, content_type: Option<&str>, body: Vec<u8>) -> Reply {
        let mut builder = Request::builder().method(Method::POST).uri(path);
        if let Some(content_type) = content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        self.send(builder.body(Body::from(body)).unwrap()).await
    }

    pub async fn post_json(&self, path: &str, body: &Value) -> Reply {
        self.post_raw(
            path,
            Some("application/json"),
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    pub async fn get(&self, uri: &str) -> Reply {
        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        self.send(request).await
    }

    pub async fn get_with_headers(&self, uri: &str, headers: &[(&str, &str)]) -> Reply {
        let mut builder = Request::builder().method(Method::GET).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        self.send(builder.body(Body::empty()).unwrap()).await
    }

    pub fn next_verifier(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        format!("verifier-{n:0>34}")
    }

    pub async fn start_body(&self, body: &Value) -> Reply {
        self.post_json("/v1/login/start", body).await
    }

    pub async fn begin_on(&self, port: u16) -> Session {
        let verifier = self.next_verifier();
        let reply = self
            .start_body(&json!({
                "code_challenge": challenge_for(&verifier),
                "code_challenge_method": "S256",
                "redirect_port": port,
                "client_label": "test laptop",
            }))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let body = reply.json();
        let authorize_url = body["authorize_url"].as_str().unwrap().to_owned();
        let query = authorize_url.split_once('?').unwrap().1;
        Session {
            login_id: body["login_id"].as_str().unwrap().to_owned(),
            verifier,
            state: form_pairs(query)["state"].clone(),
            authorize_url,
            port,
            completion: OnceLock::new(),
        }
    }

    pub async fn begin(&self) -> Session {
        self.begin_on(45123).await
    }

    pub fn browser_code(&self, session: &Session) -> String {
        self.provider
            .grant(&session.authorize_url, Identity::alice())
    }

    pub async fn callback(&self, query: &str) -> Reply {
        self.get(&format!("/v1/login/callback?{query}")).await
    }

    pub async fn approve(&self, session: &Session) -> Reply {
        let code = self.browser_code(session);
        let reply = self
            .callback(&format!("code={code}&state={}", session.state))
            .await;
        session.record_completion(reply.location());
        reply
    }

    pub async fn finish_raw(
        &self,
        login_id: &str,
        verifier: &str,
        completion_code: &str,
        public_key: &str,
    ) -> Reply {
        self.post_json(
            "/v1/login/finish",
            &json!({
                "login_id": login_id,
                "code_verifier": verifier,
                "completion_code": completion_code,
                "public_key": public_key,
            }),
        )
        .await
    }

    pub async fn finish(&self, session: &Session, public_key: &str) -> Reply {
        self.finish_raw(
            &session.login_id,
            &session.verifier,
            session.completion_code(),
            public_key,
        )
        .await
    }

    pub async fn login(&self) -> Value {
        let session = self.begin().await;
        self.approve(&session).await;
        let reply = self
            .finish(&session, &ed25519_public_key_line("alice@laptop"))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        reply.json()
    }

    pub async fn whoami(&self, token: &str) -> Reply {
        self.get_with_headers(
            "/v1/whoami",
            &[("authorization", &format!("Bearer {token}"))],
        )
        .await
    }
}
