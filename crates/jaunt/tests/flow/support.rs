use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt::agent::SshAgent;
use jaunt::browser::{BrowserError, BrowserOpener};
use jaunt::consent::ConsentPrompt;
use jaunt::login::{LoginError, LoginOptions, LoginPorts, LoginReport, SshSetup, login};
use jaunt::profile::ProfileName;
use jaunt::server_url::ServerUrl;
use jaunt::ssh_include::IncludeTarget;
use jaunt_proto::{
    ClientConfig, ErrorBody, FinishRequest, FinishResponse, GateEndpoint, NodeList, NodeSummary,
    ServiceList, ServiceSummary, StartRequest, StartResponse, WhoamiResponse,
    X509CertificateRequest, X509CertificateResponse,
};
use sha2::{Digest, Sha256};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::public::KeyData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, PrivateKey, PublicKey};
use url::Url;

pub const LOGIN_ID: &str = "7b9d6a02-3f4e-4a62-8f5c-2c1f6f0f9a11";
pub const COMPLETION_CODE: &str = "cmFuZG9tLWNvbXBsZXRpb24tY29kZS0xMjM0NTY3ODk";
pub const API_TOKEN: &str = "jt_dG9rZW50b2tlbnRva2VudG9rZW50b2tlbnRva2Vu";
pub const USER_ID: &str = "3f2b1c9e-7a44-4d0e-9c58-0a6b8f1d2e77";
pub const EMAIL: &str = "alice@example.com";
pub const SERIAL: u64 = 7;
pub const DEFAULT_VALIDITY_SECS: u64 = 8 * 3600;
pub const SUFFIX: &str = "example.test";
pub const GATE_HOST: &str = "gate.other.test";
pub const GATE_PORT: u16 = 2222;
pub const HARMLESS_PROGRAM: &str = "/usr/bin/true";
pub const ADMIN_TOKEN_ID: &str = "AbC-_09xyzQ";
pub const ADMIN_TOKEN: &str = "jat_AbC-_09xyzQ_s3cr3t-s3cr3t_s3cr3t-s3cr3t_s3cr3t-s3cr3t_Z";

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

pub fn serial_section() -> MutexGuard<'static, ()> {
    SPAWN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn new_key_data() -> KeyData {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .key_data()
        .clone()
}

pub fn ca_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

pub struct CertSpec {
    pub subject: KeyData,
    pub cert_type: CertType,
    pub principals: Vec<String>,
    pub serial: u64,
    pub key_id: String,
    pub valid_after: u64,
    pub valid_before: u64,
}

impl CertSpec {
    pub fn user(subject: KeyData, validity_secs: u64) -> CertSpec {
        let now = now_secs();
        CertSpec {
            subject,
            cert_type: CertType::User,
            principals: vec![USER_ID.to_owned()],
            serial: SERIAL,
            key_id: format!("jaunt:{EMAIL}:{SERIAL}"),
            valid_after: now - 120,
            valid_before: now + validity_secs,
        }
    }
}

pub fn sign(ca: &PrivateKey, spec: &CertSpec) -> Certificate {
    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        spec.subject.clone(),
        spec.valid_after,
        spec.valid_before,
    )
    .unwrap();
    builder.serial(spec.serial).unwrap();
    builder.cert_type(spec.cert_type).unwrap();
    builder.key_id(spec.key_id.clone()).unwrap();
    for principal in &spec.principals {
        builder.valid_principal(principal.clone()).unwrap();
    }
    builder.sign(ca).unwrap()
}

pub fn response_for(certificate: &Certificate, spec: &CertSpec) -> FinishResponse {
    let ca_line = PublicKey::from(ca_key().public_key().key_data().clone())
        .to_openssh()
        .unwrap();
    FinishResponse {
        certificate: certificate.to_openssh().unwrap(),
        serial: i64::try_from(spec.serial).unwrap(),
        key_id: spec.key_id.clone(),
        valid_after: i64::try_from(spec.valid_after).unwrap(),
        valid_before: i64::try_from(spec.valid_before).unwrap(),
        api_token: API_TOKEN.to_owned(),
        token_expires_at: i64::try_from(spec.valid_before).unwrap(),
        user_id: USER_ID.to_owned(),
        email: EMAIL.to_owned(),
        host_ca_keys: vec![ca_line],
    }
}

#[derive(Clone, Default)]
pub enum ClientConfigReply {
    #[default]
    NotConfigured,
    Valid,
    Failing,
    Custom(serde_json::Value),
}

#[derive(Clone, Default)]
pub enum V2Reply {
    #[default]
    Missing,
    Status(StatusCode),
    Json(serde_json::Value),
}

#[derive(Clone, Default)]
pub enum X509Reply {
    #[default]
    Missing,
    NotConfigured,
    Garbage,
    Issue {
        valid_before: i64,
    },
    IssueUnder {
        valid_before: i64,
        root_der: Vec<u8>,
        root_key_der: Vec<u8>,
    },
}

#[derive(Clone, Default)]
pub struct Behavior {
    pub client_config: ClientConfigReply,
    pub client_config_v2: V2Reply,
    pub services: Option<Vec<ServiceSummary>>,
    pub x509: X509Reply,
    pub nodes: Vec<NodeSummary>,
    pub finish_error: Option<&'static str>,
    pub principals: Option<Vec<String>>,
    pub host_certificate: bool,
    pub foreign_key: bool,
    pub validity_secs: Option<u64>,
    pub authorize_url: Option<String>,
    pub admin_status: Option<StatusCode>,
}

#[derive(Default)]
pub struct Seen {
    pub redirect_port: Option<u16>,
    pub challenge_method: Option<String>,
    pub label: Option<String>,
    pub verifier: Option<String>,
    pub completion: Option<String>,
    pub public_key: Option<String>,
    pub finish_calls: usize,
    pub client_config_calls: usize,
    pub client_config_v2_calls: usize,
    pub x509_requests: Vec<SeenRequest>,
    pub revoked: bool,
    pub requests: usize,
    pub admin_requests: Vec<Vec<(String, String)>>,
    pub token_requests: Vec<SeenRequest>,
}

#[derive(Clone, Debug)]
pub struct SeenRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl SeenRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, value)| value.as_str())
    }
}

fn record_request(shared: &Shared) -> bool {
    let mut seen = shared.seen.lock().unwrap();
    seen.requests += 1;
    seen.revoked
}

struct Shared {
    behavior: Behavior,
    v2: Mutex<V2Reply>,
    ca: PrivateKey,
    host_ca: PrivateKey,
    port: Mutex<u16>,
    seen: Mutex<Seen>,
    challenge: Mutex<Option<String>>,
}

pub struct FakeServer {
    shared: Arc<Shared>,
    port: u16,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

fn error_response(status: StatusCode, code: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code.to_owned(),
        }),
    )
        .into_response()
}

async fn start_handler(
    State(shared): State<Arc<Shared>>,
    Json(request): Json<StartRequest>,
) -> Response {
    let port = *shared.port.lock().unwrap();
    {
        let mut seen = shared.seen.lock().unwrap();
        seen.requests += 1;
        seen.redirect_port = u16::try_from(request.redirect_port).ok();
        seen.challenge_method = Some(request.code_challenge_method.clone());
        seen.label.clone_from(&request.client_label);
    }
    *shared.challenge.lock().unwrap() = Some(request.code_challenge);
    let authorize_url = shared
        .behavior
        .authorize_url
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{port}/authorize?state=fake"));
    Json(StartResponse {
        login_id: LOGIN_ID.to_owned(),
        authorize_url,
    })
    .into_response()
}

async fn finish_handler(
    State(shared): State<Arc<Shared>>,
    Json(request): Json<FinishRequest>,
) -> Response {
    {
        let mut seen = shared.seen.lock().unwrap();
        seen.requests += 1;
        seen.finish_calls += 1;
        seen.verifier = Some(request.code_verifier.clone());
        seen.completion.clone_from(&request.completion_code);
        seen.public_key = Some(request.public_key.clone());
    }
    if let Some(code) = shared.behavior.finish_error {
        return error_response(StatusCode::BAD_REQUEST, code);
    }
    let expected = shared.challenge.lock().unwrap().clone();
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(request.code_verifier.as_bytes()));
    let granted = request.login_id == LOGIN_ID
        && expected.as_deref() == Some(computed.as_str())
        && request.completion_code.as_deref() == Some(COMPLETION_CODE);
    if !granted {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let Ok(public) = PublicKey::from_openssh(&request.public_key) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let behavior = &shared.behavior;
    let subject = if behavior.foreign_key {
        new_key_data()
    } else {
        public.key_data().clone()
    };
    let mut spec = CertSpec::user(
        subject,
        behavior.validity_secs.unwrap_or(DEFAULT_VALIDITY_SECS),
    );
    if let Some(principals) = &behavior.principals {
        spec.principals.clone_from(principals);
    }
    if behavior.host_certificate {
        spec.cert_type = CertType::Host;
    }
    let certificate = sign(&shared.ca, &spec);
    Json(response_for(&certificate, &spec)).into_response()
}

async fn whoami_handler(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let revoked = record_request(&shared);
    if revoked || presented != Some(format!("Bearer {API_TOKEN}").as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(WhoamiResponse {
        user_id: USER_ID.to_owned(),
        email: EMAIL.to_owned(),
        groups: vec!["ops".to_owned(), "dev".to_owned()],
        cert_serial: i64::try_from(SERIAL).unwrap(),
        token_expires_at: i64::try_from(now_secs() + DEFAULT_VALIDITY_SECS).unwrap(),
    })
    .into_response()
}

pub const ADMIN_HEADERS: [&str; 4] = [
    "jaunt-certificate",
    "content-digest",
    "signature-input",
    "signature",
];

fn record_token_request(
    shared: &Shared,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) {
    record_request(shared);
    let captured = headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    shared
        .seen
        .lock()
        .unwrap()
        .token_requests
        .push(SeenRequest {
            method: method.as_str().to_owned(),
            path: uri.path().to_owned(),
            headers: captured,
            body: body.to_vec(),
        });
}

fn token_summary() -> serde_json::Value {
    serde_json::json!({
        "id": ADMIN_TOKEN_ID,
        "name": "ci-audit",
        "creator": USER_ID,
        "scope": ["audit.read"],
        "cidrs": [],
        "created_at": 1_700_000_000,
        "expires_at": 1_702_592_000,
        "revoked_at": null,
        "last_used_at": null,
    })
}

async fn tokens_create_handler(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    record_token_request(&shared, &method, &uri, &headers, &body);
    let mut created = token_summary();
    created["secret"] = serde_json::Value::String(ADMIN_TOKEN.to_owned());
    (StatusCode::CREATED, Json(created)).into_response()
}

async fn tokens_list_handler(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    record_token_request(&shared, &method, &uri, &headers, b"");
    Json(serde_json::json!({ "tokens": [token_summary()], "truncated": true })).into_response()
}

async fn tokens_revoke_handler(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Response {
    record_token_request(&shared, &method, &uri, &headers, b"");
    if id == ADMIN_TOKEN_ID {
        StatusCode::NO_CONTENT.into_response()
    } else {
        error_response(StatusCode::NOT_FOUND, "not_found")
    }
}

async fn admin_whoami_handler(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        record_token_request(&shared, &method, &uri, &headers, b"");
        if authorization.to_str().ok() != Some(format!("Bearer {ADMIN_TOKEN}").as_str()) {
            return error_response(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        return Json(serde_json::json!({ "token": {
            "id": ADMIN_TOKEN_ID,
            "name": "ci-audit",
            "scope": ["audit.read"],
            "rights": ["audit.read"],
            "expires_at": 1_702_592_000,
        } }))
        .into_response();
    }
    record_request(&shared);
    let captured = ADMIN_HEADERS
        .iter()
        .filter_map(|name| {
            let value = headers.get(*name)?.to_str().ok()?;
            Some(((*name).to_owned(), value.to_owned()))
        })
        .collect();
    shared.seen.lock().unwrap().admin_requests.push(captured);
    if let Some(status) = shared.behavior.admin_status {
        let code = match status {
            StatusCode::FORBIDDEN => "forbidden",
            StatusCode::NOT_FOUND => "not_found",
            StatusCode::TOO_MANY_REQUESTS => "too_many_requests",
            _ => "unauthorized",
        };
        return error_response(status, code);
    }
    Json(serde_json::json!({
        "user_id": USER_ID,
        "email": EMAIL,
        "display_name": "Alice",
        "groups": ["ops"],
    }))
    .into_response()
}

fn host_ca_line(shared: &Shared) -> String {
    PublicKey::from(shared.host_ca.public_key().key_data().clone())
        .to_openssh()
        .unwrap()
}

async fn client_config_handler(State(shared): State<Arc<Shared>>) -> Response {
    record_request(&shared);
    shared.seen.lock().unwrap().client_config_calls += 1;
    match &shared.behavior.client_config {
        ClientConfigReply::NotConfigured => error_response(StatusCode::NOT_FOUND, "not_configured"),
        ClientConfigReply::Failing => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
        ClientConfigReply::Custom(value) => Json(value.clone()).into_response(),
        ClientConfigReply::Valid => Json(ClientConfig {
            ssh_suffix: SUFFIX.to_owned(),
            gate: GateEndpoint {
                host: GATE_HOST.to_owned(),
                port: GATE_PORT,
            },
            host_ca_keys: vec![host_ca_line(&shared)],
        })
        .into_response(),
    }
}

fn bearer_matches(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(format!("Bearer {API_TOKEN}").as_str())
}

async fn client_config_v2_handler(
    State(shared): State<Arc<Shared>>,
    headers: HeaderMap,
) -> Response {
    let reply = shared.v2.lock().unwrap().clone();
    if matches!(reply, V2Reply::Missing) {
        return StatusCode::NOT_FOUND.into_response();
    }
    shared.seen.lock().unwrap().client_config_v2_calls += 1;
    if !bearer_matches(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match reply {
        V2Reply::Missing => StatusCode::NOT_FOUND.into_response(),
        V2Reply::Status(status) => status.into_response(),
        V2Reply::Json(value) => Json(value).into_response(),
    }
}

async fn services_handler(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let Some(services) = shared.behavior.services.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    record_request(&shared);
    if !bearer_matches(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(ServiceList {
        services,
        truncated: false,
    })
    .into_response()
}

async fn x509_handler(
    State(shared): State<Arc<Shared>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    shared.seen.lock().unwrap().x509_requests.push(SeenRequest {
        method: method.to_string(),
        path: uri.path().to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
    });
    if !bearer_matches(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match shared.behavior.x509 {
        X509Reply::Missing => StatusCode::NOT_FOUND.into_response(),
        X509Reply::NotConfigured => error_response(StatusCode::NOT_FOUND, "not_configured"),
        X509Reply::Garbage => Json(X509CertificateResponse {
            certificate_der: "bm90IGEgY2VydGlmaWNhdGU=".to_owned(),
            serial: 9,
            parent_serial: 7,
            valid_after: 1,
            valid_before: 2,
        })
        .into_response(),
        X509Reply::Issue { valid_before } => {
            let request: X509CertificateRequest = serde_json::from_slice(&body).unwrap();
            Json(user_certificate(&request.public_key, valid_before)).into_response()
        }
        X509Reply::IssueUnder {
            valid_before,
            ref root_der,
            ref root_key_der,
        } => {
            let request: X509CertificateRequest = serde_json::from_slice(&body).unwrap();
            let key = rcgen::KeyPair::try_from(root_key_der.as_slice()).unwrap();
            let issuer = rcgen::Issuer::from_ca_cert_der(&root_der.clone().into(), key).unwrap();
            Json(user_certificate_under(
                &request.public_key,
                valid_before,
                &issuer,
            ))
            .into_response()
        }
    }
}

pub fn user_certificate(public_key: &str, valid_before: i64) -> X509CertificateResponse {
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

    let mut root = CertificateParams::new(Vec::<String>::new()).unwrap();
    root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let issuer = CertifiedIssuer::self_signed(root, KeyPair::generate().unwrap()).unwrap();
    user_certificate_under(public_key, valid_before, &issuer)
}

pub fn user_certificate_under(
    public_key: &str,
    valid_before: i64,
    issuer: &rcgen::Issuer<'_, rcgen::KeyPair>,
) -> X509CertificateResponse {
    use base64::engine::general_purpose::STANDARD;
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, SanType, SubjectPublicKeyInfo};

    let spki = STANDARD.decode(public_key).unwrap();
    let subject = SubjectPublicKeyInfo::from_der(&spki).unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(
        format!("urn:jaunt:user:{USER_ID}").try_into().unwrap(),
    )];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.is_ca = IsCa::ExplicitNoCa;
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    let now = i64::try_from(now_secs()).unwrap();
    params.not_before = epoch + Duration::from_secs(u64::try_from(now - 60).unwrap());
    params.not_after = epoch + Duration::from_secs(u64::try_from(valid_before).unwrap());
    let certificate = params.signed_by(&subject, issuer).unwrap();
    X509CertificateResponse {
        certificate_der: STANDARD.encode(certificate.der()),
        serial: 9,
        parent_serial: 7,
        valid_after: now - 60,
        valid_before,
    }
}

async fn nodes_handler(State(shared): State<Arc<Shared>>, headers: HeaderMap) -> Response {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let revoked = record_request(&shared);
    if revoked || presented != Some(format!("Bearer {API_TOKEN}").as_str()) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    Json(NodeList {
        nodes: shared.behavior.nodes.clone(),
        truncated: false,
    })
    .into_response()
}

impl FakeServer {
    pub fn start(behavior: Behavior) -> FakeServer {
        let shared = Arc::new(Shared {
            v2: Mutex::new(behavior.client_config_v2.clone()),
            behavior,
            ca: ca_key(),
            host_ca: ca_key(),
            port: Mutex::new(0),
            seen: Mutex::new(Seen::default()),
            challenge: Mutex::new(None),
        });
        let router = Router::new()
            .route("/v1/login/start", post(start_handler))
            .route("/v1/login/finish", post(finish_handler))
            .route("/v1/whoami", get(whoami_handler))
            .route("/v1/client-config", get(client_config_handler))
            .route("/v2/client/config", get(client_config_v2_handler))
            .route("/v1/services", get(services_handler))
            .route("/v1/certificates/x509", post(x509_handler))
            .route("/v1/nodes", get(nodes_handler))
            .route("/v1/admin/whoami", get(admin_whoami_handler))
            .route(
                "/v1/admin/tokens",
                get(tokens_list_handler).post(tokens_create_handler),
            )
            .route("/v1/admin/tokens/{id}", delete(tokens_revoke_handler))
            .with_state(Arc::clone(&shared));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread_shared = Arc::clone(&shared);
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                *thread_shared.port.lock().unwrap() = port;
                ready_tx.send(port).unwrap();
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        stop_rx.await.ok();
                    })
                    .await
                    .unwrap();
            });
        });
        let port = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        FakeServer {
            shared,
            port,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn server_url(&self) -> ServerUrl {
        ServerUrl::parse(&self.url()).unwrap()
    }

    pub fn host_ca_line(&self) -> String {
        host_ca_line(&self.shared)
    }

    pub fn redirect_port(&self) -> u16 {
        self.shared.seen.lock().unwrap().redirect_port.unwrap()
    }

    pub fn seen<T>(&self, read: impl FnOnce(&Seen) -> T) -> T {
        read(&self.shared.seen.lock().unwrap())
    }

    pub fn set_client_config_v2(&self, reply: V2Reply) {
        *self.shared.v2.lock().unwrap() = reply;
    }

    pub fn revoke(&self) {
        self.shared.seen.lock().unwrap().revoked = true;
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.send(()).ok();
        }
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

pub fn visit(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[derive(Clone, Copy)]
pub enum Script {
    Approve,
    Deny(&'static str),
    WrongThenApprove,
    ErrorWithoutIdThenApprove,
    Silent,
}

pub struct Browser {
    opened: Arc<Mutex<Vec<String>>>,
    responses: Arc<Mutex<Vec<String>>>,
    shared: Arc<Shared>,
    script: Script,
    fail_to_open: bool,
}

impl Browser {
    pub fn new(server: &FakeServer, script: Script) -> Browser {
        Browser {
            opened: Arc::default(),
            responses: Arc::default(),
            shared: Arc::clone(&server.shared),
            script,
            fail_to_open: false,
        }
    }

    pub fn failing_to_open(mut self) -> Browser {
        self.fail_to_open = true;
        self
    }

    pub fn opened_urls(&self) -> Vec<String> {
        self.opened.lock().unwrap().clone()
    }

    pub fn responses(&self) -> Vec<String> {
        self.responses.lock().unwrap().clone()
    }
}

impl BrowserOpener for Browser {
    fn open(&self, url: &Url) -> Result<(), BrowserError> {
        self.opened.lock().unwrap().push(url.to_string());
        let port = self.shared.seen.lock().unwrap().redirect_port.unwrap();
        let responses = Arc::clone(&self.responses);
        let script = self.script;
        thread::spawn(move || {
            let good = format!("/callback?login_id={LOGIN_ID}&code={COMPLETION_CODE}");
            let mut visited = Vec::new();
            match script {
                Script::Approve => visited.push(visit(port, &good)),
                Script::Deny(code) => {
                    visited.push(visit(
                        port,
                        &format!("/callback?login_id={LOGIN_ID}&error={code}"),
                    ));
                }
                Script::ErrorWithoutIdThenApprove => {
                    visited.push(visit(port, "/callback?error=access_denied"));
                    visited.push(visit(port, &good));
                }
                Script::WrongThenApprove => {
                    let wrong = format!(
                        "/callback?login_id=00000000-0000-0000-0000-000000000000&code={COMPLETION_CODE}"
                    );
                    visited.push(visit(port, &wrong));
                    visited.push(visit(port, &good));
                }
                Script::Silent => {}
            }
            responses.lock().unwrap().extend(visited);
        });
        if self.fail_to_open {
            Err(BrowserError::Failed { program: "test" })
        } else {
            Ok(())
        }
    }
}

pub struct Outcome {
    pub result: Result<LoginReport, LoginError>,
    pub notices: String,
}

pub struct ScriptedPrompt {
    interactive: bool,
    answer: bool,
    asked: Mutex<Vec<String>>,
}

impl ScriptedPrompt {
    pub fn new(interactive: bool, answer: bool) -> ScriptedPrompt {
        ScriptedPrompt {
            interactive,
            answer,
            asked: Mutex::new(Vec::new()),
        }
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl ConsentPrompt for ScriptedPrompt {
    fn interactive(&self) -> bool {
        self.interactive
    }

    fn confirm(&self, question: &str) -> std::io::Result<bool> {
        self.asked.lock().unwrap().push(question.to_owned());
        Ok(self.answer)
    }
}

pub struct LoginSetup<'a> {
    pub profile: &'a str,
    pub ssh: Option<IncludeTarget>,
    pub accept: bool,
    pub prompt: &'a ScriptedPrompt,
}

pub fn run_login(
    server: &FakeServer,
    home: &Path,
    opener: &dyn BrowserOpener,
    agent: &SshAgent,
    no_browser: bool,
    timeout: Duration,
) -> Outcome {
    let prompt = ScriptedPrompt::new(false, false);
    run_login_setup(
        server,
        home,
        opener,
        agent,
        no_browser,
        timeout,
        LoginSetup {
            profile: "default",
            ssh: None,
            accept: false,
            prompt: &prompt,
        },
    )
}

pub fn run_login_setup(
    server: &FakeServer,
    home: &Path,
    opener: &dyn BrowserOpener,
    agent: &SshAgent,
    no_browser: bool,
    timeout: Duration,
    setup: LoginSetup<'_>,
) -> Outcome {
    let options = LoginOptions {
        server: server.server_url(),
        profile: ProfileName::parse(setup.profile).unwrap(),
        home: home.to_owned(),
        no_browser,
        timeout,
        ssh: setup.ssh.map(|include| SshSetup {
            include,
            program: PathBuf::from(HARMLESS_PROGRAM),
            ensure_home: None,
        }),
        accept_ssh_config: setup.accept,
    };
    let mut notices = Vec::new();
    let result = {
        let mut ports = LoginPorts {
            browser: opener,
            agent,
            clock: &SystemTime::now,
            notices: &mut notices,
            consent: setup.prompt,
        };
        login(&options, &mut ports)
    };
    Outcome {
        result,
        notices: String::from_utf8(notices).unwrap(),
    }
}

#[derive(Clone, Copy)]
pub enum RawReply {
    Redirect,
    OversizedContentLength,
    OversizedChunked,
    Dribble,
    Silent,
}

pub struct RawServer {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl RawServer {
    pub fn start(reply: RawReply) -> RawServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests: Arc<Mutex<Vec<String>>> = Arc::default();
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let requests = Arc::clone(&requests);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else {
                        continue;
                    };
                    let requests = Arc::clone(&requests);
                    let stop = Arc::clone(&stop);
                    thread::spawn(move || answer(stream, reply, port, &requests, &stop));
                }
            })
        };
        RawServer {
            port,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    pub fn server_url(&self) -> ServerUrl {
        ServerUrl::parse(&format!("http://127.0.0.1:{}", self.port)).unwrap()
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        TcpStream::connect(("127.0.0.1", self.port)).ok();
        if let Some(thread) = self.thread.take() {
            thread.join().ok();
        }
    }
}

fn answer(
    mut stream: TcpStream,
    reply: RawReply,
    port: u16,
    requests: &Mutex<Vec<String>>,
    stop: &AtomicBool,
) {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut received = Vec::new();
    let mut chunk = [0_u8; 1024];
    let head_end = loop {
        if let Some(position) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => received.extend_from_slice(&chunk[..count]),
        }
    };
    let head = String::from_utf8_lossy(&received[..head_end]).into_owned();
    requests
        .lock()
        .unwrap()
        .push(head.lines().next().unwrap_or_default().to_owned());
    let body_length = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(str::to_owned)
        })
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while received.len() < head_end + body_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(count) => received.extend_from_slice(&chunk[..count]),
        }
    }
    match reply {
        RawReply::Redirect => {
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .ok();
        }
        RawReply::OversizedContentLength => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2000000\r\nConnection: close\r\n\r\n"
            )
            .ok();
        }
        RawReply::OversizedChunked => {
            let block = vec![b'a'; 64 * 1024];
            let mut written = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .is_ok();
            for _ in 0..20 {
                if !written {
                    break;
                }
                written = write!(stream, "{:x}\r\n", block.len()).is_ok()
                    && stream.write_all(&block).is_ok()
                    && stream.write_all(b"\r\n").is_ok();
            }
            if written {
                stream.write_all(b"0\r\n\r\n").ok();
            }
        }
        RawReply::Dribble => {
            let mut written = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n",
                )
                .is_ok();
            let started = std::time::Instant::now();
            while written
                && !stop.load(Ordering::SeqCst)
                && started.elapsed() < Duration::from_secs(20)
            {
                written = stream.write_all(b"x").and_then(|()| stream.flush()).is_ok();
                thread::sleep(Duration::from_millis(100));
            }
        }
        RawReply::Silent => {
            let started = std::time::Instant::now();
            while !stop.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(20) {
                thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let script = dir.join(name);
    fs::write(&script, format!("#!/bin/sh\n{body}")).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

pub fn snapshot(dir: &Path) -> Vec<(String, u32, Vec<u8>)> {
    let mut entries: Vec<(String, u32, Vec<u8>)> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            (
                path.file_name().unwrap().to_string_lossy().into_owned(),
                mode,
                fs::read(&path).unwrap(),
            )
        })
        .collect();
    entries.sort();
    entries
}

pub fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}
