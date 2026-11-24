use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    EnrollRequest, EnrollResponse, EnrollmentApproved, ErrorBody, NodeCertificates, PollRequest,
    PollResponse, RenewRequest,
};
use jaunt_tunnel::{
    AcceptorConfig, AgentApiConnection, AgentRegistry, BoxFuture, Gate, GateAcceptor, GateStats,
    Handover, Keepalive, MainConnection, NodeId, PeerAuthenticator, RegistryEvent, RejectReason,
    Rejection, SwappableClientCert, TunnelOptions, agent_client_config_swappable,
    agent_server_config, main_server_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::public::KeyData;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::clock::Clock;
use crate::endpoint::AgentEndpoint;
use crate::run::api::{API_KEEPALIVE, AgentApi};

pub const NODE_ID: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
pub const NODE_NAME: &str = "web-01";
pub const CODE: &str = "ABCD-2345";
pub const HANDLE: &str = "handle-secret-7f3a9c";
pub const SUFFIX: &str = "jaunt.test";
pub const EXPIRES_AT: i64 = 1_900_000_000;
pub const AGENT_HOST: &str = "localhost";
const WAIT_LIMIT: Duration = Duration::from_secs(15);
const WEEK: i64 = 7 * 24 * 3600;

pub fn unix_now() -> i64 {
    crate::clock::unix_secs(SystemTime::now())
}

pub async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT_LIMIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn soon<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT_LIMIT, future)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn offset(secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap()
}

pub struct TestPki {
    issuer: CertifiedIssuer<'static, KeyPair>,
    host_ca: PrivateKey,
}

impl TestPki {
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "jaunt test internal root");
        let key = KeyPair::generate().unwrap();
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).unwrap(),
            host_ca: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
        }
    }

    pub fn root_der(&self) -> &[u8] {
        self.issuer.der().as_ref()
    }

    pub fn root_base64(&self) -> String {
        STANDARD.encode(self.root_der())
    }

    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    pub fn server_leaf(
        &self,
        name: &str,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    pub fn leaf_der(&self, name: &str) -> Vec<u8> {
        self.server_leaf(name).0[0].to_vec()
    }

    pub fn node_x509(&self, spki: &[u8], node_id: &str, not_before: i64, not_after: i64) -> String {
        self.node_x509_with(spki, node_id, not_before, not_after, &|_| {})
    }

    pub fn node_x509_with(
        &self,
        spki: &[u8],
        node_id: &str,
        not_before: i64,
        not_after: i64,
        adjust: &dyn Fn(&mut CertificateParams),
    ) -> String {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(
            format!("urn:jaunt:node:{node_id}").try_into().unwrap(),
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.not_before = offset(not_before);
        params.not_after = offset(not_after);
        adjust(&mut params);
        let subject = rcgen::SubjectPublicKeyInfo::from_der(spki).unwrap();
        let cert = params.signed_by(&subject, &*self.issuer).unwrap();
        STANDARD.encode(cert.der())
    }

    pub fn host_certificate(
        &self,
        key: &KeyData,
        principals: &[&str],
        valid_after: i64,
        valid_before: i64,
    ) -> String {
        self.ssh_certificate(key, CertType::Host, principals, valid_after, valid_before)
    }

    pub fn user_certificate(&self, key: &KeyData, valid_after: i64, valid_before: i64) -> String {
        self.ssh_certificate(key, CertType::User, &["root"], valid_after, valid_before)
    }

    fn ssh_certificate(
        &self,
        key: &KeyData,
        kind: CertType,
        principals: &[&str],
        valid_after: i64,
        valid_before: i64,
    ) -> String {
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            key.clone(),
            u64::try_from(valid_after).unwrap(),
            u64::try_from(valid_before).unwrap(),
        )
        .unwrap();
        builder.cert_type(kind).unwrap();
        builder.key_id("test").unwrap();
        for principal in principals {
            builder.valid_principal(*principal).unwrap();
        }
        builder.sign(&self.host_ca).unwrap().to_openssh().unwrap()
    }

    pub fn node_certificates(
        &self,
        spki: &[u8],
        host_key: &KeyData,
        node_id: &str,
        name: &str,
    ) -> NodeCertificates {
        let now = unix_now();
        self.node_certificates_for(spki, host_key, node_id, name, now - 60, now + WEEK)
    }

    pub fn node_certificates_for(
        &self,
        spki: &[u8],
        host_key: &KeyData,
        node_id: &str,
        name: &str,
        not_before: i64,
        not_after: i64,
    ) -> NodeCertificates {
        let qualified = format!("{name}.{SUFFIX}");
        NodeCertificates {
            x509_certificate_der: self.node_x509(spki, node_id, not_before, not_after),
            x509_not_after: not_after,
            ssh_host_certificate: self.host_certificate(
                host_key,
                &[qualified.as_str(), name],
                not_before,
                not_after,
            ),
            ssh_not_after: not_after,
        }
    }
}

struct SleepState {
    now: SystemTime,
    sleepers: Vec<(u64, SystemTime)>,
    slept: Vec<Duration>,
    next_id: u64,
}

pub struct ManualClock {
    state: Mutex<SleepState>,
    changed: watch::Sender<u64>,
    auto_advance: bool,
}

impl ManualClock {
    pub fn new(now: SystemTime) -> Arc<Self> {
        Self::build(now, false)
    }

    pub fn auto(now: SystemTime) -> Arc<Self> {
        Self::build(now, true)
    }

    fn build(now: SystemTime, auto_advance: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SleepState {
                now,
                sleepers: Vec::new(),
                slept: Vec::new(),
                next_id: 0,
            }),
            changed: watch::Sender::new(0),
            auto_advance,
        })
    }

    pub fn set(&self, now: SystemTime) {
        self.state.lock().unwrap().now = now;
        self.changed.send_modify(|version| *version += 1);
    }

    pub fn advance(&self, by: Duration) {
        let now = self.now() + by;
        self.set(now);
    }

    pub fn slept(&self) -> Vec<Duration> {
        self.state.lock().unwrap().slept.clone()
    }

    pub fn sleepers(&self) -> Vec<SystemTime> {
        self.state
            .lock()
            .unwrap()
            .sleepers
            .iter()
            .map(|(_, deadline)| *deadline)
            .collect()
    }

    pub async fn wait_for_sleeper(&self, deadline: SystemTime) {
        eventually("a sleeper with the expected deadline", || {
            self.sleepers().contains(&deadline)
        })
        .await;
    }

    fn register(&self, deadline: SystemTime) -> u64 {
        let mut state = self.state.lock().unwrap();
        let id = state.next_id;
        state.next_id += 1;
        state.sleepers.push((id, deadline));
        let wait = deadline.duration_since(state.now).unwrap_or_default();
        state.slept.push(wait);
        id
    }

    fn unregister(&self, id: u64) {
        self.state
            .lock()
            .unwrap()
            .sleepers
            .retain(|(other, _)| *other != id);
    }
}

struct Registration<'a> {
    clock: &'a ManualClock,
    id: u64,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.clock.unregister(self.id);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        self.state.lock().unwrap().now
    }

    fn sleep_until(&self, deadline: SystemTime) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if self.auto_advance {
                let mut state = self.state.lock().unwrap();
                let wait = deadline.duration_since(state.now).unwrap_or_default();
                state.slept.push(wait);
                if deadline > state.now {
                    state.now = deadline;
                }
                return;
            }
            let mut changes = self.changed.subscribe();
            let _registration = Registration {
                clock: self,
                id: self.register(deadline),
            };
            while self.now() < deadline {
                if changes.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        })
    }
}

#[derive(Clone, Default)]
pub struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl LogCapture {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    pub fn install(&self) -> tracing::subscriber::DefaultGuard {
        let filter = crate::run::logging::build_filter(Some("info,jaunt=debug")).unwrap();
        tracing::subscriber::set_default(crate::run::logging::subscriber(filter, self.clone()))
    }
}

impl io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for LogCapture {
    type Writer = LogCapture;

    fn make_writer(&self) -> LogCapture {
        self.clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approval {
    Valid,
    OtherKey,
    WrongNode,
    Expired,
    BadHostCertificate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollStep {
    Pending,
    Rejected,
    Expired,
    AlreadyDelivered,
    NotFound,
    TooMany,
    Unavailable,
    Oversized,
    Approve(Approval),
}

pub const OVERSIZED_BODY: usize = 70 * 1024;

pub struct ControlScript {
    pub enroll_status: StatusCode,
    pub enroll_error: &'static str,
    pub redirect_to: Option<String>,
    pub code: String,
    pub polls: VecDeque<PollStep>,
    pub agent_endpoint: String,
    pub create_on_first_poll: Option<PathBuf>,
}

impl ControlScript {
    pub fn new(polls: &[PollStep]) -> Self {
        Self {
            enroll_status: StatusCode::OK,
            enroll_error: "",
            redirect_to: None,
            code: CODE.to_owned(),
            polls: polls.iter().copied().collect(),
            agent_endpoint: "agents.jaunt.test:443".to_owned(),
            create_on_first_poll: None,
        }
    }
}

struct ControlInner {
    pki: Arc<TestPki>,
    script: Mutex<ControlScript>,
    enrolls: Mutex<Vec<EnrollRequest>>,
    polls: Mutex<Vec<String>>,
}

pub struct FakeControl {
    pub url: String,
    inner: Arc<ControlInner>,
    task: JoinHandle<()>,
}

impl FakeControl {
    pub async fn start(pki: Arc<TestPki>, script: ControlScript) -> Self {
        let inner = Arc::new(ControlInner {
            pki,
            script: Mutex::new(script),
            enrolls: Mutex::new(Vec::new()),
            polls: Mutex::new(Vec::new()),
        });
        let router = Router::new()
            .route("/v1/agent/enroll", post(fake_enroll))
            .route("/v1/agent/enroll/poll", post(fake_poll))
            .with_state(inner.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self { url, inner, task }
    }

    pub fn enrolls(&self) -> Vec<EnrollRequest> {
        self.inner.enrolls.lock().unwrap().clone()
    }

    pub fn polls(&self) -> Vec<String> {
        self.inner.polls.lock().unwrap().clone()
    }
}

impl Drop for FakeControl {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn json_reply<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    (
        status,
        [("content-type", "application/json")],
        serde_json::to_vec(body).unwrap(),
    )
        .into_response()
}

fn error_reply(status: StatusCode, code: &str) -> Response {
    json_reply(
        status,
        &ErrorBody {
            error: code.to_owned(),
        },
    )
}

async fn fake_enroll(State(inner): State<Arc<ControlInner>>, body: Bytes) -> Response {
    let request: EnrollRequest = serde_json::from_slice(&body).unwrap();
    inner.enrolls.lock().unwrap().push(request);
    let script = inner.script.lock().unwrap();
    if let Some(target) = &script.redirect_to {
        return (StatusCode::FOUND, [("location", target.clone())]).into_response();
    }
    if script.enroll_status != StatusCode::OK {
        return error_reply(script.enroll_status, script.enroll_error);
    }
    json_reply(
        StatusCode::OK,
        &EnrollResponse {
            handle: HANDLE.to_owned(),
            code: script.code.clone(),
            expires_at: EXPIRES_AT,
            poll_interval: 3,
        },
    )
}

async fn fake_poll(State(inner): State<Arc<ControlInner>>, body: Bytes) -> Response {
    let request: PollRequest = serde_json::from_slice(&body).unwrap();
    inner.polls.lock().unwrap().push(request.handle.clone());
    if request.handle != HANDLE {
        return error_reply(StatusCode::NOT_FOUND, "not_found");
    }
    let (step, endpoint) = {
        let mut script = inner.script.lock().unwrap();
        if let Some(path) = script.create_on_first_poll.take() {
            std::fs::write(path, b"{}").unwrap();
        }
        let step = script.polls.pop_front().unwrap_or(PollStep::Pending);
        (step, script.agent_endpoint.clone())
    };
    let state = match step {
        PollStep::Pending => PollResponse::Pending,
        PollStep::Rejected => PollResponse::Rejected,
        PollStep::Expired => PollResponse::Expired,
        PollStep::AlreadyDelivered => PollResponse::AlreadyDelivered,
        PollStep::NotFound => return error_reply(StatusCode::NOT_FOUND, "not_found"),
        PollStep::TooMany => {
            return error_reply(StatusCode::TOO_MANY_REQUESTS, "too_many_requests");
        }
        PollStep::Unavailable => {
            return error_reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
        }
        PollStep::Oversized => {
            return (StatusCode::OK, vec![b' '; OVERSIZED_BODY]).into_response();
        }
        PollStep::Approve(approval) => {
            let enroll = inner.enrolls.lock().unwrap().last().cloned().unwrap();
            PollResponse::Approved(approve(&inner.pki, &enroll, approval, endpoint))
        }
    };
    json_reply(StatusCode::OK, &state)
}

fn approve(
    pki: &TestPki,
    enroll: &EnrollRequest,
    approval: Approval,
    agent_endpoint: String,
) -> EnrollmentApproved {
    let spki = STANDARD.decode(&enroll.tls_public_key).unwrap();
    let host = PublicKey::from_openssh(&enroll.ssh_host_public_key).unwrap();
    let mut certificates = pki.node_certificates(&spki, host.key_data(), NODE_ID, &enroll.name);
    let now = unix_now();
    match approval {
        Approval::Valid => {}
        Approval::OtherKey => {
            let other = crate::keys::TlsKey::generate().unwrap();
            certificates.x509_certificate_der =
                pki.node_x509(other.spki_der(), NODE_ID, now - 60, now + WEEK);
        }
        Approval::WrongNode => {
            certificates.x509_certificate_der = pki.node_x509(
                &spki,
                "11111111-2222-4333-8444-555555555555",
                now - 60,
                now + WEEK,
            );
        }
        Approval::Expired => {
            certificates.x509_certificate_der = pki.node_x509(&spki, NODE_ID, now - WEEK, now - 60);
        }
        Approval::BadHostCertificate => {
            certificates.ssh_host_certificate = "ssh-ed25519-cert-v01@openssh.com AAAA".to_owned();
        }
    }
    EnrollmentApproved {
        node_id: NODE_ID.to_owned(),
        certificates,
        internal_ca_root_der: pki.root_base64(),
        agent_endpoint,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RenewStep {
    Issue { not_before: i64, not_after: i64 },
    OtherKey,
    Oversized,
    RefuseStream,
    Status(u16, &'static str),
}

pub struct NodeIdentity {
    pub spki: Vec<u8>,
    pub host_key: KeyData,
}

#[derive(Clone, Debug)]
pub struct SeenRenewal {
    pub node: NodeId,
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub request: Option<RenewRequest>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum ApiStep {
    Json(u16, serde_json::Value),
    Oversized,
    RefuseStream,
}

pub const RENEW_PATH: &str = "/v1/agent/renew";
pub const TRUST_PATH: &str = "/v1/agent/trust";
pub const AUTHORIZE_PATH: &str = "/v1/agent/authorize";
pub const SESSION_END_PATH: &str = "/v1/agent/session/end";

pub fn user_ca_line() -> String {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap()
}

pub fn trust_reply(lines: &[String]) -> ApiStep {
    ApiStep::Json(200, serde_json::json!({ "user_ca_keys": lines }))
}

struct ApiInner {
    pki: Arc<TestPki>,
    identity: Mutex<NodeIdentity>,
    script: Mutex<VecDeque<RenewStep>>,
    scripts: Mutex<HashMap<String, VecDeque<ApiStep>>>,
    standing: Mutex<HashMap<String, ApiStep>>,
    server_time: Mutex<Option<SystemTime>>,
    requests: Mutex<Vec<SeenRenewal>>,
    connections: AtomicUsize,
    open: AtomicUsize,
}

impl ApiInner {
    fn next_step(&self, path: &str) -> Option<ApiStep> {
        let scripted = self
            .scripts
            .lock()
            .unwrap()
            .get_mut(path)
            .and_then(VecDeque::pop_front);
        scripted.or_else(|| self.standing.lock().unwrap().get(path).cloned())
    }
}

#[derive(Default)]
pub struct RecordingAuthenticator {
    presented: Mutex<Vec<Vec<u8>>>,
}

impl RecordingAuthenticator {
    pub fn presented(&self) -> Vec<Vec<u8>> {
        self.presented.lock().unwrap().clone()
    }
}

impl PeerAuthenticator for RecordingAuthenticator {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(async move {
            self.presented.lock().unwrap().push(peer_cert_der.to_vec());
            let unknown = || Rejection::new(RejectReason::UnknownNode);
            let (_, certificate) = parse_x509_certificate(peer_cert_der).map_err(|_| unknown())?;
            let san = certificate
                .subject_alternative_name()
                .ok()
                .flatten()
                .ok_or_else(unknown)?;
            match san.value.general_names.as_slice() {
                [GeneralName::URI(uri)] => {
                    let id = uri.strip_prefix("urn:jaunt:node:").ok_or_else(unknown)?;
                    Ok(NodeId::new(id)?)
                }
                _ => Err(unknown()),
            }
        })
    }
}

struct ApiHandover {
    api: Arc<ApiInner>,
    stop: CancellationToken,
}

impl Handover for ApiHandover {
    fn main(&self, _connection: MainConnection) {}

    fn agent_api(&self, connection: AgentApiConnection) {
        self.api.connections.fetch_add(1, Ordering::SeqCst);
        self.api.open.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(serve_api(self.api.clone(), connection, self.stop.clone()));
    }
}

struct OpenConnection(Arc<ApiInner>);

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve_api(api: Arc<ApiInner>, connection: AgentApiConnection, stop: CancellationToken) {
    let _open = OpenConnection(api.clone());
    let Ok(mut h2) = h2::server::handshake(connection.stream).await else {
        return;
    };
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => return,
            accepted = h2.accept() => accepted,
        };
        let Some(Ok((request, mut respond))) = accepted else {
            return;
        };
        let api = api.clone();
        let node = connection.node.clone();
        tokio::spawn(async move {
            let (parts, mut body) = request.into_parts();
            let mut bytes = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                if body.flow_control().release_capacity(chunk.len()).is_err() {
                    return;
                }
                bytes.extend_from_slice(&chunk);
            }
            let path = parts.uri.path().to_owned();
            api.requests.lock().unwrap().push(SeenRenewal {
                node,
                method: parts.method.to_string(),
                path: path.clone(),
                content_type: parts
                    .headers
                    .get("content-type")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                request: serde_json::from_slice(&bytes).ok(),
                body: bytes,
            });
            let (status, reply) = if path == RENEW_PATH {
                let step = api.script.lock().unwrap().pop_front();
                if step == Some(RenewStep::RefuseStream) {
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                    return;
                }
                renew_reply(&api, step)
            } else {
                match api.next_step(&path) {
                    Some(ApiStep::Json(status, value)) => {
                        (status, serde_json::to_vec(&value).unwrap())
                    }
                    Some(ApiStep::Oversized) => (200, vec![b' '; OVERSIZED_BODY]),
                    Some(ApiStep::RefuseStream) => {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                        return;
                    }
                    None => (
                        404,
                        serde_json::to_vec(&ErrorBody {
                            error: "not_found".to_owned(),
                        })
                        .unwrap(),
                    ),
                }
            };
            let mut response = http::Response::builder().status(status);
            if let Some(time) = *api.server_time.lock().unwrap() {
                response = response.header("date", httpdate::fmt_http_date(time));
            }
            if let Ok(mut send) = respond.send_response(response.body(()).unwrap(), false) {
                drop(send.send_data(reply.into(), true));
            }
        });
    }
}

fn renew_reply(api: &ApiInner, step: Option<RenewStep>) -> (u16, Vec<u8>) {
    let identity = api.identity.lock().unwrap();
    let issue = |spki: &[u8], not_before: i64, not_after: i64| {
        api.pki.node_certificates_for(
            spki,
            &identity.host_key,
            NODE_ID,
            NODE_NAME,
            not_before,
            not_after,
        )
    };
    let now = unix_now();
    match step {
        Some(RenewStep::Issue {
            not_before,
            not_after,
        }) => (
            200,
            serde_json::to_vec(&issue(&identity.spki, not_before, not_after)).unwrap(),
        ),
        Some(RenewStep::OtherKey) => {
            let other = crate::keys::TlsKey::generate().unwrap();
            (
                200,
                serde_json::to_vec(&issue(other.spki_der(), now - 60, now + WEEK)).unwrap(),
            )
        }
        Some(RenewStep::Oversized) => (200, vec![b' '; OVERSIZED_BODY]),
        Some(RenewStep::Status(status, code)) => (
            status,
            serde_json::to_vec(&ErrorBody {
                error: code.to_owned(),
            })
            .unwrap(),
        ),
        Some(RenewStep::RefuseStream) | None => (
            500,
            serde_json::to_vec(&ErrorBody {
                error: "script_exhausted".to_owned(),
            })
            .unwrap(),
        ),
    }
}

pub struct FakeGate {
    pub addr: SocketAddr,
    pub registry: AgentRegistry,
    pub events: broadcast::Receiver<RegistryEvent>,
    pub auth: Arc<RecordingAuthenticator>,
    api: Arc<ApiInner>,
    shutdown: CancellationToken,
    serve: JoinHandle<()>,
}

impl FakeGate {
    pub async fn start(pki: Arc<TestPki>, identity: NodeIdentity, renewals: &[RenewStep]) -> Self {
        let standing = HashMap::from([(TRUST_PATH.to_owned(), trust_reply(&[user_ca_line()]))]);
        let api = Arc::new(ApiInner {
            pki,
            identity: Mutex::new(identity),
            script: Mutex::new(renewals.iter().cloned().collect()),
            scripts: Mutex::new(HashMap::new()),
            standing: Mutex::new(standing),
            server_time: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            connections: AtomicUsize::new(0),
            open: AtomicUsize::new(0),
        });
        Self::start_with(
            "127.0.0.1:0".parse().unwrap(),
            api,
            Arc::new(RecordingAuthenticator::default()),
        )
        .await
    }

    async fn start_with(
        addr: SocketAddr,
        api: Arc<ApiInner>,
        auth: Arc<RecordingAuthenticator>,
    ) -> Self {
        let (chain, key) = api.pki.server_leaf(AGENT_HOST);
        let agent = agent_server_config(chain.clone(), key.clone_key(), api.pki.roots()).unwrap();
        let main = main_server_config(chain, key).unwrap();
        let acceptor = GateAcceptor::new(
            AcceptorConfig::new(vec![AGENT_HOST.to_owned()], Arc::new(agent), Arc::new(main)),
            Arc::new(GateStats::default()),
        )
        .unwrap();
        let registry = AgentRegistry::new();
        let events = registry.subscribe();
        let shutdown = CancellationToken::new();
        let gate = Gate::new(
            acceptor,
            registry.clone(),
            auth.clone(),
            Arc::new(ApiHandover {
                api: api.clone(),
                stop: shutdown.child_token(),
            }),
            TunnelOptions {
                close_grace: Duration::from_millis(100),
                ..TunnelOptions::default()
            },
        )
        .unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let token = shutdown.clone();
        let serve = tokio::spawn(async move { gate.serve(listener, token).await.unwrap() });
        Self {
            addr,
            registry,
            events,
            auth,
            api,
            shutdown,
            serve,
        }
    }

    pub fn endpoint(&self) -> String {
        format!("{AGENT_HOST}:{}", self.addr.port())
    }

    pub fn set_identity(&self, identity: NodeIdentity) {
        *self.api.identity.lock().unwrap() = identity;
    }

    pub fn open_api_connections(&self) -> usize {
        self.api.open.load(Ordering::SeqCst)
    }

    pub fn api_connections(&self) -> usize {
        self.api.connections.load(Ordering::SeqCst)
    }

    pub fn renewals(&self) -> Vec<SeenRenewal> {
        self.requests(RENEW_PATH)
    }

    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .api
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|seen| seen.path.clone())
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }

    pub fn requests(&self, path: &str) -> Vec<SeenRenewal> {
        self.api
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|seen| seen.path == path)
            .cloned()
            .collect()
    }

    pub fn script(&self, path: &str, steps: Vec<ApiStep>) {
        self.api
            .scripts
            .lock()
            .unwrap()
            .entry(path.to_owned())
            .or_default()
            .extend(steps);
    }

    pub fn set_standing(&self, path: &str, step: ApiStep) {
        self.api
            .standing
            .lock()
            .unwrap()
            .insert(path.to_owned(), step);
    }

    pub fn set_server_time(&self, time: Option<SystemTime>) {
        *self.api.server_time.lock().unwrap() = time;
    }

    pub async fn restart(self) -> Self {
        let (addr, api, auth) = (self.addr, self.api.clone(), self.auth.clone());
        self.shutdown.cancel();
        self.serve.await.unwrap();
        for node in self.registry.connected_nodes() {
            self.registry.disconnect(&node);
        }
        Self::start_with(addr, api, auth).await
    }

    pub async fn wait_connected(&mut self) {
        let expected = NodeId::new(NODE_ID).unwrap();
        soon("the agent to register its tunnel", async {
            loop {
                match self.events.recv().await {
                    Ok(RegistryEvent::Connected { node, .. })
                    | Ok(RegistryEvent::Replaced { node, .. })
                        if node == expected =>
                    {
                        return;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => panic!("registry closed"),
                }
            }
        })
        .await;
    }

    pub async fn stop(self) {
        self.shutdown.cancel();
        self.serve.await.unwrap();
        for node in self.registry.connected_nodes() {
            self.registry.disconnect(&node);
        }
    }
}

pub struct RawTlsServer {
    pub addr: SocketAddr,
    task: JoinHandle<()>,
}

impl RawTlsServer {
    pub async fn start(pki: &TestPki, alpn: &[&[u8]], speak_h2: bool) -> Self {
        let (chain, key) = pki.server_leaf(AGENT_HOST);
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut held: Vec<Box<dyn std::any::Any + Send>> = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                if speak_h2 {
                    if let Ok(connection) = h2::server::handshake(tls).await {
                        held.push(Box::new(connection));
                    }
                } else {
                    held.push(Box::new(tls));
                }
            }
        });
        Self { addr, task }
    }

    pub fn endpoint(&self) -> String {
        format!("{AGENT_HOST}:{}", self.addr.port())
    }
}

impl Drop for RawTlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn agent_api(pki: &TestPki, endpoint: &str, keepalive: Keepalive) -> (AgentApi, NodeIdentity) {
    let tls = crate::keys::TlsKey::generate().unwrap();
    let host = crate::keys::HostKey::generate().unwrap();
    let certificates = pki.node_certificates(tls.spki_der(), host.key_data(), NODE_ID, NODE_NAME);
    let x509 = STANDARD.decode(&certificates.x509_certificate_der).unwrap();
    let identity = Arc::new(
        SwappableClientCert::new(vec![CertificateDer::from(x509)], tls.rustls_key()).unwrap(),
    );
    let config = agent_client_config_swappable(pki.roots(), identity).unwrap();
    let api = AgentApi::new(
        &config,
        &AgentEndpoint::parse(endpoint).unwrap(),
        keepalive,
        CancellationToken::new(),
    )
    .unwrap();
    let node = NodeIdentity {
        spki: tls.spki_der().to_vec(),
        host_key: host.key_data().clone(),
    };
    (api, node)
}

pub async fn gate_and_api() -> (FakeGate, Arc<AgentApi>) {
    let pki = Arc::new(TestPki::new());
    let placeholder = NodeIdentity {
        spki: Vec::new(),
        host_key: crate::keys::HostKey::generate().unwrap().key_data().clone(),
    };
    let gate = FakeGate::start(pki.clone(), placeholder, &[]).await;
    let (api, node) = agent_api(&pki, &gate.endpoint(), API_KEEPALIVE);
    gate.set_identity(node);
    (gate, Arc::new(api))
}

pub fn sshd_host_key_file(dir: &Path) -> PathBuf {
    let path = dir.join("ssh_host_ed25519_key.pub");
    let line = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .to_openssh()
        .unwrap();
    std::fs::write(&path, format!("{line}\n")).unwrap();
    path
}
