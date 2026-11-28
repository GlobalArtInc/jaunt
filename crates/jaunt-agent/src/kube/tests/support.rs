use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, HOST};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use jaunt_proto::{
    AgentEvent, AgentEventBatch, AgentEventValue, AgentEventsAccepted, KubeAccess, KubernetesAudit,
    ServiceAccess, ServiceOutcome,
};
use jaunt_tunnel::{BoxFuture, ServiceName};
use rustls::pki_types::ServerName;
use rustls::server::ResolvesServerCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;

use crate::kube::{KUBE_LIMITS, KubeHandler, KubeLimits, KubeParts, KubernetesUpstream};
use crate::run::api::{ApiError, EventsAnswer};
use crate::runtime::events::{EventSink, EventTransport, SINK_LIMITS, SinkLimits};
use crate::runtime::handler::{
    ByteCounts, Counted, EndReason, HandlerError, ServiceConnection, ServiceGrant, ServiceHandler,
    ServiceSession, Transport,
};
use crate::runtime::x509::VerifiedUser;
use crate::testkit::{ManualClock, TestPki, eventually, soon};

pub const CLUSTER: &str = "prod-eu";
pub const DNS_NAME: &str = "prod-eu.kube.svc.test";
pub const SESSION: &str = "k-0123456789abcdef0123456789abcdef";
pub const TOKEN: &str = "sa-token-one";
pub const CLIENT_ADDR: &str = "203.0.113.5:40000";
pub const USER_A: &str = "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11";
pub const USER_B: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
pub const PODS: &str = "/api/v1/namespaces/default/pods";
pub const CONFIGMAPS: &str = "/api/v1/namespaces/default/configmaps";

pub fn kube(users: &[&str], groups: &[&str]) -> ServiceAccess {
    ServiceAccess::Kube(KubeAccess {
        users: users.iter().map(|user| (*user).to_owned()).collect(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        record_exec: true,
        record_input: false,
    })
}

pub fn alice() -> ServiceAccess {
    kube(&["alice@example.com"], &["view", "dev"])
}

pub fn pattern(offset: u64, len: usize) -> Vec<u8> {
    (offset..offset + len as u64)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

pub fn pattern_sum(len: u64) -> u64 {
    (0..len).map(|index| index % 251).sum()
}

pub enum TestBody {
    Trailing(u8, HeaderMap),
    Full(Option<Bytes>),
    Channel(mpsc::Receiver<Bytes>),
    Generated {
        offset: u64,
        total: u64,
        chunk: usize,
        produced: Arc<AtomicU64>,
    },
}

impl TestBody {
    pub fn empty() -> Self {
        Self::Full(None)
    }

    pub fn text(text: &str) -> Self {
        Self::Full(Some(Bytes::from(text.to_owned())))
    }

    pub fn generated(total: u64, produced: Arc<AtomicU64>) -> Self {
        Self::Generated {
            offset: 0,
            total,
            chunk: 16 * 1024,
            produced,
        }
    }
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Self::Trailing(step, trailers) => {
                *step += 1;
                Poll::Ready(match *step {
                    1 => Some(Ok(Frame::data(Bytes::from_static(b"abcd")))),
                    2 => Some(Ok(Frame::trailers(std::mem::take(trailers)))),
                    _ => None,
                })
            }
            Self::Full(bytes) => Poll::Ready(bytes.take().map(|bytes| Ok(Frame::data(bytes)))),
            Self::Channel(receiver) => receiver
                .poll_recv(cx)
                .map(|chunk| chunk.map(|chunk| Ok(Frame::data(chunk)))),
            Self::Generated {
                offset,
                total,
                chunk,
                produced,
            } => {
                let left = *total - *offset;
                if left == 0 {
                    return Poll::Ready(None);
                }
                let len = usize::try_from(left).unwrap().min(*chunk);
                let data = pattern(*offset, len);
                *offset += len as u64;
                produced.fetch_add(len as u64, Ordering::SeqCst);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(data)))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Trailing(step, _) => *step >= 2,
            Self::Full(bytes) => bytes.is_none(),
            Self::Channel(_) => false,
            Self::Generated { offset, total, .. } => offset == total,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            Self::Full(bytes) => http_body::SizeHint::with_exact(
                bytes.as_ref().map_or(0, |bytes| bytes.len() as u64),
            ),
            Self::Trailing(..) | Self::Channel(_) | Self::Generated { .. } => {
                http_body::SizeHint::default()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct Seen {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
}

impl Seen {
    pub fn values(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8(value.as_bytes().to_vec()).unwrap())
            .collect()
    }
}

struct ApiState {
    token: Mutex<String>,
    seen: Mutex<Vec<Seen>>,
    trailers: Mutex<Vec<HeaderMap>>,
    watchers: Mutex<Vec<mpsc::Sender<Bytes>>>,
    upload_gate: Notify,
    upload_received: AtomicU64,
    upload_failures: AtomicU64,
    log_gate: Notify,
    download_total: AtomicU64,
    download_produced: Arc<AtomicU64>,
    connections: Mutex<Vec<tokio::task::AbortHandle>>,
    handshakes: Mutex<Vec<rustls::HandshakeKind>>,
}

#[derive(Debug)]
struct SwappableCertificate(Mutex<Arc<CertifiedKey>>);

impl ResolvesServerCert for SwappableCertificate {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0.lock().unwrap()))
    }
}

fn certified(pki: &TestPki) -> Arc<CertifiedKey> {
    let (chain, key) = pki.server_leaf("127.0.0.1");
    let signing = rustls::crypto::ring::sign::any_supported_type(&key).unwrap();
    Arc::new(CertifiedKey::new(chain, signing))
}

pub struct FakeOptions<'a> {
    pub serving: &'a TestPki,
    pub trusted: &'a TestPki,
    pub alpn: &'a [&'a [u8]],
    pub tls12_only: bool,
    pub resumption: bool,
}

pub struct FakeApi {
    pub addr: SocketAddr,
    pub ca_file: PathBuf,
    pub token_file: PathBuf,
    state: Arc<ApiState>,
    certificate: Arc<SwappableCertificate>,
    accepting: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for FakeApi {
    fn drop(&mut self) {
        self.accepting.abort();
        self.drop_connections();
    }
}

pub fn pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

impl FakeApi {
    pub async fn start() -> Self {
        let pki = TestPki::new();
        Self::start_with(&pki, &pki).await
    }

    pub async fn start_with(serving: &TestPki, trusted: &TestPki) -> Self {
        Self::start_options(FakeOptions {
            serving,
            trusted,
            alpn: &[b"h2", b"http/1.1"],
            tls12_only: false,
            resumption: false,
        })
        .await
    }

    pub async fn start_options(options: FakeOptions<'_>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca_file = dir.path().join("ca.crt");
        let token_file = dir.path().join("token");
        std::fs::write(&ca_file, pem(options.trusted.root_der())).unwrap();
        std::fs::write(&token_file, format!("{TOKEN}\n")).unwrap();
        let certificate = Arc::new(SwappableCertificate(Mutex::new(certified(options.serving))));
        let versions: &[&rustls::SupportedProtocolVersion] = if options.tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(certificate.clone());
        config.alpn_protocols = options.alpn.iter().map(|alpn| alpn.to_vec()).collect();
        if !options.resumption {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
            config.send_tls13_tickets = 0;
        }
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(ApiState {
            token: Mutex::new(TOKEN.to_owned()),
            seen: Mutex::new(Vec::new()),
            trailers: Mutex::new(Vec::new()),
            watchers: Mutex::new(Vec::new()),
            upload_gate: Notify::new(),
            upload_received: AtomicU64::new(0),
            upload_failures: AtomicU64::new(0),
            log_gate: Notify::new(),
            download_total: AtomicU64::new(0),
            download_produced: Arc::new(AtomicU64::new(0)),
            connections: Mutex::new(Vec::new()),
            handshakes: Mutex::new(Vec::new()),
        });
        let shared = Arc::clone(&state);
        let accepting = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&shared);
                let serving = tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    if let Some(kind) = tls.get_ref().1.handshake_kind() {
                        state.handshakes.lock().unwrap().push(kind);
                    }
                    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(answer(&state, request).await) }
                    });
                    let io = TokioIo::new(tls);
                    let served = if h2 {
                        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .max_header_list_size(1024 * 1024)
                            .initial_stream_window_size(256 * 1024)
                            .initial_connection_window_size(1024 * 1024)
                            .max_send_buf_size(256 * 1024)
                            .serve_connection(io, service)
                            .await
                    } else {
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .await
                    };
                    drop(served);
                });
                shared
                    .connections
                    .lock()
                    .unwrap()
                    .push(serving.abort_handle());
            }
        });
        Self {
            addr,
            ca_file,
            token_file,
            state,
            certificate,
            accepting,
            _dir: dir,
        }
    }

    pub fn upstream(&self) -> KubernetesUpstream {
        KubernetesUpstream {
            base_url: format!("https://{}", self.addr),
            ca_file: self.ca_file.clone(),
            token_file: self.token_file.clone(),
        }
    }

    pub fn accept_token(&self, token: &str) {
        *self.state.token.lock().unwrap() = token.to_owned();
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    pub fn handshakes(&self) -> Vec<rustls::HandshakeKind> {
        self.state.handshakes.lock().unwrap().clone()
    }

    pub fn open_watches(&self) -> usize {
        self.state
            .watchers
            .lock()
            .unwrap()
            .iter()
            .filter(|watcher| !watcher.is_closed())
            .count()
    }

    pub fn trailers(&self) -> Vec<HeaderMap> {
        self.state.trailers.lock().unwrap().clone()
    }

    pub fn swap_certificate(&self, pki: &TestPki) {
        *self.certificate.0.lock().unwrap() = certified(pki);
    }

    pub fn drop_connections(&self) {
        for connection in self.state.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    pub async fn watch_event(&self, event: &str) {
        let watchers = self.state.watchers.lock().unwrap().clone();
        assert!(!watchers.is_empty(), "no watch is open");
        for watcher in watchers {
            drop(
                soon(
                    "a watch event to be queued",
                    watcher.send(Bytes::from(format!("{event}\n"))),
                )
                .await,
            );
        }
    }

    pub fn open_uploads(&self) {
        self.state.upload_gate.notify_one();
    }

    pub fn upload_received(&self) -> u64 {
        self.state.upload_received.load(Ordering::SeqCst)
    }

    pub fn upload_failures(&self) -> u64 {
        self.state.upload_failures.load(Ordering::SeqCst)
    }

    pub fn release_logs(&self) {
        self.state.log_gate.notify_one();
    }

    pub fn serve_download(&self, total: u64) -> Arc<AtomicU64> {
        self.state.download_total.store(total, Ordering::SeqCst);
        Arc::clone(&self.state.download_produced)
    }
}

pub struct SilentListener {
    pub addr: SocketAddr,
    accepting: JoinHandle<()>,
}

impl Drop for SilentListener {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

impl SilentListener {
    pub async fn start(close_at_once: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepting = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                if !close_at_once {
                    held.push(tcp);
                }
            }
        });
        Self { addr, accepting }
    }
}

fn reply(status: StatusCode, body: TestBody) -> Response<TestBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

async fn drain(state: &ApiState, body: Incoming) -> Option<(u64, u64)> {
    let mut body = body;
    let (mut bytes, mut sum) = (0_u64, 0_u64);
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            state.upload_failures.fetch_add(1, Ordering::SeqCst);
            return None;
        };
        match frame.into_data() {
            Ok(data) => {
                bytes += data.len() as u64;
                sum += data.iter().map(|byte| u64::from(*byte)).sum::<u64>();
                state
                    .upload_received
                    .fetch_add(data.len() as u64, Ordering::SeqCst);
            }
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    state.trailers.lock().unwrap().push(trailers);
                }
            }
        }
    }
    Some((bytes, sum))
}

async fn answer(state: &ApiState, request: Request<Incoming>) -> Response<TestBody> {
    let path = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_default();
    state.seen.lock().unwrap().push(Seen {
        method: request.method().clone(),
        path: path.clone(),
        headers: request.headers().clone(),
    });
    let expected = format!("Bearer {}", state.token.lock().unwrap());
    let authorized = request
        .headers()
        .get(AUTHORIZATION)
        .is_some_and(|value| value.as_bytes() == expected.as_bytes());
    if !authorized {
        return reply(StatusCode::UNAUTHORIZED, TestBody::text("{\"code\":401}"));
    }
    let name = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .unwrap_or_default()
        .to_owned();
    if let Some(code) = name.strip_prefix("status-") {
        let status = StatusCode::from_u16(code.parse().unwrap()).unwrap();
        let mut response = reply(status, TestBody::text("{\"from\":\"api\"}"));
        response
            .headers_mut()
            .insert("retry-after", http::HeaderValue::from_static("7"));
        return response;
    }
    let watch = request
        .uri()
        .query()
        .is_some_and(|query| query.contains("watch=1"));
    match name.as_str() {
        "slow" => std::future::pending().await,
        "log" if request.uri().query() == Some("follow=true") => {
            state.log_gate.notified().await;
            reply(StatusCode::OK, TestBody::text("log line 1\n"))
        }
        "redirect" => {
            let mut response = reply(StatusCode::FOUND, TestBody::empty());
            response.headers_mut().insert(
                "location",
                http::HeaderValue::from_static("https://elsewhere.example/api"),
            );
            response
        }
        "big" => reply(
            StatusCode::OK,
            TestBody::generated(
                state.download_total.load(Ordering::SeqCst),
                Arc::clone(&state.download_produced),
            ),
        ),
        "upload" => {
            state.upload_gate.notified().await;
            match drain(state, request.into_body()).await {
                Some((bytes, sum)) => reply(
                    StatusCode::OK,
                    TestBody::text(&format!("{{\"bytes\":{bytes},\"sum\":{sum}}}")),
                ),
                None => reply(StatusCode::BAD_REQUEST, TestBody::empty()),
            }
        }
        _ if watch => {
            let (sender, receiver) = mpsc::channel(16);
            state.watchers.lock().unwrap().push(sender);
            reply(StatusCode::OK, TestBody::Channel(receiver))
        }
        _ => {
            let received = drain(state, request.into_body())
                .await
                .map_or(0, |(bytes, _)| bytes);
            reply(
                StatusCode::OK,
                TestBody::text(&format!("{{\"kind\":\"Echo\",\"received\":{received}}}")),
            )
        }
    }
}

#[derive(Default)]
pub struct CapturedEvents {
    batches: Mutex<Vec<AgentEventBatch>>,
    hold: AtomicBool,
}

impl CapturedEvents {
    pub fn hold(&self) {
        self.hold.store(true, Ordering::SeqCst);
    }

    pub fn events(&self) -> Vec<AgentEvent> {
        self.batches
            .lock()
            .unwrap()
            .iter()
            .flat_map(|batch| batch.events.clone())
            .collect()
    }

    pub fn named(&self, name: &str) -> Vec<AgentEvent> {
        self.events()
            .into_iter()
            .filter(|event| event.name == name)
            .collect()
    }
}

impl EventTransport for CapturedEvents {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        let hold = self.hold.load(Ordering::SeqCst);
        if !hold {
            self.batches.lock().unwrap().push(batch.clone());
        }
        let accepted = batch.events.len() as u64;
        Box::pin(async move {
            if hold {
                std::future::pending::<()>().await;
            }
            Ok(EventsAnswer::Accepted(AgentEventsAccepted {
                accepted,
                ..AgentEventsAccepted::default()
            }))
        })
    }
}

pub fn text(event: &AgentEvent, field: &str) -> Option<String> {
    match event.fields.get(field) {
        Some(AgentEventValue::Text(text)) => Some(text.clone()),
        _ => None,
    }
}

pub fn int(event: &AgentEvent, field: &str) -> Option<i64> {
    match event.fields.get(field) {
        Some(AgentEventValue::Int(value)) => Some(*value),
        _ => None,
    }
}

pub struct Options {
    pub limits: KubeLimits,
    pub mode: KubernetesAudit,
    pub sink: SinkLimits,
    pub upstream: Option<KubernetesUpstream>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            limits: KUBE_LIMITS,
            mode: KubernetesAudit::Mutating,
            sink: SinkLimits {
                batch_events: 1,
                ..SINK_LIMITS
            },
            upstream: None,
        }
    }
}

pub struct Kube {
    pub handler: Arc<KubeHandler>,
    pub clock: Arc<ManualClock>,
    pub sink: EventSink,
    pub captured: Arc<CapturedEvents>,
    pub api: FakeApi,
    agent_pki: TestPki,
    _stop: tokio_util::sync::DropGuard,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Alpn {
    H2,
    Http11,
}

pub struct Session {
    pub cancel: CancellationToken,
    pub serving: JoinHandle<Result<ServiceOutcome, HandlerError>>,
    pub tls: Option<TlsStream<DuplexStream>>,
}

impl Session {
    pub fn take(&mut self) -> TlsStream<DuplexStream> {
        self.tls.take().unwrap()
    }

    pub async fn finished(self) -> ServiceOutcome {
        soon("the handler to finish", self.serving)
            .await
            .unwrap()
            .unwrap()
    }
}

impl Kube {
    pub async fn new() -> Self {
        Self::with(Options::default()).await
    }

    pub async fn with(options: Options) -> Self {
        let api = FakeApi::start().await;
        let clock = ManualClock::new(SystemTime::now());
        let captured = Arc::new(CapturedEvents::default());
        let sink = EventSink::new(
            captured.clone(),
            clock.clone(),
            Arc::new(|| 1.0),
            options.sink,
        );
        let stop = CancellationToken::new();
        tokio::spawn(sink.clone().run(stop.clone()));
        let services = jaunt_proto::ServiceAnnouncement {
            ssh_enabled: false,
            services: vec![jaunt_proto::AnnouncedService {
                kind: jaunt_proto::ServiceKind::Kubernetes,
                name: CLUSTER.to_owned(),
                labels: Default::default(),
                address: None,
                kubernetes: Some(jaunt_proto::KubernetesSettings {
                    api: jaunt_proto::KubernetesApi::InCluster,
                    audit: options.mode,
                }),
                postgres: None,
                tcp: None,
            }],
        };
        let upstream = options.upstream.unwrap_or_else(|| api.upstream());
        let handler = KubeHandler::new(KubeParts {
            upstream: &upstream,
            services: &services,
            clock: clock.clone(),
            limits: options.limits,
        })
        .unwrap();
        Self {
            handler: Arc::new(handler),
            clock,
            sink,
            captured,
            api,
            agent_pki: TestPki::new(),
            _stop: stop.drop_guard(),
        }
    }

    pub async fn open(&self, access: ServiceAccess, alpn: Alpn) -> Session {
        self.open_as(USER_A, access, alpn).await
    }

    pub async fn open_as(&self, user_id: &str, access: ServiceAccess, alpn: Alpn) -> Session {
        let (client_io, agent_io) = tokio::io::duplex(64 * 1024);
        let (chain, key) = self.agent_pki.server_leaf(DNS_NAME);
        let mut server =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap();
        server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let mut client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(self.agent_pki.roots())
                .with_no_client_auth();
        client.alpn_protocols = vec![match alpn {
            Alpn::H2 => b"h2".to_vec(),
            Alpn::Http11 => b"http/1.1".to_vec(),
        }];
        let accepting = TlsAcceptor::from(Arc::new(server)).accept(Box::new(agent_io) as Transport);
        let connecting = TlsConnector::from(Arc::new(client))
            .connect(ServerName::try_from(DNS_NAME).unwrap(), client_io);
        let (accepted, connected) = soon("the TLS handshake with the handler", async {
            tokio::join!(accepting, connecting)
        })
        .await;
        let accepted = accepted.unwrap();
        let alpn = accepted.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let connection = ServiceConnection {
            stream: Counted::new(accepted, Arc::new(ByteCounts::default())),
            alpn,
            user: VerifiedUser {
                user_id: user_id.to_owned(),
                serial: 4242,
                subject_fingerprint: "aa".to_owned(),
                issuer_fingerprint: "bb".to_owned(),
            },
            client_addr: CLIENT_ADDR.to_owned(),
            prepared: None,
        };
        let cancel = CancellationToken::new();
        let session = ServiceSession {
            session_id: SESSION.to_owned(),
            service: ServiceName::new(CLUSTER).unwrap(),
            dns_name: DNS_NAME.to_owned(),
            cancel: cancel.clone(),
            reason: EndReason::default(),
            events: self.sink.session(SESSION),
        };
        let grant = ServiceGrant {
            access,
            max_duration: Duration::from_secs(3600),
            target: None,
        };
        let serving = tokio::spawn(self.handler.serve(connection, grant, session));
        Session {
            cancel,
            serving,
            tls: Some(connected.unwrap()),
        }
    }

    pub async fn events_settled(&self, name: &str, count: usize) -> Vec<AgentEvent> {
        eventually(&format!("{count} {name} events"), || {
            self.captured.named(name).len() >= count
        })
        .await;
        self.captured.named(name)
    }
}

#[derive(Clone)]
pub struct H2(hyper::client::conn::http2::SendRequest<TestBody>);

impl H2 {
    pub fn send_request(
        &mut self,
        request: Request<TestBody>,
    ) -> impl Future<Output = Result<Response<Incoming>, hyper::Error>> + use<> {
        let sent = self.0.send_request(request);
        async move { soon("a response head", sent).await }
    }
}

pub struct H1(hyper::client::conn::http1::SendRequest<TestBody>);

impl H1 {
    pub fn send_request(
        &mut self,
        request: Request<TestBody>,
    ) -> impl Future<Output = Result<Response<Incoming>, hyper::Error>> + use<> {
        let sent = self.0.send_request(request);
        async move { soon("a response head", sent).await }
    }
}

pub async fn h2(tls: TlsStream<DuplexStream>) -> H2 {
    h2_windowed(tls, 256 * 1024).await
}

pub async fn h2_windowed(tls: TlsStream<DuplexStream>, stream_window: u32) -> H2 {
    let (sender, connection) = soon(
        "the HTTP/2 handshake",
        hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(stream_window)
            .initial_connection_window_size(1024 * 1024)
            .handshake(TokioIo::new(tls)),
    )
    .await
    .unwrap();
    tokio::spawn(async move { drop(connection.await) });
    H2(sender)
}

pub async fn h2_watched(
    tls: TlsStream<DuplexStream>,
) -> (H2, JoinHandle<Result<(), hyper::Error>>) {
    let (sender, connection) = soon(
        "the HTTP/2 handshake",
        hyper::client::conn::http2::Builder::new(TokioExecutor::new()).handshake(TokioIo::new(tls)),
    )
    .await
    .unwrap();
    (H2(sender), tokio::spawn(connection))
}

pub async fn h1(tls: TlsStream<DuplexStream>) -> H1 {
    let (sender, connection) = soon(
        "the HTTP/1.1 handshake",
        hyper::client::conn::http1::handshake(TokioIo::new(tls)),
    )
    .await
    .unwrap();
    tokio::spawn(async move { drop(connection.await) });
    H1(sender)
}

pub fn h2_request(method: Method, path: &str, body: TestBody) -> Request<TestBody> {
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = format!("https://{DNS_NAME}{path}").parse().unwrap();
    request
}

pub fn h1_request(method: Method, path: &str, body: TestBody) -> Request<TestBody> {
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = path.parse().unwrap();
    request
        .headers_mut()
        .insert(HOST, http::HeaderValue::from_static(DNS_NAME));
    request
}

pub async fn body_text(response: Response<Incoming>) -> (StatusCode, String) {
    let status = response.status();
    let bytes = soon("the response body", response.into_body().collect())
        .await
        .unwrap()
        .to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

pub fn message(body: &str) -> String {
    let status: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(status["kind"], "Status", "{body}");
    assert_eq!(status["apiVersion"], "v1", "{body}");
    assert_eq!(status["status"], "Failure", "{body}");
    status["message"].as_str().unwrap().to_owned()
}

pub async fn raw_exchange(tls: &mut TlsStream<DuplexStream>, request: &[u8]) -> (u16, String) {
    write_all(tls, request).await;
    read_response(tls).await
}

pub async fn write_all(tls: &mut TlsStream<DuplexStream>, bytes: &[u8]) {
    soon("the request to be written", async {
        tls.write_all(bytes).await.unwrap();
        tls.flush().await.unwrap();
    })
    .await;
}

pub async fn read_response(tls: &mut TlsStream<DuplexStream>) -> (u16, String) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = soon("a response head", tls.read(&mut byte)).await.unwrap();
        assert_eq!(read, 1, "the connection closed before a response head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status: u16 = head[9..12].parse().unwrap();
    let header = |wanted: &str| {
        head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted)
                .then(|| value.trim().to_ascii_lowercase())
        })
    };
    let mut body = Vec::new();
    if header("transfer-encoding").as_deref() == Some("chunked") {
        loop {
            let mut size_line = Vec::new();
            while !size_line.ends_with(b"\r\n") {
                soon("a chunk size", tls.read_exact(&mut byte))
                    .await
                    .unwrap();
                size_line.push(byte[0]);
            }
            let size =
                usize::from_str_radix(std::str::from_utf8(&size_line).unwrap().trim(), 16).unwrap();
            let mut chunk = vec![0_u8; size + 2];
            soon("a chunk", tls.read_exact(&mut chunk)).await.unwrap();
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        let length = header("content-length").map_or(0, |value| value.parse().unwrap());
        body.resize(length, 0);
        soon("a response body", tls.read_exact(&mut body))
            .await
            .unwrap();
    }
    (status, String::from_utf8(body).unwrap())
}
