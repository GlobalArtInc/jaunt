use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Ping, PingPong};
use http::header::{ACCEPT, CONTENT_TYPE, DATE, RETRY_AFTER};
use http::{HeaderMap, Method, Request, StatusCode};
use jaunt_proto::{
    AGENT_CAPABILITIES_PATH, AGENT_EVENTS_INVALID_SESSION, AGENT_EVENTS_PATH,
    AGENT_SERVICE_AUTHORIZE_PATH, AGENT_SERVICE_CERTIFICATE_PATH, AGENT_SERVICE_END_PATH,
    AGENT_SERVICES_PATH, AGENT_SESSION_ACCOUNT_PATH, AGENT_TRUST_V3_PATH, AccountReport,
    AgentCapabilities, AgentEventBatch, AgentEventsAccepted, AgentEventsRefusal, AgentTrust,
    AgentTrustV2, AgentTrustV3, AuthorizeRequest, AuthorizeResponse, ErrorBody, NodeServices,
    RecordingAck, RecordingChunk, RecordingComplete, RecordingReceipt, RenewRequest, RenewResponse,
    ServiceAnnouncement, ServiceAuthorizeRequest, ServiceAuthorizeResponse,
    ServiceCertificateRequest, ServiceCertificateResponse, ServiceEnd, SessionEnd,
    SessionEndOutcome, TrustedX509Root, recording_chunks_path, recording_complete_path,
};
use jaunt_tunnel::{ALPN_AGENT_API, Keepalive};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::endpoint::AgentEndpoint;

const RENEW_PATH: &str = "/v1/agent/renew";
const AUTHORIZE_PATH: &str = "/v1/agent/authorize";
const SESSION_END_PATH: &str = "/v1/agent/session/end";
const TRUST_PATH: &str = "/v1/agent/trust";
const TRUST_V2_PATH: &str = "/v2/agent/trust";
const JSON: &str = "application/json";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_BYTES: usize = 64 * 1024;
const MAX_ERROR_CODE_LEN: usize = 64;

pub const API_KEEPALIVE: Keepalive = Keepalive {
    interval: Duration::from_secs(20),
    timeout: Duration::from_secs(10),
};

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("the agent endpoint is not a valid TLS server name")]
    ServerName,
    #[error("connecting to the agent API timed out")]
    ConnectTimeout,
    #[error("cannot connect to the agent API: {0}")]
    Tcp(#[source] io::Error),
    #[error("the TLS handshake with the agent API failed: {0}")]
    Tls(#[source] io::Error),
    #[error("the server did not select the agent API protocol")]
    UnexpectedProtocol,
    #[error("the HTTP/2 exchange with the agent API failed: {0}")]
    Http2(#[source] h2::Error),
    #[error("the agent API call timed out")]
    CallTimeout,
    #[error("the agent is shutting down")]
    Shutdown,
    #[error("this node was removed on the server")]
    NodeRemoved,
    #[error("the server did not accept this node's certificate")]
    Unauthorized,
    #[error("the agent API answered HTTP {status} ({code})")]
    Status {
        status: u16,
        code: String,
        retry_after: Option<Duration>,
    },
    #[error("the agent API response is too large")]
    BodyTooLarge,
    #[error("the agent API sent a response that cannot be understood")]
    BadResponse,
    #[error("cannot build the agent API request")]
    Request,
}

enum Exchange {
    NotSent(h2::Error),
    NoResponse(h2::Error),
    Failed(ApiError),
}

struct Answer {
    status: StatusCode,
    server_time: Option<SystemTime>,
    retry_after: Option<Duration>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dated<T> {
    pub value: T,
    pub server_time: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServedTrust {
    V1(AgentTrust),
    V2(AgentTrustV2),
    V3(AgentTrustV3),
}

impl ServedTrust {
    pub fn into_user_ca_keys(self) -> Vec<String> {
        match self {
            ServedTrust::V1(trust) => trust.user_ca_keys,
            ServedTrust::V2(trust) => trust.user_ca_keys,
            ServedTrust::V3(trust) => trust.user_ca_keys,
        }
    }

    pub fn host_ca_active(&self) -> Option<&str> {
        match self {
            ServedTrust::V1(_) => None,
            ServedTrust::V2(trust) => Some(&trust.host_ca_active),
            ServedTrust::V3(trust) => Some(&trust.host_ca_active),
        }
    }

    pub fn user_x509_roots(&self) -> Option<&[TrustedX509Root]> {
        match self {
            ServedTrust::V1(_) | ServedTrust::V2(_) => None,
            ServedTrust::V3(trust) => Some(&trust.user_x509_roots),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    Idempotent,
    OnlyUnsent,
}

struct Cached {
    generation: u64,
    sender: SendRequest<Bytes>,
}

struct Connection {
    cached: Option<Cached>,
    next_generation: u64,
    resets: u64,
}

type SharedConnection = Arc<Mutex<Connection>>;

pub struct AgentApi {
    connector: TlsConnector,
    server_addr: String,
    server_name: ServerName<'static>,
    authority: String,
    keepalive: Keepalive,
    connection: SharedConnection,
    connecting: Mutex<()>,
    shutdown: CancellationToken,
    first_trust_version_only: AtomicBool,
    third_trust_version_missing: AtomicBool,
}

impl AgentApi {
    pub fn new(
        tls: &ClientConfig,
        endpoint: &AgentEndpoint,
        keepalive: Keepalive,
        shutdown: CancellationToken,
    ) -> Result<Self, ApiError> {
        let mut config = tls.clone();
        config.alpn_protocols = vec![ALPN_AGENT_API.to_vec()];
        let server_name = ServerName::try_from(endpoint.server_name().to_owned())
            .map_err(|_| ApiError::ServerName)?;
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_addr: endpoint.as_str().to_owned(),
            server_name,
            authority: endpoint.as_str().to_owned(),
            keepalive,
            connection: Arc::new(Mutex::new(Connection {
                cached: None,
                next_generation: 0,
                resets: 0,
            })),
            connecting: Mutex::new(()),
            shutdown,
            first_trust_version_only: AtomicBool::new(false),
            third_trust_version_missing: AtomicBool::new(false),
        })
    }

    pub async fn renew(&self, request: &RenewRequest) -> Result<RenewResponse, ApiError> {
        self.post_json(RENEW_PATH, request, Retry::Idempotent).await
    }

    pub async fn authorize(
        &self,
        request: &AuthorizeRequest,
    ) -> Result<AuthorizeResponse, ApiError> {
        if self.first_trust_version_only.load(Ordering::Acquire)
            && request.subject_fingerprint.is_some()
        {
            let older = AuthorizeRequest {
                subject_fingerprint: None,
                ..request.clone()
            };
            return self
                .post_json(AUTHORIZE_PATH, &older, Retry::OnlyUnsent)
                .await;
        }
        self.post_json(AUTHORIZE_PATH, request, Retry::OnlyUnsent)
            .await
    }

    pub async fn session_end(&self, end: &SessionEnd) -> Result<SessionEndOutcome, ApiError> {
        self.post_json(SESSION_END_PATH, end, Retry::Idempotent)
            .await
    }

    pub async fn recording_chunk(
        &self,
        session_id: &str,
        chunk: &RecordingChunk,
    ) -> Result<RecordingAck, ApiError> {
        self.post_json(&recording_chunks_path(session_id), chunk, Retry::Idempotent)
            .await
    }

    pub async fn recording_complete(
        &self,
        session_id: &str,
        complete: &RecordingComplete,
    ) -> Result<RecordingReceipt, ApiError> {
        self.post_json(
            &recording_complete_path(session_id),
            complete,
            Retry::Idempotent,
        )
        .await
    }

    pub fn retry_third_trust_version(&self) {
        self.third_trust_version_missing
            .store(false, Ordering::Release);
    }

    pub async fn node_services(&self) -> Result<NodeServices, ApiError> {
        self.call(Method::GET, AGENT_SERVICES_PATH, None, Retry::Idempotent)
            .await
            .map(|dated| dated.value)
    }

    pub async fn authorize_service(
        &self,
        request: &ServiceAuthorizeRequest,
    ) -> Result<ServiceAuthorizeResponse, ApiError> {
        self.post_json(AGENT_SERVICE_AUTHORIZE_PATH, request, Retry::OnlyUnsent)
            .await
    }

    pub async fn end_service(&self, end: &ServiceEnd) -> Result<SessionEndOutcome, ApiError> {
        self.post_json(AGENT_SERVICE_END_PATH, end, Retry::Idempotent)
            .await
    }

    pub async fn agent_events(&self, batch: &AgentEventBatch) -> Result<EventsAnswer, ApiError> {
        let payload = Bytes::from(serde_json::to_vec(batch).map_err(|_| ApiError::Request)?);
        let answer = self
            .answer(
                Method::POST,
                AGENT_EVENTS_PATH,
                Some(payload),
                Retry::Idempotent,
            )
            .await?;
        events_answer(answer.status, &answer.body, answer.retry_after)
    }

    pub async fn service_certificate(
        &self,
        request: &ServiceCertificateRequest,
    ) -> Result<ServiceCertificateResponse, ApiError> {
        self.post_json(AGENT_SERVICE_CERTIFICATE_PATH, request, Retry::OnlyUnsent)
            .await
    }

    pub async fn trust(&self) -> Result<Dated<ServedTrust>, ApiError> {
        if !self.third_trust_version_missing.load(Ordering::Acquire)
            && !self.first_trust_version_only.load(Ordering::Acquire)
        {
            match self
                .call::<AgentTrustV3>(Method::GET, AGENT_TRUST_V3_PATH, None, Retry::Idempotent)
                .await
            {
                Ok(dated) => {
                    return Ok(Dated {
                        value: ServedTrust::V3(dated.value),
                        server_time: dated.server_time,
                    });
                }
                Err(ApiError::Status { status: 404, .. }) => {
                    self.third_trust_version_missing
                        .store(true, Ordering::Release);
                    tracing::info!(
                        target: "jaunt::agent",
                        "the control plane does not serve the third trust version; \
                         Kubernetes, database and TCP client certificates are refused until the agent reconnects to a newer server"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        if !self.first_trust_version_only.load(Ordering::Acquire) {
            match self
                .call::<AgentTrustV2>(Method::GET, TRUST_V2_PATH, None, Retry::Idempotent)
                .await
            {
                Ok(dated) => {
                    return Ok(Dated {
                        value: ServedTrust::V2(dated.value),
                        server_time: dated.server_time,
                    });
                }
                Err(ApiError::Status { status: 404, .. }) => {
                    self.first_trust_version_only.store(true, Ordering::Release);
                    tracing::info!(
                        target: "jaunt::agent",
                        "the control plane does not serve the second trust version; \
                         the first one is used until the agent restarts"
                    );
                }
                Err(error) => return Err(error),
            }
        }
        let dated = self
            .call::<AgentTrust>(Method::GET, TRUST_PATH, None, Retry::Idempotent)
            .await?;
        Ok(Dated {
            value: ServedTrust::V1(dated.value),
            server_time: dated.server_time,
        })
    }

    pub async fn account_report(&self, report: &AccountReport) -> Result<(), ApiError> {
        self.send_without_reply(
            Method::POST,
            AGENT_SESSION_ACCOUNT_PATH,
            report,
            Retry::OnlyUnsent,
        )
        .await
    }

    pub async fn capabilities(&self, capabilities: &AgentCapabilities) -> Result<(), ApiError> {
        self.send_without_reply(
            Method::PUT,
            AGENT_CAPABILITIES_PATH,
            capabilities,
            Retry::Idempotent,
        )
        .await
    }

    pub async fn services(&self, announcement: &ServiceAnnouncement) -> Result<(), ApiError> {
        self.send_without_reply(
            Method::POST,
            AGENT_SERVICES_PATH,
            announcement,
            Retry::Idempotent,
        )
        .await
    }

    pub async fn reset(&self) {
        let mut connection = self.connection.lock().await;
        connection.cached = None;
        connection.resets = connection.resets.wrapping_add(1);
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        retry: Retry,
    ) -> Result<T, ApiError> {
        let payload = Bytes::from(serde_json::to_vec(body).map_err(|_| ApiError::Request)?);
        self.call(Method::POST, path, Some(payload), retry)
            .await
            .map(|dated| dated.value)
    }

    async fn send_without_reply<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
        retry: Retry,
    ) -> Result<(), ApiError> {
        let payload = Bytes::from(serde_json::to_vec(body).map_err(|_| ApiError::Request)?);
        let answer = self.answer(method, path, Some(payload), retry).await?;
        if answer.status.is_success() {
            return Ok(());
        }
        Err(with_retry_after(
            refusal(answer.status, &answer.body),
            answer.retry_after,
        ))
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        payload: Option<Bytes>,
        retry: Retry,
    ) -> Result<Dated<T>, ApiError> {
        let answer = self.answer(method, path, payload, retry).await?;
        interpret(answer.status, &answer.body)
            .map(|value| Dated {
                value,
                server_time: answer.server_time,
            })
            .map_err(|error| with_retry_after(error, answer.retry_after))
    }

    async fn answer(
        &self,
        method: Method,
        path: &str,
        payload: Option<Bytes>,
        retry: Retry,
    ) -> Result<Answer, ApiError> {
        let uri = format!("https://{}{path}", self.authority);
        let mut retried = false;
        loop {
            let (generation, reused, sender) = self.sender().await?;
            let mut builder = Request::builder()
                .method(method.clone())
                .uri(uri.as_str())
                .header(ACCEPT, JSON);
            if payload.is_some() {
                builder = builder.header(CONTENT_TYPE, JSON);
            }
            let request = builder.body(()).map_err(|_| ApiError::Request)?;
            let outcome = tokio::select! {
                () = self.shutdown.cancelled() => return Err(ApiError::Shutdown),
                outcome = timeout(CALL_TIMEOUT, exchange(sender, request, payload.clone())) => outcome,
            };
            let error = match outcome {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(exchange)) => exchange,
                Err(_) => Exchange::Failed(ApiError::CallTimeout),
            };
            forget(&self.connection, generation).await;
            let may_retry = reused && !retried;
            match error {
                Exchange::NotSent(_) if may_retry => retried = true,
                Exchange::NoResponse(_) if may_retry && retry == Retry::Idempotent => {
                    retried = true;
                }
                Exchange::NotSent(error) | Exchange::NoResponse(error) => {
                    return Err(ApiError::Http2(error));
                }
                Exchange::Failed(error) => return Err(error),
            }
        }
    }

    async fn cached(&self) -> Option<(u64, bool, SendRequest<Bytes>)> {
        let connection = self.connection.lock().await;
        connection
            .cached
            .as_ref()
            .map(|cached| (cached.generation, true, cached.sender.clone()))
    }

    async fn sender(&self) -> Result<(u64, bool, SendRequest<Bytes>), ApiError> {
        if let Some(found) = self.cached().await {
            return Ok(found);
        }
        let _connecting = tokio::select! {
            () = self.shutdown.cancelled() => return Err(ApiError::Shutdown),
            guard = self.connecting.lock() => guard,
        };
        let (generation, resets) = {
            let mut connection = self.connection.lock().await;
            if let Some(cached) = &connection.cached {
                return Ok((cached.generation, true, cached.sender.clone()));
            }
            let generation = connection.next_generation;
            connection.next_generation = generation.wrapping_add(1);
            (generation, connection.resets)
        };
        let sender = tokio::select! {
            () = self.shutdown.cancelled() => return Err(ApiError::Shutdown),
            connected = self.connect(generation) => connected?,
        };
        let mut connection = self.connection.lock().await;
        if connection.resets == resets {
            connection.cached = Some(Cached {
                generation,
                sender: sender.clone(),
            });
        }
        Ok((generation, false, sender))
    }

    async fn connect(&self, generation: u64) -> Result<SendRequest<Bytes>, ApiError> {
        let tcp = timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect(self.server_addr.as_str()),
        )
        .await
        .map_err(|_| ApiError::ConnectTimeout)?
        .map_err(ApiError::Tcp)?;
        tcp.set_nodelay(true).map_err(ApiError::Tcp)?;
        let tls = timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| ApiError::ConnectTimeout)?
        .map_err(ApiError::Tls)?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN_AGENT_API) {
            return Err(ApiError::UnexpectedProtocol);
        }
        let (sender, mut connection) = timeout(
            CONNECT_TIMEOUT,
            h2::client::Builder::new().handshake::<_, Bytes>(tls),
        )
        .await
        .map_err(|_| ApiError::ConnectTimeout)?
        .map_err(ApiError::Http2)?;
        let pings = connection.ping_pong();
        let keepalive = self.keepalive;
        let shared = self.connection.clone();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = shutdown.cancelled() => {}
                ended = &mut connection => {
                    if let Err(error) = ended {
                        tracing::debug!(
                            target: "jaunt::agent",
                            error = %error,
                            "the agent API connection ended"
                        );
                    }
                }
                () = keep_alive(pings, keepalive) => {
                    tracing::warn!(
                        target: "jaunt::agent",
                        "the agent API peer stopped answering pings; dropping the connection"
                    );
                }
            }
            forget(&shared, generation).await;
        });
        Ok(sender)
    }
}

async fn forget(connection: &SharedConnection, generation: u64) {
    let mut connection = connection.lock().await;
    if connection
        .cached
        .as_ref()
        .is_some_and(|cached| cached.generation == generation)
    {
        connection.cached = None;
    }
}

async fn keep_alive(pings: Option<PingPong>, settings: Keepalive) {
    let Some(mut pings) = pings else {
        return std::future::pending().await;
    };
    loop {
        tokio::time::sleep(settings.interval).await;
        let answered = timeout(settings.timeout, pings.ping(Ping::opaque())).await;
        if !matches!(answered, Ok(Ok(_))) {
            return;
        }
    }
}

async fn exchange(
    sender: SendRequest<Bytes>,
    request: Request<()>,
    payload: Option<Bytes>,
) -> Result<Answer, Exchange> {
    let mut sender = sender.ready().await.map_err(Exchange::NotSent)?;
    let (response, mut stream) = sender
        .send_request(request, payload.is_none())
        .map_err(Exchange::NotSent)?;
    if let Some(payload) = payload {
        stream
            .send_data(payload, true)
            .map_err(Exchange::NoResponse)?;
    }
    let response = response.await.map_err(Exchange::NoResponse)?;
    let status = response.status();
    let server_time = server_time(response.headers());
    let retry_after = retry_after(response.headers());
    let failed = |error| Exchange::Failed(ApiError::Http2(error));
    let mut body = response.into_body();
    let mut reply = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(failed)?;
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(failed)?;
        if reply.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(Exchange::Failed(ApiError::BodyTooLarge));
        }
        reply.extend_from_slice(&chunk);
    }
    Ok(Answer {
        status,
        server_time,
        retry_after,
        body: reply,
    })
}

fn server_time(headers: &HeaderMap) -> Option<SystemTime> {
    let value = headers.get(DATE)?.to_str().ok()?;
    httpdate::parse_http_date(value).ok()
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().map(Duration::from_secs)
}

fn with_retry_after(error: ApiError, after: Option<Duration>) -> ApiError {
    match error {
        ApiError::Status { status, code, .. } => ApiError::Status {
            status,
            code,
            retry_after: after,
        },
        other => other,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventsAnswer {
    Accepted(AgentEventsAccepted),
    SessionsRefused(Vec<String>),
}

fn events_answer(
    status: StatusCode,
    body: &[u8],
    retry_after: Option<Duration>,
) -> Result<EventsAnswer, ApiError> {
    if status.is_success() {
        return serde_json::from_slice(body)
            .map(EventsAnswer::Accepted)
            .map_err(|_| ApiError::BadResponse);
    }
    if status == StatusCode::BAD_REQUEST
        && let Ok(refusal) = serde_json::from_slice::<AgentEventsRefusal>(body)
        && refusal.error == AGENT_EVENTS_INVALID_SESSION
    {
        return Ok(EventsAnswer::SessionsRefused(refusal.sessions));
    }
    Err(with_retry_after(refusal(status, body), retry_after))
}

fn interpret<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<T, ApiError> {
    if status.is_success() {
        return serde_json::from_slice(body).map_err(|_| ApiError::BadResponse);
    }
    Err(refusal(status, body))
}

fn refusal(status: StatusCode, body: &[u8]) -> ApiError {
    let code: String = serde_json::from_slice::<ErrorBody>(body)
        .map(|error| {
            error
                .error
                .chars()
                .take(MAX_ERROR_CODE_LEN)
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        })
        .unwrap_or_default();
    match (status, code.as_str()) {
        (StatusCode::FORBIDDEN, "node_removed") => ApiError::NodeRemoved,
        (StatusCode::UNAUTHORIZED, _) => ApiError::Unauthorized,
        _ => ApiError::Status {
            status: status.as_u16(),
            code,
            retry_after: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use http::StatusCode;
    use jaunt_proto::{
        AGENT_SERVICE_AUTHORIZE_PATH, AGENT_SERVICE_CERTIFICATE_PATH, AGENT_SERVICE_END_PATH,
        AGENT_SERVICES_PATH, AGENT_SESSION_ACCOUNT_PATH, AGENT_TRUST_V3_PATH, AccountEvent,
        AccountReference, AccountReport, AgentEventsAccepted, AgentTrust, AgentTrustV2,
        AuthorizeRequest, AuthorizeResponse, RenewRequest, RenewResponse, ServiceAuthorizeRequest,
        ServiceAuthorizeResponse, ServiceCertificateRequest, ServiceEnd, ServiceIdentity,
        ServiceKind, ServiceOutcome, SessionEnd, SessionEndOutcome, SessionPermissions,
    };
    use jaunt_tunnel::{ALPN_AGENT_API, Keepalive};
    use serde_json::json;
    use tokio::net::TcpListener;

    use super::{
        API_KEEPALIVE, AgentApi, ApiError, EventsAnswer, ServedTrust, events_answer, forget,
        interpret, retry_after, with_retry_after,
    };
    use crate::keys::HostKey;
    use crate::testkit::{
        AGENT_HOST, AUTHORIZE_PATH, ApiStep, FakeGate, NodeIdentity, RawTlsServer, RenewStep,
        SESSION_END_PATH, TRUST_PATH, TRUST_V2_PATH, TestPki, agent_api, eventually, soon,
        trust_reply, unix_now, user_ca_line,
    };

    const EMPTY: RenewRequest = RenewRequest {
        tls_public_key: None,
        ssh_host_public_key: None,
    };

    fn authorize_request() -> AuthorizeRequest {
        AuthorizeRequest {
            session_id: "session-1".to_owned(),
            user_id: "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11".to_owned(),
            serial: 7,
            key_id: "jaunt:alice@example.com:7".to_owned(),
            login: "deploy".to_owned(),
            client_addr: "203.0.113.5:40000".to_owned(),
            subject_fingerprint: Some("ab".repeat(32)),
        }
    }

    fn session_end() -> SessionEnd {
        SessionEnd {
            session_id: "session-1".to_owned(),
            exit_status: Some(7),
            bytes_in: 10,
            bytes_out: 20,
            recording_incomplete: false,
        }
    }

    const PERMISSIONS: SessionPermissions = SessionPermissions {
        pty: true,
        port_forwarding: false,
        record_input: false,
        max_duration_secs: 3600,
    };

    fn client(pki: &TestPki, endpoint: &str, keepalive: Keepalive) -> (AgentApi, NodeIdentity) {
        agent_api(pki, endpoint, keepalive)
    }

    #[tokio::test]
    async fn the_second_trust_version_is_preferred_and_a_404_switches_to_the_first_for_good() {
        let (_pki, gate, api) = gate_with(&[]).await;
        let first = vec![user_ca_line()];
        let host = user_ca_line();
        gate.set_standing(TRUST_PATH, trust_reply(&first));
        gate.script(
            TRUST_V2_PATH,
            vec![
                ApiStep::Json(
                    200,
                    json!({"trust_id": "t1", "user_ca_keys": first, "host_ca_active": host}),
                ),
                ApiStep::Json(500, json!({"error": "server_error"})),
            ],
        );

        assert_eq!(
            api.trust().await.unwrap().value,
            ServedTrust::V2(AgentTrustV2 {
                trust_id: "t1".to_owned(),
                user_ca_keys: first.clone(),
                host_ca_active: host,
            })
        );
        assert!(matches!(
            api.trust().await,
            Err(ApiError::Status { status: 500, .. })
        ));
        assert!(gate.requests(TRUST_PATH).is_empty());

        let fallen_back = api.trust().await.unwrap().value;
        let again = api.trust().await.unwrap().value;

        assert_eq!(
            fallen_back,
            ServedTrust::V1(AgentTrust {
                user_ca_keys: first.clone()
            })
        );
        assert_eq!(again, fallen_back);
        assert_eq!(gate.requests(TRUST_V2_PATH).len(), 3);
        assert_eq!(gate.requests(TRUST_PATH).len(), 2);
        gate.stop().await;
    }

    #[tokio::test]
    async fn authorize_names_the_certified_key_unless_the_server_only_speaks_the_first_trust_version()
     {
        let (_pki, gate, api) = gate_with(&[]).await;
        gate.set_standing(
            AUTHORIZE_PATH,
            ApiStep::Json(200, json!({"decision": "deny"})),
        );
        gate.set_standing(TRUST_PATH, trust_reply(&[user_ca_line()]));

        api.authorize(&authorize_request()).await.unwrap();
        api.trust().await.unwrap();
        api.authorize(&authorize_request()).await.unwrap();

        let sent: Vec<serde_json::Value> = gate
            .requests(AUTHORIZE_PATH)
            .iter()
            .map(|seen| serde_json::from_slice(&seen.body).unwrap())
            .collect();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0]["subject_fingerprint"], json!("ab".repeat(32)));
        assert!(sent[1].get("subject_fingerprint").is_none(), "{}", sent[1]);
        assert_eq!(sent[1]["serial"], json!(7));
        gate.stop().await;
    }

    async fn gate_with(renewals: &[RenewStep]) -> (Arc<TestPki>, FakeGate, AgentApi) {
        let pki = Arc::new(TestPki::new());
        let placeholder = NodeIdentity {
            spki: Vec::new(),
            host_key: HostKey::generate().unwrap().key_data().clone(),
        };
        let gate = FakeGate::start(pki.clone(), placeholder, renewals).await;
        let (api, node) = client(&pki, &gate.endpoint(), API_KEEPALIVE);
        gate.set_identity(node);
        (pki, gate, api)
    }

    fn issue() -> RenewStep {
        let now = unix_now();
        RenewStep::Issue {
            not_before: now - 60,
            not_after: now + 3600,
        }
    }

    fn service_request() -> ServiceAuthorizeRequest {
        ServiceAuthorizeRequest {
            session_id: "k-0123456789abcdef0123456789abcdef".to_owned(),
            kind: ServiceKind::Kubernetes,
            service: "prod-eu".to_owned(),
            identity: ServiceIdentity {
                user_id: "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11".to_owned(),
                serial: 7,
                subject_fingerprint: "ab".repeat(32),
                issuer_fingerprint: "cd".repeat(32),
            },
            client_addr: "203.0.113.5:40000".to_owned(),
            db: None,
        }
    }

    #[tokio::test]
    async fn the_approved_services_are_read_with_a_get_and_parsed_strictly() {
        let (_pki, gate, api) = gate_with(&[]).await;
        let listed = json!({"services": [{"id": "id-1", "kind": "tcp", "name": "grafana"}]});
        gate.script(
            AGENT_SERVICES_PATH,
            vec![
                ApiStep::Json(200, listed),
                ApiStep::Json(
                    200,
                    json!({"services": [{"id": "id-1", "kind": "tcp", "name": "grafana",
                                         "address": "10.0.0.5:3000"}]}),
                ),
                ApiStep::Json(404, json!({"error": "not_found"})),
            ],
        );
        let read = api.node_services().await.unwrap();
        assert_eq!(read.services[0].name, "grafana");
        assert!(matches!(
            api.node_services().await,
            Err(ApiError::BadResponse)
        ));
        assert!(matches!(
            api.node_services().await,
            Err(ApiError::Status { status: 404, .. })
        ));
        let seen = gate.requests(AGENT_SERVICES_PATH);
        assert_eq!(seen.len(), 3);
        assert!(
            seen.iter()
                .all(|request| request.method == "GET" && request.body.is_empty())
        );
        gate.stop().await;
    }

    #[tokio::test]
    async fn the_third_trust_version_is_preferred_and_a_404_is_not_asked_again() {
        let (_pki, gate, api) = gate_with(&[]).await;
        gate.script(
            AGENT_TRUST_V3_PATH,
            vec![ApiStep::Json(
                200,
                json!({"trust_id": "t3", "user_ca_keys": [user_ca_line()],
                       "host_ca_active": user_ca_line(), "user_x509_roots": []}),
            )],
        );
        let served = api.trust().await.unwrap().value;
        assert_eq!(served.user_x509_roots(), Some(&[][..]));
        assert!(gate.requests(TRUST_V2_PATH).is_empty());
        let fallen_back = api.trust().await.unwrap().value;
        assert_eq!(fallen_back.user_x509_roots(), None);
        api.trust().await.unwrap();
        assert_eq!(gate.requests(AGENT_TRUST_V3_PATH).len(), 2);
        gate.stop().await;
    }

    #[tokio::test]
    async fn service_calls_speak_their_routes_and_authorization_is_never_repeated() {
        let (_pki, gate, api) = gate_with(&[]).await;
        gate.script(
            AGENT_SERVICE_AUTHORIZE_PATH,
            vec![
                ApiStep::Json(200, json!({"decision": "deny"})),
                ApiStep::RefuseStream,
            ],
        );
        gate.script(
            AGENT_SERVICE_END_PATH,
            vec![ApiStep::Json(200, json!({"outcome": "recorded"}))],
        );
        let end = ServiceEnd {
            session_id: "s".to_owned(),
            outcome: ServiceOutcome::UpstreamError,
            bytes_in: 1,
            bytes_out: 2,
        };
        let certificate = ServiceCertificateRequest {
            service_id: "svc-1".to_owned(),
            public_key: "MCowBQYDK2VwAyEA".to_owned(),
        };
        gate.script(
            AGENT_SERVICE_CERTIFICATE_PATH,
            vec![ApiStep::Json(
                200,
                json!({"certificate_der": "MIIB", "serial": 9, "dns_name": "prod-eu.kube.svc.test",
                       "valid_after": 1, "valid_before": 2}),
            )],
        );

        assert_eq!(
            api.authorize_service(&service_request()).await.unwrap(),
            ServiceAuthorizeResponse::Deny
        );
        assert_eq!(
            api.end_service(&end).await.unwrap(),
            SessionEndOutcome::Recorded
        );
        assert_eq!(
            api.service_certificate(&certificate)
                .await
                .unwrap()
                .dns_name,
            "prod-eu.kube.svc.test"
        );
        let unanswered = api.authorize_service(&service_request()).await;
        assert!(
            matches!(unanswered, Err(ApiError::Http2(_))),
            "{unanswered:?}"
        );

        let asked = gate.requests(AGENT_SERVICE_AUTHORIZE_PATH);
        assert_eq!(asked.len(), 2);
        let sent: ServiceAuthorizeRequest = serde_json::from_slice(&asked[0].body).unwrap();
        assert_eq!(sent, service_request());
        let ended: ServiceEnd =
            serde_json::from_slice(&gate.requests(AGENT_SERVICE_END_PATH)[0].body).unwrap();
        assert_eq!(ended, end);
        let issued: ServiceCertificateRequest =
            serde_json::from_slice(&gate.requests(AGENT_SERVICE_CERTIFICATE_PATH)[0].body).unwrap();
        assert_eq!(issued, certificate);
        gate.stop().await;
    }

    #[tokio::test]
    async fn calls_reuse_one_connection_and_retry_once_when_a_reused_stream_is_refused() {
        let (_pki, gate, api) = gate_with(&[issue(), RenewStep::RefuseStream, issue()]).await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 1);
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 2);
        assert_eq!(gate.renewals().len(), 3);
        gate.stop().await;
    }

    #[tokio::test]
    async fn a_restarted_gate_does_not_break_the_next_call() {
        let (_pki, gate, api) = gate_with(&[issue(), issue(), issue()]).await;
        api.renew(&EMPTY).await.unwrap();
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 1);
        let gate = gate.restart().await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 2);
        assert_eq!(gate.renewals().len(), 3);
        gate.stop().await;
    }

    #[tokio::test]
    async fn forget_drops_only_the_connection_of_its_generation() {
        let (_pki, gate, api) = gate_with(&[issue(), issue(), issue(), issue(), issue()]).await;
        api.renew(&EMPTY).await.unwrap();
        forget(&api.connection, 1).await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 1);
        forget(&api.connection, 0).await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 2);
        api.reset().await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 3);
        forget(&api.connection, 1).await;
        api.renew(&EMPTY).await.unwrap();
        assert_eq!(gate.api_connections(), 3);
        gate.stop().await;
    }

    #[tokio::test]
    async fn authorize_is_not_repeated_after_an_unanswered_request() {
        let (_pki, gate, api) = gate_with(&[issue()]).await;
        api.renew(&EMPTY).await.unwrap();
        gate.script(AUTHORIZE_PATH, vec![ApiStep::RefuseStream]);
        let outcome = api.authorize(&authorize_request()).await;
        assert!(matches!(outcome, Err(ApiError::Http2(_))), "{outcome:?}");
        assert_eq!(gate.api_connections(), 1);
        assert_eq!(gate.requests(AUTHORIZE_PATH).len(), 1);
        gate.stop().await;
    }

    #[tokio::test]
    async fn an_account_report_is_sent_again_only_when_it_never_left() {
        let (_pki, gate, api) = gate_with(&[issue(), issue()]).await;
        let report = AccountReport::new(
            "session-1".to_owned(),
            "alice".to_owned(),
            AccountEvent::Missing {
                reference: AccountReference::parse("H-0000000A").unwrap(),
            },
        );
        api.renew(&EMPTY).await.unwrap();
        gate.script(AGENT_SESSION_ACCOUNT_PATH, vec![ApiStep::RefuseStream]);
        let outcome = api.account_report(&report).await;
        assert!(matches!(outcome, Err(ApiError::Http2(_))), "{outcome:?}");
        assert_eq!(gate.requests(AGENT_SESSION_ACCOUNT_PATH).len(), 1);

        api.renew(&EMPTY).await.unwrap();
        let stale = api
            .connection
            .lock()
            .await
            .cached
            .as_ref()
            .unwrap()
            .sender
            .clone();
        let gate = gate.restart().await;
        soon("the old connection to close", async {
            while stale.clone().ready().await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        gate.script(
            AGENT_SESSION_ACCOUNT_PATH,
            vec![ApiStep::Json(200, json!({}))],
        );
        api.account_report(&report).await.unwrap();
        assert_eq!(gate.requests(AGENT_SESSION_ACCOUNT_PATH).len(), 2);
        assert_eq!(gate.api_connections(), 3);
        gate.stop().await;
    }

    #[tokio::test]
    async fn authorize_session_end_and_trust_speak_the_agent_api() {
        let (_pki, gate, api) = gate_with(&[]).await;
        let lines = vec![user_ca_line(), user_ca_line()];
        gate.set_standing(TRUST_PATH, trust_reply(&lines));
        gate.script(
            AUTHORIZE_PATH,
            vec![
                ApiStep::Json(
                    200,
                    json!({"decision": "allow", "permissions": PERMISSIONS}),
                ),
                ApiStep::Json(200, json!({"decision": "deny"})),
            ],
        );
        gate.script(
            SESSION_END_PATH,
            vec![ApiStep::Json(200, json!({"outcome": "rejected"}))],
        );
        let server_time = UNIX_EPOCH + Duration::from_secs(1_795_000_000);
        gate.set_server_time(Some(server_time));

        assert_eq!(
            api.authorize(&authorize_request()).await.unwrap(),
            AuthorizeResponse::Allow {
                permissions: PERMISSIONS
            }
        );
        assert_eq!(
            api.authorize(&authorize_request()).await.unwrap(),
            AuthorizeResponse::Deny
        );
        assert_eq!(
            api.session_end(&session_end()).await.unwrap(),
            SessionEndOutcome::Rejected
        );
        let trust = api.trust().await.unwrap();
        assert_eq!(
            trust.value,
            ServedTrust::V1(AgentTrust {
                user_ca_keys: lines
            })
        );
        assert_eq!(trust.server_time, Some(server_time));
        gate.set_server_time(None);
        assert_eq!(api.trust().await.unwrap().server_time, None);

        let authorize = gate.requests(AUTHORIZE_PATH);
        assert_eq!(authorize[0].method, "POST");
        assert_eq!(
            authorize[0].content_type.as_deref(),
            Some("application/json")
        );
        let sent: AuthorizeRequest = serde_json::from_slice(&authorize[0].body).unwrap();
        assert_eq!(sent, authorize_request());
        let ended: SessionEnd =
            serde_json::from_slice(&gate.requests(SESSION_END_PATH)[0].body).unwrap();
        assert_eq!(ended, session_end());
        let trust = gate.requests(TRUST_PATH);
        assert_eq!(trust[0].method, "GET");
        assert_eq!(trust[0].content_type, None);
        assert!(trust[0].body.is_empty());
        assert_eq!(gate.api_connections(), 1);
        gate.stop().await;
    }

    #[tokio::test]
    async fn session_end_and_trust_are_retried_once_on_a_refused_reused_stream() {
        for path in [SESSION_END_PATH, TRUST_PATH] {
            let (_pki, gate, api) = gate_with(&[issue()]).await;
            api.renew(&EMPTY).await.unwrap();
            let answer = if path == TRUST_PATH {
                trust_reply(&[user_ca_line()])
            } else {
                ApiStep::Json(200, json!({"outcome": "recorded"}))
            };
            gate.script(path, vec![ApiStep::RefuseStream, answer]);
            if path == TRUST_PATH {
                api.trust().await.unwrap();
            } else {
                assert_eq!(
                    api.session_end(&session_end()).await.unwrap(),
                    SessionEndOutcome::Recorded
                );
            }
            assert_eq!(gate.requests(path).len(), 2, "{path}");
            assert_eq!(gate.api_connections(), 2, "{path}");
            gate.stop().await;
        }
    }

    #[tokio::test]
    async fn oversized_and_malformed_agent_replies_are_refused() {
        let (_pki, gate, api) = gate_with(&[]).await;
        gate.script(TRUST_PATH, vec![ApiStep::Oversized]);
        assert!(matches!(api.trust().await, Err(ApiError::BodyTooLarge)));
        gate.script(
            TRUST_PATH,
            vec![ApiStep::Json(200, json!({"user_ca_keys": [], "extra": 1}))],
        );
        assert!(matches!(api.trust().await, Err(ApiError::BadResponse)));
        gate.script(
            AUTHORIZE_PATH,
            vec![ApiStep::Json(200, json!({"decision": "maybe"}))],
        );
        assert!(matches!(
            api.authorize(&authorize_request()).await,
            Err(ApiError::BadResponse)
        ));
        gate.stop().await;
    }

    #[tokio::test]
    async fn parallel_first_calls_share_one_new_connection() {
        let (_pki, gate, api) = gate_with(&[]).await;
        let api = Arc::new(api);
        let calls: Vec<_> = (0..5)
            .map(|_| {
                let api = api.clone();
                tokio::spawn(async move { api.trust().await })
            })
            .collect();
        for call in calls {
            soon("a parallel call", call).await.unwrap().unwrap();
        }
        assert_eq!(gate.requests(TRUST_PATH).len(), 5);
        assert_eq!(gate.api_connections(), 1);
        gate.stop().await;
    }

    #[tokio::test]
    async fn connecting_does_not_hold_the_connection_lock() {
        let pki = TestPki::new();
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("{AGENT_HOST}:{}", silent.local_addr().unwrap().port());
        let (api, _) = client(&pki, &endpoint, API_KEEPALIVE);
        let api = Arc::new(api);
        let pending = tokio::spawn({
            let api = api.clone();
            async move { api.trust().await }
        });
        let (_held, _) = soon("the client to connect", silent.accept())
            .await
            .unwrap();
        assert!(api.connection.try_lock().is_ok());
        soon("a reset during a slow connect", api.reset()).await;
        soon(
            "forgetting during a slow connect",
            forget(&api.connection, 0),
        )
        .await;
        assert!(!pending.is_finished());
        pending.abort();
        assert!(api.connection.lock().await.cached.is_none());
    }

    #[tokio::test]
    async fn a_reset_while_connecting_keeps_that_connection_out_of_the_cache() {
        let pki = Arc::new(TestPki::new());
        let placeholder = NodeIdentity {
            spki: Vec::new(),
            host_key: HostKey::generate().unwrap().key_data().clone(),
        };
        let gate = FakeGate::start(pki.clone(), placeholder, &[]).await;
        let relay = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("{AGENT_HOST}:{}", relay.local_addr().unwrap().port());
        let (api, node) = client(&pki, &endpoint, API_KEEPALIVE);
        gate.set_identity(node);
        gate.set_standing(
            AGENT_TRUST_V3_PATH,
            ApiStep::Json(
                200,
                json!({"trust_id": "t", "user_ca_keys": [user_ca_line()], "host_ca_active": user_ca_line(), "user_x509_roots": []}),
            ),
        );
        let api = Arc::new(api);
        let pending = tokio::spawn({
            let api = api.clone();
            async move { api.trust().await }
        });
        let (mut inbound, _) = soon("the client to connect", relay.accept()).await.unwrap();
        api.reset().await;
        let mut outbound = tokio::net::TcpStream::connect(gate.addr).await.unwrap();
        tokio::spawn(async move {
            drop(tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await);
        });
        soon("the call to finish", pending).await.unwrap().unwrap();
        assert!(api.connection.lock().await.cached.is_none());
        gate.stop().await;
    }

    #[tokio::test]
    async fn an_idempotent_call_is_retried_at_most_once() {
        let (_pki, gate, api) = gate_with(&[
            issue(),
            RenewStep::RefuseStream,
            RenewStep::RefuseStream,
            issue(),
        ])
        .await;
        api.renew(&EMPTY).await.unwrap();
        assert!(matches!(api.renew(&EMPTY).await, Err(ApiError::Http2(_))));
        assert_eq!(gate.api_connections(), 2);
        assert_eq!(gate.renewals().len(), 3);
        gate.stop().await;
    }

    #[test]
    fn the_api_keepalive_pings_every_twenty_seconds_and_waits_ten() {
        assert_eq!(API_KEEPALIVE.interval, Duration::from_secs(20));
        assert_eq!(API_KEEPALIVE.timeout, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn an_oversized_reply_is_refused() {
        let (_pki, gate, api) = gate_with(&[RenewStep::Oversized]).await;
        assert!(matches!(
            api.renew(&EMPTY).await,
            Err(ApiError::BodyTooLarge)
        ));
        gate.stop().await;
    }

    #[tokio::test]
    async fn servers_that_do_not_select_the_agent_protocol_are_refused() {
        let pki = TestPki::new();
        let silent = RawTlsServer::start(&pki, &[], false).await;
        let (api, _) = client(&pki, &silent.endpoint(), API_KEEPALIVE);
        assert!(matches!(
            api.renew(&EMPTY).await,
            Err(ApiError::UnexpectedProtocol)
        ));
        let other = RawTlsServer::start(&pki, &[b"h2"], false).await;
        let (api, _) = client(&pki, &other.endpoint(), API_KEEPALIVE);
        assert!(matches!(api.renew(&EMPTY).await, Err(ApiError::Tls(_))));
    }

    #[tokio::test]
    async fn a_peer_that_stops_answering_pings_is_dropped() {
        let pki = TestPki::new();
        let mute = RawTlsServer::start(&pki, &[ALPN_AGENT_API], true).await;
        let keepalive = Keepalive {
            interval: Duration::from_millis(50),
            timeout: Duration::from_millis(100),
        };
        let (api, _) = client(&pki, &mute.endpoint(), keepalive);
        api.sender().await.unwrap();
        assert!(api.connection.lock().await.cached.is_some());
        eventually("the silent connection to be forgotten", || {
            api.connection
                .try_lock()
                .is_ok_and(|connection| connection.cached.is_none())
        })
        .await;
    }

    #[test]
    fn statuses_map_to_typed_errors() {
        let removed = br#"{"error":"node_removed"}"#;
        assert!(matches!(
            interpret::<RenewResponse>(StatusCode::FORBIDDEN, removed),
            Err(ApiError::NodeRemoved)
        ));
        assert!(matches!(
            interpret::<RenewResponse>(StatusCode::FORBIDDEN, br#"{"error":"other"}"#),
            Err(ApiError::Status { status: 403, .. })
        ));
        assert!(matches!(
            interpret::<RenewResponse>(StatusCode::UNAUTHORIZED, b""),
            Err(ApiError::Unauthorized)
        ));
        assert!(matches!(
            interpret::<RenewResponse>(StatusCode::OK, b"{}"),
            Err(ApiError::BadResponse)
        ));
        let Err(ApiError::Status { code, .. }) = interpret::<RenewResponse>(
            StatusCode::INTERNAL_SERVER_ERROR,
            "{\"error\":\"bad\\u001b[31m code\"}".as_bytes(),
        ) else {
            panic!("expected a status error");
        };
        assert_eq!(code, "bad31mcode");
    }

    #[test]
    fn a_refusal_carries_retry_after_only_as_plain_seconds() {
        let cases = [
            ("60", Some(Duration::from_secs(60))),
            ("0", Some(Duration::ZERO)),
            ("-5", None),
            ("1.5", None),
            ("Wed, 21 Oct 2026 07:28:00 GMT", None),
            ("", None),
            ("99999999999999999999999", None),
        ];
        for (value, expected) in cases {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::RETRY_AFTER, value.parse().unwrap());
            assert_eq!(retry_after(&headers), expected, "{value:?}");
        }
        assert_eq!(retry_after(&http::HeaderMap::new()), None);
        let refused = interpret::<RenewResponse>(
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"error":"too_many_recordings"}"#,
        )
        .unwrap_err();
        assert!(matches!(
            with_retry_after(refused, Some(Duration::from_secs(60))),
            ApiError::Status { status: 429, retry_after: Some(after), .. } if after == Duration::from_secs(60)
        ));
        assert!(matches!(
            with_retry_after(ApiError::CallTimeout, Some(Duration::from_secs(60))),
            ApiError::CallTimeout
        ));
    }

    #[test]
    fn an_events_answer_names_the_refused_sessions_only_for_an_invalid_session_refusal() {
        let accepted = events_answer(
            StatusCode::OK,
            br#"{"accepted":2,"dropped":1,"withheld":1}"#,
            None,
        )
        .unwrap();
        assert!(
            matches!(accepted, EventsAnswer::Accepted(body) if body.accepted == 2 && body.withheld == 1)
        );
        let refused = events_answer(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_session","sessions":["a","b"]}"#,
            None,
        )
        .unwrap();
        assert_eq!(
            refused,
            EventsAnswer::SessionsRefused(vec!["a".to_owned(), "b".to_owned()])
        );
        for (status, body, expected) in [
            (
                StatusCode::BAD_REQUEST,
                &br#"{"error":"invalid_batch"}"#[..],
                400,
            ),
            (
                StatusCode::BAD_REQUEST,
                br#"{"error":"other","sessions":["a"]}"#,
                400,
            ),
            (StatusCode::NOT_FOUND, b"", 404),
            (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":"too_many_requests"}"#,
                429,
            ),
        ] {
            match events_answer(status, body, Some(Duration::from_secs(3))) {
                Err(ApiError::Status {
                    status,
                    retry_after,
                    ..
                }) => {
                    assert_eq!(status, expected);
                    assert_eq!(retry_after, Some(Duration::from_secs(3)));
                }
                other => panic!("{status}: {other:?}"),
            }
        }
        assert!(matches!(
            events_answer(StatusCode::OK, br#"{"accepted":0,"dropped":0}"#, None),
            Ok(EventsAnswer::Accepted(body)) if body == AgentEventsAccepted::default()
        ));
        for body in [
            &b"{}"[..],
            br#"{"error":"x"}"#,
            br#"{"dropped":1,"withheld":0}"#,
            b"7",
        ] {
            assert!(
                matches!(
                    events_answer(StatusCode::OK, body, None),
                    Err(ApiError::BadResponse)
                ),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }
}
