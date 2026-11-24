use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Ping, PingPong};
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use jaunt_proto::{ErrorBody, RenewRequest, RenewResponse};
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
    Status { status: u16, code: String },
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

struct Cached {
    generation: u64,
    sender: SendRequest<Bytes>,
}

struct Connection {
    cached: Option<Cached>,
    next_generation: u64,
}

type SharedConnection = Arc<Mutex<Connection>>;

pub struct AgentApi {
    connector: TlsConnector,
    server_addr: String,
    server_name: ServerName<'static>,
    authority: String,
    keepalive: Keepalive,
    connection: SharedConnection,
    shutdown: CancellationToken,
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
            })),
            shutdown,
        })
    }

    pub async fn renew(&self, request: &RenewRequest) -> Result<RenewResponse, ApiError> {
        self.post_json(RENEW_PATH, request, true).await
    }

    pub async fn reset(&self) {
        self.connection.lock().await.cached = None;
    }

    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
        idempotent: bool,
    ) -> Result<T, ApiError> {
        let payload = Bytes::from(serde_json::to_vec(body).map_err(|_| ApiError::Request)?);
        let uri = format!("https://{}{path}", self.authority);
        let mut retried = false;
        loop {
            let (generation, reused, sender) = self.sender().await?;
            let request = Request::builder()
                .method(Method::POST)
                .uri(uri.as_str())
                .header(CONTENT_TYPE, JSON)
                .header(ACCEPT, JSON)
                .body(())
                .map_err(|_| ApiError::Request)?;
            let outcome = tokio::select! {
                () = self.shutdown.cancelled() => return Err(ApiError::Shutdown),
                outcome = timeout(CALL_TIMEOUT, exchange(sender, request, payload.clone())) => outcome,
            };
            let error = match outcome {
                Ok(Ok((status, reply))) => return interpret(status, &reply),
                Ok(Err(exchange)) => exchange,
                Err(_) => Exchange::Failed(ApiError::CallTimeout),
            };
            forget(&self.connection, generation).await;
            let may_retry = reused && !retried;
            match error {
                Exchange::NotSent(_) if may_retry => retried = true,
                Exchange::NoResponse(_) if may_retry && idempotent => {
                    retried = true;
                }
                Exchange::NotSent(error) | Exchange::NoResponse(error) => {
                    return Err(ApiError::Http2(error));
                }
                Exchange::Failed(error) => return Err(error),
            }
        }
    }

    async fn sender(&self) -> Result<(u64, bool, SendRequest<Bytes>), ApiError> {
        let mut connection = self.connection.lock().await;
        if let Some(cached) = &connection.cached {
            return Ok((cached.generation, true, cached.sender.clone()));
        }
        let generation = connection.next_generation;
        connection.next_generation = generation.wrapping_add(1);
        let sender = tokio::select! {
            () = self.shutdown.cancelled() => return Err(ApiError::Shutdown),
            connected = self.connect(generation) => connected?,
        };
        connection.cached = Some(Cached {
            generation,
            sender: sender.clone(),
        });
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
    payload: Bytes,
) -> Result<(StatusCode, Vec<u8>), Exchange> {
    let mut sender = sender.ready().await.map_err(Exchange::NotSent)?;
    let (response, mut stream) = sender
        .send_request(request, false)
        .map_err(Exchange::NotSent)?;
    stream
        .send_data(payload, true)
        .map_err(Exchange::NoResponse)?;
    let response = response.await.map_err(Exchange::NoResponse)?;
    let status = response.status();
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
    Ok((status, reply))
}

fn interpret<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<T, ApiError> {
    if status.is_success() {
        return serde_json::from_slice(body).map_err(|_| ApiError::BadResponse);
    }
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
    Err(match (status, code.as_str()) {
        (StatusCode::FORBIDDEN, "node_removed") => ApiError::NodeRemoved,
        (StatusCode::UNAUTHORIZED, _) => ApiError::Unauthorized,
        _ => ApiError::Status {
            status: status.as_u16(),
            code,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use http::StatusCode;
    use jaunt_proto::{RenewRequest, RenewResponse};
    use jaunt_tunnel::{
        ALPN_AGENT_API, Keepalive, SwappableClientCert, agent_client_config_swappable,
    };
    use rustls::pki_types::CertificateDer;
    use tokio_util::sync::CancellationToken;

    use super::{API_KEEPALIVE, AgentApi, ApiError, RENEW_PATH, forget, interpret};
    use crate::endpoint::AgentEndpoint;
    use crate::keys::{HostKey, TlsKey};
    use crate::testkit::{
        FakeGate, NODE_ID, NODE_NAME, NodeIdentity, RawTlsServer, RenewStep, TestPki, eventually,
        unix_now,
    };

    const EMPTY: RenewRequest = RenewRequest {
        tls_public_key: None,
        ssh_host_public_key: None,
    };

    fn client(pki: &TestPki, endpoint: &str, keepalive: Keepalive) -> (AgentApi, NodeIdentity) {
        let tls = TlsKey::generate().unwrap();
        let host = HostKey::generate().unwrap();
        let certificates =
            pki.node_certificates(tls.spki_der(), host.key_data(), NODE_ID, NODE_NAME);
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
    async fn a_non_idempotent_call_is_not_repeated_after_an_unanswered_request() {
        let (_pki, gate, api) = gate_with(&[issue(), RenewStep::RefuseStream]).await;
        api.renew(&EMPTY).await.unwrap();
        let outcome = api
            .post_json::<_, RenewResponse>(RENEW_PATH, &EMPTY, false)
            .await;
        assert!(matches!(outcome, Err(ApiError::Http2(_))), "{outcome:?}");
        assert_eq!(gate.api_connections(), 1);
        assert_eq!(gate.renewals().len(), 2);
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
}
