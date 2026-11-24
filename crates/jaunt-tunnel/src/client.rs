use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use rustls::pki_types::ServerName;
use rustls::{AlertDescription, ClientConfig};
use thiserror::Error;
use tokio::net::{TcpStream, lookup_host};
use tokio::runtime::Handle;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use crate::BoxFuture;
use crate::backoff::{Backoff, BackoffPolicy};
use crate::control::{AgentMessage, ControlChannel, ServerMessage, agent_version_is_valid};
use crate::h2io::H2Io;
use crate::options::{OptionsError, TunnelOptions, keepalive};
use crate::proto::{ALPN_TUNNEL, CONTROL_VERSION, PATH_CONTROL, PATH_STREAM, StreamMeta};
use crate::session::SessionRegistry;

const EVENT_BACKLOG: usize = 64;

type Connection = h2::server::Connection<TlsStream<TcpStream>, Bytes>;
type BoxTask = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Debug)]
pub struct IncomingStream {
    pub meta: StreamMeta,
    pub io: H2Io,
    pub cancel: CancellationToken,
}

pub trait StreamHandler: Send + Sync {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()>;

    fn trust_update(&self) {}
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClientError {
    #[error("server name is not valid for tls")]
    InvalidServerName,
    #[error("agent version is not valid")]
    InvalidAgentVersion,
    #[error("no tokio runtime is running")]
    NoRuntime,
    #[error("client options are invalid")]
    InvalidOptions(#[from] OptionsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailure {
    Timeout,
    Dns(io::ErrorKind),
    Tcp(io::ErrorKind),
    Tls(io::ErrorKind),
    ServerCertificate,
    CertificateRefused,
    UnexpectedProtocol,
    Http2,
}

impl ConnectFailure {
    pub fn cause(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Dns(_) => "dns",
            Self::Tcp(_) => "tcp",
            Self::Tls(_) | Self::UnexpectedProtocol => "tls",
            Self::ServerCertificate | Self::CertificateRefused => "auth",
            Self::Http2 => "h2",
        }
    }

    fn from_tls(error: &io::Error) -> Self {
        match error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(rustls::Error::InvalidCertificate(_)) => Self::ServerCertificate,
            Some(rustls::Error::AlertReceived(alert)) if refuses_our_certificate(*alert) => {
                Self::CertificateRefused
            }
            _ => Self::Tls(error.kind()),
        }
    }

    fn from_http2(io_error: Option<&io::Error>) -> Self {
        match io_error.map(Self::from_tls) {
            Some(Self::CertificateRefused) => Self::CertificateRefused,
            _ => Self::Http2,
        }
    }
}

fn refuses_our_certificate(alert: AlertDescription) -> bool {
    matches!(
        alert,
        AlertDescription::BadCertificate
            | AlertDescription::UnsupportedCertificate
            | AlertDescription::CertificateRevoked
            | AlertDescription::CertificateExpired
            | AlertDescription::CertificateUnknown
            | AlertDescription::UnknownCA
            | AlertDescription::AccessDenied
            | AlertDescription::CertificateRequired
    )
}

async fn dial(server_addr: &str) -> Result<TcpStream, ConnectFailure> {
    let addresses = lookup_host(server_addr)
        .await
        .map_err(|error| ConnectFailure::Dns(error.kind()))?;
    let mut failure = ConnectFailure::Dns(io::ErrorKind::NotFound);
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(tcp) => return Ok(tcp),
            Err(error) => failure = ConnectFailure::Tcp(error.kind()),
        }
    }
    Err(failure)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEvent {
    ConnectFailed(ConnectFailure),
    Connected,
    Disconnected { lasted: Duration },
}

pub struct TunnelClientConfig {
    pub tls: Arc<ClientConfig>,
    pub server_addr: String,
    pub sni: String,
    pub agent_version: String,
    pub options: TunnelOptions,
    pub backoff: BackoffPolicy,
    pub sessions: SessionRegistry,
    events: broadcast::Sender<ClientEvent>,
}

impl TunnelClientConfig {
    pub fn new(
        tls: Arc<ClientConfig>,
        server_addr: impl Into<String>,
        sni: impl Into<String>,
        agent_version: impl Into<String>,
    ) -> Self {
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        Self {
            tls,
            server_addr: server_addr.into(),
            sni: sni.into(),
            agent_version: agent_version.into(),
            options: TunnelOptions::default(),
            backoff: BackoffPolicy::default(),
            sessions: SessionRegistry::new(),
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ClientEvent> {
        self.events.subscribe()
    }
}

struct Context {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    server_addr: String,
    agent_version: String,
    options: TunnelOptions,
    sessions: SessionRegistry,
    handler: Arc<dyn StreamHandler>,
    events: broadcast::Sender<ClientEvent>,
}

enum TaskEnd {
    Stream,
    Control,
}

pub struct TunnelClient;

impl TunnelClient {
    pub async fn run(
        config: TunnelClientConfig,
        handler: Arc<dyn StreamHandler>,
        shutdown: CancellationToken,
    ) -> Result<(), ClientError> {
        Handle::try_current().map_err(|_| ClientError::NoRuntime)?;
        config.options.validate()?;
        config.backoff.validate()?;
        let server_name =
            ServerName::try_from(config.sni.clone()).map_err(|_| ClientError::InvalidServerName)?;
        if !agent_version_is_valid(&config.agent_version) {
            return Err(ClientError::InvalidAgentVersion);
        }
        let mut tls = (*config.tls).clone();
        tls.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
        let context = Context {
            connector: TlsConnector::from(Arc::new(tls)),
            server_name,
            server_addr: config.server_addr,
            agent_version: config.agent_version,
            options: config.options,
            sessions: config.sessions,
            handler,
            events: config.events,
        };
        let mut backoff = Backoff::new(config.backoff);
        while !shutdown.is_cancelled() {
            let lasted = context.attempt(&shutdown).await;
            let delay = backoff.next_delay(lasted, rand::random_range(0.0..=1.0));
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = sleep(delay) => {}
            }
        }
        Ok(())
    }
}

impl Context {
    fn publish(&self, event: ClientEvent) {
        drop(self.events.send(event));
    }

    async fn attempt(&self, shutdown: &CancellationToken) -> Duration {
        let connected = tokio::select! {
            () = shutdown.cancelled() => return Duration::ZERO,
            connected = self.connect() => connected,
        };
        let connection = match connected {
            Ok(connection) => connection,
            Err(failure) => {
                self.publish(ClientEvent::ConnectFailed(failure));
                return Duration::ZERO;
            }
        };
        self.publish(ClientEvent::Connected);
        let started = Instant::now();
        self.serve_connection(connection, shutdown).await;
        let lasted = started.elapsed();
        self.publish(ClientEvent::Disconnected { lasted });
        lasted
    }

    async fn connect(&self) -> Result<Connection, ConnectFailure> {
        let limit = self.options.handshake_timeout;
        let tcp = timeout(limit, dial(&self.server_addr))
            .await
            .map_err(|_| ConnectFailure::Timeout)??;
        tcp.set_nodelay(true)
            .map_err(|error| ConnectFailure::Tcp(error.kind()))?;
        let tls = timeout(limit, self.connector.connect(self.server_name.clone(), tcp))
            .await
            .map_err(|_| ConnectFailure::Timeout)?
            .map_err(|error| ConnectFailure::from_tls(&error))?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN_TUNNEL) {
            return Err(ConnectFailure::UnexpectedProtocol);
        }
        let mut builder = h2::server::Builder::new();
        builder
            .initial_window_size(self.options.stream_window)
            .initial_connection_window_size(self.options.connection_window)
            .max_header_list_size(self.options.max_header_list_size)
            .max_concurrent_streams(self.options.advertised_stream_limit());
        timeout(limit, builder.handshake::<_, Bytes>(tls))
            .await
            .map_err(|_| ConnectFailure::Timeout)?
            .map_err(|error| ConnectFailure::from_http2(error.get_io()))
    }

    async fn serve_connection(&self, mut connection: Connection, shutdown: &CancellationToken) {
        let Some(pings) = connection.ping_pong() else {
            return;
        };
        let token = shutdown.child_token();
        let mut keepalive_task: BoxTask =
            Box::pin(keepalive(pings, self.options.keepalive, token.clone()));
        let mut tasks: JoinSet<TaskEnd> = JoinSet::new();
        let mut control_started = false;
        let graceful = loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break true,
                () = keepalive_task.as_mut() => break false,
                Some(ended) = tasks.join_next() => {
                    if matches!(ended, Ok(TaskEnd::Control)) {
                        break false;
                    }
                }
                accepted = connection.accept() => match accepted {
                    Some(Ok((request, respond))) => {
                        self.dispatch(request, respond, &token, &mut tasks, &mut control_started);
                    }
                    Some(Err(_)) | None => break false,
                },
            }
        };
        let graceful = shutdown_is_graceful(graceful, shutdown.is_cancelled());
        token.cancel();
        drop(keepalive_task);
        if graceful {
            connection.graceful_shutdown();
        }
        let grace = self.options.close_grace;
        drop(timeout(grace, poll_fn(|cx| connection.poll_closed(cx))).await);
        drop(timeout(grace, async { while tasks.join_next().await.is_some() {} }).await);
    }

    fn dispatch(
        &self,
        request: Request<RecvStream>,
        respond: SendResponse<Bytes>,
        token: &CancellationToken,
        tasks: &mut JoinSet<TaskEnd>,
        control_started: &mut bool,
    ) {
        let (parts, body) = request.into_parts();
        let path = parts.uri.path();
        let known = path == PATH_STREAM || path == PATH_CONTROL;
        if !known {
            refuse(respond, StatusCode::NOT_FOUND);
            return;
        }
        if parts.method != Method::POST {
            refuse(respond, StatusCode::METHOD_NOT_ALLOWED);
            return;
        }
        if path == PATH_CONTROL {
            if *control_started {
                refuse(respond, StatusCode::CONFLICT);
                return;
            }
            *control_started = true;
            let Some(send) = answer_ok(respond) else {
                return;
            };
            let io = H2Io::new(body, send).with_cancel(token);
            tasks.spawn(control_loop(
                io,
                self.agent_version.clone(),
                self.sessions.clone(),
                self.handler.clone(),
            ));
            return;
        }
        let Ok(meta) = StreamMeta::from_headers(&parts.headers) else {
            refuse(respond, StatusCode::BAD_REQUEST);
            return;
        };
        let Ok(guard) = self.sessions.begin(meta.session(), token) else {
            refuse(respond, StatusCode::CONFLICT);
            return;
        };
        let Some(send) = answer_ok(respond) else {
            return;
        };
        let io = H2Io::new(body, send).with_cancel(guard.token());
        let cancel = guard.token().clone();
        let handler = self.handler.clone();
        tasks.spawn(async move {
            handler.handle(IncomingStream { meta, io, cancel }).await;
            drop(guard);
            TaskEnd::Stream
        });
    }
}

fn shutdown_is_graceful(loop_graceful: bool, shutdown_cancelled: bool) -> bool {
    loop_graceful || shutdown_cancelled
}

fn refuse(mut respond: SendResponse<Bytes>, status: StatusCode) {
    let mut response = Response::new(());
    *response.status_mut() = status;
    drop(respond.send_response(response, true));
}

fn answer_ok(mut respond: SendResponse<Bytes>) -> Option<SendStream<Bytes>> {
    respond.send_response(Response::new(()), false).ok()
}

async fn control_loop(
    io: H2Io,
    agent_version: String,
    sessions: SessionRegistry,
    handler: Arc<dyn StreamHandler>,
) -> TaskEnd {
    let mut channel = ControlChannel::new(io);
    let hello = AgentMessage::Hello {
        version: CONTROL_VERSION,
        agent_version,
    };
    if channel.send(&hello).await.is_err() {
        return TaskEnd::Control;
    }
    loop {
        match channel.recv::<ServerMessage>().await {
            Ok(Some(ServerMessage::Welcome {})) => {}
            Ok(Some(ServerMessage::TerminateSession { session })) => {
                sessions.terminate(&session);
            }
            Ok(Some(ServerMessage::TrustUpdate {})) => handler.trust_update(),
            Ok(None) | Err(_) => return TaskEnd::Control,
        }
    }
}

#[cfg(test)]
mod tests {
    use rustls::CertificateError;

    use super::*;

    #[test]
    fn connect_failures_name_their_cause_and_carry_no_details() {
        let tls = |inner: rustls::Error| {
            ConnectFailure::from_tls(&io::Error::new(io::ErrorKind::InvalidData, inner))
        };
        let cases = [
            (
                ConnectFailure::Dns(io::ErrorKind::NotFound),
                ConnectFailure::Dns(io::ErrorKind::NotFound),
                "dns",
            ),
            (
                ConnectFailure::Tcp(io::ErrorKind::ConnectionRefused),
                ConnectFailure::Tcp(io::ErrorKind::ConnectionRefused),
                "tcp",
            ),
            (
                ConnectFailure::from_tls(&io::Error::from(io::ErrorKind::ConnectionReset)),
                ConnectFailure::Tls(io::ErrorKind::ConnectionReset),
                "tls",
            ),
            (
                tls(rustls::Error::AlertReceived(
                    AlertDescription::HandshakeFailure,
                )),
                ConnectFailure::Tls(io::ErrorKind::InvalidData),
                "tls",
            ),
            (
                tls(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                )),
                ConnectFailure::ServerCertificate,
                "auth",
            ),
            (
                tls(rustls::Error::AlertReceived(
                    AlertDescription::CertificateRequired,
                )),
                ConnectFailure::CertificateRefused,
                "auth",
            ),
            (
                tls(rustls::Error::AlertReceived(AlertDescription::UnknownCA)),
                ConnectFailure::CertificateRefused,
                "auth",
            ),
            (
                ConnectFailure::UnexpectedProtocol,
                ConnectFailure::UnexpectedProtocol,
                "tls",
            ),
            (ConnectFailure::Http2, ConnectFailure::Http2, "h2"),
            (ConnectFailure::Timeout, ConnectFailure::Timeout, "timeout"),
        ];
        for (failure, expected, cause) in cases {
            assert_eq!(failure, expected);
            assert_eq!(failure.cause(), cause, "{failure:?}");
            assert!(!format!("{failure:?}").contains("Issuer"), "{failure:?}");
        }
        let refused = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(AlertDescription::BadCertificate),
        );
        assert_eq!(
            ConnectFailure::from_http2(Some(&refused)),
            ConnectFailure::CertificateRefused
        );
        let reset = io::Error::from(io::ErrorKind::ConnectionReset);
        assert_eq!(
            ConnectFailure::from_http2(Some(&reset)),
            ConnectFailure::Http2
        );
        assert_eq!(ConnectFailure::from_http2(None), ConnectFailure::Http2);
    }

    #[test]
    fn a_cancelled_shutdown_is_graceful_whichever_branch_ended_the_loop() {
        let cases = [
            ("loop saw shutdown", true, true, true),
            ("loop saw shutdown, flag not yet visible", true, false, true),
            ("keepalive child token won the race", false, true, true),
            ("peer or keepalive failure", false, false, false),
        ];
        for (name, loop_graceful, cancelled, expected) in cases {
            assert_eq!(
                shutdown_is_graceful(loop_graceful, cancelled),
                expected,
                "{name}"
            );
        }
    }
}
