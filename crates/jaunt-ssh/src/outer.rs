use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use russh::server::{self, ChannelOpenHandle, RunningSession};
use russh::{ChannelOpenFailure, Disconnect, SshId};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::cert::{CertRejection, UserCaSource, UserIdentity};
use crate::config::ServerConfigCell;
use crate::limits::OuterLimits;

mod forward;
mod handler;
mod io;

use handler::OuterHandler;
use io::Severable;

const ROUTE_TIMEOUT: Duration = Duration::from_secs(10);
const DISCONNECT_GRACE: Duration = Duration::from_secs(2);
const FAR_FUTURE: Duration = Duration::from_secs(365 * 24 * 60 * 60);
const DENIED_TEXT: &str = "jaunt: access denied or node unavailable";
const LIMIT_TEXT: &str = "jaunt: too many open sessions";
const AUTH_TIMEOUT_TEXT: &str = "jaunt: authentication timed out";
const AUTH_ATTEMPTS_TEXT: &str = "jaunt: too many authentication attempts";
const EXPIRED_TEXT: &str = "jaunt: your certificate has expired, run jaunt login";
const SHUTDOWN_TEXT: &str = "jaunt: the gateway is shutting down";

pub trait TunnelStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> TunnelStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub type RouteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RoutedStream, RouteRefusal>> + Send + 'a>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub identity: UserIdentity,
    pub node: String,
    pub client_addr: SocketAddr,
}

pub struct RoutedStream {
    pub session_id: String,
    pub stream: Box<dyn TunnelStream>,
}

impl fmt::Debug for RoutedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedStream")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRefusal {
    Denied,
    Unavailable,
    Limit,
}

pub trait RouteBackend: Send + Sync + 'static {
    fn route(&self, target: RouteTarget) -> RouteFuture<'_>;
    fn released(&self, identity: &UserIdentity, node: &str);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthDenial {
    PlainKey,
    Password,
    KeyboardInteractive,
    Certificate(CertRejection),
}

impl AuthDenial {
    pub fn reason(self) -> &'static str {
        match self {
            Self::PlainKey => "plain_key",
            Self::Password => "password",
            Self::KeyboardInteractive => "keyboard_interactive",
            Self::Certificate(rejection) => rejection.reason(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardRefusal {
    BadTarget,
    Denied,
    Unavailable,
    Limit,
}

impl ForwardRefusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::BadTarget => "bad_target",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Limit => "limit",
        }
    }
}

impl From<RouteRefusal> for ForwardRefusal {
    fn from(refusal: RouteRefusal) -> Self {
        match refusal {
            RouteRefusal::Denied => Self::Denied,
            RouteRefusal::Unavailable => Self::Unavailable,
            RouteRefusal::Limit => Self::Limit,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    Eof,
    ClientGone,
    TunnelGone,
    Stall,
    Shutdown,
}

impl StreamEnd {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Eof => "eof",
            Self::ClientGone => "client_gone",
            Self::TunnelGone => "tunnel_gone",
            Self::Stall => "stall",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterEndReason {
    HandshakeFailed,
    AuthTimeout,
    AuthFailed,
    AuthAttempts,
    ClientGone,
    CertificateExpired,
    ProtocolViolation,
    Shutdown,
    Terminated,
}

impl OuterEndReason {
    pub fn reason(self) -> &'static str {
        match self {
            Self::HandshakeFailed => "handshake_failed",
            Self::AuthTimeout => "auth_timeout",
            Self::AuthFailed => "auth_failed",
            Self::AuthAttempts => "auth_attempts",
            Self::ClientGone => "client_gone",
            Self::CertificateExpired => "certificate_expired",
            Self::ProtocolViolation => "protocol_violation",
            Self::Shutdown => "shutdown",
            Self::Terminated => "terminated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OuterEvent {
    Connected {
        client_addr: SocketAddr,
    },
    AuthAccepted {
        user_id: String,
        serial: u64,
        login: String,
    },
    AuthDenied {
        reason: AuthDenial,
        login: String,
    },
    SessionRefused,
    ForwardRefused {
        node: Option<String>,
        refusal: ForwardRefusal,
    },
    ForwardOpened {
        node: String,
        session_id: String,
    },
    ForwardClosed {
        node: String,
        session_id: String,
        bytes_up: u64,
        bytes_down: u64,
        duration: Duration,
        reason: StreamEnd,
    },
    Disconnected {
        reason: OuterEndReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterEnd {
    pub reason: OuterEndReason,
    pub identity: Option<UserIdentity>,
}

type Events = Arc<dyn Fn(OuterEvent) + Send + Sync>;
type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Clone)]
struct Hop {
    cas: Arc<UserCaSource>,
    suffix: Arc<str>,
    limits: OuterLimits,
    backend: Arc<dyn RouteBackend>,
    events: Events,
    clock: Clock,
    session_refusal: Arc<str>,
    target_refusal: Arc<str>,
    cut_at_expiry: bool,
}

impl Hop {
    fn emit(&self, event: OuterEvent) {
        (self.events)(event);
    }

    async fn refuse(
        &self,
        reply: ChannelOpenHandle,
        node: Option<String>,
        refusal: ForwardRefusal,
    ) {
        let (code, reason) = match refusal {
            ForwardRefusal::BadTarget => (1, self.target_refusal.to_string()),
            ForwardRefusal::Denied | ForwardRefusal::Unavailable => (2, DENIED_TEXT.to_owned()),
            ForwardRefusal::Limit => (4, LIMIT_TEXT.to_owned()),
        };
        self.emit(OuterEvent::ForwardRefused { node, refusal });
        reply
            .reject(ChannelOpenFailure::Other { code, reason })
            .await;
    }
}

pub struct OuterHop {
    config: Arc<ServerConfigCell>,
    hop: Hop,
}

impl OuterHop {
    pub fn new(
        config: Arc<ServerConfigCell>,
        cas: Arc<UserCaSource>,
        suffix: impl Into<String>,
        limits: OuterLimits,
        backend: Arc<dyn RouteBackend>,
    ) -> Self {
        let suffix: String = suffix.into();
        let session_refusal = format!(
            "jaunt: this is the Jaunt SSH gateway and it has no shell. Connect to a node instead: ssh <login>@<node>.{suffix} (with this gateway as ProxyJump, ssh -J)"
        );
        let target_refusal =
            format!("jaunt: only <node>.{suffix} port 22 is reachable through this gateway");
        Self {
            config,
            hop: Hop {
                cas,
                suffix: suffix.into(),
                limits,
                backend,
                events: Arc::new(|_| {}),
                clock: Arc::new(SystemTime::now),
                session_refusal: session_refusal.into(),
                target_refusal: target_refusal.into(),
                cut_at_expiry: true,
            },
        }
    }

    pub fn keep_after_certificate_expiry(mut self) -> Self {
        self.hop.cut_at_expiry = false;
        self
    }

    pub fn with_events(mut self, events: impl Fn(OuterEvent) + Send + Sync + 'static) -> Self {
        self.hop.events = Arc::new(events);
        self
    }

    pub fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.hop.clock = Arc::new(clock);
        self
    }

    pub async fn serve<S: TunnelStream>(
        &self,
        stream: S,
        client_addr: SocketAddr,
        pre_auth: OwnedSemaphorePermit,
        shutdown: CancellationToken,
    ) -> OuterEnd {
        let stops = Stops {
            shutdown,
            terminate: CancellationToken::new(),
        };
        self.serve_until(stream, client_addr, pre_auth, stops).await
    }

    pub async fn serve_with_termination<S: TunnelStream>(
        &self,
        stream: S,
        client_addr: SocketAddr,
        pre_auth: OwnedSemaphorePermit,
        shutdown: CancellationToken,
        terminate: CancellationToken,
    ) -> OuterEnd {
        let stops = Stops {
            shutdown,
            terminate,
        };
        self.serve_until(stream, client_addr, pre_auth, stops).await
    }

    async fn serve_until<S: TunnelStream>(
        &self,
        stream: S,
        client_addr: SocketAddr,
        pre_auth: OwnedSemaphorePermit,
        stops: Stops,
    ) -> OuterEnd {
        let deadline = later(self.hop.limits.auth_deadline);
        self.hop.emit(OuterEvent::Connected { client_addr });
        let config = Arc::new(connection_config(
            &self.config.current(),
            self.hop.limits.max_auth_attempts.saturating_add(1),
        ));
        let connection = Arc::new(Connection::new(self.hop.clone(), client_addr));
        let sever = SeverOnDrop(Arc::clone(&connection));
        let tracker = TaskTracker::new();
        let handler = OuterHandler::new(
            Arc::clone(&connection),
            config.window_size,
            pre_auth,
            tracker.clone(),
        );
        let stream = Severable::new(stream, &connection.token);
        let started = tokio::select! {
            biased;
            ending = stops.stopped() => Err(ending),
            started = tokio::time::timeout_at(deadline, server::run_stream(config, stream, handler)) => {
                Ok(started)
            }
        };
        let reason = match started {
            Err(ending) => {
                connection.end.get_or_init(|| StreamEnd::Shutdown);
                ending.reason()
            }
            Ok(Err(_)) => OuterEndReason::AuthTimeout,
            Ok(Ok(Err(_))) => OuterEndReason::HandshakeFailed,
            Ok(Ok(Ok(running))) => supervise(&connection, running, deadline, &stops).await,
        };
        connection.end.get_or_init(|| StreamEnd::ClientGone);
        drop(sever);
        tracker.close();
        tracker.wait().await;
        self.hop.emit(OuterEvent::Disconnected { reason });
        OuterEnd {
            reason,
            identity: connection.phase().identity(),
        }
    }
}

#[derive(Debug, Clone)]
enum Phase {
    PreAuth,
    Authenticated(UserIdentity),
    Exhausted,
}

impl Phase {
    fn identity(self) -> Option<UserIdentity> {
        match self {
            Self::Authenticated(identity) => Some(identity),
            Self::PreAuth | Self::Exhausted => None,
        }
    }
}

struct Connection {
    hop: Hop,
    client_addr: SocketAddr,
    token: CancellationToken,
    phase: Mutex<Phase>,
    phase_changed: Notify,
    end: OnceLock<StreamEnd>,
    violation: AtomicBool,
    denied: AtomicBool,
}

impl Connection {
    fn new(hop: Hop, client_addr: SocketAddr) -> Self {
        Self {
            hop,
            client_addr,
            token: CancellationToken::new(),
            phase: Mutex::new(Phase::PreAuth),
            phase_changed: Notify::new(),
            end: OnceLock::new(),
            violation: AtomicBool::new(false),
            denied: AtomicBool::new(false),
        }
    }

    fn lock_phase(&self) -> MutexGuard<'_, Phase> {
        self.phase.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn phase(&self) -> Phase {
        self.lock_phase().clone()
    }

    fn set_phase(&self, phase: Phase) {
        *self.lock_phase() = phase;
        self.phase_changed.notify_one();
    }

    fn unix_now(&self) -> u64 {
        (self.hop.clock)()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }

    fn expiry(&self, valid_before: u64) -> Instant {
        let remaining = UNIX_EPOCH
            .checked_add(Duration::from_secs(valid_before))
            .and_then(|end| end.duration_since((self.hop.clock)()).ok())
            .unwrap_or(Duration::ZERO);
        later(remaining)
    }

    fn violated(&self) -> russh::Error {
        self.violation.store(true, Ordering::SeqCst);
        russh::Error::Inconsistent
    }

    fn settled(&self) -> OuterEndReason {
        match self.phase() {
            Phase::Exhausted => OuterEndReason::AuthAttempts,
            _ if self.violation.load(Ordering::SeqCst) => OuterEndReason::ProtocolViolation,
            Phase::PreAuth if self.denied.load(Ordering::SeqCst) => OuterEndReason::AuthFailed,
            Phase::PreAuth | Phase::Authenticated(_) => OuterEndReason::ClientGone,
        }
    }
}

struct SeverOnDrop(Arc<Connection>);

impl Drop for SeverOnDrop {
    fn drop(&mut self) {
        self.0.end.get_or_init(|| StreamEnd::Shutdown);
        self.0.token.cancel();
    }
}

#[derive(Debug, Clone, Copy)]
enum Ending {
    AuthTimeout,
    AuthAttempts,
    Expired,
    Shutdown,
    Terminated,
}

impl Ending {
    fn reason(self) -> OuterEndReason {
        match self {
            Self::AuthTimeout => OuterEndReason::AuthTimeout,
            Self::AuthAttempts => OuterEndReason::AuthAttempts,
            Self::Expired => OuterEndReason::CertificateExpired,
            Self::Shutdown => OuterEndReason::Shutdown,
            Self::Terminated => OuterEndReason::Terminated,
        }
    }

    fn disconnect(self) -> (Disconnect, &'static str) {
        match self {
            Self::AuthTimeout => (Disconnect::ByApplication, AUTH_TIMEOUT_TEXT),
            Self::AuthAttempts => (Disconnect::NoMoreAuthMethodsAvailable, AUTH_ATTEMPTS_TEXT),
            Self::Expired => (Disconnect::ByApplication, EXPIRED_TEXT),
            Self::Shutdown => (Disconnect::ByApplication, SHUTDOWN_TEXT),
            Self::Terminated => (Disconnect::ByApplication, DENIED_TEXT),
        }
    }
}

struct Stops {
    shutdown: CancellationToken,
    terminate: CancellationToken,
}

impl Stops {
    async fn stopped(&self) -> Ending {
        tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Ending::Shutdown,
            () = self.terminate.cancelled() => Ending::Terminated,
        }
    }
}

async fn supervise(
    connection: &Connection,
    mut running: RunningSession<OuterHandler>,
    deadline: Instant,
    stops: &Stops,
) -> OuterEndReason {
    let handle = running.handle();
    let mut alarm = (deadline, Ending::AuthTimeout);
    let ending = loop {
        tokio::select! {
            biased;
            _ = &mut running => return connection.settled(),
            ending = stops.stopped() => break ending,
            () = connection.phase_changed.notified() => {
                match connection.phase() {
                    Phase::PreAuth => {}
                    Phase::Authenticated(identity) => {
                        alarm = if connection.hop.cut_at_expiry {
                            (connection.expiry(identity.valid_before), Ending::Expired)
                        } else {
                            (later(FAR_FUTURE), Ending::Expired)
                        };
                    }
                    Phase::Exhausted => alarm = (Instant::now(), Ending::AuthAttempts),
                }
            }
            () = tokio::time::sleep_until(alarm.0) => break alarm.1,
        }
    };
    connection.end.get_or_init(|| StreamEnd::Shutdown);
    let (code, text) = ending.disconnect();
    let grace = later(DISCONNECT_GRACE);
    let notice = handle.disconnect(code, text.to_owned(), String::new());
    if tokio::time::timeout_at(grace, notice).await.is_err() {
        connection.token.cancel();
    }
    if tokio::time::timeout_at(grace, &mut running).await.is_err() {
        connection.token.cancel();
        let _ = running.await;
    }
    ending.reason()
}

fn connection_config(base: &server::Config, max_auth_attempts: usize) -> server::Config {
    server::Config {
        server_id: match &base.server_id {
            SshId::Standard(id) => SshId::Standard(id.clone()),
            SshId::Raw(id) => SshId::Raw(id.clone()),
        },
        methods: base.methods.clone(),
        auth_rejection_time: base.auth_rejection_time,
        auth_rejection_time_initial: base.auth_rejection_time_initial,
        keys: base.keys.clone(),
        certificates: base.certificates.clone(),
        limits: base.limits.clone(),
        window_size: base.window_size,
        maximum_packet_size: base.maximum_packet_size,
        channel_buffer_size: base.channel_buffer_size,
        event_buffer_size: base.event_buffer_size,
        preferred: base.preferred.clone(),
        max_auth_attempts,
        inactivity_timeout: base.inactivity_timeout,
        keepalive_interval: base.keepalive_interval,
        keepalive_max: base.keepalive_max,
        nodelay: base.nodelay,
        manual_window: base.manual_window,
    }
}

fn later(by: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(by)
        .or_else(|| now.checked_add(FAR_FUTURE))
        .unwrap_or(now)
}

#[cfg(test)]
mod tests {
    use russh::keys::Algorithm;

    use super::connection_config;
    use crate::config::{ServerConfigCell, ServerProfile};
    use crate::test_support::{host_identity, key};

    #[test]
    fn a_connection_config_differs_only_in_the_attempt_limit() {
        let ca = key(Algorithm::Ed25519);
        let base = ServerConfigCell::new(host_identity(&ca).0, ServerProfile::Gate).current();
        let same = connection_config(&base, base.max_auth_attempts);
        assert_eq!(format!("{same:?}"), format!("{base:?}"));
        assert_eq!(same.keys, base.keys);
        assert_eq!(same.certificates, base.certificates);
        assert_eq!(connection_config(&base, 4).max_auth_attempts, 4);
    }
}
