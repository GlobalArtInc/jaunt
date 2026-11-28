use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_limits::{ConcurrencyLimiter, LogThrottle};
use jaunt_proto::{
    AgentEventValue, MAX_SERVICES_PER_AGENT, ServiceAnnouncement, ServiceKind, ServiceOutcome,
    ServiceSettings,
};
use jaunt_tunnel::BoxFuture;
use rustix::net::sockopt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use super::events::{SessionEvent, SessionEvents};
use super::handler::{
    HandlerError, ServiceConnection, ServiceGrant, ServiceHandler, ServiceSession, ServiceStream,
};
use crate::clock::Clock;

const SPLICE_BUFFER: usize = 16 * 1024;
pub const CLIENT_ADDR_BYTES: usize = 64;
const SESSION_START: &str = "tcp.session.start";
const SESSION_END: &str = "tcp.session.end";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpLimits {
    pub sessions_per_service: usize,
    pub connect_timeout: Duration,
    pub half_close_grace: Duration,
    pub failures_before_pause: u32,
    pub failure_pause: Duration,
    pub keepalive_idle: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_probes: u32,
    pub refusal_log_every: Duration,
}

pub const TCP_LIMITS: TcpLimits = TcpLimits {
    sessions_per_service: 256,
    connect_timeout: Duration::from_secs(10),
    half_close_grace: Duration::from_secs(30),
    failures_before_pause: 5,
    failure_pause: Duration::from_secs(5),
    keepalive_idle: Duration::from_secs(60),
    keepalive_interval: Duration::from_secs(20),
    keepalive_probes: 3,
    refusal_log_every: Duration::from_secs(60),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Closed,
    IdleTimeout,
    MaxDuration,
    Cancelled,
    UpstreamError,
    ClientError,
    ServiceLimit,
    UpstreamUnavailable,
    HalfCloseTimeout,
}

impl EndReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IdleTimeout => "idle_timeout",
            Self::MaxDuration => "max_duration",
            Self::Cancelled => "cancelled",
            Self::UpstreamError => "upstream_error",
            Self::ClientError => "client_error",
            Self::ServiceLimit => "service_limit",
            Self::UpstreamUnavailable => "upstream_unavailable",
            Self::HalfCloseTimeout => "half_close_timeout",
        }
    }

    const fn outcome(self) -> ServiceOutcome {
        match self {
            Self::Closed | Self::Cancelled | Self::HalfCloseTimeout => ServiceOutcome::Closed,
            Self::IdleTimeout => ServiceOutcome::IdleTimeout,
            Self::MaxDuration => ServiceOutcome::MaxDuration,
            Self::ClientError => ServiceOutcome::ProtocolError,
            Self::UpstreamError | Self::ServiceLimit | Self::UpstreamUnavailable => {
                ServiceOutcome::UpstreamError
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialFailure {
    TimedOut,
    Connect(io::ErrorKind),
    SocketOptions(io::ErrorKind),
}

impl DialFailure {
    const fn stage(self) -> &'static str {
        match self {
            Self::TimedOut => "connect_timeout",
            Self::Connect(_) => "connect",
            Self::SocketOptions(_) => "socket_options",
        }
    }

    const fn kind(self) -> io::ErrorKind {
        match self {
            Self::TimedOut => io::ErrorKind::TimedOut,
            Self::Connect(kind) | Self::SocketOptions(kind) => kind,
        }
    }
}

struct Upstream {
    address: String,
    idle_timeout: Duration,
    throttles: Throttles,
}

#[derive(Debug, Default)]
struct DialHealth {
    failures: u32,
    paused_until: Option<SystemTime>,
}

struct Throttles {
    service_limit: LogThrottle,
    paused: LogThrottle,
    dial: LogThrottle,
}

impl Throttles {
    fn new(every: Duration) -> Self {
        Self {
            service_limit: LogThrottle::new(every),
            paused: LogThrottle::new(every),
            dial: LogThrottle::new(every),
        }
    }
}

pub trait Connect: Send + Sync {
    fn connect<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<TcpStream>>;
}

pub struct SystemConnect;

impl Connect for SystemConnect {
    fn connect<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<TcpStream>> {
        Box::pin(TcpStream::connect(address))
    }
}

struct Inner {
    upstreams: HashMap<String, Upstream>,
    clock: Arc<dyn Clock>,
    limits: TcpLimits,
    connect: Arc<dyn Connect>,
    sessions: ConcurrencyLimiter<String>,
    health: Mutex<HashMap<String, DialHealth>>,
    unconfigured: LogThrottle,
}

pub struct TcpHandler {
    inner: Arc<Inner>,
}

fn configured_upstreams(
    local: &ServiceAnnouncement,
    limits: &TcpLimits,
) -> HashMap<String, Upstream> {
    let mut upstreams = HashMap::new();
    for declared in &local.services {
        if declared.kind != ServiceKind::Tcp {
            continue;
        }
        let Ok(ServiceSettings::Tcp(settings)) = declared.settings() else {
            continue;
        };
        let Some(address) = declared.address.clone() else {
            continue;
        };
        upstreams
            .entry(declared.name.clone())
            .or_insert_with(|| Upstream {
                address,
                idle_timeout: Duration::from_secs(settings.idle_timeout_secs),
                throttles: Throttles::new(limits.refusal_log_every),
            });
    }
    upstreams
}

fn later(time: SystemTime, by: Duration) -> SystemTime {
    time.checked_add(by).unwrap_or(time)
}

fn since_epoch(time: SystemTime) -> Duration {
    time.duration_since(UNIX_EPOCH).unwrap_or_default()
}

fn widen(value: u128) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn bounded(text: &str, limit: usize) -> String {
    text.get(..text.floor_char_boundary(limit))
        .unwrap_or_default()
        .to_owned()
}

impl TcpHandler {
    pub fn new(local: &ServiceAnnouncement, clock: Arc<dyn Clock>, limits: TcpLimits) -> Self {
        Self::with_connect(local, clock, limits, Arc::new(SystemConnect))
    }

    pub fn with_connect(
        local: &ServiceAnnouncement,
        clock: Arc<dyn Clock>,
        limits: TcpLimits,
        connect: Arc<dyn Connect>,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                upstreams: configured_upstreams(local, &limits),
                clock,
                limits,
                connect,
                sessions: ConcurrencyLimiter::new(
                    limits.sessions_per_service,
                    MAX_SERVICES_PER_AGENT,
                ),
                health: Mutex::new(HashMap::new()),
                unconfigured: LogThrottle::new(limits.refusal_log_every),
            }),
        }
    }

    #[cfg(test)]
    pub fn sessions_held(&self, service: &str) -> usize {
        self.inner.sessions.held(&service.to_owned())
    }

    #[cfg(test)]
    pub fn idle_timeout(&self, service: &str) -> Option<Duration> {
        self.inner
            .upstreams
            .get(service)
            .map(|upstream| upstream.idle_timeout)
    }
}

impl ServiceHandler for TcpHandler {
    fn serve(
        &self,
        connection: ServiceConnection,
        _grant: ServiceGrant,
        session: ServiceSession,
    ) -> BoxFuture<'static, Result<ServiceOutcome, HandlerError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.serve(connection, session).await })
    }
}

impl Inner {
    async fn serve(
        &self,
        connection: ServiceConnection,
        session: ServiceSession,
    ) -> Result<ServiceOutcome, HandlerError> {
        let ServiceConnection {
            stream,
            client_addr,
            ..
        } = connection;
        let service = session.service.as_str();
        let mut ledger = Ledger::open(Arc::clone(&self.clock), &session, &client_addr);
        let Some(upstream) = self.upstreams.get(service) else {
            if let Some(suppressed) = self.unconfigured.admit(since_epoch(self.clock.now())) {
                tracing::error!(
                    target: "jaunt::agent",
                    session_id = session.session_id.as_str(),
                    service,
                    suppressed,
                    "a TCP session names a service that has no address in the agent configuration; the session is closed"
                );
            }
            ledger.close(EndReason::UpstreamError);
            return Err(HandlerError);
        };
        let Ok(_slot) = self.sessions.try_acquire(service.to_owned()) else {
            self.refused(&session, upstream, EndReason::ServiceLimit);
            return Ok(ledger.close(EndReason::ServiceLimit));
        };
        if self.paused(service) {
            self.refused(&session, upstream, EndReason::UpstreamUnavailable);
            return Ok(ledger.close(EndReason::UpstreamUnavailable));
        }
        let dialed = dial(
            self.connect.connect(upstream.address.as_str()),
            &self.limits,
            self.clock.as_ref(),
        )
        .await;
        let upstream_stream = match dialed {
            Ok(upstream_stream) => {
                self.dial_succeeded(service);
                upstream_stream
            }
            Err(failure) => {
                let failures = self.dial_failed(service);
                self.dial_logged(&session, upstream, failure, failures);
                return Ok(ledger.close(EndReason::UpstreamError));
            }
        };
        let reason = splice(
            stream,
            upstream_stream,
            &Splicing {
                clock: self.clock.as_ref(),
                idle_timeout: upstream.idle_timeout,
                grace: self.limits.half_close_grace,
                moved: &ledger.moved,
            },
        )
        .await;
        Ok(ledger.close(reason))
    }

    fn health(&self) -> std::sync::MutexGuard<'_, HashMap<String, DialHealth>> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn paused(&self, service: &str) -> bool {
        let now = self.clock.now();
        self.health()
            .get(service)
            .and_then(|health| health.paused_until)
            .is_some_and(|until| now < until)
    }

    fn dial_succeeded(&self, service: &str) {
        self.health().remove(service);
    }

    fn dial_failed(&self, service: &str) -> u32 {
        let now = self.clock.now();
        let mut health = self.health();
        let entry = health.entry(service.to_owned()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.limits.failures_before_pause {
            entry.paused_until = Some(later(now, self.limits.failure_pause));
        }
        entry.failures
    }

    fn refused(&self, session: &ServiceSession, upstream: &Upstream, reason: EndReason) {
        let throttle = match reason {
            EndReason::ServiceLimit => &upstream.throttles.service_limit,
            _ => &upstream.throttles.paused,
        };
        let Some(suppressed) = throttle.admit(since_epoch(self.clock.now())) else {
            return;
        };
        tracing::warn!(
            target: "jaunt::agent",
            session_id = session.session_id.as_str(),
            service = session.service.as_str(),
            reason = reason.as_str(),
            suppressed,
            "a TCP session was refused before the agent connected to the service"
        );
    }

    fn dial_logged(
        &self,
        session: &ServiceSession,
        upstream: &Upstream,
        failure: DialFailure,
        failures: u32,
    ) {
        let Some(suppressed) = upstream.throttles.dial.admit(since_epoch(self.clock.now())) else {
            return;
        };
        tracing::warn!(
            target: "jaunt::agent",
            session_id = session.session_id.as_str(),
            service = session.service.as_str(),
            stage = failure.stage(),
            error_kind = %failure.kind(),
            failures,
            paused = failures >= self.limits.failures_before_pause,
            suppressed,
            "connecting to a TCP service failed; the session is closed"
        );
    }
}

pub async fn dial(
    connect: impl Future<Output = io::Result<TcpStream>>,
    limits: &TcpLimits,
    clock: &dyn Clock,
) -> Result<TcpStream, DialFailure> {
    let deadline = later(clock.now(), limits.connect_timeout);
    let stream = tokio::select! {
        connected = connect => {
            connected.map_err(|error| DialFailure::Connect(error.kind()))?
        }
        () = clock.sleep_until(deadline) => return Err(DialFailure::TimedOut),
    };
    socket_options(&stream, limits)
        .map_err(|errno| DialFailure::SocketOptions(io::Error::from(errno).kind()))?;
    Ok(stream)
}

fn socket_options(stream: &TcpStream, limits: &TcpLimits) -> rustix::io::Result<()> {
    sockopt::set_tcp_nodelay(stream, true)?;
    sockopt::set_socket_keepalive(stream, true)?;
    sockopt::set_tcp_keepidle(stream, limits.keepalive_idle)?;
    sockopt::set_tcp_keepintvl(stream, limits.keepalive_interval)?;
    sockopt::set_tcp_keepcnt(stream, limits.keepalive_probes)
}

#[derive(Debug, Default)]
struct Moved {
    up: AtomicU64,
    down: AtomicU64,
}

pub struct Ledger {
    events: SessionEvents,
    session_id: String,
    clock: Arc<dyn Clock>,
    cancel: CancellationToken,
    service: String,
    started: SystemTime,
    moved: Moved,
    closed: bool,
}

impl Ledger {
    pub fn open(clock: Arc<dyn Clock>, session: &ServiceSession, client_addr: &str) -> Self {
        let service = session.service.as_str().to_owned();
        session.events.emit(SessionEvent {
            name: SESSION_START,
            fields: BTreeMap::from([
                ("service".to_owned(), AgentEventValue::Text(service.clone())),
                (
                    "client_addr".to_owned(),
                    AgentEventValue::Text(bounded(client_addr, CLIENT_ADDR_BYTES)),
                ),
            ]),
        });
        Self {
            events: session.events.clone(),
            session_id: session.session_id.clone(),
            started: clock.now(),
            clock,
            cancel: session.cancel.clone(),
            service,
            moved: Moved::default(),
            closed: false,
        }
    }

    pub fn close(&mut self, reason: EndReason) -> ServiceOutcome {
        if self.closed {
            return reason.outcome();
        }
        self.closed = true;
        let bytes_up = self.moved.up.load(Ordering::Acquire);
        let bytes_down = self.moved.down.load(Ordering::Acquire);
        let duration_ms = widen(
            self.clock
                .now()
                .duration_since(self.started)
                .unwrap_or_default()
                .as_millis(),
        );
        self.events.emit(SessionEvent {
            name: SESSION_END,
            fields: BTreeMap::from([
                (
                    "service".to_owned(),
                    AgentEventValue::Text(self.service.clone()),
                ),
                (
                    "bytes_up".to_owned(),
                    AgentEventValue::Int(widen(u128::from(bytes_up))),
                ),
                (
                    "bytes_down".to_owned(),
                    AgentEventValue::Int(widen(u128::from(bytes_down))),
                ),
                ("duration_ms".to_owned(), AgentEventValue::Int(duration_ms)),
                (
                    "reason".to_owned(),
                    AgentEventValue::Text(reason.as_str().to_owned()),
                ),
            ]),
        });
        tracing::debug!(
            target: "jaunt::agent",
            session_id = self.session_id.as_str(),
            service = self.service.as_str(),
            reason = reason.as_str(),
            bytes_up,
            bytes_down,
            duration_ms,
            "a TCP session ended"
        );
        reason.outcome()
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        let reason = if std::thread::panicking() {
            EndReason::UpstreamError
        } else if self.cancel.is_cancelled() {
            EndReason::Cancelled
        } else {
            EndReason::MaxDuration
        };
        self.close(reason);
    }
}

struct Activity<'a> {
    clock: &'a dyn Clock,
    last: AtomicU64,
}

fn stamp(time: SystemTime) -> u64 {
    u64::try_from(since_epoch(time).as_nanos()).unwrap_or(u64::MAX)
}

impl<'a> Activity<'a> {
    fn new(clock: &'a dyn Clock) -> Self {
        Self {
            last: AtomicU64::new(stamp(clock.now())),
            clock,
        }
    }

    fn touch(&self) {
        self.last.store(stamp(self.clock.now()), Ordering::Release);
    }

    async fn idle(&self, timeout: Duration) {
        loop {
            let last = later(
                UNIX_EPOCH,
                Duration::from_nanos(self.last.load(Ordering::Acquire)),
            );
            let deadline = later(last, timeout);
            if self.clock.now() >= deadline {
                return;
            }
            self.clock.sleep_until(deadline).await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Client,
    Upstream,
}

impl Fault {
    const fn reason(self) -> EndReason {
        match self {
            Self::Client => EndReason::ClientError,
            Self::Upstream => EndReason::UpstreamError,
        }
    }
}

struct Splicing<'a> {
    clock: &'a dyn Clock,
    idle_timeout: Duration,
    grace: Duration,
    moved: &'a Moved,
}

enum First {
    Up,
    Down,
}

async fn splice(client: ServiceStream, upstream: TcpStream, splicing: &Splicing<'_>) -> EndReason {
    let activity = Activity::new(splicing.clock);
    let (client_read, client_write) = tokio::io::split(client);
    let (upstream_read, upstream_write) = upstream.into_split();
    let up = pump(
        client_read,
        upstream_write,
        &splicing.moved.up,
        &activity,
        Fault::Client,
        Fault::Upstream,
    );
    let down = pump(
        upstream_read,
        client_write,
        &splicing.moved.down,
        &activity,
        Fault::Upstream,
        Fault::Client,
    );
    let idle = activity.idle(splicing.idle_timeout);
    tokio::pin!(up, down, idle);
    let first = tokio::select! {
        biased;
        pumped = &mut up => pumped.map(|()| First::Up),
        pumped = &mut down => pumped.map(|()| First::Down),
        () = &mut idle => return EndReason::IdleTimeout,
    };
    match first {
        Err(fault) => fault.reason(),
        Ok(First::Up) => remaining(down, idle, splicing).await,
        Ok(First::Down) => remaining(up, idle, splicing).await,
    }
}

async fn remaining<F, I>(
    other: Pin<&mut F>,
    idle: Pin<&mut I>,
    splicing: &Splicing<'_>,
) -> EndReason
where
    F: Future<Output = Result<(), Fault>>,
    I: Future<Output = ()>,
{
    let deadline = later(splicing.clock.now(), splicing.grace);
    tokio::select! {
        biased;
        pumped = other => match pumped {
            Ok(()) => EndReason::Closed,
            Err(fault) => fault.reason(),
        },
        () = idle => EndReason::IdleTimeout,
        () = splicing.clock.sleep_until(deadline) => EndReason::HalfCloseTimeout,
    }
}

async fn pump<R, W>(
    mut from: R,
    mut to: W,
    moved: &AtomicU64,
    activity: &Activity<'_>,
    read_fault: Fault,
    write_fault: Fault,
) -> Result<(), Fault>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; SPLICE_BUFFER];
    loop {
        let read = from.read(&mut buffer).await.map_err(|_| read_fault)?;
        let chunk = buffer.get(..read).ok_or(read_fault)?;
        if chunk.is_empty() {
            return to.shutdown().await.map_err(|_| write_fault);
        }
        activity.touch();
        to.write_all(chunk).await.map_err(|_| write_fault)?;
        to.flush().await.map_err(|_| write_fault)?;
        moved.fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::AcqRel);
        activity.touch();
    }
}
