mod budget;
mod session;
mod upload;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use jaunt_proto::{
    BoxFuture, RecordingAck, RecordingChunk, RecordingComplete, RecordingReceipt,
    SessionPermissions,
};
use jaunt_record::{Clock as CastClock, DEFAULT_QUEUE_MAX_BYTES, SystemClock as CastSystemClock};
use jaunt_ssh::{ObserverFactory, SessionInfo, SessionObserver};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::clock::{Clock, unix_secs};
use crate::run::api::{AgentApi, ApiError};
use budget::Budget;
use session::{CastIdentity, Discard, End, SessionRecorder, Shared};
use upload::Uploader;

pub const DEFAULT_SESSION_QUEUE_BYTES: usize = DEFAULT_QUEUE_MAX_BYTES;
pub const DEFAULT_MEMORY_BUDGET_BYTES: usize = 256 * 1024 * 1024;
pub const DISABLED_FOR: Duration = Duration::from_secs(10 * 60);
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const MAX_SESSION_ID_LEN: usize = 128;
const DRAIN_MARGIN: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingLimits {
    pub session_queue_bytes: usize,
    pub memory_budget_bytes: usize,
    pub max_uploads: usize,
}

impl Default for RecordingLimits {
    fn default() -> Self {
        Self {
            session_queue_bytes: DEFAULT_SESSION_QUEUE_BYTES,
            memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
            max_uploads: usize::try_from(jaunt_tunnel::DEFAULT_MAX_CONCURRENT_STREAMS)
                .unwrap_or(usize::MAX),
        }
    }
}

pub trait RecordingTransport: Send + Sync + 'static {
    fn chunk<'a>(
        &'a self,
        session_id: &'a str,
        chunk: &'a RecordingChunk,
    ) -> BoxFuture<'a, Result<RecordingAck, ApiError>>;

    fn complete<'a>(
        &'a self,
        session_id: &'a str,
        complete: &'a RecordingComplete,
    ) -> BoxFuture<'a, Result<RecordingReceipt, ApiError>>;
}

impl RecordingTransport for AgentApi {
    fn chunk<'a>(
        &'a self,
        session_id: &'a str,
        chunk: &'a RecordingChunk,
    ) -> BoxFuture<'a, Result<RecordingAck, ApiError>> {
        Box::pin(self.recording_chunk(session_id, chunk))
    }

    fn complete<'a>(
        &'a self,
        session_id: &'a str,
        complete: &'a RecordingComplete,
    ) -> BoxFuture<'a, Result<RecordingReceipt, ApiError>> {
        Box::pin(self.recording_complete(session_id, complete))
    }
}

pub type CastClocks = Arc<dyn Fn() -> Box<dyn CastClock> + Send + Sync>;
pub type Jitter = Arc<dyn Fn() -> f64 + Send + Sync>;

pub struct RecordingParts {
    pub node_id: String,
    pub limits: RecordingLimits,
    pub transport: Arc<dyn RecordingTransport>,
    pub clock: Arc<dyn Clock>,
    pub jitter: Jitter,
    pub cast_clocks: CastClocks,
}

impl RecordingParts {
    pub fn system_cast_clocks() -> CastClocks {
        Arc::new(|| Box::new(CastSystemClock::start()))
    }
}

pub(crate) struct Service {
    node_id: String,
    limits: RecordingLimits,
    transport: Arc<dyn RecordingTransport>,
    clock: Arc<dyn Clock>,
    jitter: Jitter,
    cast_clocks: CastClocks,
    budget: Arc<Budget>,
    uploaders: Arc<Semaphore>,
    disabled_until: Mutex<Option<SystemTime>>,
    live: Mutex<HashMap<u64, Arc<Shared>>>,
    next_id: AtomicU64,
    shutdown: CancellationToken,
    drain: CancellationToken,
    drain_started: OnceLock<SystemTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotStarted {
    ShuttingDown,
    Disabled,
    TooMany,
    BadSessionId,
    NoRuntime,
}

impl NotStarted {
    fn reason(self) -> &'static str {
        match self {
            NotStarted::ShuttingDown => "agent_shutdown",
            NotStarted::Disabled => "recording_disabled",
            NotStarted::TooMany => "too_many_uploads",
            NotStarted::BadSessionId => "bad_session_id",
            NotStarted::NoRuntime => "no_runtime",
        }
    }
}

impl Service {
    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn shutting_down(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    pub(crate) fn drain_started(&self) -> Option<SystemTime> {
        self.drain_started.get().copied()
    }

    pub(crate) async fn draining(&self) {
        self.drain.cancelled().await;
    }

    pub(crate) fn disabled(&self, now: SystemTime) -> bool {
        Self::lock(&self.disabled_until).is_some_and(|until| now < until)
    }

    pub(crate) fn disable(&self, now: SystemTime) {
        let first = {
            let mut until = Self::lock(&self.disabled_until);
            let first = until.is_none_or(|until| now >= until);
            *until = Some(now + DISABLED_FOR);
            first
        };
        if first {
            tracing::warn!(
                target: "jaunt::agent",
                event = "agent.ssh.recording_disabled",
                pause_secs = DISABLED_FOR.as_secs(),
                "the server does not accept recordings; uploads pause and queued recordings are dropped"
            );
        }
        let live: Vec<Arc<Shared>> = Self::lock(&self.live).values().map(Arc::clone).collect();
        let dropped = live
            .iter()
            .filter(|shared| shared.end(End::Disabled))
            .count();
        if dropped > 0 {
            tracing::info!(
                target: "jaunt::agent",
                event = "agent.ssh.recording_disabled_dropped",
                sessions = dropped,
                "recordings dropped because the server does not accept recordings"
            );
        }
    }

    pub(crate) fn unregister(&self, id: u64) {
        Self::lock(&self.live).remove(&id);
    }

    fn begin_shutdown(&self) {
        self.shutdown.cancel();
    }

    fn begin_drain(&self) -> SystemTime {
        self.shutdown.cancel();
        let started = *self.drain_started.get_or_init(|| self.clock.now());
        self.drain.cancel();
        started
    }

    fn now_unix(&self) -> u64 {
        u64::try_from(unix_secs(self.clock.now())).unwrap_or(0)
    }

    fn open(
        self: &Arc<Self>,
        session: &SessionInfo,
        permissions: &SessionPermissions,
    ) -> Result<SessionRecorder, NotStarted> {
        if self.shutting_down() {
            return Err(NotStarted::ShuttingDown);
        }
        if self.disabled(self.clock.now()) {
            return Err(NotStarted::Disabled);
        }
        if !path_safe(&session.session_id) {
            return Err(NotStarted::BadSessionId);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| NotStarted::NoRuntime)?;
        let permit = Arc::clone(&self.uploaders)
            .try_acquire_owned()
            .map_err(|_| NotStarted::TooMany)?;
        let shared = Arc::new(Shared::new(
            self.limits.session_queue_bytes,
            Arc::clone(&self.budget),
        ));
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        Self::lock(&self.live).insert(id, Arc::clone(&shared));
        let clock = Arc::clone(&self.clock);
        let observer = SessionRecorder::new(
            Arc::clone(&shared),
            CastIdentity {
                session_id: session.session_id.clone(),
                node: self.node_id.clone(),
                user: session.user_id.clone(),
                login: session.login.clone(),
                started_at: self.now_unix(),
                record_input: permissions.record_input,
                pty_allowed: permissions.pty,
            },
            (self.cast_clocks)(),
            clock,
        );
        let uploader = Uploader {
            service: Arc::clone(self),
            shared,
            session_id: session.session_id.clone(),
            id,
            _permit: permit,
        };
        runtime.spawn(uploader.run());
        Ok(observer)
    }
}

#[derive(Clone)]
pub struct Recordings {
    service: Arc<Service>,
}

impl Recordings {
    pub fn new(parts: RecordingParts) -> Self {
        let uploads = parts.limits.max_uploads.clamp(1, Semaphore::MAX_PERMITS);
        Self {
            service: Arc::new(Service {
                node_id: parts.node_id,
                limits: RecordingLimits {
                    max_uploads: uploads,
                    ..parts.limits
                },
                transport: parts.transport,
                clock: parts.clock,
                jitter: parts.jitter,
                cast_clocks: parts.cast_clocks,
                budget: Arc::new(Budget::new(parts.limits.memory_budget_bytes)),
                uploaders: Arc::new(Semaphore::new(uploads)),
                disabled_until: Mutex::new(None),
                live: Mutex::new(HashMap::new()),
                next_id: AtomicU64::new(0),
                shutdown: CancellationToken::new(),
                drain: CancellationToken::new(),
                drain_started: OnceLock::new(),
            }),
        }
    }

    pub fn begin_shutdown(&self) {
        self.service.begin_shutdown();
    }

    pub async fn drain(&self) -> bool {
        let started = self.service.begin_drain();
        let all = u32::try_from(self.service.limits.max_uploads).unwrap_or(u32::MAX);
        let limit = SHUTDOWN_GRACE.saturating_mul(2) + DRAIN_MARGIN;
        let drained = tokio::select! {
            acquired = self.service.uploaders.acquire_many(all) => acquired.is_ok(),
            () = self.service.clock.sleep_until(started + limit) => false,
            () = tokio::time::sleep(limit) => false,
        };
        if !drained {
            tracing::warn!(
                target: "jaunt::agent",
                uploads = self.active_uploads(),
                "recording uploads did not finish before the shutdown deadline"
            );
        }
        drained
    }

    #[cfg(test)]
    pub(crate) fn memory_in_use(&self) -> usize {
        self.service.budget.used()
    }

    #[cfg(test)]
    pub(crate) fn snapshots(&self) -> Vec<session::Snapshot> {
        Service::lock(&self.service.live)
            .values()
            .map(|shared| shared.snapshot())
            .collect()
    }

    pub fn active_uploads(&self) -> usize {
        self.service
            .limits
            .max_uploads
            .saturating_sub(self.service.uploaders.available_permits())
    }
}

impl ObserverFactory for Recordings {
    fn create(
        &self,
        session: &SessionInfo,
        permissions: &SessionPermissions,
    ) -> Box<dyn SessionObserver> {
        match self.service.open(session, permissions) {
            Ok(observer) => Box::new(observer),
            Err(reason) => {
                tracing::warn!(
                    target: "jaunt::audit",
                    event = "agent.ssh.recording_not_started",
                    session_id = session.session_id.as_str(),
                    reason = reason.reason(),
                    "this session is not recorded"
                );
                Box::new(Discard)
            }
        }
    }
}

fn path_safe(session_id: &str) -> bool {
    !session_id.is_empty()
        && session_id.len() <= MAX_SESSION_ID_LEN
        && session_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && session_id.bytes().any(|byte| byte.is_ascii_alphanumeric())
}
