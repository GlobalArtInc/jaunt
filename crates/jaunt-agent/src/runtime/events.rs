use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_limits::LogThrottle;
use jaunt_proto::{
    AGENT_EVENTS_MAX_BATCH, AGENT_EVENTS_MAX_BODY_BYTES, AGENT_EVENTS_MAX_DROPPED,
    AGENT_EVENTS_MAX_REFUSED_SESSIONS, AgentEvent, AgentEventBatch, AgentEventValue, DroppedEvents,
    agent_event_name,
};
use jaunt_tunnel::{BoxFuture, ClientEvent, MAX_SESSION_ID_LEN};
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::run::api::{AgentApi, ApiError, EventsAnswer};
use crate::trust::{Sampler, spread};

const BATCH_FRAME_BYTES: usize = 32;
const REPORT_BYTES: usize = 128;
const MAX_PENDING_REPORTS: usize = 4096;
const MAX_REJECTED_SESSIONS: usize = 4096;
const SEQ_PER_MILLISECOND: u64 = 1000;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
const FAILURE_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkLimits {
    pub queue_events: usize,
    pub queue_bytes: usize,
    pub batch_events: usize,
    pub batch_bytes: usize,
    pub batch_wait: Duration,
    pub first_retry: Duration,
    pub max_retry: Duration,
    pub send_timeout: Duration,
    pub first_probe: Duration,
    pub max_probe: Duration,
    pub rejected_for: Duration,
}

pub const SINK_LIMITS: SinkLimits = SinkLimits {
    queue_events: 4096,
    queue_bytes: 4 * 1024 * 1024,
    batch_events: AGENT_EVENTS_MAX_BATCH,
    batch_bytes: AGENT_EVENTS_MAX_BODY_BYTES,
    batch_wait: Duration::from_secs(1),
    first_retry: Duration::from_secs(1),
    max_retry: Duration::from_secs(30),
    send_timeout: Duration::from_secs(30),
    first_probe: Duration::from_secs(5),
    max_probe: Duration::from_secs(300),
    rejected_for: Duration::from_secs(3600),
};

impl SinkLimits {
    fn largest_event(&self) -> usize {
        self.batch_bytes
            .saturating_sub(BATCH_FRAME_BYTES + REPORT_BYTES * AGENT_EVENTS_MAX_DROPPED + 1)
    }
}

pub trait EventTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>>;
}

impl EventTransport for AgentApi {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        Box::pin(self.agent_events(batch))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEvent {
    pub name: &'static str,
    pub fields: BTreeMap<String, AgentEventValue>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkCounters {
    pub emitted: u64,
    pub sent: u64,
    pub dropped: u64,
    pub refused: u64,
    pub unsupported: u64,
    pub unreported: u64,
    pub failures: u64,
}

struct Pending {
    event: AgentEvent,
    size: usize,
    critical: bool,
    queued_at: SystemTime,
}

#[derive(Default)]
struct Held {
    events: Vec<Pending>,
    reports: Vec<DroppedEvents>,
}

impl Held {
    fn batch(&self) -> AgentEventBatch {
        AgentEventBatch {
            events: self
                .events
                .iter()
                .map(|pending| pending.event.clone())
                .collect(),
            dropped: self.reports.clone(),
        }
    }
}

#[derive(Default)]
struct State {
    critical: VecDeque<Pending>,
    noisy: VecDeque<Pending>,
    held: Option<Held>,
    sending: bool,
    events: usize,
    bytes: usize,
    reports: HashMap<String, u64>,
    reports_since: Option<SystemTime>,
    next_seq: u64,
    retry_at: Option<SystemTime>,
    attempt: u32,
    flush_wanted: bool,
    unsupported: bool,
    probe_at: Option<SystemTime>,
    probe_wait: Duration,
    probe_now: bool,
    rejected: HashMap<String, (u64, SystemTime)>,
    counters: SinkCounters,
}

impl State {
    fn report(&mut self, session_id: &str, count: u64, now: SystemTime) {
        self.counters.dropped = self.counters.dropped.saturating_add(count);
        self.add_report(session_id, count, now);
    }

    fn lose_unsupported(&mut self, session_id: &str, count: u64, now: SystemTime) {
        self.counters.unsupported = self.counters.unsupported.saturating_add(count);
        self.add_report(session_id, count, now);
    }

    fn add_report(&mut self, session_id: &str, count: u64, now: SystemTime) {
        if let Some(slot) = self.reports.get_mut(session_id) {
            *slot = slot.saturating_add(count);
            return;
        }
        if self.reports.len() >= MAX_PENDING_REPORTS {
            self.counters.unreported = self.counters.unreported.saturating_add(count);
            return;
        }
        self.reports.insert(session_id.to_owned(), count);
        self.reports_since.get_or_insert(now);
    }

    fn release(&mut self, pending: &Pending) {
        self.events = self.events.saturating_sub(1);
        self.bytes = self.bytes.saturating_sub(pending.size);
    }

    fn evict_noisy(&mut self) -> Option<Pending> {
        if let Some(evicted) = self.noisy.pop_back() {
            return Some(evicted);
        }
        if self.sending {
            return None;
        }
        let held = self.held.as_mut()?;
        let position = held.events.iter().rposition(|pending| !pending.critical)?;
        Some(held.events.remove(position))
    }

    fn holds(&self, session_id: &str) -> bool {
        let queued = |pending: &Pending| pending.event.session_id == session_id;
        self.critical.iter().any(queued)
            || self.noisy.iter().any(queued)
            || self.reports.contains_key(session_id)
            || self.held.as_ref().is_some_and(|held| {
                held.events.iter().any(queued)
                    || held
                        .reports
                        .iter()
                        .any(|report| report.session_id == session_id)
            })
    }

    fn oldest(&self) -> Option<SystemTime> {
        [
            self.critical.front().map(|pending| pending.queued_at),
            self.noisy.front().map(|pending| pending.queued_at),
            self.reports_since,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn form(&mut self, limits: &SinkLimits) -> Option<Held> {
        let mut held = Held::default();
        let mut bytes = BATCH_FRAME_BYTES;
        let sessions: Vec<String> = self
            .reports
            .keys()
            .take(AGENT_EVENTS_MAX_DROPPED)
            .cloned()
            .collect();
        for session_id in sessions {
            if let Some(count) = self.reports.remove(&session_id) {
                bytes += REPORT_BYTES;
                held.reports.push(DroppedEvents { session_id, count });
            }
        }
        if self.reports.is_empty() {
            self.reports_since = None;
        }
        while held.events.len() < limits.batch_events {
            let next = self
                .critical
                .front()
                .or_else(|| self.noisy.front())
                .map(|pending| pending.size);
            let Some(size) = next else {
                break;
            };
            if bytes.saturating_add(size + 1) > limits.batch_bytes {
                break;
            }
            let taken = match self.critical.pop_front() {
                Some(pending) => Some(pending),
                None => self.noisy.pop_front(),
            };
            let Some(mut pending) = taken else {
                break;
            };
            bytes += size + 1;
            self.next_seq = self.next_seq.saturating_add(1);
            pending.event.seq = self.next_seq;
            held.events.push(pending);
        }
        if self.critical.is_empty() && self.noisy.is_empty() {
            self.flush_wanted = false;
        }
        (!held.events.is_empty() || !held.reports.is_empty()).then_some(held)
    }

    fn settle(&mut self) -> usize {
        let Some(held) = self.held.take() else {
            return 0;
        };
        for pending in &held.events {
            self.release(pending);
        }
        held.events.len()
    }

    fn lose_everything(&mut self, now: SystemTime) {
        let mut lost: Vec<Pending> = Vec::new();
        if let Some(held) = self.held.take() {
            for report in held.reports {
                self.add_report(&report.session_id, report.count, now);
            }
            lost.extend(held.events);
        }
        lost.extend(self.critical.drain(..));
        lost.extend(self.noisy.drain(..));
        for pending in lost {
            self.release(&pending);
            self.lose_unsupported(&pending.event.session_id, 1, now);
        }
    }

    fn reject(&mut self, session_id: &str, count: u64, now: SystemTime) {
        self.counters.refused = self.counters.refused.saturating_add(count);
        if let Some((slot, _)) = self.rejected.get_mut(session_id) {
            *slot = slot.saturating_add(count);
        } else if self.rejected.len() < MAX_REJECTED_SESSIONS {
            self.rejected.insert(session_id.to_owned(), (count, now));
        }
    }

    fn still_rejected(
        &mut self,
        session_id: &str,
        now: SystemTime,
        rejected_for: Duration,
    ) -> bool {
        let Some((_, since)) = self.rejected.get(session_id) else {
            return false;
        };
        if now.duration_since(*since).unwrap_or_default() < rejected_for {
            return true;
        }
        self.rejected.remove(session_id);
        false
    }

    fn refuse_sessions(&mut self, named: &[String], now: SystemTime) -> bool {
        let Some(mut held) = self.held.take() else {
            return false;
        };
        let in_batch: HashSet<&str> = held
            .events
            .iter()
            .map(|pending| pending.event.session_id.as_str())
            .chain(held.reports.iter().map(|report| report.session_id.as_str()))
            .collect();
        let refused: HashSet<String> = named
            .iter()
            .filter(|id| in_batch.contains(id.as_str()))
            .take(AGENT_EVENTS_MAX_REFUSED_SESSIONS)
            .cloned()
            .collect();
        if refused.is_empty() {
            self.held = Some(held);
            return false;
        }
        let mut removed: Vec<Pending> = Vec::new();
        let (gone, kept): (Vec<Pending>, Vec<Pending>) = held
            .events
            .into_iter()
            .partition(|pending| refused.contains(&pending.event.session_id));
        removed.extend(gone);
        held.events = kept;
        held.reports
            .retain(|report| !refused.contains(&report.session_id));
        for queue in [&mut self.critical, &mut self.noisy] {
            let (gone, kept): (VecDeque<Pending>, VecDeque<Pending>) = queue
                .drain(..)
                .partition(|pending| refused.contains(&pending.event.session_id));
            removed.extend(gone);
            *queue = kept;
        }
        self.reports
            .retain(|session_id, _| !refused.contains(session_id));
        for session_id in &refused {
            self.reject(session_id, 0, now);
        }
        for pending in removed {
            self.release(&pending);
            self.reject(&pending.event.session_id, 1, now);
        }
        if !held.events.is_empty() || !held.reports.is_empty() {
            self.held = Some(held);
        }
        true
    }
}

enum Next {
    Ready,
    Idle,
    Until(SystemTime),
}

enum Sent {
    Answer(Result<EventsAnswer, ApiError>),
    TimedOut,
}

struct Inner {
    clock: Arc<dyn Clock>,
    sample: Sampler,
    transport: Arc<dyn EventTransport>,
    limits: SinkLimits,
    state: Mutex<State>,
    wake: Notify,
    progress: watch::Sender<u64>,
    failures: LogThrottle,
}

#[derive(Clone)]
pub struct EventSink {
    inner: Arc<Inner>,
}

impl fmt::Debug for EventSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventSink")
            .field("queued", &self.queue_len())
            .finish_non_exhaustive()
    }
}

fn unix_millis(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |elapsed| {
        i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
    })
}

fn later(time: SystemTime, by: Duration) -> SystemTime {
    time.checked_add(by).unwrap_or(time)
}

fn wire_size(event: &AgentEvent) -> Option<usize> {
    serde_json::to_vec(event).ok().map(|bytes| bytes.len())
}

impl EventSink {
    pub fn new(
        transport: Arc<dyn EventTransport>,
        clock: Arc<dyn Clock>,
        sample: Sampler,
        limits: SinkLimits,
    ) -> Self {
        let first_seq = u64::try_from(unix_millis(clock.now()))
            .unwrap_or(0)
            .saturating_mul(SEQ_PER_MILLISECOND);
        Self {
            inner: Arc::new(Inner {
                clock,
                sample,
                transport,
                limits,
                state: Mutex::new(State {
                    next_seq: first_seq,
                    ..State::default()
                }),
                wake: Notify::new(),
                progress: watch::Sender::new(0),
                failures: LogThrottle::new(FAILURE_LOG_EVERY),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub fn session(&self, session_id: &str) -> SessionEvents {
        SessionEvents {
            sink: self.clone(),
            session_id: Arc::from(session_id),
        }
    }

    pub fn emit(&self, session_id: &str, event: SessionEvent) {
        let now = self.inner.clock.now();
        let known = agent_event_name(event.name);
        let mut wire = AgentEvent {
            session_id: session_id.to_owned(),
            seq: u64::MAX,
            observed_at: unix_millis(now),
            name: event.name.to_owned(),
            fields: event.fields,
        };
        let size = wire_size(&wire).unwrap_or(usize::MAX);
        wire.seq = 0;
        let mut state = self.state();
        state.counters.emitted = state.counters.emitted.saturating_add(1);
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_LEN {
            state.counters.unreported = state.counters.unreported.saturating_add(1);
            return;
        }
        if state.still_rejected(session_id, now, self.inner.limits.rejected_for) {
            state.reject(session_id, 1, now);
            return;
        }
        if state.unsupported {
            state.lose_unsupported(session_id, 1, now);
            return;
        }
        let Some(known) = known else {
            state.report(session_id, 1, now);
            return;
        };
        if size > self.inner.limits.largest_event() {
            state.report(session_id, 1, now);
            return;
        }
        let limits = &self.inner.limits;
        while state.events + 1 > limits.queue_events
            || state.bytes.saturating_add(size) > limits.queue_bytes
        {
            if !known.lifecycle {
                state.report(session_id, 1, now);
                return;
            }
            let Some(evicted) = state.evict_noisy() else {
                state.report(session_id, 1, now);
                return;
            };
            state.release(&evicted);
            let owner = evicted.event.session_id.clone();
            state.report(&owner, 1, now);
        }
        state.events += 1;
        state.bytes += size;
        let pending = Pending {
            event: wire,
            size,
            critical: known.lifecycle,
            queued_at: now,
        };
        if known.lifecycle {
            state.critical.push_back(pending);
        } else {
            state.noisy.push_back(pending);
        }
        drop(state);
        self.inner.wake.notify_one();
    }

    pub async fn flush(&self, session_id: &str, deadline: SystemTime) -> bool {
        let mut progress = self.inner.progress.subscribe();
        {
            let mut state = self.state();
            if !state.holds(session_id) {
                return true;
            }
            state.flush_wanted = true;
        }
        self.inner.wake.notify_one();
        loop {
            {
                let state = self.state();
                if !state.holds(session_id) {
                    return true;
                }
                if state.unsupported {
                    return false;
                }
            }
            tokio::select! {
                changed = progress.changed() => if changed.is_err() {
                    return !self.state().holds(session_id);
                },
                () = self.inner.clock.sleep_until(deadline) => {
                    return !self.state().holds(session_id);
                }
            }
        }
    }

    pub fn session_ended(&self, session_id: &str) {
        self.state().rejected.remove(session_id);
    }

    pub fn reconnected(&self) {
        {
            let mut state = self.state();
            if !state.unsupported {
                return;
            }
            state.probe_now = true;
        }
        self.inner.wake.notify_one();
    }

    pub fn queue_len(&self) -> usize {
        self.state().events
    }

    #[cfg_attr(not(test), expect(dead_code))]
    pub fn counters(&self) -> SinkCounters {
        self.state().counters
    }

    fn next(&self) -> Next {
        let now = self.inner.clock.now();
        let state = self.state();
        if let Some(at) = state.retry_at
            && now < at
        {
            return Next::Until(at);
        }
        if state.held.is_some() {
            return Next::Ready;
        }
        if state.unsupported {
            return match state.probe_at {
                Some(at) if !state.probe_now && now < at => Next::Until(at),
                _ => Next::Ready,
            };
        }
        let Some(oldest) = state.oldest() else {
            return Next::Idle;
        };
        let queued = state.critical.len() + state.noisy.len();
        let limits = &self.inner.limits;
        if state.flush_wanted || queued >= limits.batch_events || state.bytes >= limits.batch_bytes
        {
            return Next::Ready;
        }
        let due = later(oldest, limits.batch_wait);
        if now >= due {
            Next::Ready
        } else {
            Next::Until(due)
        }
    }

    async fn ready(&self, stop: &CancellationToken) -> bool {
        loop {
            let woken = self.inner.wake.notified();
            match self.next() {
                Next::Ready => return true,
                Next::Idle => tokio::select! {
                    () = stop.cancelled() => return false,
                    () = woken => {}
                },
                Next::Until(at) => tokio::select! {
                    () = stop.cancelled() => return false,
                    () = woken => {}
                    () = self.inner.clock.sleep_until(at) => {}
                },
            }
        }
    }

    fn take_batch(&self) -> Option<AgentEventBatch> {
        let mut state = self.state();
        if state.held.is_none() {
            let formed = state.form(&self.inner.limits);
            state.held = match formed {
                Some(held) => Some(held),
                None if state.unsupported => Some(Held::default()),
                None => None,
            };
            state.probe_now = false;
        }
        let batch = state.held.as_ref().map(Held::batch)?;
        state.sending = true;
        Some(batch)
    }

    pub async fn run(self, stop: CancellationToken) {
        while self.ready(&stop).await {
            let Some(batch) = self.take_batch() else {
                continue;
            };
            let deadline = later(self.inner.clock.now(), self.inner.limits.send_timeout);
            let sent = tokio::select! {
                () = stop.cancelled() => return,
                answer = self.inner.transport.send(&batch) => Sent::Answer(answer),
                () = self.inner.clock.sleep_until(deadline) => Sent::TimedOut,
            };
            self.settle(&batch, sent);
            self.inner.progress.send_modify(|version| *version += 1);
        }
    }

    fn backoff(&self, state: &mut State) -> Duration {
        let limits = &self.inner.limits;
        let cap = limits
            .first_retry
            .saturating_mul(2_u32.saturating_pow(state.attempt))
            .min(limits.max_retry);
        state.attempt = state.attempt.saturating_add(1);
        spread(limits.first_retry, cap, (self.inner.sample)())
    }

    fn settle(&self, batch: &AgentEventBatch, sent: Sent) {
        let now = self.inner.clock.now();
        let mut state = self.state();
        state.sending = false;
        let events = u64::try_from(batch.events.len()).unwrap_or(u64::MAX);
        match sent {
            Sent::Answer(Ok(EventsAnswer::Accepted(_))) => {
                state.settle();
                state.counters.sent = state.counters.sent.saturating_add(events);
                state.attempt = 0;
                state.retry_at = None;
                if state.unsupported {
                    state.unsupported = false;
                    state.probe_at = None;
                    state.probe_wait = Duration::ZERO;
                    drop(state);
                    tracing::info!(
                        target: "jaunt::agent",
                        "the control plane takes audit events of service sessions again; the counts of the events dropped meanwhile were sent"
                    );
                }
            }
            Sent::Answer(Ok(EventsAnswer::SessionsRefused(named))) => {
                let narrowed = state.refuse_sessions(&named, now);
                if !narrowed {
                    let dropped = u64::try_from(state.settle()).unwrap_or(u64::MAX);
                    state.counters.refused = state.counters.refused.saturating_add(dropped);
                }
                state.attempt = 0;
                drop(state);
                tracing::warn!(
                    target: "jaunt::agent",
                    sessions = named.len(),
                    narrowed,
                    "the control plane refused audit events of sessions it does not know for this node; their events were dropped and the rest is sent again"
                );
            }
            Sent::Answer(Err(ApiError::Status {
                status: 404 | 405, ..
            })) => {
                let first = !state.unsupported;
                state.unsupported = true;
                state.probe_now = false;
                let limits = &self.inner.limits;
                state.probe_wait = if first {
                    limits.first_probe
                } else {
                    state.probe_wait.saturating_mul(2).min(limits.max_probe)
                };
                state.probe_at = Some(later(now, state.probe_wait));
                state.attempt = 0;
                state.retry_at = None;
                state.lose_everything(now);
                drop(state);
                if first {
                    tracing::warn!(
                        target: "jaunt::agent",
                        "the control plane does not take audit events of service sessions; they are counted per session and the route is tried again at every connection and after 5 seconds, then less often up to every 5 minutes"
                    );
                }
            }
            Sent::Answer(Err(ApiError::Status {
                status: status @ (400 | 413 | 422),
                ..
            })) => {
                let dropped = u64::try_from(state.settle()).unwrap_or(u64::MAX);
                let reported: u64 = batch.dropped.iter().map(|report| report.count).sum();
                state.counters.refused = state.counters.refused.saturating_add(dropped);
                state.counters.unreported = state.counters.unreported.saturating_add(reported);
                state.attempt = 0;
                drop(state);
                tracing::warn!(
                    target: "jaunt::agent",
                    status,
                    events,
                    reports = batch.dropped.len(),
                    "the control plane refused a batch of audit events; it was dropped and is not sent again"
                );
            }
            Sent::Answer(Err(ApiError::Status {
                status: 429,
                retry_after: Some(after),
                ..
            })) => {
                let wait = after.clamp(self.inner.limits.first_retry, MAX_RETRY_AFTER);
                state.retry_at = Some(later(now, wait));
            }
            Sent::Answer(Err(error)) => {
                let wait = self.backoff(&mut state);
                state.retry_at = Some(later(now, wait));
                state.counters.failures = state.counters.failures.saturating_add(1);
                drop(state);
                self.log_failure(Some(&error), now, wait);
            }
            Sent::TimedOut => {
                let wait = self.backoff(&mut state);
                state.retry_at = Some(later(now, wait));
                state.counters.failures = state.counters.failures.saturating_add(1);
                drop(state);
                self.log_failure(None, now, wait);
            }
        }
    }

    fn log_failure(&self, error: Option<&ApiError>, now: SystemTime, wait: Duration) {
        let tick = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        if let Some(suppressed) = self.inner.failures.admit(tick) {
            match error {
                Some(error) => tracing::warn!(
                    target: "jaunt::agent",
                    error = %error,
                    retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    suppressed,
                    "sending audit events to the control plane failed; the batch is kept and sent again"
                ),
                None => tracing::warn!(
                    target: "jaunt::agent",
                    retry_in_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX),
                    suppressed,
                    "sending audit events to the control plane timed out; the batch is kept and sent again"
                ),
            }
        }
    }
}

#[derive(Clone)]
pub struct SessionEvents {
    sink: EventSink,
    session_id: Arc<str>,
}

impl fmt::Debug for SessionEvents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionEvents")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl SessionEvents {
    pub fn emit(&self, event: SessionEvent) {
        self.sink.emit(&self.session_id, event);
    }
}

pub async fn follow_connections(
    mut events: broadcast::Receiver<ClientEvent>,
    sink: EventSink,
    stop: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            () = stop.cancelled() => return,
            event = events.recv() => event,
        };
        match event {
            Ok(ClientEvent::Connected) | Err(broadcast::error::RecvError::Lagged(_)) => {
                sink.reconnected();
            }
            Ok(ClientEvent::Disconnected { .. } | ClientEvent::ConnectFailed(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}
