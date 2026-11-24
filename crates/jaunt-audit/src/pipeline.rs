use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout_at};

use crate::clock::Clock;
use crate::event::AuditEvent;
use crate::limiter::IntervalCounter;
use crate::sink::AuditSink;
use crate::spec::Class;

pub const DEFAULT_QUEUE: usize = 1024;
pub const MAX_QUEUE: usize = 1_000_000;
pub const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_millis(100);

const BATCH_MAX: usize = 128;
const WRITE_ATTEMPTS: u32 = 3;
const NOISY_QUEUE_DIVISOR: usize = 4;
const REPORT_INTERVAL_MS: i64 = 60_000;
const LOG_TARGET: &str = "jaunt::daemon";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneSnapshot {
    pub sink: &'static str,
    pub accepted: u64,
    pub written: u64,
    pub dropped_full: u64,
    pub dropped_noisy: u64,
    pub lost_after_retries: u64,
    pub unwritten: u64,
}

impl LaneSnapshot {
    pub fn lost_total(&self) -> u64 {
        self.dropped_full + self.dropped_noisy + self.lost_after_retries + self.unwritten
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    pub timed_out: bool,
    pub lanes: Vec<LaneSnapshot>,
    pub dropped_after_close: u64,
}

impl ShutdownReport {
    pub fn lost_total(&self) -> u64 {
        self.lanes.iter().map(LaneSnapshot::lost_total).sum::<u64>() + self.dropped_after_close
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the audit pipeline is shut down")]
pub struct PipelineClosed;

struct LaneStats {
    sink: &'static str,
    accepted: AtomicU64,
    written: AtomicU64,
    lost: AtomicU64,
    full: IntervalCounter,
    noisy_full: IntervalCounter,
    failed: IntervalCounter,
}

impl LaneStats {
    fn new(sink: &'static str) -> LaneStats {
        LaneStats {
            sink,
            accepted: AtomicU64::new(0),
            written: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            full: IntervalCounter::new(REPORT_INTERVAL_MS),
            noisy_full: IntervalCounter::new(REPORT_INTERVAL_MS),
            failed: IntervalCounter::new(REPORT_INTERVAL_MS),
        }
    }

    fn snapshot(&self) -> LaneSnapshot {
        let accepted = self.accepted.load(Ordering::Relaxed);
        let written = self.written.load(Ordering::Relaxed);
        let lost = self.lost.load(Ordering::Relaxed);
        LaneSnapshot {
            sink: self.sink,
            accepted,
            written,
            dropped_full: self.full.total(),
            dropped_noisy: self.noisy_full.total(),
            lost_after_retries: lost,
            unwritten: accepted.saturating_sub(written.saturating_add(lost)),
        }
    }
}

struct Lane {
    critical: mpsc::Sender<Arc<AuditEvent>>,
    noisy: mpsc::Sender<Arc<AuditEvent>>,
    stats: Arc<LaneStats>,
}

struct Inner {
    clock: Arc<dyn Clock>,
    queue: usize,
    retry_backoff: Duration,
    lanes: RwLock<Option<Vec<Lane>>>,
    stats: Mutex<Vec<Arc<LaneStats>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    closed_drops: AtomicU64,
}

#[derive(Clone)]
pub struct Pipeline {
    inner: Arc<Inner>,
}

impl Pipeline {
    pub fn new(clock: Arc<dyn Clock>, queue: usize) -> Pipeline {
        Pipeline::tuned(clock, queue, DEFAULT_RETRY_BACKOFF)
    }

    pub fn tuned(clock: Arc<dyn Clock>, queue: usize, retry_backoff: Duration) -> Pipeline {
        Pipeline {
            inner: Arc::new(Inner {
                clock,
                queue: queue.clamp(1, MAX_QUEUE),
                retry_backoff,
                lanes: RwLock::new(Some(Vec::new())),
                stats: Mutex::new(Vec::new()),
                tasks: Mutex::new(Vec::new()),
                closed_drops: AtomicU64::new(0),
            }),
        }
    }

    pub fn add_sink<S: AuditSink>(&self, sink: S) -> Result<(), PipelineClosed> {
        let noisy_queue = (self.inner.queue / NOISY_QUEUE_DIVISOR).max(1);
        let (critical_tx, critical_rx) = mpsc::channel(self.inner.queue);
        let (noisy_tx, noisy_rx) = mpsc::channel(noisy_queue);
        let stats = Arc::new(LaneStats::new(sink.name()));
        {
            let mut lanes = self
                .inner
                .lanes
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let lanes = lanes.as_mut().ok_or(PipelineClosed)?;
            lanes.push(Lane {
                critical: critical_tx,
                noisy: noisy_tx,
                stats: Arc::clone(&stats),
            });
        }
        self.inner
            .stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::clone(&stats));
        let task = tokio::spawn(run_lane(
            sink,
            Receivers {
                critical: critical_rx,
                noisy: noisy_rx,
            },
            stats,
            Arc::clone(&self.inner.clock),
            self.inner.retry_backoff,
        ));
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(task);
        Ok(())
    }

    pub fn submit(&self, event: Arc<AuditEvent>) {
        let lanes = self
            .inner
            .lanes
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(lanes) = lanes.as_ref() else {
            self.inner.closed_drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let class = event.kind().class();
        for lane in lanes {
            let (sender, counter, message) = match class {
                Class::Critical => (
                    &lane.critical,
                    &lane.stats.full,
                    "the audit queue is full, the newest events were dropped",
                ),
                Class::Noisy => (
                    &lane.noisy,
                    &lane.stats.noisy_full,
                    "the noisy audit queue is full, the newest noisy events were dropped",
                ),
            };
            match sender.try_send(Arc::clone(&event)) {
                Ok(()) => {
                    lane.stats.accepted.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(_)) => {
                    let now = self.inner.clock.now().millis();
                    if let Some(count) = counter.record(now) {
                        let snapshot = lane.stats.snapshot();
                        tracing::warn!(
                            target: LOG_TARGET,
                            sink = lane.stats.sink,
                            dropped = count,
                            dropped_critical_total = snapshot.dropped_full,
                            dropped_noisy_total = snapshot.dropped_noisy,
                            lost_after_retries = snapshot.lost_after_retries,
                            "{message}"
                        );
                    }
                }
                Err(TrySendError::Closed(_)) => {
                    lane.stats.lost.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn dropped_after_close(&self) -> u64 {
        self.inner.closed_drops.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> Vec<LaneSnapshot> {
        self.inner
            .stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|stats| stats.snapshot())
            .collect()
    }

    pub async fn shutdown(&self, deadline: Duration) -> ShutdownReport {
        let closed = self
            .inner
            .lanes
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(closed);
        let tasks = std::mem::take(
            &mut *self
                .inner
                .tasks
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let until = Instant::now() + deadline;
        let mut timed_out = false;
        for mut task in tasks {
            if timeout_at(until, &mut task).await.is_err() {
                task.abort();
                timed_out = true;
            }
        }
        let report = ShutdownReport {
            timed_out,
            lanes: self.snapshot(),
            dropped_after_close: self.inner.closed_drops.load(Ordering::Relaxed),
        };
        if timed_out {
            tracing::error!(
                target: LOG_TARGET,
                lost = report.lost_total(),
                "the audit queues were not flushed before the shutdown deadline"
            );
        }
        report
    }
}

struct Receivers {
    critical: mpsc::Receiver<Arc<AuditEvent>>,
    noisy: mpsc::Receiver<Arc<AuditEvent>>,
}

fn drain(receiver: &mut mpsc::Receiver<Arc<AuditEvent>>, batch: &mut Vec<Arc<AuditEvent>>) {
    while batch.len() < BATCH_MAX {
        match receiver.try_recv() {
            Ok(event) => batch.push(event),
            Err(_) => break,
        }
    }
}

async fn run_lane<S: AuditSink>(
    sink: S,
    mut receivers: Receivers,
    stats: Arc<LaneStats>,
    clock: Arc<dyn Clock>,
    retry_backoff: Duration,
) {
    let mut batch: Vec<Arc<AuditEvent>> = Vec::with_capacity(BATCH_MAX);
    loop {
        let first = tokio::select! {
            biased;
            Some(event) = receivers.critical.recv() => event,
            Some(event) = receivers.noisy.recv() => event,
            else => break,
        };
        batch.push(first);
        drain(&mut receivers.critical, &mut batch);
        drain(&mut receivers.noisy, &mut batch);
        write_batch(&sink, &batch, &stats, clock.as_ref(), retry_backoff).await;
        batch.clear();
    }
}

async fn write_batch<S: AuditSink>(
    sink: &S,
    batch: &[Arc<AuditEvent>],
    stats: &LaneStats,
    clock: &dyn Clock,
    retry_backoff: Duration,
) {
    let count = u64::try_from(batch.len()).unwrap_or(u64::MAX);
    for attempt in 1..=WRITE_ATTEMPTS {
        match sink.write(batch).await {
            Ok(()) => {
                stats.written.fetch_add(count, Ordering::Relaxed);
                return;
            }
            Err(error) if attempt == WRITE_ATTEMPTS => {
                stats.lost.fetch_add(count, Ordering::Relaxed);
                if let Some(batches) = stats.failed.record(clock.now().millis()) {
                    tracing::error!(
                        target: LOG_TARGET,
                        sink = stats.sink,
                        failed_batches = batches,
                        lost_after_retries = stats.lost.load(Ordering::Relaxed),
                        error = %error,
                        "an audit sink failed and its events were lost"
                    );
                }
            }
            Err(_) => sleep(retry_backoff * attempt).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use tokio::sync::{Notify, Semaphore};

    use super::{LaneSnapshot, Pipeline};
    use crate::clock::ManualClock;
    use crate::event::{AuditEvent, RawValue};
    use crate::sink::{AuditSink, MemorySink, SinkError};
    use crate::spec::EventType;
    use crate::time::Timestamp;

    fn event_of(kind: EventType, index: usize) -> Arc<AuditEvent> {
        let (event, _) = AuditEvent::from_raw(
            kind,
            &[("login_id", RawValue::Text(format!("l-{index}")))],
            format!("id-{index:04}"),
            Timestamp::from_millis(1_700_000_000_000).unwrap(),
        );
        Arc::new(event)
    }

    fn event(index: usize) -> Arc<AuditEvent> {
        event_of(EventType::LoginStarted, index)
    }

    fn noisy(index: usize) -> Arc<AuditEvent> {
        event_of(EventType::GateConnect, index)
    }

    fn pipeline(queue: usize) -> Pipeline {
        Pipeline::new(Arc::new(ManualClock::new(1_700_000_000_000)), queue)
    }

    struct GatedSink {
        entered: Arc<Notify>,
        release: Arc<Semaphore>,
        inner: MemorySink,
    }

    impl AuditSink for GatedSink {
        fn name(&self) -> &'static str {
            "gated"
        }

        async fn write(&self, batch: &[Arc<AuditEvent>]) -> Result<(), SinkError> {
            self.entered.notify_one();
            let permit = self.release.acquire().await.map_err(|_| SinkError::Task)?;
            permit.forget();
            self.inner.write(batch).await
        }
    }

    struct FailingSink {
        attempts: Arc<AtomicU32>,
        fail_first: u32,
        inner: MemorySink,
    }

    impl AuditSink for FailingSink {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn write(&self, batch: &[Arc<AuditEvent>]) -> Result<(), SinkError> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt <= self.fail_first {
                return Err(SinkError::Task);
            }
            self.inner.write(batch).await
        }
    }

    fn ids(sink: &MemorySink) -> Vec<String> {
        sink.events()
            .iter()
            .map(|event| event.id().to_owned())
            .collect()
    }

    fn gated(entered: &Arc<Notify>, release: &Arc<Semaphore>, inner: &MemorySink) -> GatedSink {
        GatedSink {
            entered: Arc::clone(entered),
            release: Arc::clone(release),
            inner: inner.clone(),
        }
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_newest_events_counts_them_and_never_blocks() {
        let pipeline = pipeline(3);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let memory = MemorySink::new();
        pipeline
            .add_sink(gated(&entered, &release, &memory))
            .unwrap();
        pipeline.submit(event(0));
        entered.notified().await;

        for index in 1..=7 {
            pipeline.submit(event(index));
        }
        release.add_permits(100);
        let report = pipeline.shutdown(Duration::from_secs(5)).await;

        assert!(!report.timed_out);
        assert_eq!(ids(&memory), ["id-0000", "id-0001", "id-0002", "id-0003"]);
        assert_eq!(
            report.lanes,
            [LaneSnapshot {
                sink: "gated",
                accepted: 4,
                written: 4,
                dropped_full: 4,
                dropped_noisy: 0,
                lost_after_retries: 0,
                unwritten: 0,
            }]
        );
    }

    #[tokio::test]
    async fn a_flood_of_noisy_events_never_displaces_a_critical_event() {
        let pipeline = pipeline(8);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let memory = MemorySink::new();
        pipeline
            .add_sink(gated(&entered, &release, &memory))
            .unwrap();
        pipeline.submit(event(0));
        entered.notified().await;

        for index in 100..300 {
            pipeline.submit(noisy(index));
        }
        for index in 1..=8 {
            pipeline.submit(event(index));
        }
        release.add_permits(100);
        let report = pipeline.shutdown(Duration::from_secs(5)).await;

        let written = ids(&memory);
        for index in 0..=8 {
            assert!(written.contains(&format!("id-{index:04}")), "{index}");
        }
        let lane = &report.lanes[0];
        assert_eq!(lane.dropped_full, 0);
        assert_eq!(lane.dropped_noisy, 198);
        assert_eq!(lane.written, 11);
        assert_eq!(written.len(), 11);
    }

    #[tokio::test]
    async fn critical_events_are_written_before_the_noisy_ones_queued_with_them() {
        let pipeline = pipeline(8);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let memory = MemorySink::new();
        pipeline
            .add_sink(gated(&entered, &release, &memory))
            .unwrap();
        pipeline.submit(event(0));
        entered.notified().await;
        pipeline.submit(noisy(100));
        pipeline.submit(event(1));
        pipeline.submit(event(2));
        release.add_permits(100);

        pipeline.shutdown(Duration::from_secs(5)).await;

        assert_eq!(ids(&memory), ["id-0000", "id-0001", "id-0002", "id-0100"]);
    }

    #[tokio::test]
    async fn a_full_first_queue_does_not_stop_the_second_sink() {
        let pipeline = pipeline(2);
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Semaphore::new(0));
        let stuck = MemorySink::new();
        let live = MemorySink::new();
        pipeline
            .add_sink(gated(&entered, &release, &stuck))
            .unwrap();
        pipeline.add_sink(live.clone()).unwrap();
        pipeline.submit(event(0));
        entered.notified().await;

        for index in 1..=10 {
            pipeline.submit(event(index));
            tokio::task::yield_now().await;
        }
        release.add_permits(100);
        let report = pipeline.shutdown(Duration::from_secs(5)).await;

        assert_eq!(live.events().len(), 11);
        assert_eq!(report.lanes[1].dropped_full, 0);
        assert!(report.lanes[0].dropped_full > 0);
        assert_eq!(stuck.events().len(), 3);
    }

    #[tokio::test]
    async fn shutdown_flushes_everything_queued_and_later_events_are_counted_as_dropped() {
        let pipeline = pipeline(64);
        let memory = MemorySink::new();
        pipeline.add_sink(memory.clone()).unwrap();
        for index in 0..50 {
            pipeline.submit(event(index));
        }

        let report = pipeline.shutdown(Duration::from_secs(5)).await;
        pipeline.submit(event(99));

        assert!(!report.timed_out);
        assert_eq!(report.lost_total(), 0);
        assert_eq!(memory.events().len(), 50);
        assert_eq!(pipeline.snapshot()[0].written, 50);
        let again = pipeline.shutdown(Duration::from_secs(1)).await;
        assert_eq!(again.dropped_after_close, 1);
        assert_eq!(memory.events().len(), 50);
        assert!(pipeline.add_sink(MemorySink::new()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn a_failing_sink_never_stops_the_other_one_and_its_loss_is_counted() {
        let pipeline = pipeline(16);
        let good = MemorySink::new();
        let attempts = Arc::new(AtomicU32::new(0));
        pipeline
            .add_sink(FailingSink {
                attempts: Arc::clone(&attempts),
                fail_first: u32::MAX,
                inner: MemorySink::new(),
            })
            .unwrap();
        pipeline.add_sink(good.clone()).unwrap();

        for index in 0..5 {
            pipeline.submit(event(index));
        }
        let report = pipeline.shutdown(Duration::from_secs(10)).await;

        assert!(!report.timed_out);
        assert_eq!(good.events().len(), 5);
        let failing = &report.lanes[0];
        assert_eq!(failing.written, 0);
        assert_eq!(failing.lost_after_retries, 5);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_transient_failure_is_retried_on_the_injected_backoff_and_nothing_is_lost() {
        let clock = Arc::new(ManualClock::new(1_700_000_000_000));
        let pipeline = Pipeline::tuned(clock, 16, Duration::from_secs(3600));
        let memory = MemorySink::new();
        pipeline
            .add_sink(FailingSink {
                attempts: Arc::new(AtomicU32::new(0)),
                fail_first: 2,
                inner: memory.clone(),
            })
            .unwrap();

        pipeline.submit(event(0));
        let started = tokio::time::Instant::now();
        let report = pipeline.shutdown(Duration::from_secs(7 * 3600)).await;

        assert!(!report.timed_out);
        assert_eq!(ids(&memory), ["id-0000"]);
        assert_eq!(report.lanes[0].lost_after_retries, 0);
        assert!(started.elapsed() >= Duration::from_secs(3 * 3600));
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_sink_cannot_hold_the_shutdown_past_its_deadline_and_the_queue_counts_as_lost()
    {
        let pipeline = pipeline(4);
        let entered = Arc::new(Notify::new());
        pipeline
            .add_sink(GatedSink {
                entered: Arc::clone(&entered),
                release: Arc::new(Semaphore::new(0)),
                inner: MemorySink::new(),
            })
            .unwrap();
        pipeline.submit(event(0));
        entered.notified().await;
        pipeline.submit(event(1));
        pipeline.submit(event(2));

        let report = pipeline.shutdown(Duration::from_millis(50)).await;

        assert!(report.timed_out);
        assert_eq!(report.lanes[0].written, 0);
        assert_eq!(report.lanes[0].unwritten, 3);
        assert_eq!(report.lost_total(), 3);
    }
}
