use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_tunnel::{Backoff, BackoffPolicy, MAX_TIMER};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::{MirrorError, StateMirror};
use crate::clock::Clock;
use crate::trust::{Sampler, random_sampler};

pub const PERSIST_BACKOFF: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_secs(1),
    max: Duration::from_secs(60),
    reset_after: MAX_TIMER,
};

pub const PERSIST_LOG_EVERY: Duration = Duration::from_secs(60);

pub struct PersistTiming {
    pub backoff: BackoffPolicy,
    pub log_every: Duration,
    pub sample: Sampler,
}

impl Default for PersistTiming {
    fn default() -> Self {
        Self {
            backoff: PERSIST_BACKOFF,
            log_every: PERSIST_LOG_EVERY,
            sample: random_sampler(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Stored,
    Stopped,
    Foreign,
}

pub struct Persister {
    mirror: Arc<dyn StateMirror>,
    dir: PathBuf,
    clock: Arc<dyn Clock>,
    timing: PersistTiming,
    last_logged: Option<SystemTime>,
    suppressed: u64,
    failing: bool,
    serving: bool,
}

impl Persister {
    pub fn new(
        mirror: Arc<dyn StateMirror>,
        dir: PathBuf,
        clock: Arc<dyn Clock>,
        timing: PersistTiming,
    ) -> Self {
        Self {
            mirror,
            dir,
            clock,
            timing,
            last_logged: None,
            suppressed: 0,
            failing: false,
            serving: false,
        }
    }

    pub async fn store(&mut self, stop: &CancellationToken) -> Outcome {
        let mut backoff = Backoff::new(self.timing.backoff);
        loop {
            match self.mirror.persist(&self.dir).await {
                Ok(()) => {
                    if self.failing {
                        tracing::info!(
                            target: "jaunt::agent",
                            "the agent state is stored in the Secret again"
                        );
                    }
                    self.failing = false;
                    return Outcome::Stored;
                }
                Err(MirrorError::Foreign) => {
                    foreign_logged();
                    return Outcome::Foreign;
                }
                Err(error) => {
                    let sample = (self.timing.sample)();
                    let delay = backoff.next_delay(Duration::ZERO, 0.5 + 0.5 * sample);
                    self.report(&error, delay);
                    let now = self.clock.now();
                    let wake = now.checked_add(delay).unwrap_or(now);
                    tokio::select! {
                        biased;
                        () = stop.cancelled() => return Outcome::Stopped,
                        () = self.clock.sleep_until(wake) => {}
                    }
                }
            }
        }
    }

    pub async fn last_attempt(&mut self) -> Result<(), MirrorError> {
        match self.mirror.persist(&self.dir).await {
            Ok(()) => Ok(()),
            Err(MirrorError::Foreign) => {
                foreign_logged();
                Err(MirrorError::Foreign)
            }
            Err(error) => {
                tracing::error!(
                    target: "jaunt::agent",
                    event = "agent.state.persist_failed",
                    error = %error,
                    "the last attempt to store the agent state in the Secret before stopping failed"
                );
                Err(error)
            }
        }
    }

    pub async fn follow(
        mut self,
        mut changes: watch::Receiver<u64>,
        stop: CancellationToken,
        stop_agent: CancellationToken,
    ) -> Outcome {
        self.serving = true;
        let mut persisted = 0;
        loop {
            let current = *changes.borrow_and_update();
            if current == persisted {
                tokio::select! {
                    () = stop.cancelled() => break,
                    changed = changes.changed() => {
                        if changed.is_err() {
                            break;
                        }
                    }
                }
                continue;
            }
            match self.store(&stop).await {
                Outcome::Stored => persisted = current,
                Outcome::Stopped => break,
                Outcome::Foreign => {
                    stop_agent.cancel();
                    return Outcome::Foreign;
                }
            }
        }
        if *changes.borrow() == persisted {
            return Outcome::Stopped;
        }
        match self.last_attempt().await {
            Ok(()) => Outcome::Stored,
            Err(MirrorError::Foreign) => Outcome::Foreign,
            Err(_) => Outcome::Stopped,
        }
    }

    fn report(&mut self, error: &MirrorError, delay: Duration) {
        self.failing = true;
        let now = self.clock.now();
        let due = self.last_logged.is_none_or(|at| {
            now.duration_since(at)
                .map_or(true, |gap| gap >= self.timing.log_every)
        });
        let retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        if due && self.serving {
            tracing::error!(
                target: "jaunt::agent",
                event = "agent.state.persist_failed",
                error = %error,
                retry_in_ms,
                suppressed = self.suppressed,
                "storing the agent state in the Secret failed; the agent keeps running and retries"
            );
        } else if due {
            tracing::error!(
                target: "jaunt::agent",
                event = "agent.state.persist_failed",
                error = %error,
                retry_in_ms,
                suppressed = self.suppressed,
                "storing the new enrollment in the Secret failed; the agent does not serve until it is stored and retries"
            );
        }
        if due {
            self.last_logged = Some(now);
            self.suppressed = 0;
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            tracing::debug!(
                target: "jaunt::agent",
                error = %error,
                "storing the agent state in the Secret failed again"
            );
        }
    }
}

fn foreign_logged() {
    tracing::error!(
        target: "jaunt::agent",
        event = "agent.state.foreign_enrollment",
        "the Secret now holds a different enrollment than this agent (another replica or an older pod wrote it); the agent stops instead of overwriting it; run exactly one replica with the Recreate strategy"
    );
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use jaunt_tunnel::BoxFuture;
    use tokio_util::sync::CancellationToken;

    use super::{Outcome, PERSIST_BACKOFF, PersistTiming, Persister};
    use crate::clock::{Clock, at_unix_secs};
    use crate::kube_state::client::ApiError;
    use crate::kube_state::{MirrorError, Restored, StateMirror};
    use crate::state::StateChanges;
    use crate::testkit::{LogCapture, ManualClock, eventually, soon};

    const START: i64 = 1_900_000_000;

    #[derive(Default)]
    struct Scripted {
        failures: Mutex<VecDeque<MirrorError>>,
        calls: AtomicUsize,
        change_during_first: Mutex<Option<StateChanges>>,
    }

    impl Scripted {
        fn failing(&self, error: MirrorError) {
            self.failures.lock().unwrap().push_back(error);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl StateMirror for Scripted {
        fn restore<'a>(&'a self, _dir: &'a Path) -> BoxFuture<'a, Result<Restored, MirrorError>> {
            Box::pin(async { Ok(Restored::Empty) })
        }

        fn probe<'a>(&'a self) -> BoxFuture<'a, Result<(), MirrorError>> {
            Box::pin(async { Ok(()) })
        }

        fn persist<'a>(&'a self, _dir: &'a Path) -> BoxFuture<'a, Result<(), MirrorError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(changes) = self.change_during_first.lock().unwrap().take() {
                changes.notify();
            }
            let next = self.failures.lock().unwrap().pop_front();
            Box::pin(async move { next.map_or(Ok(()), Err) })
        }
    }

    fn unavailable() -> MirrorError {
        MirrorError::Api(ApiError::Status { status: 503 })
    }

    fn persister(mirror: &Arc<Scripted>, clock: &Arc<ManualClock>, sample: f64) -> Persister {
        Persister::new(
            mirror.clone(),
            PathBuf::from("/unused"),
            clock.clone(),
            PersistTiming {
                backoff: PERSIST_BACKOFF,
                log_every: Duration::from_secs(60),
                sample: Arc::new(move || sample),
            },
        )
    }

    fn errors(logs: &LogCapture) -> usize {
        logs.text()
            .lines()
            .filter(|line| {
                line.contains("\"level\":\"ERROR\"") && line.contains("agent.state.persist_failed")
            })
            .count()
    }

    #[tokio::test]
    async fn failures_back_off_from_one_second_to_a_minute_and_are_logged_once_a_minute() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let clock = ManualClock::new(at_unix_secs(START));
        let mirror = Arc::new(Scripted::default());
        for _ in 0..9 {
            mirror.failing(unavailable());
        }
        let mut persister = persister(&mirror, &clock, 1.0);
        let stop = CancellationToken::new();
        let storing = tokio::spawn(async move { persister.store(&stop).await });
        let mut at = START;
        for delay in [1, 2, 4, 8, 16, 32, 60, 60, 60] {
            at += delay;
            clock.wait_for_sleeper(at_unix_secs(at)).await;
            clock.set(at_unix_secs(at));
        }
        assert_eq!(
            soon("the stored state", storing).await.unwrap(),
            Outcome::Stored
        );
        assert_eq!(mirror.calls(), 10);
        assert_eq!(
            errors(&logs),
            4,
            "failures at 0, 63, 123 and 183 s are logged"
        );
        assert!(
            logs.text()
                .contains("the agent state is stored in the Secret again")
        );

        let mirror = Arc::new(Scripted::default());
        mirror.failing(unavailable());
        let mut persister = super::Persister::new(
            mirror.clone(),
            PathBuf::from("/unused"),
            clock.clone(),
            PersistTiming {
                sample: Arc::new(|| 0.0),
                ..PersistTiming::default()
            },
        );
        let stop = CancellationToken::new();
        let halted = stop.clone();
        let storing = tokio::spawn(async move { persister.store(&halted).await });
        clock
            .wait_for_sleeper(clock.now() + Duration::from_millis(500))
            .await;
        stop.cancel();
        assert_eq!(soon("the stop", storing).await.unwrap(), Outcome::Stopped);
    }

    #[tokio::test]
    async fn every_change_is_stored_and_a_pending_one_gets_a_last_attempt_at_shutdown() {
        let clock = ManualClock::new(at_unix_secs(START));
        let mirror = Arc::new(Scripted::default());
        let (changes, receiver) = StateChanges::channel();
        let stop = CancellationToken::new();
        let agent = CancellationToken::new();
        let following = tokio::spawn(persister(&mirror, &clock, 1.0).follow(
            receiver,
            stop.clone(),
            agent.clone(),
        ));
        changes.notify();
        eventually("the first change to be stored", || mirror.calls() == 1).await;
        mirror.failing(unavailable());
        changes.notify();
        clock.wait_for_sleeper(at_unix_secs(START + 1)).await;
        assert_eq!(mirror.calls(), 2);
        stop.cancel();
        assert_eq!(
            soon("the persister", following).await.unwrap(),
            Outcome::Stored
        );
        assert_eq!(mirror.calls(), 3);
        assert!(!agent.is_cancelled());

        let mirror = Arc::new(Scripted::default());
        let (changes, receiver) = StateChanges::channel();
        let stop = CancellationToken::new();
        let following = tokio::spawn(persister(&mirror, &clock, 1.0).follow(
            receiver,
            stop.clone(),
            CancellationToken::new(),
        ));
        changes.notify();
        eventually("the change to be stored", || mirror.calls() == 1).await;
        stop.cancel();
        assert_eq!(
            soon("the persister", following).await.unwrap(),
            Outcome::Stopped
        );
        assert_eq!(mirror.calls(), 1, "nothing was left to store");
    }

    #[tokio::test]
    async fn a_change_made_while_a_write_runs_is_written_again() {
        let clock = ManualClock::new(at_unix_secs(START));
        let mirror = Arc::new(Scripted::default());
        let (changes, receiver) = StateChanges::channel();
        *mirror.change_during_first.lock().unwrap() = Some(changes.clone());
        let stop = CancellationToken::new();
        let following = tokio::spawn(persister(&mirror, &clock, 1.0).follow(
            receiver,
            stop.clone(),
            CancellationToken::new(),
        ));
        changes.notify();
        eventually("the second write", || mirror.calls() == 2).await;
        stop.cancel();
        assert_eq!(
            soon("the persister", following).await.unwrap(),
            Outcome::Stopped
        );
        assert_eq!(mirror.calls(), 2);
    }

    #[tokio::test]
    async fn a_different_enrollment_in_the_secret_stops_the_agent_without_retrying() {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let clock = ManualClock::new(at_unix_secs(START));
        let mirror = Arc::new(Scripted::default());
        mirror.failing(MirrorError::Foreign);
        let (changes, receiver) = StateChanges::channel();
        let agent = CancellationToken::new();
        let following = tokio::spawn(persister(&mirror, &clock, 1.0).follow(
            receiver,
            CancellationToken::new(),
            agent.clone(),
        ));
        changes.notify();
        assert_eq!(
            soon("the persister", following).await.unwrap(),
            Outcome::Foreign
        );
        assert!(agent.is_cancelled());
        assert_eq!(mirror.calls(), 1);
        assert!(clock.sleepers().is_empty());
        assert!(logs.text().contains("agent.state.foreign_enrollment"));
    }
}
