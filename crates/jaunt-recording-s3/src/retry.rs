use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use jaunt_audit::RecordingStoreError;

pub const DEFAULT_FIRST_DELAY: Duration = Duration::from_millis(250);
pub const DEFAULT_MAX_DELAY: Duration = Duration::from_secs(8);

pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;

pub trait Timer: Send + Sync {
    fn elapsed(&self) -> Duration;
    fn sleep(&self, duration: Duration) -> Sleep;
}

#[derive(Debug)]
pub struct SystemTimer {
    started: Instant,
}

impl SystemTimer {
    pub fn new() -> SystemTimer {
        SystemTimer {
            started: Instant::now(),
        }
    }
}

impl Default for SystemTimer {
    fn default() -> SystemTimer {
        SystemTimer::new()
    }
}

impl Timer for SystemTimer {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn sleep(&self, duration: Duration) -> Sleep {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub deadline: Duration,
    pub first_delay: Duration,
    pub max_delay: Duration,
}

impl RetryPolicy {
    pub fn new(deadline: Duration) -> RetryPolicy {
        RetryPolicy {
            deadline,
            first_delay: DEFAULT_FIRST_DELAY,
            max_delay: DEFAULT_MAX_DELAY,
        }
    }

    pub fn delay(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(32);
        self.first_delay
            .saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
            .min(self.max_delay)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("transient failure: {0}")]
    Transient(String),
    #[error("access denied: {0}")]
    Denied(String),
    #[error("not found: {0}")]
    Missing(String),
    #[error("the object store rejects the request for good: {0}")]
    Permanent(String),
    #[error("the object store failed a moment ago: the next attempt waits")]
    Waiting,
    #[error("an object already exists")]
    Conflict,
    #[error(transparent)]
    Local(#[from] RecordingStoreError),
}

pub async fn retrying<T, F, Fut>(
    timer: &dyn Timer,
    policy: &RetryPolicy,
    start: Duration,
    mut operation: F,
) -> Result<T, RemoteError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, RemoteError>>,
{
    let mut failures: u32 = 0;
    loop {
        match operation().await {
            Err(RemoteError::Transient(detail)) => {
                failures = failures.saturating_add(1);
                let delay = policy.delay(failures);
                let spent = timer.elapsed().saturating_sub(start);
                if spent.saturating_add(delay) > policy.deadline {
                    return Err(RemoteError::Transient(detail));
                }
                timer.sleep(delay).await;
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[derive(Default)]
    struct FakeTimer {
        now: Mutex<Duration>,
        sleeps: Mutex<Vec<Duration>>,
    }

    impl Timer for FakeTimer {
        fn elapsed(&self) -> Duration {
            *self.now.lock().unwrap()
        }

        fn sleep(&self, duration: Duration) -> Sleep {
            *self.now.lock().unwrap() += duration;
            self.sleeps.lock().unwrap().push(duration);
            Box::pin(async {})
        }
    }

    fn policy() -> RetryPolicy {
        RetryPolicy {
            deadline: Duration::from_secs(10),
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(4),
        }
    }

    #[test]
    fn the_delay_doubles_up_to_the_cap() {
        let delays: Vec<u64> = [1, 2, 3, 4, 5, 40, u32::MAX]
            .iter()
            .map(|failures| policy().delay(*failures).as_secs())
            .collect();
        assert_eq!(delays, [1, 2, 4, 4, 4, 4, 4]);
    }

    #[tokio::test]
    async fn transient_failures_are_retried_until_the_deadline_then_reported() {
        let timer = FakeTimer::default();
        let attempts = AtomicU32::new(0);
        let result: Result<(), RemoteError> = retrying(&timer, &policy(), Duration::ZERO, || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async { Err(RemoteError::Transient("down".to_owned())) }
        })
        .await;
        assert!(matches!(result, Err(RemoteError::Transient(_))));
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        assert_eq!(
            *timer.sleeps.lock().unwrap(),
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4)
            ]
        );
    }

    #[tokio::test]
    async fn a_success_after_failures_is_returned_and_the_deadline_counts_from_the_start() {
        let timer = FakeTimer::default();
        let attempts = AtomicU32::new(0);
        let result = retrying(&timer, &policy(), Duration::ZERO, || {
            let seen = attempts.fetch_add(1, Ordering::SeqCst);
            async move {
                if seen < 2 {
                    Err(RemoteError::Transient("down".to_owned()))
                } else {
                    Ok(seen)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 2);

        let late = FakeTimer::default();
        *late.now.lock().unwrap() = Duration::from_secs(100);
        let attempts = AtomicU32::new(0);
        let result: Result<(), RemoteError> =
            retrying(&late, &policy(), Duration::from_secs(95), || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async { Err(RemoteError::Transient("down".to_owned())) }
            })
            .await;
        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_failures_are_never_retried() {
        let timer = FakeTimer::default();
        for make in [
            (|| RemoteError::Denied("no".to_owned())) as fn() -> RemoteError,
            || RemoteError::Missing("bucket".to_owned()),
            || RemoteError::Permanent("501".to_owned()),
            || RemoteError::Waiting,
            || RemoteError::Conflict,
            || RemoteError::Local(RecordingStoreError::Finished),
        ] {
            let attempts = AtomicU32::new(0);
            let result: Result<(), RemoteError> =
                retrying(&timer, &policy(), Duration::ZERO, || {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    let error = make();
                    async move { Err(error) }
                })
                .await;
            assert!(result.is_err());
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
        assert!(timer.sleeps.lock().unwrap().is_empty());
    }
}
