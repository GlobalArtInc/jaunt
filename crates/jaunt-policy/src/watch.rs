use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::handle::{PolicyHandle, ReloadOutcome};

pub const DEFAULT_WATCH_INTERVAL: Duration = Duration::from_secs(5);
pub const MIN_WATCH_INTERVAL: Duration = Duration::from_millis(10);

const THREAD_NAME: &str = "jaunt-policy-watch";
const RELOAD_PANICKED: &str = "policy reload panicked";

#[derive(Debug)]
pub struct Watcher {
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    pub fn stop(self) {
        drop(self);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            drop(thread.join());
        }
    }
}

#[derive(PartialEq, Eq)]
struct Rejection {
    input_hash: Option<String>,
    errors: Vec<String>,
}

fn rejection(outcome: &ReloadOutcome) -> Rejection {
    Rejection {
        input_hash: outcome.input_hash.clone(),
        errors: outcome.errors.clone(),
    }
}

fn clamp_interval(interval: Duration) -> Duration {
    interval.max(MIN_WATCH_INTERVAL)
}

fn reload_guarded(handle: &PolicyHandle, dir: &Path) -> ReloadOutcome {
    catch_unwind(AssertUnwindSafe(|| handle.reload(dir))).unwrap_or_else(|_| ReloadOutcome {
        applied: false,
        unchanged: false,
        hash: None,
        input_hash: None,
        errors: vec![RELOAD_PANICKED.to_owned()],
    })
}

fn run(
    handle: &PolicyHandle,
    dir: &Path,
    interval: Duration,
    stop: &Receiver<()>,
    notify: &dyn Fn(&ReloadOutcome),
) {
    let mut last_rejected: Option<Rejection> = None;
    let mut first = true;
    loop {
        let outcome = reload_guarded(handle, dir);
        let report = if outcome.applied {
            let recovered = last_rejected.take().is_some();
            first || recovered || !outcome.unchanged
        } else {
            let current = rejection(&outcome);
            let repeated = last_rejected.as_ref() == Some(&current);
            last_rejected = Some(current);
            first || !repeated
        };
        first = false;
        if report {
            drop(catch_unwind(AssertUnwindSafe(|| notify(&outcome))));
        }
        match stop.recv_timeout(interval) {
            Err(RecvTimeoutError::Timeout) => {}
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

pub fn watch(
    handle: PolicyHandle,
    dir: PathBuf,
    interval: Duration,
    on_outcome: impl Fn(&ReloadOutcome) + Send + 'static,
) -> Watcher {
    let interval = clamp_interval(interval);
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let callback = Arc::new(Mutex::new(on_outcome));
    let thread_callback = Arc::clone(&callback);
    let spawned = std::thread::Builder::new()
        .name(THREAD_NAME.to_owned())
        .spawn(move || {
            let notify = |outcome: &ReloadOutcome| {
                let callback = thread_callback
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                (*callback)(outcome);
            };
            run(&handle, &dir, interval, &stop_rx, &notify);
        });
    match spawned {
        Ok(thread) => Watcher {
            stop: Some(stop_tx),
            thread: Some(thread),
        },
        Err(err) => {
            let outcome = ReloadOutcome {
                applied: false,
                unchanged: false,
                hash: None,
                input_hash: None,
                errors: vec![format!("cannot start the policy watcher thread: {err}")],
            };
            let callback = callback.lock().unwrap_or_else(PoisonError::into_inner);
            drop(catch_unwind(AssertUnwindSafe(|| (*callback)(&outcome))));
            Watcher {
                stop: None,
                thread: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{MIN_WATCH_INTERVAL, clamp_interval};

    #[test]
    fn interval_is_clamped_to_the_minimum() {
        assert_eq!(clamp_interval(Duration::ZERO), MIN_WATCH_INTERVAL);
        assert_eq!(
            clamp_interval(MIN_WATCH_INTERVAL - Duration::from_millis(1)),
            MIN_WATCH_INTERVAL
        );
        assert_eq!(
            clamp_interval(Duration::from_secs(5)),
            Duration::from_secs(5)
        );
    }
}
