use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) const INITIAL_INTERVAL_SECS: i64 = 5;
const INTERVAL_STEP_SECS: i64 = 5;
const MAX_INTERVAL_SECS: i64 = 300;

struct Entry {
    last_at: i64,
    interval_secs: i64,
    expires_at: i64,
}

pub(crate) struct PollTracker {
    capacity: usize,
    entries: Mutex<HashMap<String, Entry>>,
}

impl PollTracker {
    pub(crate) fn new(capacity: usize) -> PollTracker {
        PollTracker {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn admit(&self, login_id: &str, now: i64, expires_at: i64) -> bool {
        let mut entries = self.lock();
        if let Some(entry) = entries.get_mut(login_id) {
            let due = now.saturating_sub(entry.last_at) >= entry.interval_secs;
            entry.last_at = now;
            if !due {
                entry.interval_secs = entry
                    .interval_secs
                    .saturating_add(INTERVAL_STEP_SECS)
                    .min(MAX_INTERVAL_SECS);
            }
            return due;
        }
        if entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.expires_at > now);
        }
        if entries.len() >= self.capacity {
            return false;
        }
        entries.insert(
            login_id.to_owned(),
            Entry {
                last_at: now,
                interval_secs: INITIAL_INTERVAL_SECS,
                expires_at,
            },
        );
        true
    }

    pub(crate) fn forget(&self, login_id: &str) {
        self.lock().remove(login_id);
    }

    pub(crate) fn sweep(&self, now: i64) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        before - entries.len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::PollTracker;

    #[test]
    fn the_first_poll_is_free_and_a_poll_after_the_interval_is_accepted() {
        let tracker = PollTracker::new(4);

        assert!(tracker.admit("a", 100, 400));
        assert!(tracker.admit("a", 105, 400));
        assert!(tracker.admit("a", 110, 400));
    }

    #[test]
    fn polling_early_is_refused_and_every_refusal_lengthens_the_interval_by_five() {
        let tracker = PollTracker::new(4);
        assert!(tracker.admit("a", 100, 400));

        assert!(!tracker.admit("a", 104, 400));
        assert!(!tracker.admit("a", 113, 400));
        assert!(!tracker.admit("a", 127, 400));
        assert!(tracker.admit("a", 147, 400));
        assert!(!tracker.admit("a", 151, 400));
    }

    #[test]
    fn the_interval_never_grows_past_the_request_lifetime() {
        let tracker = PollTracker::new(4);
        assert!(tracker.admit("a", 0, 400));
        for second in 1..100 {
            assert!(!tracker.admit("a", second, 400));
        }

        assert!(tracker.admit("a", 99 + 300, 400));
    }

    #[test]
    fn requests_are_tracked_separately_and_can_be_forgotten() {
        let tracker = PollTracker::new(4);
        assert!(tracker.admit("a", 100, 400));
        assert!(tracker.admit("b", 101, 400));
        assert!(!tracker.admit("a", 102, 400));

        tracker.forget("a");

        assert!(tracker.admit("a", 102, 400));
    }

    #[test]
    fn a_full_tracker_sweeps_expired_entries_and_otherwise_refuses_new_requests() {
        let tracker = PollTracker::new(2);
        assert!(tracker.admit("a", 0, 10));
        assert!(tracker.admit("b", 0, 100));

        assert!(!tracker.admit("c", 5, 100));
        assert!(tracker.admit("c", 10, 100));
        assert_eq!(tracker.len(), 2);
        assert_eq!(tracker.sweep(100), 2);
        assert_eq!(tracker.len(), 0);
    }
}
