use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) const POLL_WINDOW_SECS: i64 = 10;
pub(crate) const POLLS_PER_WINDOW: usize = 20;
pub(crate) const ENROLL_WINDOW_SECS: i64 = 600;
pub(crate) const ENROLLS_PER_WINDOW: usize = 60;
pub(crate) const RATE_LIMITER_CAPACITY: usize = 10_000;

pub(crate) struct RateLimiter {
    capacity: usize,
    window_secs: i64,
    max_per_window: usize,
    entries: Mutex<HashMap<String, VecDeque<i64>>>,
}

impl RateLimiter {
    pub(crate) fn new(capacity: usize, window_secs: i64, max_per_window: usize) -> RateLimiter {
        RateLimiter {
            capacity,
            window_secs,
            max_per_window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn polls() -> RateLimiter {
        RateLimiter::new(RATE_LIMITER_CAPACITY, POLL_WINDOW_SECS, POLLS_PER_WINDOW)
    }

    pub(crate) fn enrollments() -> RateLimiter {
        RateLimiter::new(
            RATE_LIMITER_CAPACITY,
            ENROLL_WINDOW_SECS,
            ENROLLS_PER_WINDOW,
        )
    }

    pub(crate) fn allow(&self, key: &str, now: i64) -> bool {
        let mut entries = self.lock();
        if !entries.contains_key(key) && entries.len() >= self.capacity {
            self.prune(&mut entries, now);
            if entries.len() >= self.capacity {
                return false;
            }
        }
        let horizon = now.saturating_sub(self.window_secs);
        let attempts = entries.entry(key.to_owned()).or_default();
        while attempts.front().is_some_and(|at| *at <= horizon) {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_per_window {
            return false;
        }
        attempts.push_back(now);
        true
    }

    pub(crate) fn sweep(&self, now: i64) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        self.prune(&mut entries, now);
        before - entries.len()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn prune(&self, entries: &mut HashMap<String, VecDeque<i64>>, now: i64) {
        let horizon = now.saturating_sub(self.window_secs);
        entries.retain(|_, attempts| attempts.back().is_some_and(|at| *at > horizon));
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, VecDeque<i64>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{ENROLLS_PER_WINDOW, POLLS_PER_WINDOW, RateLimiter};

    #[test]
    fn the_twenty_first_poll_inside_ten_seconds_is_refused_and_the_window_slides() {
        let limiter = RateLimiter::polls();
        for _ in 0..POLLS_PER_WINDOW {
            assert!(limiter.allow("a", 100));
        }
        assert!(!limiter.allow("a", 100));
        assert!(!limiter.allow("a", 109));
        assert!(limiter.allow("b", 109));
        assert!(limiter.allow("a", 110));
    }

    #[test]
    fn the_sixty_first_enrollment_attempt_inside_ten_minutes_is_refused() {
        let limiter = RateLimiter::enrollments();
        for _ in 0..ENROLLS_PER_WINDOW {
            assert!(limiter.allow("a", 1000));
        }
        assert!(!limiter.allow("a", 1599));
        assert!(limiter.allow("a", 1600));
    }

    #[test]
    fn a_full_map_forgets_stale_keys_before_refusing_new_ones() {
        let limiter = RateLimiter::new(2, 10, 20);
        assert!(limiter.allow("a", 100));
        assert!(limiter.allow("b", 105));
        assert!(!limiter.allow("c", 105));
        assert!(limiter.allow("c", 110));
        assert_eq!(limiter.len(), 2);
        assert_eq!(limiter.sweep(120), 2);
        assert_eq!(limiter.len(), 0);
    }
}
