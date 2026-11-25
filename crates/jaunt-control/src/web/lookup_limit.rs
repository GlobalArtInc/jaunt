use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) const LOOKUP_FAILURES_PER_WINDOW: usize = 5;
pub(crate) const LOOKUP_WINDOW_SECS: i64 = 60;
pub(crate) const MAX_TRACKED_SESSIONS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attempt {
    at: i64,
}

#[derive(Default)]
pub(crate) struct LookupLimiter(Mutex<HashMap<String, VecDeque<i64>>>);

impl LookupLimiter {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, VecDeque<i64>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(&self, session_hash: &str, now: i64) -> Result<Attempt, i64> {
        let mut sessions = self.lock();
        sessions.retain(|_, attempts| {
            forget_old(attempts, now);
            !attempts.is_empty()
        });
        if !sessions.contains_key(session_hash) && sessions.len() >= MAX_TRACKED_SESSIONS {
            return Err(LOOKUP_WINDOW_SECS);
        }
        let attempts = sessions.entry(session_hash.to_owned()).or_default();
        if attempts.len() >= LOOKUP_FAILURES_PER_WINDOW {
            let oldest = attempts.front().copied().unwrap_or(now);
            return Err(oldest
                .saturating_add(LOOKUP_WINDOW_SECS)
                .saturating_sub(now)
                .max(1));
        }
        attempts.push_back(now);
        Ok(Attempt { at: now })
    }

    pub(crate) fn succeeded(&self, session_hash: &str, attempt: Attempt) {
        let mut sessions = self.lock();
        let Some(attempts) = sessions.get_mut(session_hash) else {
            return;
        };
        if let Some(position) = attempts.iter().rposition(|at| *at == attempt.at) {
            attempts.remove(position);
        }
        if attempts.is_empty() {
            sessions.remove(session_hash);
        }
    }
}

fn forget_old(attempts: &mut VecDeque<i64>, now: i64) {
    while attempts
        .front()
        .is_some_and(|at| at.saturating_add(LOOKUP_WINDOW_SECS) <= now)
    {
        attempts.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::{LOOKUP_WINDOW_SECS, LookupLimiter, MAX_TRACKED_SESSIONS};

    const NOW: i64 = 1_000;

    #[test]
    fn the_sixth_failure_in_a_minute_is_refused_until_the_oldest_leaves_the_window() {
        let limiter = LookupLimiter::default();
        for offset in 0..5 {
            limiter.admit("a", NOW + offset).unwrap();
        }
        assert_eq!(limiter.admit("a", NOW + 10), Err(50));
        assert!(limiter.admit("b", NOW + 10).is_ok());
        assert_eq!(limiter.admit("a", NOW + LOOKUP_WINDOW_SECS - 1), Err(1));
        assert!(limiter.admit("a", NOW + LOOKUP_WINDOW_SECS).is_ok());
    }

    #[test]
    fn successful_lookups_give_their_attempt_back() {
        let limiter = LookupLimiter::default();
        for _ in 0..20 {
            let attempt = limiter.admit("a", NOW).unwrap();
            limiter.succeeded("a", attempt);
        }
        for _ in 0..5 {
            limiter.admit("a", NOW).unwrap();
        }
        assert!(limiter.admit("a", NOW).is_err());
    }

    #[test]
    fn a_success_refunds_only_its_own_attempt_and_keeps_earlier_failures() {
        let limiter = LookupLimiter::default();
        for _ in 0..4 {
            limiter.admit("a", NOW).unwrap();
        }
        let success = limiter.admit("a", NOW + 1).unwrap();
        limiter.succeeded("a", success);
        limiter.admit("a", NOW + 2).unwrap();
        assert_eq!(limiter.admit("a", NOW + 3), Err(LOOKUP_WINDOW_SECS - 3));
    }

    #[test]
    fn a_full_table_refuses_unknown_sessions_instead_of_forgetting_failures() {
        let limiter = LookupLimiter::default();
        for index in 0..MAX_TRACKED_SESSIONS {
            limiter.admit(&format!("s-{index}"), NOW).unwrap();
        }
        assert_eq!(limiter.admit("new", NOW), Err(LOOKUP_WINDOW_SECS));
        assert!(limiter.admit("s-0", NOW).is_ok());
        assert!(limiter.admit("new", NOW + LOOKUP_WINDOW_SECS).is_ok());
    }
}
