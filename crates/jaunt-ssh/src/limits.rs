use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use crate::config::ServerProfile;

const MAX_FORWARDS: usize = 8;
const OPENS_PER_MINUTE: u32 = 60;
const WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterLimits {
    pub auth_deadline: Duration,
    pub max_auth_attempts: usize,
    pub max_forwards: usize,
    pub opens_per_minute: u32,
    pub write_stall_timeout: Option<Duration>,
}

impl Default for OuterLimits {
    fn default() -> Self {
        Self {
            auth_deadline: ServerProfile::Gate.auth_deadline(),
            max_auth_attempts: ServerProfile::Gate.max_auth_attempts(),
            max_forwards: MAX_FORWARDS,
            opens_per_minute: OPENS_PER_MINUTE,
            write_stall_timeout: Some(WRITE_STALL_TIMEOUT),
        }
    }
}

pub(crate) struct OpenRate {
    limit: usize,
    opens: VecDeque<Instant>,
}

impl OpenRate {
    pub(crate) fn new(per_minute: u32) -> Self {
        Self {
            limit: usize::try_from(per_minute).unwrap_or(usize::MAX),
            opens: VecDeque::new(),
        }
    }

    pub(crate) fn admit(&mut self, now: Instant) -> bool {
        while self
            .opens
            .front()
            .is_some_and(|opened| now.saturating_duration_since(*opened) >= RATE_WINDOW)
        {
            self.opens.pop_front();
        }
        if self.opens.len() >= self.limit {
            return false;
        }
        self.opens.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{OpenRate, OuterLimits};

    #[test]
    fn the_defaults_are_the_gate_limits_of_the_design() {
        assert_eq!(
            OuterLimits::default(),
            OuterLimits {
                auth_deadline: Duration::from_secs(30),
                max_auth_attempts: 3,
                max_forwards: 8,
                opens_per_minute: 60,
                write_stall_timeout: Some(Duration::from_secs(900)),
            }
        );
    }

    #[test]
    fn opens_are_counted_over_a_sliding_minute() {
        let start = Instant::now();
        let mut rate = OpenRate::new(2);
        assert!(rate.admit(start));
        assert!(rate.admit(start + Duration::from_secs(30)));
        assert!(!rate.admit(start + Duration::from_secs(59)));
        assert!(rate.admit(start + Duration::from_secs(60)));
        assert!(!rate.admit(start + Duration::from_secs(89)));
        assert!(rate.admit(start + Duration::from_secs(90)));
        assert_eq!(rate.opens.len(), 2);
    }

    #[test]
    fn a_zero_rate_refuses_every_open() {
        let mut rate = OpenRate::new(0);
        assert!(!rate.admit(Instant::now()));
        assert!(rate.opens.is_empty());
    }
}
