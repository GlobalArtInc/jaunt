use serde::{Deserialize, Serialize};

pub const ATTEMPTS_PER_MINUTE: usize = 5;
pub const ATTEMPTS_PER_DAY: usize = 50;

const MINUTE_SECONDS: u64 = 60;
const DAY_SECONDS: u64 = 86_400;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Attempts(Vec<u64>);

impl Attempts {
    pub fn allows(&self, now: u64) -> bool {
        self.within(now, MINUTE_SECONDS) < ATTEMPTS_PER_MINUTE
            && self.within(now, DAY_SECONDS) < ATTEMPTS_PER_DAY
    }

    pub fn record(&mut self, now: u64) {
        self.settle(now);
        self.0.push(now);
    }

    pub fn settle(&mut self, now: u64) -> bool {
        let before = self.0.clone();
        for at in &mut self.0 {
            *at = (*at).min(now);
        }
        self.0.retain(|at| age(*at, now) < DAY_SECONDS);
        self.0.sort_unstable();
        let excess = self.0.len().saturating_sub(ATTEMPTS_PER_DAY);
        self.0.drain(..excess);
        self.0 != before
    }

    pub fn count(&self) -> usize {
        self.0.len()
    }

    pub fn times(&self) -> &[u64] {
        &self.0
    }

    fn within(&self, now: u64, window: u64) -> usize {
        self.0.iter().filter(|at| age(**at, now) < window).count()
    }
}

#[cfg(test)]
impl Attempts {
    pub(crate) fn from_times(times: &[u64]) -> Self {
        Self(times.to_vec())
    }
}

fn age(at: u64, now: u64) -> u64 {
    now.saturating_sub(at)
}

#[cfg(test)]
mod tests {
    use super::{ATTEMPTS_PER_DAY, ATTEMPTS_PER_MINUTE, Attempts};

    const START: u64 = 1_764_000_000;

    fn recorded(times: impl IntoIterator<Item = u64>) -> Attempts {
        let mut attempts = Attempts::default();
        for at in times {
            assert!(attempts.allows(at), "attempt at {at} should be allowed");
            attempts.record(at);
        }
        attempts
    }

    #[test]
    fn five_attempts_in_a_minute_close_the_window_until_the_oldest_ages_out() {
        let attempts = recorded((0..5).map(|offset| START + offset));
        assert_eq!(ATTEMPTS_PER_MINUTE, 5);
        for (now, allowed) in [
            (START + 4, false),
            (START + 59, false),
            (START + 60, true),
            (START + 64, true),
        ] {
            assert_eq!(
                attempts.allows(now),
                allowed,
                "now = START + {}",
                now - START
            );
        }
    }

    #[test]
    fn fifty_attempts_in_a_day_close_the_window_for_the_rest_of_the_day() {
        let attempts = recorded((0..50).map(|index| START + index * 120));
        assert_eq!(ATTEMPTS_PER_DAY, 50);
        let last = START + 49 * 120;
        for (now, allowed) in [
            (last + 120, false),
            (START + 86_399, false),
            (START + 86_400, true),
        ] {
            assert_eq!(
                attempts.allows(now),
                allowed,
                "now = START + {}",
                now - START
            );
        }
    }

    #[test]
    fn settling_drops_old_attempts_and_pulls_future_ones_back_to_now() {
        let mut attempts = Attempts::from_times(&[START, START + 10, START + 86_500]);
        assert!(attempts.settle(START + 86_405));
        assert_eq!(attempts.times(), [START + 10, START + 86_405]);
        assert!(!attempts.settle(START + 86_405));

        let mut jumped_back = Attempts::from_times(&[START + 1000; 5]);
        assert!(!jumped_back.allows(START));
        jumped_back.settle(START);
        assert_eq!(jumped_back.times(), [START; 5]);
        assert!(!jumped_back.allows(START + 59));
        assert!(jumped_back.allows(START + 60));
    }

    #[test]
    fn settling_keeps_only_the_newest_day_limit_entries() {
        let times: Vec<u64> = (0..120).map(|offset| START + offset).collect();
        let mut attempts = Attempts::from_times(&times);
        attempts.settle(START + 200);
        assert_eq!(attempts.count(), ATTEMPTS_PER_DAY);
        assert_eq!(attempts.times().first(), Some(&(START + 70)));
        assert!(!attempts.allows(START + 200));
    }
}
