use std::time::Duration;

use crate::options::{MAX_TIMER, OptionsError, timer_in_range};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub initial: Duration,
    pub max: Duration,
    pub reset_after: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            reset_after: Duration::from_secs(30),
        }
    }
}

impl BackoffPolicy {
    pub fn validate(&self) -> Result<(), OptionsError> {
        if !timer_in_range(self.initial) || self.initial > self.max {
            return Err(OptionsError::BackoffInitial);
        }
        if self.max > MAX_TIMER {
            return Err(OptionsError::BackoffMax);
        }
        if self.reset_after > MAX_TIMER {
            return Err(OptionsError::BackoffResetAfter);
        }
        Ok(())
    }

    pub fn cap(&self, attempt: u32) -> Duration {
        let factor = 1_u32.checked_shl(attempt).unwrap_or(u32::MAX);
        self.initial
            .checked_mul(factor)
            .map_or(self.max, |delay| delay.min(self.max))
    }
}

#[derive(Debug, Clone)]
pub struct Backoff {
    policy: BackoffPolicy,
    attempt: u32,
}

impl Backoff {
    pub fn new(policy: BackoffPolicy) -> Self {
        Self { policy, attempt: 0 }
    }

    pub fn next_delay(&mut self, connection_lasted: Duration, unit_sample: f64) -> Duration {
        if connection_lasted > self.policy.reset_after {
            self.attempt = 0;
        }
        let cap = self.policy.cap(self.attempt);
        self.attempt = self.attempt.saturating_add(1);
        let fraction = if unit_sample.is_finite() {
            unit_sample.clamp(0.0, 1.0)
        } else {
            1.0
        };
        cap.mul_f64(fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> BackoffPolicy {
        BackoffPolicy {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            reset_after: Duration::from_secs(30),
        }
    }

    #[test]
    fn validation_rejects_values_that_could_overflow_or_spin() {
        let cases: [(&str, BackoffPolicy, Result<(), OptionsError>); 7] = [
            ("defaults", BackoffPolicy::default(), Ok(())),
            (
                "zero initial",
                BackoffPolicy {
                    initial: Duration::ZERO,
                    ..policy()
                },
                Err(OptionsError::BackoffInitial),
            ),
            (
                "initial above max",
                BackoffPolicy {
                    initial: Duration::from_secs(61),
                    ..policy()
                },
                Err(OptionsError::BackoffInitial),
            ),
            (
                "endless initial",
                BackoffPolicy {
                    initial: Duration::MAX,
                    max: Duration::MAX,
                    ..policy()
                },
                Err(OptionsError::BackoffInitial),
            ),
            (
                "endless max",
                BackoffPolicy {
                    max: Duration::MAX,
                    ..policy()
                },
                Err(OptionsError::BackoffMax),
            ),
            (
                "endless reset threshold",
                BackoffPolicy {
                    reset_after: Duration::MAX,
                    ..policy()
                },
                Err(OptionsError::BackoffResetAfter),
            ),
            (
                "zero reset threshold",
                BackoffPolicy {
                    reset_after: Duration::ZERO,
                    ..policy()
                },
                Ok(()),
            ),
        ];
        for (name, candidate, expected) in cases {
            assert_eq!(candidate.validate(), expected, "{name}");
        }
    }

    #[test]
    fn caps_double_until_the_maximum() {
        let caps: Vec<u64> = (0..9)
            .map(|attempt| policy().cap(attempt).as_secs())
            .collect();
        assert_eq!(caps, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(policy().cap(u32::MAX), Duration::from_secs(60));
    }

    #[test]
    fn jitter_stays_within_zero_and_the_cap() {
        let mut backoff = Backoff::new(policy());
        let samples = [0.0, 0.25, 0.5, 1.0, 7.0, -3.0, f64::NAN];
        for (attempt, sample) in samples.into_iter().enumerate() {
            let cap = policy().cap(attempt as u32);
            let delay = backoff.next_delay(Duration::ZERO, sample);
            assert!(delay <= cap, "attempt {attempt}: {delay:?} > {cap:?}");
        }
        let mut backoff = Backoff::new(policy());
        assert_eq!(backoff.next_delay(Duration::ZERO, 0.0), Duration::ZERO);
        assert_eq!(
            backoff.next_delay(Duration::ZERO, 1.0),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn delay_resets_only_after_a_long_connection() {
        let mut backoff = Backoff::new(policy());
        for _ in 0..4 {
            backoff.next_delay(Duration::ZERO, 1.0);
        }
        assert_eq!(
            backoff.next_delay(Duration::from_secs(30), 1.0),
            Duration::from_secs(16)
        );
        assert_eq!(
            backoff.next_delay(Duration::from_secs(31), 1.0),
            Duration::from_secs(1)
        );
        assert_eq!(
            backoff.next_delay(Duration::ZERO, 1.0),
            Duration::from_secs(2)
        );
    }
}
