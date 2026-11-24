use jaunt_limits::{Rate, RateLimiter};

pub(crate) const POLLS_BURST: u32 = 20;
pub(crate) const POLLS_PER_MINUTE: u32 = 120;
pub(crate) const HANDLE_LIMITER_CAPACITY: usize = 10_000;

pub(crate) fn handle_polls() -> RateLimiter<String> {
    RateLimiter::new(
        Rate::clamped(POLLS_BURST, POLLS_PER_MINUTE),
        HANDLE_LIMITER_CAPACITY,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{POLLS_BURST, handle_polls};

    #[test]
    fn the_twenty_first_poll_of_one_handle_is_refused_until_ten_seconds_refill_the_burst() {
        let limiter = handle_polls();
        let at = Duration::from_secs;
        for _ in 0..POLLS_BURST {
            assert!(limiter.check(&"a".to_owned(), at(100)).is_allowed());
        }
        assert!(!limiter.check(&"a".to_owned(), at(100)).is_allowed());
        assert!(limiter.check(&"b".to_owned(), at(100)).is_allowed());
        for _ in 0..POLLS_BURST {
            assert!(limiter.check(&"a".to_owned(), at(110)).is_allowed());
        }
        assert!(!limiter.check(&"a".to_owned(), at(110)).is_allowed());
    }
}
