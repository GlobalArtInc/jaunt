use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::clock::Clock;

pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

pub(crate) fn unix_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::unix_seconds;

    #[test]
    fn wall_time_is_whole_seconds_since_the_epoch_and_earlier_times_are_zero() {
        assert_eq!(unix_seconds(UNIX_EPOCH), 0);
        assert_eq!(
            unix_seconds(UNIX_EPOCH + Duration::from_millis(1_764_000_000_999)),
            1_764_000_000
        );
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(5)), 0);
    }
}
