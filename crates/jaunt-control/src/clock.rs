use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub type Ticker = Arc<dyn Fn() -> Duration + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

pub fn monotonic_ticker() -> Ticker {
    let origin = Instant::now();
    Arc::new(move || origin.elapsed())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Moment {
    pub(crate) system: SystemTime,
    pub(crate) secs: i64,
}

impl Moment {
    pub(crate) fn read(clock: &Clock) -> Option<Moment> {
        let system = clock();
        let secs = system.duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(Moment {
            system,
            secs: i64::try_from(secs).ok()?,
        })
    }
}

pub(crate) fn whole_secs(elapsed: Duration) -> i64 {
    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{monotonic_ticker, whole_secs};

    #[test]
    fn the_ticker_never_goes_back_and_whole_seconds_saturate() {
        let ticker = monotonic_ticker();
        let first = ticker();
        assert!(ticker() >= first);
        assert_eq!(whole_secs(Duration::from_millis(2_999)), 2);
        assert_eq!(whole_secs(Duration::MAX), i64::MAX);
    }
}
