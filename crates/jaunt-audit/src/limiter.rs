use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

#[derive(Debug)]
pub(crate) struct IntervalCounter {
    interval_ms: i64,
    pending: AtomicU64,
    total: AtomicU64,
    last_report_ms: AtomicI64,
}

impl IntervalCounter {
    pub(crate) fn new(interval_ms: i64) -> IntervalCounter {
        IntervalCounter {
            interval_ms,
            pending: AtomicU64::new(0),
            total: AtomicU64::new(0),
            last_report_ms: AtomicI64::new(i64::MIN),
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    pub(crate) fn record(&self, now_ms: i64) -> Option<u64> {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.pending.fetch_add(1, Ordering::Relaxed);
        let last = self.last_report_ms.load(Ordering::Acquire);
        let due = last == i64::MIN || now_ms.saturating_sub(last) >= self.interval_ms;
        if due
            && self
                .last_report_ms
                .compare_exchange(last, now_ms, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            Some(self.pending.swap(0, Ordering::AcqRel))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::IntervalCounter;

    #[test]
    fn the_first_occurrence_reports_and_later_ones_wait_for_the_interval() {
        let counter = IntervalCounter::new(1000);

        assert_eq!(counter.record(5000), Some(1));
        assert_eq!(counter.record(5100), None);
        assert_eq!(counter.record(5999), None);
        assert_eq!(counter.record(6000), Some(3));
        assert_eq!(counter.record(6001), None);
        assert_eq!(counter.total(), 5);
    }
}
