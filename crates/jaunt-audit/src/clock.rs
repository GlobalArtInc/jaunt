use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use crate::time::Timestamp;

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

pub fn system_clock() -> Arc<dyn Clock> {
    Arc::new(SystemClock)
}

#[derive(Debug, Default)]
pub struct ManualClock {
    millis: AtomicI64,
}

impl ManualClock {
    pub fn new(millis: i64) -> ManualClock {
        ManualClock {
            millis: AtomicI64::new(millis),
        }
    }

    pub fn advance(&self, millis: i64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        let millis = self.millis.load(Ordering::SeqCst);
        Timestamp::from_millis(millis).unwrap_or_else(|_| Timestamp::now())
    }
}
