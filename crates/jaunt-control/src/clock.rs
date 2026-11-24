use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
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
