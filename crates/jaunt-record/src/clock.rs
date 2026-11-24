use std::time::{Duration, Instant};

pub trait Clock: Send {
    fn elapsed(&self) -> Duration;
}

#[derive(Debug)]
pub struct SystemClock {
    started: Instant,
}

impl SystemClock {
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}
