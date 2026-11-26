use std::time::{Duration, Instant};

pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}
