use std::sync::{Mutex, PoisonError};
use std::time::Duration;

struct State {
    next: Option<Duration>,
    suppressed: u64,
}

pub struct LogThrottle {
    every: Duration,
    state: Mutex<State>,
}

impl LogThrottle {
    pub const fn new(every: Duration) -> Self {
        Self {
            every,
            state: Mutex::new(State {
                next: None,
                suppressed: 0,
            }),
        }
    }

    pub fn admit(&self, now: Duration) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.next.is_some_and(|next| now < next) {
            state.suppressed = state.suppressed.saturating_add(1);
            return None;
        }
        state.next = Some(now.saturating_add(self.every));
        Some(std::mem::take(&mut state.suppressed))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::LogThrottle;

    #[test]
    fn one_line_passes_per_interval_and_reports_how_many_were_held_back() {
        let throttle = LogThrottle::new(Duration::from_secs(10));
        let at = Duration::from_secs;
        assert_eq!(throttle.admit(at(100)), Some(0));
        assert_eq!(throttle.admit(at(100)), None);
        assert_eq!(throttle.admit(at(109)), None);
        assert_eq!(throttle.admit(at(110)), Some(2));
        assert_eq!(throttle.admit(at(111)), None);
        assert_eq!(throttle.admit(at(500)), Some(1));
        assert_eq!(throttle.admit(at(5)), None);
    }
}
