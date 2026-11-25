use std::sync::{Mutex, PoisonError};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Go,
    Probe,
    Wait,
}

#[derive(Debug, Default)]
struct State {
    open_until: Option<Duration>,
    probing: bool,
}

#[derive(Debug)]
pub struct Breaker {
    state: Mutex<State>,
}

impl Breaker {
    pub fn new() -> Breaker {
        Breaker {
            state: Mutex::new(State::default()),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn admit(&self, now: Duration) -> Admission {
        let mut state = self.state();
        match state.open_until {
            None => Admission::Go,
            Some(until) if now < until => Admission::Wait,
            Some(_) if state.probing => Admission::Wait,
            Some(_) => {
                state.probing = true;
                Admission::Probe
            }
        }
    }

    pub fn is_open(&self, now: Duration) -> bool {
        let state = self.state();
        state
            .open_until
            .is_some_and(|until| now < until || state.probing)
    }

    pub fn trip(&self, until: Duration) {
        let mut state = self.state();
        state.open_until = Some(until);
        state.probing = false;
    }

    pub fn close(&self) {
        let mut state = self.state();
        state.open_until = None;
        state.probing = false;
    }

    pub fn release(&self) {
        self.state().probing = false;
    }
}

impl Default for Breaker {
    fn default() -> Breaker {
        Breaker::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Admission, Breaker};

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn a_closed_breaker_admits_everyone() {
        let breaker = Breaker::new();
        assert_eq!(breaker.admit(at(0)), Admission::Go);
        assert_eq!(breaker.admit(at(1)), Admission::Go);
    }

    #[test]
    fn an_open_breaker_makes_all_wait_then_lets_exactly_one_probe_through() {
        let breaker = Breaker::new();
        breaker.trip(at(15));
        assert_eq!(breaker.admit(at(14)), Admission::Wait);
        assert_eq!(breaker.admit(at(15)), Admission::Probe);
        assert_eq!(breaker.admit(at(16)), Admission::Wait);
        assert_eq!(breaker.admit(at(100)), Admission::Wait);
    }

    #[test]
    fn the_open_state_can_be_asked_without_taking_the_probe_turn() {
        let breaker = Breaker::new();
        assert!(!breaker.is_open(at(0)));
        breaker.trip(at(15));
        assert!(breaker.is_open(at(14)));
        assert!(!breaker.is_open(at(15)));
        assert!(!breaker.is_open(at(15)));
        assert_eq!(breaker.admit(at(15)), Admission::Probe);
    }

    #[test]
    fn a_failed_probe_reopens_and_a_good_one_closes() {
        let breaker = Breaker::new();
        breaker.trip(at(15));
        assert_eq!(breaker.admit(at(20)), Admission::Probe);
        breaker.trip(at(35));
        assert_eq!(breaker.admit(at(34)), Admission::Wait);
        assert_eq!(breaker.admit(at(36)), Admission::Probe);
        breaker.close();
        assert_eq!(breaker.admit(at(37)), Admission::Go);
    }

    #[test]
    fn a_probe_that_neither_succeeds_nor_fails_hands_the_turn_to_the_next_caller() {
        let breaker = Breaker::new();
        breaker.trip(at(15));
        assert_eq!(breaker.admit(at(20)), Admission::Probe);
        breaker.release();
        assert_eq!(breaker.admit(at(21)), Admission::Probe);
    }
}
