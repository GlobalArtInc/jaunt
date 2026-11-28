use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

pub(crate) const NOTICE_EVERY: Duration = Duration::from_secs(10);
const MAX_KEYS: usize = 65_536;

struct Notice {
    next: Duration,
    suppressed: u64,
}

pub(crate) struct Notices {
    every: Duration,
    slots: Mutex<HashMap<(String, &'static str), Notice>>,
}

impl Notices {
    pub(crate) fn new() -> Notices {
        Notices {
            every: NOTICE_EVERY,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<(String, &'static str), Notice>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn admit(&self, node_id: &str, class: &'static str, now: Duration) -> Option<u64> {
        let mut slots = self.lock();
        let key = (node_id.to_owned(), class);
        if let Some(slot) = slots.get_mut(&key) {
            if now < slot.next {
                slot.suppressed = slot.suppressed.saturating_add(1);
                return None;
            }
            slot.next = now.saturating_add(self.every);
            return Some(std::mem::take(&mut slot.suppressed));
        }
        if slots.len() >= MAX_KEYS {
            slots.retain(|_, slot| slot.next > now);
        }
        if slots.len() < MAX_KEYS {
            slots.insert(
                key,
                Notice {
                    next: now.saturating_add(self.every),
                    suppressed: 0,
                },
            );
        }
        Some(0)
    }

    pub(crate) fn sweep(&self, now: Duration) {
        self.lock()
            .retain(|_, slot| slot.next > now || slot.suppressed > 0);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{NOTICE_EVERY, Notices};

    #[test]
    fn one_notice_passes_per_node_class_and_interval_and_reports_what_it_held_back() {
        let notices = Notices::new();
        let at = Duration::from_secs;
        assert_eq!(notices.admit("n", "body", at(100)), Some(0));
        assert_eq!(notices.admit("n", "body", at(100)), None);
        assert_eq!(notices.admit("n", "body", at(109)), None);
        assert_eq!(notices.admit("n", "expired", at(109)), Some(0));
        assert_eq!(notices.admit("m", "body", at(109)), Some(0));
        assert_eq!(notices.admit("n", "body", at(100) + NOTICE_EVERY), Some(2));
        assert_eq!(notices.admit("n", "body", at(111)), None);
        notices.sweep(at(1000));
        assert_eq!(notices.admit("n", "body", at(1000)), Some(1));
        notices.sweep(at(2000));
        assert_eq!(notices.admit("n", "body", at(2000)), Some(0));
    }
}
