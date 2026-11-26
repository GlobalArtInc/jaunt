use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

#[derive(Default)]
pub(crate) struct Capabilities {
    announced: Mutex<HashMap<String, SystemTime>>,
}

impl Capabilities {
    fn locked(&self) -> MutexGuard<'_, HashMap<String, SystemTime>> {
        self.announced
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn announce(&self, node_id: &str, creates_accounts: bool, at: SystemTime) {
        let mut announced = self.locked();
        if creates_accounts {
            announced.insert(node_id.to_owned(), at);
        } else {
            announced.remove(node_id);
        }
    }

    pub(crate) fn creates_accounts(
        &self,
        node_id: &str,
        connected_since: Option<SystemTime>,
    ) -> bool {
        let mut announced = self.locked();
        let Some(at) = announced.get(node_id).copied() else {
            return false;
        };
        let current = connected_since.is_some_and(|since| since <= at);
        if !current {
            announced.remove(node_id);
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::Capabilities;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn the_flag_holds_only_for_the_connection_it_was_announced_on() {
        let capabilities = Capabilities::default();
        assert!(!capabilities.creates_accounts("n1", Some(at(100))));
        capabilities.announce("n1", true, at(105));
        assert!(capabilities.creates_accounts("n1", Some(at(100))));
        assert!(capabilities.creates_accounts("n1", Some(at(105))));
        assert!(!capabilities.creates_accounts("n2", Some(at(100))));
        assert!(!capabilities.creates_accounts("n1", None));
        assert!(!capabilities.creates_accounts("n1", Some(at(100))));

        capabilities.announce("n1", true, at(205));
        assert!(!capabilities.creates_accounts("n1", Some(at(206))));
        assert!(!capabilities.creates_accounts("n1", Some(at(200))));

        capabilities.announce("n1", true, at(305));
        capabilities.announce("n1", false, at(306));
        assert!(!capabilities.creates_accounts("n1", Some(at(300))));
    }
}
