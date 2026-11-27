use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

pub(crate) const PENDING_ANNOUNCEMENT_WINDOW: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct Announcement {
    connection: Option<SystemTime>,
    at: SystemTime,
}

impl Announcement {
    fn holds_for(self, connected_since: SystemTime) -> bool {
        match self.connection {
            Some(connection) => connection == connected_since,
            None => gap(self.at, connected_since) <= PENDING_ANNOUNCEMENT_WINDOW,
        }
    }
}

fn gap(left: SystemTime, right: SystemTime) -> Duration {
    right
        .duration_since(left)
        .unwrap_or_else(|earlier| earlier.duration())
}

#[derive(Default)]
pub(crate) struct Capabilities {
    announced: Mutex<HashMap<String, Announcement>>,
}

impl Capabilities {
    fn locked(&self) -> MutexGuard<'_, HashMap<String, Announcement>> {
        self.announced
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn announce(
        &self,
        node_id: &str,
        creates_accounts: bool,
        connection: Option<SystemTime>,
        at: SystemTime,
    ) {
        let mut announced = self.locked();
        if creates_accounts {
            announced.insert(node_id.to_owned(), Announcement { connection, at });
        } else {
            announced.remove(node_id);
        }
    }

    pub(crate) fn creates_accounts(
        &self,
        node_id: &str,
        connected_since: Option<SystemTime>,
    ) -> bool {
        let Some(since) = connected_since else {
            return false;
        };
        self.locked()
            .get(node_id)
            .is_some_and(|announcement| announcement.holds_for(since))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{Capabilities, PENDING_ANNOUNCEMENT_WINDOW};

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn ms(millis: u64) -> Duration {
        Duration::from_millis(millis)
    }

    #[test]
    fn the_flag_holds_only_for_the_connection_it_was_announced_on() {
        let capabilities = Capabilities::default();
        assert!(!capabilities.creates_accounts("n1", Some(at(100))));
        capabilities.announce("n1", true, Some(at(100)), at(105));
        assert!(capabilities.creates_accounts("n1", Some(at(100))));
        assert!(!capabilities.creates_accounts("n2", Some(at(100))));
        assert!(!capabilities.creates_accounts("n1", None));
        assert!(!capabilities.creates_accounts("n1", Some(at(200))));

        capabilities.announce("n1", true, Some(at(200)), at(205));
        assert!(!capabilities.creates_accounts("n1", Some(at(206))));
        assert!(!capabilities.creates_accounts("n1", Some(at(100))));
        assert!(capabilities.creates_accounts("n1", Some(at(200))));

        capabilities.announce("n1", true, Some(at(300)), at(305));
        capabilities.announce("n1", false, Some(at(300)), at(306));
        assert!(!capabilities.creates_accounts("n1", Some(at(300))));
    }

    #[test]
    fn an_announcement_made_before_its_connection_registered_is_kept() {
        let capabilities = Capabilities::default();
        let since = at(100);
        capabilities.announce("n1", true, None, since - ms(5));
        assert!(!capabilities.creates_accounts("n1", None));
        assert!(capabilities.creates_accounts("n1", Some(since)));
        assert!(capabilities.creates_accounts("n1", Some(since)));
    }

    #[test]
    fn an_announcement_on_the_old_connection_is_not_shown_for_the_new_one() {
        let capabilities = Capabilities::default();
        let since = at(100);
        capabilities.announce("n1", true, Some(at(40)), since - ms(5));
        assert!(!capabilities.creates_accounts("n1", Some(since)));
        assert!(capabilities.creates_accounts("n1", Some(at(40))));
    }

    #[test]
    fn a_pending_announcement_attaches_only_within_the_window() {
        let since = at(100);
        let window = PENDING_ANNOUNCEMENT_WINDOW;
        for (announced_at, holds) in [
            (since - window, true),
            (since - window - ms(1), false),
            (since + window, true),
            (since + window + ms(1), false),
            (since - Duration::from_secs(5) - ms(1), false),
            (since - Duration::from_secs(60), false),
        ] {
            let capabilities = Capabilities::default();
            capabilities.announce("n1", true, None, announced_at);
            assert_eq!(
                capabilities.creates_accounts("n1", Some(since)),
                holds,
                "{announced_at:?}"
            );
        }
    }

    #[test]
    fn a_false_announcement_removes_a_pending_flag() {
        let capabilities = Capabilities::default();
        capabilities.announce("n1", true, None, at(99));
        capabilities.announce("n1", false, None, at(99));
        assert!(!capabilities.creates_accounts("n1", Some(at(100))));
    }

    #[test]
    fn a_reconnect_after_a_disconnect_does_not_revive_the_flag() {
        let capabilities = Capabilities::default();
        capabilities.announce("n1", true, None, at(99));
        assert!(capabilities.creates_accounts("n1", Some(at(100))));
        assert!(!capabilities.creates_accounts("n1", None));
        assert!(!capabilities.creates_accounts("n1", Some(at(160))));
    }
}
