use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_proto::{AccountEvent, AccountReference};
use tokio::sync::watch;

pub(crate) const NOTICE_RETENTION: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AccountNotice {
    pub(crate) creating: Option<AccountReference>,
    pub(crate) outcome: Option<AccountEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutOfOrder;

struct Entry {
    sender: watch::Sender<AccountNotice>,
    changed_at: Duration,
}

impl Entry {
    fn new(now: Duration) -> Entry {
        Entry {
            sender: watch::Sender::new(AccountNotice::default()),
            changed_at: now,
        }
    }

    fn expired(&self, now: Duration) -> bool {
        if now.saturating_sub(self.changed_at) < NOTICE_RETENTION {
            return false;
        }
        self.sender.borrow().outcome.is_some() || self.sender.receiver_count() == 0
    }
}

#[derive(Default)]
pub(crate) struct AccountNotices {
    entries: Mutex<HashMap<String, Entry>>,
}

fn advance(current: &AccountNotice, event: &AccountEvent) -> Result<AccountNotice, OutOfOrder> {
    if current.outcome.is_some() {
        return Err(OutOfOrder);
    }
    match event {
        AccountEvent::Creating { reference } => match current.creating {
            Some(_) => Err(OutOfOrder),
            None => Ok(AccountNotice {
                creating: Some(reference.clone()),
                outcome: None,
            }),
        },
        outcome => {
            if let Some(started) = &current.creating
                && started != outcome.reference()
            {
                return Err(OutOfOrder);
            }
            Ok(AccountNotice {
                creating: current.creating.clone(),
                outcome: Some(outcome.clone()),
            })
        }
    }
}

impl AccountNotices {
    fn locked(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn pruned(&self, now: Duration) -> MutexGuard<'_, HashMap<String, Entry>> {
        let mut entries = self.locked();
        entries.retain(|_, entry| !entry.expired(now));
        entries
    }

    pub(crate) fn subscribe(
        &self,
        session_id: &str,
        now: Duration,
    ) -> watch::Receiver<AccountNotice> {
        self.pruned(now)
            .entry(session_id.to_owned())
            .or_insert_with(|| Entry::new(now))
            .sender
            .subscribe()
    }

    pub(crate) fn accept(
        &self,
        session_id: &str,
        event: &AccountEvent,
        now: Duration,
    ) -> Result<(), OutOfOrder> {
        let mut entries = self.pruned(now);
        let entry = entries
            .entry(session_id.to_owned())
            .or_insert_with(|| Entry::new(now));
        let next = advance(&entry.sender.borrow(), event)?;
        entry.sender.send_replace(next);
        entry.changed_at = now;
        Ok(())
    }

    #[cfg(test)]
    fn tracked(&self, now: Duration) -> usize {
        self.pruned(now).len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jaunt_proto::{AccountEvent, AccountReference, AccountRefusal, AccountStage};

    use super::{AccountNotices, NOTICE_RETENTION, OutOfOrder};

    fn reference(text: &str) -> AccountReference {
        AccountReference::parse(text).unwrap()
    }

    fn creating() -> AccountEvent {
        AccountEvent::Creating {
            reference: reference("H-0000000A"),
        }
    }

    fn missing(text: &str) -> AccountEvent {
        AccountEvent::Missing {
            reference: reference(text),
        }
    }

    fn created() -> AccountEvent {
        AccountEvent::Created {
            reference: reference("H-0000000A"),
            uid: 30_000,
            home: "/home/alice".to_owned(),
            groups: Vec::new(),
        }
    }

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn at_most_one_creating_comes_before_exactly_one_outcome_with_the_same_reference() {
        let refused = AccountEvent::Refused {
            reference: reference("H-0000000A"),
            reason: AccountRefusal::MaxUsers,
        };
        let other_reference = AccountEvent::Failed {
            reference: reference("H-0000000B"),
            stage: AccountStage::Tool,
            exit_code: None,
        };
        for (events, last) in [
            (vec![creating(), created()], Ok(())),
            (vec![created()], Ok(())),
            (vec![creating(), missing("H-0000000A")], Ok(())),
            (vec![missing("H-0000000B")], Ok(())),
            (vec![creating(), missing("H-0000000B")], Err(OutOfOrder)),
            (vec![creating(), creating()], Err(OutOfOrder)),
            (
                vec![creating(), created(), refused.clone()],
                Err(OutOfOrder),
            ),
            (vec![created(), created()], Err(OutOfOrder)),
            (vec![refused.clone(), creating()], Err(OutOfOrder)),
            (vec![creating(), other_reference], Err(OutOfOrder)),
        ] {
            let notices = AccountNotices::default();
            let (head, tail) = events.split_at(events.len() - 1);
            for event in head {
                assert_eq!(notices.accept("s-1", event, at(1)), Ok(()), "{events:?}");
            }
            assert_eq!(notices.accept("s-1", &tail[0], at(1)), last, "{events:?}");
        }
    }

    #[test]
    fn a_subscriber_sees_every_step_and_other_sessions_stay_apart() {
        let notices = AccountNotices::default();
        let mut watching = notices.subscribe("s-1", at(0));
        let other = notices.subscribe("s-2", at(0));
        assert_eq!(*watching.borrow_and_update(), Default::default());
        notices.accept("s-1", &creating(), at(1)).unwrap();
        assert!(watching.has_changed().unwrap());
        assert_eq!(
            watching.borrow_and_update().creating,
            Some(reference("H-0000000A"))
        );
        notices.accept("s-1", &created(), at(2)).unwrap();
        assert_eq!(watching.borrow_and_update().outcome, Some(created()));
        assert_eq!(*other.borrow(), Default::default());
    }

    #[test]
    fn entries_go_60_seconds_after_the_outcome_or_after_the_last_step_once_nobody_watches() {
        let notices = AccountNotices::default();
        notices.accept("settled", &created(), at(10)).unwrap();
        notices.accept("stalled", &creating(), at(10)).unwrap();
        let watcher = notices.subscribe("watched", at(10));
        assert_eq!(notices.tracked(at(69)), 3);
        assert_eq!(notices.tracked(at(10) + NOTICE_RETENTION), 1);
        drop(watcher);
        assert_eq!(notices.tracked(at(10) + NOTICE_RETENTION), 0);

        let held = notices.subscribe("held", at(100));
        notices.accept("held", &creating(), at(105)).unwrap();
        notices.accept("held", &created(), at(110)).unwrap();
        assert_eq!(notices.tracked(at(169)), 1);
        assert_eq!(notices.tracked(at(170)), 0);
        assert_eq!(held.borrow().outcome, Some(created()));
    }
}
