use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use jaunt_store::Session;
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

use crate::killer::{KillReason, KillScope};

use super::locked;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    Exited,
    ClientClosed,
    Revoked,
    IdleTimeout,
    MaxDuration,
    WebSessionEnded,
    Denied,
    Limit,
    Unavailable,
    Malformed,
    TooBig,
    DeadPeer,
    Wedged,
    Shutdown,
}

impl End {
    fn of_kill(reason: KillReason) -> End {
        match reason {
            KillReason::Revoked => End::Revoked,
            KillReason::Expired => End::MaxDuration,
            KillReason::AgentGone | KillReason::NodeRemoved => End::Unavailable,
        }
    }
}

pub(crate) struct Stop {
    pub(crate) user_id: String,
    web_session: String,
    node_id: String,
    serial: OnceLock<u64>,
    session_id: OnceLock<String>,
    end: OnceLock<End>,
    token: CancellationToken,
}

impl Stop {
    pub(crate) fn stop(&self, end: End) {
        self.end.get_or_init(|| end);
        self.token.cancel();
    }

    pub(crate) fn end(&self) -> Option<End> {
        self.end.get().copied()
    }

    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.token.cancelled()
    }

    pub(crate) fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    pub(crate) fn certificate_issued(&self, serial: u64) {
        self.serial.get_or_init(|| serial);
    }

    pub(crate) fn routed(&self, session_id: &str) {
        self.session_id.get_or_init(|| session_id.to_owned());
    }

    pub(crate) fn serial(&self) -> Option<u64> {
        self.serial.get().copied()
    }

    pub(crate) fn node_id(&self) -> &str {
        &self.node_id
    }

    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session_id.get().map(String::as_str)
    }

    fn matches(&self, scope: &KillScope) -> bool {
        match scope {
            KillScope::User { user_id } => &self.user_id == user_id,
            KillScope::Certificate { user_id, serial } => {
                &self.user_id == user_id && self.serial.get() == Some(serial)
            }
            KillScope::Node { node_id } => &self.node_id == node_id,
            KillScope::Sessions => false,
        }
    }
}

#[derive(Default)]
struct Book {
    entries: HashMap<u64, Arc<Stop>>,
    per_user: HashMap<String, usize>,
    next: u64,
    closing: bool,
}

#[derive(Default)]
pub(crate) struct LiveTerminals {
    book: Mutex<Book>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Full,
    Closing,
}

pub(crate) struct Admission {
    pub(crate) stop: Arc<Stop>,
    live: Arc<LiveTerminals>,
    id: u64,
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.stop.stop(End::Unavailable);
        let mut book = locked(&self.live.book);
        if book.entries.remove(&self.id).is_some()
            && let Some(count) = book.per_user.get_mut(&self.stop.user_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                book.per_user.remove(&self.stop.user_id);
            }
        }
    }
}

pub(crate) struct Limits {
    pub(crate) per_user: usize,
    pub(crate) total: usize,
}

impl LiveTerminals {
    pub(crate) fn admit(
        self: &Arc<Self>,
        user_id: &str,
        web_session: &str,
        node_id: &str,
        limits: &Limits,
    ) -> Result<Admission, Refused> {
        let mut book = locked(&self.book);
        if book.closing {
            return Err(Refused::Closing);
        }
        let mine = book.per_user.get(user_id).copied().unwrap_or(0);
        if mine >= limits.per_user || book.entries.len() >= limits.total {
            return Err(Refused::Full);
        }
        let id = book.next;
        book.next = book.next.wrapping_add(1);
        let stop = Arc::new(Stop {
            user_id: user_id.to_owned(),
            web_session: web_session.to_owned(),
            node_id: node_id.to_owned(),
            serial: OnceLock::new(),
            session_id: OnceLock::new(),
            end: OnceLock::new(),
            token: CancellationToken::new(),
        });
        book.entries.insert(id, Arc::clone(&stop));
        *book.per_user.entry(user_id.to_owned()).or_insert(0) += 1;
        Ok(Admission {
            stop,
            live: Arc::clone(self),
            id,
        })
    }

    fn each(&self, mut visit: impl FnMut(&Stop)) {
        let stops: Vec<Arc<Stop>> = locked(&self.book).entries.values().cloned().collect();
        for stop in stops {
            visit(&stop);
        }
    }

    pub(crate) fn stop_matching(
        &self,
        scope: &KillScope,
        reason: KillReason,
        sessions: &[Session],
    ) {
        let end = End::of_kill(reason);
        self.each(|stop| {
            let named = stop
                .session_id()
                .is_some_and(|id| sessions.iter().any(|session| session.id == id));
            if named || stop.matches(scope) {
                stop.stop(end);
            }
        });
    }

    pub(crate) fn stop_web_session(&self, web_session: &str, end: End) {
        self.each(|stop| {
            if stop.web_session == web_session {
                stop.stop(end);
            }
        });
    }

    pub(crate) fn stop_all(&self, end: End) -> usize {
        locked(&self.book).closing = true;
        let mut stopped = 0;
        self.each(|stop| {
            stop.stop(end);
            stopped += 1;
        });
        stopped
    }

    pub(crate) fn open(&self) -> usize {
        locked(&self.book).entries.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::killer::{KillReason, KillScope};

    use super::{End, Limits, LiveTerminals, Refused};

    const LIMITS: Limits = Limits {
        per_user: 2,
        total: 3,
    };

    #[test]
    fn admissions_stop_at_the_user_and_total_limits_and_return_their_slot_on_drop() {
        let live = Arc::new(LiveTerminals::default());
        let first = live.admit("alice", "s1", "n1", &LIMITS).unwrap();
        let second = live.admit("alice", "s1", "n1", &LIMITS).unwrap();
        assert!(matches!(
            live.admit("alice", "s2", "n2", &LIMITS),
            Err(Refused::Full)
        ));
        let third = live.admit("bob", "s3", "n1", &LIMITS).unwrap();
        assert!(matches!(
            live.admit("carol", "s4", "n1", &LIMITS),
            Err(Refused::Full)
        ));
        let first_stop = Arc::clone(&first.stop);
        drop(first);
        assert_eq!(live.open(), 2);
        assert_eq!(first_stop.end(), Some(End::Unavailable));
        assert!(first_stop.token().is_cancelled());
        let again = live.admit("alice", "s1", "n1", &LIMITS).unwrap();
        drop((second, third, again));
        assert_eq!(live.open(), 0);
    }

    #[test]
    fn kill_orders_stop_exactly_the_terminals_they_name_with_the_matching_end() {
        let live = Arc::new(LiveTerminals::default());
        let limits = Limits {
            per_user: 8,
            total: 8,
        };
        let alice = live.admit("alice", "s1", "n1", &limits).unwrap();
        alice.stop.certificate_issued(7);
        let alice_other = live.admit("alice", "s1", "n2", &limits).unwrap();
        alice_other.stop.certificate_issued(8);
        let bob = live.admit("bob", "s2", "n1", &limits).unwrap();
        bob.stop.routed("session-b");

        live.stop_matching(
            &KillScope::Certificate {
                user_id: "alice".to_owned(),
                serial: 7,
            },
            KillReason::Revoked,
            &[],
        );
        assert_eq!(alice.stop.end(), Some(End::Revoked));
        assert_eq!(alice_other.stop.end(), None);
        assert_eq!(bob.stop.end(), None);

        live.stop_matching(
            &KillScope::Node {
                node_id: "n2".to_owned(),
            },
            KillReason::NodeRemoved,
            &[],
        );
        assert_eq!(alice_other.stop.end(), Some(End::Unavailable));

        let mut session = jaunt_store_session("session-b");
        session.node_id = "n1".to_owned();
        live.stop_matching(&KillScope::Sessions, KillReason::Expired, &[session]);
        assert_eq!(bob.stop.end(), Some(End::MaxDuration));
    }

    #[test]
    fn the_first_end_wins_web_sessions_stop_their_own_terminals_and_shutdown_admits_no_more() {
        let live = Arc::new(LiveTerminals::default());
        let limits = Limits {
            per_user: 8,
            total: 8,
        };
        let mine = live.admit("alice", "s1", "n1", &limits).unwrap();
        let other = live.admit("alice", "s2", "n1", &limits).unwrap();
        live.stop_web_session("s1", End::WebSessionEnded);
        mine.stop.stop(End::Revoked);
        assert_eq!(mine.stop.end(), Some(End::WebSessionEnded));
        assert_eq!(other.stop.end(), None);
        live.stop_matching(
            &KillScope::User {
                user_id: "alice".to_owned(),
            },
            KillReason::Revoked,
            &[],
        );
        assert_eq!(other.stop.end(), Some(End::Revoked));
        assert_eq!(live.stop_all(End::Shutdown), 2);
        assert!(matches!(
            live.admit("bob", "s3", "n1", &limits),
            Err(Refused::Closing)
        ));
    }

    fn jaunt_store_session(id: &str) -> jaunt_store::Session {
        jaunt_store::Session {
            id: id.to_owned(),
            user_id: "bob".to_owned(),
            serial: 1,
            node_id: String::new(),
            state: jaunt_store::SessionState::Active,
            created_at: 0,
            expires_at: 0,
            authorized_at: None,
            ended_at: None,
            login: None,
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: None,
        }
    }
}
