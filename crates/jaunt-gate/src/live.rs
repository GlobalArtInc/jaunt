use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    Revoked,
}

impl TerminationReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
        }
    }
}

struct Entry {
    identity: Option<(String, u64)>,
    terminate: CancellationToken,
}

#[derive(Default)]
pub(crate) struct LiveConnections {
    next: AtomicU64,
    entries: Mutex<HashMap<u64, Entry>>,
}

impl LiveConnections {
    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn register(self: &Arc<Self>) -> LiveConnection {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let terminate = CancellationToken::new();
        self.lock().insert(
            id,
            Entry {
                identity: None,
                terminate: terminate.clone(),
            },
        );
        LiveConnection {
            live: Arc::clone(self),
            id,
            terminate,
        }
    }

    pub(crate) fn terminate(&self, user_id: &str, serial: Option<u64>) -> usize {
        let entries = self.lock();
        let mut terminated = 0;
        for entry in entries.values() {
            let matches = entry.identity.as_ref().is_some_and(|(user, held)| {
                user == user_id && serial.is_none_or(|wanted| wanted == *held)
            });
            if matches && !entry.terminate.is_cancelled() {
                entry.terminate.cancel();
                terminated += 1;
            }
        }
        terminated
    }

    pub(crate) fn authenticated(&self) -> usize {
        self.lock()
            .values()
            .filter(|entry| entry.identity.is_some())
            .count()
    }
}

pub(crate) struct LiveConnection {
    live: Arc<LiveConnections>,
    id: u64,
    terminate: CancellationToken,
}

impl LiveConnection {
    pub(crate) fn token(&self) -> CancellationToken {
        self.terminate.clone()
    }

    pub(crate) fn identify(&self) -> Identify {
        Identify {
            live: Arc::clone(&self.live),
            id: self.id,
        }
    }
}

impl Drop for LiveConnection {
    fn drop(&mut self) {
        self.live.lock().remove(&self.id);
    }
}

pub(crate) struct Identify {
    live: Arc<LiveConnections>,
    id: u64,
}

impl Identify {
    pub(crate) fn holder(&self, user_id: &str, serial: u64) {
        if let Some(entry) = self.live.lock().get_mut(&self.id) {
            entry.identity = Some((user_id.to_owned(), serial));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::LiveConnections;

    #[test]
    fn termination_reaches_only_matching_authenticated_connections_once() {
        let live = Arc::new(LiveConnections::default());
        let first = live.register();
        let second = live.register();
        let other = live.register();
        let anonymous = live.register();
        let longer = live.register();
        first.identify().holder("alice", 7);
        second.identify().holder("alice", 8);
        other.identify().holder("bob", 7);
        longer.identify().holder("alice2", 7);
        assert_eq!(live.authenticated(), 4);

        assert_eq!(live.terminate("alic", None), 0);
        assert_eq!(live.terminate("alice", Some(9)), 0);
        assert_eq!(live.terminate("alice", Some(7)), 1);
        assert!(first.token().is_cancelled());
        assert!(!second.token().is_cancelled());
        assert_eq!(live.terminate("alice", None), 1);
        assert!(second.token().is_cancelled());
        assert_eq!(live.terminate("alice", None), 0);
        assert!(!other.token().is_cancelled() && !anonymous.token().is_cancelled());
        assert!(!longer.token().is_cancelled());
        assert_eq!(live.terminate("alice2", Some(7)), 1);
        assert!(longer.token().is_cancelled());
        drop(longer);

        let identify = other.identify();
        drop(other);
        identify.holder("alice", 1);
        assert_eq!(live.authenticated(), 2);
        drop((first, second, anonymous));
        assert_eq!(live.authenticated(), 0);
    }
}
