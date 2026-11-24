use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use jaunt_oidc::PendingAuth;

pub(crate) struct PendingLogin {
    pub(crate) auth: PendingAuth,
    pub(crate) login_id: String,
    pub(crate) redirect_port: u16,
    pub(crate) expires_at: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InsertError {
    Full,
    Duplicate,
}

pub(crate) struct PendingLogins {
    capacity: usize,
    entries: Mutex<HashMap<String, PendingLogin>>,
}

impl PendingLogins {
    pub(crate) fn new(capacity: usize) -> PendingLogins {
        PendingLogins {
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn has_room(&self, now: i64) -> bool {
        let mut entries = self.lock();
        if entries.len() >= self.capacity {
            entries.retain(|_, entry| entry.expires_at > now);
        }
        entries.len() < self.capacity
    }

    pub(crate) fn insert(
        &self,
        state: String,
        entry: PendingLogin,
        now: i64,
    ) -> Result<(), InsertError> {
        let mut entries = self.lock();
        if entries.len() >= self.capacity {
            entries.retain(|_, existing| existing.expires_at > now);
        }
        if entries.len() >= self.capacity {
            return Err(InsertError::Full);
        }
        if entries.contains_key(&state) {
            return Err(InsertError::Duplicate);
        }
        entries.insert(state, entry);
        Ok(())
    }

    pub(crate) fn take(&self, state: &str) -> Option<PendingLogin> {
        self.lock().remove(state)
    }

    pub(crate) fn sweep(&self, now: i64) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        before - entries.len()
    }

    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, PendingLogin>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use jaunt_oidc::{PendingAuth, Secret};

    use super::{InsertError, PendingLogin, PendingLogins};

    fn entry(expires_at: i64) -> PendingLogin {
        PendingLogin {
            auth: PendingAuth {
                authorize_url: "https://idp.example/authorize".to_owned(),
                state: "state".to_owned(),
                nonce: Secret::new("nonce"),
                pkce_verifier: Secret::new("verifier"),
                created_at: SystemTime::UNIX_EPOCH,
            },
            login_id: "login".to_owned(),
            redirect_port: 40000,
            expires_at,
        }
    }

    #[test]
    fn entries_are_taken_at_most_once() {
        let pending = PendingLogins::new(4);
        pending.insert("a".to_owned(), entry(100), 0).unwrap();
        assert!(pending.take("a").is_some());
        assert!(pending.take("a").is_none());
        assert!(pending.take("b").is_none());
    }

    #[test]
    fn a_full_map_sweeps_expired_entries_before_refusing() {
        let pending = PendingLogins::new(2);
        pending.insert("a".to_owned(), entry(10), 0).unwrap();
        pending.insert("b".to_owned(), entry(100), 0).unwrap();
        assert!(!pending.has_room(5));
        assert_eq!(
            pending.insert("c".to_owned(), entry(100), 5),
            Err(InsertError::Full)
        );
        assert!(pending.has_room(10));
        pending.insert("c".to_owned(), entry(100), 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.take("a").is_none());
    }

    #[test]
    fn sweep_removes_only_expired_entries_and_duplicates_are_refused() {
        let pending = PendingLogins::new(8);
        pending.insert("a".to_owned(), entry(10), 0).unwrap();
        pending.insert("b".to_owned(), entry(11), 0).unwrap();
        assert_eq!(
            pending.insert("b".to_owned(), entry(50), 0),
            Err(InsertError::Duplicate)
        );
        assert_eq!(pending.sweep(10), 1);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending.sweep(11), 1);
        assert_eq!(pending.len(), 0);
    }
}
