use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::proto::SessionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("session is already active")]
pub(crate) struct DuplicateSession;

struct Entry {
    generation: u64,
    token: CancellationToken,
}

#[derive(Default)]
struct SessionsInner {
    next_generation: AtomicU64,
    active: Mutex<HashMap<SessionId, Entry>>,
}

impl SessionsInner {
    fn lock(&self) -> MutexGuard<'_, HashMap<SessionId, Entry>> {
        self.active.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<SessionsInner>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active(&self) -> Vec<SessionId> {
        let mut sessions: Vec<SessionId> = self.inner.lock().keys().cloned().collect();
        sessions.sort();
        sessions
    }

    pub fn is_active(&self, session: &SessionId) -> bool {
        self.inner.lock().contains_key(session)
    }

    pub(crate) fn begin(
        &self,
        session: &SessionId,
        connection: &CancellationToken,
    ) -> Result<SessionGuard, DuplicateSession> {
        let mut active = self.inner.lock();
        if active.contains_key(session) {
            return Err(DuplicateSession);
        }
        let generation = self.inner.next_generation.fetch_add(1, Ordering::Relaxed);
        let token = connection.child_token();
        active.insert(
            session.clone(),
            Entry {
                generation,
                token: token.clone(),
            },
        );
        Ok(SessionGuard {
            registry: self.clone(),
            session: session.clone(),
            generation,
            token,
        })
    }

    pub(crate) fn terminate(&self, session: &SessionId) -> bool {
        let token = self
            .inner
            .lock()
            .get(session)
            .map(|entry| entry.token.clone());
        match token {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }
}

pub(crate) struct SessionGuard {
    registry: SessionRegistry,
    session: SessionId,
    generation: u64,
    token: CancellationToken,
}

impl SessionGuard {
    pub(crate) fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut active = self.registry.inner.lock();
        if active
            .get(&self.session)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            active.remove(&self.session);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> SessionId {
        SessionId::new(value).unwrap()
    }

    #[test]
    fn duplicate_sessions_are_refused_and_released_on_drop() {
        let registry = SessionRegistry::new();
        let connection = CancellationToken::new();
        let first = registry.begin(&id("a"), &connection).unwrap();
        assert_eq!(
            registry.begin(&id("a"), &connection).err(),
            Some(DuplicateSession)
        );
        let _second = registry.begin(&id("b"), &connection).unwrap();
        assert_eq!(registry.active(), [id("a"), id("b")]);
        drop(first);
        assert_eq!(registry.active(), [id("b")]);
        assert!(registry.begin(&id("a"), &connection).is_ok());
    }

    #[test]
    fn terminate_cancels_only_the_named_session() {
        let registry = SessionRegistry::new();
        let connection = CancellationToken::new();
        let a = registry.begin(&id("a"), &connection).unwrap();
        let b = registry.begin(&id("b"), &connection).unwrap();
        assert!(registry.terminate(&id("a")));
        assert!(!registry.terminate(&id("missing")));
        assert!(a.token().is_cancelled());
        assert!(!b.token().is_cancelled());
        assert!(!connection.is_cancelled());
    }

    #[test]
    fn connection_cancellation_reaches_every_session() {
        let registry = SessionRegistry::new();
        let connection = CancellationToken::new();
        let a = registry.begin(&id("a"), &connection).unwrap();
        connection.cancel();
        assert!(a.token().is_cancelled());
    }
}
