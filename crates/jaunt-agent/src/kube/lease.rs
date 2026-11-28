use std::sync::Arc;

use jaunt_limits::{ConcurrencyGuard, ConcurrencyLimiter};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const USERS_TRACKED: usize = 64 * 1024;

pub(crate) struct UserSlots(ConcurrencyLimiter<String>);

impl UserSlots {
    pub(crate) fn new(per_user: usize) -> Self {
        Self(ConcurrencyLimiter::new(per_user, USERS_TRACKED))
    }
}

pub(crate) struct ConnectionSlots {
    user: String,
    slots: Arc<Semaphore>,
}

impl ConnectionSlots {
    pub(crate) fn new(user: &str, per_connection: usize) -> Self {
        Self {
            user: user.to_owned(),
            slots: Arc::new(Semaphore::new(per_connection)),
        }
    }

    pub(crate) fn lease(&self, users: &UserSlots) -> Option<Lease> {
        let connection = Arc::clone(&self.slots).try_acquire_owned().ok()?;
        let user = users.0.try_acquire(self.user.clone()).ok()?;
        Some(Lease {
            _user: user,
            _connection: connection,
        })
    }
}

pub(crate) struct Lease {
    _user: ConcurrencyGuard<String>,
    _connection: OwnedSemaphorePermit,
}
