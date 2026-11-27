use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

pub trait AgentPresence: Send + Sync {
    fn connected_since(&self, node_id: &str) -> Option<SystemTime>;
}

#[derive(Default)]
pub(crate) struct PresenceSlot(Mutex<Option<Arc<dyn AgentPresence>>>);

impl PresenceSlot {
    fn lock(&self) -> MutexGuard<'_, Option<Arc<dyn AgentPresence>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn install(&self, presence: Arc<dyn AgentPresence>) {
        *self.lock() = Some(presence);
    }

    pub(crate) fn is_installed(&self) -> bool {
        self.lock().is_some()
    }

    pub(crate) fn connected_since(&self, node_id: &str) -> Option<SystemTime> {
        let presence = self.lock().clone()?;
        presence.connected_since(node_id)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{AgentPresence, PresenceSlot};

    struct One(SystemTime);

    impl AgentPresence for One {
        fn connected_since(&self, node_id: &str) -> Option<SystemTime> {
            (node_id == "node-1").then_some(self.0)
        }
    }

    #[test]
    fn nothing_is_connected_until_a_presence_source_is_installed() {
        let slot = PresenceSlot::default();
        assert_eq!(slot.connected_since("node-1"), None);
        let since = UNIX_EPOCH + Duration::from_secs(10);
        slot.install(Arc::new(One(since)));
        assert_eq!(slot.connected_since("node-1"), Some(since));
        assert_eq!(slot.connected_since("node-2"), None);
    }
}
