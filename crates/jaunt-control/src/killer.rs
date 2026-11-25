use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use jaunt_proto::BoxFuture;
use jaunt_store::Session;

use crate::revocation_audit;
use crate::web::terminal::LiveTerminals;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KillReason {
    Revoked,
    Expired,
    AgentGone,
    NodeRemoved,
}

impl KillReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            KillReason::Revoked => "revoked",
            KillReason::Expired => "expired",
            KillReason::AgentGone => "agent_gone",
            KillReason::NodeRemoved => "node_removed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KillScope {
    User { user_id: String },
    Certificate { user_id: String, serial: u64 },
    Node { node_id: String },
    Sessions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KilledSession {
    pub session_id: String,
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillOrder {
    pub scope: KillScope,
    pub reason: KillReason,
    pub sessions: Vec<KilledSession>,
}

pub trait SessionKiller: Send + Sync {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()>;
}

#[derive(Default)]
pub(crate) struct KillerSlot {
    killer: Mutex<Option<Arc<dyn SessionKiller>>>,
    terminals: OnceLock<Arc<LiveTerminals>>,
}

impl KillerSlot {
    fn lock(&self) -> MutexGuard<'_, Option<Arc<dyn SessionKiller>>> {
        self.killer.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn watch_terminals(&self, terminals: Arc<LiveTerminals>) {
        self.terminals.get_or_init(|| terminals);
    }

    pub(crate) fn install(&self, killer: Arc<dyn SessionKiller>) {
        *self.lock() = Some(killer);
    }

    pub(crate) fn current(&self) -> Option<Arc<dyn SessionKiller>> {
        self.lock().clone()
    }

    pub(crate) async fn order(
        &self,
        scope: KillScope,
        reason: KillReason,
        sessions: &[Session],
    ) -> bool {
        if let Some(terminals) = self.terminals.get() {
            terminals.stop_matching(&scope, reason, sessions);
        }
        let Some(killer) = self.current() else {
            if !sessions.is_empty() {
                tracing::warn!(
                    target: "jaunt::control",
                    sessions = sessions.len(),
                    reason = reason.as_str(),
                    "sessions were closed in the database but no live session killer runs in this process"
                );
            }
            return false;
        };
        let order = KillOrder {
            scope,
            reason,
            sessions: sessions
                .iter()
                .map(|session| KilledSession {
                    session_id: session.id.clone(),
                    node_id: session.node_id.clone(),
                })
                .collect(),
        };
        killer.kill(&order).await;
        for session in sessions {
            revocation_audit::session_terminated(session, reason);
        }
        true
    }
}
