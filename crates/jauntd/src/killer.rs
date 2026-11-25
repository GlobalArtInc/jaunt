use std::sync::Arc;

use jaunt_control::{KillOrder, KillReason, KillScope, SessionKiller};
use jaunt_gate::{ConnectedAgents, DisconnectReason, SshGate, TerminationReason};
use jaunt_proto::BoxFuture;
use jaunt_tunnel::{NodeId, SendError, SessionId};

pub struct InProcessKiller {
    agents: ConnectedAgents,
    gate: Option<Arc<SshGate>>,
}

impl InProcessKiller {
    pub fn new(agents: ConnectedAgents, gate: Option<Arc<SshGate>>) -> Self {
        Self { agents, gate }
    }

    fn terminate_sessions(&self, order: &KillOrder) {
        for session in &order.sessions {
            let (Ok(node), Ok(id)) = (
                NodeId::new(session.node_id.as_str()),
                SessionId::new(session.session_id.as_str()),
            ) else {
                tracing::error!(
                    target: "jaunt::daemon",
                    session_id = %session.session_id,
                    node_id = %session.node_id,
                    "a session to terminate has an id the tunnel cannot carry"
                );
                continue;
            };
            match self.agents.registry().terminate_session(&node, &id) {
                Ok(()) => {}
                Err(SendError::NotConnected | SendError::Closed) => tracing::debug!(
                    target: "jaunt::daemon",
                    session_id = %session.session_id,
                    node_id = %session.node_id,
                    "the agent of a terminated session is not connected"
                ),
                Err(error @ SendError::Backlogged) => tracing::warn!(
                    target: "jaunt::daemon",
                    session_id = %session.session_id,
                    node_id = %session.node_id,
                    error = %error,
                    "the agent was not told to terminate a session"
                ),
            }
        }
    }

    fn close_outer(&self, scope: &KillScope, reason: KillReason) {
        if reason != KillReason::Revoked {
            return;
        }
        let reason = TerminationReason::Revoked;
        match scope {
            KillScope::User { user_id } => {
                if let Some(gate) = &self.gate {
                    gate.terminate(user_id, None, reason);
                }
            }
            KillScope::Certificate { user_id, serial } => {
                if let Some(gate) = &self.gate {
                    gate.terminate(user_id, Some(*serial), reason);
                }
            }
            KillScope::Node { node_id } => match NodeId::new(node_id.as_str()) {
                Ok(node) => {
                    self.agents.disconnect(&node, DisconnectReason::Removed);
                }
                Err(_) => tracing::error!(
                    target: "jaunt::daemon",
                    node_id = %node_id,
                    "a revoked node has an id the tunnel cannot carry"
                ),
            },
            KillScope::Sessions => {}
        }
    }
}

impl SessionKiller for InProcessKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.terminate_sessions(order);
        self.close_outer(&order.scope, order.reason);
        Box::pin(async {})
    }
}
