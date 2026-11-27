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

    fn terminate_sessions(&self, order: &KillOrder) -> bool {
        let registry = self.agents.registry();
        deliver(order, |node, id| registry.terminate_session(node, id))
    }

    fn close_outer(&self, scope: &KillScope, reason: KillReason) {
        if reason == KillReason::NodeRemoved
            && let KillScope::Node { node_id } = scope
        {
            self.disconnect_node(node_id);
            return;
        }
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
            KillScope::Node { node_id } => self.disconnect_node(node_id),
            KillScope::Sessions => {}
        }
    }

    fn disconnect_node(&self, node_id: &str) {
        match NodeId::new(node_id) {
            Ok(node) => {
                self.agents.disconnect(&node, DisconnectReason::Removed);
            }
            Err(_) => tracing::error!(
                target: "jaunt::daemon",
                node_id = %node_id,
                "a node to disconnect has an id the tunnel cannot carry"
            ),
        }
    }
}

impl SessionKiller for InProcessKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.terminate_sessions(order);
        self.close_outer(&order.scope, order.reason);
        Box::pin(async {})
    }

    fn kill_and_report<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, bool> {
        let delivered = self.terminate_sessions(order);
        self.close_outer(&order.scope, order.reason);
        Box::pin(async move { delivered })
    }
}

fn deliver(order: &KillOrder, send: impl Fn(&NodeId, &SessionId) -> Result<(), SendError>) -> bool {
    let mut delivered = true;
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
            delivered = false;
            continue;
        };
        let sent = send(&node, &id);
        delivered &= sent.is_ok();
        match sent {
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
    delivered
}

#[cfg(test)]
mod tests {
    use jaunt_control::{KillOrder, KillReason, KillScope, KilledSession};
    use jaunt_tunnel::{AgentRegistry, SendError};

    use super::deliver;

    const NODE: &str = "0b9f3a6e-2a51-4d8e-9a67-0f3a8a8d2c11";
    const SESSION: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn order(session_id: &str) -> KillOrder {
        KillOrder {
            scope: KillScope::Sessions,
            reason: KillReason::Terminated,
            sessions: vec![KilledSession {
                session_id: session_id.to_owned(),
                node_id: NODE.to_owned(),
            }],
        }
    }

    #[test]
    fn an_order_is_delivered_only_when_the_node_took_it_for_every_session() {
        let registry = AgentRegistry::new();
        assert!(!deliver(&order(SESSION), |node, id| registry
            .terminate_session(node, id)));
        assert!(deliver(&order(SESSION), |_, _| Ok(())));
        assert!(!deliver(&order(SESSION), |_, _| Err(SendError::Backlogged)));
        assert!(!deliver(&order("not a session id\n"), |_, _| Ok(())));
        let mut two = order(SESSION);
        two.sessions.push(KilledSession {
            session_id: "11111111-2222-4333-8444-555555555555".to_owned(),
            node_id: NODE.to_owned(),
        });
        let mut answers = vec![Err(SendError::NotConnected), Ok(())];
        let answers = std::sync::Mutex::new(&mut answers);
        assert!(!deliver(&two, |_, _| answers
            .lock()
            .unwrap()
            .pop()
            .unwrap()));
    }
}
