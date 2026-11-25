use std::time::SystemTime;

use jaunt_control::AgentPresence;
use jaunt_gate::ConnectedAgents;
use jaunt_tunnel::NodeId;

pub struct RegistryPresence {
    agents: ConnectedAgents,
}

impl RegistryPresence {
    pub fn new(agents: ConnectedAgents) -> Self {
        Self { agents }
    }
}

impl AgentPresence for RegistryPresence {
    fn connected_since(&self, node_id: &str) -> Option<SystemTime> {
        let node = NodeId::new(node_id).ok()?;
        self.agents.registered_at(&node)
    }
}
