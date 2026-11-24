use std::collections::HashSet;
use std::time::Duration;

use jaunt_gate::{ConnectedAgents, DisconnectReason};
use jaunt_store::{NodeState, Nodes, StoreError};
use jaunt_tunnel::{BoxFuture, NodeId};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tokio_util::sync::CancellationToken;

pub(crate) trait ActiveNodes: Send + Sync {
    fn active_node_ids(&self) -> BoxFuture<'_, Result<HashSet<String>, StoreError>>;
}

pub(crate) trait Connections: Send + Sync {
    fn connected_nodes(&self) -> Vec<NodeId>;
    fn disconnect_removed(&self, node: &NodeId) -> bool;
}

pub(crate) struct StoreNodes {
    nodes: Nodes,
}

impl StoreNodes {
    pub(crate) fn new(nodes: Nodes) -> Self {
        Self { nodes }
    }
}

impl ActiveNodes for StoreNodes {
    fn active_node_ids(&self) -> BoxFuture<'_, Result<HashSet<String>, StoreError>> {
        Box::pin(async move {
            Ok(self
                .nodes
                .list()
                .await?
                .into_iter()
                .filter(|node| node.state == NodeState::Active)
                .map(|node| node.id)
                .collect())
        })
    }
}

impl Connections for ConnectedAgents {
    fn connected_nodes(&self) -> Vec<NodeId> {
        let mut nodes = ConnectedAgents::connected_nodes(self);
        nodes.extend(self.api_session_nodes());
        nodes.sort();
        nodes.dedup();
        nodes
    }

    fn disconnect_removed(&self, node: &NodeId) -> bool {
        self.disconnect(node, DisconnectReason::Removed)
    }
}

pub(crate) async fn reconcile_once(
    nodes: &dyn ActiveNodes,
    connections: &dyn Connections,
) -> Result<Vec<NodeId>, StoreError> {
    let connected = connections.connected_nodes();
    if connected.is_empty() {
        return Ok(Vec::new());
    }
    let active = nodes.active_node_ids().await?;
    Ok(connected
        .into_iter()
        .filter(|node| !active.contains(node.as_str()) && connections.disconnect_removed(node))
        .collect())
}

pub(crate) async fn run<N, T>(nodes: N, connections: T, every: Duration, stop: CancellationToken)
where
    N: ActiveNodes,
    T: Connections,
{
    let mut ticker = interval_at(Instant::now() + every, every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let outcome = tokio::select! {
            () = stop.cancelled() => return,
            outcome = reconcile_once(&nodes, &connections) => outcome,
        };
        if let Err(error) = outcome {
            tracing::warn!(
                target: "jaunt::agents",
                error = %error,
                "checking connected agents against the node registry failed"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use jaunt_store::StoreError;
    use jaunt_tunnel::{BoxFuture, NodeId};

    use super::{ActiveNodes, Connections, reconcile_once};

    struct FakeNodes {
        active: Option<HashSet<String>>,
        queries: AtomicUsize,
    }

    impl FakeNodes {
        fn active(ids: &[&str]) -> Self {
            Self {
                active: Some(ids.iter().map(|id| (*id).to_owned()).collect()),
                queries: AtomicUsize::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                active: None,
                queries: AtomicUsize::new(0),
            }
        }
    }

    impl ActiveNodes for FakeNodes {
        fn active_node_ids(&self) -> BoxFuture<'_, Result<HashSet<String>, StoreError>> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            let answer = self
                .active
                .clone()
                .ok_or(StoreError::InvalidInput("forced failure"));
            Box::pin(async move { answer })
        }
    }

    struct FakeConnections(Mutex<Vec<NodeId>>);

    impl FakeConnections {
        fn of(ids: &[&str]) -> Self {
            Self(Mutex::new(
                ids.iter().map(|id| NodeId::new(*id).unwrap()).collect(),
            ))
        }

        fn ids(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .map(|node| node.as_str().to_owned())
                .collect()
        }
    }

    impl Connections for FakeConnections {
        fn connected_nodes(&self) -> Vec<NodeId> {
            self.0.lock().unwrap().clone()
        }

        fn disconnect_removed(&self, node: &NodeId) -> bool {
            let mut connected = self.0.lock().unwrap();
            let before = connected.len();
            connected.retain(|candidate| candidate != node);
            connected.len() != before
        }
    }

    #[tokio::test]
    async fn only_connections_of_nodes_that_are_no_longer_active_are_disconnected() {
        let nodes = FakeNodes::active(&["node-a", "node-c"]);
        let connections = FakeConnections::of(&["node-a", "node-b", "node-d"]);

        let removed = reconcile_once(&nodes, &connections).await.unwrap();

        let removed: Vec<&str> = removed.iter().map(NodeId::as_str).collect();
        assert_eq!(removed, ["node-b", "node-d"]);
        assert_eq!(connections.ids(), ["node-a"]);
        assert_eq!(nodes.queries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failing_store_disconnects_nothing() {
        let nodes = FakeNodes::failing();
        let connections = FakeConnections::of(&["node-a"]);

        assert!(reconcile_once(&nodes, &connections).await.is_err());

        assert_eq!(connections.ids(), ["node-a"]);
    }

    #[tokio::test]
    async fn the_store_is_not_queried_while_no_agent_is_connected() {
        let nodes = FakeNodes::active(&[]);
        let connections = FakeConnections::of(&[]);

        assert!(
            reconcile_once(&nodes, &connections)
                .await
                .unwrap()
                .is_empty()
        );

        assert_eq!(nodes.queries.load(Ordering::SeqCst), 0);
    }
}
