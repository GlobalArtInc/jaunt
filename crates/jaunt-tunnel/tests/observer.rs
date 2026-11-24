use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use jaunt_tunnel::{
    AgentRegistry, ConnectionId, DisconnectReason, NodeId, RegistryObserver, TunnelConnection,
    TunnelOptions,
};
use tokio::io::duplex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const HELLO: &[u8] = b"{\"type\":\"hello\",\"version\":1,\"agent_version\":\"fake/1\"}\n";
const TUNNELS: usize = 300;
const WAIT_LIMIT: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Ledger(Mutex<Vec<(NodeId, DisconnectReason)>>);

impl RegistryObserver for Ledger {
    fn connection_ended(&self, node: &NodeId, _connection: ConnectionId, reason: DisconnectReason) {
        self.0.lock().unwrap().push((node.clone(), reason));
    }
}

async fn fake_tunnel(parent: &CancellationToken) -> (TunnelConnection, JoinHandle<()>) {
    let (gate_io, agent_io) = duplex(64 * 1024);
    let agent = tokio::spawn(async move {
        let mut connection = h2::server::handshake(agent_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let mut send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        send.send_data(Bytes::from_static(HELLO), false).unwrap();
        let _control = (send, request.into_body());
        while let Some(Ok(_)) = connection.accept().await {}
    });
    let connection = TunnelConnection::establish(gate_io, &TunnelOptions::default(), parent)
        .await
        .unwrap();
    (connection, agent)
}

fn node(index: usize) -> NodeId {
    NodeId::new(format!("node-{index}")).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn every_ended_tunnel_reaches_the_observer_with_its_reason_even_in_bulk() {
    let ledger = Arc::new(Ledger::default());
    let registry = AgentRegistry::with_observer(ledger.clone());
    let parent = CancellationToken::new();
    let mut agents = Vec::new();
    for index in 0..TUNNELS {
        let (connection, agent) = fake_tunnel(&parent).await;
        registry.register(node(index), connection).unwrap();
        agents.push(agent);
    }
    let (replacement, agent) = fake_tunnel(&parent).await;
    registry.register(node(0), replacement).unwrap();
    agents.push(agent);
    assert!(registry.disconnect_because(&node(1), DisconnectReason::Removed));
    assert!(!registry.disconnect_because(&node(1), DisconnectReason::Removed));

    tokio::time::timeout(WAIT_LIMIT, registry.shutdown())
        .await
        .unwrap();

    let ended = ledger.0.lock().unwrap().clone();
    let mut by_reason: HashMap<DisconnectReason, Vec<NodeId>> = HashMap::new();
    for (node, reason) in ended {
        by_reason.entry(reason).or_default().push(node);
    }
    assert_eq!(by_reason[&DisconnectReason::Replaced], [node(0)]);
    assert_eq!(by_reason[&DisconnectReason::Removed], [node(1)]);
    assert_eq!(by_reason[&DisconnectReason::Shutdown].len(), TUNNELS - 1);
    assert!(!by_reason[&DisconnectReason::Shutdown].contains(&node(1)));
    assert!(!by_reason.contains_key(&DisconnectReason::Closed));
    for agent in agents {
        tokio::time::timeout(WAIT_LIMIT, agent)
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(ledger.0.lock().unwrap().len(), TUNNELS + 1);
}
