use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::broadcast;

use crate::control::ServerMessage;
use crate::h2io::H2Io;
use crate::proto::{NodeId, SessionId, StreamMeta};
use crate::server::{ConnectionId, OpenError, SendError, StreamOpener, TunnelConnection};

const EVENT_BACKLOG: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryEvent {
    Connected {
        node: NodeId,
        connection: ConnectionId,
    },
    Replaced {
        node: NodeId,
        previous: ConnectionId,
        connection: ConnectionId,
    },
    Disconnected {
        node: NodeId,
        connection: ConnectionId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RegisterError {
    #[error("no tokio runtime is running")]
    NoRuntime,
}

struct RegistryInner {
    connections: Mutex<HashMap<NodeId, TunnelConnection>>,
    events: broadcast::Sender<RegistryEvent>,
}

impl RegistryInner {
    fn lock(&self) -> MutexGuard<'_, HashMap<NodeId, TunnelConnection>> {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, event: RegistryEvent) {
        drop(self.events.send(event));
    }

    fn connection_ended(&self, node: &NodeId, connection: ConnectionId) {
        let removed = {
            let mut connections = self.lock();
            match connections.get(node) {
                Some(current) if current.id() == connection => {
                    let removed = connections.remove(node);
                    self.publish(RegistryEvent::Disconnected {
                        node: node.clone(),
                        connection,
                    });
                    removed
                }
                _ => None,
            }
        };
        drop(removed);
    }
}

#[derive(Clone)]
pub struct AgentRegistry {
    inner: Arc<RegistryInner>,
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentRegistry {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        Self {
            inner: Arc::new(RegistryInner {
                connections: Mutex::new(HashMap::new()),
                events,
            }),
        }
    }

    pub fn register(
        &self,
        node: NodeId,
        connection: TunnelConnection,
    ) -> Result<ConnectionId, RegisterError> {
        let runtime = Handle::try_current().map_err(|_| RegisterError::NoRuntime)?;
        let id = connection.id();
        let closed = connection.closed_token();
        let replaced = {
            let mut connections = self.inner.lock();
            let previous = connections.insert(node.clone(), connection);
            self.inner.publish(match &previous {
                Some(old) => RegistryEvent::Replaced {
                    node: node.clone(),
                    previous: old.id(),
                    connection: id,
                },
                None => RegistryEvent::Connected {
                    node: node.clone(),
                    connection: id,
                },
            });
            previous
        };
        drop(replaced);
        let inner = self.inner.clone();
        runtime.spawn(async move {
            closed.cancelled().await;
            inner.connection_ended(&node, id);
        });
        Ok(id)
    }

    pub async fn open_stream(&self, node: &NodeId, meta: &StreamMeta) -> Result<H2Io, OpenError> {
        let opener = self.opener(node).ok_or(OpenError::NotConnected)?;
        opener.open(meta).await
    }

    pub fn terminate_session(&self, node: &NodeId, session: &SessionId) -> Result<(), SendError> {
        self.send_control(
            node,
            ServerMessage::TerminateSession {
                session: session.clone(),
            },
        )
    }

    pub fn send_trust_update(&self, node: &NodeId) -> Result<(), SendError> {
        self.send_control(node, ServerMessage::TrustUpdate {})
    }

    pub fn disconnect(&self, node: &NodeId) -> bool {
        let removed = {
            let mut connections = self.inner.lock();
            let removed = connections.remove(node);
            if let Some(connection) = &removed {
                self.inner.publish(RegistryEvent::Disconnected {
                    node: node.clone(),
                    connection: connection.id(),
                });
            }
            removed
        };
        removed.is_some()
    }

    pub fn is_connected(&self, node: &NodeId) -> bool {
        self.inner.lock().contains_key(node)
    }

    pub fn connected_nodes(&self) -> Vec<NodeId> {
        let mut nodes: Vec<NodeId> = self.inner.lock().keys().cloned().collect();
        nodes.sort();
        nodes
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RegistryEvent> {
        self.inner.events.subscribe()
    }

    fn opener(&self, node: &NodeId) -> Option<StreamOpener> {
        self.inner.lock().get(node).map(TunnelConnection::opener)
    }

    fn send_control(&self, node: &NodeId, message: ServerMessage) -> Result<(), SendError> {
        let connections = self.inner.lock();
        let connection = connections.get(node).ok_or(SendError::NotConnected)?;
        connection.queue_control(message)
    }
}
