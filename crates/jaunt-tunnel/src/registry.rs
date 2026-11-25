use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::SystemTime;

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
        registered_at: SystemTime,
    },
    Replaced {
        node: NodeId,
        previous: ConnectionId,
        connection: ConnectionId,
        registered_at: SystemTime,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectReason {
    Closed,
    Replaced,
    Removed,
    Requested,
    Shutdown,
}

impl DisconnectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Replaced => "replaced",
            Self::Removed => "removed",
            Self::Requested => "requested",
            Self::Shutdown => "shutdown",
        }
    }
}

pub trait RegistryObserver: Send + Sync {
    fn connection_ended(&self, node: &NodeId, connection: ConnectionId, reason: DisconnectReason);
}

struct Registered {
    connection: TunnelConnection,
    at: SystemTime,
}

struct RegistryInner {
    connections: Mutex<HashMap<NodeId, Registered>>,
    events: broadcast::Sender<RegistryEvent>,
    observer: Option<Arc<dyn RegistryObserver>>,
}

impl RegistryInner {
    fn lock(&self) -> MutexGuard<'_, HashMap<NodeId, Registered>> {
        self.connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn publish(&self, event: RegistryEvent) {
        drop(self.events.send(event));
    }

    fn ended(&self, node: &NodeId, connection: ConnectionId, reason: DisconnectReason) {
        if let Some(observer) = &self.observer {
            observer.connection_ended(node, connection, reason);
        }
    }

    fn connection_ended(&self, node: &NodeId, connection: ConnectionId) {
        let removed = {
            let mut connections = self.lock();
            match connections.get(node) {
                Some(current) if current.connection.id() == connection => {
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
        if removed.is_some() {
            self.ended(node, connection, DisconnectReason::Closed);
        }
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
        Self::build(None)
    }

    pub fn with_observer(observer: Arc<dyn RegistryObserver>) -> Self {
        Self::build(Some(observer))
    }

    fn build(observer: Option<Arc<dyn RegistryObserver>>) -> Self {
        let (events, _) = broadcast::channel(EVENT_BACKLOG);
        Self {
            inner: Arc::new(RegistryInner {
                connections: Mutex::new(HashMap::new()),
                events,
                observer,
            }),
        }
    }

    pub fn register(
        &self,
        node: NodeId,
        connection: TunnelConnection,
    ) -> Result<ConnectionId, RegisterError> {
        self.register_tracked(node, connection).map(|(id, _)| id)
    }

    pub(crate) fn register_tracked(
        &self,
        node: NodeId,
        connection: TunnelConnection,
    ) -> Result<(ConnectionId, bool), RegisterError> {
        let runtime = Handle::try_current().map_err(|_| RegisterError::NoRuntime)?;
        let id = connection.id();
        let closed = connection.closed_token();
        let replaced = {
            let mut connections = self.inner.lock();
            let registered_at = SystemTime::now();
            let previous = connections
                .insert(
                    node.clone(),
                    Registered {
                        connection,
                        at: registered_at,
                    },
                )
                .map(|old| old.connection);
            self.inner.publish(match &previous {
                Some(old) => RegistryEvent::Replaced {
                    node: node.clone(),
                    previous: old.id(),
                    connection: id,
                    registered_at,
                },
                None => RegistryEvent::Connected {
                    node: node.clone(),
                    connection: id,
                    registered_at,
                },
            });
            previous
        };
        let was_replaced = replaced.is_some();
        let inner = self.inner.clone();
        let watched = node.clone();
        runtime.spawn(async move {
            closed.cancelled().await;
            inner.connection_ended(&watched, id);
        });
        if let Some(previous) = &replaced {
            self.inner
                .ended(&node, previous.id(), DisconnectReason::Replaced);
        }
        drop(replaced);
        Ok((id, was_replaced))
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
        self.disconnect_because(node, DisconnectReason::Requested)
    }

    pub fn disconnect_because(&self, node: &NodeId, reason: DisconnectReason) -> bool {
        let removed = {
            let mut connections = self.inner.lock();
            let removed = connections.remove(node).map(|old| old.connection);
            if let Some(connection) = &removed {
                self.inner.publish(RegistryEvent::Disconnected {
                    node: node.clone(),
                    connection: connection.id(),
                });
            }
            removed
        };
        let Some(connection) = removed else {
            return false;
        };
        self.inner.ended(node, connection.id(), reason);
        drop(connection);
        true
    }

    pub fn shutdown(&self) -> impl Future<Output = ()> + Send + 'static {
        let drained: Vec<(NodeId, TunnelConnection)> = {
            let mut connections = self.inner.lock();
            connections
                .drain()
                .map(|(node, registered)| (node, registered.connection))
                .inspect(|(node, connection)| {
                    self.inner.publish(RegistryEvent::Disconnected {
                        node: node.clone(),
                        connection: connection.id(),
                    });
                })
                .collect()
        };
        for (node, connection) in &drained {
            self.inner
                .ended(node, connection.id(), DisconnectReason::Shutdown);
        }
        let finished: Vec<_> = drained
            .iter()
            .map(|(_, connection)| connection.finished_token())
            .collect();
        drop(drained);
        async move {
            for token in finished {
                token.cancelled().await;
            }
        }
    }

    pub fn is_connected(&self, node: &NodeId) -> bool {
        self.inner.lock().contains_key(node)
    }

    pub fn registered_at(&self, node: &NodeId) -> Option<SystemTime> {
        self.inner.lock().get(node).map(|registered| registered.at)
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
        self.inner
            .lock()
            .get(node)
            .map(|registered| registered.connection.opener())
    }

    fn send_control(&self, node: &NodeId, message: ServerMessage) -> Result<(), SendError> {
        let connections = self.inner.lock();
        let registered = connections.get(node).ok_or(SendError::NotConnected)?;
        registered.connection.queue_control(message)
    }
}
