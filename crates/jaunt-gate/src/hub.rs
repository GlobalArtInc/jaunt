use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use jaunt_tunnel::{
    ALPN_AGENT_API, ALPN_TUNNEL, AcceptorConfig, AgentApiConnection, AgentRegistry, BoxFuture,
    ConnectionId, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_HANDSHAKING, DisconnectReason, Gate,
    GateAcceptor, GateError, GateObserver, GateStats, Handover, MainConnection, NodeId,
    OptionsError, PeerAuthenticator, RegistryObserver, RejectReason, Rejection, TlsConfigError,
    TunnelOptions, refusing_server_config,
};
use rustls::ServerConfig;
use socket2::{SockRef, TcpKeepalive};
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout_at};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::{CancellationToken, DropGuard};
use tokio_util::task::TaskTracker;

use crate::audit;

pub const DEFAULT_MAX_API_SESSIONS_PER_NODE: usize = 4;
pub const DEFAULT_MAX_API_SESSIONS: usize = 1024;
const API_KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const API_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub trait AgentApiHandler: Send + Sync {
    fn serve(
        &self,
        node: NodeId,
        stream: TlsStream<TcpStream>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()>;
}

pub struct AgentHubConfig {
    pub server_name: String,
    pub tls: Arc<ServerConfig>,
    pub tunnel: TunnelOptions,
    pub handshake_timeout: Duration,
    pub max_handshaking: usize,
    pub max_api_sessions_per_node: usize,
    pub max_api_sessions: usize,
}

impl AgentHubConfig {
    pub fn new(server_name: impl Into<String>, tls: Arc<ServerConfig>) -> Self {
        Self {
            server_name: server_name.into(),
            tls,
            tunnel: TunnelOptions::default(),
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_handshaking: DEFAULT_MAX_HANDSHAKING,
            max_api_sessions_per_node: DEFAULT_MAX_API_SESSIONS_PER_NODE,
            max_api_sessions: DEFAULT_MAX_API_SESSIONS,
        }
    }
}

#[derive(Debug, Error)]
pub enum HubError {
    #[error("no tokio runtime is running")]
    NoRuntime,
    #[error("the agents' listener has no local address")]
    LocalAddr(#[source] io::Error),
    #[error("the agents' tls configuration is invalid")]
    Tls(#[from] TlsConfigError),
    #[error("the agents' connection options are invalid")]
    Options(#[from] OptionsError),
    #[error("the agent api session limits must be at least one")]
    SessionLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownReport {
    pub tunnels_closed: bool,
    pub api_sessions_ended: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HubStatsSnapshot {
    pub no_certificate: u64,
    pub api_sessions_refused_per_node: u64,
    pub api_sessions_refused_global: u64,
    pub api_sessions_open: usize,
}

#[derive(Debug, Default)]
struct Counters {
    no_certificate: AtomicU64,
    refused_per_node: AtomicU64,
    refused_global: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NodeFull,
    HubFull,
}

impl Counters {
    fn refused(&self, refusal: Refusal) {
        let counter = match refusal {
            Refusal::NodeFull => &self.refused_per_node,
            Refusal::HubFull => &self.refused_global,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

type EndReason = Arc<OnceLock<DisconnectReason>>;

struct NodeSessions {
    count: usize,
    token: CancellationToken,
    reason: EndReason,
}

impl NodeSessions {
    fn new(parent: &CancellationToken) -> Self {
        Self {
            count: 0,
            token: parent.child_token(),
            reason: Arc::new(OnceLock::new()),
        }
    }
}

#[derive(Default)]
struct OpenSessions {
    by_node: HashMap<NodeId, NodeSessions>,
    total: usize,
}

struct SessionBook {
    per_node: usize,
    total: usize,
    parent: CancellationToken,
    open: Mutex<OpenSessions>,
}

impl SessionBook {
    fn open(&self) -> MutexGuard<'_, OpenSessions> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn admit(self: &Arc<Self>, node: &NodeId) -> Result<SessionSlot, Refusal> {
        let mut open = self.open();
        if open.total >= self.total {
            return Err(Refusal::HubFull);
        }
        if open
            .by_node
            .get(node)
            .is_some_and(|sessions| sessions.count >= self.per_node)
        {
            return Err(Refusal::NodeFull);
        }
        let sessions = open
            .by_node
            .entry(node.clone())
            .or_insert_with(|| NodeSessions::new(&self.parent));
        sessions.count += 1;
        let token = sessions.token.child_token();
        let reason = sessions.reason.clone();
        open.total += 1;
        Ok(SessionSlot {
            book: self.clone(),
            node: node.clone(),
            token,
            reason,
        })
    }

    fn cancel_node(&self, node: &NodeId, reason: DisconnectReason) -> bool {
        let mut open = self.open();
        let Some(sessions) = open.by_node.get_mut(node) else {
            return false;
        };
        sessions.reason.get_or_init(|| reason);
        sessions.token.cancel();
        sessions.token = self.parent.child_token();
        sessions.reason = Arc::new(OnceLock::new());
        sessions.count > 0
    }

    fn nodes(&self) -> Vec<NodeId> {
        self.open().by_node.keys().cloned().collect()
    }

    fn release(&self, node: &NodeId) {
        let mut open = self.open();
        open.total = open.total.saturating_sub(1);
        let emptied = open.by_node.get_mut(node).is_some_and(|sessions| {
            sessions.count = sessions.count.saturating_sub(1);
            sessions.count == 0
        });
        if emptied {
            open.by_node.remove(node);
        }
    }
}

struct SessionSlot {
    book: Arc<SessionBook>,
    node: NodeId,
    token: CancellationToken,
    reason: EndReason,
}

impl SessionSlot {
    fn end_reason(&self) -> DisconnectReason {
        match self.reason.get() {
            Some(reason) => *reason,
            None if self.token.is_cancelled() => DisconnectReason::Shutdown,
            None => DisconnectReason::Closed,
        }
    }
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.book.release(&self.node);
    }
}

struct TunnelLedger;

impl RegistryObserver for TunnelLedger {
    fn connection_ended(&self, node: &NodeId, _connection: ConnectionId, reason: DisconnectReason) {
        audit::disconnected(node, reason, ALPN_TUNNEL);
    }
}

#[derive(Clone)]
pub struct ConnectedAgents {
    registry: AgentRegistry,
    book: Arc<SessionBook>,
}

impl ConnectedAgents {
    pub fn registry(&self) -> &AgentRegistry {
        &self.registry
    }

    pub fn connected_nodes(&self) -> Vec<NodeId> {
        self.registry.connected_nodes()
    }

    pub fn api_session_nodes(&self) -> Vec<NodeId> {
        self.book.nodes()
    }

    pub fn disconnect(&self, node: &NodeId, reason: DisconnectReason) -> bool {
        let tunnel = self.registry.disconnect_because(node, reason);
        let sessions = self.book.cancel_node(node, reason);
        tunnel || sessions
    }
}

struct Glue {
    handler: Arc<dyn AgentApiHandler>,
    sessions: TaskTracker,
    book: Arc<SessionBook>,
    counters: Counters,
    shutdown: CancellationToken,
}

impl Handover for Glue {
    fn main(&self, connection: MainConnection) {
        drop(connection);
    }

    fn agent_api(&self, connection: AgentApiConnection) {
        let AgentApiConnection {
            stream,
            node,
            peer_addr,
            ..
        } = connection;
        let slot = match self.book.admit(&node) {
            Ok(slot) => slot,
            Err(refusal) => {
                self.counters.refused(refusal);
                audit::rejected(
                    peer_addr,
                    &Rejection::of_node(RejectReason::TooManySessions, node),
                );
                drop(stream);
                return;
            }
        };
        enable_keepalive(stream.get_ref().0);
        audit::connected(&node, peer_addr, ALPN_AGENT_API, false);
        let session = self.handler.serve(node.clone(), stream, slot.token.clone());
        self.sessions.spawn(async move {
            session.await;
            let reason = slot.end_reason();
            drop(slot);
            audit::disconnected(&node, reason, ALPN_AGENT_API);
        });
    }
}

impl GateObserver for Glue {
    fn tunnel_registered(&self, node: &NodeId, peer_addr: SocketAddr, replaced: bool) {
        audit::connected(node, peer_addr, ALPN_TUNNEL, replaced);
    }

    fn peer_rejected(&self, peer_addr: SocketAddr, rejection: &Rejection) {
        if rejection.reason == RejectReason::NoCertificate {
            self.counters.no_certificate.fetch_add(1, Ordering::Relaxed);
        }
        audit::rejected(peer_addr, rejection);
    }
}

fn enable_keepalive(tcp: &TcpStream) {
    let keepalive = TcpKeepalive::new()
        .with_time(API_KEEPALIVE_TIME)
        .with_interval(API_KEEPALIVE_INTERVAL);
    if let Err(error) = SockRef::from(tcp).set_tcp_keepalive(&keepalive) {
        tracing::warn!(
            target: "jaunt::agents",
            error = %error,
            "tcp keepalive could not be enabled on an agent api connection"
        );
    }
}

pub struct AgentHub {
    agents: ConnectedAgents,
    stats: Arc<GateStats>,
    local_addr: SocketAddr,
    glue: Arc<Glue>,
    accept: JoinHandle<Result<(), GateError>>,
    stop_connections: DropGuard,
}

impl AgentHub {
    pub fn start<A, H>(
        listener: TcpListener,
        config: AgentHubConfig,
        authenticator: Arc<A>,
        handler: Arc<H>,
    ) -> Result<Self, HubError>
    where
        A: PeerAuthenticator + 'static,
        H: AgentApiHandler + 'static,
    {
        Handle::try_current().map_err(|_| HubError::NoRuntime)?;
        if config.max_api_sessions_per_node == 0 || config.max_api_sessions == 0 {
            return Err(HubError::SessionLimits);
        }
        let local_addr = listener.local_addr().map_err(HubError::LocalAddr)?;
        let mut acceptor_config = AcceptorConfig::new(
            vec![config.server_name],
            config.tls,
            Arc::new(refusing_server_config()?),
        );
        acceptor_config.handshake_timeout = config.handshake_timeout;
        acceptor_config.max_handshaking = config.max_handshaking;
        let stats = Arc::new(GateStats::default());
        let acceptor = GateAcceptor::new(acceptor_config, stats.clone())?;
        let registry = AgentRegistry::with_observer(Arc::new(TunnelLedger));
        let connections = CancellationToken::new();
        let shutdown = connections.child_token();
        let book = Arc::new(SessionBook {
            per_node: config.max_api_sessions_per_node,
            total: config.max_api_sessions,
            parent: shutdown.clone(),
            open: Mutex::new(OpenSessions::default()),
        });
        let glue = Arc::new(Glue {
            handler,
            sessions: TaskTracker::new(),
            book: book.clone(),
            counters: Counters::default(),
            shutdown,
        });
        let gate = Gate::new(
            acceptor,
            registry.clone(),
            authenticator,
            glue.clone(),
            config.tunnel,
        )?
        .with_observer(glue.clone());
        let token = connections.clone();
        let accept = tokio::spawn(async move { gate.serve(listener, token).await });
        Ok(Self {
            agents: ConnectedAgents { registry, book },
            stats,
            local_addr,
            glue,
            accept,
            stop_connections: connections.drop_guard(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn registry(&self) -> &AgentRegistry {
        self.agents.registry()
    }

    pub fn agents(&self) -> ConnectedAgents {
        self.agents.clone()
    }

    pub fn stats(&self) -> &Arc<GateStats> {
        &self.stats
    }

    pub fn hub_stats(&self) -> HubStatsSnapshot {
        let counters = &self.glue.counters;
        HubStatsSnapshot {
            no_certificate: counters.no_certificate.load(Ordering::Relaxed),
            api_sessions_refused_per_node: counters.refused_per_node.load(Ordering::Relaxed),
            api_sessions_refused_global: counters.refused_global.load(Ordering::Relaxed),
            api_sessions_open: self.glue.book.open().total,
        }
    }

    pub async fn shutdown(self, grace: Duration) -> ShutdownReport {
        let deadline = Instant::now() + grace;
        let Self {
            agents,
            glue,
            accept,
            stop_connections,
            ..
        } = self;
        accept.abort();
        match accept.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(target: "jaunt::agents", error = %error, "the agents' accept loop failed");
            }
            Err(error) if error.is_cancelled() => {}
            Err(_) => {
                tracing::error!(target: "jaunt::agents", "the agents' accept loop panicked");
            }
        }
        glue.shutdown.cancel();
        glue.sessions.close();
        let (tunnels, sessions) = tokio::join!(
            timeout_at(deadline, agents.registry.shutdown()),
            timeout_at(deadline, glue.sessions.wait()),
        );
        drop(stop_connections);
        let report = ShutdownReport {
            tunnels_closed: tunnels.is_ok(),
            api_sessions_ended: sessions.is_ok(),
        };
        if !(report.tunnels_closed && report.api_sessions_ended) {
            tracing::warn!(
                target: "jaunt::agents",
                tunnels_closed = report.tunnels_closed,
                api_sessions_ended = report.api_sessions_ended,
                "agent connections did not finish within the shutdown grace"
            );
        }
        report
    }
}
