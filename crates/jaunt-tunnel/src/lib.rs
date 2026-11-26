use std::future::Future;
use std::pin::Pin;

use thiserror::Error;

mod backoff;
mod client;
mod control;
mod gate;
mod h2io;
mod options;
mod proto;
mod registry;
mod server;
mod session;
mod stats;
mod tls;

pub use backoff::{Backoff, BackoffPolicy};
pub use client::{
    ClientError, ClientEvent, ConnectFailure, IncomingStream, NoServedKinds, ServedKinds,
    StreamHandler, TunnelClient, TunnelClientConfig,
};
pub use control::ControlError;
pub use gate::{AgentApiConnection, Gate, GateError, GateObserver, Handover, MainConnection};
pub use h2io::{H2Io, StreamAborted};
pub use options::{
    DEFAULT_CONNECTION_WINDOW, DEFAULT_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_HEADER_LIST_SIZE,
    DEFAULT_STREAM_WINDOW, Keepalive, MAX_HANDSHAKING_LIMIT, MAX_HEADER_LIST_SIZE,
    MAX_STREAM_LIMIT, MAX_TIMER, MAX_WINDOW, MIN_HEADER_LIST_SIZE, OptionsError, TunnelOptions,
};
pub use proto::{
    ALPN_AGENT_API, ALPN_TUNNEL, CONTROL_VERSION, HEADER_CLIENT, HEADER_KIND, HEADER_SERVICE,
    HEADER_SESSION, InvalidNodeId, MAX_CLIENT_ADDRESS_LEN, MAX_CONTROL_MESSAGE_BYTES,
    MAX_NODE_ID_LEN, MAX_SERVICE_NAME_LEN, MAX_SESSION_ID_LEN, MetaError, NodeId, ServiceName,
    SessionId, StreamKind, StreamMeta,
};
pub use registry::{
    AgentRegistry, DisconnectReason, RegisterError, RegistryEvent, RegistryObserver, TrustBroadcast,
};
pub use server::{ConnectionId, OpenError, SendError, TunnelConnection, TunnelError};
pub use session::SessionRegistry;
pub use stats::{GateStats, GateStatsSnapshot};
pub use tls::{
    AcceptError, Accepted, AcceptorConfig, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_HANDSHAKING,
    GateAcceptor, HandshakePermit, PeerStream, RotatingCertificate, SwappableClientCert,
    TlsConfigError, agent_client_config, agent_client_config_swappable, agent_server_config,
    main_server_config, refusing_server_config, rotating_agent_server_config,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    NoCertificate,
    UnknownNode,
    Inactive,
    KeyMismatch,
    Timeout,
    Unavailable,
    TooManySessions,
}

impl RejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCertificate => "no_certificate",
            Self::UnknownNode => "unknown_node",
            Self::Inactive => "inactive",
            Self::KeyMismatch => "key_mismatch",
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::TooManySessions => "too_many_sessions",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("peer was rejected: {}", .reason.as_str())]
pub struct Rejection {
    pub reason: RejectReason,
    pub node: Option<NodeId>,
}

impl Rejection {
    pub fn new(reason: RejectReason) -> Self {
        Self { reason, node: None }
    }

    pub fn of_node(reason: RejectReason, node: NodeId) -> Self {
        Self {
            reason,
            node: Some(node),
        }
    }
}

impl From<InvalidNodeId> for Rejection {
    fn from(_: InvalidNodeId) -> Self {
        Self::new(RejectReason::UnknownNode)
    }
}

pub trait PeerAuthenticator: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>>;
}
