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
    ClientError, ClientEvent, ConnectFailure, IncomingStream, StreamHandler, TunnelClient,
    TunnelClientConfig,
};
pub use control::ControlError;
pub use gate::{AgentApiConnection, Gate, GateError, Handover, MainConnection};
pub use h2io::{H2Io, StreamAborted};
pub use options::{
    DEFAULT_CONNECTION_WINDOW, DEFAULT_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_HEADER_LIST_SIZE,
    DEFAULT_STREAM_WINDOW, Keepalive, MAX_HANDSHAKING_LIMIT, MAX_HEADER_LIST_SIZE,
    MAX_STREAM_LIMIT, MAX_TIMER, MAX_WINDOW, MIN_HEADER_LIST_SIZE, OptionsError, TunnelOptions,
};
pub use proto::{
    ALPN_AGENT_API, ALPN_TUNNEL, CONTROL_VERSION, HEADER_CLIENT, HEADER_KIND, HEADER_SESSION,
    InvalidNodeId, MAX_CLIENT_ADDRESS_LEN, MAX_CONTROL_MESSAGE_BYTES, MAX_NODE_ID_LEN,
    MAX_SESSION_ID_LEN, MetaError, NodeId, SessionId, StreamKind, StreamMeta,
};
pub use registry::{AgentRegistry, RegisterError, RegistryEvent};
pub use server::{ConnectionId, OpenError, SendError, TunnelConnection, TunnelError};
pub use session::SessionRegistry;
pub use stats::{GateStats, GateStatsSnapshot};
pub use tls::{
    AcceptError, Accepted, AcceptorConfig, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_HANDSHAKING,
    GateAcceptor, HandshakePermit, PeerStream, TlsConfigError, agent_client_config,
    agent_server_config, main_server_config,
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("peer was rejected")]
pub struct Rejection;

impl From<InvalidNodeId> for Rejection {
    fn from(_: InvalidNodeId) -> Self {
        Self
    }
}

pub trait PeerAuthenticator: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>>;
}
