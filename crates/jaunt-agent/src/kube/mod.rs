mod audit;
mod body;
mod connection;
mod lease;
mod policy;
mod request;
mod status;
#[cfg(test)]
mod tests;
mod token;
mod upstream;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::{ServiceAnnouncement, ServiceKind, ServiceOutcome};
use jaunt_tunnel::BoxFuture;

use crate::clock::Clock;
use crate::runtime::handler::{
    HandlerError, ServiceConnection, ServiceGrant, ServiceHandler, ServiceSession,
};
use connection::Shared;
use upstream::Upstream;
pub use upstream::{KubernetesUpstream, UpstreamError};

const MAX_WINDOW: u32 = (1 << 31) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KubeLimits {
    pub max_header_bytes: usize,
    pub max_concurrent_streams: u32,
    pub idle_keep_alive: Duration,
    pub ping_interval: Duration,
    pub ping_timeout: Duration,
    pub head_timeout: Duration,
    pub slot_wait: Duration,
    pub progress_timeout: Duration,
    pub connect_timeout: Duration,
    pub shutdown_grace: Duration,
    pub token_reread: Duration,
    pub token_check_every: Duration,
    pub api_connections: usize,
    pub api_streams_per_connection: usize,
    pub slots_per_user: usize,
    pub slots_per_connection: usize,
    pub stream_window: u32,
    pub client_connection_window: u32,
    pub send_buffer: usize,
}

pub const KUBE_LIMITS: KubeLimits = KubeLimits {
    max_header_bytes: 64 * 1024,
    max_concurrent_streams: 128,
    idle_keep_alive: Duration::from_secs(60),
    ping_interval: Duration::from_secs(30),
    ping_timeout: Duration::from_secs(20),
    head_timeout: Duration::from_secs(60),
    slot_wait: Duration::from_secs(60),
    progress_timeout: Duration::from_secs(60),
    connect_timeout: Duration::from_secs(10),
    shutdown_grace: Duration::from_millis(500),
    token_reread: Duration::from_secs(60),
    token_check_every: Duration::from_secs(1),
    api_connections: 16,
    api_streams_per_connection: 100,
    slots_per_user: 256,
    slots_per_connection: 128,
    stream_window: 128 * 1024,
    client_connection_window: 1024 * 1024,
    send_buffer: 256 * 1024,
};

impl KubeLimits {
    pub fn api_connection_window(&self) -> u32 {
        let streams = u32::try_from(self.api_streams_per_connection).unwrap_or(u32::MAX);
        streams
            .saturating_mul(self.stream_window)
            .max(self.stream_window)
            .min(MAX_WINDOW)
    }
}

pub struct KubeParts<'a> {
    pub upstream: &'a KubernetesUpstream,
    pub services: &'a ServiceAnnouncement,
    pub clock: Arc<dyn Clock>,
    pub limits: KubeLimits,
}

pub struct KubeHandler {
    shared: Arc<Shared>,
}

impl KubeHandler {
    pub fn new(parts: KubeParts<'_>) -> Result<Self, UpstreamError> {
        let upstream = Upstream::new(parts.upstream, Arc::clone(&parts.clock), parts.limits)?;
        let audits = parts
            .services
            .services
            .iter()
            .filter(|service| service.kind == ServiceKind::Kubernetes)
            .map(|service| {
                (
                    service.name.clone(),
                    service.kubernetes.unwrap_or_default().audit,
                )
            })
            .collect::<HashMap<_, _>>();
        Ok(Self {
            shared: Arc::new(Shared {
                upstream,
                clock: parts.clock,
                audits,
                users: lease::UserSlots::new(parts.limits.slots_per_user),
                limits: parts.limits,
            }),
        })
    }
}

#[cfg(test)]
impl KubeHandler {
    pub fn open_upstream_connections(&self) -> usize {
        self.shared.upstream.open_connections()
    }
}

pub fn declares_kubernetes(services: &ServiceAnnouncement) -> bool {
    services
        .services
        .iter()
        .any(|service| service.kind == ServiceKind::Kubernetes)
}

impl ServiceHandler for KubeHandler {
    fn serve(
        &self,
        connection: ServiceConnection,
        grant: ServiceGrant,
        session: ServiceSession,
    ) -> BoxFuture<'static, Result<ServiceOutcome, HandlerError>> {
        Box::pin(connection::serve(
            Arc::clone(&self.shared),
            connection,
            grant,
            session,
        ))
    }
}
