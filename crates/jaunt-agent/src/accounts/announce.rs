use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::AgentCapabilities;
use jaunt_tunnel::{BoxFuture, ClientEvent};
use tokio::sync::broadcast;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::accounts::availability::Availability;
use crate::run::api::{AgentApi, ApiError};

pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(60);

const ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(10);

pub trait CapabilitySink: Send + Sync {
    fn announce(&self, capabilities: AgentCapabilities) -> BoxFuture<'_, ()>;
}

pub struct ControlCapabilities {
    api: Arc<AgentApi>,
}

impl ControlCapabilities {
    pub fn new(api: Arc<AgentApi>) -> Self {
        Self { api }
    }
}

impl CapabilitySink for ControlCapabilities {
    fn announce(&self, capabilities: AgentCapabilities) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let answer =
                tokio::time::timeout(ANNOUNCE_TIMEOUT, self.api.capabilities(&capabilities)).await;
            match answer {
                Ok(Ok(())) => tracing::debug!(
                    target: "jaunt::agent",
                    creates_accounts = capabilities.creates_accounts,
                    "announced the capabilities of this node"
                ),
                Ok(Err(ApiError::Status { status: 404, .. })) => tracing::debug!(
                    target: "jaunt::agent",
                    "the control plane does not take capability announcements"
                ),
                Ok(Err(error)) => tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.capabilities_failed",
                    error = %error,
                    "announcing the capabilities of this node failed; retrying later"
                ),
                Err(_) => tracing::warn!(
                    target: "jaunt::agent",
                    event = "agent.capabilities_failed",
                    "announcing the capabilities of this node timed out; retrying later"
                ),
            }
        })
    }
}

pub async fn announce_capabilities(
    availability: Arc<Availability>,
    sink: Arc<dyn CapabilitySink>,
    mut events: broadcast::Receiver<ClientEvent>,
    every: Duration,
    stop: CancellationToken,
) {
    let mut next: Option<Instant> = None;
    let mut helper_listens = false;
    loop {
        let due = async {
            match next {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let connected = tokio::select! {
            () = stop.cancelled() => return,
            () = due => false,
            event = events.recv() => match event {
                Ok(ClientEvent::Connected) | Err(broadcast::error::RecvError::Lagged(_)) => true,
                Ok(ClientEvent::Disconnected { .. }) => {
                    next = None;
                    helper_listens = false;
                    continue;
                }
                Ok(ClientEvent::ConnectFailed(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
        };
        let announced = async {
            if connected {
                helper_listens =
                    availability.creation().is_ok() && availability.helper_listens().await;
            }
            let capabilities = AgentCapabilities {
                creates_accounts: helper_listens && availability.creation().is_ok(),
            };
            sink.announce(capabilities).await;
        };
        tokio::select! {
            () = stop.cancelled() => return,
            () = announced => {}
        }
        next = Some(Instant::now() + every);
    }
}
