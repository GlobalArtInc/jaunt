use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::{MAX_SERVICES_PER_AGENT, NodeServices};
use jaunt_tunnel::{BoxFuture, ClientEvent, ServiceName};
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;

use super::directory::{ApprovedService, stream_kind};
use crate::run::api::{AgentApi, ApiError};
use crate::trust::{Sampler, spread};

pub const MAX_SERVICE_ID_LEN: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalTiming {
    pub every_min: Duration,
    pub every_max: Duration,
}

pub const APPROVAL_TIMING: ApprovalTiming = ApprovalTiming {
    every_min: Duration::from_secs(54),
    every_max: Duration::from_secs(66),
};

pub trait ApprovalSource: Send + Sync {
    fn read(&self) -> BoxFuture<'_, Result<NodeServices, ApiError>>;
}

impl ApprovalSource for AgentApi {
    fn read(&self) -> BoxFuture<'_, Result<NodeServices, ApiError>> {
        Box::pin(self.node_services())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalProblem {
    #[error("the control plane listed more than {MAX_SERVICES_PER_AGENT} approved services")]
    TooMany,
    #[error("the control plane listed a service id that is not an identifier")]
    Id,
    #[error("the control plane listed a service name that is not a DNS label")]
    Name,
}

fn is_service_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_SERVICE_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub fn approved_of(listed: NodeServices) -> Result<Vec<ApprovedService>, ApprovalProblem> {
    if listed.services.len() > MAX_SERVICES_PER_AGENT {
        return Err(ApprovalProblem::TooMany);
    }
    listed
        .services
        .into_iter()
        .map(|service| {
            if !is_service_id(&service.id) {
                return Err(ApprovalProblem::Id);
            }
            Ok(ApprovedService {
                id: service.id,
                kind: stream_kind(service.kind),
                name: ServiceName::new(service.name).map_err(|_| ApprovalProblem::Name)?,
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    Connected,
    Announced,
    Periodic,
}

pub struct ApprovalPoller {
    pub source: Arc<dyn ApprovalSource>,
    pub approved: watch::Sender<Vec<ApprovedService>>,
    pub events: broadcast::Receiver<ClientEvent>,
    pub announced: Arc<Notify>,
    pub sample: Sampler,
    pub timing: ApprovalTiming,
}

impl ApprovalPoller {
    pub async fn run(mut self, stop: CancellationToken) {
        let mut served_by_control = true;
        let mut events_open = true;
        loop {
            let every = spread(
                self.timing.every_min,
                self.timing.every_max,
                (self.sample)(),
            );
            let periodic = async {
                if served_by_control {
                    tokio::time::sleep(every).await;
                } else {
                    std::future::pending::<()>().await;
                }
            };
            let wake = tokio::select! {
                () = stop.cancelled() => return,
                () = self.announced.notified() => Wake::Announced,
                () = periodic => Wake::Periodic,
                event = self.events.recv(), if events_open => match event {
                    Ok(ClientEvent::Connected) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        Wake::Connected
                    }
                    Ok(ClientEvent::Disconnected { .. } | ClientEvent::ConnectFailed(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => {
                        events_open = false;
                        continue;
                    }
                },
            };
            if wake == Wake::Connected {
                served_by_control = true;
            }
            let read = tokio::select! {
                () = stop.cancelled() => return,
                read = self.source.read() => read,
            };
            match read {
                Ok(listed) => {
                    served_by_control = true;
                    match approved_of(listed) {
                        Ok(services) => self.publish(services),
                        Err(problem) => tracing::error!(
                            target: "jaunt::agent",
                            error = %problem,
                            "the control plane listed approved services that cannot be used; the previous set stays in use"
                        ),
                    }
                }
                Err(ApiError::Status {
                    status: 404 | 405, ..
                }) => {
                    if served_by_control {
                        tracing::info!(
                            target: "jaunt::agent",
                            "the control plane does not list the approved services of nodes; only SSH is served until the agent reconnects to a newer server"
                        );
                    }
                    served_by_control = false;
                    self.publish(Vec::new());
                }
                Err(ApiError::NodeRemoved) => {
                    tracing::error!(
                        target: "jaunt::agent",
                        "the server no longer knows this node (node_removed); no service is served"
                    );
                    self.publish(Vec::new());
                }
                Err(ApiError::Shutdown) => return,
                Err(error) => tracing::warn!(
                    target: "jaunt::agent",
                    error = %error,
                    "reading the approved services of this node failed; the previous set stays in use"
                ),
            }
        }
    }

    fn publish(&self, services: Vec<ApprovedService>) {
        self.approved.send_if_modified(|current| {
            if *current == services {
                return false;
            }
            *current = services;
            true
        });
    }
}
