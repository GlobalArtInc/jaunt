use std::sync::Arc;
use std::time::Duration;

use jaunt_proto::ServiceAnnouncement;
use jaunt_tunnel::{BoxFuture, ClientEvent};
use tokio::sync::{Notify, broadcast};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::run::api::{AgentApi, ApiError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceTiming {
    pub first_retry: Duration,
    pub max_retry: Duration,
    pub call_timeout: Duration,
}

pub const ANNOUNCE_TIMING: AnnounceTiming = AnnounceTiming {
    first_retry: Duration::from_secs(5),
    max_retry: Duration::from_secs(300),
    call_timeout: Duration::from_secs(10),
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    Accepted,
    Unsupported,
    Refused(String),
    Retry(Option<Duration>),
}

pub trait ServiceSink: Send + Sync {
    fn announce<'a>(&'a self, announcement: &'a ServiceAnnouncement) -> BoxFuture<'a, Delivery>;
}

pub struct ControlServices {
    api: Arc<AgentApi>,
    timeout: Duration,
}

impl ControlServices {
    pub fn new(api: Arc<AgentApi>, timeout: Duration) -> Self {
        Self { api, timeout }
    }
}

pub fn delivery_of(answer: Result<(), ApiError>) -> Delivery {
    match answer {
        Ok(()) => Delivery::Accepted,
        Err(ApiError::Status { status: 404, .. }) => Delivery::Unsupported,
        Err(ApiError::Status {
            status: 429,
            retry_after,
            ..
        }) => Delivery::Retry(retry_after),
        Err(ApiError::Status { status, code, .. }) if (400..500).contains(&status) => {
            Delivery::Refused(format!("HTTP {status} ({code})"))
        }
        Err(error @ (ApiError::NodeRemoved | ApiError::Unauthorized)) => {
            Delivery::Refused(error.to_string())
        }
        Err(_) => Delivery::Retry(None),
    }
}

impl ServiceSink for ControlServices {
    fn announce<'a>(&'a self, announcement: &'a ServiceAnnouncement) -> BoxFuture<'a, Delivery> {
        Box::pin(async move {
            match tokio::time::timeout(self.timeout, self.api.services(announcement)).await {
                Ok(answer) => delivery_of(answer),
                Err(_) => Delivery::Retry(None),
            }
        })
    }
}

pub struct AnnouncedSink {
    pub inner: Arc<dyn ServiceSink>,
    pub announced: Arc<Notify>,
}

impl ServiceSink for AnnouncedSink {
    fn announce<'a>(&'a self, announcement: &'a ServiceAnnouncement) -> BoxFuture<'a, Delivery> {
        Box::pin(async move {
            let delivery = self.inner.announce(announcement).await;
            if delivery == Delivery::Accepted {
                self.announced.notify_one();
            }
            delivery
        })
    }
}

fn report(delivery: &Delivery, announcement: &ServiceAnnouncement) {
    match delivery {
        Delivery::Accepted => tracing::info!(
            target: "jaunt::agent",
            services = announcement.services.len(),
            ssh_enabled = announcement.ssh_enabled,
            "announced the services of this node; new or changed services wait for an administrator"
        ),
        Delivery::Unsupported => tracing::debug!(
            target: "jaunt::agent",
            "the control plane does not take service announcements"
        ),
        Delivery::Refused(reason) => tracing::error!(
            target: "jaunt::agent",
            event = "agent.services_refused",
            reason = reason.as_str(),
            "the control plane refused the services of this node; they are announced again at the next connection"
        ),
        Delivery::Retry(_) => tracing::warn!(
            target: "jaunt::agent",
            event = "agent.services_failed",
            "announcing the services of this node failed; retrying"
        ),
    }
}

pub async fn announce_services(
    announcement: Arc<ServiceAnnouncement>,
    sink: Arc<dyn ServiceSink>,
    mut events: broadcast::Receiver<ClientEvent>,
    timing: AnnounceTiming,
    stop: CancellationToken,
) {
    let mut retry_at: Option<Instant> = None;
    let mut backoff = timing.first_retry;
    loop {
        let due = async {
            match retry_at {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = stop.cancelled() => return,
            () = due => {}
            event = events.recv() => match event {
                Ok(ClientEvent::Connected) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    backoff = timing.first_retry;
                }
                Ok(ClientEvent::Disconnected { .. }) => {
                    retry_at = None;
                    continue;
                }
                Ok(ClientEvent::ConnectFailed(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
        let delivery = tokio::select! {
            () = stop.cancelled() => return,
            delivery = sink.announce(&announcement) => delivery,
        };
        report(&delivery, &announcement);
        retry_at = match delivery {
            Delivery::Retry(after) => {
                let wait = after.map_or(backoff, |after| after.max(backoff));
                backoff = backoff.saturating_mul(2).min(timing.max_retry);
                Some(Instant::now() + wait.min(timing.max_retry))
            }
            Delivery::Accepted | Delivery::Unsupported | Delivery::Refused(_) => None,
        };
    }
}

#[cfg(test)]
mod tests;
