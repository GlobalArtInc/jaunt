use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_ssh::{SshError, UserCaKeys};
use jaunt_tunnel::{Backoff, BackoffPolicy, ClientEvent, MAX_TIMER};
use tokio::sync::{Notify, broadcast};
use tokio_util::sync::CancellationToken;

use crate::clock::Clock;
use crate::run::api::{AgentApi, ApiError};
use crate::ssh::SshService;

pub const CLOCK_SKEW_LIMIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustTiming {
    pub backoff: BackoffPolicy,
    pub refresh_min: Duration,
    pub refresh_max: Duration,
    pub wake_jitter: Duration,
}

pub const TRUST_TIMING: TrustTiming = TrustTiming {
    backoff: BackoffPolicy {
        initial: Duration::from_secs(1),
        max: Duration::from_secs(60),
        reset_after: MAX_TIMER,
    },
    refresh_min: Duration::from_secs(10 * 60),
    refresh_max: Duration::from_secs(15 * 60),
    wake_jitter: Duration::from_secs(5),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEnd {
    Shutdown,
    NodeRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wake {
    Announced,
    Reconnected,
    Periodic,
    Shutdown,
}

impl Wake {
    fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Reconnected => "reconnected",
            Self::Periodic => "periodic",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum TrustError {
    #[error(transparent)]
    Api(ApiError),
    #[error("the control plane sent a user CA trust set that cannot be used: {0}")]
    Invalid(SshError),
}

pub fn spread(min: Duration, max: Duration, sample: f64) -> Duration {
    let sample = if sample.is_finite() {
        sample.clamp(0.0, 1.0)
    } else {
        0.0
    };
    min.saturating_add(max.saturating_sub(min).mul_f64(sample))
}

pub type Sampler = Arc<dyn Fn() -> f64 + Send + Sync>;

pub fn random_sampler() -> Sampler {
    Arc::new(|| rand::random_range(0.0..=1.0))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Event(ClientEvent),
    Lagged,
}

#[derive(Debug, Default)]
pub struct Reconnections {
    first_connection_seen: bool,
}

impl Reconnections {
    pub fn wants_reload(&mut self, signal: Signal) -> bool {
        match signal {
            Signal::Lagged => {
                self.first_connection_seen = true;
                true
            }
            Signal::Event(ClientEvent::Connected) => {
                let reconnected = self.first_connection_seen;
                self.first_connection_seen = true;
                reconnected
            }
            Signal::Event(ClientEvent::ConnectFailed(_) | ClientEvent::Disconnected { .. }) => {
                false
            }
        }
    }
}

pub struct TrustLoader {
    pub api: Arc<AgentApi>,
    pub ssh: Arc<SshService>,
    pub clock: Arc<dyn Clock>,
    pub timing: TrustTiming,
    pub events: Option<broadcast::Receiver<ClientEvent>>,
    pub sample: Sampler,
}

impl TrustLoader {
    pub async fn run(mut self, shutdown: CancellationToken) -> TrustEnd {
        let changed = self.ssh.trust_changed();
        let mut reconnections = Reconnections::default();
        let mut first = true;
        loop {
            self.drain_events(&mut reconnections);
            if let Err(end) = self.load_with_retries(&shutdown, first).await {
                return end;
            }
            first = false;
            let wake = self.wait(&changed, &mut reconnections, &shutdown).await;
            tracing::debug!(
                target: "jaunt::agent",
                wake = wake.as_str(),
                "refreshing the user CA trust set"
            );
            let jitter = match wake {
                Wake::Shutdown => return TrustEnd::Shutdown,
                Wake::Periodic => Duration::ZERO,
                Wake::Announced | Wake::Reconnected => {
                    spread(Duration::ZERO, self.timing.wake_jitter, (self.sample)())
                }
            };
            tokio::select! {
                () = shutdown.cancelled() => return TrustEnd::Shutdown,
                () = tokio::time::sleep(jitter) => {}
            }
        }
    }

    fn drain_events(&mut self, reconnections: &mut Reconnections) {
        let Some(events) = self.events.as_mut() else {
            return;
        };
        loop {
            let signal = match events.try_recv() {
                Ok(event) => Signal::Event(event),
                Err(broadcast::error::TryRecvError::Lagged(_)) => Signal::Lagged,
                Err(broadcast::error::TryRecvError::Empty) => return,
                Err(broadcast::error::TryRecvError::Closed) => {
                    self.events = None;
                    return;
                }
            };
            reconnections.wants_reload(signal);
        }
    }

    async fn wait(
        &mut self,
        changed: &Notify,
        reconnections: &mut Reconnections,
        shutdown: &CancellationToken,
    ) -> Wake {
        let refresh = spread(
            self.timing.refresh_min,
            self.timing.refresh_max,
            (self.sample)(),
        );
        tokio::select! {
            () = shutdown.cancelled() => Wake::Shutdown,
            () = changed.notified() => Wake::Announced,
            () = next_reconnection(&mut self.events, reconnections) => Wake::Reconnected,
            () = tokio::time::sleep(refresh) => Wake::Periodic,
        }
    }

    async fn load_with_retries(
        &self,
        shutdown: &CancellationToken,
        check_clock: bool,
    ) -> Result<(), TrustEnd> {
        let mut backoff = Backoff::new(self.timing.backoff);
        loop {
            match self.load_once().await {
                Ok(server_time) => {
                    if check_clock {
                        report_clock_skew(self.clock.now(), server_time);
                    }
                    return Ok(());
                }
                Err(TrustError::Api(ApiError::Shutdown)) => return Err(TrustEnd::Shutdown),
                Err(TrustError::Api(ApiError::NodeRemoved)) => {
                    tracing::error!(
                        target: "jaunt::agent",
                        "the server no longer knows this node (node_removed); the user CA trust set is not refreshed any more"
                    );
                    return Err(TrustEnd::NodeRemoved);
                }
                Err(error) => {
                    let delay = backoff.next_delay(Duration::ZERO, (self.sample)());
                    tracing::warn!(
                        target: "jaunt::agent",
                        error = %error,
                        retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "loading the user CA trust set failed; the previous set stays in use"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => return Err(TrustEnd::Shutdown),
                        () = tokio::time::sleep(delay) => {}
                    }
                }
            }
        }
    }

    async fn load_once(&self) -> Result<Option<SystemTime>, TrustError> {
        let reply = self.api.trust().await.map_err(TrustError::Api)?;
        let lines = reply.value.user_ca_keys;
        let keys = UserCaKeys::from_openssh_lines(&lines).map_err(TrustError::Invalid)?;
        self.ssh.install_trust(keys);
        tracing::info!(
            target: "jaunt::agent",
            keys = lines.len(),
            "loaded the user CA trust set"
        );
        Ok(reply.server_time)
    }
}

async fn next_reconnection(
    events: &mut Option<broadcast::Receiver<ClientEvent>>,
    reconnections: &mut Reconnections,
) {
    loop {
        let Some(receiver) = events.as_mut() else {
            return std::future::pending().await;
        };
        let signal = match receiver.recv().await {
            Ok(event) => Signal::Event(event),
            Err(broadcast::error::RecvError::Lagged(_)) => Signal::Lagged,
            Err(broadcast::error::RecvError::Closed) => {
                *events = None;
                continue;
            }
        };
        if reconnections.wants_reload(signal) {
            return;
        }
    }
}

pub fn clock_skew(local: SystemTime, server: SystemTime) -> Duration {
    match local.duration_since(server) {
        Ok(ahead) => ahead,
        Err(behind) => behind.duration(),
    }
}

fn report_clock_skew(local: SystemTime, server: Option<SystemTime>) {
    let Some(server) = server else {
        tracing::debug!(
            target: "jaunt::agent",
            "the control plane sent no Date header; the clock skew was not checked"
        );
        return;
    };
    let skew = clock_skew(local, server);
    if skew > CLOCK_SKEW_LIMIT {
        tracing::warn!(
            target: "jaunt::agent",
            event = "agent.clock_skew",
            skew_secs = skew.as_secs(),
            local_ahead = local > server,
            "the system clock differs from the control plane clock by more than a minute; SSH certificates may be refused as not yet valid or expired, so fix the time synchronization of this node"
        );
    }
}

#[cfg(test)]
mod tests;
