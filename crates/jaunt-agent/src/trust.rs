use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use jaunt_ssh::{SshError, UserCaKeys};
use jaunt_tunnel::{Backoff, BackoffPolicy, ClientEvent, MAX_TIMER};
use ssh_key::PublicKey;
use ssh_key::public::KeyData;
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;

use crate::clock::{Clock, unix_secs};
use crate::run::api::{AgentApi, ApiError, ServedTrust};
use crate::runtime::x509::{UserRoots, UserX509Trust};
use crate::ssh::SshService;

pub const CLOCK_SKEW_LIMIT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustTiming {
    pub backoff: BackoffPolicy,
    pub refresh_min: Duration,
    pub refresh_max: Duration,
    pub wake_jitter: Duration,
    pub refusal_interval: Duration,
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
    refusal_interval: Duration::from_secs(60),
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
    Refused,
    Shutdown,
}

impl Wake {
    fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Reconnected => "reconnected",
            Self::Periodic => "periodic",
            Self::Refused => "untrusted_ca",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Debug, Default)]
pub struct UntrustedRefusals {
    pending: AtomicBool,
    wake: Notify,
}

impl UntrustedRefusals {
    pub fn record(&self) {
        self.pending.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    fn pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    fn clear(&self) {
        self.pending.store(false, Ordering::Release);
    }

    fn restore(&self) {
        self.pending.store(true, Ordering::Release);
    }
}

pub type HostCaActive = watch::Sender<Option<KeyData>>;

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
    pub host_ca: HostCaActive,
    pub user_x509: Arc<UserX509Trust>,
}

impl TrustLoader {
    pub async fn run(mut self, shutdown: CancellationToken) -> TrustEnd {
        let changed = self.ssh.trust_changed();
        let refusals = self.ssh.untrusted_refusals();
        let mut reconnections = Reconnections::default();
        let mut first = true;
        let mut last_refusal_read = None;
        let mut wake = Wake::Periodic;
        loop {
            self.drain_events(&mut reconnections);
            let loaded = if wake == Wake::Refused {
                last_refusal_read = Some(self.clock.now());
                self.load_after_refusal(&refusals).await
            } else {
                self.load_with_retries(&refusals, &shutdown, first).await
            };
            if let Err(end) = loaded {
                return end;
            }
            first = false;
            wake = self
                .wait(
                    &changed,
                    &refusals,
                    last_refusal_read,
                    &mut reconnections,
                    &shutdown,
                )
                .await;
            tracing::debug!(
                target: "jaunt::agent",
                wake = wake.as_str(),
                "refreshing the user CA trust set"
            );
            if wake == Wake::Reconnected {
                self.api.retry_third_trust_version();
            }
            let jitter = match wake {
                Wake::Shutdown => return TrustEnd::Shutdown,
                Wake::Periodic | Wake::Refused => Duration::ZERO,
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
        refusals: &UntrustedRefusals,
        last_refusal_read: Option<SystemTime>,
        reconnections: &mut Reconnections,
        shutdown: &CancellationToken,
    ) -> Wake {
        let refresh = spread(
            self.timing.refresh_min,
            self.timing.refresh_max,
            (self.sample)(),
        );
        let periodic = tokio::time::sleep(refresh);
        tokio::pin!(periodic);
        let clock = Arc::clone(&self.clock);
        loop {
            let due = refusals
                .pending()
                .then(|| refusal_due(last_refusal_read, self.timing.refusal_interval, clock.now()))
                .flatten();
            let refused = async {
                match due {
                    Some(deadline) => clock.sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = shutdown.cancelled() => return Wake::Shutdown,
                () = changed.notified() => return Wake::Announced,
                () = next_reconnection(&mut self.events, reconnections) => return Wake::Reconnected,
                () = &mut periodic => return Wake::Periodic,
                () = refused => return Wake::Refused,
                () = refusals.wake.notified(), if due.is_none() => {}
            }
        }
    }

    async fn load_after_refusal(&self, refusals: &UntrustedRefusals) -> Result<(), TrustEnd> {
        refusals.clear();
        match self.load_once().await {
            Ok(_) => Ok(()),
            Err(TrustError::Api(ApiError::Shutdown)) => Err(TrustEnd::Shutdown),
            Err(TrustError::Api(ApiError::NodeRemoved)) => Err(node_removed()),
            Err(error) => {
                refusals.restore();
                tracing::warn!(
                    target: "jaunt::agent",
                    error = %error,
                    retry_in_secs = self.timing.refusal_interval.as_secs(),
                    "reloading the user CA trust set after a refused certificate failed; the previous set stays in use"
                );
                Ok(())
            }
        }
    }

    async fn load_with_retries(
        &self,
        refusals: &UntrustedRefusals,
        shutdown: &CancellationToken,
        check_clock: bool,
    ) -> Result<(), TrustEnd> {
        let mut backoff = Backoff::new(self.timing.backoff);
        loop {
            refusals.clear();
            match self.load_once().await {
                Ok(server_time) => {
                    if check_clock {
                        report_clock_skew(self.clock.now(), server_time);
                    }
                    return Ok(());
                }
                Err(TrustError::Api(ApiError::Shutdown)) => return Err(TrustEnd::Shutdown),
                Err(TrustError::Api(ApiError::NodeRemoved)) => return Err(node_removed()),
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
        let host_ca = reply.value.host_ca_active().map(str::to_owned);
        self.install_user_x509(&reply.value);
        let lines = reply.value.into_user_ca_keys();
        let keys = UserCaKeys::from_openssh_lines(&lines).map_err(TrustError::Invalid)?;
        self.ssh.install_trust(keys);
        tracing::info!(
            target: "jaunt::agent",
            keys = lines.len(),
            "loaded the user CA trust set"
        );
        self.publish_host_ca(host_ca.as_deref());
        Ok(reply.server_time)
    }

    fn install_user_x509(&self, served: &ServedTrust) {
        let Some(entries) = served.user_x509_roots() else {
            self.user_x509.install(UserRoots::default());
            return;
        };
        match UserRoots::from_trust(entries, unix_secs(self.clock.now())) {
            Ok(roots) => {
                let count = roots.len();
                self.user_x509.install(roots);
                if count == 0 {
                    tracing::warn!(
                        target: "jaunt::agent",
                        "the control plane serves no usable user X.509 roots; Kubernetes, database and TCP client certificates are refused"
                    );
                } else {
                    tracing::info!(
                        target: "jaunt::agent",
                        roots = count,
                        "loaded the user X.509 roots"
                    );
                }
            }
            Err(error) => tracing::error!(
                target: "jaunt::agent",
                error = %error,
                "the control plane sent user X.509 roots that cannot be used; the previous roots stay in use"
            ),
        }
    }

    fn publish_host_ca(&self, line: Option<&str>) {
        let active = match line.map(|line| PublicKey::from_openssh(line.trim())) {
            None => None,
            Some(Ok(key)) => Some(key.key_data().clone()),
            Some(Err(_)) => {
                tracing::warn!(
                    target: "jaunt::agent",
                    "the control plane sent an active host CA key that cannot be read; the host certificate is renewed on its usual schedule"
                );
                return;
            }
        };
        self.host_ca.send_if_modified(|current| {
            if *current == active {
                return false;
            }
            *current = active;
            true
        });
    }
}

fn node_removed() -> TrustEnd {
    tracing::error!(
        target: "jaunt::agent",
        "the server no longer knows this node (node_removed); the user CA trust set is not refreshed any more"
    );
    TrustEnd::NodeRemoved
}

fn refusal_due(
    last_read: Option<SystemTime>,
    interval: Duration,
    now: SystemTime,
) -> Option<SystemTime> {
    let Some(at) = last_read else {
        return Some(SystemTime::UNIX_EPOCH);
    };
    Some(at.checked_add(interval)?.min(now.checked_add(interval)?))
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
