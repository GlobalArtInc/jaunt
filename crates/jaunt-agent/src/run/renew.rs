use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_proto::RenewRequest;
use jaunt_tunnel::{Backoff, BackoffPolicy, MAX_TIMER, SwappableClientCert, TlsConfigError};
use rustls::pki_types::CertificateDer;
use ssh_key::public::KeyData;
use tokio_util::sync::CancellationToken;

use super::api::{AgentApi, ApiError};
use crate::clock::{Clock, at_unix_secs, format_utc, unix_secs};
use crate::state::{EnrollmentRecord, StateDir, StateError};
use crate::verify::{self, Expected, Validity, VerifyError};

pub const RENEWAL_BACKOFF: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_secs(60),
    max: Duration::from_secs(30 * 60),
    reset_after: MAX_TIMER,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalEnd {
    Shutdown,
    NodeRemoved,
    Expired,
}

#[derive(Debug, thiserror::Error)]
enum RenewError {
    #[error(transparent)]
    Api(ApiError),
    #[error("the renewed certificates were refused: {0}")]
    Verify(VerifyError),
    #[error("the renewed certificates could not be stored: {0}")]
    Store(StateError),
    #[error("the renewed certificate could not be loaded for new connections: {0}")]
    Identity(TlsConfigError),
}

pub fn half_life(validity: Validity) -> i64 {
    if validity.not_after <= validity.not_before {
        return validity.not_before;
    }
    let span = validity.not_after.saturating_sub(validity.not_before);
    validity.not_before.saturating_add(span / 2)
}

pub fn next_attempt(validity: Validity, earliest: i64) -> i64 {
    half_life(validity).max(earliest)
}

pub struct Renewer {
    pub api: Arc<AgentApi>,
    pub state: StateDir,
    pub identity: Arc<SwappableClientCert>,
    pub record: EnrollmentRecord,
    pub tls_spki: Vec<u8>,
    pub ssh_key: KeyData,
    pub root_der: Vec<u8>,
    pub validity: Validity,
    pub clock: Arc<dyn Clock>,
    pub jitter: Box<dyn FnMut() -> f64 + Send + Sync>,
    pub backoff: BackoffPolicy,
    pub after_renewal: Box<dyn Fn(&StateDir) + Send + Sync>,
}

impl Renewer {
    pub async fn run(mut self, shutdown: CancellationToken) -> RenewalEnd {
        let mut earliest = i64::MIN;
        loop {
            let at = next_attempt(self.validity, earliest);
            tracing::info!(
                target: "jaunt::agent",
                renew_at = %format_utc(at),
                x509_not_after = %format_utc(self.validity.not_after),
                "next certificate renewal scheduled"
            );
            if !self.wait_until(at_unix_secs(at), &shutdown).await {
                return RenewalEnd::Shutdown;
            }
            if let Err(end) = self.renew_with_retries(&shutdown).await {
                return end;
            }
            let gap = i64::try_from(self.backoff.initial.as_secs()).unwrap_or(i64::MAX);
            earliest = unix_secs(self.clock.now()).saturating_add(gap);
        }
    }

    async fn wait_until(&self, deadline: SystemTime, shutdown: &CancellationToken) -> bool {
        tokio::select! {
            () = shutdown.cancelled() => false,
            () = self.clock.sleep_until(deadline) => !shutdown.is_cancelled(),
        }
    }

    async fn renew_with_retries(&mut self, shutdown: &CancellationToken) -> Result<(), RenewalEnd> {
        let mut backoff = Backoff::new(self.backoff);
        loop {
            if unix_secs(self.clock.now()) >= self.validity.not_after {
                tracing::error!(
                    target: "jaunt::agent",
                    node_id = %self.record.node_id,
                    x509_not_after = %format_utc(self.validity.not_after),
                    "the node certificate has expired and the server does not accept expired certificates; re-enroll this node with `jaunt-agent enroll --replace`"
                );
                self.api.reset().await;
                return Err(RenewalEnd::Expired);
            }
            match self.renew_once().await {
                Ok(()) => {
                    tracing::info!(
                        target: "jaunt::agent",
                        node_id = %self.record.node_id,
                        x509_not_after = %format_utc(self.record.x509_not_after),
                        ssh_not_after = %format_utc(self.record.ssh_not_after),
                        "renewed the node certificates"
                    );
                    return Ok(());
                }
                Err(RenewError::Api(ApiError::NodeRemoved)) => {
                    tracing::error!(
                        target: "jaunt::agent",
                        node_id = %self.record.node_id,
                        "the server reports that this node was removed (node_removed); certificate renewal stops"
                    );
                    self.api.reset().await;
                    return Err(RenewalEnd::NodeRemoved);
                }
                Err(RenewError::Api(ApiError::Shutdown)) => return Err(RenewalEnd::Shutdown),
                Err(error) => {
                    let delay = backoff.next_delay(Duration::ZERO, (self.jitter)());
                    tracing::warn!(
                        target: "jaunt::agent",
                        error = %error,
                        retry_in_secs = delay.as_secs(),
                        "certificate renewal failed"
                    );
                    let now = self.clock.now();
                    let next = now.checked_add(delay).unwrap_or(now);
                    if !self.wait_until(next, shutdown).await {
                        return Err(RenewalEnd::Shutdown);
                    }
                }
            }
        }
    }

    async fn renew_once(&mut self) -> Result<(), RenewError> {
        let request = RenewRequest {
            tls_public_key: None,
            ssh_host_public_key: None,
        };
        let response = self.api.renew(&request).await.map_err(RenewError::Api)?;
        let checked = verify::check_certificates(
            &response,
            &self.root_der,
            &Expected {
                node_id: &self.record.node_id,
                name: &self.record.name,
                tls_spki: &self.tls_spki,
                ssh_key: &self.ssh_key,
            },
            self.clock.now(),
        )
        .map_err(RenewError::Verify)?;
        let record = EnrollmentRecord {
            x509_not_after: checked.x509.not_after,
            ssh_not_after: checked.ssh_not_after,
            ..self.record.clone()
        };
        self.state
            .store_renewal(&record, &checked.x509_der, &checked.ssh_certificate)
            .map_err(RenewError::Store)?;
        self.identity
            .replace_certificate(vec![CertificateDer::from(checked.x509_der)])
            .map_err(RenewError::Identity)?;
        self.api.reset().await;
        self.record = record;
        self.validity = checked.x509;
        (self.after_renewal)(&self.state);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use jaunt_tunnel::Backoff;

    use super::{RENEWAL_BACKOFF, half_life, next_attempt};
    use crate::verify::Validity;

    fn validity(not_before: i64, not_after: i64) -> Validity {
        Validity {
            not_before,
            not_after,
        }
    }

    #[test]
    fn renewal_is_due_at_half_life_and_never_before_the_earliest_time() {
        let week = 7 * 24 * 3600;
        assert_eq!(half_life(validity(1000, 1000 + week)), 1000 + week / 2);
        assert_eq!(half_life(validity(1000, 1001)), 1000);
        assert_eq!(half_life(validity(1000, 900)), 1000);
        assert!(half_life(validity(i64::MIN, i64::MAX)) < 0);
        assert_eq!(next_attempt(validity(0, 100), 10), 50);
        assert_eq!(next_attempt(validity(0, 100), 70), 70);
    }

    #[test]
    fn the_renewal_backoff_doubles_from_one_minute_to_half_an_hour_with_full_jitter() {
        assert_eq!(RENEWAL_BACKOFF.validate(), Ok(()));
        let mut backoff = Backoff::new(RENEWAL_BACKOFF);
        let caps: Vec<u64> = (0..7)
            .map(|_| backoff.next_delay(Duration::ZERO, 1.0).as_secs())
            .collect();
        assert_eq!(caps, [60, 120, 240, 480, 960, 1800, 1800]);
        let mut jittered = Backoff::new(RENEWAL_BACKOFF);
        assert_eq!(jittered.next_delay(Duration::ZERO, 0.0), Duration::ZERO);
        assert_eq!(
            jittered.next_delay(Duration::ZERO, 0.5),
            Duration::from_secs(60)
        );
        for sample in [f64::NAN, 7.0, -1.0] {
            assert!(jittered.next_delay(Duration::ZERO, sample) <= Duration::from_secs(1800));
        }
    }
}
