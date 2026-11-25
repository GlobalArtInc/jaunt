use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_proto::RenewRequest;
use jaunt_tunnel::{Backoff, BackoffPolicy, MAX_TIMER, SwappableClientCert, TlsConfigError};
use rustls::pki_types::CertificateDer;
use ssh_key::Certificate;
use ssh_key::public::KeyData;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::api::{AgentApi, ApiError};
use crate::clock::{Clock, at_unix_secs, format_utc, unix_secs};
use crate::state::{EnrollmentRecord, StateDir, StateError};
use crate::trust::spread;
use crate::verify::{self, Expected, Validity, VerifyError};

pub const RENEWAL_BACKOFF: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_secs(60),
    max: Duration::from_secs(30 * 60),
    reset_after: MAX_TIMER,
};

pub const HOST_CA_RENEWAL_SPREAD: Duration = Duration::from_secs(5 * 60);

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

pub fn wake_at(scheduled: i64, early: Option<i64>, earliest: i64) -> i64 {
    early.map_or(scheduled, |due| due.max(earliest).min(scheduled))
}

pub fn host_signer(certificate: &str) -> Option<KeyData> {
    let certificate = Certificate::from_openssh(certificate.trim()).ok()?;
    certificate.verify_signature().ok()?;
    Some(certificate.signature_key().clone())
}

#[derive(Debug, Default)]
pub struct Rotation {
    handled: Option<KeyData>,
    due: Option<i64>,
}

impl Rotation {
    pub fn observe(
        &mut self,
        active: Option<&KeyData>,
        signer: Option<&KeyData>,
        now: i64,
        delay: impl FnOnce() -> Duration,
    ) -> Option<i64> {
        let Some(active) = active else {
            self.due = None;
            return None;
        };
        if signer == Some(active) {
            self.handled = None;
            self.due = None;
            return None;
        }
        if self.handled.as_ref() == Some(active) {
            return None;
        }
        let wait = i64::try_from(delay().as_secs()).unwrap_or(i64::MAX);
        let due = now.saturating_add(wait);
        self.handled = Some(active.clone());
        self.due = Some(due);
        Some(due)
    }

    pub fn due(&self) -> Option<i64> {
        self.due
    }

    pub fn renewed(&mut self) {
        self.due = None;
    }
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
    pub host_ca: watch::Receiver<Option<KeyData>>,
    pub host_ca_spread: Duration,
}

impl Renewer {
    pub async fn run(mut self, shutdown: CancellationToken) -> RenewalEnd {
        let mut signer = self.stored_host_signer();
        let mut rotation = Rotation::default();
        let mut announcements = true;
        let mut earliest = i64::MIN;
        loop {
            let at = next_attempt(self.validity, earliest);
            tracing::info!(
                target: "jaunt::agent",
                renew_at = %format_utc(at),
                x509_not_after = %format_utc(self.validity.not_after),
                "next certificate renewal scheduled"
            );
            loop {
                self.observe_host_ca(&mut rotation, signer.as_ref());
                let due = wake_at(at, rotation.due(), earliest);
                let clock = Arc::clone(&self.clock);
                tokio::select! {
                    () = shutdown.cancelled() => return RenewalEnd::Shutdown,
                    () = clock.sleep_until(at_unix_secs(due)) => break,
                    changed = self.host_ca.changed(), if announcements => {
                        announcements = changed.is_ok();
                    }
                }
            }
            if shutdown.is_cancelled() {
                return RenewalEnd::Shutdown;
            }
            match self.renew_with_retries(&shutdown).await {
                Ok(renewed) => signer = renewed,
                Err(end) => return end,
            }
            rotation.renewed();
            let gap = i64::try_from(self.backoff.initial.as_secs()).unwrap_or(i64::MAX);
            earliest = unix_secs(self.clock.now()).saturating_add(gap);
        }
    }

    fn stored_host_signer(&self) -> Option<KeyData> {
        let certificate = self.state.read_ssh_certificate().ok()?;
        host_signer(std::str::from_utf8(&certificate).ok()?)
    }

    fn observe_host_ca(&mut self, rotation: &mut Rotation, signer: Option<&KeyData>) {
        let active = self.host_ca.borrow_and_update().clone();
        let now = unix_secs(self.clock.now());
        let spread_max = self.host_ca_spread;
        let jitter = &mut self.jitter;
        let scheduled = rotation.observe(active.as_ref(), signer, now, || {
            spread(Duration::ZERO, spread_max, jitter())
        });
        if let Some(due) = scheduled {
            tracing::info!(
                target: "jaunt::agent",
                renew_at = %format_utc(due),
                "the control plane signs host certificates with another key; the host certificate is renewed early"
            );
        }
    }

    async fn wait_until(&self, deadline: SystemTime, shutdown: &CancellationToken) -> bool {
        tokio::select! {
            () = shutdown.cancelled() => false,
            () = self.clock.sleep_until(deadline) => !shutdown.is_cancelled(),
        }
    }

    async fn renew_with_retries(
        &mut self,
        shutdown: &CancellationToken,
    ) -> Result<Option<KeyData>, RenewalEnd> {
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
                Ok(signer) => {
                    tracing::info!(
                        target: "jaunt::agent",
                        node_id = %self.record.node_id,
                        x509_not_after = %format_utc(self.record.x509_not_after),
                        ssh_not_after = %format_utc(self.record.ssh_not_after),
                        "renewed the node certificates"
                    );
                    return Ok(signer);
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

    async fn renew_once(&mut self) -> Result<Option<KeyData>, RenewError> {
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
        Ok(host_signer(&checked.ssh_certificate))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_tunnel::Backoff;
    use ssh_key::public::KeyData;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey, PublicKey};

    use super::{
        HOST_CA_RENEWAL_SPREAD, RENEWAL_BACKOFF, Rotation, half_life, host_signer, next_attempt,
        wake_at,
    };
    use crate::testkit::{TestPki, unix_now};
    use crate::verify::Validity;

    fn key() -> KeyData {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
            .unwrap()
            .public_key()
            .key_data()
            .clone()
    }

    #[test]
    fn a_new_active_host_ca_key_schedules_one_early_renewal() {
        let (a, b, c) = (key(), key(), key());
        let delay = || Duration::from_secs(90);
        let mut rotation = Rotation::default();
        assert_eq!(rotation.observe(None, Some(&a), 1000, delay), None);
        assert_eq!(rotation.observe(Some(&a), Some(&a), 1000, delay), None);
        assert_eq!(rotation.due(), None);
        assert_eq!(
            rotation.observe(Some(&b), Some(&a), 1000, delay),
            Some(1090)
        );
        assert_eq!(rotation.observe(Some(&b), Some(&a), 1050, delay), None);
        assert_eq!(rotation.due(), Some(1090));
        rotation.renewed();
        assert_eq!(rotation.observe(Some(&b), Some(&a), 1100, delay), None);
        assert_eq!(rotation.due(), None);
        assert_eq!(rotation.observe(Some(&c), None, 1200, delay), Some(1290));
        assert_eq!(rotation.observe(Some(&c), Some(&c), 1300, delay), None);
        assert_eq!(rotation.due(), None);
        assert_eq!(rotation.observe(None, None, 1400, delay), None);
        assert_eq!(HOST_CA_RENEWAL_SPREAD, Duration::from_secs(300));

        let mut flapping = Rotation::default();
        assert_eq!(
            flapping.observe(Some(&b), Some(&a), 2000, delay),
            Some(2090)
        );
        assert_eq!(flapping.observe(Some(&a), Some(&a), 2010, delay), None);
        assert_eq!(flapping.due(), None);
        assert_eq!(
            flapping.observe(Some(&b), Some(&a), 2020, delay),
            Some(2110)
        );
    }

    #[test]
    fn an_early_renewal_waits_for_the_floor_and_never_passes_the_scheduled_time() {
        for (scheduled, early, earliest, expected) in [
            (5000, None, 0, 5000),
            (5000, Some(1000), 0, 1000),
            (5000, Some(1000), 1060, 1060),
            (5000, Some(6000), 0, 5000),
            (5000, Some(1000), i64::MIN, 1000),
        ] {
            assert_eq!(
                wake_at(scheduled, early, earliest),
                expected,
                "{scheduled} {early:?} {earliest}"
            );
        }
    }

    #[test]
    fn the_host_signer_is_read_only_from_a_correctly_signed_certificate() {
        let pki = TestPki::new();
        let now = unix_now();
        let certificate = pki.host_certificate(&key(), &["web-01.jaunt.test"], now - 60, now + 60);
        let expected = PublicKey::from_openssh(&pki.host_ca_line())
            .unwrap()
            .key_data()
            .clone();
        assert_eq!(host_signer(&format!("{certificate}\n")), Some(expected));

        let mut fields: Vec<String> = certificate.split(' ').map(str::to_owned).collect();
        let mut blob = STANDARD.decode(&fields[1]).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        fields[1] = STANDARD.encode(blob);
        for broken in [
            fields.join(" "),
            "not a certificate".to_owned(),
            String::new(),
        ] {
            assert_eq!(host_signer(&broken), None);
        }
    }

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
