use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_proto::ServiceCertificateRequest;
use jaunt_tunnel::{Backoff, BackoffPolicy, MAX_TIMER};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use super::control::ServiceControl;
use super::directory::ApprovedService;
use crate::clock::{Clock, at_unix_secs, format_utc, unix_secs};
use crate::keys::{KeyError, TlsKey};
use crate::run::api::ApiError;
use crate::trust::{Sampler, spread};
use crate::verify::decode_der;

pub const SERVICE_RENEWAL_SPREAD: Duration = Duration::from_secs(60 * 60);

pub const SERVICE_CERTIFICATE_BACKOFF: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_secs(5),
    max: Duration::from_secs(10 * 60),
    reset_after: MAX_TIMER,
};

pub struct IssuedCertificate {
    key: Arc<CertifiedKey>,
    dns_name: String,
    serial: i64,
    not_before: i64,
    not_after: i64,
    renew_at: i64,
}

impl fmt::Debug for IssuedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCertificate")
            .field("dns_name", &self.dns_name)
            .field("serial", &self.serial)
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .field("renew_at", &self.renew_at)
            .finish_non_exhaustive()
    }
}

impl IssuedCertificate {
    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.key)
    }

    pub fn dns_name(&self) -> &str {
        &self.dns_name
    }

    #[cfg(test)]
    pub fn serial(&self) -> i64 {
        self.serial
    }

    #[cfg(test)]
    pub fn not_after(&self) -> i64 {
        self.not_after
    }

    #[cfg(test)]
    pub fn renew_at(&self) -> i64 {
        self.renew_at
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("cannot generate the service key: {0}")]
    Key(#[source] KeyError),
    #[error(transparent)]
    Api(ApiError),
    #[error("the service certificate is not valid base64 or cannot be parsed")]
    Malformed,
    #[error("the service certificate is for another key than the one this agent generated")]
    KeyMismatch,
    #[error("the service certificate does not name exactly this service")]
    Name,
    #[error("the service certificate has already expired")]
    Expired,
    #[error("the service certificate key cannot be used for TLS")]
    Unusable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no server certificate is available for this service")]
pub struct Unavailable;

struct SlotState {
    current: Option<Arc<IssuedCertificate>>,
    retry_at: Option<i64>,
    backoff: Backoff,
}

struct Slot {
    service: ApprovedService,
    flight: tokio::sync::Mutex<()>,
    state: Mutex<SlotState>,
}

impl Slot {
    fn state(&self) -> MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn usable(&self, now: i64) -> Option<Arc<IssuedCertificate>> {
        self.state()
            .current
            .as_ref()
            .filter(|current| now < current.not_after)
            .cloned()
    }

    fn waiting(&self, now: i64) -> bool {
        self.state().retry_at.is_some_and(|at| now < at)
    }

    fn renewal_due_at(&self) -> Option<i64> {
        let state = self.state();
        let current = state.current.as_ref()?;
        Some(current.renew_at.max(state.retry_at.unwrap_or(i64::MIN)))
    }
}

pub struct ServiceCertificates {
    control: Arc<dyn ServiceControl>,
    clock: Arc<dyn Clock>,
    sample: Sampler,
    policy: BackoffPolicy,
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    changed: Notify,
}

impl ServiceCertificates {
    pub fn new(
        control: Arc<dyn ServiceControl>,
        clock: Arc<dyn Clock>,
        sample: Sampler,
        policy: BackoffPolicy,
    ) -> Self {
        Self {
            control,
            clock,
            sample,
            policy,
            slots: Mutex::new(HashMap::new()),
            changed: Notify::new(),
        }
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<String, Arc<Slot>>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> i64 {
        unix_secs(self.clock.now())
    }

    fn slot(&self, service: &ApprovedService) -> Arc<Slot> {
        let mut slots = self.slots();
        if let Some(slot) = slots.get(&service.id)
            && slot.service == *service
        {
            return Arc::clone(slot);
        }
        let slot = Arc::new(Slot {
            service: service.clone(),
            flight: tokio::sync::Mutex::new(()),
            state: Mutex::new(SlotState {
                current: None,
                retry_at: None,
                backoff: Backoff::new(self.policy),
            }),
        });
        slots.insert(service.id.clone(), Arc::clone(&slot));
        slot
    }

    pub async fn get(
        &self,
        service: &ApprovedService,
    ) -> Result<Arc<IssuedCertificate>, Unavailable> {
        let slot = self.slot(service);
        if let Some(current) = slot.usable(self.now()) {
            return Ok(current);
        }
        let _flight = slot.flight.lock().await;
        let now = self.now();
        if let Some(current) = slot.usable(now) {
            return Ok(current);
        }
        if slot.waiting(now) {
            return Err(Unavailable);
        }
        self.attempt(&slot).await.ok_or(Unavailable)
    }

    #[cfg(test)]
    pub fn slot_serial(&self, service: &ApprovedService) -> Option<i64> {
        let slot = self.slots().get(&service.id).cloned()?;
        slot.state().current.as_ref().map(|current| current.serial)
    }

    pub fn retain(&self, keep: impl Fn(&ApprovedService) -> bool) {
        self.slots().retain(|_, slot| keep(&slot.service));
        self.changed.notify_one();
    }

    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        loop {
            let due = self
                .slots()
                .values()
                .filter_map(|slot| slot.renewal_due_at())
                .min();
            let clock = Arc::clone(&self.clock);
            let sleep = async {
                match due {
                    Some(at) => clock.sleep_until(at_unix_secs(at)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stop.cancelled() => return,
                () = self.changed.notified() => continue,
                () = sleep => {}
            }
            let now = self.now();
            let due: Vec<Arc<Slot>> = self
                .slots()
                .values()
                .filter(|slot| slot.renewal_due_at().is_some_and(|at| at <= now))
                .cloned()
                .collect();
            for slot in due {
                let renewed = async {
                    let _flight = slot.flight.lock().await;
                    if slot.renewal_due_at().is_some_and(|at| at <= self.now()) {
                        self.attempt(&slot).await;
                    }
                };
                tokio::select! {
                    () = stop.cancelled() => return,
                    () = renewed => {}
                }
            }
        }
    }

    async fn attempt(&self, slot: &Slot) -> Option<Arc<IssuedCertificate>> {
        let issued = self.issue(&slot.service).await;
        let now = self.now();
        let mut state = slot.state();
        match issued {
            Ok(issued) => {
                let issued = Arc::new(issued);
                tracing::info!(
                    target: "jaunt::agent",
                    service = %slot.service.name,
                    kind = slot.service.kind.as_str(),
                    dns_name = issued.dns_name.as_str(),
                    serial = issued.serial,
                    not_after = %format_utc(issued.not_after),
                    renew_at = %format_utc(issued.renew_at),
                    "obtained the server certificate of a service"
                );
                state.current = Some(Arc::clone(&issued));
                state.retry_at = None;
                state.backoff = Backoff::new(self.policy);
                drop(state);
                self.changed.notify_one();
                Some(issued)
            }
            Err(error) => {
                let delay = state.backoff.next_delay(Duration::ZERO, (self.sample)());
                let wait = i64::try_from(delay.as_secs()).unwrap_or(i64::MAX).max(1);
                state.retry_at = Some(now.saturating_add(wait));
                let kept = state
                    .current
                    .as_ref()
                    .filter(|current| now < current.not_after)
                    .map(|current| current.not_after);
                drop(state);
                tracing::warn!(
                    target: "jaunt::agent",
                    service = %slot.service.name,
                    kind = slot.service.kind.as_str(),
                    error = %error,
                    retry_in_secs = wait,
                    kept_until = kept.map(format_utc),
                    "obtaining the server certificate of a service failed"
                );
                self.changed.notify_one();
                None
            }
        }
    }

    async fn issue(&self, service: &ApprovedService) -> Result<IssuedCertificate, IssueError> {
        let key = TlsKey::generate().map_err(IssueError::Key)?;
        let response = self
            .control
            .issue_certificate(&ServiceCertificateRequest {
                service_id: service.id.clone(),
                public_key: key.spki_base64(),
            })
            .await
            .map_err(IssueError::Api)?;
        let der = decode_der(&response.certificate_der).ok_or(IssueError::Malformed)?;
        let (rest, certificate) =
            parse_x509_certificate(&der).map_err(|_| IssueError::Malformed)?;
        if !rest.is_empty() {
            return Err(IssueError::Malformed);
        }
        if certificate.public_key().raw != key.spki_der() {
            return Err(IssueError::KeyMismatch);
        }
        let prefix = format!("{}.{}.", service.name, service.kind.as_str());
        let dns_name = response.dns_name;
        let named = dns_name.len() > prefix.len()
            && dns_name.starts_with(&prefix)
            && dns_name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            });
        let san = certificate
            .subject_alternative_name()
            .map_err(|_| IssueError::Malformed)?
            .ok_or(IssueError::Name)?;
        let signed = matches!(
            san.value.general_names.as_slice(),
            [GeneralName::DNSName(signed)] if *signed == dns_name
        );
        if !named || !signed {
            return Err(IssueError::Name);
        }
        let validity = certificate.validity();
        let (not_before, not_after) = (
            validity.not_before.timestamp(),
            validity.not_after.timestamp(),
        );
        if self.now() >= not_after || not_after <= not_before {
            return Err(IssueError::Expired);
        }
        let signing =
            rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(key.pkcs8_der()))
                .map_err(|_| IssueError::Unusable)?;
        let span = not_after.saturating_sub(not_before);
        let half = Duration::from_secs(u64::try_from(span / 2).unwrap_or(0));
        let jitter = spread(
            Duration::ZERO,
            SERVICE_RENEWAL_SPREAD.min(half / 2),
            (self.sample)(),
        );
        let renew_at = not_before
            .saturating_add(i64::try_from(half.as_secs()).unwrap_or(i64::MAX))
            .saturating_add(i64::try_from(jitter.as_secs()).unwrap_or(0));
        Ok(IssuedCertificate {
            key: Arc::new(CertifiedKey::new(vec![CertificateDer::from(der)], signing)),
            dns_name,
            serial: response.serial,
            not_before,
            not_after,
            renew_at,
        })
    }
}
