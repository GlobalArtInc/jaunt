use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_proto::{GateTlsIssueError, GateTlsIssuer};
use jaunt_tunnel::RotatingCertificate;
use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::host_cert::{Clock, ISSUE_TIMEOUT, Window, retry_delay, unix_secs};

#[derive(Debug, Error)]
pub enum GateCertificateError {
    #[error("cannot generate the gate tls key")]
    Key,
    #[error("cannot obtain the gate tls certificate")]
    Issue(#[source] GateTlsIssueError),
    #[error("the gate tls certificate authority did not answer in time")]
    Timeout,
    #[error("the issued gate tls certificate is not usable")]
    Unusable,
}

struct Issued {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    state: State,
}

#[derive(Debug, Clone, Copy)]
struct State {
    window: Window,
    serial: u64,
}

pub(crate) struct GateCertificate {
    issuer: Arc<dyn GateTlsIssuer>,
    domain: String,
    clock: Clock,
    slot: Arc<RotatingCertificate>,
    state: Mutex<State>,
    issuing: tokio::sync::Mutex<()>,
}

impl GateCertificate {
    pub(crate) async fn obtain(
        issuer: Arc<dyn GateTlsIssuer>,
        domain: String,
        clock: Clock,
    ) -> Result<Self, GateCertificateError> {
        let issued = issue(issuer.as_ref(), &domain, &clock).await?;
        let slot = Arc::new(
            RotatingCertificate::new(issued.chain, issued.key)
                .map_err(|_| GateCertificateError::Unusable)?,
        );
        Ok(Self {
            issuer,
            domain,
            clock,
            slot,
            state: Mutex::new(issued.state),
            issuing: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) fn resolver(&self) -> Arc<RotatingCertificate> {
        Arc::clone(&self.slot)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn serial(&self) -> u64 {
        self.state().serial
    }

    pub(crate) fn valid_before(&self) -> u64 {
        self.state().window.valid_before
    }

    pub(crate) fn expired(&self) -> bool {
        unix_secs((self.clock)()) >= self.valid_before()
    }

    pub(crate) async fn renew_if_due(&self) -> Result<bool, GateCertificateError> {
        let _issuing = self.issuing.lock().await;
        let window = self.state().window;
        if !window.renewal_due(unix_secs((self.clock)())) {
            return Ok(false);
        }
        let issued = issue(self.issuer.as_ref(), &self.domain, &self.clock).await?;
        self.slot
            .replace(issued.chain, issued.key)
            .map_err(|_| GateCertificateError::Unusable)?;
        *self.state() = issued.state;
        tracing::info!(
            target: "jaunt::gate",
            serial = issued.state.serial,
            valid_before = issued.state.window.valid_before,
            "the gate tls certificate was renewed"
        );
        Ok(true)
    }

    pub(crate) async fn renew_forever(
        &self,
        check: Duration,
        retry: Duration,
        stop: CancellationToken,
    ) {
        let mut failures: u32 = 0;
        loop {
            let wait = if failures == 0 {
                check
            } else {
                retry_delay(retry, failures)
            };
            tokio::select! {
                biased;
                () = stop.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            let renewed = tokio::select! {
                biased;
                () = stop.cancelled() => return,
                renewed = self.renew_if_due() => renewed,
            };
            match renewed {
                Ok(_) => failures = 0,
                Err(error) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        target: "jaunt::gate",
                        error = %error,
                        failures,
                        retry_in_secs = retry_delay(retry, failures).as_secs(),
                        valid_before = self.valid_before(),
                        "renewing the gate tls certificate failed; the current one stays in use"
                    );
                }
            }
        }
    }
}

async fn issue(
    issuer: &dyn GateTlsIssuer,
    domain: &str,
    clock: &Clock,
) -> Result<Issued, GateCertificateError> {
    let key = KeyPair::generate_for(&PKCS_ED25519).map_err(|_| GateCertificateError::Key)?;
    let public = key.subject_public_key_info();
    let certificate = tokio::time::timeout(ISSUE_TIMEOUT, issuer.issue(&public, domain))
        .await
        .map_err(|_| GateCertificateError::Timeout)?
        .map_err(GateCertificateError::Issue)?;
    let window = inspect(&certificate.certificate_der, &public, domain)
        .ok_or(GateCertificateError::Unusable)?;
    let now = unix_secs(clock());
    if !(window.valid_after < window.valid_before && now < window.valid_before) {
        return Err(GateCertificateError::Unusable);
    }
    Ok(Issued {
        chain: vec![CertificateDer::from(certificate.certificate_der)],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        state: State {
            window,
            serial: certificate.serial,
        },
    })
}

fn inspect(certificate_der: &[u8], public: &[u8], domain: &str) -> Option<Window> {
    let (rest, certificate) = parse_x509_certificate(certificate_der).ok()?;
    if !rest.is_empty() || certificate.public_key().raw != public {
        return None;
    }
    let names = certificate.subject_alternative_name().ok()??;
    let [GeneralName::DNSName(name)] = names.value.general_names.as_slice() else {
        return None;
    };
    if *name != domain {
        return None;
    }
    let validity = certificate.validity();
    Some(Window {
        valid_after: u64::try_from(validity.not_before.timestamp()).ok()?,
        valid_before: u64::try_from(validity.not_after.timestamp()).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    use jaunt_proto::{BoxFuture, GateTlsCertificate, GateTlsIssueError, GateTlsIssuer};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, PKCS_ED25519,
        PublicKeyData, SubjectPublicKeyInfo, date_time_ymd,
    };
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::{GateCertificate, inspect};
    use crate::host_cert::Clock;

    const START: u64 = 1_700_000_000;
    const DAY: u64 = 24 * 3600;

    struct Scripted {
        ca: CertifiedIssuer<'static, KeyPair>,
        offset: Arc<AtomicU64>,
        failing: AtomicBool,
        calls: Mutex<Vec<Instant>>,
    }

    impl Scripted {
        fn new() -> Arc<Self> {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            Arc::new(Self {
                ca: CertifiedIssuer::self_signed(
                    params,
                    KeyPair::generate_for(&PKCS_ED25519).unwrap(),
                )
                .unwrap(),
                offset: Arc::new(AtomicU64::new(0)),
                failing: AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn clock(&self) -> Clock {
            let offset = Arc::clone(&self.offset);
            Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(START + offset.load(Ordering::SeqCst))
            })
        }

        fn calls(&self) -> Vec<Instant> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl GateTlsIssuer for Scripted {
        fn issue<'a>(
            &'a self,
            subject_public_key_der: &'a [u8],
            server_name: &'a str,
        ) -> BoxFuture<'a, Result<GateTlsCertificate, GateTlsIssueError>> {
            self.calls.lock().unwrap().push(Instant::now());
            Box::pin(async move {
                if self.failing.load(Ordering::SeqCst) {
                    return Err(GateTlsIssueError::Unavailable);
                }
                let now = START + self.offset.load(Ordering::SeqCst);
                let subject = SubjectPublicKeyInfo::from_der(subject_public_key_der).unwrap();
                let mut params = CertificateParams::new(vec![server_name.to_owned()]).unwrap();
                params.not_before = date_time_ymd(1970, 1, 1) + Duration::from_secs(now - 60);
                params.not_after =
                    date_time_ymd(1970, 1, 1) + Duration::from_secs(now - 60 + 7 * DAY);
                let certificate = params.signed_by(&subject, &*self.ca).unwrap();
                Ok(GateTlsCertificate {
                    certificate_der: certificate.der().to_vec(),
                    serial: u64::try_from(self.calls().len()).unwrap(),
                    valid_after: 0,
                    valid_before: 0,
                })
            })
        }
    }

    async fn calls_reach(issuer: &Scripted, count: usize) {
        let mut waited = 0_u32;
        while issuer.calls().len() < count {
            assert!(waited < 100_000, "the issuer was not called often enough");
            waited += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failed_renewals_back_off_keep_the_certificate_and_stopping_ends_the_loop() {
        let issuer = Scripted::new();
        let certificate = Arc::new(
            GateCertificate::obtain(issuer.clone(), "svc.test".to_owned(), issuer.clock())
                .await
                .unwrap(),
        );
        assert_eq!(certificate.valid_before(), START - 60 + 7 * DAY);
        let stop = CancellationToken::new();
        let renewing = Arc::clone(&certificate);
        let token = stop.clone();
        let task = tokio::spawn(async move {
            renewing
                .renew_forever(Duration::from_secs(60), Duration::from_secs(5), token)
                .await;
        });

        tokio::time::sleep(Duration::from_secs(10 * 60)).await;
        assert_eq!(issuer.calls().len(), 1, "renewed a fresh certificate");

        issuer.failing.store(true, Ordering::SeqCst);
        issuer.offset.store(4 * DAY, Ordering::SeqCst);
        calls_reach(&issuer, 6).await;
        assert_eq!(certificate.valid_before(), START - 60 + 7 * DAY);
        assert!(!certificate.expired());
        issuer.failing.store(false, Ordering::SeqCst);
        calls_reach(&issuer, 7).await;
        let calls = issuer.calls();
        let gaps: Vec<u64> = calls[2..]
            .iter()
            .zip(&calls[1..])
            .map(|(later, earlier)| (*later - *earlier).as_secs())
            .collect();
        assert_eq!(gaps, [5, 10, 20, 40, 80]);
        assert_eq!(certificate.valid_before(), START + 4 * DAY - 60 + 7 * DAY);

        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the renewal loop did not stop")
            .unwrap();
        tokio::time::sleep(Duration::from_secs(60 * 60)).await;
        assert_eq!(issuer.calls().len(), 7);
    }

    #[test]
    fn only_a_certificate_for_the_requested_key_and_exactly_the_domain_is_usable() {
        let issuer = Scripted::new();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let public = key.subject_public_key_info();
        let other = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let sign = |names: Vec<String>, subject: &KeyPair| {
            let mut params = CertificateParams::new(names).unwrap();
            params.not_before = date_time_ymd(2030, 1, 1);
            params.not_after = date_time_ymd(2030, 1, 8);
            params
                .signed_by(subject, &*issuer.ca)
                .unwrap()
                .der()
                .to_vec()
        };
        let good = sign(vec!["svc.test".to_owned()], &key);
        let window = inspect(&good, &public, "svc.test").unwrap();
        assert_eq!(
            (window.valid_after, window.valid_before),
            (1_893_456_000, 1_894_060_800)
        );
        let mut trailing = good.clone();
        trailing.push(0);
        for (der, name) in [
            (sign(vec!["svc.test".to_owned()], &other), "svc.test"),
            (sign(vec!["other.test".to_owned()], &key), "svc.test"),
            (
                sign(vec!["svc.test".to_owned(), "x.svc.test".to_owned()], &key),
                "svc.test",
            ),
            (good.clone(), "other.test"),
            (trailing, "svc.test"),
        ] {
            assert!(inspect(&der, &public, name).is_none(), "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_certificate_past_its_end_is_reported_expired() {
        let issuer = Scripted::new();
        let certificate =
            GateCertificate::obtain(issuer.clone(), "svc.test".to_owned(), issuer.clock())
                .await
                .unwrap();
        issuer.offset.store(7 * DAY - 61, Ordering::SeqCst);
        assert!(!certificate.expired());
        issuer.offset.store(7 * DAY - 60, Ordering::SeqCst);
        assert!(certificate.expired());
    }
}
