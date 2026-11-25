use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_proto::BoxFuture;
use jaunt_ssh::{HostIdentity, HostKey, ServerConfigCell, ServerProfile, SshError};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

pub(crate) const ISSUE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RENEWAL_RETRY: Duration = Duration::from_secs(15 * 60);

pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

pub trait HostCertIssuer: Send + Sync + 'static {
    fn issue<'a>(
        &'a self,
        public_key_openssh: &'a str,
        hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IssueError {
    #[error("the host certificate request is invalid")]
    InvalidRequest,
    #[error("the host certificate authority is unavailable")]
    Unavailable,
}

#[derive(Debug, Error)]
pub enum HostCertError {
    #[error("cannot generate the gate host key")]
    Key(#[source] SshError),
    #[error("cannot obtain the gate host certificate")]
    Issue(#[source] IssueError),
    #[error("the host certificate authority did not answer in time")]
    Timeout,
    #[error("the issued gate host certificate is not usable")]
    Certificate(#[source] SshError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    valid_after: u64,
    valid_before: u64,
}

impl Window {
    fn of(identity: &HostIdentity) -> Self {
        Self {
            valid_after: identity.valid_after(),
            valid_before: identity.valid_before(),
        }
    }

    fn renewal_due(self, now: u64) -> bool {
        let half = self.valid_before.saturating_sub(self.valid_after) / 2;
        now >= self.valid_after.saturating_add(half)
    }
}

pub(crate) struct HostCertificate {
    issuer: Arc<dyn HostCertIssuer>,
    hostnames: Vec<String>,
    clock: Clock,
    cell: Arc<ServerConfigCell>,
    window: Mutex<Window>,
    signer: Mutex<String>,
    issuing: tokio::sync::Mutex<()>,
}

impl HostCertificate {
    pub(crate) async fn obtain(
        issuer: Arc<dyn HostCertIssuer>,
        hostnames: Vec<String>,
        clock: Clock,
    ) -> Result<Self, HostCertError> {
        let identity = issue(issuer.as_ref(), &hostnames, &clock).await?;
        let window = Window::of(&identity);
        let signer = identity.signer_fingerprint();
        Ok(Self {
            issuer,
            hostnames,
            clock,
            cell: Arc::new(ServerConfigCell::new(identity, ServerProfile::Gate)),
            window: Mutex::new(window),
            signer: Mutex::new(signer),
            issuing: tokio::sync::Mutex::new(()),
        })
    }

    pub(crate) fn cell(&self) -> Arc<ServerConfigCell> {
        Arc::clone(&self.cell)
    }

    pub(crate) fn hostnames(&self) -> &[String] {
        &self.hostnames
    }

    fn window(&self) -> MutexGuard<'_, Window> {
        self.window.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> u64 {
        unix_secs((self.clock)())
    }

    pub(crate) fn signer(&self) -> String {
        self.signer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub(crate) async fn reissue(&self) -> Result<(), HostCertError> {
        let _issuing = self.issuing.lock().await;
        self.replace().await
    }

    pub(crate) async fn reissue_unless_signed_by(
        &self,
        fingerprint: &str,
    ) -> Result<bool, HostCertError> {
        let _issuing = self.issuing.lock().await;
        if self.signer() == fingerprint {
            return Ok(false);
        }
        self.replace().await?;
        Ok(true)
    }

    async fn replace(&self) -> Result<(), HostCertError> {
        let identity = issue(self.issuer.as_ref(), &self.hostnames, &self.clock).await?;
        let window = Window::of(&identity);
        let signer = identity.signer_fingerprint();
        self.cell.replace(identity);
        *self.window() = window;
        *self.signer.lock().unwrap_or_else(PoisonError::into_inner) = signer;
        tracing::info!(
            target: "jaunt::gate",
            valid_before = window.valid_before,
            "the gate host certificate was renewed"
        );
        Ok(())
    }

    async fn renew_if_due(&self) -> Result<(), HostCertError> {
        let _issuing = self.issuing.lock().await;
        if self.window().renewal_due(self.now()) {
            self.replace().await?;
        }
        Ok(())
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
                Ok(()) => failures = 0,
                Err(error) => {
                    failures = failures.saturating_add(1);
                    tracing::warn!(
                        target: "jaunt::gate",
                        error = %error,
                        failures,
                        retry_in_secs = retry_delay(retry, failures).as_secs(),
                        valid_before = self.window().valid_before,
                        "renewing the gate host certificate failed; retrying"
                    );
                }
            }
        }
    }
}

async fn issue(
    issuer: &dyn HostCertIssuer,
    hostnames: &[String],
    clock: &Clock,
) -> Result<HostIdentity, HostCertError> {
    let key = HostKey::generate().map_err(HostCertError::Key)?;
    let public = key.public_openssh().map_err(HostCertError::Key)?;
    let line = tokio::time::timeout(ISSUE_TIMEOUT, issuer.issue(&public, hostnames))
        .await
        .map_err(|_| HostCertError::Timeout)?
        .map_err(HostCertError::Issue)?;
    key.with_certificate(&line, unix_secs(clock()))
        .map_err(HostCertError::Certificate)
}

fn retry_delay(initial: Duration, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    initial
        .checked_mul(1 << doublings)
        .unwrap_or(MAX_RENEWAL_RETRY)
        .min(MAX_RENEWAL_RETRY)
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    use jaunt_proto::BoxFuture;
    use russh::keys::key::safe_rng;
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::{Algorithm, HashAlg, PrivateKey, PublicKey};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use super::{
        Clock, HostCertError, HostCertIssuer, HostCertificate, IssueError, MAX_RENEWAL_RETRY,
        Window, retry_delay,
    };

    const START: u64 = 1_700_000_000;
    const DAY: u64 = 24 * 3600;

    struct Scripted {
        ca: Mutex<PrivateKey>,
        offset: Arc<AtomicU64>,
        failing: AtomicBool,
        hanging: bool,
        calls: Mutex<Vec<Instant>>,
    }

    impl Scripted {
        fn new(hanging: bool) -> Arc<Self> {
            Arc::new(Self {
                ca: Mutex::new(PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()),
                offset: Arc::new(AtomicU64::new(0)),
                failing: AtomicBool::new(false),
                hanging,
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

        fn ca_fingerprint(&self) -> String {
            self.ca
                .lock()
                .unwrap()
                .public_key()
                .fingerprint(HashAlg::Sha256)
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        fn rotate_ca(&self) {
            *self.ca.lock().unwrap() =
                PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        }
    }

    impl HostCertIssuer for Scripted {
        fn issue<'a>(
            &'a self,
            public_key_openssh: &'a str,
            hostnames: &'a [String],
        ) -> BoxFuture<'a, Result<String, IssueError>> {
            self.calls.lock().unwrap().push(Instant::now());
            Box::pin(async move {
                if self.hanging {
                    std::future::pending::<()>().await;
                }
                if self.failing.load(Ordering::SeqCst) {
                    return Err(IssueError::Unavailable);
                }
                let public = PublicKey::from_openssh(public_key_openssh).unwrap();
                let now = START + self.offset.load(Ordering::SeqCst);
                let mut builder = Builder::new_with_random_nonce(
                    &mut safe_rng(),
                    public.key_data().clone(),
                    now - 120,
                    now + 7 * DAY,
                )
                .unwrap();
                builder.cert_type(CertType::Host).unwrap();
                builder.key_id("jaunt-host:gate").unwrap();
                for name in hostnames {
                    builder.valid_principal(name.as_str()).unwrap();
                }
                let ca = self.ca.lock().unwrap().clone();
                Ok(builder.sign(&ca).unwrap().to_openssh().unwrap())
            })
        }
    }

    async fn calls_reach(issuer: &Scripted, count: usize) {
        while issuer.calls().len() < count {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn an_issuer_that_never_answers_times_out_after_thirty_seconds() {
        let issuer = Scripted::new(true);
        let started = Instant::now();
        let obtained =
            HostCertificate::obtain(issuer.clone(), vec!["gate.test".to_owned()], issuer.clock())
                .await;
        assert!(matches!(obtained, Err(HostCertError::Timeout)));
        assert_eq!(started.elapsed(), Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_renewals_back_off_and_a_fresh_certificate_is_not_renewed() {
        let issuer = Scripted::new(false);
        let host = Arc::new(
            HostCertificate::obtain(issuer.clone(), vec!["gate.test".to_owned()], issuer.clock())
                .await
                .unwrap(),
        );
        let stop = CancellationToken::new();
        let renewing = Arc::clone(&host);
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
        issuer.failing.store(false, Ordering::SeqCst);
        calls_reach(&issuer, 7).await;
        let calls = issuer.calls();
        let gaps: Vec<u64> = calls[2..]
            .iter()
            .zip(&calls[1..])
            .map(|(later, earlier)| (*later - *earlier).as_secs())
            .collect();
        assert_eq!(gaps, [5, 10, 20, 40, 80]);

        tokio::time::sleep(Duration::from_secs(60 * 60)).await;
        assert_eq!(issuer.calls().len(), 7, "renewed again before half life");
        issuer.offset.store(8 * DAY, Ordering::SeqCst);
        calls_reach(&issuer, 8).await;
        stop.cancel();
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_certificate_from_another_authority_is_replaced_only_once_one_is_issued() {
        let issuer = Scripted::new(false);
        let host =
            HostCertificate::obtain(issuer.clone(), vec!["gate.test".to_owned()], issuer.clock())
                .await
                .unwrap();
        let first = issuer.ca_fingerprint();
        assert_eq!(host.signer(), first);
        assert!(!host.reissue_unless_signed_by(&first).await.unwrap());
        assert_eq!(issuer.calls().len(), 1);

        issuer.rotate_ca();
        let second = issuer.ca_fingerprint();
        issuer.failing.store(true, Ordering::SeqCst);
        let served = host.cell().current();
        assert!(matches!(
            host.reissue_unless_signed_by(&second).await,
            Err(HostCertError::Issue(IssueError::Unavailable))
        ));
        assert!(Arc::ptr_eq(&served, &host.cell().current()));
        assert_eq!(host.signer(), first);

        issuer.failing.store(false, Ordering::SeqCst);
        assert!(host.reissue_unless_signed_by(&second).await.unwrap());
        assert!(!Arc::ptr_eq(&served, &host.cell().current()));
        assert_eq!(host.signer(), second);
        assert!(!host.reissue_unless_signed_by(&second).await.unwrap());
        assert_eq!(issuer.calls().len(), 3);
    }

    #[test]
    fn renewal_is_due_from_half_of_the_lifetime_on() {
        let window = Window {
            valid_after: 1_000,
            valid_before: 1_000 + 7 * 24 * 3600,
        };
        let half = 1_000 + 7 * 12 * 3600;
        for (now, due) in [
            (0, false),
            (1_000, false),
            (half - 1, false),
            (half, true),
            (window.valid_before, true),
            (u64::MAX, true),
        ] {
            assert_eq!(window.renewal_due(now), due, "{now}");
        }
    }

    #[test]
    fn retries_double_up_to_a_ceiling() {
        let initial = Duration::from_secs(5);
        let delays: Vec<u64> = (1..=10)
            .map(|failures| retry_delay(initial, failures).as_secs())
            .collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 320, 640, 900, 900]);
        assert_eq!(retry_delay(Duration::MAX, 3), MAX_RENEWAL_RETRY);
        assert_eq!(retry_delay(initial, u32::MAX), MAX_RENEWAL_RETRY);
    }
}
