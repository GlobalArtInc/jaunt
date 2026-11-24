use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use jaunt_ca::{CaKind, InternalCa, MAX_USER_VALIDITY, Signer, TrustSet};
use jaunt_oidc::OidcClient;
use jaunt_policy::{PolicyHandle, PolicySet};
use jaunt_store::{EnrollmentState, Store};
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;

use crate::admin::NodeAdmin;
use crate::clock::{Clock, Moment};
use crate::device::{DeviceSettings, DeviceState};
use crate::error::ControlError;
use crate::http;
use crate::naming::{AgentEndpoint, GateEndpoint, SshSuffix};
use crate::node_audit;
use crate::pending::PendingLogins;
use crate::rate_limit::RateLimiter;

pub const PENDING_CAPACITY: usize = 10_000;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const STORED_REQUEST_RETENTION_SECS: i64 = 3600;
const STORED_ENROLLMENT_RETENTION_SECS: i64 = 3600;
const STALE_DELIVERY_SECS: i64 = 120;
const STALE_SESSION_RETENTION_SECS: i64 = 3600;

pub struct ControlParts {
    pub store: Store,
    pub oidc: OidcClient,
    pub user_authority: Arc<dyn Signer>,
    pub host_trust: TrustSet,
    pub host_authority: Arc<dyn Signer>,
    pub internal_ca: InternalCa,
    pub ssh_suffix: SshSuffix,
    pub gate_endpoint: Option<GateEndpoint>,
    pub agent_endpoint: AgentEndpoint,
    pub cert_ttl: Duration,
    pub pending_capacity: usize,
    pub device: DeviceSettings,
    pub policy: PolicyHandle,
    pub clock: Clock,
}

pub struct Inner {
    pub(crate) store: Store,
    pub(crate) oidc: OidcClient,
    pub(crate) user_authority: Arc<dyn Signer>,
    pub(crate) host_ca_keys: Vec<String>,
    pub(crate) host_authority: Arc<dyn Signer>,
    pub(crate) internal_ca: InternalCa,
    pub(crate) ssh_suffix: SshSuffix,
    pub(crate) gate_endpoint: Option<GateEndpoint>,
    pub(crate) agent_endpoint: AgentEndpoint,
    pub(crate) cert_ttl: Duration,
    pub(crate) pending: PendingLogins,
    pub(crate) device: DeviceState,
    pub(crate) poll_limiter: RateLimiter,
    pub(crate) enroll_limiter: RateLimiter,
    policy: PolicyHandle,
    clock: Clock,
}

#[derive(Clone)]
pub struct Control {
    inner: Arc<Inner>,
}

impl Deref for Control {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.inner
    }
}

impl Control {
    pub fn new(parts: ControlParts) -> Result<Control, ControlError> {
        if parts.user_authority.kind() != CaKind::User {
            return Err(ControlError::NotUserAuthority);
        }
        if parts.cert_ttl < Duration::from_secs(1) {
            return Err(ControlError::CertificateTtlTooShort);
        }
        if parts.pending_capacity == 0 {
            return Err(ControlError::NoPendingCapacity);
        }
        if parts.host_authority.kind() != CaKind::Host {
            return Err(ControlError::NotHostAuthority);
        }
        if parts.host_trust.active().key_data() != parts.host_authority.public_key().key_data() {
            return Err(ControlError::HostAuthorityNotTrusted);
        }
        let host_ca_keys = parts
            .host_trust
            .to_authorized_lines()
            .map_err(ControlError::HostKeys)?;
        let device = DeviceState::new(parts.device, parts.pending_capacity)?;
        let cert_ttl =
            Duration::from_secs(parts.cert_ttl.as_secs().min(MAX_USER_VALIDITY.as_secs()));
        Ok(Control {
            inner: Arc::new(Inner {
                store: parts.store,
                oidc: parts.oidc,
                user_authority: parts.user_authority,
                host_ca_keys,
                host_authority: parts.host_authority,
                internal_ca: parts.internal_ca,
                ssh_suffix: parts.ssh_suffix,
                gate_endpoint: parts.gate_endpoint,
                agent_endpoint: parts.agent_endpoint,
                cert_ttl,
                pending: PendingLogins::new(parts.pending_capacity),
                device,
                poll_limiter: RateLimiter::polls(),
                enroll_limiter: RateLimiter::enrollments(),
                policy: parts.policy,
                clock: parts.clock,
            }),
        })
    }

    pub fn router(&self) -> Router {
        http::router(self.clone())
    }

    pub fn agent_router(&self) -> Router {
        http::agent_router(self.clone())
    }

    pub fn policy(&self) -> &PolicyHandle {
        &self.inner.policy
    }

    pub(crate) fn policy_snapshot(&self) -> Arc<PolicySet> {
        self.inner.policy.snapshot()
    }

    pub fn node_admin(&self) -> NodeAdmin {
        NodeAdmin::new(self.store.clone(), self.clock.clone())
    }

    pub fn sweep_expired(&self) -> usize {
        match self.now() {
            Some(now) => {
                self.device.sweep(now.secs);
                self.pending.sweep(now.secs)
                    + self.poll_limiter.sweep(now.secs)
                    + self.enroll_limiter.sweep(now.secs)
            }
            None => 0,
        }
    }

    pub async fn purge_stored_requests(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .login_requests()
            .purge_expired(now.secs.saturating_sub(STORED_REQUEST_RETENTION_SECS))
            .await
            .map_err(ControlError::Purge)
    }

    pub async fn purge_stored_enrollments(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let purged = self
            .store
            .enrollments()
            .purge_expired(now.secs.saturating_sub(STORED_ENROLLMENT_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeEnrollments)?;
        for enrollment in &purged {
            if !enrollment.expiry_reported
                && matches!(
                    enrollment.state,
                    EnrollmentState::Pending
                        | EnrollmentState::Approved
                        | EnrollmentState::Delivering
                )
            {
                node_audit::enroll_expired(&enrollment.id, &enrollment.name);
            }
        }
        Ok(u64::try_from(purged.len()).unwrap_or(u64::MAX))
    }

    pub async fn purge_stale_sessions(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .sessions()
            .purge_expired_routed(now.secs.saturating_sub(STALE_SESSION_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeSessions)
    }

    pub async fn recover_stale_deliveries(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let recovered = self
            .store
            .enrollments()
            .recover_stale_deliveries(now.secs.saturating_sub(STALE_DELIVERY_SECS))
            .await
            .map_err(ControlError::RecoverDeliveries)?;
        for enrollment in &recovered {
            tracing::warn!(
                target: "jaunt::control",
                enrollment_id = %enrollment.id,
                name = %enrollment.name,
                "an interrupted delivery was returned to approved"
            );
        }
        Ok(u64::try_from(recovered.len()).unwrap_or(u64::MAX))
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ControlError> {
        let sweeper = tokio::spawn(sweep_forever(self.clone()));
        let served = axum::serve(
            listener,
            self.router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown)
        .await;
        sweeper.abort();
        served.map_err(ControlError::Serve)
    }

    pub(crate) fn now(&self) -> Option<Moment> {
        Moment::read(&self.clock)
    }
}

async fn sweep_forever(control: Control) {
    let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        control.sweep_expired();
        if let Err(err) = control.purge_stored_requests().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging expired login requests failed");
        }
        if let Err(err) = control.recover_stale_deliveries().await {
            tracing::warn!(target: "jaunt::control", error = %err, "recovering interrupted deliveries failed");
        }
        if let Err(err) = control.purge_stored_enrollments().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging expired enrollments failed");
        }
        if let Err(err) = control.purge_stale_sessions().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging stale sessions failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener as StdListener;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use jaunt_ca::{AgeIdentity, CaKind, FileBackend, InternalCa};
    use jaunt_oidc::{ClientSecret, OidcClient, OidcConfig};
    use jaunt_policy::{PolicyHandle, PolicySet};
    use jaunt_store::Store;

    use super::{Control, ControlParts};
    use crate::clock::system_clock;
    use crate::device::DeviceSettings;
    use crate::naming::{AgentEndpoint, SshSuffix};

    const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy] }\n";

    fn fake_discovery() -> String {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let discovery = format!(
            "{{\"issuer\":\"{base}\",\"authorization_endpoint\":\"{base}/authorize\",\
             \"token_endpoint\":\"{base}/token\",\"jwks_uri\":\"{base}/jwks\",\
             \"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\
             \"id_token_signing_alg_values_supported\":[\"EdDSA\"]}}"
        );
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = stream.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                }
                let body = if request.starts_with(b"GET /jwks") {
                    "{\"keys\":[]}".to_owned()
                } else {
                    discovery.clone()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        base
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_policy_snapshot_is_the_loaded_set() {
        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join("policy");
        std::fs::create_dir(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("roles.yaml"), ROLE).unwrap();
        let policy = PolicyHandle::empty();
        assert!(policy.reload(&policy_dir).applied);

        let ca_root = dir.path().join("ca");
        let identity = AgeIdentity::generate();
        for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
            FileBackend::init(&ca_root, kind, &identity.recipient()).unwrap();
        }
        let (_, user) = FileBackend::load(&ca_root, CaKind::User, &identity).unwrap();
        let (host_trust, host) = FileBackend::load(&ca_root, CaKind::Host, &identity).unwrap();
        let (_, internal) = FileBackend::load(&ca_root, CaKind::Internal, &identity).unwrap();
        let root = InternalCa::create_root(&internal, SystemTime::now()).unwrap();
        let internal_ca = InternalCa::new(Arc::new(internal), root.certificate_der).unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        let oidc = OidcClient::discover(OidcConfig::new(
            fake_discovery(),
            "jaunt",
            ClientSecret::new("secret".to_owned()),
            "https://jaunt.example/v1/login/callback",
        ))
        .await
        .unwrap();

        let control = Control::new(ControlParts {
            store,
            oidc,
            user_authority: Arc::new(user),
            host_trust,
            host_authority: Arc::new(host),
            internal_ca,
            ssh_suffix: SshSuffix::parse("jaunt.test").unwrap(),
            gate_endpoint: None,
            agent_endpoint: AgentEndpoint::parse("agents.example.com:443").unwrap(),
            cert_ttl: Duration::from_secs(3600),
            pending_capacity: 10,
            device: DeviceSettings {
                enabled: false,
                public_origin: "https://jaunt.example".to_owned(),
                client_ip_header: None,
            },
            policy: policy.clone(),
            clock: system_clock(),
        })
        .unwrap();

        let snapshot = control.policy_snapshot();
        assert_eq!(snapshot.hash(), policy.snapshot().hash());
        assert_ne!(snapshot.hash(), PolicySet::empty().hash());
        assert_eq!(snapshot.role_count(), 1);
    }
}
