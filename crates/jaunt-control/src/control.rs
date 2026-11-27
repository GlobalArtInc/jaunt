use std::future::Future;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::Router;
use jaunt_ca::{
    CaError, CaKind, ClientSlot, InternalCa, IssuedCertificate, MAX_USER_VALIDITY,
    ServerCertParams, Signer, TrustSet,
};
use jaunt_limits::RateLimiter;
use jaunt_oidc::OidcClient;
use jaunt_policy::{PolicyHandle, PolicySet};
use jaunt_proto::ClientTransport;
use jaunt_store::{EnrollmentState, Store};
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;

use crate::admin::NodeAdmin;
use crate::audit::{self, SessionEnd};
use crate::ca_snapshot::CaSnapshot;
use crate::clock::{Clock, Moment, Ticker, monotonic_ticker, whole_secs};
use crate::device::{DeviceSettings, DeviceState};
use crate::error::ControlError;
use crate::host_accounts::HostAccounts;
use crate::http;
use crate::join_tokens::JoinTokenAdmin;
use crate::killer::{KillerSlot, SessionKiller};
use crate::limits::{NoiseLog, RequestLimiters, RequestLimits};
use crate::naming::{AgentEndpoint, GateEndpoint, ServicesDomain, SshSuffix};
use crate::node_audit;
use crate::pending::PendingLogins;
use crate::presence::{AgentPresence, PresenceSlot};
use crate::rate_limit;
use crate::recordings::{self, RecordingSettings, RecoveredRecordings, RejectionLog, Uploads};
use crate::revocation::RevocationAdmin;
use crate::serve;
use crate::services;
use crate::session_sweep::RevocationWatch;
use crate::web::WebState;
use crate::web::terminal::{End, TerminalGate, WebTerminalSettings};
use crate::{db_client, service_authorize, service_cert, x509_cert};

pub const PENDING_CAPACITY: usize = 10_000;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const STORED_REQUEST_RETENTION_SECS: i64 = 3600;
const STORED_ENROLLMENT_RETENTION_SECS: i64 = 3600;
const EXPIRED_JOIN_TOKEN_RETENTION_SECS: i64 = 3600;
const DEAD_ADMIN_TOKEN_RETENTION_SECS: i64 = 30 * 86_400;
const STALE_DELIVERY_SECS: i64 = 120;
const STALE_SESSION_RETENTION_SECS: i64 = 3600;
const SERVICE_CERTIFICATE_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;
const CLOSE_POLL: Duration = Duration::from_millis(20);

pub struct ControlParts {
    pub store: Store,
    pub oidc: OidcClient,
    pub user_authority: Arc<dyn Signer>,
    pub user_trust: TrustSet,
    pub host_trust: TrustSet,
    pub host_authority: Arc<dyn Signer>,
    pub ca_dir: PathBuf,
    pub internal_ca: InternalCa,
    pub ssh_suffix: SshSuffix,
    pub gate_endpoint: Option<GateEndpoint>,
    pub agent_endpoint: AgentEndpoint,
    pub cert_ttl: Duration,
    pub pending_capacity: usize,
    pub device: DeviceSettings,
    pub policy: PolicyHandle,
    pub web_enabled: bool,
    pub clock: Clock,
    pub recordings: Option<RecordingSettings>,
    pub user_x509: Option<ClientSlot>,
    pub services_domain: Option<String>,
    pub client_transport: Option<ClientTransport>,
    pub db_client: Option<ClientSlot>,
}

pub struct Inner {
    pub(crate) store: Store,
    pub(crate) oidc: OidcClient,
    ca: ArcSwap<CaSnapshot>,
    pub(crate) ca_dir: PathBuf,
    pub(crate) internal_ca: InternalCa,
    pub(crate) ssh_suffix: SshSuffix,
    pub(crate) gate_endpoint: Option<GateEndpoint>,
    pub(crate) agent_endpoint: AgentEndpoint,
    pub(crate) cert_ttl: Duration,
    pub(crate) pending: PendingLogins,
    pub(crate) device: DeviceState,
    pub(crate) poll_limiter: RateLimiter<String>,
    pub(crate) request_limits: RequestLimiters,
    pub(crate) callback_noise: NoiseLog,
    policy: PolicyHandle,
    pub(crate) web: WebState,
    clock: Clock,
    ticker: Ticker,
    started_at: Option<i64>,
    pub(crate) killer: Arc<KillerSlot>,
    pub(crate) watched: Arc<RevocationWatch>,
    pub(crate) recordings: Option<Uploads>,
    pub(crate) recording_rejections: RejectionLog,
    pub(crate) presence: PresenceSlot,
    pub(crate) host_accounts: HostAccounts,
    pub(crate) service_announcements: RateLimiter<String>,
    pub(crate) service_reads: RateLimiter<String>,
    user_x509: ArcSwapOption<ClientSlot>,
    pub(crate) services_domain: Option<ServicesDomain>,
    pub(crate) client_transport: ClientTransport,
    pub(crate) x509_issuance: RateLimiter<String>,
    pub(crate) service_issuance: RateLimiter<String>,
    db_client: ArcSwapOption<ClientSlot>,
    pub(crate) db_client_user_issuance: RateLimiter<String>,
    pub(crate) service_user_authorizations: RateLimiter<(String, String)>,
    pub(crate) service_authorizations: RateLimiter<String>,
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
        Control::with_request_limits(parts, RequestLimits::default())
    }

    pub fn with_request_limits(
        parts: ControlParts,
        limits: RequestLimits,
    ) -> Result<Control, ControlError> {
        Control::build(parts, limits, monotonic_ticker())
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn with_limits_and_ticker(
        parts: ControlParts,
        limits: RequestLimits,
        ticker: Ticker,
    ) -> Result<Control, ControlError> {
        Control::build(parts, limits, ticker)
    }

    fn build(
        parts: ControlParts,
        limits: RequestLimits,
        ticker: Ticker,
    ) -> Result<Control, ControlError> {
        let ca = CaSnapshot::new(
            parts.user_authority,
            parts.user_trust,
            parts.host_authority,
            parts.host_trust,
        )?;
        if parts.cert_ttl < Duration::from_secs(1) {
            return Err(ControlError::CertificateTtlTooShort);
        }
        if parts.pending_capacity == 0 {
            return Err(ControlError::NoPendingCapacity);
        }
        if parts
            .recordings
            .as_ref()
            .is_some_and(|settings| !settings.limits.is_usable())
        {
            return Err(ControlError::RecordingLimits);
        }
        let services_domain = parts
            .services_domain
            .as_deref()
            .map(ServicesDomain::parse)
            .transpose()
            .map_err(ControlError::ServicesDomain)?;
        let client_transport = client_transport(parts.client_transport, services_domain.is_some())?;
        if parts
            .user_x509
            .as_ref()
            .is_some_and(|slot| slot.ca.kind() != CaKind::UserX509)
        {
            return Err(ControlError::NotUserX509Authority);
        }
        if parts
            .db_client
            .as_ref()
            .is_some_and(|slot| slot.ca.kind() != CaKind::DbClient)
        {
            return Err(ControlError::NotDbClientAuthority);
        }
        let web = WebState::new(parts.web_enabled, &parts.device.public_origin);
        let device = DeviceState::new(parts.device, parts.pending_capacity)?;
        let cert_ttl =
            Duration::from_secs(parts.cert_ttl.as_secs().min(MAX_USER_VALIDITY.as_secs()));
        let started_at = Moment::read(&parts.clock).map(|now| now.secs);
        let watched = RevocationWatch::starting_at(started_at);
        let killer = Arc::new(KillerSlot::default());
        killer.watch_terminals(Arc::clone(&web.terminals.live));
        Ok(Control {
            inner: Arc::new(Inner {
                store: parts.store,
                oidc: parts.oidc,
                ca: ArcSwap::from_pointee(ca),
                ca_dir: parts.ca_dir,
                internal_ca: parts.internal_ca,
                ssh_suffix: parts.ssh_suffix,
                gate_endpoint: parts.gate_endpoint,
                agent_endpoint: parts.agent_endpoint,
                cert_ttl,
                pending: PendingLogins::new(parts.pending_capacity),
                device,
                poll_limiter: rate_limit::handle_polls(),
                request_limits: RequestLimiters::new(&limits),
                callback_noise: NoiseLog::new(),
                policy: parts.policy,
                web,
                clock: parts.clock,
                ticker,
                started_at,
                killer,
                watched: Arc::new(watched),
                recordings: parts.recordings.map(Uploads::new),
                recording_rejections: RejectionLog::default(),
                presence: PresenceSlot::default(),
                host_accounts: HostAccounts::default(),
                service_announcements: services::announcement_limiter(),
                service_reads: services::read_limiter(),
                user_x509: ArcSwapOption::from(parts.user_x509.map(Arc::new)),
                services_domain,
                client_transport,
                x509_issuance: x509_cert::issuance_limiter(),
                service_issuance: service_cert::issuance_limiter(),
                db_client: ArcSwapOption::from(parts.db_client.map(Arc::new)),
                db_client_user_issuance: db_client::user_issuance_limiter(),
                service_user_authorizations: service_authorize::user_authorization_limiter(),
                service_authorizations: service_authorize::authorization_limiter(),
            }),
        })
    }

    pub fn router(&self) -> Router {
        http::router(self.clone(), Router::new())
    }

    #[doc(hidden)]
    pub fn router_with_extra_web_routes(&self, extra: Router<Control>) -> Router {
        http::router(self.clone(), extra)
    }

    pub fn agent_router(&self) -> Router {
        http::agent_router(self.clone())
    }

    pub fn policy(&self) -> &PolicyHandle {
        &self.inner.policy
    }

    pub fn ca_snapshot(&self) -> Arc<CaSnapshot> {
        self.inner.ca.load_full()
    }

    pub fn replace_snapshot(&self, snapshot: CaSnapshot) -> Arc<CaSnapshot> {
        self.inner.ca.swap(Arc::new(snapshot))
    }

    pub fn user_x509(&self) -> Option<Arc<ClientSlot>> {
        self.inner.user_x509.load_full()
    }

    pub fn replace_user_x509(&self, slot: ClientSlot) -> Result<(), ControlError> {
        if slot.ca.kind() != CaKind::UserX509 {
            return Err(ControlError::NotUserX509Authority);
        }
        self.inner.user_x509.store(Some(Arc::new(slot)));
        Ok(())
    }

    pub fn db_client(&self) -> Option<Arc<ClientSlot>> {
        self.inner.db_client.load_full()
    }

    pub fn replace_db_client(&self, slot: ClientSlot) -> Result<(), ControlError> {
        if slot.ca.kind() != CaKind::DbClient {
            return Err(ControlError::NotDbClientAuthority);
        }
        self.inner.db_client.store(Some(Arc::new(slot)));
        Ok(())
    }

    pub(crate) fn policy_snapshot(&self) -> Arc<PolicySet> {
        self.inner.policy.snapshot()
    }

    pub fn node_admin(&self) -> NodeAdmin {
        NodeAdmin::new(self.store.clone(), self.clock.clone())
    }

    pub fn join_tokens(&self) -> JoinTokenAdmin {
        JoinTokenAdmin::new(self.store.clone(), self.clock.clone())
    }

    pub fn revocations(&self) -> RevocationAdmin {
        RevocationAdmin::shared(
            self.store.clone(),
            self.clock.clone(),
            Arc::clone(&self.inner.killer),
            Arc::clone(&self.inner.watched),
        )
    }

    pub fn install_session_killer(&self, killer: Arc<dyn SessionKiller>) {
        self.inner.killer.install(killer);
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub async fn open_web_session(&self, user_id: &str) -> Option<crate::web::TestWebSession> {
        crate::web::open_for_tests(self, user_id).await
    }

    pub fn install_web_terminal(&self, gate: Arc<dyn TerminalGate>, settings: WebTerminalSettings) {
        self.web.terminals.install(gate, settings);
    }

    pub async fn close_web_terminals(&self, grace: Duration) -> usize {
        let closing = self.web.terminals.live.stop_all(End::Shutdown);
        let deadline = tokio::time::Instant::now() + grace;
        while self.web.terminals.live.open() > 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(CLOSE_POLL).await;
        }
        closing
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn web_terminal_counters(&self) -> crate::web::terminal::WebTerminalCounters {
        self.web.terminals.counters()
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn use_web_terminal_keys(
        &self,
        source: impl Fn() -> Result<jaunt_ssh::EphemeralKey, jaunt_ssh::JumpError>
        + Send
        + Sync
        + 'static,
    ) {
        self.web.terminals.use_keys(Arc::new(source));
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn hold_web_terminal(
        &self,
        user_id: &str,
        web_session: &str,
        node_id: &str,
    ) -> Option<crate::web::HeldTerminal> {
        self.web.terminals.hold(user_id, web_session, node_id)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn web_terminal_certificates(&self) -> Vec<String> {
        self.web.terminals.issued()
    }

    pub fn set_recording_playback_limit(&self, bytes: u64) {
        self.web.playback.set(bytes);
    }

    pub fn install_agent_presence(&self, presence: Arc<dyn AgentPresence>) {
        self.inner.presence.install(presence);
    }

    pub fn issue_server_certificate(
        &self,
        params: ServerCertParams,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        self.internal_ca.issue_server_certificate(params, now)
    }

    pub fn internal_root_der(&self) -> &[u8] {
        self.internal_ca.root_der()
    }

    pub fn sweep_expired(&self) -> usize {
        let tick = self.tick();
        self.request_limits.sweep(tick);
        self.web.tokens.sweep(tick);
        self.x509_issuance.sweep(tick);
        self.service_issuance.sweep(tick);
        self.service_reads.sweep(tick);
        self.db_client_user_issuance.sweep(tick);
        self.service_user_authorizations.sweep(tick);
        self.service_authorizations.sweep(tick);
        let polls = self.poll_limiter.sweep(tick);
        match self.now() {
            Some(now) => {
                self.device.sweep(now.secs, whole_secs(tick));
                self.pending.sweep(now.secs) + polls
            }
            None => polls,
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

    pub async fn purge_join_tokens(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .join_tokens()
            .purge_expired(now.secs.saturating_sub(EXPIRED_JOIN_TOKEN_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeJoinTokens)
    }

    pub async fn purge_admin_tokens(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .admin_tokens()
            .purge_dead(now.secs.saturating_sub(DEAD_ADMIN_TOKEN_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeAdminTokens)
    }

    pub async fn purge_stale_sessions(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .sessions()
            .purge_expired_routed(now.secs.saturating_sub(STALE_SESSION_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeSessions)
    }

    pub async fn purge_service_certificates(&self) -> Result<u64, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        self.store
            .service_certificates()
            .purge_expired(now.secs.saturating_sub(SERVICE_CERTIFICATE_RETENTION_SECS))
            .await
            .map_err(ControlError::PurgeServiceCertificates)
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

    pub async fn purge_web_sessions(&self) -> Result<usize, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let ended = self
            .store
            .web_sessions()
            .purge_expired(now.secs)
            .await
            .map_err(ControlError::PurgeWebSessions)?;
        for user_id in &ended {
            audit::web_session_ended(user_id, SessionEnd::Expired);
        }
        Ok(ended.len())
    }

    pub async fn sweep_idle_recordings(&self) -> usize {
        recordings::sweep(self).await
    }

    #[doc(hidden)]
    pub fn recording_upload_waiters(&self, session_id: &str) -> usize {
        self.recordings
            .as_ref()
            .map_or(0, |uploads| uploads.waiting_for(session_id))
    }

    pub async fn recover_recordings(&self) -> Result<RecoveredRecordings, ControlError> {
        recordings::recover(self)
            .await
            .map_err(ControlError::RecoverRecordings)
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub async fn serve(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ControlError> {
        self.serve_sweeping_every(listener, shutdown, SWEEP_INTERVAL)
            .await
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub async fn serve_with_sweep_interval(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
        sweep_interval: Duration,
    ) -> Result<(), ControlError> {
        self.serve_sweeping_every(listener, shutdown, sweep_interval)
            .await
    }

    async fn serve_sweeping_every(
        self,
        listener: TcpListener,
        shutdown: impl Future<Output = ()> + Send + 'static,
        sweep_interval: Duration,
    ) -> Result<(), ControlError> {
        if sweep_interval.is_zero() {
            return Err(ControlError::ZeroSweepInterval);
        }
        let sweeper = tokio::spawn(sweep_forever(self.clone(), sweep_interval));
        serve::serve(
            self.router(),
            listener,
            serve::ServerLimits::new(
                self.request_limits.max_connections,
                self.request_limits.max_connections_per_address,
                self.device.client_ip.trusted_proxies().clone(),
            ),
            shutdown,
        )
        .await;
        sweeper.abort();
        Ok(())
    }

    pub(crate) fn now(&self) -> Option<Moment> {
        Moment::read(&self.clock)
    }

    pub(crate) fn tick(&self) -> Duration {
        (self.ticker)()
    }

    pub(crate) fn started_at(&self) -> Option<i64> {
        self.started_at
    }

    pub(crate) fn public_origin(&self) -> &str {
        &self.device.origin
    }
}

fn client_transport(
    configured: Option<ClientTransport>,
    services_domain: bool,
) -> Result<ClientTransport, ControlError> {
    match (configured, services_domain) {
        (Some(ClientTransport::Tls), false) => Err(ControlError::TlsTransportWithoutServicesDomain),
        (Some(chosen), _) => Ok(chosen),
        (None, true) => Ok(ClientTransport::Tls),
        (None, false) => Ok(ClientTransport::Tcp),
    }
}

async fn sweep_forever(control: Control, sweep_interval: Duration) {
    let mut ticker = tokio::time::interval(sweep_interval);
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
        if let Err(err) = control.purge_join_tokens().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging expired join tokens failed");
        }
        if let Err(err) = control.purge_admin_tokens().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging dead admin tokens failed");
        }
        if let Err(err) = control.purge_stale_sessions().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging stale sessions failed");
        }
        if let Err(err) = control.purge_web_sessions().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging expired web sessions failed");
        }
        if let Err(err) = control.purge_service_certificates().await {
            tracing::warn!(target: "jaunt::control", error = %err, "purging expired service certificates failed");
        }
        control.sweep_idle_recordings().await;
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
    use jaunt_proto::ClientTransport;
    use jaunt_store::Store;

    use super::{Control, ControlParts, client_transport};
    use crate::clock::system_clock;
    use crate::device::DeviceSettings;
    use crate::error::ControlError;
    use crate::naming::{AgentEndpoint, SshSuffix};

    #[test]
    fn the_client_transport_defaults_to_tls_only_with_a_services_domain() {
        for (configured, domain, expected) in [
            (None, false, Some(ClientTransport::Tcp)),
            (None, true, Some(ClientTransport::Tls)),
            (Some(ClientTransport::Tcp), true, Some(ClientTransport::Tcp)),
            (
                Some(ClientTransport::Tcp),
                false,
                Some(ClientTransport::Tcp),
            ),
            (Some(ClientTransport::Tls), true, Some(ClientTransport::Tls)),
            (Some(ClientTransport::Tls), false, None),
        ] {
            match (client_transport(configured, domain), expected) {
                (Ok(chosen), Some(expected)) => assert_eq!(chosen, expected),
                (Err(ControlError::TlsTransportWithoutServicesDomain), None) => {}
                (other, _) => panic!("{configured:?} {domain}: {other:?}"),
            }
        }
    }

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
        let (user_trust, user) = FileBackend::load(&ca_root, CaKind::User, &identity).unwrap();
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
            user_trust,
            host_trust,
            host_authority: Arc::new(host),
            ca_dir: ca_root.clone(),
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
                client_ip_trusted_proxies: Vec::new(),
            },
            policy: policy.clone(),
            web_enabled: false,
            clock: system_clock(),
            recordings: None,
            user_x509: None,
            services_domain: None,
            client_transport: None,
            db_client: None,
        })
        .unwrap();

        let snapshot = control.policy_snapshot();
        assert_eq!(snapshot.hash(), policy.snapshot().hash());
        assert_ne!(snapshot.hash(), PolicySet::empty().hash());
        assert_eq!(snapshot.role_count(), 1);
    }
}
