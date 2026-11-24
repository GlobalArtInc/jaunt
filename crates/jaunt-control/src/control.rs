use std::future::Future;
use std::net::SocketAddr;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use jaunt_ca::{CaKind, MAX_USER_VALIDITY, Signer, TrustSet};
use jaunt_oidc::OidcClient;
use jaunt_store::Store;
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;

use crate::clock::{Clock, Moment};
use crate::device::{DeviceSettings, DeviceState};
use crate::error::ControlError;
use crate::http;
use crate::pending::PendingLogins;

pub const PENDING_CAPACITY: usize = 10_000;

const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const STORED_REQUEST_RETENTION_SECS: i64 = 3600;

pub struct ControlParts {
    pub store: Store,
    pub oidc: OidcClient,
    pub user_authority: Arc<dyn Signer>,
    pub host_trust: TrustSet,
    pub cert_ttl: Duration,
    pub pending_capacity: usize,
    pub device: DeviceSettings,
    pub clock: Clock,
}

pub struct Inner {
    pub(crate) store: Store,
    pub(crate) oidc: OidcClient,
    pub(crate) user_authority: Arc<dyn Signer>,
    pub(crate) host_ca_keys: Vec<String>,
    pub(crate) cert_ttl: Duration,
    pub(crate) pending: PendingLogins,
    pub(crate) device: DeviceState,
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
                cert_ttl,
                pending: PendingLogins::new(parts.pending_capacity),
                device,
                clock: parts.clock,
            }),
        })
    }

    pub fn router(&self) -> Router {
        http::router(self.clone())
    }

    pub fn sweep_expired(&self) -> usize {
        match self.now() {
            Some(now) => {
                self.device.sweep(now.secs);
                self.pending.sweep(now.secs)
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
    }
}
