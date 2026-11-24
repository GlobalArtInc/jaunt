pub(crate) mod approval;
pub(crate) mod browser;
mod code;
mod forms;
mod limiter;
pub(crate) mod net;
pub(crate) mod page;
mod poll;
mod polls;
mod proceed;
mod start;
mod tokens;
mod verify;

use axum::Router;
use axum::http::HeaderName;
use axum::routing::{get, post};
use ipnet::IpNet;
use jaunt_limits::TrustedProxies;

use crate::control::Control;
use crate::error::ControlError;

use self::approval::Approval;
use self::limiter::{FailureLimiter, Limits};
use self::net::ClientIp;
use self::polls::PollTracker;
use self::tokens::TokenBook;

pub(crate) const DEVICE_KIND: &str = "device";
pub(crate) const EXPIRES_IN_SECS: u32 = 300;
pub(crate) const POLL_INTERVAL_SECS: u32 = 5;

const VERIFICATION_PATH: &str = "/login/device";

#[derive(Debug, Clone)]
pub struct DeviceSettings {
    pub enabled: bool,
    pub public_origin: String,
    pub client_ip_header: Option<String>,
    pub client_ip_trusted_proxies: Vec<IpNet>,
}

pub(crate) struct DeviceState {
    pub(crate) enabled: bool,
    pub(crate) origin: String,
    pub(crate) client_ip: ClientIp,
    pub(crate) capacity: usize,
    pub(crate) failures: FailureLimiter,
    pub(crate) continue_tokens: TokenBook<()>,
    pub(crate) approvals: TokenBook<Approval>,
    pub(crate) polls: PollTracker,
}

impl DeviceState {
    pub(crate) fn new(
        settings: DeviceSettings,
        capacity: usize,
    ) -> Result<DeviceState, ControlError> {
        if !net::is_valid_origin(&settings.public_origin) {
            return Err(ControlError::InvalidPublicOrigin);
        }
        if !net::is_canonical_origin(&settings.public_origin) {
            return Err(ControlError::NonCanonicalPublicOrigin);
        }
        let client_ip_header = settings
            .client_ip_header
            .map(|name| {
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| ControlError::InvalidClientIpHeader)
            })
            .transpose()?;
        let proxies = TrustedProxies::new(settings.client_ip_trusted_proxies)
            .map_err(ControlError::UnusableTrustedProxy)?;
        match (client_ip_header.is_some(), proxies.is_empty()) {
            (true, true) => return Err(ControlError::ClientIpHeaderWithoutTrustedProxies),
            (false, false) => return Err(ControlError::TrustedProxiesWithoutClientIpHeader),
            (true, false) | (false, true) => {}
        }
        Ok(DeviceState {
            enabled: settings.enabled,
            origin: settings.public_origin,
            client_ip: ClientIp::new(client_ip_header, proxies),
            capacity,
            failures: FailureLimiter::new(Limits::STANDARD),
            continue_tokens: TokenBook::new(capacity),
            approvals: TokenBook::new(capacity),
            polls: PollTracker::new(capacity),
        })
    }

    pub(crate) fn verification_url(&self) -> String {
        format!("{}{VERIFICATION_PATH}", self.origin)
    }

    pub(crate) fn sweep(&self, now: i64, tick_secs: i64) {
        self.failures.sweep(tick_secs);
        self.continue_tokens.sweep(now);
        self.approvals.sweep(now);
        self.polls.sweep(now);
    }
}

pub(crate) fn mount(routes: Router<Control>, control: &Control) -> Router<Control> {
    if !control.device.enabled {
        return routes;
    }
    routes.merge(
        Router::new()
            .route("/v1/login/device/start", post(start::handle))
            .route("/v1/login/device/poll", post(poll::handle))
            .route(VERIFICATION_PATH, get(verify::show).post(verify::submit))
            .route("/login/device/continue", post(proceed::handle))
            .route("/login/device/approve", post(approval::approve))
            .route("/login/device/deny", post(approval::deny))
            .route("/static/login.css", get(stylesheet)),
    )
}

async fn stylesheet() -> axum::response::Response {
    page::stylesheet()
}
