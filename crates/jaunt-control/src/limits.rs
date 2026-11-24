use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use jaunt_limits::{
    ClientKey, DEFAULT_CAPACITY, Decision, LogThrottle, MAX_TRACKED_ADDRESSES, Rate, RateLimiter,
};
use serde::Serialize;

use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::http::{json_response, server_error};

pub const DEFAULT_MAX_CONNECTIONS: usize = 4096;
pub const DEFAULT_MAX_CONNECTIONS_PER_ADDRESS: usize = 256;
pub const MAX_CONNECTIONS_LIMIT: usize = 1 << 20;

const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);
const NOISE_PER_ADDRESS: Rate = Rate::clamped(1, 6);
const NOISE_TRACKED: usize = 4096;
const NOISE_INTERVAL: Duration = Duration::from_secs(1);
const TOO_MANY_REQUESTS: &str = "too_many_requests";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    pub login_start: Rate,
    pub login_finish: Rate,
    pub device_start: Rate,
    pub device_poll: Rate,
    pub web_login: Rate,
    pub enroll: Rate,
    pub enroll_poll: Rate,
    pub other: Rate,
    pub tracked_addresses: usize,
    pub max_connections: usize,
    pub max_connections_per_address: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            login_start: Rate::clamped(60, 30),
            login_finish: Rate::clamped(60, 30),
            device_start: Rate::clamped(30, 10),
            device_poll: Rate::clamped(60, 60),
            web_login: Rate::clamped(60, 30),
            enroll: Rate::clamped(60, 6),
            enroll_poll: Rate::clamped(120, 120),
            other: Rate::clamped(600, 300),
            tracked_addresses: DEFAULT_CAPACITY,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_address: DEFAULT_MAX_CONNECTIONS_PER_ADDRESS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Endpoint {
    LoginStart,
    LoginFinish,
    DeviceStart,
    DevicePoll,
    WebLogin,
    Enroll,
    EnrollPoll,
    Other,
}

impl Endpoint {
    const ALL: [Endpoint; 8] = [
        Endpoint::LoginStart,
        Endpoint::LoginFinish,
        Endpoint::DeviceStart,
        Endpoint::DevicePoll,
        Endpoint::WebLogin,
        Endpoint::Enroll,
        Endpoint::EnrollPoll,
        Endpoint::Other,
    ];

    pub(crate) fn of(method: &Method, path: &str) -> Option<Endpoint> {
        if is_unlimited(path) {
            return None;
        }
        let post = |endpoint| {
            if method == Method::POST {
                endpoint
            } else {
                Endpoint::Other
            }
        };
        Some(match path {
            "/v1/login/start" => post(Endpoint::LoginStart),
            "/v1/login/finish" => post(Endpoint::LoginFinish),
            "/v1/login/device/start" => post(Endpoint::DeviceStart),
            "/v1/login/device/poll" => post(Endpoint::DevicePoll),
            "/v1/web/login" => Endpoint::WebLogin,
            "/v1/agent/enroll" => post(Endpoint::Enroll),
            "/v1/agent/enroll/poll" => post(Endpoint::EnrollPoll),
            _ => Endpoint::Other,
        })
    }

    const fn name(self) -> &'static str {
        match self {
            Endpoint::LoginStart => "login_start",
            Endpoint::LoginFinish => "login_finish",
            Endpoint::DeviceStart => "device_start",
            Endpoint::DevicePoll => "device_poll",
            Endpoint::WebLogin => "web_login",
            Endpoint::Enroll => "enroll",
            Endpoint::EnrollPoll => "enroll_poll",
            Endpoint::Other => "other",
        }
    }

    fn rate(self, limits: &RequestLimits) -> Rate {
        match self {
            Endpoint::LoginStart => limits.login_start,
            Endpoint::LoginFinish => limits.login_finish,
            Endpoint::DeviceStart => limits.device_start,
            Endpoint::DevicePoll => limits.device_poll,
            Endpoint::WebLogin => limits.web_login,
            Endpoint::Enroll => limits.enroll,
            Endpoint::EnrollPoll => limits.enroll_poll,
            Endpoint::Other => limits.other,
        }
    }
}

struct Guard {
    endpoint: Endpoint,
    limiter: RateLimiter<ClientKey>,
    log: LogThrottle,
}

pub(crate) struct RequestLimiters {
    guards: Vec<Guard>,
    pub(crate) max_connections: usize,
    pub(crate) max_connections_per_address: usize,
    missing_peer_log: LogThrottle,
}

impl RequestLimiters {
    pub(crate) fn new(limits: &RequestLimits) -> RequestLimiters {
        let capacity = limits.tracked_addresses.clamp(1, MAX_TRACKED_ADDRESSES);
        RequestLimiters {
            guards: Endpoint::ALL
                .iter()
                .map(|endpoint| Guard {
                    endpoint: *endpoint,
                    limiter: RateLimiter::new(endpoint.rate(limits), capacity),
                    log: LogThrottle::new(REFUSAL_LOG_INTERVAL),
                })
                .collect(),
            max_connections: limits.max_connections.clamp(1, MAX_CONNECTIONS_LIMIT),
            max_connections_per_address: limits
                .max_connections_per_address
                .clamp(1, MAX_CONNECTIONS_LIMIT),
            missing_peer_log: LogThrottle::new(REFUSAL_LOG_INTERVAL),
        }
    }

    fn guard(&self, endpoint: Endpoint) -> Option<&Guard> {
        self.guards.iter().find(|guard| guard.endpoint == endpoint)
    }

    pub(crate) fn sweep(&self, now: Duration) {
        for guard in &self.guards {
            guard.limiter.sweep(now);
        }
    }
}

pub(crate) struct NoiseLog {
    per_address: RateLimiter<ClientKey>,
    overall: LogThrottle,
    held_back: AtomicU64,
}

impl NoiseLog {
    pub(crate) fn new() -> NoiseLog {
        NoiseLog {
            per_address: RateLimiter::new(NOISE_PER_ADDRESS, NOISE_TRACKED),
            overall: LogThrottle::new(NOISE_INTERVAL),
            held_back: AtomicU64::new(0),
        }
    }

    pub(crate) fn admit(&self, client: ClientKey, now: Duration) -> Option<u64> {
        let logged =
            self.per_address.check(&client, now).is_allowed() && self.overall.admit(now).is_some();
        if logged {
            Some(self.held_back.swap(0, Ordering::Relaxed))
        } else {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[derive(Serialize)]
struct RateLimited {
    error: &'static str,
    retry_after: u64,
}

fn is_unlimited(path: &str) -> bool {
    path == "/healthz" || path.starts_with("/assets/") || path.starts_with("/static/")
}

pub(crate) fn retry_after_secs(wait: Duration) -> u64 {
    let whole = wait.as_secs();
    let rounded = if wait.subsec_nanos() > 0 {
        whole.saturating_add(1)
    } else {
        whole
    };
    rounded.max(1)
}

pub(crate) fn too_many_requests(wait: Duration) -> Response {
    let retry_after = retry_after_secs(wait);
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        &RateLimited {
            error: TOO_MANY_REQUESTS,
            retry_after,
        },
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after));
    response
}

pub(crate) async fn enforce(
    State(control): State<Control>,
    request: Request,
    next: Next,
) -> Response {
    let Some(endpoint) = Endpoint::of(request.method(), request.uri().path()) else {
        return next.run(request).await;
    };
    let Some(guard) = control.request_limits.guard(endpoint) else {
        return next.run(request).await;
    };
    let Some(ConnectInfo(peer)) = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied()
    else {
        if let Some(suppressed) = control
            .request_limits
            .missing_peer_log
            .admit(control.tick())
        {
            tracing::error!(
                target: "jaunt::control",
                suppressed,
                "the peer address is not available"
            );
        }
        return server_error();
    };
    let tick = control.tick();
    let address = control.device.client_ip.resolve(request.headers(), peer);
    let client = ClientKey::of(address);
    let mut request = request;
    request.extensions_mut().insert(ClientAddress(address));
    match guard.limiter.check(&client, tick) {
        Decision::Allowed => next.run(request).await,
        Decision::Limited { retry_after } => {
            if let Some(suppressed) = guard.log.admit(tick) {
                tracing::info!(
                    target: "jaunt::audit",
                    event = "http.rate_limited",
                    endpoint = endpoint.name(),
                    client = %client,
                    retry_after = retry_after_secs(retry_after),
                    suppressed
                );
            }
            too_many_requests(retry_after)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::http::Method;

    use jaunt_limits::ClientKey;

    use super::{Endpoint, NoiseLog, RequestLimits, retry_after_secs};

    #[test]
    fn retry_after_rounds_up_to_whole_seconds_and_is_never_zero() {
        for (wait, secs) in [
            (Duration::ZERO, 1),
            (Duration::from_millis(1), 1),
            (Duration::from_secs(1), 1),
            (Duration::from_millis(1_001), 2),
            (Duration::from_secs(600), 600),
        ] {
            assert_eq!(retry_after_secs(wait), secs, "{wait:?}");
        }
    }

    #[test]
    fn every_route_but_health_and_static_files_is_limited_and_starts_have_their_own_bucket() {
        for (method, path, endpoint) in [
            (Method::POST, "/v1/login/start", Some(Endpoint::LoginStart)),
            (
                Method::POST,
                "/v1/login/finish",
                Some(Endpoint::LoginFinish),
            ),
            (
                Method::POST,
                "/v1/login/device/start",
                Some(Endpoint::DeviceStart),
            ),
            (
                Method::POST,
                "/v1/login/device/poll",
                Some(Endpoint::DevicePoll),
            ),
            (Method::GET, "/v1/web/login", Some(Endpoint::WebLogin)),
            (Method::POST, "/v1/web/login", Some(Endpoint::WebLogin)),
            (Method::POST, "/v1/agent/enroll", Some(Endpoint::Enroll)),
            (
                Method::POST,
                "/v1/agent/enroll/poll",
                Some(Endpoint::EnrollPoll),
            ),
            (Method::GET, "/v1/login/start", Some(Endpoint::Other)),
            (Method::POST, "/v1/login/start/", Some(Endpoint::Other)),
            (Method::GET, "/v1/login/callback", Some(Endpoint::Other)),
            (Method::GET, "/v1/whoami", Some(Endpoint::Other)),
            (Method::GET, "/v1/nodes", Some(Endpoint::Other)),
            (Method::GET, "/v1/web/session", Some(Endpoint::Other)),
            (Method::POST, "/v1/web/logout", Some(Endpoint::Other)),
            (Method::GET, "/v1/admin/whoami", Some(Endpoint::Other)),
            (Method::POST, "/login/device", Some(Endpoint::Other)),
            (Method::GET, "/", Some(Endpoint::Other)),
            (Method::GET, "/healthz", None),
            (Method::GET, "/assets/app.js", None),
            (Method::GET, "/static/login.css", None),
        ] {
            assert_eq!(Endpoint::of(&method, path), endpoint, "{method} {path}");
        }
        let limits = RequestLimits::default();
        assert_eq!(limits.enroll.burst(), 60);
        assert_eq!(limits.enroll.per_minute(), 6);
        assert_eq!(
            (limits.other.burst(), limits.other.per_minute()),
            (600, 300)
        );
        assert_eq!(limits.max_connections_per_address, 256);
    }

    #[test]
    fn anonymous_noise_is_logged_once_per_address_and_at_most_once_a_second_overall() {
        let log = NoiseLog::new();
        let key = |text: &str| ClientKey::of(text.parse().unwrap());
        let at = Duration::from_secs;
        assert_eq!(log.admit(key("192.0.2.1"), at(100)), Some(0));
        assert_eq!(log.admit(key("192.0.2.1"), at(102)), None);
        assert_eq!(log.admit(key("192.0.2.2"), at(100)), None);
        assert_eq!(log.admit(key("192.0.2.3"), at(101)), Some(2));
        assert_eq!(log.admit(key("192.0.2.1"), at(110)), Some(0));
    }
}
