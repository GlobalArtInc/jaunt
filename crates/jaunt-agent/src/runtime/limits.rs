use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use jaunt_limits::{ConcurrencyGuard, ConcurrencyLimiter, LogThrottle};
use jaunt_proto::MAX_SERVICES_PER_AGENT;
use jaunt_tunnel::StreamKind;

use super::x509::CertRefusal;
use crate::clock::Clock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceLimits {
    pub handshakes_per_service: usize,
    pub handshake_timeout: Duration,
    pub connections_per_user: usize,
    pub connections_per_service: usize,
    pub authorize_timeout: Duration,
    pub end_timeout: Duration,
    pub event_flush_timeout: Duration,
    pub refusal_log_every: Duration,
}

pub const SERVICE_LIMITS: ServiceLimits = ServiceLimits {
    handshakes_per_service: 64,
    handshake_timeout: Duration::from_secs(10),
    connections_per_user: 32,
    connections_per_service: 512,
    authorize_timeout: Duration::from_secs(10),
    end_timeout: Duration::from_secs(10),
    event_flush_timeout: Duration::from_secs(2),
    refusal_log_every: Duration::from_secs(60),
};

pub type ServiceSlot = ConcurrencyGuard<String>;
pub type UserSlot = ConcurrencyGuard<(String, String)>;

pub struct Gauges {
    handshakes: ConcurrencyLimiter<String>,
    connections: ConcurrencyLimiter<String>,
    users: ConcurrencyLimiter<(String, String)>,
}

impl Gauges {
    pub fn new(limits: &ServiceLimits) -> Self {
        let users_tracked = limits
            .connections_per_service
            .saturating_mul(MAX_SERVICES_PER_AGENT);
        Self {
            handshakes: ConcurrencyLimiter::new(
                limits.handshakes_per_service,
                MAX_SERVICES_PER_AGENT,
            ),
            connections: ConcurrencyLimiter::new(
                limits.connections_per_service,
                MAX_SERVICES_PER_AGENT,
            ),
            users: ConcurrencyLimiter::new(limits.connections_per_user, users_tracked),
        }
    }

    pub fn connection(&self, service_id: &str) -> Option<ServiceSlot> {
        self.connections.try_acquire(service_id.to_owned()).ok()
    }

    pub fn handshake(&self, service_id: &str) -> Option<ServiceSlot> {
        self.handshakes.try_acquire(service_id.to_owned()).ok()
    }

    pub fn user(&self, service_id: &str, user_id: &str) -> Option<UserSlot> {
        self.users
            .try_acquire((service_id.to_owned(), user_id.to_owned()))
            .ok()
    }

    #[cfg(test)]
    pub fn handshakes_held(&self, service_id: &str) -> usize {
        self.handshakes.held(&service_id.to_owned())
    }

    #[cfg(test)]
    pub fn connections_held(&self, service_id: &str) -> usize {
        self.connections.held(&service_id.to_owned())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownService,
    NotServed,
    ServiceLimit,
    HandshakeLimit,
    HandshakeTimeout,
    NotTls,
    NoSni,
    SniMismatch,
    CertificateUnavailable,
    NoCertificate,
    Certificate(CertRefusal),
    HandshakeFailed,
    UserLimit,
}

impl Refusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownService => "unknown_service",
            Self::NotServed => "not_served",
            Self::ServiceLimit => "service_limit",
            Self::HandshakeLimit => "handshake_limit",
            Self::HandshakeTimeout => "handshake_timeout",
            Self::NotTls => "not_tls",
            Self::NoSni => "no_sni",
            Self::SniMismatch => "sni_mismatch",
            Self::CertificateUnavailable => "certificate_unavailable",
            Self::NoCertificate => "no_certificate",
            Self::Certificate(refusal) => refusal.as_str(),
            Self::HandshakeFailed => "handshake_failed",
            Self::UserLimit => "user_limit",
        }
    }
}

pub struct RefusalLog {
    clock: Arc<dyn Clock>,
    every: Duration,
    throttles: Mutex<HashMap<(&'static str, &'static str), Arc<LogThrottle>>>,
}

impl RefusalLog {
    pub fn new(clock: Arc<dyn Clock>, every: Duration) -> Self {
        Self {
            clock,
            every,
            throttles: Mutex::new(HashMap::new()),
        }
    }

    pub fn refused(&self, kind: StreamKind, refusal: Refusal, service: &str, session_id: &str) {
        let reason = refusal.as_str();
        let throttle = Arc::clone(
            self.throttles
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .entry((kind.as_str(), reason))
                .or_insert_with(|| Arc::new(LogThrottle::new(self.every))),
        );
        let now = self
            .clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let Some(suppressed) = throttle.admit(now) else {
            return;
        };
        match kind {
            StreamKind::Kube => tracing::info!(
                target: "jaunt::audit",
                event = "kube.tls.refused",
                service,
                session_id,
                reason,
                suppressed
            ),
            StreamKind::Db => tracing::info!(
                target: "jaunt::audit",
                event = "db.tls.refused",
                service,
                session_id,
                reason,
                suppressed
            ),
            StreamKind::Tcp => tracing::info!(
                target: "jaunt::audit",
                event = "tcp.tls.refused",
                service,
                session_id,
                reason,
                suppressed
            ),
            StreamKind::Ssh => {}
        }
    }
}
