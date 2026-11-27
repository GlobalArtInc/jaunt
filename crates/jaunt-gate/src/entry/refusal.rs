use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_limits::{ClientKey, LogThrottle};
use tokio::time::Instant;

use super::hello::HelloError;
use crate::audit;

const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsRefusal {
    ProxyUntrusted,
    ProxyMalformed,
    ProxyTimeout,
    Limit,
    HelloTooLarge,
    HelloTimeout,
    BadHello,
    NoSni,
    UnknownSni,
    AlpnUnsupported,
    UnsupportedClass,
    ClientCertificate,
    TlsHandshake,
    GateCertificateExpired,
}

impl TlsRefusal {
    pub const ALL: [TlsRefusal; 14] = [
        Self::ProxyUntrusted,
        Self::ProxyMalformed,
        Self::ProxyTimeout,
        Self::Limit,
        Self::HelloTooLarge,
        Self::HelloTimeout,
        Self::BadHello,
        Self::NoSni,
        Self::UnknownSni,
        Self::AlpnUnsupported,
        Self::UnsupportedClass,
        Self::ClientCertificate,
        Self::TlsHandshake,
        Self::GateCertificateExpired,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProxyUntrusted => "proxy_untrusted",
            Self::ProxyMalformed => "proxy_malformed",
            Self::ProxyTimeout => "proxy_timeout",
            Self::Limit => "limit",
            Self::HelloTooLarge => "hello_too_large",
            Self::HelloTimeout => "hello_timeout",
            Self::BadHello => "bad_hello",
            Self::NoSni => "no_sni",
            Self::UnknownSni => "unknown_sni",
            Self::AlpnUnsupported => "alpn_unsupported",
            Self::UnsupportedClass => "unsupported_class",
            Self::ClientCertificate => "client_certificate",
            Self::TlsHandshake => "tls_handshake",
            Self::GateCertificateExpired => "gate_certificate_expired",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

impl From<HelloError> for TlsRefusal {
    fn from(error: HelloError) -> Self {
        match error {
            HelloError::TooLarge => Self::HelloTooLarge,
            HelloError::Timeout => Self::HelloTimeout,
            HelloError::Malformed | HelloError::Truncated | HelloError::Io(_) => Self::BadHello,
        }
    }
}

#[derive(Clone)]
pub struct RefusalLog(Arc<Refusals>);

impl RefusalLog {
    pub(super) fn new(refusals: Arc<Refusals>) -> Self {
        Self(refusals)
    }

    pub fn refuse(&self, reason: TlsRefusal, client: SocketAddr) {
        self.0.record(reason, client);
    }
}

pub(super) struct Refusals {
    counts: [AtomicU64; TlsRefusal::ALL.len()],
    logs: [LogThrottle; TlsRefusal::ALL.len()],
    started: Instant,
}

impl Refusals {
    pub(super) fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            logs: std::array::from_fn(|_| LogThrottle::new(REFUSAL_LOG_INTERVAL)),
            started: Instant::now(),
        }
    }

    pub(super) fn record(&self, reason: TlsRefusal, client: SocketAddr) {
        if let Some(count) = self.counts.get(reason.index()) {
            count.fetch_add(1, Ordering::Relaxed);
        }
        let Some(log) = self.logs.get(reason.index()) else {
            return;
        };
        if let Some(suppressed) = log.admit(self.started.elapsed()) {
            audit::tls_refused(ClientKey::of(client.ip()), reason.as_str(), suppressed);
        }
    }

    pub(super) fn count(&self, reason: TlsRefusal) -> u64 {
        self.counts
            .get(reason.index())
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::TlsRefusal;

    #[test]
    fn every_reason_has_its_own_slot_and_name() {
        let names: HashSet<&str> = TlsRefusal::ALL
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        assert_eq!(names.len(), TlsRefusal::ALL.len());
        for (position, reason) in TlsRefusal::ALL.iter().enumerate() {
            assert_eq!(reason.index(), position, "{reason:?}");
            assert!(reason.as_str().len() <= 32, "{reason:?}");
        }
    }
}
