use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_audit::new_denial_reference;
use jaunt_limits::{Rate, RateLimiter};

const DENIALS_PER_USER: Rate = Rate::clamped(5, 6);
const DENIAL_USERS_TRACKED: usize = 4096;

pub(crate) struct DenialLog {
    per_user: RateLimiter<String>,
    held_back: AtomicU64,
}

impl Default for DenialLog {
    fn default() -> Self {
        Self {
            per_user: RateLimiter::new(DENIALS_PER_USER, DENIAL_USERS_TRACKED),
            held_back: AtomicU64::new(0),
        }
    }
}

pub(crate) struct Denial<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) reference: Option<&'a str>,
    pub(crate) node: &'a str,
    pub(crate) login: &'a str,
    pub(crate) client_addr: Option<SocketAddr>,
}

impl DenialLog {
    pub(crate) fn record(&self, denial: &Denial<'_>, now: Duration) -> Option<String> {
        if !self
            .per_user
            .check(&denial.user_id.to_owned(), now)
            .is_allowed()
        {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            return denial.reference.map(str::to_owned);
        }
        let reference = denial
            .reference
            .map_or_else(new_denial_reference, str::to_owned);
        let suppressed = self.held_back.swap(0, Ordering::Relaxed);
        let client_addr = denial
            .client_addr
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        tracing::info!(
            target: "jaunt::audit",
            event = "terminal.denied",
            user_id = denial.user_id,
            reason = denial.reason,
            "ref" = reference.as_str(),
            node = denial.node,
            login = denial.login,
            client_addr = client_addr.as_str(),
            suppressed
        );
        Some(reference)
    }
}

pub(crate) struct Opened<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) node: &'a str,
    pub(crate) login: &'a str,
    pub(crate) serial: u64,
    pub(crate) client_addr: SocketAddr,
}

pub(crate) fn opened(opened: &Opened<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "terminal.opened",
        user_id = opened.user_id,
        session_id = opened.session_id,
        node_id = opened.node_id,
        node = opened.node,
        login = opened.login,
        serial = opened.serial,
        client_addr = %opened.client_addr
    );
}

pub(crate) struct Closed<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) bytes_in: u64,
    pub(crate) bytes_out: u64,
    pub(crate) duration: Duration,
    pub(crate) serial: u64,
    pub(crate) reference: Option<&'a str>,
}

pub(crate) fn closed(closed: &Closed<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "terminal.closed",
        user_id = closed.user_id,
        session_id = closed.session_id,
        node_id = closed.node_id,
        reason = closed.reason,
        bytes_in = closed.bytes_in,
        bytes_out = closed.bytes_out,
        duration_ms = u64::try_from(closed.duration.as_millis()).unwrap_or(u64::MAX),
        serial = closed.serial,
        "ref" = closed.reference
    );
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Denial, DenialLog};

    #[test]
    fn denials_are_logged_a_few_times_per_user_and_then_counted() {
        let log = DenialLog::default();
        let denial = |user_id| Denial {
            user_id,
            reason: "denied",
            reference: None,
            node: "web-01",
            login: "deploy",
            client_addr: None,
        };
        let at = Duration::from_secs(100);
        let references: Vec<Option<String>> =
            (0..8).map(|_| log.record(&denial("alice"), at)).collect();
        assert_eq!(log.held_back.load(std::sync::atomic::Ordering::Relaxed), 3);
        assert!(references[..5].iter().all(|reference| {
            reference
                .as_deref()
                .is_some_and(jaunt_proto::is_denial_reference)
        }));
        assert!(references[5..].iter().all(Option::is_none));
        let written: std::collections::HashSet<_> = references.iter().flatten().collect();
        assert_eq!(written.len(), 5);
        assert!(log.record(&denial("bob"), at).is_some());
        assert_eq!(log.held_back.load(std::sync::atomic::Ordering::Relaxed), 0);
        let account = Denial {
            reference: Some("H-9D0311FE"),
            ..denial("carol")
        };
        assert_eq!(log.record(&account, at).as_deref(), Some("H-9D0311FE"));
    }
}
