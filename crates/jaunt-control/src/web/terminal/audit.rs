use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
    pub(crate) node: &'a str,
    pub(crate) login: &'a str,
    pub(crate) client_addr: Option<SocketAddr>,
}

impl DenialLog {
    pub(crate) fn record(&self, denial: &Denial<'_>, now: Duration) {
        if !self
            .per_user
            .check(&denial.user_id.to_owned(), now)
            .is_allowed()
        {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            return;
        }
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
            node = denial.node,
            login = denial.login,
            client_addr = client_addr.as_str(),
            suppressed
        );
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
        serial = closed.serial
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
            node: "web-01",
            login: "deploy",
            client_addr: None,
        };
        let at = Duration::from_secs(100);
        for _ in 0..8 {
            log.record(&denial("alice"), at);
        }
        assert_eq!(log.held_back.load(std::sync::atomic::Ordering::Relaxed), 3);
        log.record(&denial("bob"), at);
        assert_eq!(log.held_back.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
