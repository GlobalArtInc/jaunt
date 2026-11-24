use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct GateStats {
    handshake_failures: AtomicU64,
    handshake_timeouts: AtomicU64,
    refused_busy: AtomicU64,
    no_application_protocol: AtomicU64,
    auth_rejections: AtomicU64,
    tunnels_established: AtomicU64,
    tunnel_setup_failures: AtomicU64,
    agent_api_handed_over: AtomicU64,
    main_handed_over: AtomicU64,
    accept_errors: AtomicU64,
    task_panics: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GateStatsSnapshot {
    pub handshake_failures: u64,
    pub handshake_timeouts: u64,
    pub refused_busy: u64,
    pub no_application_protocol: u64,
    pub auth_rejections: u64,
    pub tunnels_established: u64,
    pub tunnel_setup_failures: u64,
    pub agent_api_handed_over: u64,
    pub main_handed_over: u64,
    pub accept_errors: u64,
    pub task_panics: u64,
}

macro_rules! counters {
    ($($record:ident => $field:ident),* $(,)?) => {
        impl GateStats {
            $(
                pub(crate) fn $record(&self) {
                    self.$field.fetch_add(1, Ordering::Relaxed);
                }
            )*

            pub fn snapshot(&self) -> GateStatsSnapshot {
                GateStatsSnapshot {
                    $($field: self.$field.load(Ordering::Relaxed),)*
                }
            }
        }
    };
}

counters! {
    record_handshake_failure => handshake_failures,
    record_handshake_timeout => handshake_timeouts,
    record_refused_busy => refused_busy,
    record_no_application_protocol => no_application_protocol,
    record_auth_rejection => auth_rejections,
    record_tunnel_established => tunnels_established,
    record_tunnel_setup_failure => tunnel_setup_failures,
    record_agent_api_handed_over => agent_api_handed_over,
    record_main_handed_over => main_handed_over,
    record_accept_error => accept_errors,
    record_task_panic => task_panics,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reflects_recorded_events() {
        let stats = GateStats::default();
        stats.record_auth_rejection();
        stats.record_auth_rejection();
        stats.record_handshake_timeout();
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.auth_rejections, 2);
        assert_eq!(snapshot.handshake_timeouts, 1);
        assert_eq!(snapshot.tunnels_established, 0);
    }
}
