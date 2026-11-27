use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use jaunt_limits::LogThrottle;

const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamRefusal {
    AddressLimit,
    ClusterLimit,
    UserLimit,
    UnknownCluster,
    InnerHello,
    ServiceName,
    Denied,
    ControlUnavailable,
    NodeNotConnected,
    KindNotServed,
    AgentUnavailable,
}

impl StreamRefusal {
    pub const ALL: [StreamRefusal; 11] = [
        Self::AddressLimit,
        Self::ClusterLimit,
        Self::UserLimit,
        Self::UnknownCluster,
        Self::InnerHello,
        Self::ServiceName,
        Self::Denied,
        Self::ControlUnavailable,
        Self::NodeNotConnected,
        Self::KindNotServed,
        Self::AgentUnavailable,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AddressLimit => "address_limit",
            Self::ClusterLimit => "cluster_limit",
            Self::UserLimit => "user_limit",
            Self::UnknownCluster => "unknown_cluster",
            Self::InnerHello => "inner_hello",
            Self::ServiceName => "service_name",
            Self::Denied => "denied",
            Self::ControlUnavailable => "control_unavailable",
            Self::NodeNotConnected => "node_not_connected",
            Self::KindNotServed => "kind_not_served",
            Self::AgentUnavailable => "agent_unavailable",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

pub(super) struct StreamRefusals {
    counts: [AtomicU64; StreamRefusal::ALL.len()],
    logs: [LogThrottle; StreamRefusal::ALL.len()],
    started: Instant,
}

impl StreamRefusals {
    pub(super) fn new() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            logs: std::array::from_fn(|_| LogThrottle::new(REFUSAL_LOG_INTERVAL)),
            started: Instant::now(),
        }
    }

    pub(super) fn count(&self, reason: StreamRefusal) {
        if let Some(count) = self.counts.get(reason.index()) {
            count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn throttled(&self, reason: StreamRefusal) -> Option<u64> {
        self.count(reason);
        self.logs
            .get(reason.index())
            .and_then(|log| log.admit(self.started.elapsed()))
    }

    pub(super) fn refused(&self, reason: StreamRefusal) -> u64 {
        self.counts
            .get(reason.index())
            .map_or(0, |count| count.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{StreamRefusal, StreamRefusals};

    #[test]
    fn every_reason_has_its_own_slot_name_and_throttle() {
        let names: HashSet<&str> = StreamRefusal::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), StreamRefusal::ALL.len());
        for (position, reason) in StreamRefusal::ALL.iter().enumerate() {
            assert_eq!(reason.index(), position, "{reason:?}");
            assert!(reason.as_str().len() <= 32, "{reason:?}");
        }
        let refusals = StreamRefusals::new();
        assert_eq!(refusals.throttled(StreamRefusal::UnknownCluster), Some(0));
        assert_eq!(refusals.throttled(StreamRefusal::UnknownCluster), None);
        assert_eq!(refusals.throttled(StreamRefusal::AddressLimit), Some(0));
        refusals.count(StreamRefusal::Denied);
        assert_eq!(refusals.refused(StreamRefusal::UnknownCluster), 2);
        assert_eq!(refusals.refused(StreamRefusal::AddressLimit), 1);
        assert_eq!(refusals.refused(StreamRefusal::Denied), 1);
        assert_eq!(refusals.refused(StreamRefusal::UserLimit), 0);
    }
}
