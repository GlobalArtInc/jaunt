use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use jaunt_limits::{Rate, RateLimiter};
use jaunt_proto::AccountEvent;

pub(crate) const REFUSALS_PER_NODE: Rate = Rate::clamped(5, 6);
const NODES_TRACKED: usize = 4096;

pub(crate) struct Subject<'a> {
    pub(crate) user_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) login: &'a str,
}

pub(crate) struct NodeThrottle {
    per_node: RateLimiter<String>,
    held_back: Mutex<HashMap<String, u64>>,
}

impl NodeThrottle {
    pub(crate) fn new(rate: Rate) -> Self {
        Self {
            per_node: RateLimiter::new(rate, NODES_TRACKED),
            held_back: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn admit(&self, node_id: &str, now: Duration) -> Option<u64> {
        let allowed = self.per_node.check(&node_id.to_owned(), now).is_allowed();
        let mut held_back = self
            .held_back
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if allowed {
            return Some(held_back.remove(node_id).unwrap_or(0));
        }
        if let Some(count) = held_back.get_mut(node_id) {
            *count = count.saturating_add(1);
        } else if held_back.len() < NODES_TRACKED {
            held_back.insert(node_id.to_owned(), 1);
        }
        None
    }
}

pub(crate) fn record(
    refusals: &NodeThrottle,
    subject: &Subject<'_>,
    event: &AccountEvent,
    now: Duration,
) {
    match event {
        AccountEvent::Creating { .. } | AccountEvent::Missing { .. } => {}
        AccountEvent::Created {
            reference,
            uid,
            home,
            groups,
        } => {
            let groups = groups.join(",");
            tracing::info!(
                target: "jaunt::audit",
                event = "host_user.created",
                user_id = subject.user_id,
                node_id = subject.node_id,
                session_id = subject.session_id,
                login = subject.login,
                uid = *uid,
                home = home.as_str(),
                groups = groups.as_str(),
                "ref" = reference.as_str()
            );
        }
        AccountEvent::Refused { reference, reason } => {
            let Some(suppressed) = refusals.admit(subject.node_id, now) else {
                return;
            };
            tracing::info!(
                target: "jaunt::audit",
                event = "host_user.refused",
                user_id = subject.user_id,
                node_id = subject.node_id,
                session_id = subject.session_id,
                login = subject.login,
                reason = reason.as_str(),
                "ref" = reference.as_str(),
                suppressed
            );
        }
        AccountEvent::Failed {
            reference,
            stage,
            exit_code,
        } => {
            tracing::info!(
                target: "jaunt::audit",
                event = "host_user.helper_failed",
                user_id = subject.user_id,
                node_id = subject.node_id,
                session_id = subject.session_id,
                login = subject.login,
                stage = stage.as_str(),
                exit_status = *exit_code,
                "ref" = reference.as_str()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{NodeThrottle, REFUSALS_PER_NODE};

    #[test]
    fn refusals_are_logged_a_few_times_per_node_and_then_counted_for_that_node_only() {
        let log = NodeThrottle::new(REFUSALS_PER_NODE);
        let at = Duration::from_secs(100);
        let admitted: Vec<Option<u64>> = (0..7).map(|_| log.admit("n1", at)).collect();
        assert_eq!(
            admitted,
            [Some(0), Some(0), Some(0), Some(0), Some(0), None, None]
        );
        assert_eq!(log.admit("n2", at), Some(0));
        let later = at + Duration::from_secs(60);
        assert_eq!(log.admit("n1", later), Some(2));
        assert_eq!(log.admit("n1", later), Some(0));
        assert_eq!(log.admit("n2", later), Some(0));
    }
}
