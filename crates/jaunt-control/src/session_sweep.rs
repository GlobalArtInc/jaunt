use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_store::{OpenSessions, Session, SessionEndReason, StoreError};
use tokio::time::MissedTickBehavior;

use crate::authorize::DEFAULT_MAX_SESSION_SECS;
use crate::control::Control;
use crate::error::ControlError;
use crate::killer::{KillReason, KillScope};
use crate::{revocation_audit, session_audit};

pub const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
pub const REVOCATION_WATCH_INTERVAL: Duration = Duration::from_secs(1);
pub const ROUTED_GRACE_SECS: i64 = 120;
pub const OVERDUE_MARGIN_SECS: i64 = 300;
pub const REVOCATION_PRUNE_AFTER_EXPIRY_SECS: i64 = 24 * 60 * 60;
const PRUNED_BY: &str = "system:certificate-expired";
const WATCH_OVERLAP_SECS: i64 = 300;

#[derive(Default)]
pub(crate) struct Watched {
    seen: HashMap<String, i64>,
    newest: Option<i64>,
}

impl Watched {
    fn since(&self) -> i64 {
        self.newest
            .map_or(i64::MIN, |newest| newest.saturating_sub(WATCH_OVERLAP_SECS))
    }

    fn has_seen(&self, id: &str) -> bool {
        self.seen.contains_key(id)
    }

    pub(crate) fn saw(&mut self, id: &str, created_at: i64) {
        self.seen.insert(id.to_owned(), created_at);
        let newest = self
            .newest
            .map_or(created_at, |known| known.max(created_at));
        self.newest = Some(newest);
        let horizon = newest.saturating_sub(WATCH_OVERLAP_SECS);
        self.seen.retain(|_, seen_at| *seen_at >= horizon);
    }
}

#[derive(Default)]
pub(crate) struct RevocationWatch(Mutex<Watched>);

impl RevocationWatch {
    pub(crate) fn starting_at(now: Option<i64>) -> RevocationWatch {
        RevocationWatch(Mutex::new(Watched {
            seen: HashMap::new(),
            newest: now,
        }))
    }

    pub(crate) fn lock_watch(&self) -> MutexGuard<'_, Watched> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionSweep {
    pub expired: usize,
    pub revoked: usize,
    pub node_removed: usize,
    pub pruned: usize,
}

impl Control {
    pub async fn sweep_sessions(&self) -> Result<SessionSweep, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let sessions = self.store.sessions();
        let mut failure = None;
        let mut kept = |result: Result<Vec<Session>, StoreError>| match result {
            Ok(closed) => closed,
            Err(err) => {
                failure.get_or_insert(err);
                Vec::new()
            }
        };
        let mut expired = kept(
            sessions
                .close(
                    OpenSessions::RoutedCreatedBefore(now.secs.saturating_sub(ROUTED_GRACE_SECS)),
                    SessionEndReason::Expired,
                    now.secs,
                )
                .await,
        );
        expired.extend(kept(
            sessions
                .close(
                    OpenSessions::ActivePastDeadline {
                        default_max_secs: i64::try_from(DEFAULT_MAX_SESSION_SECS)
                            .unwrap_or(i64::MAX),
                        margin_secs: OVERDUE_MARGIN_SECS,
                    },
                    SessionEndReason::Expired,
                    now.secs,
                )
                .await,
        ));
        let removed = kept(
            sessions
                .close(
                    OpenSessions::OfInactiveNodes,
                    SessionEndReason::NodeRemoved,
                    now.secs,
                )
                .await,
        );
        self.closed_by_control(&expired, SessionEndReason::Expired, KillReason::Expired)
            .await;
        self.closed_by_control(
            &removed,
            SessionEndReason::NodeRemoved,
            KillReason::NodeRemoved,
        )
        .await;
        let revoked = match self.revocations().enforce_stored(now.secs).await {
            Ok(revoked) => revoked,
            Err(err) => {
                failure.get_or_insert(err);
                0
            }
        };
        let pruned = match self
            .store
            .revocations()
            .prune_expired_serials(now.secs.saturating_sub(REVOCATION_PRUNE_AFTER_EXPIRY_SECS))
            .await
        {
            Ok(pruned) => pruned,
            Err(err) => {
                failure.get_or_insert(err);
                Vec::new()
            }
        };
        for revocation in &pruned {
            revocation_audit::removed(revocation, PRUNED_BY);
        }
        if let Some(err) = failure {
            return Err(ControlError::Sessions(err));
        }
        Ok(SessionSweep {
            expired: expired.len(),
            revoked,
            node_removed: removed.len(),
            pruned: pruned.len(),
        })
    }

    pub async fn check_revocations(&self) -> Result<usize, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let enforced = match self.store.sessions().any_open_of_revoked_subjects().await {
            Ok(true) => self.revocations().enforce_stored(now.secs).await,
            Ok(false) => Ok(0),
            Err(err) => Err(err),
        };
        let net = self.order_new_revocations().await;
        let enforced = enforced.map_err(ControlError::Sessions)?;
        net.map_err(ControlError::Sessions)?;
        Ok(enforced)
    }

    async fn order_new_revocations(&self) -> Result<(), StoreError> {
        let since = self.watched.lock_watch().since();
        let fresh = self.store.revocations().since(since).await?;
        let admin = self.revocations();
        for revocation in fresh {
            if self.watched.lock_watch().has_seen(&revocation.id) {
                continue;
            }
            if !admin.order_for(&revocation).await? {
                return Ok(());
            }
            self.watched
                .lock_watch()
                .saw(&revocation.id, revocation.created_at);
        }
        Ok(())
    }

    pub async fn watch_revocations(&self, every: Duration) {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match self.check_revocations().await {
                Ok(0) => {}
                Ok(terminated) => tracing::info!(
                    target: "jaunt::control",
                    terminated,
                    "the revocation watch closed sessions of revoked subjects"
                ),
                Err(err) => tracing::warn!(
                    target: "jaunt::control",
                    error = %err,
                    "the revocation watch failed"
                ),
            }
        }
    }

    pub async fn agent_registered(
        &self,
        node_id: &str,
        registered_at: SystemTime,
    ) -> Result<usize, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let before = registered_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| i64::try_from(since.as_secs()).ok())
            .ok_or(ControlError::Clock)?;
        let closed = self
            .store
            .sessions()
            .close(
                OpenSessions::OfNodeCreatedBefore { node_id, before },
                SessionEndReason::AgentRestarted,
                now.secs,
            )
            .await
            .map_err(ControlError::Sessions)?;
        for session in &closed {
            session_audit::closed(session, SessionEndReason::AgentRestarted);
        }
        Ok(closed.len())
    }

    pub async fn agent_gone(&self, node_id: &str) -> Result<usize, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let closed = self
            .store
            .sessions()
            .close(
                OpenSessions::OfNode(node_id),
                SessionEndReason::AgentGone,
                now.secs,
            )
            .await
            .map_err(ControlError::Sessions)?;
        self.closed_by_control(&closed, SessionEndReason::AgentGone, KillReason::AgentGone)
            .await;
        Ok(closed.len())
    }

    pub async fn close_sessions_of_earlier_runs(&self) -> Result<usize, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let closed = self
            .store
            .sessions()
            .close(
                OpenSessions::CreatedBefore(now.secs.saturating_add(1)),
                SessionEndReason::AgentGone,
                now.secs,
            )
            .await
            .map_err(ControlError::Sessions)?;
        for session in &closed {
            session_audit::closed(session, SessionEndReason::AgentGone);
        }
        Ok(closed.len())
    }

    async fn closed_by_control(
        &self,
        closed: &[Session],
        outcome: SessionEndReason,
        reason: KillReason,
    ) {
        for session in closed {
            session_audit::closed(session, outcome);
        }
        if !closed.is_empty() {
            self.killer.order(KillScope::Sessions, reason, closed).await;
        }
    }
}
