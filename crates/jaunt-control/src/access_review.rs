use std::time::Duration;

use jaunt_policy::{Identity, KubeDecision, NodeInfo, PolicySet, ResourceInfo};
use jaunt_store::{
    LiveEntry, LiveServiceSession, LiveSshSession, ServiceKind, Session, SessionEndReason,
    SessionKind, StoreError,
};
use tokio::time::{Instant, MissedTickBehavior};

use crate::control::Control;
use crate::error::ControlError;
use crate::killer::{KillReason, KillScope};
use crate::session_audit;
use crate::token::hex_digest;

pub const ACCESS_REVIEW_INTERVAL: Duration = Duration::from_secs(30);
pub const ACCESS_REVIEW_POLL: Duration = Duration::from_secs(1);
pub const ACCESS_REVIEW_DEBOUNCE: Duration = Duration::from_secs(5);
const MIN_POLL: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessReview {
    pub checked: usize,
    pub withdrawn: usize,
    pub changed: usize,
    pub service_removed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Keep,
    Withdrawn,
    Changed,
    ServiceRemoved,
}

impl Verdict {
    const fn ending(self) -> Option<(SessionEndReason, KillReason)> {
        match self {
            Verdict::Keep => None,
            Verdict::Withdrawn => Some((
                SessionEndReason::AccessWithdrawn,
                KillReason::AccessWithdrawn,
            )),
            Verdict::Changed => Some((SessionEndReason::AccessChanged, KillReason::AccessChanged)),
            Verdict::ServiceRemoved => {
                Some((SessionEndReason::ServiceRemoved, KillReason::ServiceRemoved))
            }
        }
    }
}

pub(crate) fn kube_grant_hash(
    users: &[String],
    groups: &[String],
    record_exec: bool,
    record_input: bool,
) -> String {
    let mut users = users.to_vec();
    let mut groups = groups.to_vec();
    users.sort();
    users.dedup();
    groups.sort();
    groups.dedup();
    let canonical = serde_json::json!({
        "users": users,
        "groups": groups,
        "record_exec": record_exec,
        "record_input": record_input,
    });
    hex_digest(canonical.to_string().as_bytes())
}

pub(crate) fn kube_decision_hash(decision: &KubeDecision) -> String {
    kube_grant_hash(
        &decision.users,
        &decision.groups,
        decision.record_exec,
        decision.record_input,
    )
}

fn identity(email: &str, username: &str, groups: &[String]) -> Identity {
    Identity {
        email: email.to_owned(),
        username: username.to_owned(),
        groups: groups.to_vec(),
    }
}

fn service_verdict(policy: &PolicySet, live: &LiveServiceSession) -> Verdict {
    let Some(service) = &live.service else {
        return Verdict::ServiceRemoved;
    };
    let identity = identity(&live.email, &live.username, &live.groups);
    let resource = ResourceInfo {
        name: service.name.clone(),
        labels: service.labels.clone(),
    };
    let session = &live.session;
    match (session.kind, service.kind) {
        (SessionKind::Kube, ServiceKind::Kubernetes) => {
            let decision = policy.authorize_kube(&identity, &resource);
            if !decision.allowed {
                Verdict::Withdrawn
            } else if session.decision_hash.as_deref()
                != Some(kube_decision_hash(&decision).as_str())
            {
                Verdict::Changed
            } else {
                Verdict::Keep
            }
        }
        (SessionKind::Tcp, ServiceKind::Tcp) => {
            kept(policy.authorize_tcp(&identity, &resource).allowed)
        }
        (SessionKind::Db, ServiceKind::Postgres) => match (&session.login, &session.target) {
            (Some(user), Some(name)) => kept(
                policy
                    .authorize_db(&identity, &resource, user, name)
                    .allowed,
            ),
            _ => Verdict::Withdrawn,
        },
        _ => Verdict::Withdrawn,
    }
}

fn ssh_verdict(policy: &PolicySet, live: &LiveSshSession) -> Verdict {
    let Some(login) = &live.session.login else {
        return Verdict::Withdrawn;
    };
    let node = NodeInfo {
        name: live.node_name.clone(),
        labels: live.node_labels.clone(),
    };
    let identity = identity(&live.email, &live.username, &live.groups);
    kept(policy.authorize_ssh(&identity, &node, login).allowed)
}

const fn kept(allowed: bool) -> Verdict {
    if allowed {
        Verdict::Keep
    } else {
        Verdict::Withdrawn
    }
}

#[derive(Debug, Clone, Copy)]
struct Schedule {
    every: Duration,
    debounce: Duration,
}

impl Schedule {
    fn due(
        self,
        reviewed: Option<&(String, Instant)>,
        changed: &mut Option<(String, Instant)>,
        hash: &str,
        now: Instant,
    ) -> bool {
        let Some((seen, at)) = reviewed else {
            return true;
        };
        if seen == hash {
            *changed = None;
            return now.saturating_duration_since(*at) >= self.every;
        }
        match changed {
            Some((pending, since)) if pending == hash => {
                now.saturating_duration_since(*since) >= self.debounce
            }
            _ => {
                *changed = Some((hash.to_owned(), now));
                self.debounce.is_zero()
            }
        }
    }
}

#[derive(Default)]
struct Cuts {
    withdrawn: Vec<Session>,
    changed: Vec<Session>,
    removed: Vec<Session>,
    failure: Option<StoreError>,
}

impl Cuts {
    fn of(&mut self, verdict: Verdict) -> &mut Vec<Session> {
        match verdict {
            Verdict::Changed => &mut self.changed,
            Verdict::ServiceRemoved => &mut self.removed,
            Verdict::Keep | Verdict::Withdrawn => &mut self.withdrawn,
        }
    }
}

fn judged<'a, T>(
    entry: &'a LiveEntry<T>,
    judge: impl FnOnce(&'a T) -> (&'a Session, Verdict),
) -> (&'a str, SessionKind, Verdict) {
    match entry {
        LiveEntry::Readable(live) => {
            let (session, verdict) = judge(live);
            (session.id.as_str(), session.kind, verdict)
        }
        LiveEntry::Unreadable { id, kind, error } => {
            tracing::warn!(
                target: "jaunt::control",
                session_id = %id,
                kind = kind.as_str(),
                error = %error,
                "a live session cannot be evaluated and is closed"
            );
            (id.as_str(), *kind, Verdict::Withdrawn)
        }
    }
}

impl Control {
    pub async fn review_access(&self) -> Result<AccessReview, ControlError> {
        let now = self.now().ok_or(ControlError::Clock)?;
        let policy = self.policy_snapshot();
        let sessions = self.store.service_sessions();
        let services = sessions.live().await.map_err(ControlError::Sessions)?;
        let shells = sessions.live_ssh().await.map_err(ControlError::Sessions)?;
        let verdicts =
            services
                .iter()
                .map(|entry| {
                    judged(entry, |live| {
                        (&live.session, service_verdict(&policy, live))
                    })
                })
                .chain(shells.iter().map(|entry| {
                    judged(entry, |live| (&live.session, ssh_verdict(&policy, live)))
                }));
        let mut cuts = Cuts::default();
        for (id, kind, verdict) in verdicts {
            let Some((reason, _)) = verdict.ending() else {
                continue;
            };
            match sessions.close_active(id, kind, reason, now.secs).await {
                Ok(Some(closed)) => {
                    session_audit::closed(&closed, reason);
                    cuts.of(verdict).push(closed);
                }
                Ok(None) => {}
                Err(err) => {
                    cuts.failure.get_or_insert(err);
                }
            }
        }
        let review = AccessReview {
            checked: services.len() + shells.len(),
            withdrawn: cuts.withdrawn.len(),
            changed: cuts.changed.len(),
            service_removed: cuts.removed.len(),
        };
        for (closed, verdict) in [
            (&cuts.withdrawn, Verdict::Withdrawn),
            (&cuts.changed, Verdict::Changed),
            (&cuts.removed, Verdict::ServiceRemoved),
        ] {
            if let (false, Some((_, kill))) = (closed.is_empty(), verdict.ending()) {
                self.killer.order(KillScope::Sessions, kill, closed).await;
            }
        }
        match cuts.failure {
            Some(err) => Err(ControlError::Sessions(err)),
            None => Ok(review),
        }
    }

    pub async fn watch_access(&self, poll: Duration, every: Duration, debounce: Duration) {
        let mut ticker = tokio::time::interval(poll.max(MIN_POLL));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut reviewed: Option<(String, Instant)> = None;
        let mut changed: Option<(String, Instant)> = None;
        loop {
            ticker.tick().await;
            let hash = self.policy_snapshot().hash().to_owned();
            let now = Instant::now();
            let schedule = Schedule { every, debounce };
            if !schedule.due(reviewed.as_ref(), &mut changed, &hash, now) {
                continue;
            }
            reviewed = Some((hash, now));
            changed = None;
            match self.review_access().await {
                Ok(review) if review.withdrawn + review.changed + review.service_removed > 0 => {
                    tracing::info!(
                        target: "jaunt::control",
                        withdrawn = review.withdrawn,
                        changed = review.changed,
                        service_removed = review.service_removed,
                        "live sessions whose access was taken away or changed were closed"
                    );
                }
                Ok(_) => {}
                Err(err) => {
                    reviewed = None;
                    tracing::warn!(
                        target: "jaunt::control",
                        error = %err,
                        "reviewing the access of live sessions failed; the next tick retries"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{Schedule, kube_grant_hash};

    #[test]
    fn a_changed_policy_waits_for_the_debounce_and_every_new_change_re_arms_it() {
        let schedule = Schedule {
            every: Duration::from_secs(30),
            debounce: Duration::from_secs(5),
        };
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let reviewed = ("a".to_owned(), start);
        let mut changed = None;
        assert!(schedule.due(None, &mut changed, "a", start));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "a", at(29)));
        assert!(schedule.due(Some(&reviewed), &mut changed, "a", at(30)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "b", at(1)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "b", at(5)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "c", at(4)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "c", at(8)));
        assert!(schedule.due(Some(&reviewed), &mut changed, "c", at(9)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "a", at(10)));
        assert_eq!(changed, None);
        assert!(!schedule.due(Some(&reviewed), &mut changed, "a", at(29)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "d", at(40)));
        assert!(!schedule.due(Some(&reviewed), &mut changed, "d", at(44)));
        let immediate = Schedule {
            debounce: Duration::ZERO,
            ..schedule
        };
        let mut fresh = None;
        assert!(immediate.due(Some(&reviewed), &mut fresh, "e", at(1)));
    }

    fn names(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn the_kube_grant_hash_covers_users_groups_and_both_recording_flags_and_nothing_else() {
        let base = kube_grant_hash(&names(&["a@x"]), &names(&["view", "edit"]), true, false);
        assert_eq!(base.len(), 64);
        assert_eq!(
            base,
            kube_grant_hash(
                &names(&["a@x", "a@x"]),
                &names(&["edit", "view"]),
                true,
                false
            )
        );
        for other in [
            kube_grant_hash(&names(&["b@x"]), &names(&["view", "edit"]), true, false),
            kube_grant_hash(&names(&["a@x"]), &names(&["view"]), true, false),
            kube_grant_hash(
                &names(&["a@x"]),
                &names(&["view", "edit", "admin"]),
                true,
                false,
            ),
            kube_grant_hash(&names(&["a@x"]), &names(&["view", "edit"]), false, false),
            kube_grant_hash(&names(&["a@x"]), &names(&["view", "edit"]), true, true),
            kube_grant_hash(&names(&["a@x", "view"]), &names(&["edit"]), true, false),
        ] {
            assert_ne!(base, other);
        }
    }
}
