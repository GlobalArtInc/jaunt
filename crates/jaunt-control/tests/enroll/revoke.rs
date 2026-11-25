use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    Holder, LOGIN, NODE_NAME, Scenario, authorize, certificate, end, end_request, holder, raw_pool,
    route, routed, scenario, stored,
};
use jaunt_control::{
    Control, KillOrder, KillReason, KillScope, KilledSession, RevocationAdmin, RevokeError,
    RevokeRequest, Revoked, SessionKiller, system_clock,
};
use jaunt_proto::{
    AuthorizeDecision, BoxFuture, ControlPlane, DenyReason, RouteDecision, RouteRequest,
    SessionEndOutcome,
};
use jaunt_store::{
    NewRevocation, NewSession, RevocationKind, SessionEndReason, SessionState, Store,
};

const AUTHOR: &str = "cli:tester";

#[derive(Default)]
struct RecordingKiller(Mutex<Vec<KillOrder>>);

impl RecordingKiller {
    fn orders(&self) -> Vec<KillOrder> {
        self.0.lock().unwrap().clone()
    }
}

impl SessionKiller for RecordingKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(order.clone());
        Box::pin(async {})
    }
}

fn with_killer(s: &Scenario) -> Arc<RecordingKiller> {
    let killer = Arc::new(RecordingKiller::default());
    s.harness.control.install_session_killer(killer.clone());
    killer
}

fn request(kind: RevocationKind, subject: &str) -> RevokeRequest {
    RevokeRequest {
        kind,
        subject: subject.to_owned(),
        reason: "lost laptop".to_owned(),
    }
}

async fn revoke(s: &Scenario, kind: RevocationKind, subject: &str) -> Revoked {
    s.harness
        .control
        .revocations()
        .revoke(&request(kind, subject), AUTHOR)
        .await
        .unwrap()
}

fn subject_of(s: &Scenario, kind: RevocationKind) -> String {
    match kind {
        RevocationKind::User => s.alice.user_id.clone(),
        RevocationKind::Serial => s.alice.serial.to_string(),
        RevocationKind::Node => s.node_id.clone(),
    }
}

async fn reactivate_node(s: &Scenario) {
    sqlx::query("UPDATE nodes SET state = 'active', removed_at = NULL WHERE id = ?")
        .bind(&s.node_id)
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();
}

async fn active_session(s: &Scenario, holder: &Holder) -> String {
    let session_id = routed(&s.harness, holder).await;
    let decision = authorize(&s.harness, &s.node_id, holder.authorize(&session_id, LOGIN)).await;
    assert!(
        matches!(decision, AuthorizeDecision::Allow { .. }),
        "{decision:?}"
    );
    session_id
}

async fn behind_route(s: &Scenario, holder: &Holder) -> String {
    s.harness
        .store
        .sessions()
        .create(
            &NewSession {
                user_id: holder.user_id.clone(),
                serial: i64::try_from(holder.serial).unwrap(),
                node_id: s.node_id.clone(),
                ttl_secs: 60,
            },
            s.harness.clock.now_secs(),
        )
        .await
        .unwrap()
        .id
}

async fn second_store(s: &Scenario) -> Store {
    let store = Store::open(&s.harness.db_path).await.unwrap();
    store.migrate().await.unwrap();
    store
}

fn denied(reason: DenyReason) -> AuthorizeDecision {
    AuthorizeDecision::Deny { reason }
}

fn at(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap())
}

#[tokio::test]
async fn route_and_authorize_deny_each_kind_of_revocation_with_the_revoked_reason() {
    for kind in [
        RevocationKind::User,
        RevocationKind::Serial,
        RevocationKind::Node,
    ] {
        let s = scenario().await;
        let waiting = routed(&s.harness, &s.alice).await;

        let revoked = revoke(&s, kind, &subject_of(&s, kind)).await;
        assert!(revoked.created);
        assert_eq!(revoked.terminated, 0, "{kind:?}");
        if kind == RevocationKind::Node {
            assert_eq!(
                route(&s.harness, s.alice.route_to(NODE_NAME)).await,
                RouteDecision::Deny {
                    reason: DenyReason::NodeUnknown
                }
            );
            reactivate_node(&s).await;
        }

        assert_eq!(
            route(&s.harness, s.alice.route_to(NODE_NAME)).await,
            RouteDecision::Deny {
                reason: DenyReason::Revoked
            },
            "{kind:?}"
        );
        assert_eq!(
            authorize(&s.harness, &s.node_id, s.alice.authorize(&waiting, LOGIN)).await,
            denied(DenyReason::Revoked),
            "{kind:?}"
        );
        assert_eq!(
            stored(&s.harness, &waiting).await.unwrap().state,
            SessionState::Routed
        );
    }
}

#[tokio::test]
async fn a_serial_revocation_leaves_the_other_certificates_of_the_user_working() {
    let s = scenario().await;
    let now = s.harness.clock.now_secs();
    let other = certificate(&s.harness, &s.alice.user_id, now - 60, now + 3600).await;

    revoke(&s, RevocationKind::Serial, &s.alice.serial.to_string()).await;

    assert!(matches!(
        route(&s.harness, other.route_to(NODE_NAME)).await,
        RouteDecision::Allow { .. }
    ));
    assert_eq!(
        route(&s.harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::Revoked
        }
    );
}

#[tokio::test]
async fn removing_a_revocation_restores_access_on_the_very_next_check() {
    let s = scenario().await;
    let revoked = revoke(&s, RevocationKind::User, &s.alice.user_id).await;
    assert!(matches!(
        route(&s.harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny { .. }
    ));

    let removed = s
        .harness
        .control
        .revocations()
        .remove(&revoked.revocation.id, AUTHOR)
        .await
        .unwrap();

    assert_eq!(removed, revoked.revocation);
    let session_id = active_session(&s, &s.alice).await;
    assert_eq!(
        stored(&s.harness, &session_id).await.unwrap().state,
        SessionState::Active
    );
    assert!(matches!(
        s.harness
            .control
            .revocations()
            .remove(&removed.id, AUTHOR)
            .await,
        Err(jaunt_control::UnrevokeError::NotFound)
    ));
}

#[tokio::test]
async fn a_revocation_written_through_another_store_handle_is_refused_at_once_and_killed_by_the_check()
 {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 0);
    let other_process = RevocationAdmin::new(second_store(&s).await, system_clock());

    let written = other_process
        .revoke(
            &request(RevocationKind::Serial, &s.alice.serial.to_string()),
            AUTHOR,
        )
        .await
        .unwrap();

    assert_eq!(written.terminated, 0);
    assert!(killer.orders().is_empty());
    assert_eq!(
        route(&s.harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::Revoked
        }
    );
    assert_eq!(
        stored(&s.harness, &active).await.unwrap().state,
        SessionState::Active
    );
    start_recording();
    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 1);
    let ends: Vec<_> = take_recording()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("session.end"))
        .collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["session_id"], active);
    assert_eq!(ends[0]["outcome"], "revoked");
    let orders = killer.orders();
    assert_eq!(orders.len(), 2);
    let certificate = KillScope::Certificate {
        user_id: s.alice.user_id.clone(),
        serial: s.alice.serial,
    };
    assert_eq!(orders[0].scope, certificate);
    assert_eq!(orders[0].sessions[0].session_id, active);
    assert_eq!(orders[1].scope, certificate);
    assert!(orders[1].sessions.is_empty());
    assert_eq!(
        stored(&s.harness, &active).await.unwrap().end_reason,
        Some(SessionEndReason::Revoked)
    );
    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 0);
    assert_eq!(killer.orders().len(), 2);
}

#[tokio::test]
async fn the_revocation_flow_leaves_schema_events_without_dropped_fields() {
    let s = scenario().await;
    with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    let capture = jaunt_audit::ScopedCapture::start();

    let revoked = revoke(&s, RevocationKind::User, &s.alice.user_id).await;
    end(&s.harness, &s.node_id, end_request(&active, 10)).await;
    end(&s.harness, &s.node_id, end_request(&active, 10)).await;
    s.harness
        .control
        .revocations()
        .remove(&revoked.revocation.id, AUTHOR)
        .await
        .unwrap();
    let snapshot = capture.snapshot();
    let events = capture.finish().await;

    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );
    let names: Vec<&str> = events.iter().map(|event| event.kind().name()).collect();
    assert_eq!(
        names,
        [
            "revoke.created",
            "session.end",
            "session.terminated",
            "session.end",
            "session.end_rejected",
            "revoke.removed",
        ]
    );
    assert_eq!(events[0].actor().as_wire(), AUTHOR);
    assert_eq!(events[0].text("kind"), Some("user"));
    assert_eq!(events[1].text("outcome"), Some("revoked"));
    assert_eq!(events[1].text("state_before"), Some("active"));
    assert_eq!(events[2].text("reason"), Some("revoked"));
    assert_eq!(events[3].flag("late"), Some(true));
    assert_eq!(events[3].int("bytes_out"), Some(10));
    assert_eq!(events[4].text("reason"), Some("session_closed"));
    assert_eq!(events[5].actor().as_wire(), AUTHOR);
}

#[tokio::test]
async fn the_watch_cuts_once_for_every_new_revocation_even_when_no_session_looks_open() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    sqlx::query("UPDATE sessions SET state = 'ended', end_reason = 'closed' WHERE id = ?")
        .bind(&active)
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();
    let bob = holder(&s.harness, "bob", &["ops"]).await;
    revoke(&s, RevocationKind::User, &bob.user_id).await;
    let in_process = killer.orders().len();
    s.harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind: RevocationKind::User,
                subject: s.alice.user_id.clone(),
                reason: "written by another process".to_owned(),
                created_by: AUTHOR.to_owned(),
            },
            s.harness.clock.now_secs() - 60,
        )
        .await
        .unwrap();

    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 0);

    let orders = killer.orders();
    assert_eq!(orders.len(), in_process + 1);
    assert_eq!(
        orders[in_process].scope,
        KillScope::User {
            user_id: s.alice.user_id.clone()
        }
    );
    assert!(orders[in_process].sessions.is_empty());
    s.harness.control.check_revocations().await.unwrap();
    assert_eq!(killer.orders().len(), in_process + 1);
}

#[tokio::test]
async fn a_revocation_from_before_the_start_is_enforced_by_the_probe_and_not_cut_again() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    s.harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind: RevocationKind::User,
                subject: s.alice.user_id.clone(),
                reason: "written while the daemon was down".to_owned(),
                created_by: AUTHOR.to_owned(),
            },
            s.harness.clock.now_secs() - 3600,
        )
        .await
        .unwrap();

    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 1);

    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        orders[0].scope,
        KillScope::User {
            user_id: s.alice.user_id.clone()
        }
    );
    assert_eq!(orders[0].sessions[0].session_id, active);
    assert_eq!(
        route(&s.harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::Revoked
        }
    );
    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 0);
    assert_eq!(killer.orders().len(), 1);
}

#[tokio::test]
async fn a_stored_revocation_that_cannot_be_read_still_gets_its_sessions_killed() {
    for kind in [
        RevocationKind::User,
        RevocationKind::Node,
        RevocationKind::Serial,
    ] {
        let s = scenario().await;
        let killer = with_killer(&s);
        let active = active_session(&s, &s.alice).await;
        sqlx::query(
            "INSERT INTO revocations (id, kind, subject, reason, created_at, created_by) \
             VALUES ('r-broken', ?, ?, 'r', 'not a number', 'cli:test')",
        )
        .bind(kind.as_str())
        .bind(subject_of(&s, kind))
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();

        let checked = s.harness.control.check_revocations().await;

        assert!(checked.is_err(), "{kind:?}: {checked:?}");
        assert_eq!(
            stored(&s.harness, &active).await.unwrap().end_reason,
            Some(SessionEndReason::Revoked),
            "{kind:?}"
        );
        let orders = killer.orders();
        assert_eq!(orders.len(), 1, "{kind:?}");
        let expected = match kind {
            RevocationKind::User | RevocationKind::Node => KillScope::Sessions,
            RevocationKind::Serial => KillScope::Certificate {
                user_id: s.alice.user_id.clone(),
                serial: s.alice.serial,
            },
        };
        assert_eq!(orders[0].scope, expected, "{kind:?}");
        assert_eq!(orders[0].sessions[0].session_id, active, "{kind:?}");
    }
}

#[tokio::test]
async fn a_failed_revocation_write_still_cuts_the_live_connections() {
    let s = scenario().await;
    let killer = with_killer(&s);
    sqlx::query("ALTER TABLE revocations RENAME TO revocations_gone")
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();
    let started = Instant::now();

    let failed = s
        .harness
        .control
        .revocations()
        .revoke(&request(RevocationKind::User, &s.alice.user_id), AUTHOR)
        .await;

    assert!(matches!(failed, Err(RevokeError::Store(_))), "{failed:?}");
    assert!(started.elapsed() < Duration::from_secs(1));
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        orders[0].scope,
        KillScope::User {
            user_id: s.alice.user_id.clone()
        }
    );
}

#[tokio::test]
async fn route_and_authorize_refuse_when_revocations_cannot_be_read() {
    let s = scenario().await;
    let waiting = routed(&s.harness, &s.alice).await;
    sqlx::query("ALTER TABLE revocations RENAME TO revocations_gone")
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();

    let routed = s.harness.control.route(s.alice.route_to(NODE_NAME)).await;
    let authorized = s
        .harness
        .control
        .authorize(
            jaunt_proto::NodeCaller(s.node_id.clone()),
            s.alice.authorize(&waiting, LOGIN),
        )
        .await;

    assert_eq!(routed, Err(jaunt_proto::ControlError::Store));
    assert_eq!(authorized, Err(jaunt_proto::ControlError::Store));
    assert_eq!(
        stored(&s.harness, &waiting).await.unwrap().state,
        SessionState::Routed
    );
}

#[tokio::test]
async fn a_session_close_slower_than_its_budget_still_orders_the_cut() {
    let s = scenario().await;
    let active = active_session(&s, &s.alice).await;
    let serial = s.alice.serial.to_string();
    revoke(&s, RevocationKind::Serial, &serial).await;
    let killer = with_killer(&s);
    let blocker = raw_pool(&s.harness).await;
    let mut writer = blocker.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .unwrap();

    let slow = s
        .harness
        .control
        .revocations()
        .with_session_close_budget(Duration::from_millis(100))
        .revoke(&request(RevocationKind::Serial, &serial), AUTHOR)
        .await;

    assert!(matches!(slow, Err(RevokeError::CloseTimedOut)), "{slow:?}");
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        orders[0].scope,
        KillScope::Certificate {
            user_id: s.alice.user_id.clone(),
            serial: s.alice.serial,
        }
    );
    assert!(orders[0].sessions.is_empty());
    assert_eq!(
        stored(&s.harness, &active).await.unwrap().state,
        SessionState::Active
    );
    sqlx::query("COMMIT").execute(&mut *writer).await.unwrap();
}

#[tokio::test]
async fn a_sweep_whose_second_close_fails_still_kills_and_audits_the_first() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let stale = routed(&s.harness, &s.alice).await;
    let overdue = active_session(&s, &s.alice).await;
    sqlx::query("UPDATE sessions SET created_at = 'unreadable' WHERE id = ?")
        .bind(&overdue)
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();
    s.harness.clock.advance(13 * 3600);
    start_recording();

    let swept = s.harness.control.sweep_sessions().await;

    assert!(swept.is_err(), "{swept:?}");
    let ends: Vec<_> = take_recording()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("session.end"))
        .collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["session_id"], stale);
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].reason, KillReason::Expired);
    assert_eq!(orders[0].sessions[0].session_id, stale);
}

#[tokio::test]
async fn a_revocation_closes_open_sessions_of_its_subject_and_orders_their_kill() {
    for kind in [
        RevocationKind::User,
        RevocationKind::Serial,
        RevocationKind::Node,
    ] {
        let s = scenario().await;
        let killer = with_killer(&s);
        let now = s.harness.clock.now_secs();
        let spare = certificate(&s.harness, &s.alice.user_id, now - 60, now + 3600).await;
        let active = active_session(&s, &s.alice).await;
        let waiting = routed(&s.harness, &s.alice).await;
        let other = active_session(&s, &spare).await;
        start_recording();

        let revoked = revoke(&s, kind, &subject_of(&s, kind)).await;

        let events = take_recording();
        let mut closed = vec![active.clone(), waiting.clone()];
        if kind != RevocationKind::Serial {
            closed.push(other.clone());
        }
        closed.sort();
        assert_eq!(revoked.terminated, closed.len(), "{kind:?}");
        for session_id in &closed {
            let session = stored(&s.harness, session_id).await.unwrap();
            assert_eq!(session.state, SessionState::Ended, "{kind:?}");
            assert_eq!(session.end_reason, Some(SessionEndReason::Revoked));
        }
        if kind == RevocationKind::Serial {
            assert_eq!(
                stored(&s.harness, &other).await.unwrap().state,
                SessionState::Active
            );
        }
        let orders = killer.orders();
        assert_eq!(orders.len(), 1, "{kind:?}");
        let expected_scope = match kind {
            RevocationKind::User => KillScope::User {
                user_id: s.alice.user_id.clone(),
            },
            RevocationKind::Serial => KillScope::Certificate {
                user_id: s.alice.user_id.clone(),
                serial: s.alice.serial,
            },
            RevocationKind::Node => KillScope::Node {
                node_id: s.node_id.clone(),
            },
        };
        assert_eq!(orders[0].scope, expected_scope);
        assert_eq!(orders[0].reason, KillReason::Revoked);
        let mut ordered: Vec<String> = orders[0]
            .sessions
            .iter()
            .map(
                |KilledSession {
                     session_id,
                     node_id,
                 }| {
                    assert_eq!(node_id, &s.node_id);
                    session_id.clone()
                },
            )
            .collect();
        ordered.sort();
        assert_eq!(ordered, closed);

        let names: Vec<&str> = events
            .iter()
            .filter(|event| event["target"] == "jaunt::audit")
            .map(|event| event["event"].as_str())
            .collect();
        assert_eq!(names.first(), Some(&"revoke.created"), "{names:?}");
        let count = |name: &str| names.iter().filter(|seen| **seen == name).count();
        assert_eq!(count("session.end"), closed.len());
        assert_eq!(count("session.terminated"), closed.len());
        assert!(
            events
                .iter()
                .filter(|event| event.get("event").map(String::as_str) == Some("session.end"))
                .all(|event| event["outcome"] == "revoked")
        );
        let created = events
            .iter()
            .find(|event| event.get("event").map(String::as_str) == Some("revoke.created"))
            .unwrap();
        assert_eq!(created["kind"], kind.as_str());
        assert_eq!(created["created_by"], AUTHOR);

        assert_eq!(
            end(&s.harness, &s.node_id, end_request(&active, 10)).await,
            SessionEndOutcome::Recorded,
            "{kind:?}"
        );
        let filled = stored(&s.harness, &active).await.unwrap();
        assert_eq!(filled.end_reason, Some(SessionEndReason::Revoked));
        assert_eq!((filled.bytes_in, filled.bytes_out), (Some(42), Some(10)));
        assert_eq!(
            end(&s.harness, &s.node_id, end_request(&active, 10)).await,
            SessionEndOutcome::Rejected
        );

        let straggler = behind_route(&s, &s.alice).await;
        let again = revoke(&s, kind, &subject_of(&s, kind)).await;
        assert!(!again.created);
        assert_eq!(again.revocation, revoked.revocation);
        assert_eq!(again.terminated, 1, "{kind:?}");
        assert_eq!(
            stored(&s.harness, &straggler).await.unwrap().end_reason,
            Some(SessionEndReason::Revoked)
        );
        assert_eq!(killer.orders()[1].sessions[0].session_id, straggler);
    }
}

#[tokio::test]
async fn bad_requests_are_refused_before_anything_is_written() {
    let s = scenario().await;
    let request = |kind, subject: &str, reason: &str| RevokeRequest {
        kind,
        subject: subject.to_owned(),
        reason: reason.to_owned(),
    };
    let revocations = s.harness.control.revocations();
    for (given, author) in [
        (request(RevocationKind::User, "a/b", "r"), AUTHOR),
        (request(RevocationKind::Serial, "007", "r"), AUTHOR),
        (request(RevocationKind::Node, "", "r"), AUTHOR),
        (request(RevocationKind::User, &s.alice.user_id, ""), AUTHOR),
        (
            request(RevocationKind::User, &s.alice.user_id, "a\nb"),
            AUTHOR,
        ),
        (
            request(RevocationKind::User, &s.alice.user_id, "r"),
            "bad author",
        ),
        (request(RevocationKind::User, "no-such-user", "r"), AUTHOR),
        (request(RevocationKind::Serial, "999999", "r"), AUTHOR),
        (request(RevocationKind::Node, "no-such-node", "r"), AUTHOR),
    ] {
        let refused = revocations.revoke(&given, author).await;
        assert!(
            matches!(
                refused,
                Err(RevokeError::InvalidSubject(_)
                    | RevokeError::InvalidReason
                    | RevokeError::InvalidAuthor
                    | RevokeError::UnknownSubject(_))
            ),
            "{given:?}: {refused:?}"
        );
    }
    assert!(
        revocations
            .list(None, 10)
            .await
            .unwrap()
            .revocations
            .is_empty()
    );
}

struct RoutingKiller {
    control: Control,
    probe: RouteRequest,
    seen: Mutex<Vec<RouteDecision>>,
}

impl SessionKiller for RoutingKiller {
    fn kill<'a>(&'a self, _order: &'a KillOrder) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let decision = self.control.route(self.probe.clone()).await.unwrap();
            self.seen.lock().unwrap().push(decision);
        })
    }
}

#[tokio::test]
async fn the_refusal_already_holds_when_the_kill_orders_go_out() {
    let s = scenario().await;
    active_session(&s, &s.alice).await;
    let killer = Arc::new(RoutingKiller {
        control: s.harness.control.clone(),
        probe: s.alice.route_to(NODE_NAME),
        seen: Mutex::new(Vec::new()),
    });
    s.harness.control.install_session_killer(killer.clone());

    revoke(&s, RevocationKind::User, &s.alice.user_id).await;

    let seen = killer.seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        [RouteDecision::Deny {
            reason: DenyReason::Revoked
        }]
    );
}

#[tokio::test]
async fn a_failing_session_close_still_cuts_the_live_connections() {
    let s = scenario().await;
    let killer = with_killer(&s);
    active_session(&s, &s.alice).await;
    sqlx::query("ALTER TABLE sessions RENAME TO sessions_gone")
        .execute(&raw_pool(&s.harness).await)
        .await
        .unwrap();

    let failed = s
        .harness
        .control
        .revocations()
        .revoke(&request(RevocationKind::User, &s.alice.user_id), AUTHOR)
        .await;

    assert!(matches!(failed, Err(RevokeError::Store(_))), "{failed:?}");
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        orders[0].scope,
        KillScope::User {
            user_id: s.alice.user_id.clone()
        }
    );
    assert!(orders[0].sessions.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_revocation_write_cuts_the_live_connections_before_it_finishes() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    let pool = raw_pool(&s.harness).await;
    let mut holder = pool.acquire().await.unwrap();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let admin = s.harness.control.revocations();
    let user_id = s.alice.user_id.clone();
    let started = Instant::now();
    let revoking = tokio::spawn(async move {
        admin
            .revoke(&request(RevocationKind::User, &user_id), AUTHOR)
            .await
    });

    while killer.orders().is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "no early cut while the database was busy"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let cut_after = started.elapsed();
    assert!(!revoking.is_finished());
    sqlx::query("COMMIT").execute(&mut *holder).await.unwrap();
    holder.close().await.unwrap();
    let revoked = revoking.await.unwrap().unwrap();

    assert!(cut_after >= Duration::from_millis(900), "{cut_after:?}");
    assert!(cut_after < Duration::from_secs(2), "{cut_after:?}");
    let orders = killer.orders();
    assert_eq!(orders.len(), 2);
    assert!(orders[0].sessions.is_empty());
    assert_eq!(orders[1].sessions[0].session_id, active);
    assert_eq!(revoked.terminated, 1);
}

#[tokio::test]
async fn a_route_that_raced_past_the_check_is_caught_at_authorize() {
    let s = scenario().await;
    with_killer(&s);
    revoke(&s, RevocationKind::User, &s.alice.user_id).await;
    let late = behind_route(&s, &s.alice).await;

    assert_eq!(
        authorize(&s.harness, &s.node_id, s.alice.authorize(&late, LOGIN)).await,
        denied(DenyReason::Revoked)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_session_routed_around_a_concurrent_revocation_survives() {
    let s = Arc::new(scenario().await);
    with_killer(&s);
    let mut routes = Vec::new();
    for index in 0..24 {
        let s = Arc::clone(&s);
        routes.push(tokio::spawn(async move {
            if index == 12 {
                revoke(&s, RevocationKind::User, &s.alice.user_id).await;
                return None;
            }
            match route(&s.harness, s.alice.route_to(NODE_NAME)).await {
                RouteDecision::Allow { session_id, .. } => Some(session_id),
                RouteDecision::Deny { .. } => None,
            }
        }));
    }
    let mut allowed = Vec::new();
    for task in routes {
        allowed.extend(task.await.unwrap());
    }

    for session_id in allowed {
        let decision = authorize(
            &s.harness,
            &s.node_id,
            s.alice.authorize(&session_id, LOGIN),
        )
        .await;
        assert!(
            matches!(decision, AuthorizeDecision::Deny { .. }),
            "{session_id}: {decision:?}"
        );
    }
}

#[tokio::test]
async fn the_sweep_expires_stale_routes_and_overdue_sessions_and_orders_their_kill() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let harness = &s.harness;
    let stale = routed(harness, &s.alice).await;
    let active = active_session(&s, &s.alice).await;
    harness.clock.advance(120);
    let fresh = routed(harness, &s.alice).await;
    assert_eq!(harness.control.sweep_sessions().await.unwrap().expired, 0);

    harness.clock.advance(1);
    start_recording();
    let swept = harness.control.sweep_sessions().await.unwrap();

    assert_eq!(swept.expired, 1);
    let expired = stored(harness, &stale).await.unwrap();
    assert_eq!(expired.end_reason, Some(SessionEndReason::Expired));
    assert_eq!(
        stored(harness, &fresh).await.unwrap().state,
        SessionState::Routed
    );
    let ends: Vec<_> = take_recording()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("session.end"))
        .collect();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0]["outcome"], "expired");
    assert_eq!(ends[0]["session_id"], stale);
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        (orders[0].scope.clone(), orders[0].reason),
        (KillScope::Sessions, KillReason::Expired)
    );
    assert_eq!(orders[0].sessions[0].session_id, stale);

    harness.clock.advance(12 * 3600 + 300 - 121);
    harness.control.sweep_sessions().await.unwrap();
    assert_eq!(
        stored(harness, &active).await.unwrap().state,
        SessionState::Active
    );
    harness.clock.advance(1);
    harness.control.sweep_sessions().await.unwrap();
    let overdue = stored(harness, &active).await.unwrap();
    assert_eq!(
        (overdue.state, overdue.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Expired))
    );
    let last = killer.orders().last().cloned().unwrap();
    assert_eq!(last.reason, KillReason::Expired);
    assert!(
        last.sessions
            .iter()
            .any(|killed| killed.session_id == active)
    );
    assert_eq!(
        end(harness, &s.node_id, end_request(&active, 1)).await,
        SessionEndOutcome::Recorded
    );
    assert_eq!(
        end(harness, &s.node_id, end_request(&active, 1)).await,
        SessionEndOutcome::Rejected
    );
}

#[tokio::test]
async fn the_sweep_closes_sessions_of_removed_nodes() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    s.harness
        .admin
        .remove_node(NODE_NAME, AUTHOR)
        .await
        .unwrap();

    let swept = s.harness.control.sweep_sessions().await.unwrap();

    assert_eq!(swept.node_removed, 1);
    assert_eq!(
        stored(&s.harness, &active).await.unwrap().end_reason,
        Some(SessionEndReason::NodeRemoved)
    );
    let orders = killer.orders();
    assert_eq!(
        (orders[0].scope.clone(), orders[0].reason),
        (KillScope::Sessions, KillReason::NodeRemoved)
    );
}

#[tokio::test]
async fn the_sweep_closes_and_kills_sessions_of_revocations_written_elsewhere() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    s.harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind: RevocationKind::Serial,
                subject: s.alice.serial.to_string(),
                reason: "written by the cli".to_owned(),
                created_by: AUTHOR.to_owned(),
            },
            s.harness.clock.now_secs(),
        )
        .await
        .unwrap();

    let swept = s.harness.control.sweep_sessions().await.unwrap();

    assert_eq!(swept.revoked, 1);
    assert_eq!(
        stored(&s.harness, &active).await.unwrap().end_reason,
        Some(SessionEndReason::Revoked)
    );
    let orders = killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        orders[0].scope,
        KillScope::Certificate {
            user_id: s.alice.user_id.clone(),
            serial: s.alice.serial,
        }
    );
    assert_eq!(s.harness.control.sweep_sessions().await.unwrap().revoked, 0);
}

#[tokio::test]
async fn a_session_under_a_revoked_node_and_a_revoked_serial_is_cut_with_its_node() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let active = active_session(&s, &s.alice).await;
    for (kind, subject) in [
        (RevocationKind::Serial, s.alice.serial.to_string()),
        (RevocationKind::Node, s.node_id.clone()),
    ] {
        s.harness
            .store
            .revocations()
            .insert(
                &NewRevocation {
                    kind,
                    subject,
                    reason: "written by the cli".to_owned(),
                    created_by: AUTHOR.to_owned(),
                },
                s.harness.clock.now_secs(),
            )
            .await
            .unwrap();
    }

    assert_eq!(s.harness.control.check_revocations().await.unwrap(), 1);

    let orders = killer.orders();
    assert_eq!(
        orders[0].scope,
        KillScope::Node {
            node_id: s.node_id.clone()
        }
    );
    assert_eq!(orders[0].sessions[0].session_id, active);
}

#[tokio::test]
async fn the_sweep_prunes_a_serial_revocation_a_day_after_its_certificate_expired() {
    let s = scenario().await;
    let now = s.harness.clock.now_secs();
    let short = certificate(&s.harness, &s.alice.user_id, now - 60, now + 60).await;
    revoke(&s, RevocationKind::Serial, &short.serial.to_string()).await;
    revoke(&s, RevocationKind::Serial, &s.alice.serial.to_string()).await;
    s.harness.clock.advance(60 + 24 * 3600);
    assert_eq!(s.harness.control.sweep_sessions().await.unwrap().pruned, 0);
    s.harness.clock.advance(1);
    start_recording();

    let swept = s.harness.control.sweep_sessions().await.unwrap();

    assert_eq!(swept.pruned, 1);
    let removed: Vec<_> = take_recording()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("revoke.removed"))
        .collect();
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0]["subject"], short.serial.to_string());
    assert_eq!(removed[0]["removed_by"], "system:certificate-expired");
    let left = s
        .harness
        .control
        .revocations()
        .list(None, 10)
        .await
        .unwrap();
    assert_eq!(left.revocations.len(), 1);
    assert_eq!(left.revocations[0].subject, s.alice.serial.to_string());
}

#[tokio::test]
async fn a_registering_agent_closes_the_sessions_its_node_had_before_and_takes_the_late_report() {
    let s = scenario().await;
    let before = active_session(&s, &s.alice).await;
    let waiting = routed(&s.harness, &s.alice).await;
    s.harness.clock.advance(1);
    let registered_at = at(s.harness.clock.now_secs());
    let after = routed(&s.harness, &s.alice).await;

    let closed = s
        .harness
        .control
        .agent_registered(&s.node_id, registered_at)
        .await
        .unwrap();

    assert_eq!(closed, 2);
    for session_id in [&before, &waiting] {
        assert_eq!(
            stored(&s.harness, session_id).await.unwrap().end_reason,
            Some(SessionEndReason::AgentRestarted)
        );
    }
    assert_eq!(
        stored(&s.harness, &after).await.unwrap().state,
        SessionState::Routed
    );
    assert_eq!(
        end(&s.harness, &s.node_id, end_request(&before, 5)).await,
        SessionEndOutcome::Recorded
    );
    let late = stored(&s.harness, &before).await.unwrap();
    assert_eq!(
        (late.bytes_out, late.end_reason),
        (Some(5), Some(SessionEndReason::AgentRestarted))
    );
    assert_eq!(
        end(&s.harness, &s.node_id, end_request(&before, 5)).await,
        SessionEndOutcome::Rejected
    );
}

#[tokio::test]
async fn an_absent_agent_and_an_earlier_run_close_their_open_sessions() {
    let s = scenario().await;
    let killer = with_killer(&s);
    let bob = holder(&s.harness, "bob", &["ops"]).await;
    let gone = active_session(&s, &s.alice).await;

    assert_eq!(s.harness.control.agent_gone(&s.node_id).await.unwrap(), 1);
    assert_eq!(
        stored(&s.harness, &gone).await.unwrap().end_reason,
        Some(SessionEndReason::AgentGone)
    );
    assert_eq!(
        (killer.orders()[0].scope.clone(), killer.orders()[0].reason),
        (KillScope::Sessions, KillReason::AgentGone)
    );

    let left = active_session(&s, &bob).await;
    let waiting = routed(&s.harness, &s.alice).await;
    assert_eq!(
        s.harness
            .control
            .close_sessions_of_earlier_runs()
            .await
            .unwrap(),
        2
    );
    for session_id in [&left, &waiting] {
        assert_eq!(
            stored(&s.harness, session_id).await.unwrap().end_reason,
            Some(SessionEndReason::AgentGone)
        );
    }
}
