use jaunt_control::{AccessReview, KillReason};
use jaunt_proto::ServiceKind;
use jaunt_store::{SessionEndReason, SessionState};

use crate::service_support::{
    KUBE, OPS_ROLE, SERVICE_NODE, Stand, TCP, open, person, row, ssh_session, stand_with_policy,
};
use crate::session_support::{apply_policy, holder, raw_pool, role};

const KUBE_TWO_GROUPS: &str = "groups: [view, edit], recordInput: true";

const BOB_SHELL: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: bob-shell }\nspec:\n  \
    members: { users: [bob@example.com] }\n  ssh: { nodes: { name: [svc-01] }, logins: [deploy] }\n";

const NO_DEPLOY: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: no-deploy }\nspec:\n  \
    members: { groups: [locked] }\n  deny: { ssh: { nodes: { env: [prod] }, logins: [deploy] } }\n";

fn kube_base() -> String {
    OPS_ROLE.replace("groups: [view], recordInput: true", KUBE_TWO_GROUPS)
}

fn shell() -> String {
    role("shell", "ops", false, false)
}

fn ended_by_kill(stand: &Stand, id: &str) -> Option<KillReason> {
    stand
        .killer
        .orders()
        .into_iter()
        .find(|order| {
            order
                .sessions
                .iter()
                .any(|session| session.session_id == id)
        })
        .map(|order| order.reason)
}

#[tokio::test]
async fn a_live_kube_session_is_cut_when_its_effective_grant_changes_in_any_way() {
    let base = kube_base();
    let stand = stand_with_policy(std::slice::from_ref(&base)).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let deny_cluster =
        format!("{base}  deny: {{ kubernetes: {{ clusters: {{ env: [prod] }} }} }}\n");
    let cases = [
        (
            "unrelated change",
            base.replace("team: [ops]", "team: [ops, dev]"),
            None,
        ),
        (
            "narrower groups",
            base.replace(KUBE_TWO_GROUPS, "groups: [view], recordInput: true"),
            Some(SessionEndReason::AccessChanged),
        ),
        (
            "wider groups",
            base.replace(
                KUBE_TWO_GROUPS,
                "groups: [view, edit, admin], recordInput: true",
            ),
            Some(SessionEndReason::AccessChanged),
        ),
        (
            "another user",
            base.replace(
                KUBE_TWO_GROUPS,
                "groups: [view, edit], recordInput: true, users: ['{email}', ops-robot]",
            ),
            Some(SessionEndReason::AccessChanged),
        ),
        (
            "exec not recorded",
            base.replace(
                KUBE_TWO_GROUPS,
                "groups: [view, edit], recordInput: true, recordExec: false",
            ),
            Some(SessionEndReason::AccessChanged),
        ),
        (
            "input not recorded",
            base.replace(KUBE_TWO_GROUPS, "groups: [view, edit], recordInput: false"),
            Some(SessionEndReason::AccessChanged),
        ),
        (
            "cluster denied",
            deny_cluster,
            Some(SessionEndReason::AccessWithdrawn),
        ),
    ];
    for (label, changed, expected) in cases {
        apply_policy(harness, std::slice::from_ref(&base));
        let id = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
        assert_eq!(
            row(harness, &id).await.decision_hash.map(|hash| hash.len()),
            Some(64)
        );
        apply_policy(harness, &[changed]);
        harness.control.review_access().await.unwrap();
        let stored = row(harness, &id).await;
        assert_eq!(stored.end_reason, expected, "{label}");
        let killed = ended_by_kill(&stand, &id);
        match expected {
            None => {
                assert_eq!(stored.state, SessionState::Active, "{label}");
                assert_eq!(killed, None, "{label}");
            }
            Some(SessionEndReason::AccessChanged) => {
                assert_eq!(killed, Some(KillReason::AccessChanged), "{label}");
            }
            Some(_) => assert_eq!(killed, Some(KillReason::AccessWithdrawn), "{label}"),
        }
    }
    apply_policy(harness, std::slice::from_ref(&base));
    let reconnected = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    assert_eq!(
        harness.control.review_access().await.unwrap(),
        AccessReview {
            checked: 1,
            withdrawn: 0,
            changed: 0,
            service_removed: 0,
        }
    );
    assert_eq!(row(harness, &reconnected).await.end_reason, None);
}

#[tokio::test]
async fn live_ssh_sessions_are_cut_when_the_policy_or_the_node_no_longer_allows_their_login() {
    let roles = [OPS_ROLE.to_owned(), shell(), BOB_SHELL.to_owned()];
    let stand = stand_with_policy(&roles).await;
    let harness = &stand.harness;
    let alice = holder(harness, "alice", &["ops"]).await;
    let carol = holder(harness, "carol", &["ops", "locked"]).await;
    let bob = holder(harness, "bob", &["dev"]).await;
    let alice_ssh = ssh_session(&stand, &alice).await;
    let carol_ssh = ssh_session(&stand, &carol).await;
    let bob_ssh = ssh_session(&stand, &bob).await;
    let x509 = person(harness, "dora", &["ops"]).await;
    let tcp = open(&stand, &x509, ServiceKind::Tcp, TCP).await;
    let state = |id: String| async move { row(harness, &id).await.end_reason };

    apply_policy(
        harness,
        &[
            OPS_ROLE.replace("team: [ops]", "team: [ops, dev]"),
            shell(),
            BOB_SHELL.to_owned(),
        ],
    );
    let unrelated = harness.control.review_access().await.unwrap();
    assert_eq!((unrelated.checked, unrelated.withdrawn), (4, 0));

    apply_policy(
        harness,
        &[
            OPS_ROLE.to_owned(),
            shell(),
            BOB_SHELL.to_owned(),
            NO_DEPLOY.to_owned(),
        ],
    );
    assert_eq!(harness.control.review_access().await.unwrap().withdrawn, 1);
    assert_eq!(
        state(carol_ssh.clone()).await,
        Some(SessionEndReason::AccessWithdrawn)
    );
    assert_eq!(state(alice_ssh.clone()).await, None);
    assert_eq!(state(bob_ssh.clone()).await, None);
    assert_eq!(
        ended_by_kill(&stand, &carol_ssh),
        Some(KillReason::AccessWithdrawn)
    );

    sqlx::query("UPDATE nodes SET labels = '{\"env\":\"stage\"}' WHERE name = ?")
        .bind(SERVICE_NODE)
        .execute(&raw_pool(harness).await)
        .await
        .unwrap();
    assert_eq!(harness.control.review_access().await.unwrap().withdrawn, 1);
    assert_eq!(
        state(alice_ssh.clone()).await,
        Some(SessionEndReason::AccessWithdrawn)
    );
    assert_eq!(state(bob_ssh.clone()).await, None);
    assert_eq!(state(tcp.clone()).await, None);

    apply_policy(
        harness,
        &[
            OPS_ROLE.to_owned(),
            shell(),
            BOB_SHELL.replace("logins: [deploy]", "logins: [other]"),
        ],
    );
    assert_eq!(harness.control.review_access().await.unwrap().withdrawn, 1);
    assert_eq!(
        state(bob_ssh.clone()).await,
        Some(SessionEndReason::AccessWithdrawn)
    );
    assert_eq!(state(tcp).await, None);
    let orders = stand.killer.orders();
    assert_eq!(orders.len(), 3);
    assert!(
        orders
            .iter()
            .all(|order| order.reason == KillReason::AccessWithdrawn
                && order.scope == jaunt_control::KillScope::Sessions
                && order.sessions.len() == 1)
    );
}

fn raw_items(event: &crate::audit::Captured) -> Vec<(&str, jaunt_audit::RawValue)> {
    event
        .iter()
        .filter(|(name, _)| name.as_str() != "target")
        .map(|(name, value)| {
            let raw = match (value.parse::<i64>(), value.as_str()) {
                (Ok(number), _) => jaunt_audit::RawValue::Signed(number),
                (Err(_), "true") => jaunt_audit::RawValue::Bool(true),
                (Err(_), "false") => jaunt_audit::RawValue::Bool(false),
                (Err(_), text) => jaunt_audit::RawValue::Text(text.to_owned()),
            };
            (name.as_str(), raw)
        })
        .collect()
}

#[tokio::test]
async fn every_service_event_the_control_writes_fits_its_audit_spec_without_dropping_a_field() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    crate::audit::start_recording();
    let db = open(
        &stand,
        &alice,
        ServiceKind::Postgres,
        crate::service_support::DB,
    )
    .await;
    crate::service_support::end_service(
        harness,
        &stand.node_id,
        &db,
        jaunt_proto::ServiceOutcome::Closed,
        3,
    )
    .await;
    let denied = crate::service_support::authorize_service(
        harness,
        &stand.node_id,
        crate::service_support::authorize_request(&alice, "no-such-session", ServiceKind::Tcp, TCP),
    )
    .await;
    assert!(crate::service_support::denied(&denied).is_some());
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    apply_policy(harness, &[kube_base()]);
    harness.control.review_access().await.unwrap();
    let recorded = crate::session_support::audit_events(crate::audit::take_recording());

    let mut seen = std::collections::BTreeSet::new();
    for event in &recorded {
        let name = event["event"].as_str();
        let wanted = [
            "session.service.routed",
            "session.service.start",
            "session.service.end",
            "authz.service.deny",
            "cert.db_client.issued",
            "session.end",
        ];
        if !wanted.contains(&name) {
            continue;
        }
        let kind = jaunt_audit::EventType::from_emitted(name).unwrap();
        let (_, report) = jaunt_audit::AuditEvent::from_raw(
            kind,
            &raw_items(event),
            "id-1".to_owned(),
            jaunt_audit::Timestamp::from_millis(0).unwrap(),
        );
        assert_eq!(
            report.fields_dropped, 0,
            "{name}: {:?}",
            report.dropped_names
        );
        seen.insert(name.to_owned());
    }
    assert_eq!(seen.len(), 6, "{seen:?}");
    let cut = recorded
        .iter()
        .find(|event| event["event"] == "session.end" && event["session_id"] == kube)
        .unwrap();
    assert_eq!(
        (
            cut["kind"].as_str(),
            cut["service"].as_str(),
            cut["outcome"].as_str()
        ),
        ("kube", KUBE, "access_changed")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_failed_review_is_retried_on_the_next_tick_and_not_thirty_seconds_later() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let canary = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    apply_policy(harness, &[kube_base()]);
    let pool = raw_pool(harness).await;

    tokio::time::pause();
    let spinner = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let control = harness.control.clone();
    let watch = tokio::spawn(async move {
        control
            .watch_access(
                jaunt_control::ACCESS_REVIEW_POLL,
                jaunt_control::ACCESS_REVIEW_INTERVAL,
                jaunt_control::ACCESS_REVIEW_DEBOUNCE,
            )
            .await;
    });
    settle().await;
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    assert_eq!(
        ended(&stand, &canary).await,
        SessionEndReason::AccessChanged
    );

    sqlx::query("ALTER TABLE services RENAME TO services_kept")
        .execute(&pool)
        .await
        .unwrap();
    crate::audit::start_recording();
    apply_policy(
        harness,
        &[kube_base().replace("team: [ops]", "team: [none]")],
    );
    let started = std::time::Instant::now();
    loop {
        tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
        settle().await;
        let failed = crate::audit::take_recording().iter().any(|event| {
            event.get("message").is_some_and(|text| {
                text.starts_with("reviewing the access of live sessions failed")
            })
        });
        crate::audit::start_recording();
        if failed {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the review did not fail"
        );
        tokio::task::yield_now().await;
    }
    sqlx::query("ALTER TABLE services_kept RENAME TO services")
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
    assert_eq!(ended(&stand, &tcp).await, SessionEndReason::AccessWithdrawn);
    watch.abort();
    spinner.abort();
}

async fn ended(stand: &Stand, id: &str) -> SessionEndReason {
    let started = std::time::Instant::now();
    loop {
        if let Some(reason) = row(&stand.harness, id).await.end_reason {
            return reason;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the session {id} was not cut"
        );
        tokio::task::yield_now().await;
    }
}

async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_live_session_that_cannot_be_evaluated_is_cut_and_the_others_are_still_judged() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    let kept = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let unreadable = open(&stand, &bob, ServiceKind::Tcp, TCP).await;
    sqlx::query("UPDATE users SET groups = 'not json' WHERE id = ?")
        .bind(&bob.user_id)
        .execute(&raw_pool(harness).await)
        .await
        .unwrap();
    let review = harness.control.review_access().await.unwrap();
    assert_eq!((review.checked, review.withdrawn), (2, 1));
    assert_eq!(
        row(harness, &unreadable).await.end_reason,
        Some(SessionEndReason::AccessWithdrawn)
    );
    assert_eq!(row(harness, &kept).await.end_reason, None);
    assert_eq!(
        ended_by_kill(&stand, &unreadable),
        Some(KillReason::AccessWithdrawn)
    );
}

#[tokio::test]
async fn a_live_session_survives_more_re_approvals_than_the_kept_history() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let first_revision = row(harness, &tcp).await.service_id.unwrap();
    for version in 0..10 {
        harness.clock.advance(10);
        let mut grafana = crate::service_support::tcp_service(TCP);
        grafana["labels"]["v"] = serde_json::json!(version.to_string());
        crate::service_support::announce(
            harness,
            &stand.node_id,
            &[
                grafana,
                crate::service_support::tcp_service(crate::service_support::METRICS),
                crate::service_support::tcp_service(crate::service_support::SHARED),
                crate::service_support::db_service(crate::service_support::SHARED),
                crate::service_support::db_service(crate::service_support::DB),
                crate::service_support::kube_service(KUBE),
            ],
        )
        .await;
        crate::service_support::approve(harness, &stand.node_id, "tcp", TCP).await;
    }
    assert!(
        harness
            .store
            .services()
            .get(&first_revision)
            .await
            .unwrap()
            .is_none()
    );
    let review = harness.control.review_access().await.unwrap();
    assert_eq!((review.service_removed, review.withdrawn), (0, 0));
    assert_eq!(row(harness, &tcp).await.end_reason, None);
}

#[tokio::test(flavor = "current_thread")]
async fn a_reload_is_reviewed_only_once_it_settles_and_a_burst_of_reloads_cuts_once() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let canary = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let base = kube_base();
    apply_policy(harness, std::slice::from_ref(&base));

    tokio::time::pause();
    let spinner = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let control = harness.control.clone();
    let watch = tokio::spawn(async move {
        control
            .watch_access(
                jaunt_control::ACCESS_REVIEW_POLL,
                jaunt_control::ACCESS_REVIEW_INTERVAL,
                jaunt_control::ACCESS_REVIEW_DEBOUNCE,
            )
            .await;
    });
    settle().await;
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    assert_eq!(
        ended(&stand, &canary).await,
        SessionEndReason::AccessChanged
    );
    let orders_before = stand.killer.orders().len();
    let kube_first = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;

    apply_policy(harness, &[base.replace("team: [ops]", "team: [none]")]);
    for _ in 0..2 {
        tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
        settle().await;
        assert_eq!(row(harness, &tcp).await.end_reason, None);
    }
    apply_policy(
        harness,
        &[format!(
            "{base}  deny: {{ kubernetes: {{ clusters: {{ env: [prod] }} }} }}\n"
        )],
    );
    for _ in 0..5 {
        tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
        settle().await;
        assert_eq!(row(harness, &tcp).await.end_reason, None);
        assert_eq!(row(harness, &kube_first).await.end_reason, None);
    }
    tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
    assert_eq!(
        ended(&stand, &kube_first).await,
        SessionEndReason::AccessWithdrawn
    );
    assert_eq!(row(harness, &tcp).await.end_reason, None);
    let orders = stand.killer.orders();
    assert_eq!(orders.len(), orders_before + 1);
    assert_eq!(orders.last().unwrap().reason, KillReason::AccessWithdrawn);
    watch.abort();
    spinner.abort();
}
