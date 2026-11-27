use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_audit::ScopedCapture;
use jaunt_control::{
    JoinTokenError, JoinTokenRequest, KillOrder, KillReason, KillScope, Labels, SessionKiller,
};
use jaunt_proto::BoxFuture;
use jaunt_store::{JoinToken, NameScope, NodeState, SessionEndReason, SessionState};
use serde_json::{Value, json};

use crate::audit::{Captured, start_recording, take_recording};
use crate::session_support::{
    LOGIN, NODE_NAME, apply_policy, authorize, holder, node, raw_pool, role, routed, stored,
};
use crate::support::{
    DEFAULT_PEER, Harness, Reply, new_agent, request, send, sha256_hex, verify_node_certificate,
};

struct Issued {
    secret: String,
    id: String,
}

fn labels(text: &str) -> Labels {
    Labels::parse_assignments(text).unwrap()
}

async fn issue(
    harness: &Harness,
    scope: NameScope,
    uses: u32,
    ttl_secs: u64,
    allow_replace: bool,
) -> Issued {
    let created = harness
        .control
        .join_tokens()
        .create(
            JoinTokenRequest {
                scope,
                labels: labels("env=prod,team=core"),
                uses,
                ttl: Duration::from_secs(ttl_secs),
                allow_replace,
            },
            "cli:tester",
        )
        .await
        .unwrap();
    Issued {
        secret: created.secret.expose().to_owned(),
        id: created.token.id,
    }
}

fn prefix(text: &str) -> NameScope {
    NameScope::Prefix(text.to_owned())
}

fn token_body(name: &str, secret: &str, labels: &Value, replace: bool) -> Value {
    let mut body = new_agent().enroll_body(name);
    body["join_token"] = json!(secret);
    body["labels"] = labels.clone();
    body["replace"] = json!(replace);
    body
}

async fn join(harness: &Harness, name: &str, secret: &str) -> Reply {
    harness
        .enroll_body(&token_body(name, secret, &json!({"env": "prod"}), false))
        .await
}

async fn token(harness: &Harness, id: &str) -> JoinToken {
    harness
        .store
        .join_tokens()
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|token| token.id == id)
        .unwrap()
}

fn audit_events(events: &[Captured], name: &str) -> Vec<Captured> {
    events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit" && event["event"] == name)
        .cloned()
        .collect()
}

fn assert_never_shown(events: &[Captured], secrets: &[&str]) {
    for event in events {
        for value in event.values() {
            for secret in secrets {
                assert!(!value.contains(secret), "{event:?}");
            }
        }
    }
}

#[tokio::test]
async fn two_agents_enrol_with_a_two_use_token_without_a_code_and_the_third_is_refused() {
    let harness = Harness::new().await;
    start_recording();
    let issued = issue(&harness, prefix("web-"), 2, 3600, false).await;

    let mut node_ids = Vec::new();
    for name in ["web-01", "web-02"] {
        let reply = join(&harness, name, &issued.secret).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let answer = reply.json();
        assert!(answer.get("code").is_none(), "{answer}");
        let delivered = harness.poll(answer["handle"].as_str().unwrap()).await;
        assert_eq!(delivered.state(), "approved", "{}", delivered.text());
        let body = delivered.json();
        let der = STANDARD
            .decode(body["x509_certificate_der"].as_str().unwrap())
            .unwrap();
        verify_node_certificate(&harness.root_der, &der, harness.clock.now_secs()).unwrap();
        let node = harness
            .store
            .nodes()
            .get_active_by_name(name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.id, body["node_id"].as_str().unwrap());
        assert_eq!(node.labels, labels("env=prod,team=core").into_map());
        assert_eq!(node.approved_by, format!("join-token:{}", issued.id));
        node_ids.push(node.id);
    }
    let third = join(&harness, "web-03", &issued.secret).await;

    assert_eq!(third.status, StatusCode::FORBIDDEN);
    assert_eq!(third.error_code(), "join_token_refused");
    assert_eq!(token(&harness, &issued.id).await.uses_left, 0);
    assert!(
        harness
            .store
            .nodes()
            .get_active_by_name("web-03")
            .await
            .unwrap()
            .is_none()
    );
    let events = take_recording();
    assert_never_shown(&events, &[&issued.secret, &sha256_hex(&issued.secret)]);
    let created = audit_events(&events, "join_token.created");
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["join_id"], issued.id);
    assert_eq!(created[0]["name_prefix"], "web-");
    assert_eq!(created[0]["labels"], "env=prod,team=core");
    let used = audit_events(&events, "join_token.used");
    let used_nodes: Vec<&str> = used.iter().map(|event| event["node_id"].as_str()).collect();
    assert_eq!(used_nodes, node_ids);
    assert!(used.iter().all(|event| event["join_id"] == issued.id));
    let refused = audit_events(&events, "join_token.refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["reason"], "used_up");
    assert_eq!(refused[0]["join_id"], issued.id);
    assert_eq!(refused[0]["source_ip"], DEFAULT_PEER);
    assert_eq!(audit_events(&events, "node.enroll.requested").len(), 2);
    assert_eq!(audit_events(&events, "node.enroll.delivered").len(), 2);
}

#[tokio::test]
async fn every_refused_token_gets_the_same_answer_and_the_cause_goes_only_to_the_audit() {
    let harness = Harness::new().await;
    let web = issue(&harness, prefix("web-"), 5, 3600, false).await;
    let exact = issue(
        &harness,
        NameScope::Exact("db-01".to_owned()),
        5,
        3600,
        false,
    )
    .await;
    let revoked = issue(&harness, prefix("web-"), 5, 3600, false).await;
    let short = issue(&harness, prefix("web-"), 5, 60, false).await;
    harness
        .control
        .join_tokens()
        .revoke(&revoked.id, "cli:tester")
        .await
        .unwrap();
    harness.clock.advance(60);
    let unknown = format!("jt1.{}", "A".repeat(43));
    start_recording();

    let prod = json!({"env": "prod"});
    let cases = [
        (
            "malformed",
            token_body("web-01", "jt1.short", &prod, false),
            None,
        ),
        (
            "unknown",
            token_body("web-01", &unknown, &prod, false),
            None,
        ),
        (
            "revoked",
            token_body("web-01", &revoked.secret, &prod, false),
            Some(&revoked.id),
        ),
        (
            "expired",
            token_body("web-01", &short.secret, &prod, false),
            Some(&short.id),
        ),
        (
            "name_mismatch",
            token_body("db-02", &exact.secret, &prod, false),
            Some(&exact.id),
        ),
        (
            "name_mismatch",
            token_body("api-01", &web.secret, &prod, false),
            Some(&web.id),
        ),
        (
            "label_mismatch",
            token_body(
                "web-01",
                &web.secret,
                &json!({"env": "prod", "role": "db"}),
                false,
            ),
            Some(&web.id),
        ),
        (
            "label_mismatch",
            token_body("web-01", &web.secret, &json!({"env": "dev"}), false),
            Some(&web.id),
        ),
    ];
    let mut answers: Vec<Reply> = Vec::new();
    for (_, body, _) in &cases {
        let reply = harness.enroll_body(body).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.text());
        answers.push(reply);
    }

    for answer in &answers[1..] {
        assert_eq!(answer.status, answers[0].status);
        assert_eq!(answer.headers, answers[0].headers);
        assert_eq!(answer.body, answers[0].body);
    }
    assert_eq!(answers[0].json(), json!({"error": "join_token_refused"}));
    let events = take_recording();
    let refused = audit_events(&events, "join_token.refused");
    let seen: Vec<(&str, Option<&str>)> = refused
        .iter()
        .map(|event| {
            (
                event["reason"].as_str(),
                event.get("join_id").map(String::as_str),
            )
        })
        .collect();
    let expected: Vec<(&str, Option<&str>)> = cases
        .iter()
        .map(|(reason, _, id)| (*reason, id.map(String::as_str)))
        .collect();
    assert_eq!(seen, expected);
    let all_secrets = [&web, &exact, &revoked, &short]
        .iter()
        .flat_map(|issued| [issued.secret.clone(), sha256_hex(&issued.secret)])
        .chain([unknown.clone()])
        .collect::<Vec<_>>();
    let shown: Vec<&str> = all_secrets.iter().map(String::as_str).collect();
    assert_never_shown(&events, &shown);
    assert_eq!(token(&harness, &web.id).await.uses_left, 5);
    assert_eq!(token(&harness, &exact.id).await.uses_left, 5);
    assert!(harness.store.nodes().list().await.unwrap().is_empty());
}

#[tokio::test]
async fn the_agent_may_omit_or_repeat_pinned_labels_and_the_node_gets_exactly_the_pinned_ones() {
    let harness = Harness::new().await;
    let issued = issue(&harness, prefix("web-"), 2, 3600, false).await;

    for (name, asked) in [
        ("web-01", json!({})),
        ("web-02", json!({"team": "core", "env": "prod"})),
    ] {
        let reply = harness
            .enroll_body(&token_body(name, &issued.secret, &asked, false))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let node = harness
            .store
            .nodes()
            .get_active_by_name(name)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(node.labels, labels("env=prod,team=core").into_map());
    }
}

#[tokio::test]
async fn a_taken_name_is_replaced_only_when_the_agent_asks_and_the_token_allows_it() {
    let harness = Harness::new().await;
    let strict = issue(&harness, prefix("web-"), 3, 3600, false).await;
    let replacing = issue(&harness, prefix("web-"), 3, 3600, true).await;
    let prod = json!({"env": "prod"});
    assert_eq!(
        join(&harness, "web-01", &strict.secret).await.status,
        StatusCode::OK
    );
    let old = harness
        .store
        .nodes()
        .get_active_by_name("web-01")
        .await
        .unwrap()
        .unwrap();
    start_recording();

    let taken = join(&harness, "web-01", &strict.secret).await;
    let not_allowed = harness
        .enroll_body(&token_body("web-01", &strict.secret, &prod, true))
        .await;
    let not_asked = join(&harness, "web-01", &replacing.secret).await;
    let replaced = harness
        .enroll_body(&token_body("web-01", &replacing.secret, &prod, true))
        .await;

    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(taken.error_code(), "name_taken");
    assert_eq!(not_allowed.status, StatusCode::FORBIDDEN);
    assert_eq!(not_allowed.error_code(), "join_token_refused");
    assert_eq!(not_asked.status, StatusCode::CONFLICT);
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.text());
    assert_eq!(token(&harness, &strict.id).await.uses_left, 2);
    assert_eq!(token(&harness, &replacing.id).await.uses_left, 2);
    let removed = harness.store.nodes().get(&old.id).await.unwrap().unwrap();
    assert_eq!(removed.state, NodeState::Removed);
    let events = take_recording();
    let refused = audit_events(&events, "join_token.refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["reason"], "replace_not_allowed");
    let used = audit_events(&events, "join_token.used");
    assert_eq!(used.len(), 1);
    assert_eq!(used[0]["replaced_node_id"], old.id);
    let node_removed = audit_events(&events, "node.removed");
    assert_eq!(node_removed.len(), 1);
    assert_eq!(
        node_removed[0]["removed_by"],
        format!("join-token:{}", replacing.id)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_eight_concurrent_requests_for_the_last_use_exactly_one_enrols() {
    let harness = Harness::new().await;
    let issued = issue(&harness, prefix("web-"), 1, 3600, false).await;

    let mut tasks = Vec::new();
    for index in 0..8 {
        let router = harness.router.clone();
        let body = token_body(
            &format!("web-{index:02}"),
            &issued.secret,
            &json!({"env": "prod"}),
            false,
        );
        tasks.push(tokio::spawn(async move {
            send(
                router,
                request("/v1/agent/enroll", &body, Some(DEFAULT_PEER), None),
            )
            .await
            .status
        }));
    }
    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.unwrap());
    }

    let won = statuses
        .iter()
        .filter(|status| **status == StatusCode::OK)
        .count();
    let refused = statuses
        .iter()
        .filter(|status| **status == StatusCode::FORBIDDEN)
        .count();
    assert_eq!((won, refused), (1, 7), "{statuses:?}");
    assert_eq!(token(&harness, &issued.id).await.uses_left, 0);
    assert_eq!(harness.store.nodes().list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_enrolment_without_a_token_still_waits_for_an_approval_code() {
    let harness = Harness::new().await;
    issue(&harness, prefix("web-"), 1, 3600, false).await;

    let enrolled = harness.enroll("web-01").await;
    let mut null_token = new_agent().enroll_body("web-02");
    null_token["join_token"] = Value::Null;
    let explicit_null = harness.enroll_body(&null_token).await;

    assert_eq!(enrolled.code.len(), 9);
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "pending");
    assert_eq!(explicit_null.status, StatusCode::OK);
    assert!(explicit_null.json()["code"].is_string());
    harness.approve(&enrolled).await;
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "approved");
}

#[tokio::test]
async fn token_attempts_share_the_per_address_enrolment_limit() {
    let harness = Harness::new().await;
    let flood = token_body("web-01", "jt1.short", &json!({"env": "prod"}), false);
    let mut statuses = Vec::new();
    for _ in 0..61 {
        statuses.push(harness.enroll_from("198.51.100.7", &flood).await.status);
    }
    let other = harness.enroll_from("198.51.100.8", &flood).await;

    assert!(
        statuses[..60]
            .iter()
            .all(|status| *status == StatusCode::FORBIDDEN)
    );
    assert_eq!(statuses[60], StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(other.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_tokens_are_purged_an_hour_after_their_expiry_and_used_up_ones_wait_for_theirs() {
    let harness = Harness::new().await;
    issue(&harness, prefix("web-"), 1, 60, false).await;
    let used_up = issue(&harness, prefix("db-"), 1, 7 * 86_400, false).await;
    assert_eq!(
        join(&harness, "db-01", &used_up.secret).await.status,
        StatusCode::OK
    );
    assert_eq!(token(&harness, &used_up.id).await.uses_left, 0);

    harness.clock.advance(60 + 3600);
    assert_eq!(harness.control.purge_join_tokens().await.unwrap(), 0);
    harness.clock.advance(1);
    assert_eq!(harness.control.purge_join_tokens().await.unwrap(), 1);
    let left: Vec<String> = harness
        .store
        .join_tokens()
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|token| token.id)
        .collect();
    assert_eq!(left, vec![used_up.id]);
}

#[tokio::test]
async fn the_server_keeps_a_token_lifetime_between_one_second_and_seven_days_in_whole_seconds() {
    let harness = Harness::new().await;
    let week = Duration::from_secs(7 * 86_400);
    for (ttl, accepted) in [
        (week, true),
        (Duration::from_secs(1), true),
        (week + Duration::from_secs(1), false),
        (Duration::from_millis(1500), false),
        (Duration::ZERO, false),
    ] {
        let created = harness
            .control
            .join_tokens()
            .create(
                JoinTokenRequest {
                    scope: prefix("web-"),
                    labels: labels("env=prod"),
                    uses: 1,
                    ttl,
                    allow_replace: false,
                },
                "cli:tester",
            )
            .await;
        match created {
            Ok(created) => {
                assert!(accepted, "{ttl:?}");
                let expected = harness.clock.now_secs() + i64::try_from(ttl.as_secs()).unwrap();
                assert_eq!(created.token.expires_at, expected, "{ttl:?}");
            }
            Err(err) => {
                assert!(!accepted, "{ttl:?}: {err}");
                assert!(matches!(err, JoinTokenError::InvalidTtl), "{ttl:?}: {err}");
            }
        }
    }
    assert_eq!(harness.store.join_tokens().list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn the_schema_events_keep_every_field_and_none_of_them_carries_the_token_or_its_hash() {
    let harness = Harness::new().await;
    let capture = ScopedCapture::start();

    let issued = issue(&harness, prefix("web-"), 1, 3600, false).await;
    let joined = join(&harness, "web-01", &issued.secret).await;
    let refused = join(&harness, "web-02", &issued.secret).await;
    harness
        .control
        .join_tokens()
        .revoke(&issued.id, "cli:tester")
        .await
        .unwrap();
    let snapshot = capture.snapshot();
    let mut events = capture.finish().await;
    let emitted = [
        "join_token.created",
        "node.enroll.requested",
        "join_token.used",
        "join_token.refused",
        "join_token.revoked",
    ];
    events.sort_by_key(|event| emitted.iter().position(|name| *name == event.kind().name()));

    assert_eq!(joined.status, StatusCode::OK);
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );
    let sequence: Vec<(&str, String)> = events
        .iter()
        .map(|event| (event.kind().name(), event.actor().as_wire()))
        .collect();
    assert_eq!(
        sequence,
        [
            ("join_token.created", "cli:tester".to_owned()),
            ("node.enroll.requested", "anonymous".to_owned()),
            ("join_token.used", "anonymous".to_owned()),
            ("join_token.refused", "anonymous".to_owned()),
            ("join_token.revoked", "cli:tester".to_owned()),
        ]
    );
    let node_id = harness
        .store
        .nodes()
        .get_active_by_name("web-01")
        .await
        .unwrap()
        .unwrap()
        .id;
    assert_eq!(events[2].node(), Some(node_id.as_str()));
    assert_eq!(events[2].text("node_id"), None);
    assert_eq!(events[2].int("uses_left"), Some(0));
    assert_eq!(events[3].text("reason"), Some("used_up"));
    for event in &events[..] {
        if event.kind().name().starts_with("join_token.") {
            assert_eq!(event.text("join_id"), Some(issued.id.as_str()));
        }
    }
    let lines: Vec<String> = events
        .iter()
        .map(|event| serde_json::to_string(event.as_ref()).unwrap())
        .collect();
    for line in &lines {
        assert!(!line.contains(&issued.secret), "{line}");
        assert!(!line.contains(&sha256_hex(&issued.secret)), "{line}");
    }
}

#[derive(Default)]
struct RecordingKiller(Mutex<Vec<KillOrder>>);

impl SessionKiller for RecordingKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(order.clone());
        Box::pin(async {})
    }
}

#[tokio::test]
async fn replacing_a_node_with_a_token_closes_the_old_node_sessions_at_once() {
    let harness = Harness::new().await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let old_id = node(&harness, NODE_NAME).await;
    apply_policy(&harness, &[role("ops", "ops", false, false)]);
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &old_id, bob.authorize(&session_id, LOGIN)).await;
    assert_eq!(
        stored(&harness, &session_id).await.unwrap().state,
        SessionState::Active
    );
    let issued = issue(&harness, prefix("web-"), 1, 3600, true).await;

    let replaced = harness
        .enroll_body(&token_body(
            NODE_NAME,
            &issued.secret,
            &json!({"env": "prod"}),
            true,
        ))
        .await;

    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.text());
    let closed = stored(&harness, &session_id).await.unwrap();
    assert_eq!(
        (closed.state, closed.end_reason),
        (SessionState::Ended, Some(SessionEndReason::NodeRemoved))
    );
    let orders = killer.0.lock().unwrap().clone();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        (orders[0].scope.clone(), orders[0].reason),
        (
            KillScope::Node {
                node_id: old_id.clone()
            },
            KillReason::NodeRemoved
        )
    );
    assert_eq!(orders[0].sessions[0].session_id, session_id);
}

#[tokio::test]
async fn a_token_row_with_a_stored_name_label_enrols_nobody() {
    let harness = Harness::new().await;
    let issued = issue(&harness, prefix("web-"), 2, 3600, false).await;
    sqlx::query("UPDATE join_tokens SET labels = ? WHERE id = ?")
        .bind(r#"{"env":"prod","name":"legacy"}"#)
        .bind(&issued.id)
        .execute(&raw_pool(&harness).await)
        .await
        .unwrap();

    let reply = join(&harness, "web-01", &issued.secret).await;
    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (StatusCode::BAD_REQUEST, "invalid_labels"),
        "{}",
        reply.text()
    );
    assert!(
        harness
            .store
            .nodes()
            .get_active_by_name("web-01")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(token(&harness, &issued.id).await.uses_left, 2);
}
