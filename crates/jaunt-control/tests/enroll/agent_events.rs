use std::time::Duration;

use axum::http::{StatusCode, header};
use jaunt_proto::{AGENT_EVENTS_PATH, ServiceKind, ServiceOutcome};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::audit::{Captured, start_recording, take_recording};
use crate::service_support::{
    CLIENT, DB, KUBE, METRICS, OPS_ROLE, Stand, TCP, X509, announce, approve, authorize_request,
    authorize_service, denied, end_service, open, person, routed_id, row, ssh_session, stand,
    stand_with_policy, tcp_service,
};
use crate::session_support::{holder, raw_pool, role};
use crate::support::{Reply, request, send};

const UNKNOWN: &str = "0b0f4c6e-1d2a-4b3c-8d4e-5f6a7b8c9d0e";
const NO_MARKS: &str = "CREATE TRIGGER no_marks BEFORE UPDATE OF audit_incomplete ON sessions \
    BEGIN SELECT RAISE(ABORT, 'marks are refused'); END";

async fn post(stand: &Stand, node_id: &str, body: &Value) -> Reply {
    send(
        stand.harness.agent_router.clone(),
        request(AGENT_EVENTS_PATH, body, None, Some(node_id)),
    )
    .await
}

async fn post_raw(stand: &Stand, node_id: &str, body: &[u8]) -> Reply {
    send(
        stand.harness.agent_router.clone(),
        crate::support::request_raw(
            AGENT_EVENTS_PATH,
            "application/json",
            body.to_vec(),
            None,
            Some(node_id),
        ),
    )
    .await
}

fn event(session_id: &str, seq: u64, name: &str, fields: Value) -> Value {
    json!({"session_id": session_id, "seq": seq, "observed_at": 0, "name": name, "fields": fields})
}

fn batch(events: Vec<Value>) -> Value {
    json!({"events": events, "dropped": []})
}

fn report(session_id: &str, count: u64) -> Value {
    json!({"events": [], "dropped": [{"session_id": session_id, "count": count}]})
}

fn counts(reply: &Reply) -> (u64, u64) {
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    (
        body["accepted"].as_u64().unwrap(),
        body["dropped"].as_u64().unwrap(),
    )
}

fn audited(event: &Captured) -> bool {
    matches!(
        event["target"].as_str(),
        "jaunt::audit" | "jaunt::audit::private"
    )
}

fn named<'a>(recorded: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    recorded
        .iter()
        .filter(|event| audited(event) && event["event"] == name)
        .collect()
}

fn agent_written(recorded: &[Captured]) -> Vec<String> {
    recorded
        .iter()
        .filter(|event| audited(event))
        .map(|event| event["event"].clone())
        .filter(|name| {
            ["kube.", "db.", "tcp."]
                .iter()
                .any(|kind| name.starts_with(kind))
        })
        .collect()
}

fn values<'a>(events: &[&'a Captured], field: &str) -> Vec<&'a str> {
    events.iter().map(|event| event[field].as_str()).collect()
}

async fn foreign_session(stand: &Stand, holder: &X509) -> String {
    let harness = &stand.harness;
    announce(harness, &stand.other_node_id, &[tcp_service("elsewhere")]).await;
    approve(harness, &stand.other_node_id, "tcp", "elsewhere").await;
    let id = routed_id(harness, holder, ServiceKind::Tcp, "elsewhere").await;
    let decision = authorize_service(
        harness,
        &stand.other_node_id,
        authorize_request(holder, &id, ServiceKind::Tcp, "elsewhere"),
    )
    .await;
    assert_eq!(denied(&decision), None);
    id
}

async fn execute(stand: &Stand, statement: &'static str) {
    sqlx::query(statement)
        .execute(&raw_pool(&stand.harness).await)
        .await
        .unwrap();
}

async fn until_marked(stand: &Stand, session_id: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !row(&stand.harness, session_id).await.audit_incomplete {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the session was not marked"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn an_event_of_an_owned_session_is_written_under_the_identity_of_its_session_row() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let now_ms = stand.harness.clock.now_secs() * 1000;
    let mut start = event(&tcp, 1, "tcp.session.start", json!({"client_addr": CLIENT}));
    start["observed_at"] = json!(i64::MAX);
    start_recording();

    let reply = post(&stand, &stand.node_id, &batch(vec![start])).await;

    assert_eq!(counts(&reply), (1, 0));
    let recorded = take_recording();
    let written = named(&recorded, "tcp.session.start");
    assert_eq!(written.len(), 1);
    let written = written[0];
    assert_eq!(written["target"], "jaunt::audit");
    assert_eq!(written["user_id"], alice.user_id);
    assert_eq!(written["node_id"], stand.node_id);
    assert_eq!(written["session_id"], tcp);
    assert_eq!(written["service"], TCP);
    assert_eq!(written["client_addr"], CLIENT);
    assert_eq!(written["observed_at"], (now_ms + 60_000).to_string());
    assert!(named(&recorded, "session.audit_incomplete").is_empty());
}

#[tokio::test]
async fn a_session_that_is_not_an_authorized_service_session_of_this_node_refuses_the_batch_by_name()
 {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned(), role("shell", "ops", false, false)]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let erin = holder(harness, "erin", &["ops"]).await;
    let live = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let foreign = foreign_session(&stand, &alice).await;
    let ssh = ssh_session(&stand, &erin).await;
    let unauthorized = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;

    for (index, (bad, reason, in_dropped)) in [
        (UNKNOWN, "unknown_session", false),
        (foreign.as_str(), "foreign_session", false),
        (foreign.as_str(), "foreign_session", true),
        (ssh.as_str(), "ssh_session", false),
        (unauthorized.as_str(), "not_authorized", false),
    ]
    .into_iter()
    .enumerate()
    {
        harness.clock.advance(10);
        let mut body = batch(vec![event(&live, 1, "tcp.session.start", json!({}))]);
        if in_dropped {
            body["dropped"] = json!([{"session_id": bad, "count": 3}]);
        } else {
            body["events"].as_array_mut().unwrap().push(event(
                bad,
                1,
                "tcp.session.end",
                json!({}),
            ));
        }
        start_recording();
        let reply = post(&stand, &stand.node_id, &body).await;
        let recorded = take_recording();
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{reason}");
        assert_eq!(
            reply.json(),
            json!({"error": "invalid_session", "sessions": [bad]}),
            "{reason}"
        );
        assert!(agent_written(&recorded).is_empty(), "{reason}");
        assert!(
            named(&recorded, "agent.events.dropped").is_empty(),
            "{reason}"
        );
        let refused = named(&recorded, "agent.events.refused");
        assert_eq!(refused.len(), 1, "{reason} {index}");
        assert_eq!(refused[0]["reason"], reason);
        assert_eq!(refused[0]["node_id"], stand.node_id);
        assert_eq!(refused[0]["sessions"], "1");
    }
    let mut many = batch(vec![event(&live, 1, "tcp.session.start", json!({}))]);
    let strangers: Vec<String> = (0..70)
        .map(|index| format!("00000000-0000-4000-8000-{index:012x}"))
        .collect();
    for stranger in &strangers {
        many["events"].as_array_mut().unwrap().push(event(
            stranger,
            1,
            "tcp.session.end",
            json!({}),
        ));
    }
    let reply = post(&stand, &stand.node_id, &many).await;
    let named_back: Vec<String> = serde_json::from_value(reply.json()["sessions"].clone()).unwrap();
    assert_eq!(named_back.len(), 64);
    assert!(named_back.iter().all(|id| strangers.contains(id)));
    for session in [&live, &foreign] {
        assert!(!row(harness, session).await.audit_incomplete);
    }
    let accepted = post(
        &stand,
        &stand.node_id,
        &batch(vec![event(&live, 1, "tcp.session.start", json!({}))]),
    )
    .await;
    assert_eq!(counts(&accepted), (1, 0));
}

#[tokio::test]
async fn events_and_reports_of_a_long_ended_session_are_dropped_one_by_one_and_the_rest_written() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let live = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let ended = open(&stand, &alice, ServiceKind::Tcp, METRICS).await;
    end_service(harness, &stand.node_id, &ended, ServiceOutcome::Closed, 1).await;
    harness.clock.advance(300);
    let at_the_edge = post(
        &stand,
        &stand.node_id,
        &batch(vec![event(&ended, 1, "tcp.session.end", json!({}))]),
    )
    .await;
    assert_eq!(counts(&at_the_edge), (1, 0));
    harness.clock.advance(1);

    let mut mixed = batch(vec![
        event(&live, 1, "tcp.session.start", json!({})),
        event(&ended, 2, "tcp.session.end", json!({})),
    ]);
    mixed["dropped"] = json!([{"session_id": ended, "count": 4}]);
    start_recording();
    let reply = post(&stand, &stand.node_id, &mixed).await;
    let recorded = take_recording();

    assert_eq!(counts(&reply), (1, 1));
    assert_eq!(agent_written(&recorded), ["tcp.session.start"]);
    let dropped = named(&recorded, "agent.events.dropped");
    assert_eq!(dropped.len(), 1);
    assert_eq!(
        (dropped[0]["reason"].as_str(), dropped[0]["count"].as_str()),
        ("expired", "5")
    );
    assert!(named(&recorded, "agent.events.refused").is_empty());
    assert!(row(harness, &ended).await.audit_incomplete);
    assert!(!row(harness, &live).await.audit_incomplete);
}

#[tokio::test]
async fn each_kind_of_session_takes_only_the_events_of_its_own_kind() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let sessions = [
        (
            open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await,
            "kube.request",
        ),
        (
            open(&stand, &alice, ServiceKind::Postgres, DB).await,
            "db.query",
        ),
        (
            open(&stand, &alice, ServiceKind::Tcp, TCP).await,
            "tcp.session.start",
        ),
    ];
    for (session, own) in &sessions {
        let names = [
            "kube.request",
            "db.query",
            "tcp.session.start",
            "kube.tls.refused",
        ];
        let events = names
            .iter()
            .zip(1..)
            .map(|(name, seq)| event(session, seq, name, json!({})))
            .collect();
        stand.harness.clock.advance(10);
        start_recording();
        let reply = post(&stand, &stand.node_id, &batch(events)).await;
        let recorded = take_recording();
        assert_eq!(counts(&reply), (1, 3), "{own}");
        assert_eq!(agent_written(&recorded), [own.to_string()]);
        let dropped = named(&recorded, "agent.events.dropped");
        assert_eq!(dropped.len(), 1);
        assert_eq!(
            (dropped[0]["reason"].as_str(), dropped[0]["count"].as_str()),
            ("invalid", "3")
        );
        assert!(row(&stand.harness, session).await.audit_incomplete);
    }
}

#[tokio::test]
async fn a_field_outside_the_spec_or_a_noisy_text_too_long_drops_its_event_and_a_lifecycle_text_is_cut()
 {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let request = "kube.request";
    let events = vec![
        event(&kube, 1, request, json!({"verb": "get"})),
        event(&kube, 2, request, json!({"verb": 7})),
        event(&kube, 3, request, json!({"verb": "a".repeat(33)})),
        event(&kube, 4, request, json!({"status": "200"})),
        event(&kube, 5, request, json!({"status": 1.5})),
        event(&kube, 6, request, json!({"policy_hash": "forged"})),
        event(&kube, 7, request, json!({"user_id": "someone-else"})),
        event(&kube, 8, request, json!({"node_id": "another-node"})),
        event(&kube, 9, request, json!({"observed_at": 1})),
        event(&kube, 10, request, json!({"service": "another"})),
        event(&kube, 11, "session.start", json!({})),
        event(
            &kube,
            12,
            "kube.session.start",
            json!({"user": "u".repeat(300)}),
        ),
        event(
            &db,
            1,
            "db.session.start",
            json!({"db_user": "€".repeat(100), "application_name": "psql"}),
        ),
    ];
    start_recording();

    let reply = post(&stand, &stand.node_id, &batch(events)).await;

    assert_eq!(counts(&reply), (3, 10));
    let recorded = take_recording();
    assert_eq!(
        agent_written(&recorded),
        ["kube.request", "kube.session.start", "db.session.start"]
    );
    assert!(
        recorded
            .iter()
            .all(|event| !event.values().any(|value| value == "forged"))
    );
    assert_eq!(
        named(&recorded, "kube.session.start")[0]["user"],
        "u".repeat(255)
    );
    assert_eq!(
        named(&recorded, "db.session.start")[0]["db_user"],
        "€".repeat(42)
    );
    let dropped = named(&recorded, "agent.events.dropped");
    assert_eq!(
        (dropped[0]["reason"].as_str(), dropped[0]["count"].as_str()),
        ("invalid", "10")
    );
    let incomplete = named(&recorded, "session.audit_incomplete");
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0]["dropped_total"], "10");
    assert!(!row(&stand.harness, &db).await.audit_incomplete);

    for forged in ["policy_hash", "actor", "user_id", "node_id"] {
        stand.harness.clock.advance(10);
        let mut body = batch(vec![event(&kube, 20, request, json!({}))]);
        body["events"][0][forged] = json!("forged");
        start_recording();
        let reply = post(&stand, &stand.node_id, &body).await;
        let recorded = take_recording();
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{forged}");
        assert!(agent_written(&recorded).is_empty(), "{forged}");
        assert_eq!(
            named(&recorded, "agent.events.refused")[0]["reason"],
            "malformed"
        );
    }
}

#[tokio::test]
async fn query_and_error_texts_go_to_the_private_trail_and_secret_looking_ones_are_withheld() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let digest = "ab".repeat(32);
    let events = vec![
        event(
            &db,
            1,
            "db.query",
            json!({"text": "SELECT 1 -- bearer abc", "sha256": digest, "length": 22, "truncated": false}),
        ),
        event(
            &db,
            2,
            "db.query",
            json!({"text": "SELECT 2", "sha256": digest}),
        ),
        event(
            &db,
            3,
            "db.error",
            json!({"sqlstate": "42601", "error_message": "-----BEGIN PRIVATE KEY-----"}),
        ),
        event(
            &db,
            4,
            "db.query",
            json!({"text": "\u{1}".repeat(8000), "sha256": digest}),
        ),
    ];
    start_recording();

    let reply = post(&stand, &stand.node_id, &batch(events)).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.json(),
        json!({"accepted": 4, "dropped": 0, "withheld": 2})
    );
    let recorded = take_recording();
    let queries = named(&recorded, "db.query");
    assert_eq!(values(&queries, "target"), ["jaunt::audit::private"; 3]);
    assert_eq!(queries[0]["text"], "[withheld]");
    assert_eq!(queries[0]["sha256"], digest);
    assert_eq!(queries[0]["truncated"], "false");
    assert_eq!(queries[0]["length"], "22");
    assert_eq!(queries[1]["text"], "SELECT 2");
    assert_eq!(queries[2]["truncated"], "true");
    assert!(queries[2]["text"].len() < 8000);
    let errors = named(&recorded, "db.error");
    assert_eq!(errors[0]["target"], "jaunt::audit::private");
    assert_eq!(errors[0]["error_message"], "[withheld]");
    assert!(named(&recorded, "agent.events.dropped").is_empty());
    assert!(!row(&stand.harness, &db).await.audit_incomplete);
}

#[tokio::test]
async fn a_batch_holds_at_most_two_hundred_fifty_six_events_and_reports_in_a_quarter_mebibyte() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let many = |count: u64, first: u64| {
        (first..first + count)
            .map(|seq| event(&kube, seq, "kube.request", json!({})))
            .collect::<Vec<_>>()
    };
    let full = post(&stand, &stand.node_id, &batch(many(256, 1))).await;
    assert_eq!(counts(&full), (256, 0));

    start_recording();
    let over = post(&stand, &stand.node_id, &batch(many(257, 1000))).await;
    assert_eq!(over.status, StatusCode::BAD_REQUEST);
    assert_eq!(over.error_code(), "invalid_batch");
    let reports: Vec<Value> = (0..257)
        .map(|_| json!({"session_id": kube, "count": 1}))
        .collect();
    let mut too_many_reports = batch(Vec::new());
    too_many_reports["dropped"] = json!(reports);
    let over_reports = post(&stand, &stand.node_id, &too_many_reports).await;
    assert_eq!(over_reports.status, StatusCode::BAD_REQUEST);
    let padding = "x".repeat(256 * 1024);
    let large = batch(vec![event(
        &kube,
        2000,
        "kube.request",
        json!({"pad": padding}),
    )]);
    let too_large = post(&stand, &stand.node_id, &large).await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    let recorded = take_recording();
    assert!(agent_written(&recorded).is_empty());
    let refused = named(&recorded, "agent.events.refused");
    assert_eq!(
        values(&refused, "reason"),
        ["too_many_events", "too_many_reports", "too_large"]
    );
}

#[tokio::test]
async fn refusals_are_written_once_per_node_reason_and_ten_seconds_with_the_rest_counted() {
    let stand = stand().await;
    start_recording();
    for body in [&b"{"[..], b"[]", b"{\"events\":7}"] {
        assert_eq!(
            post_raw(&stand, &stand.node_id, body).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let large = format!(
        "{{\"events\":[],\"dropped\":[],\"pad\":\"{}\"}}",
        "x".repeat(300_000)
    );
    assert_eq!(
        post_raw(&stand, &stand.node_id, large.as_bytes())
            .await
            .status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        post_raw(&stand, &stand.other_node_id, b"{").await.status,
        StatusCode::BAD_REQUEST
    );
    stand.harness.clock.advance(9);
    post_raw(&stand, &stand.node_id, b"{").await;
    stand.harness.clock.advance(1);
    post_raw(&stand, &stand.node_id, b"{").await;
    let recorded = take_recording();

    let refused = named(&recorded, "agent.events.refused");
    let seen: Vec<(&str, &str, &str)> = refused
        .iter()
        .map(|event| {
            (
                event["node_id"].as_str(),
                event["reason"].as_str(),
                event["suppressed"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (stand.node_id.as_str(), "malformed", "0"),
            (stand.other_node_id.as_str(), "malformed", "0"),
            (stand.node_id.as_str(), "malformed", "4"),
        ]
    );
}

#[tokio::test]
async fn the_request_rate_of_a_node_is_limited_before_the_database_is_read() {
    let stand = stand().await;
    let empty = batch(Vec::new());
    for attempt in 0..50 {
        let reply = post(&stand, "ghost-node", &empty).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{attempt}");
        assert_eq!(reply.error_code(), "node_removed");
    }
    let limited = post(&stand, "ghost-node", &empty).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers[header::RETRY_AFTER], "1");
    assert_eq!(counts(&post(&stand, &stand.node_id, &empty).await), (0, 0));
    stand.harness.clock.advance(1);
    assert_eq!(
        post(&stand, "ghost-node", &empty).await.status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn the_request_rate_is_limited_before_the_body_is_parsed() {
    let stand = stand().await;
    let empty = batch(Vec::new());
    for _ in 0..50 {
        assert_eq!(counts(&post(&stand, &stand.node_id, &empty).await), (0, 0));
    }
    let too_many: Vec<Value> = (0..257)
        .map(|seq| event(UNKNOWN, seq, "kube.request", json!({})))
        .collect();
    start_recording();
    let malformed = post_raw(&stand, &stand.node_id, b"{").await;
    let oversized = post(&stand, &stand.node_id, &batch(too_many)).await;
    let recorded = take_recording();
    assert_eq!(malformed.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(oversized.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(named(&recorded, "agent.events.refused").is_empty());
}

async fn send_many(
    stand: &Stand,
    session: &str,
    seq: &mut u64,
    name: &str,
    count: u64,
) -> (u64, u64) {
    let events: Vec<Value> = (0..count)
        .map(|_| {
            *seq += 1;
            event(session, *seq, name, json!({"verb": "get"}))
        })
        .collect();
    counts(&post(stand, &stand.node_id, &batch(events)).await)
}

#[tokio::test]
async fn ten_thousand_noisy_events_an_hour_pass_and_invalid_or_lifecycle_events_spend_none() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let mut seq = 0;
    for _ in 0..40 {
        let reply = send_many(&stand, &kube, &mut seq, "db.query", 250).await;
        assert_eq!(reply, (0, 250));
    }
    assert_eq!(
        send_many(&stand, &kube, &mut seq, "kube.request", 1).await,
        (1, 0)
    );
    stand.harness.clock.advance(1);
    for index in 0..40_u64 {
        let count = if index == 39 { 249 } else { 250 };
        let reply = send_many(&stand, &kube, &mut seq, "kube.request", count).await;
        assert_eq!(reply, (count, 0));
    }
    stand.harness.clock.advance(1);
    let next = seq;
    start_recording();
    let over = batch(vec![
        event(&kube, next + 1, "kube.request", json!({})),
        event(
            &kube,
            next + 2,
            "kube.exec.start",
            json!({"pod": "web-0", "tty": true}),
        ),
        event(
            &kube,
            next + 3,
            "kube.session.end",
            json!({"requests_read": 10_000}),
        ),
    ]);
    assert_eq!(counts(&post(&stand, &stand.node_id, &over).await), (2, 1));
    let recorded = take_recording();
    assert_eq!(
        agent_written(&recorded),
        ["kube.exec.start", "kube.session.end"]
    );
    assert_eq!(
        values(&named(&recorded, "agent.events.dropped"), "reason"),
        ["budget"]
    );
    stand.harness.clock.advance(3661);
    let rolled = batch(vec![event(&kube, next + 4, "kube.request", json!({}))]);
    assert_eq!(counts(&post(&stand, &stand.node_id, &rolled).await), (1, 0));
}

#[tokio::test]
async fn the_start_and_the_end_of_a_session_are_written_once_and_a_repeat_marks_the_session() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    start_recording();
    let reply = post(
        &stand,
        &stand.node_id,
        &batch(vec![
            event(&tcp, 1, "tcp.session.start", json!({})),
            event(&tcp, 2, "tcp.session.start", json!({})),
            event(&tcp, 3, "tcp.session.end", json!({})),
            event(&tcp, 4, "tcp.session.end", json!({})),
        ]),
    )
    .await;
    let recorded = take_recording();
    assert_eq!(counts(&reply), (2, 2));
    assert_eq!(
        agent_written(&recorded),
        ["tcp.session.start", "tcp.session.end"]
    );
    let dropped = named(&recorded, "agent.events.dropped");
    assert_eq!(
        (dropped[0]["reason"].as_str(), dropped[0]["count"].as_str()),
        ("duplicate", "2")
    );
    assert!(row(&stand.harness, &tcp).await.audit_incomplete);
}

#[tokio::test]
async fn critical_events_of_a_kind_have_an_hourly_budget_per_session() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let errors: Vec<Value> = (1..=21)
        .map(|seq| event(&db, seq, "db.protocol_error", json!({"reason": "frame"})))
        .collect();
    start_recording();
    let reply = post(&stand, &stand.node_id, &batch(errors)).await;
    let recorded = take_recording();
    assert_eq!(counts(&reply), (20, 1));
    assert_eq!(named(&recorded, "db.protocol_error").len(), 20);
    assert_eq!(
        values(&named(&recorded, "agent.events.dropped"), "reason"),
        ["budget"]
    );
    assert!(row(&stand.harness, &db).await.audit_incomplete);
}

async fn raw_sessions(
    stand: &Stand,
    holder: &X509,
    node_id: &str,
    kind: &str,
    tag: u32,
    count: u32,
    ended_at: Option<i64>,
) -> Vec<String> {
    let pool = raw_pool(&stand.harness).await;
    let now = stand.harness.clock.now_secs();
    let service = if kind == "kube" { KUBE } else { TCP };
    let mut ids = Vec::new();
    for index in 0..count {
        let id = format!("{tag:08x}-0000-4000-8000-{index:012x}");
        sqlx::query(
            "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, \
             authorized_at, ended_at, kind, service_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&holder.user_id)
        .bind(holder.serial)
        .bind(node_id)
        .bind(if ended_at.is_some() {
            "ended"
        } else {
            "active"
        })
        .bind(now - 3 * 3600)
        .bind(now + 3600)
        .bind(now - 3 * 3600)
        .bind(ended_at)
        .bind(kind)
        .bind(service)
        .execute(&pool)
        .await
        .unwrap();
        ids.push(id);
    }
    ids
}

fn exec_flood(session: &str, seq: &mut u64, count: usize) -> Value {
    let events = (0..count)
        .map(|_| {
            *seq += 1;
            event(session, *seq, "kube.exec.start", json!({"pod": "p"}))
        })
        .collect();
    batch(events)
}

fn reports_for(sessions: &[String]) -> Value {
    let dropped: Vec<Value> = sessions
        .iter()
        .map(|id| json!({"session_id": id, "count": 1}))
        .collect();
    json!({"events": [], "dropped": dropped})
}

async fn flagged(stand: &Stand) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE audit_incomplete = 1")
        .fetch_one(&raw_pool(&stand.harness).await)
        .await
        .unwrap()
}

async fn swept_marks(stand: &Stand) -> Vec<Captured> {
    start_recording();
    stand
        .harness
        .control
        .sweep_deferred_agent_event_marks()
        .await;
    take_recording()
}

#[tokio::test]
async fn lifecycle_events_of_one_user_do_not_spend_the_starts_of_another_or_of_another_node() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let mut seq = 0;
    let mut accepted = 0;
    start_recording();
    for _ in 0..3 {
        let reply = post(&stand, &stand.node_id, &exec_flood(&kube, &mut seq, 256)).await;
        accepted += counts(&reply).0;
    }
    let recorded = take_recording();
    assert_eq!(accepted, 32);
    let dropped = named(&recorded, "agent.events.dropped");
    assert_eq!(values(&dropped, "reason"), ["node_ceiling"]);
    assert_eq!(named(&recorded, "session.audit_incomplete").len(), 1);

    let bob = person(&stand.harness, "bob", &["ops"]).await;
    let tcp = open(&stand, &bob, ServiceKind::Tcp, TCP).await;
    let start = batch(vec![event(&tcp, 1, "tcp.session.start", json!({}))]);
    assert_eq!(counts(&post(&stand, &stand.node_id, &start).await), (1, 0));
    let other = &stand.other_node_id;
    let elsewhere = raw_sessions(&stand, &bob, other, "tcp", 1, 1, None).await;
    let start = batch(vec![event(
        &elsewhere[0],
        1,
        "tcp.session.start",
        json!({}),
    )]);
    assert_eq!(counts(&post(&stand, other, &start).await), (1, 0));
    let busy = raw_sessions(&stand, &bob, other, "kube", 2, 1, None).await;
    let mut other_seq = 0;
    let reply = post(&stand, other, &exec_flood(&busy[0], &mut other_seq, 256)).await;
    assert_eq!(counts(&reply), (32, 224));

    stand.harness.clock.advance(1);
    let reply = post(&stand, &stand.node_id, &exec_flood(&kube, &mut seq, 256)).await;
    assert_eq!(counts(&reply), (32, 224));
}

#[tokio::test]
async fn repeated_starts_spend_nothing_and_a_full_node_leaves_room_for_the_next_node() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let first = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let mut seq = 0;
    for round in 0..3 {
        let events = (0..200)
            .map(|_| {
                seq += 1;
                event(&first, seq, "tcp.session.start", json!({}))
            })
            .collect();
        let expected = if round == 0 { (1, 199) } else { (0, 200) };
        assert_eq!(
            counts(&post(&stand, &stand.node_id, &batch(events)).await),
            expected
        );
    }
    let starts = |ids: &[String]| {
        batch(
            ids.iter()
                .map(|id| event(id, 1, "tcp.session.start", json!({})))
                .collect(),
        )
    };
    let many = raw_sessions(&stand, &alice, &stand.node_id, "tcp", 2, 200, None).await;
    start_recording();
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &starts(&many)).await),
        (31, 169)
    );
    let reasons = values(&named(&take_recording(), "agent.events.dropped"), "reason").join(",");
    assert_eq!(reasons, "node_ceiling");
    let other = &stand.other_node_id;
    let elsewhere = raw_sessions(&stand, &alice, other, "tcp", 3, 2, None).await;
    assert_eq!(
        counts(&post(&stand, other, &starts(&elsewhere[..1])).await),
        (1, 0)
    );

    stand.harness.clock.advance(1);
    let more = raw_sessions(&stand, &alice, &stand.node_id, "tcp", 4, 200, None).await;
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &starts(&more)).await),
        (32, 168)
    );
    assert_eq!(
        counts(&post(&stand, other, &starts(&elsewhere[1..])).await),
        (1, 0)
    );
}

async fn flooding_nodes(stand: &Stand, names: &[&str]) -> Vec<String> {
    let mut nodes = Vec::new();
    for name in names {
        nodes.push(crate::session_support::node(&stand.harness, name).await);
    }
    nodes
}

async fn flood_exec(stand: &Stand, holder: &X509, node_id: &str, tag: u32) -> (String, u64) {
    let session = raw_sessions(stand, holder, node_id, "kube", tag, 1, None).await;
    let mut seq = 0;
    let mut taken = 0;
    for _ in 0..2 {
        let reply = post(stand, node_id, &exec_flood(&session[0], &mut seq, 256)).await;
        taken += counts(&reply).0;
    }
    (session[0].clone(), taken)
}

#[tokio::test]
async fn agents_together_stop_at_one_ceiling_for_the_whole_control() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let mut nodes = vec![stand.node_id.clone(), stand.other_node_id.clone()];
    nodes.extend(flooding_nodes(&stand, &["svc-03", "svc-04", "svc-05"]).await);
    let mut accepted = Vec::new();
    let mut flooded = Vec::new();
    start_recording();
    for (index, node_id) in nodes.iter().enumerate() {
        let tag = 10 + u32::try_from(index).unwrap();
        let (session, taken) = flood_exec(&stand, &alice, node_id, tag).await;
        accepted.push(taken);
        flooded.push(session);
    }
    let recorded = take_recording();
    let written = named(&recorded, "session.audit_incomplete");
    assert_eq!(accepted[..3], [32, 32, 32]);
    assert_eq!(accepted[4], 0);
    assert_eq!(accepted.iter().sum::<u64>() + written.len() as u64, 128);
    let reasons = values(&named(&recorded, "agent.events.dropped"), "reason");
    assert!(reasons.contains(&"agents_ceiling"), "{reasons:?}");
    assert_eq!(flagged(&stand).await, 5);

    stand.harness.clock.advance(5);
    let caught_up = swept_marks(&stand).await;
    let mut marked = values(&written, "session_id");
    marked.extend(values(
        &named(&caught_up, "session.audit_incomplete"),
        "session_id",
    ));
    marked.sort_unstable();
    flooded.sort_unstable();
    assert_eq!(marked, flooded);
}

#[tokio::test]
async fn two_nodes_flooding_exec_leave_the_starts_and_exec_of_a_third_passing_at_once() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let nodes = flooding_nodes(&stand, &["svc-03", "svc-04"]).await;
    for (index, node_id) in nodes.iter().enumerate() {
        let tag = 40 + u32::try_from(index).unwrap();
        let (_, taken) = flood_exec(&stand, &alice, node_id, tag).await;
        assert_eq!(taken, 32);
    }
    let bob = person(&stand.harness, "bob", &["ops"]).await;
    let tcp = open(&stand, &bob, ServiceKind::Tcp, TCP).await;
    let kube = open(&stand, &bob, ServiceKind::Kubernetes, KUBE).await;
    start_recording();
    let start = batch(vec![event(&tcp, 1, "tcp.session.start", json!({}))]);
    assert_eq!(counts(&post(&stand, &stand.node_id, &start).await), (1, 0));
    let mut seq = 0;
    let reply = post(&stand, &stand.node_id, &exec_flood(&kube, &mut seq, 10)).await;
    assert_eq!(counts(&reply), (10, 0));
    let recorded = take_recording();
    assert_eq!(agent_written(&recorded).len(), 11);
    assert!(named(&recorded, "agent.events.dropped").is_empty());
    assert!(!row(&stand.harness, &tcp).await.audit_incomplete);
    assert!(!row(&stand.harness, &kube).await.audit_incomplete);
}

#[tokio::test]
async fn a_request_sets_at_most_sixty_four_flags_and_the_five_second_sweep_sets_the_rest_and_writes_the_marks()
 {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let control = &stand.harness.control;
    let now = stand.harness.clock.now_secs();
    let recent = raw_sessions(
        &stand,
        &alice,
        &stand.node_id,
        "tcp",
        20,
        400,
        Some(now - 600),
    )
    .await;
    start_recording();
    let reply = post(&stand, &stand.node_id, &reports_for(&recent[..256])).await;
    assert_eq!(counts(&reply), (0, 0));
    assert_eq!(flagged(&stand).await, 64);
    let reply = post(&stand, &stand.node_id, &reports_for(&recent[256..])).await;
    assert_eq!(counts(&reply), (0, 0));
    assert_eq!(flagged(&stand).await, 128);
    assert_eq!(control.agent_event_mark_attempts(), 128);
    let first = take_recording();
    let mut all: Vec<String> = values(&named(&first, "session.audit_incomplete"), "session_id")
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(all.len(), 32);

    let mut expected_marks = vec![32; 11];
    expected_marks.push(16);
    for (pass, expected) in expected_marks.into_iter().enumerate() {
        stand.harness.clock.advance(5);
        let caught_up = swept_marks(&stand).await;
        let marks = named(&caught_up, "session.audit_incomplete");
        assert_eq!(marks.len(), expected, "{pass}");
        all.extend(values(&marks, "session_id").into_iter().map(str::to_owned));
        let flags = match pass {
            0 => 384,
            _ => 400,
        };
        assert_eq!(flagged(&stand).await, flags, "{pass}");
    }
    assert_eq!(control.agent_event_mark_attempts(), 400);
    all.sort_unstable();
    let mut expected = recent.clone();
    expected.sort_unstable();
    assert_eq!(all, expected);
    stand.harness.clock.advance(60);
    start_recording();
    control.sweep_agent_events().await;
    control.sweep_deferred_agent_event_marks().await;
    assert!(named(&take_recording(), "session.audit_incomplete").is_empty());
}

#[tokio::test]
async fn sessions_ended_more_than_the_budget_window_ago_get_the_flag_and_no_event() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let control = &stand.harness.control;
    let now = stand.harness.clock.now_secs();
    let node = &stand.node_id;
    let old = raw_sessions(&stand, &alice, node, "tcp", 30, 5, Some(now - 3661)).await;
    let edge = raw_sessions(&stand, &alice, node, "tcp", 31, 1, Some(now - 3660)).await;
    let mut reported = old.clone();
    reported.extend(edge.iter().cloned());
    start_recording();
    assert_eq!(
        counts(&post(&stand, node, &reports_for(&reported)).await),
        (0, 0)
    );
    stand.harness.clock.advance(60);
    control.sweep_agent_events().await;
    control.sweep_deferred_agent_event_marks().await;
    let recorded = take_recording();
    for id in &reported {
        assert!(row(&stand.harness, id).await.audit_incomplete, "{id}");
    }
    assert_eq!(
        values(&named(&recorded, "session.audit_incomplete"), "session_id"),
        [edge[0].as_str()]
    );
    assert_eq!(
        values(&named(&recorded, "agent.events.dropped"), "reason"),
        ["expired"]
    );
    assert_eq!(control.tracked_agent_event_sessions(), 0);
}

#[tokio::test]
async fn a_deferred_mark_of_a_session_that_ended_more_than_the_budget_window_ago_is_not_written() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let now = stand.harness.clock.now_secs();
    let node = &stand.node_id;
    let filler = raw_sessions(&stand, &alice, node, "tcp", 49, 32, Some(now - 600)).await;
    assert_eq!(
        counts(&post(&stand, node, &reports_for(&filler)).await),
        (0, 0)
    );
    let young = raw_sessions(&stand, &alice, node, "tcp", 50, 1, Some(now - 3654)).await;
    let old = raw_sessions(&stand, &alice, node, "tcp", 51, 1, Some(now - 3655)).await;
    let mut reported = young.clone();
    reported.extend(old.iter().cloned());
    start_recording();
    assert_eq!(
        counts(&post(&stand, node, &reports_for(&reported)).await),
        (0, 0)
    );
    assert!(named(&take_recording(), "session.audit_incomplete").is_empty());
    assert_eq!(flagged(&stand).await, 34);

    stand.harness.clock.advance(6);
    let caught_up = swept_marks(&stand).await;
    assert_eq!(
        values(&named(&caught_up, "session.audit_incomplete"), "session_id"),
        [young[0].as_str()]
    );
    stand.harness.clock.advance(5);
    assert!(named(&swept_marks(&stand).await, "session.audit_incomplete").is_empty());
}

#[tokio::test]
async fn a_replayed_batch_is_not_cut_again_and_only_sixteen_queries_per_request_are_cut() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let digest = "ab".repeat(32);
    let queries: Vec<Value> = (1..=20)
        .map(|seq| {
            event(
                &db,
                seq,
                "db.query",
                json!({"text": "\t".repeat(6000), "sha256": digest}),
            )
        })
        .collect();
    let body = batch(queries);
    assert!(serde_json::to_vec(&body).unwrap().len() < 256 * 1024);
    let control = &stand.harness.control;
    assert_eq!(counts(&post(&stand, &stand.node_id, &body).await), (16, 4));
    assert_eq!(control.agent_event_fittings(), 16);
    assert_eq!(counts(&post(&stand, &stand.node_id, &body).await), (20, 0));
    assert_eq!(control.agent_event_fittings(), 16);
}

#[tokio::test]
async fn a_resent_batch_over_a_budget_writes_no_new_drop() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let errors: Vec<Value> = (1..=21)
        .map(|seq| event(&db, seq, "db.protocol_error", json!({"reason": "frame"})))
        .collect();
    let body = batch(errors);
    assert_eq!(counts(&post(&stand, &stand.node_id, &body).await), (20, 1));
    stand.harness.clock.advance(10);
    start_recording();
    assert_eq!(counts(&post(&stand, &stand.node_id, &body).await), (21, 0));
    assert!(named(&take_recording(), "agent.events.dropped").is_empty());
}

#[tokio::test]
async fn a_credential_in_a_lifecycle_text_is_withheld_and_counted() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let start = batch(vec![event(
        &db,
        1,
        "db.session.start",
        json!({"application_name": "x bearer y", "db_user": "app"}),
    )]);
    start_recording();
    let reply = post(&stand, &stand.node_id, &start).await;
    let recorded = take_recording();
    assert_eq!(
        reply.json(),
        json!({"accepted": 1, "dropped": 0, "withheld": 1})
    );
    let written = named(&recorded, "db.session.start");
    assert_eq!(written[0]["application_name"], "[withheld]");
    assert_eq!(written[0]["db_user"], "app");
}

#[tokio::test]
async fn a_mark_settled_from_a_stale_session_row_writes_no_second_event() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let control = &stand.harness.control;
    start_recording();
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 1)).await),
        (0, 0)
    );
    assert!(control.settle_agent_event_mark_from_a_stale_row(&db).await);
    let recorded = take_recording();
    assert_eq!(control.agent_event_mark_attempts(), 2);
    assert_eq!(named(&recorded, "session.audit_incomplete").len(), 1);
}

#[tokio::test]
async fn queue_drops_reported_by_the_agent_are_written_and_mark_the_session_once() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    start_recording();
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 0)).await),
        (0, 0)
    );
    assert!(!row(&stand.harness, &db).await.audit_incomplete);
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 7)).await),
        (0, 0)
    );
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 2)).await),
        (0, 0)
    );
    stand.harness.clock.advance(10);
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 3)).await),
        (0, 0)
    );
    let recorded = take_recording();

    let dropped = named(&recorded, "agent.events.dropped");
    let seen: Vec<(&str, &str, &str)> = dropped
        .iter()
        .map(|event| {
            (
                event["reason"].as_str(),
                event["count"].as_str(),
                event["suppressed"].as_str(),
            )
        })
        .collect();
    assert_eq!(seen, [("agent_queue", "7", "0"), ("agent_queue", "3", "1")]);
    let incomplete = named(&recorded, "session.audit_incomplete");
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0]["dropped_total"], "7");
    assert_eq!(incomplete[0]["user_id"], alice.user_id);
    assert!(row(&stand.harness, &db).await.audit_incomplete);
}

#[tokio::test]
async fn a_session_already_marked_in_its_row_is_not_updated_again() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let control = &stand.harness.control;
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&db, 1)).await),
        (0, 0)
    );
    assert_eq!(control.agent_event_mark_attempts(), 1);
    for count in [1, 5, 9] {
        assert_eq!(
            counts(&post(&stand, &stand.node_id, &report(&db, count)).await),
            (0, 0)
        );
    }
    let invalid = batch(vec![event(&db, 1, "kube.request", json!({}))]);
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &invalid).await),
        (0, 1)
    );
    control.sweep_agent_events().await;
    assert_eq!(control.agent_event_mark_attempts(), 1);
}

#[tokio::test]
async fn a_failed_mark_answers_500_and_a_retry_or_the_sweep_marks_the_session_once() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let retried = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let swept = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    execute(&stand, NO_MARKS).await;
    start_recording();
    for session in [&retried, &swept] {
        let reply = post(&stand, &stand.node_id, &report(session, 2)).await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!row(&stand.harness, session).await.audit_incomplete);
    }
    execute(&stand, "DROP TRIGGER no_marks").await;
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &report(&retried, 2)).await),
        (0, 0)
    );
    stand.harness.control.sweep_agent_events().await;
    let recorded = take_recording();

    for session in [&retried, &swept] {
        assert!(row(&stand.harness, session).await.audit_incomplete);
    }
    let incomplete = named(&recorded, "session.audit_incomplete");
    let mut marked = values(&incomplete, "session_id");
    marked.sort_unstable();
    let mut expected = vec![retried.as_str(), swept.as_str()];
    expected.sort_unstable();
    assert_eq!(marked, expected);
    assert_eq!(
        incomplete
            .iter()
            .find(|event| event["session_id"] == retried)
            .unwrap()["dropped_total"],
        "4"
    );
}

fn start_and_drop(db: &str) -> Value {
    let mut body = batch(vec![event(
        db,
        1,
        "db.session.start",
        json!({"db_user": "app"}),
    )]);
    body["dropped"] = json!([{"session_id": db, "count": 2}]);
    body
}

async fn written_once_after_a_resend(stand: &Stand, db: &str, body: &Value) {
    until_marked(stand, db).await;
    let again = post(stand, &stand.node_id, body).await;
    assert_eq!(counts(&again), (1, 0));
    let recorded = take_recording();

    assert_eq!(agent_written(&recorded), ["db.session.start"]);
    assert_eq!(named(&recorded, "session.audit_incomplete").len(), 1);
    assert_eq!(stand.harness.control.agent_event_mark_attempts(), 1);
}

#[tokio::test]
async fn a_request_dropped_after_its_first_poll_still_writes_its_events_and_mark_once() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let body = start_and_drop(&db);
    start_recording();
    let mut call = Box::pin(stand.harness.agent_router.clone().oneshot(request(
        AGENT_EVENTS_PATH,
        &body,
        None,
        Some(&stand.node_id),
    )));
    let first = tokio::time::timeout(Duration::ZERO, &mut call).await;
    drop(first);
    drop(call);
    written_once_after_a_resend(&stand, &db, &body).await;
}

#[tokio::test]
async fn the_work_of_a_request_whose_caller_is_gone_runs_to_its_end_once() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let body = start_and_drop(&db);
    start_recording();
    let held = stand.harness.control.hold_agent_event_recording().await;
    let mut call = Box::pin(stand.harness.agent_router.clone().oneshot(request(
        AGENT_EVENTS_PATH,
        &body,
        None,
        Some(&stand.node_id),
    )));
    if let Ok(answered) = tokio::time::timeout(Duration::ZERO, &mut call).await {
        panic!(
            "the request was answered while its work was held: {:?}",
            answered.map(|reply| reply.status())
        );
    }
    drop(call);
    assert!(!row(&stand.harness, &db).await.audit_incomplete);
    assert_eq!(stand.harness.control.agent_event_mark_attempts(), 0);
    drop(held);
    written_once_after_a_resend(&stand, &db, &body).await;
}

#[tokio::test]
async fn a_repeated_batch_is_not_written_twice_and_the_marks_of_an_ended_session_are_forgotten() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let first = batch(vec![
        event(&tcp, 1, "tcp.session.start", json!({})),
        event(&tcp, 2, "db.query", json!({})),
    ]);
    start_recording();
    assert_eq!(counts(&post(&stand, &stand.node_id, &first).await), (1, 1));
    assert_eq!(counts(&post(&stand, &stand.node_id, &first).await), (2, 0));
    let overlapping = batch(vec![
        event(&tcp, 2, "tcp.session.end", json!({})),
        event(&tcp, 3, "tcp.session.end", json!({})),
    ]);
    assert_eq!(
        counts(&post(&stand, &stand.node_id, &overlapping).await),
        (2, 0)
    );
    let recorded = take_recording();
    assert_eq!(
        agent_written(&recorded),
        ["tcp.session.start", "tcp.session.end"]
    );
    assert_eq!(named(&recorded, "agent.events.dropped").len(), 1);
    assert_eq!(harness.control.tracked_agent_event_sessions(), 1);

    end_service(harness, &stand.node_id, &tcp, ServiceOutcome::Closed, 1).await;
    harness.control.sweep_agent_events().await;
    assert_eq!(harness.control.tracked_agent_event_sessions(), 1);
    harness.clock.advance(300);
    harness.control.sweep_agent_events().await;
    assert_eq!(harness.control.tracked_agent_event_sessions(), 1);
    harness.clock.advance(61);
    harness.control.sweep_agent_events().await;
    assert_eq!(harness.control.tracked_agent_event_sessions(), 0);
    let late = post(&stand, &stand.node_id, &first).await;
    assert_eq!(counts(&late), (0, 2));
}
