use axum::http::StatusCode;
use jaunt_audit::{AuditEvent, EventType, RawValue, Timestamp};
use jaunt_store::AuditRecord;

use crate::support::Harness;
use crate::web_support::{APPROVER_AND_OPS_ROLES, bob, carol};

const AUDIT: &str = "/v1/admin/audit";

fn seeded(index: i64, kind: EventType, user: &str) -> AuditRecord {
    let raw = [
        ("user_id", RawValue::Text(user.to_owned())),
        ("login_id", RawValue::Text(format!("login-{index}"))),
        ("serial", RawValue::Signed(index)),
        ("node_id", RawValue::Text(format!("node-{}", index % 2))),
        ("session_id", RawValue::Text(format!("sess-{index}"))),
    ];
    let time = Timestamp::from_millis(1_700_000_000_000 + index * 1000).unwrap();
    AuditEvent::from_raw(kind, &raw, format!("seed-{index:03}"), time)
        .0
        .to_record()
}

fn foreign(id: &str, time_ms: i64) -> AuditRecord {
    AuditRecord {
        id: id.to_owned(),
        time_ms,
        event_type: "future.type".to_owned(),
        actor: "anonymous".to_owned(),
        node: None,
        session_id: None,
        policy_hash: None,
        payload: "{}".to_owned(),
        v: 1,
    }
}

async fn seed(harness: &Harness) {
    let mut records: Vec<AuditRecord> = (0..5)
        .map(|index| {
            let kind = if index % 2 == 0 {
                EventType::CertIssued
            } else {
                EventType::SessionRouted
            };
            seeded(index, kind, if index < 3 { "u-1" } else { "u-2" })
        })
        .collect();
    records[0].payload = "{\"login_id\":\"login-0\",\"email\":\"leak@example.com\"}".to_owned();
    records.push(foreign("seed-050", 1_700_000_002_500));
    records.push(foreign("seed-099", 1_700_000_100_000));
    harness.store.audit_events().append(&records).await.unwrap();
}

fn ids(body: &serde_json::Value) -> Vec<String> {
    body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|event| event["id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audit_route_needs_a_session_and_the_audit_read_permission() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    seed(&harness).await;
    let allowed = harness.web_sign_in().await;
    let without = harness.web_sign_in_with("", bob()).await;
    let approver_only = harness.web_sign_in_with("", carol()).await;

    let anonymous = harness.web_get(AUDIT, None).await;
    let refused = harness.web_get(AUDIT, Some(&without.cookie())).await;
    let approver = harness.web_get(AUDIT, Some(&approver_only.cookie())).await;
    let granted = harness.web_get(AUDIT, Some(&allowed.cookie())).await;

    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json(), serde_json::json!({ "error": "forbidden" }));
    assert_eq!(approver.status, StatusCode::FORBIDDEN);
    assert!(!approver.text().contains("seed-"));
    assert_eq!(granted.status, StatusCode::OK, "{}", granted.text());
    assert_eq!(granted.header("cache-control"), "no-store");
    let whoami = harness
        .web_get("/v1/web/session", Some(&approver_only.cookie()))
        .await;
    assert_eq!(
        whoami.json()["permissions"],
        serde_json::json!(["nodes.approve", "sessions.read", "recordings.read"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_policy_nobody_can_read_the_audit_log() {
    let harness = Harness::with_web().await;
    seed(&harness).await;
    let signed = harness.web_sign_in().await;

    let reply = harness.web_get(AUDIT, Some(&signed.cookie())).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(!reply.text().contains("seed-"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cursor_visits_every_known_event_once_even_around_rows_of_an_unknown_type() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    seed(&harness).await;
    let cookie = harness.web_sign_in().await.cookie();

    let mut seen: Vec<String> = Vec::new();
    let mut pages = 0;
    let mut path = format!("{AUDIT}?limit=2");
    loop {
        let page = harness.web_get(&path, Some(&cookie)).await.json();
        pages += 1;
        seen.extend(ids(&page));
        match page["next_cursor"].as_str() {
            Some(cursor) => path = format!("{AUDIT}?limit=2&cursor={cursor}"),
            None => break,
        }
        assert!(pages < 10, "the cursor never ends");
    }

    assert_eq!(
        seen,
        ["seed-004", "seed-003", "seed-002", "seed-001", "seed-000"]
    );
    assert_eq!(pages, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_last_page_that_is_exactly_full_has_no_cursor_and_one_row_short_has_one() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    seed(&harness).await;
    let cookie = harness.web_sign_in().await.cookie();

    let exact = harness
        .web_get(&format!("{AUDIT}?limit=7"), Some(&cookie))
        .await
        .json();
    let short = harness
        .web_get(&format!("{AUDIT}?limit=6"), Some(&cookie))
        .await
        .json();

    assert_eq!(ids(&exact).len(), 5);
    assert!(exact["next_cursor"].is_null());
    assert!(short["next_cursor"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn filters_narrow_the_events_by_type_actor_node_session_and_time() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    seed(&harness).await;
    let cookie = harness.web_sign_in().await.cookie();
    let find = |query: String| {
        let harness = &harness;
        let cookie = cookie.clone();
        async move {
            let reply = harness
                .web_get(&format!("{AUDIT}?{query}"), Some(&cookie))
                .await;
            assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
            reply.json()
        }
    };

    let by_type = find("type=cert.".to_owned()).await;
    assert_eq!(ids(&by_type), ["seed-004", "seed-002", "seed-000"]);
    let by_actor = find("actor=u-2".to_owned()).await;
    assert_eq!(ids(&by_actor), ["seed-004", "seed-003"]);
    let by_node = find("node=node-1".to_owned()).await;
    assert_eq!(ids(&by_node), ["seed-003", "seed-001"]);
    let by_session = find("session=sess-3".to_owned()).await;
    assert_eq!(ids(&by_session), ["seed-003"]);
    let nothing = find("session=sess-3&node=node-0".to_owned()).await;
    assert!(ids(&nothing).is_empty());
    let window = find("from=2023-11-14T22:13:21Z&to=2023-11-14T22:13:23.000Z".to_owned()).await;
    assert_eq!(ids(&window), ["seed-002", "seed-001"]);
    let event = &window["events"][0];
    assert_eq!(event["v"], 1);
    assert_eq!(event["type"], "cert.issued");
    assert_eq!(event["time"], "2023-11-14T22:13:22.000Z");
    assert_eq!(event["actor"], "u-1");
    assert_eq!(event["fields"]["serial"], 2);
    assert_eq!(by_node["events"][0]["node"], "node-1");
    assert_eq!(by_session["events"][0]["session_id"], "sess-3");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_filters_are_a_400_with_a_typed_code_and_foreign_payload_fields_never_leave() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    seed(&harness).await;
    let cookie = harness.web_sign_in().await.cookie();

    for (query, code) in [
        ("limit=201", "invalid_limit"),
        ("limit=0", "invalid_limit"),
        ("type=Cert.", "invalid_type"),
        ("from=yesterday", "invalid_time"),
        ("cursor=garbage", "invalid_cursor"),
        ("order=asc", "unknown_parameter"),
        ("limit=1&limit=2", "duplicate_parameter"),
    ] {
        let reply = harness
            .web_get(&format!("{AUDIT}?{query}"), Some(&cookie))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(
            reply.json(),
            serde_json::json!({ "error": code }),
            "{query}"
        );
    }

    let everything = harness
        .web_get(&format!("{AUDIT}?limit=200"), Some(&cookie))
        .await;
    assert_eq!(everything.status, StatusCode::OK);
    assert!(!everything.text().contains("leak@example.com"));
    assert!(!everything.text().contains("email"));
}
