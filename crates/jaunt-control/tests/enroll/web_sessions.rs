use axum::http::StatusCode;
use jaunt_store::{AuditRecord, StoredRecording};
use serde_json::{Value, json};

use crate::session_support::{
    CLIENT, LOGIN, NODE_NAME, authorize, end, end_request, holder, node, role, routed,
};
use crate::support::Harness;
use crate::web_support::{Admin, admin, get, web_harness};

fn ids(body: &Value) -> Vec<String> {
    body["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|session| session["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn sessions(harness: &Harness, reader: &Admin, query: &str) -> Value {
    let reply = get(harness, &format!("/v1/admin/sessions{query}"), reader).await;
    assert_eq!(reply.status, StatusCode::OK, "{query}: {}", reply.text());
    reply.json()
}

#[tokio::test]
async fn sessions_are_listed_newest_first_with_filters_and_pages_that_survive_new_sessions() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let dave = holder(&harness, "dave", &["ops"]).await;
    let t0 = harness.clock.now_secs();
    let first = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&first, LOGIN)).await;
    harness.clock.advance(1);
    let second = routed(&harness, &dave).await;
    harness.clock.advance(1);
    let third = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&third, LOGIN)).await;
    end(&harness, &node_id, end_request(&third, 7)).await;

    let all = sessions(&harness, &reader, "").await;
    assert_eq!(ids(&all), [third.clone(), second.clone(), first.clone()]);
    let newest = &all["sessions"][0];
    assert_eq!(newest["user_email"], "bob@example.com");
    assert_eq!(newest["node_name"], NODE_NAME);
    assert_eq!(newest["login"], LOGIN);
    assert_eq!(newest["state"], "ended");
    assert_eq!(newest["end_reason"], "closed");
    assert_eq!(newest["bytes_out"], 7);
    assert_eq!(newest["recording"], "none");

    let page = sessions(&harness, &reader, "?limit=2").await;
    assert_eq!(ids(&page), [third.clone(), second.clone()]);
    harness.clock.advance(1);
    let fourth = routed(&harness, &dave).await;
    let next = page["next"].as_str().unwrap();
    let rest = sessions(&harness, &reader, &format!("?limit=2&cursor={next}")).await;
    assert_eq!(ids(&rest), [first.as_str()]);
    assert_eq!(rest["next"], Value::Null);

    for (query, expected) in [
        ("?state=active".to_owned(), vec![first.clone()]),
        (
            "?user=dave%40example.com&state=routed".to_owned(),
            vec![fourth.clone(), second.clone()],
        ),
        (
            format!("?node={NODE_NAME}&login={LOGIN}"),
            vec![third.clone(), first.clone()],
        ),
        (
            format!("?user=bob%40example.com&from={}", t0 + 1),
            vec![third.clone()],
        ),
        (
            format!("?node={node_id}&to={}", t0 + 1),
            vec![first.clone()],
        ),
    ] {
        assert_eq!(
            ids(&sessions(&harness, &reader, &query).await),
            expected,
            "{query}"
        );
    }
    for (query, status) in [
        ("?state=live", StatusCode::UNPROCESSABLE_ENTITY),
        ("?from=9&to=1", StatusCode::UNPROCESSABLE_ENTITY),
        ("?limit=0", StatusCode::UNPROCESSABLE_ENTITY),
        ("?from=yesterday", StatusCode::BAD_REQUEST),
        ("?recording=complete", StatusCode::BAD_REQUEST),
    ] {
        let reply = get(&harness, &format!("/v1/admin/sessions{query}"), &reader).await;
        assert_eq!(reply.status, status, "{query}");
    }
}

#[tokio::test]
async fn a_session_detail_has_times_bytes_outcome_and_the_client_address_from_the_audit() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;
    end(&harness, &node_id, end_request(&session_id, 20)).await;
    let path = format!("/v1/admin/sessions/{session_id}");

    let without = get(&harness, &path, &reader).await;
    assert_eq!(without.status, StatusCode::OK, "{}", without.text());
    let body = without.json();
    assert_eq!(body["client_addr"], Value::Null);
    assert_eq!(body["serial"], json!(bob.serial));
    assert_eq!(body["state"], "ended");
    assert_eq!(body["end_reason"], "closed");
    assert_eq!(body["exit_status"], 0);
    assert_eq!(
        (body["bytes_in"].clone(), body["bytes_out"].clone()),
        (json!(42), json!(20))
    );
    assert!(body["authorized_at"].is_i64() && body["ended_at"].is_i64());
    assert_eq!(body["recording"], "none");

    harness
        .store
        .audit_events()
        .append(&[AuditRecord {
            id: "audit-1".to_owned(),
            time_ms: harness.clock.now_secs() * 1000,
            event_type: "session.routed".to_owned(),
            actor: bob.user_id.clone(),
            node: Some(node_id.clone()),
            session_id: Some(session_id.clone()),
            policy_hash: None,
            payload: json!({"serial": 1, "node_name": NODE_NAME, "client_addr": CLIENT})
                .to_string(),
            v: 1,
        }])
        .await
        .unwrap();
    let with = get(&harness, &path, &reader).await.json();
    assert_eq!(with["client_addr"], CLIENT);

    for missing in [
        "/v1/admin/sessions/no-such-session",
        "/v1/admin/sessions/a.b",
    ] {
        assert_eq!(
            get(&harness, missing, &reader).await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn sessions_started_in_the_same_second_are_walked_once_each_across_page_boundaries() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let reader = admin(&harness, "reader").await;
    node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let mut started = Vec::new();
    for _ in 0..3 {
        started.push(routed(&harness, &bob).await);
    }
    started.sort();
    started.reverse();

    let mut walked = Vec::new();
    let mut query = "?limit=1".to_owned();
    loop {
        let page = sessions(&harness, &reader, &query).await;
        walked.extend(ids(&page));
        match page["next"].as_str() {
            Some(next) => query = format!("?limit=1&cursor={next}"),
            None => break,
        }
    }
    assert_eq!(walked, started);
}

const RECORDING_READERS: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: auditors }\nspec:\n  \
     members: { users: [auditor@example.com] }\n  admin: [sessions.read, recordings.read]\n";

#[tokio::test]
async fn the_recording_state_is_metadata_shown_alike_with_or_without_recordings_read() {
    let harness = web_harness(&[
        role("ops", "ops", false, false),
        RECORDING_READERS.to_owned(),
    ])
    .await;
    let reader = admin(&harness, "reader").await;
    let auditor = admin(&harness, "auditor").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let mut by_state = Vec::new();
    for state in ["receiving", "complete", "salvaged", "failed"] {
        let session_id = routed(&harness, &bob).await;
        authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;
        let recordings = harness.store.recordings();
        let now = harness.clock.now_secs();
        recordings.begin(&session_id, &node_id, now).await.unwrap();
        let location = format!("2026/11/{session_id}.cast");
        let stored = StoredRecording {
            session_id: &session_id,
            node_id: &node_id,
            chunks: 3,
            raw_bytes: 30,
            digest: Some("digest-of-the-cast"),
            input_recorded: false,
            dropped_chunks: 0,
            location: &location,
            cast_sha256: Some("sha-of-the-cast"),
            manifest_sha256: "sha-of-the-manifest",
            now,
        };
        match state {
            "complete" => assert!(recordings.mark_complete(&stored).await.unwrap()),
            "salvaged" => assert!(recordings.mark_salvaged(&stored).await.unwrap()),
            "failed" => assert!(recordings.mark_failed(&session_id, now).await.unwrap()),
            _ => {}
        }
        by_state.push((session_id, state));
    }

    let as_reader = get(&harness, "/v1/admin/sessions", &reader).await;
    let as_auditor = get(&harness, "/v1/admin/sessions", &auditor).await;
    assert_eq!(as_reader.status, StatusCode::OK, "{}", as_reader.text());
    assert_eq!(as_reader.json(), as_auditor.json());
    let listed = as_reader.json();
    for (session_id, state) in &by_state {
        let expected = match *state {
            "receiving" => "receiving",
            "complete" => "complete",
            "salvaged" => "incomplete",
            _ => "none",
        };
        let entry = listed["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["id"] == session_id.as_str())
            .unwrap();
        assert_eq!(entry["recording"], expected, "{state}");
        let path = format!("/v1/admin/sessions/{session_id}");
        let detail = get(&harness, &path, &reader).await;
        assert_eq!(detail.json()["recording"], expected, "{state}");
        assert_eq!(detail.json(), get(&harness, &path, &auditor).await.json());
        for reply in [&detail, &as_reader] {
            let text = reply.text();
            for content in [
                "2026/11/",
                "digest-of-the-cast",
                "sha-of-the-cast",
                "sha-of-the-manifest",
            ] {
                assert!(!text.contains(content), "{text}");
            }
        }
    }
}
