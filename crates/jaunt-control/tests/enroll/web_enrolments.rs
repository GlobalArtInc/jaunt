use axum::http::StatusCode;
use serde_json::json;

use crate::audit::{Captured, start_recording, take_recording};
use crate::support::{APPROVER, Harness, new_agent};
use crate::web_support::{Admin, admin, approve_with, looked_up, lookup, reject_with, web_harness};

fn events_named<'a>(events: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some(name))
        .collect()
}

async fn approver(harness: &Harness) -> Admin {
    admin(harness, "approver").await
}

#[tokio::test]
async fn a_code_lookup_previews_the_request_and_its_intent_approves_it_for_the_agent() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;
    start_recording();

    let typed = enrolled.code.to_lowercase().replace('-', " ");
    let reply = lookup(&harness, &alice, &typed).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let preview = reply.json();
    let enrolment = &preview["enrolment"];
    assert_eq!(enrolment["name"], "web-01");
    assert_eq!(enrolment["labels"], json!({"env": "prod"}));
    assert_eq!(enrolment["hostname"], "web-01.internal.example.com");
    assert_eq!(enrolment["agent_version"], "0.1.0");
    assert_eq!(enrolment["peer_addr"], "203.0.113.10");
    assert_eq!(enrolment["replace_existing"], false);
    assert!(enrolment["expires_at"].as_i64().unwrap() > harness.clock.now_secs());
    assert_eq!(reply.headers["cache-control"], "no-store");
    let pending = harness.poll(&enrolled.handle).await;
    assert_eq!(pending.state(), "pending");

    let looked = crate::web_support::Looked {
        enrolment_id: enrolment["id"].as_str().unwrap().to_owned(),
        intent: preview["intent"].as_str().unwrap().to_owned(),
    };
    let approved = approve_with(&harness, &alice, &looked, Some(json!({"env": "staging"}))).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());
    let body = approved.json();
    assert_eq!(body["node"]["name"], "web-01");
    assert_eq!(body["labels"], json!({"env": "staging"}));
    assert_eq!(body["replaced"], serde_json::Value::Null);

    let delivered = harness.poll(&enrolled.handle).await;
    assert_eq!(delivered.state(), "approved", "{}", delivered.text());
    assert_eq!(delivered.json()["node_id"], body["node"]["id"]);
    let reused = approve_with(&harness, &alice, &looked, None).await;
    assert_eq!(
        (reused.status, reused.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_intent")
    );
    let again = lookup(&harness, &alice, &enrolled.code).await;
    assert_eq!(
        (again.status, again.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "no_pending_enrolment")
    );

    let events = take_recording();
    let found = events_named(&events, "admin.enrolment.looked_up");
    assert_eq!(found[0]["outcome"], "found");
    assert_eq!(found[0]["looked_up_by"], alice.actor());
    assert_eq!(found[0]["enrollment_id"], looked.enrolment_id);
    assert_eq!(found[1]["outcome"], "failed");
    let approvals = events_named(&events, "node.enroll.approved");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["approved_by"], alice.actor());
}

#[tokio::test]
async fn wrong_expired_rejected_and_used_codes_get_the_same_generic_refusal() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;
    let rejected = harness.enroll("web-02").await;
    let used = harness.enroll("web-03").await;
    harness
        .admin
        .reject(&rejected.code, APPROVER)
        .await
        .unwrap();
    harness.approve(&used).await;

    let wrong = lookup(&harness, &alice, "ZZZZ-ZZZZ").await;
    let malformed = lookup(&harness, &alice, "not a code at all").await;
    let was_rejected = lookup(&harness, &alice, &rejected.code).await;
    let was_used = lookup(&harness, &alice, &used.code).await;
    harness.clock.advance(3600);
    let expired = lookup(&harness, &alice, &enrolled.code).await;

    for reply in [wrong, malformed, was_rejected, was_used, expired] {
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(reply.json(), json!({"error": "no_pending_enrolment"}));
    }
}

#[tokio::test]
async fn an_intent_is_refused_from_another_session_for_another_enrolment_and_after_five_minutes() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let second_tab = admin(&harness, "approver").await;
    let first = harness.enroll("web-01").await;
    let second = harness.enroll("web-02").await;

    let looked = looked_up(&harness, &alice, &first).await;
    let other = looked_up(&harness, &alice, &second).await;
    let foreign = approve_with(&harness, &second_tab, &looked, None).await;
    let crossed = approve_with(
        &harness,
        &alice,
        &crate::web_support::Looked {
            enrolment_id: other.enrolment_id.clone(),
            intent: looked.intent.clone(),
        },
        None,
    )
    .await;
    let late = looked_up(&harness, &alice, &second).await;
    harness.clock.advance(300);
    let expired = approve_with(&harness, &alice, &late, None).await;

    for reply in [foreign, crossed, expired] {
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, "invalid_intent")
        );
    }
    assert_eq!(harness.poll(&first.handle).await.state(), "pending");
    assert_eq!(harness.poll(&second.handle).await.state(), "pending");
}

#[tokio::test]
async fn a_taken_name_needs_the_replace_request_and_a_second_approval_is_refused() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let (_, delivered) = harness.enrolled_node("web-01").await;
    let old_id = delivered["node_id"].as_str().unwrap().to_owned();

    let winner = harness.enroll("web-05").await;
    let loser = harness.enroll("web-05").await;
    let first_claim = looked_up(&harness, &alice, &winner).await;
    let late_claim = looked_up(&harness, &alice, &loser).await;
    assert_eq!(
        approve_with(&harness, &alice, &first_claim, None)
            .await
            .status,
        StatusCode::OK
    );
    let taken = approve_with(&harness, &alice, &late_claim, None).await;
    assert_eq!(
        (taken.status, taken.error_code().as_str()),
        (StatusCode::CONFLICT, "name_taken")
    );

    let agent = new_agent();
    let mut body = agent.enroll_body("web-01");
    body["replace"] = json!(true);
    let reply = harness.enroll_body(&body).await;
    let replacing = crate::support::Enrolled {
        handle: reply.json()["handle"].as_str().unwrap().to_owned(),
        code: reply.json()["code"].as_str().unwrap().to_owned(),
        agent,
    };
    let second_tab = admin(&harness, "approver").await;
    let first = looked_up(&harness, &alice, &replacing).await;
    let second = looked_up(&harness, &second_tab, &replacing).await;
    let replaced = approve_with(&harness, &alice, &first, None).await;
    assert_eq!(replaced.status, StatusCode::OK, "{}", replaced.text());
    assert_eq!(replaced.json()["replaced"]["id"], old_id.as_str());
    let double = approve_with(&harness, &second_tab, &second, None).await;
    assert_eq!(
        (double.status, double.error_code().as_str()),
        (StatusCode::CONFLICT, "already_approved")
    );
}

#[tokio::test]
async fn bad_labels_leave_the_intent_usable() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;
    let looked = looked_up(&harness, &alice, &enrolled).await;

    let bad = approve_with(&harness, &alice, &looked, Some(json!({"Env": "prod"}))).await;
    assert_eq!(
        (bad.status, bad.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_labels")
    );
    let good = approve_with(&harness, &alice, &looked, None).await;
    assert_eq!(good.status, StatusCode::OK, "{}", good.text());
}

#[tokio::test]
async fn the_sixth_failed_lookup_in_a_minute_is_refused_for_that_session_only() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let other_session = admin(&harness, "approver").await;
    let enrolled = harness.enroll("web-01").await;
    start_recording();

    for _ in 0..5 {
        let reply = lookup(&harness, &alice, "ZZZZ-ZZZZ").await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    harness.clock.advance(10);
    let limited = lookup(&harness, &alice, &enrolled.code).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers["retry-after"], "50");
    assert_eq!(
        limited.json(),
        json!({"error": "too_many_requests", "retry_after": 50})
    );
    let elsewhere = lookup(&harness, &other_session, &enrolled.code).await;
    assert_eq!(elsewhere.status, StatusCode::OK, "{}", elsewhere.text());
    harness.clock.advance(50);
    let later = lookup(&harness, &alice, &enrolled.code).await;
    assert_eq!(later.status, StatusCode::OK, "{}", later.text());

    let events = take_recording();
    let outcomes: Vec<&str> = events_named(&events, "admin.enrolment.looked_up")
        .iter()
        .map(|event| event["outcome"].as_str())
        .collect();
    assert_eq!(
        outcomes,
        [
            "failed", "failed", "failed", "failed", "failed", "limited", "found", "found"
        ]
    );
    for event in events_named(&events, "admin.enrolment.looked_up") {
        assert!(!event.values().any(|value| value.contains("ZZZZ")));
    }
}

#[tokio::test]
async fn a_rejection_closes_the_request_and_the_agent_learns_it() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;
    let looked = looked_up(&harness, &alice, &enrolled).await;
    start_recording();

    let rejected = reject_with(&harness, &alice, &looked).await;
    assert_eq!(rejected.status, StatusCode::OK, "{}", rejected.text());
    assert_eq!(
        rejected.json(),
        json!({"enrolment_id": looked.enrolment_id, "name": "web-01"})
    );
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "rejected");
    let events = take_recording();
    let rejections = events_named(&events, "node.enroll.rejected");
    assert_eq!(rejections.len(), 1);
    assert_eq!(rejections[0]["rejected_by"], alice.actor());
    let again = lookup(&harness, &alice, &enrolled.code).await;
    assert_eq!(
        (again.status, again.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "no_pending_enrolment")
    );
}

fn without_actor(event: &Captured, actor_field: &str) -> Captured {
    let mut kept = event.clone();
    kept.remove(actor_field);
    for volatile in ["enrollment_id", "node_id"] {
        kept.remove(volatile);
    }
    kept
}

#[tokio::test]
async fn the_cli_and_the_api_approve_and_reject_with_the_same_result_and_event() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let by_cli = harness.enroll("web-01").await;
    let by_api = harness.enroll("web-02").await;
    let reject_cli = harness.enroll("web-03").await;
    let reject_api = harness.enroll("web-04").await;
    start_recording();

    let cli = harness
        .admin
        .approve(&by_cli.code, APPROVER, None)
        .await
        .unwrap();
    let looked = looked_up(&harness, &alice, &by_api).await;
    let api = approve_with(&harness, &alice, &looked, None).await.json();
    harness
        .admin
        .reject(&reject_cli.code, APPROVER)
        .await
        .unwrap();
    let looked = looked_up(&harness, &alice, &reject_api).await;
    reject_with(&harness, &alice, &looked).await;

    let api_id = api["node"]["id"].as_str().unwrap();
    let stored_cli = harness
        .store
        .nodes()
        .get(&cli.node.id)
        .await
        .unwrap()
        .unwrap();
    let stored_api = harness.store.nodes().get(api_id).await.unwrap().unwrap();
    assert_eq!(stored_cli.labels, stored_api.labels);
    assert_eq!(stored_cli.state, stored_api.state);
    assert_eq!(stored_cli.approved_by, APPROVER);
    assert_eq!(stored_api.approved_by, alice.actor());
    for handle in [&by_cli.handle, &by_api.handle] {
        assert_eq!(harness.poll(handle).await.state(), "approved");
    }
    for handle in [&reject_cli.handle, &reject_api.handle] {
        assert_eq!(harness.poll(handle).await.state(), "rejected");
    }

    let events = take_recording();
    for (name, actor_field) in [
        ("node.enroll.approved", "approved_by"),
        ("node.enroll.rejected", "rejected_by"),
    ] {
        let pair = events_named(&events, name);
        assert_eq!(pair.len(), 2, "{name}");
        assert_eq!(pair[0][actor_field], APPROVER);
        assert_eq!(pair[1][actor_field], alice.actor());
        let mut cli_view = without_actor(pair[0], actor_field);
        let mut api_view = without_actor(pair[1], actor_field);
        cli_view.remove("name");
        api_view.remove("name");
        assert_eq!(cli_view, api_view, "{name}");
    }
}

#[tokio::test]
async fn a_successful_lookup_does_not_wipe_the_failures_before_it() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;

    for _ in 0..4 {
        assert_eq!(
            lookup(&harness, &alice, "ZZZZ-ZZZZ").await.status,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    assert_eq!(
        lookup(&harness, &alice, &enrolled.code).await.status,
        StatusCode::OK
    );
    assert_eq!(
        lookup(&harness, &alice, "ZZZZ-ZZZZ").await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        lookup(&harness, &alice, &enrolled.code).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_second_lookup_of_the_same_request_replaces_the_first_intent() {
    let harness = web_harness(&[]).await;
    let alice = approver(&harness).await;
    let enrolled = harness.enroll("web-01").await;
    let old = looked_up(&harness, &alice, &enrolled).await;
    let new = looked_up(&harness, &alice, &enrolled).await;

    let stale = approve_with(&harness, &alice, &old, None).await;
    assert_eq!(
        (stale.status, stale.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_intent")
    );
    assert_eq!(
        approve_with(&harness, &alice, &new, None).await.status,
        StatusCode::OK
    );
}
