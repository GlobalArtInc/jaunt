use axum::http::{Method, StatusCode};
use serde_json::json;

use crate::audit::{Captured, start_recording, take_recording};
use crate::session_support::user;
use crate::web_support::{plant_token, web_harness, with_token};

const REVOKERS: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: revokers }\nspec:\n  \
     members: { users: [approver@example.com] }\n  admin: [revocations.write]\n";
const FIRST_ACTOR: &str = "token:firstAAAAAA";

fn events_named<'a>(events: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some(name))
        .collect()
}

#[tokio::test]
async fn an_intent_looked_up_by_one_token_is_refused_to_another_and_writes_name_the_token() {
    let harness = web_harness(&[REVOKERS.to_owned()]).await;
    let approver = user(&harness, "approver", &[]).await;
    let first = plant_token(
        &harness,
        &approver,
        "firstAAAAAA",
        &["nodes.approve", "revocations.write"],
    )
    .await;
    let second = plant_token(&harness, &approver, "secondAAAAA", &["nodes.approve"]).await;
    let bystander = user(&harness, "bystander", &[]).await;
    let enrolled = harness.enroll("web-01").await;
    start_recording();

    let looked = with_token(
        &harness,
        Method::POST,
        "/v1/admin/enrolments/lookup",
        &first,
        Some(&json!({ "code": enrolled.code })),
    )
    .await;
    assert_eq!(looked.status, StatusCode::OK, "{}", looked.text());
    let intent = json!({ "intent": looked.json()["intent"] });
    let path = format!(
        "/v1/admin/enrolments/{}/approve",
        looked.json()["enrolment"]["id"].as_str().unwrap()
    );
    let crossed = with_token(&harness, Method::POST, &path, &second, Some(&intent)).await;
    let approved = with_token(&harness, Method::POST, &path, &first, Some(&intent)).await;
    let revoked = with_token(
        &harness,
        Method::POST,
        "/v1/admin/revocations",
        &first,
        Some(&json!({ "kind": "user", "subject": bystander, "reason": "left" })),
    )
    .await;
    let events = take_recording();

    assert_eq!(
        (crossed.status, crossed.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_intent")
    );
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());
    assert_eq!(revoked.status, StatusCode::CREATED, "{}", revoked.text());
    assert_eq!(
        events_named(&events, "admin.enrolment.looked_up")[0]["looked_up_by"],
        FIRST_ACTOR
    );
    let approvals = events_named(&events, "node.enroll.approved");
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0]["approved_by"], FIRST_ACTOR);
    assert_eq!(
        events_named(&events, "revoke.created")[0]["created_by"],
        FIRST_ACTOR
    );
}
