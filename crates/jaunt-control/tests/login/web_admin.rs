use axum::http::StatusCode;

use crate::provider::Identity;
use crate::support::Harness;
use crate::web_support::{APPROVER_AND_OPS_ROLES, READERS_ONLY_ROLES, SESSION_TTL_SECS, bob};

const WHOAMI: &str = "/v1/admin/whoami";

#[tokio::test(flavor = "multi_thread")]
async fn a_role_with_the_permission_reaches_the_admin_route() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let signed = harness.web_sign_in().await;

    let reply = harness.web_get(WHOAMI, Some(&signed.cookie())).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["groups"], serde_json::json!(["dev", "ops"]));
    assert!(body.get("csrf_token").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_in_user_without_the_permission_gets_a_generic_403() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let signed = harness.web_sign_in_with("", bob()).await;

    let reply = harness.web_get(WHOAMI, Some(&signed.cookie())).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json(), serde_json::json!({ "error": "forbidden" }));
    let session = harness
        .web_get("/v1/web/session", Some(&signed.cookie()))
        .await;
    assert_eq!(
        session.json()["permissions"],
        serde_json::json!(["recordings.read"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn permissions_follow_the_policy_of_the_moment_for_the_same_cookie() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let signed = harness.web_sign_in().await;
    assert_eq!(
        harness.web_get(WHOAMI, Some(&signed.cookie())).await.status,
        StatusCode::OK
    );

    harness.load_policy(READERS_ONLY_ROLES);

    let denied = harness.web_get(WHOAMI, Some(&signed.cookie())).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let session = harness
        .web_get("/v1/web/session", Some(&signed.cookie()))
        .await;
    assert_eq!(session.status, StatusCode::OK);
    assert_eq!(
        session.json()["permissions"],
        serde_json::json!(["recordings.read"])
    );

    harness.load_policy(APPROVER_AND_OPS_ROLES);
    assert_eq!(
        harness.web_get(WHOAMI, Some(&signed.cookie())).await.status,
        StatusCode::OK
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_any_policy_nobody_is_an_administrator() {
    let harness = Harness::with_web().await;
    let signed = harness.web_sign_in().await;

    let reply = harness.web_get(WHOAMI, Some(&signed.cookie())).await;

    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let session = harness
        .web_get("/v1/web/session", Some(&signed.cookie()))
        .await;
    assert_eq!(session.json()["permissions"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn no_cookie_a_dead_session_and_a_logged_out_session_are_unauthorised() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let expiring = harness.web_sign_in().await;
    let logged_out = harness.web_sign_in().await;
    assert_eq!(
        harness
            .web_post_with_csrf("/v1/web/logout", &logged_out)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    harness.clock.advance(SESSION_TTL_SECS);

    let none = harness.web_get(WHOAMI, None).await;
    let expired = harness.web_get(WHOAMI, Some(&expiring.cookie())).await;
    let ended = harness.web_get(WHOAMI, Some(&logged_out.cookie())).await;

    for reply in [none, expired, ended] {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json(), serde_json::json!({ "error": "unauthorized" }));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_keeps_the_identity_it_was_created_with() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let alice = harness.web_sign_in_with("", Identity::alice()).await;
    let other = harness.web_sign_in_with("", bob()).await;

    let first = harness.web_get(WHOAMI, Some(&alice.cookie())).await;
    let second = harness.web_get(WHOAMI, Some(&other.cookie())).await;

    assert_eq!(first.json()["email"], "alice@example.com");
    assert_eq!(second.status, StatusCode::FORBIDDEN);
}
