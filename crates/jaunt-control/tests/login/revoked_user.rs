use axum::http::{Method, StatusCode};
use jaunt_control::RevokeRequest;
use jaunt_store::{NewUser, RevocationKind};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use crate::audit::{start_recording, take_recording};
use crate::provider::Identity;
use crate::support::{DEFAULT_PEER, Harness, PUBLIC_ORIGIN, ed25519_public_key_line};
use crate::web_support::bob;

const REVOCATIONS: &str = "/v1/admin/revocations";

const ROLES: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: revokers }
spec:
  members: { users: [alice@example.com, bob@example.com] }
  admin: [revocations.write, sessions.read]
";

impl Harness {
    async fn alice_id(&self) -> String {
        self.store
            .users()
            .upsert(
                &NewUser {
                    issuer: self.provider.base.clone(),
                    subject: "user-1".to_owned(),
                    email: "alice@example.com".to_owned(),
                    username: "alice".to_owned(),
                    display_name: None,
                    groups: Vec::new(),
                },
                self.clock.now_secs(),
            )
            .await
            .unwrap()
            .id
    }

    async fn revoke_behind_the_store(&self, user_id: &str) -> String {
        let pool =
            SqlitePool::connect_with(SqliteConnectOptions::new().filename(self.database_path()))
                .await
                .unwrap();
        let id = "11111111-2222-4333-8444-555555555555".to_owned();
        sqlx::query(
            "INSERT INTO revocations (id, kind, subject, reason, created_at, created_by) \
             VALUES (?, 'user', ?, 'test', 1, 'cli:test')",
        )
        .bind(&id)
        .bind(user_id)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
        id
    }

    async fn revoke_user(&self, user_id: &str) -> String {
        self.control
            .revocations()
            .revoke(
                &RevokeRequest {
                    kind: RevocationKind::User,
                    subject: user_id.to_owned(),
                    reason: "test".to_owned(),
                },
                "cli:test",
            )
            .await
            .unwrap()
            .revocation
            .id
    }
}

fn reasons(event: &str) -> Vec<String> {
    take_recording()
        .into_iter()
        .filter(|captured| captured.get("event").map(String::as_str) == Some(event))
        .filter_map(|captured| captured.get("reason").cloned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_admin_is_unauthenticated_and_cannot_lift_their_own_revocation() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let alice = harness.web_sign_in().await;
    let alice_id = harness.alice_id().await;
    let cookie = alice.cookie();
    assert_eq!(
        harness.web_get(REVOCATIONS, Some(&cookie)).await.status,
        StatusCode::OK
    );

    let revocation = harness.revoke_behind_the_store(&alice_id).await;
    let item = format!("{REVOCATIONS}/{revocation}");

    assert_eq!(
        harness.web_get(REVOCATIONS, Some(&cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness
            .web_get("/v1/web/session", Some(&cookie))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let lifted = harness
        .web_request(
            Method::DELETE,
            &item,
            Some(&cookie),
            &[("x-jaunt-csrf", "guess"), ("origin", PUBLIC_ORIGIN)],
        )
        .await;
    assert_eq!(lifted.status, StatusCode::UNAUTHORIZED);
    assert!(
        harness
            .store
            .revocations()
            .get(&revocation)
            .await
            .unwrap()
            .is_some()
    );

    let other = harness.web_sign_in_with("", bob()).await;
    let token = harness.csrf_token(&other).await;
    let removed = harness
        .request_as(
            Method::DELETE,
            &item,
            DEFAULT_PEER,
            &[
                ("cookie", &other.cookie()),
                ("x-jaunt-csrf", &token),
                ("origin", PUBLIC_ORIGIN),
            ],
            None,
        )
        .await;
    assert_eq!(removed.status, StatusCode::NO_CONTENT, "{}", removed.text());
    assert_eq!(
        harness.web_get(REVOCATIONS, Some(&cookie)).await.status,
        StatusCode::UNAUTHORIZED
    );
    let fresh = harness.web_sign_in().await.cookie();
    assert_eq!(
        harness.web_get(REVOCATIONS, Some(&fresh)).await.status,
        StatusCode::OK
    );

    harness.revoke_user(&alice_id).await;
    assert_eq!(
        harness.web_get(REVOCATIONS, Some(&fresh)).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness
            .store
            .web_sessions()
            .count_for_user(&alice_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_api_token_of_a_revoked_user_reaches_neither_nodes_nor_whoami() {
    let harness = Harness::new().await;
    let finished = harness.login().await;
    let token = finished["api_token"].as_str().unwrap().to_owned();
    let bearer = format!("Bearer {token}");
    let headers = [("authorization", bearer.as_str())];
    assert_eq!(
        harness.get_with_headers("/v1/nodes", &headers).await.status,
        StatusCode::OK
    );
    let alice_id = finished["user_id"].as_str().unwrap().to_owned();
    start_recording();

    harness.revoke_behind_the_store(&alice_id).await;

    assert_eq!(
        harness.get_with_headers("/v1/nodes", &headers).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness.whoami(&token).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(reasons("authz.deny"), ["revoked", "revoked"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_api_token_dies_with_the_certificate_serial_it_was_issued_with() {
    let harness = Harness::new().await;
    let revoked = harness.login().await;
    let kept = harness.login().await;
    let revoked_serial = revoked["serial"].as_i64().unwrap();
    assert_ne!(kept["serial"].as_i64().unwrap(), revoked_serial);
    let revoked_token = revoked["api_token"].as_str().unwrap().to_owned();
    let kept_token = kept["api_token"].as_str().unwrap().to_owned();
    let revoked_bearer = format!("Bearer {revoked_token}");
    let kept_bearer = format!("Bearer {kept_token}");
    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::Serial,
                subject: revoked_serial.to_string(),
                reason: "test".to_owned(),
            },
            "cli:test",
        )
        .await
        .unwrap();
    start_recording();

    assert_eq!(
        harness
            .get_with_headers("/v1/nodes", &[("authorization", &revoked_bearer)])
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        harness.whoami(&revoked_token).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(reasons("authz.deny"), ["revoked", "revoked"]);
    assert_eq!(
        harness
            .get_with_headers("/v1/nodes", &[("authorization", &kept_bearer)])
            .await
            .status,
        StatusCode::OK
    );
    let whoami = harness.whoami(&kept_token).await;
    assert_eq!(whoami.status, StatusCode::OK);
    assert_eq!(whoami.json()["cert_serial"], kept["serial"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_user_gets_no_certificate_from_a_loopback_login() {
    let harness = Harness::new().await;
    let alice_id = harness.alice_id().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    harness.revoke_user(&alice_id).await;
    start_recording();

    let finished = harness
        .finish(&session, &ed25519_public_key_line("alice@laptop"))
        .await;

    assert_eq!(finished.status, StatusCode::BAD_REQUEST);
    assert_eq!(finished.error_code(), "invalid_grant");
    assert_eq!(reasons("login.finish_failed"), ["revoked"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_user_can_neither_approve_a_device_nor_collect_an_approved_one() {
    let harness = Harness::new().await;
    let alice_id = harness.alice_id().await;
    let key = ed25519_public_key_line("alice@server");
    let refused = harness.device_start().await;
    let refused_page = harness.sign_in(&refused).await;
    let approved = harness.device_start().await;
    let approved_page = harness.sign_in(&approved).await;
    assert_eq!(
        harness
            .approve_device(&approved.login_id, &approved_page.token)
            .await
            .status,
        StatusCode::OK
    );
    harness.revoke_user(&alice_id).await;
    start_recording();

    let page = harness
        .approve_device(&refused.login_id, &refused_page.token)
        .await;

    assert_eq!(page.status, StatusCode::FORBIDDEN);
    assert!(!page.text().contains("revoked"));
    assert_eq!(reasons("login.denied"), ["revoked"]);
    harness.clock.advance(5);
    let denied = harness.poll(&refused, &key).await;
    assert_eq!(denied.error_code(), "access_denied");
    let collected = harness.poll(&approved, &key).await;
    assert_eq!(collected.status, StatusCode::BAD_REQUEST);
    assert_eq!(collected.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_user_gets_no_web_session_from_signing_in() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let alice_id = harness.alice_id().await;
    harness.revoke_user(&alice_id).await;
    start_recording();

    let start = harness.web_start("").await;
    let reply = harness
        .web_callback(&start, Identity::alice(), Some(&start.login_cookie))
        .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(!reply.text().contains("revoked"));
    assert!(
        reply
            .set_cookies()
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-jaunt="))
    );
    let recorded = take_recording();
    let named = |name: &str| {
        recorded
            .iter()
            .filter(|event| event.get("event").map(String::as_str) == Some(name))
            .count()
    };
    assert_eq!(named("web.session.created"), 0);
    assert_eq!(named("login.approved"), 0);
    assert!(recorded.iter().any(|event| {
        event.get("event").map(String::as_str) == Some("login.denied")
            && event.get("reason").map(String::as_str) == Some("revoked")
    }));
    assert_eq!(
        harness
            .store
            .web_sessions()
            .count_for_user(&alice_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_way_in_refuses_while_revocations_cannot_be_read() {
    let harness = Harness::with_web().await;
    harness.load_policy(ROLES);
    let web = harness.web_sign_in().await;
    let finished = harness.login().await;
    let bearer = format!("Bearer {}", finished["api_token"].as_str().unwrap());
    let loopback = harness.begin().await;
    harness.approve(&loopback).await;
    let device = harness.device_start().await;
    let device_page = harness.sign_in(&device).await;
    let web_login = harness.web_start("").await;
    let alice_id = harness.alice_id().await;
    let web_sessions_before = harness
        .store
        .web_sessions()
        .count_for_user(&alice_id)
        .await
        .unwrap();
    let pool =
        SqlitePool::connect_with(SqliteConnectOptions::new().filename(harness.database_path()))
            .await
            .unwrap();
    sqlx::query("ALTER TABLE revocations RENAME TO revocations_gone")
        .execute(&pool)
        .await
        .unwrap();

    let web_reply = harness
        .web_get("/v1/admin/whoami", Some(&web.cookie()))
        .await;
    let api_reply = harness
        .get_with_headers("/v1/nodes", &[("authorization", &bearer)])
        .await;
    let finish_reply = harness
        .finish(&loopback, &ed25519_public_key_line("alice@laptop"))
        .await;
    let device_reply = harness
        .approve_device(&device.login_id, &device_page.token)
        .await;
    start_recording();
    let sign_in_reply = harness
        .web_callback(&web_login, Identity::alice(), Some(&web_login.login_cookie))
        .await;

    for (path, reply) in [
        ("web session", &web_reply),
        ("api token", &api_reply),
        ("certificate", &finish_reply),
        ("device approval", &device_reply),
        ("web sign-in", &sign_in_reply),
    ] {
        assert_eq!(
            reply.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{path}: {}",
            reply.text()
        );
    }
    assert!(!finish_reply.text().contains("certificate\""));
    assert!(
        sign_in_reply
            .set_cookies()
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-jaunt="))
    );
    assert!(
        take_recording()
            .iter()
            .all(|event| event.get("event").map(String::as_str) != Some("web.session.created"))
    );
    assert_eq!(
        harness
            .store
            .web_sessions()
            .count_for_user(&alice_id)
            .await
            .unwrap(),
        web_sessions_before
    );
}
