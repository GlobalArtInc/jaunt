use axum::http::StatusCode;
use jaunt_ca::Uuid;
use jaunt_ca::ssh_key::Certificate;
use jaunt_store::LoginRequestState;
use serde_json::json;

use crate::provider::Identity;
use crate::support::{Harness, LOGIN_TTL_SECS, Options, ed25519_public_key_line, sha256_hex};

const RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbq8RTZjt4CE3S8rO3jTGFkWZNb/VU4RKaU7as+YNXyAP7sB2MGZBYgM/zsaJM4QJqOyiIWaXGKaSV2jPK0zjEZ+G1yAGKKutJuHInAw+zZYCdcZsKMPyENxGarTBfziudWiQVVdjf0QBuWDF0UOFgwRe2JMWgP8fz/9Gin3ZdLIIZGiCdZbwLmGMHEy8WIwV+PtdJ2xy2uP+5+bAcoP/TTg4i3yvmrf/POnL5GoXimJYc/1X3YXCc2KmO/wJBeoyVc2FbScDpGQJRZN8feRqzTeevM/vT9D2P86z7JKNgDgH0wDXIOKDnkPzjegvTMrf/6Vc9fczxZpPElguEAQyN";

async fn state_of(harness: &Harness, login_id: &str) -> LoginRequestState {
    harness
        .store
        .login_requests()
        .get(login_id)
        .await
        .unwrap()
        .unwrap()
        .state
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_is_issued_only_after_the_person_presses_approve() {
    let harness = Harness::new().await;
    let key = ed25519_public_key_line("alice@server");

    let session = harness.device_start().await;
    let body = &session.body;
    assert_eq!(
        body["verification_url"],
        "https://jaunt.example/login/device"
    );
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["interval"], 5);
    let shape: Vec<char> = session.user_code.chars().collect();
    assert_eq!(shape.len(), 9);
    assert_eq!(shape[4], '-');
    assert!(
        shape
            .iter()
            .enumerate()
            .all(|(index, c)| index == 4 || "23456789ABCDEFGHJKMNPQRSTUVWXYZ".contains(*c))
    );

    let pending = harness.poll(&session, &key).await;
    assert_eq!(pending.status, StatusCode::BAD_REQUEST);
    assert_eq!(pending.error_code(), "authorization_pending");

    let page = harness.sign_in(&session).await;
    harness.clock.advance(5);
    let still_pending = harness.poll(&session, &key).await;
    assert_eq!(still_pending.error_code(), "authorization_pending");
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Pending
    );

    let approved = harness.approve_device(&session.login_id, &page.token).await;
    assert_eq!(approved.status, StatusCode::OK);
    assert!(approved.text().contains("You can return to your terminal."));
    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Approved);
    assert_eq!(stored.completion_hash, None);
    assert_eq!(
        stored.user_code_hash,
        Some(sha256_hex(&session.user_code.replace('-', "")))
    );

    harness.clock.advance(5);
    let issued = harness.poll(&session, &key).await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.text());
    let issued = issued.json();
    let certificate = Certificate::from_openssh(issued["certificate"].as_str().unwrap()).unwrap();
    let user_id = issued["user_id"].as_str().unwrap();
    assert!(Uuid::parse_str(user_id).is_ok());
    assert_eq!(stored.user_id.as_deref(), Some(user_id));
    assert_eq!(certificate.valid_principals(), [user_id]);
    let serial = issued["serial"].as_i64().unwrap();
    assert_eq!(
        certificate.key_id(),
        format!("jaunt:alice@example.com:{serial}")
    );
    assert_eq!(issued["email"], "alice@example.com");
    assert_eq!(issued["host_ca_keys"], json!(harness.host_keys));

    let token = issued["api_token"].as_str().unwrap();
    assert_eq!(harness.whoami(token).await.status, StatusCode::OK);
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Redeemed
    );

    harness.clock.advance(5);
    let again = harness.poll(&session, &key).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_sign_in_stores_the_provider_username() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let identity = Identity {
        username: "alice.device".to_owned(),
        ..Identity::alice()
    };

    let page = harness.sign_in_as(&session, identity).await;
    let approved = harness.approve_device(&session.login_id, &page.token).await;
    assert_eq!(approved.status, StatusCode::OK);

    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    let user = harness
        .store
        .users()
        .get(stored.user_id.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.username, "alice.device");
}

#[tokio::test(flavor = "multi_thread")]
async fn denying_ends_the_request_and_no_certificate_follows() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let page = harness.sign_in(&session).await;
    let key = ed25519_public_key_line("alice@server");

    let denied = harness.deny_device(&session.login_id, &page.token).await;
    assert_eq!(denied.status, StatusCode::OK);
    assert!(denied.text().contains("Request denied."));
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Denied
    );

    let polled = harness.poll(&session, &key).await;
    assert_eq!(polled.status, StatusCode::BAD_REQUEST);
    assert_eq!(polled.error_code(), "access_denied");
    let replay = harness.approve_device(&session.login_id, &page.token).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Denied
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_verifier_is_refused_and_does_not_burn_the_approved_request() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let page = harness.sign_in(&session).await;
    harness.approve_device(&session.login_id, &page.token).await;
    let key = ed25519_public_key_line("alice@server");

    let wrong = harness
        .poll_with(&session.login_id, &harness.next_verifier(), &key)
        .await;

    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.error_code(), "invalid_grant");
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Approved
    );
    harness.clock.advance(5);
    assert_eq!(harness.poll(&session, &key).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_key_is_refused_without_burning_the_approved_request() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let page = harness.sign_in(&session).await;
    harness.approve_device(&session.login_id, &page.token).await;

    let refused = harness.poll(&session, RSA_PUBLIC_KEY).await;

    assert_eq!(refused.error_code(), "invalid_grant");
    assert_eq!(
        state_of(&harness, &session.login_id).await,
        LoginRequestState::Approved
    );
    harness.clock.advance(5);
    let key = ed25519_public_key_line("alice@server");
    assert_eq!(harness.poll(&session, &key).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_expire_after_three_hundred_seconds_at_every_step() {
    let harness = Harness::new().await;
    let key = ed25519_public_key_line("alice@server");

    let at_approval_page = harness.device_start().await;
    let page = harness.sign_in(&at_approval_page).await;
    let approved_then_idle = harness.device_start().await;
    let idle_page = harness.sign_in(&approved_then_idle).await;
    harness
        .approve_device(&approved_then_idle.login_id, &idle_page.token)
        .await;
    let at_confirmation = harness.device_start().await;
    let confirmation_token = harness.confirmation_token(&at_confirmation).await;

    harness.clock.advance(LOGIN_TTL_SECS);

    let expired = harness.poll(&at_approval_page, &key).await;
    assert_eq!(expired.status, StatusCode::BAD_REQUEST);
    assert_eq!(expired.error_code(), "expired_token");
    let late_approve = harness
        .approve_device(&at_approval_page.login_id, &page.token)
        .await;
    assert_eq!(late_approve.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        state_of(&harness, &at_approval_page.login_id).await,
        LoginRequestState::Pending
    );

    let approved_expired = harness.poll(&approved_then_idle, &key).await;
    assert_eq!(approved_expired.error_code(), "expired_token");
    assert_eq!(
        state_of(&harness, &approved_then_idle.login_id).await,
        LoginRequestState::Approved
    );

    let late_continue = harness
        .proceed(&at_confirmation.login_id, &confirmation_token)
        .await;
    assert_eq!(late_continue.status, StatusCode::BAD_REQUEST);
    let late_code = harness.enter_code(&at_confirmation.user_code).await;
    assert!(late_code.text().contains("not recognised or has expired"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_last_second_before_expiry_still_works() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let page = harness.sign_in(&session).await;
    let key = ed25519_public_key_line("alice@server");

    harness.clock.advance(LOGIN_TTL_SECS - 1);

    let approved = harness.approve_device(&session.login_id, &page.token).await;
    assert_eq!(approved.status, StatusCode::OK);
    assert_eq!(harness.poll(&session, &key).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_tokens_are_single_use_and_bound_to_their_own_request() {
    let harness = Harness::new().await;
    let first = harness.device_start().await;
    let second = harness.device_start().await;
    let first_page = harness.sign_in(&first).await;
    let second_page = harness.sign_in(&second).await;
    assert_ne!(first_page.token, second_page.token);

    let crossed = harness
        .approve_device(&first.login_id, &second_page.token)
        .await;
    assert_eq!(crossed.status, StatusCode::BAD_REQUEST);
    let crossed_deny = harness
        .deny_device(&second.login_id, &first_page.token)
        .await;
    assert_eq!(crossed_deny.status, StatusCode::BAD_REQUEST);
    for session in [&first, &second] {
        assert_eq!(
            state_of(&harness, &session.login_id).await,
            LoginRequestState::Pending
        );
    }

    let own = harness
        .approve_device(&first.login_id, &first_page.token)
        .await;
    assert_eq!(own.status, StatusCode::OK);
    let replay = harness
        .approve_device(&first.login_id, &first_page.token)
        .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    let deny_after = harness
        .deny_device(&first.login_id, &first_page.token)
        .await;
    assert_eq!(deny_after.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        state_of(&harness, &first.login_id).await,
        LoginRequestState::Approved
    );

    let second_own = harness
        .approve_device(&second.login_id, &second_page.token)
        .await;
    assert_eq!(second_own.status, StatusCode::OK);

    let garbage = harness.approve_device("not-a-login-id", "x").await;
    assert_eq!(garbage.status, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn continue_tokens_are_single_use_and_bound_to_their_own_request() {
    let harness = Harness::new().await;
    let first = harness.device_start().await;
    let second = harness.device_start().await;
    let first_token = harness.confirmation_token(&first).await;
    let second_token = harness.confirmation_token(&second).await;

    let crossed = harness.proceed(&first.login_id, &second_token).await;
    assert_eq!(crossed.status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.control.pending_len(), 0);

    let own = harness.proceed(&first.login_id, &first_token).await;
    assert!(own.refresh_target().starts_with(&harness.provider.base));
    assert_eq!(harness.control.pending_len(), 1);
    let replay = harness.proceed(&first.login_id, &first_token).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.control.pending_len(), 1);

    let second_own = harness.proceed(&second.login_id, &second_token).await;
    assert!(
        second_own
            .refresh_target()
            .starts_with(&harness.provider.base)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn continue_is_refused_once_the_request_was_approved_or_denied() {
    let harness = Harness::new().await;
    for approve in [true, false] {
        let session = harness.device_start().await;
        let page = harness.sign_in(&session).await;
        let stale_token = harness.confirmation_token(&session).await;
        let settled = if approve {
            harness.approve_device(&session.login_id, &page.token).await
        } else {
            harness.deny_device(&session.login_id, &page.token).await
        };
        assert_eq!(settled.status, StatusCode::OK);
        let pending_before = harness.control.pending_len();

        let refused = harness.proceed(&session.login_id, &stale_token).await;

        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{approve}");
        assert!(refused.headers.get("refresh").is_none(), "{approve}");
        assert!(refused.set_cookies().is_empty(), "{approve}");
        assert_eq!(harness.control.pending_len(), pending_before, "{approve}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn polling_faster_than_the_interval_is_slowed_down_and_the_interval_grows() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let key = ed25519_public_key_line("alice@server");

    assert_eq!(
        harness.poll(&session, &key).await.error_code(),
        "authorization_pending"
    );
    let early = harness.poll(&session, &key).await;
    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    assert_eq!(early.error_code(), "slow_down");

    harness.clock.advance(9);
    assert_eq!(harness.poll(&session, &key).await.error_code(), "slow_down");
    harness.clock.advance(14);
    assert_eq!(harness.poll(&session, &key).await.error_code(), "slow_down");
    harness.clock.advance(20);
    assert_eq!(
        harness.poll(&session, &key).await.error_code(),
        "authorization_pending"
    );
    harness.clock.advance(20);
    assert_eq!(
        harness.poll(&session, &key).await.error_code(),
        "authorization_pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_waits_the_interval_is_never_slowed_down() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let key = ed25519_public_key_line("alice@server");

    for _ in 0..5 {
        assert_eq!(
            harness.poll(&session, &key).await.error_code(),
            "authorization_pending"
        );
        harness.clock.advance(5);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn slow_down_is_only_visible_to_the_holder_of_the_verifier() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let key = ed25519_public_key_line("alice@server");
    harness.poll(&session, &key).await;

    for _ in 0..3 {
        let stranger = harness
            .poll_with(&session.login_id, &harness.next_verifier(), &key)
            .await;
        assert_eq!(stranger.error_code(), "invalid_grant");
    }

    harness.clock.advance(5);
    assert_eq!(
        harness.poll(&session, &key).await.error_code(),
        "authorization_pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn polls_for_unknown_or_foreign_requests_and_malformed_bodies_are_refused() {
    let harness = Harness::new().await;
    let key = ed25519_public_key_line("alice@server");
    let device = harness.device_start().await;
    let loopback = harness.begin().await;
    let unknown = "0b7a0a2e-6a53-4c4e-9a3e-6d3a3f1b2c4d";

    let unknown_reply = harness.poll_with(unknown, &device.verifier, &key).await;
    assert_eq!(unknown_reply.error_code(), "invalid_grant");
    let wrong_kind = harness
        .poll_with(&loopback.login_id, &loopback.verifier, &key)
        .await;
    assert_eq!(wrong_kind.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong_kind.error_code(), "invalid_grant");

    let page = harness.sign_in(&device).await;
    harness.approve_device(&device.login_id, &page.token).await;
    let finish = harness
        .finish_raw(&device.login_id, &device.verifier, "x", &key)
        .await;
    assert_eq!(finish.error_code(), "invalid_grant");
    assert_eq!(
        state_of(&harness, &device.login_id).await,
        LoginRequestState::Approved
    );

    let good = json!({
        "login_id": device.login_id,
        "code_verifier": device.verifier,
        "public_key": key,
    });
    let mut extra = good.clone();
    extra["completion_code"] = json!("x");
    let mut short_verifier = good.clone();
    short_verifier["code_verifier"] = json!("short");
    let mut upper_id = good.clone();
    upper_id["login_id"] = json!(device.login_id.to_uppercase());
    for body in [json!({}), extra, short_verifier, upper_id] {
        let reply = harness.poll_raw(&body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), "invalid_request", "{body}");
    }
    let wrong_type = harness
        .post_raw(
            "/v1/login/device/poll",
            Some("text/plain"),
            serde_json::to_vec(&good).unwrap(),
        )
        .await;
    assert_eq!(wrong_type.error_code(), "invalid_request");
}

#[tokio::test(flavor = "multi_thread")]
async fn starting_is_refused_while_too_many_device_requests_are_live() {
    let harness = Harness::with(Options {
        pending_capacity: 2,
        ..Options::default()
    })
    .await;
    harness.device_start().await;
    harness.device_start().await;

    let refused = harness
        .post_json(
            "/v1/login/device/start",
            &json!({
                "code_challenge": crate::support::challenge_for("verifier-0000000000000000000000000000000000"),
                "code_challenge_method": "S256",
            }),
        )
        .await;

    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.error_code(), "busy");
    harness.clock.advance(LOGIN_TTL_SECS);
    harness.device_start().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn start_validates_the_challenge_the_label_and_the_body() {
    let harness = Harness::new().await;
    let challenge = crate::support::challenge_for("verifier-0000000000000000000000000000000000");
    let rejected = [
        json!({"code_challenge": challenge, "code_challenge_method": "plain"}),
        json!({"code_challenge": "short", "code_challenge_method": "S256"}),
        json!({"code_challenge": format!("{}+", &challenge[1..]), "code_challenge_method": "S256"}),
        json!({"code_challenge": challenge, "code_challenge_method": "S256", "client_label": ""}),
        json!({"code_challenge": challenge, "code_challenge_method": "S256", "client_label": "x".repeat(65)}),
        json!({"code_challenge": challenge, "code_challenge_method": "S256", "client_label": "tab\there"}),
        json!({"code_challenge": challenge, "code_challenge_method": "S256", "redirect_port": 4000}),
    ];
    for body in rejected {
        let reply = harness.post_json("/v1/login/device/start", &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), "invalid_request", "{body}");
    }
    let oversized = harness
        .post_raw(
            "/v1/login/device/start",
            Some("application/json"),
            vec![b' '; 20 * 1024],
        )
        .await;
    assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        harness
            .store
            .login_requests()
            .count_live_device(harness.clock.now_secs())
            .await
            .unwrap(),
        0
    );
}
