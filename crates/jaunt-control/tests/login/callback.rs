use axum::http::StatusCode;
use jaunt_store::LoginRequestState;

use crate::audit::{start_recording, take_recording};
use crate::provider::Identity;
use crate::support::{
    Harness, LOGIN_TTL_SECS, Reply, completion_code_in, ed25519_public_key_line, sha256_hex,
};

fn assert_static_failure_page(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(
        reply.header("content-security-policy"),
        "default-src 'none'; form-action 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
    assert_eq!(reply.header("x-frame-options"), "DENY");
    assert_eq!(reply.header("x-content-type-options"), "nosniff");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("referrer-policy"), "strict-origin");
    assert!(reply.text().contains("Sign-in failed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn successful_callback_approves_the_request_and_redirects_to_the_stored_port() {
    let harness = Harness::new().await;
    let session = harness.begin_on(41234).await;

    let reply = harness.approve(&session).await;

    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    assert!(reply.body.is_empty());
    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Approved);
    let code = session.completion_code();
    assert_eq!(
        stored.completion_hash.as_deref(),
        Some(sha256_hex(code).as_str())
    );
    let user = harness
        .store
        .users()
        .get(stored.user_id.as_deref().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.issuer, harness.provider.base);
    assert_eq!(user.subject, "user-1");
    assert_eq!(user.email, "alice@example.com");
    assert_eq!(user.username, "alice");
    assert_eq!(user.display_name.as_deref(), Some("Alice Example"));
    assert_eq!(user.groups, ["dev", "ops"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_changed_provider_username_replaces_the_stored_one_at_the_next_login() {
    let harness = Harness::new().await;
    let mut user_ids = Vec::new();
    for username in ["alice", "alice.renamed"] {
        let session = harness.begin().await;
        let code = harness.provider.grant(
            &session.authorize_url,
            Identity {
                username: username.to_owned(),
                ..Identity::alice()
            },
        );
        let reply = harness
            .callback(&format!("code={code}&state={}", session.state))
            .await;
        completion_code_in(reply.location(), &session);
        let stored = harness
            .store
            .login_requests()
            .get(&session.login_id)
            .await
            .unwrap()
            .unwrap();
        let user_id = stored.user_id.unwrap();
        let user = harness.store.users().get(&user_id).await.unwrap().unwrap();
        assert_eq!(user.username, username);
        user_ids.push(user_id);
    }
    assert_eq!(user_ids[0], user_ids[1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirect_host_and_port_never_come_from_the_request() {
    let harness = Harness::new().await;
    let injected = [
        ("host", "evil.example"),
        ("x-forwarded-host", "evil.example"),
        ("x-forwarded-port", "1"),
        ("forwarded", "host=evil.example"),
        ("origin", "http://evil.example"),
        ("referer", "http://evil.example/"),
    ];
    let decoys = "redirect_uri=http%3A%2F%2Fevil.example%2F&redirect_port=2&port=3&host=evil.example&login_id=forged";

    let session = harness.begin_on(41234).await;
    let code = harness.browser_code(&session);
    let success = harness
        .get_with_headers(
            &format!(
                "/v1/login/callback?code={code}&state={}&{decoys}",
                session.state
            ),
            &injected,
        )
        .await;
    completion_code_in(success.location(), &session);

    let denied_session = harness.begin_on(41235).await;
    let denied = harness
        .get_with_headers(
            &format!(
                "/v1/login/callback?error=access_denied&state={}&{decoys}",
                denied_session.state
            ),
            &injected,
        )
        .await;
    assert_eq!(
        denied.location(),
        format!(
            "http://127.0.0.1:41235/callback?error=access_denied&login_id={}",
            denied_session.login_id
        )
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_with_a_known_login_redirect_with_a_generic_error_code() {
    let harness = Harness::new().await;
    let unverified = Identity {
        email_verified: false,
        ..Identity::alice()
    };
    for (name, expected) in [
        ("provider error", "access_denied"),
        ("missing code", "invalid_request"),
        ("empty code", "invalid_request"),
        ("code the provider never issued", "access_denied"),
        ("unverified email", "access_denied"),
    ] {
        let session = harness.begin_on(41236).await;
        let query = match name {
            "provider error" => format!(
                "error=access_denied&error_description=secret+provider+text&state={}",
                session.state
            ),
            "missing code" => format!("state={}", session.state),
            "empty code" => format!("code=&state={}", session.state),
            "code the provider never issued" => {
                format!("code=never-issued&state={}", session.state)
            }
            _ => {
                let code = harness
                    .provider
                    .grant(&session.authorize_url, unverified.clone());
                format!("code={code}&state={}", session.state)
            }
        };

        let reply = harness.callback(&query).await;
        assert_eq!(
            reply.location(),
            format!(
                "http://127.0.0.1:41236/callback?error={expected}&login_id={}",
                session.login_id
            ),
            "{name}"
        );

        let stored = harness
            .store
            .login_requests()
            .get(&session.login_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, LoginRequestState::Pending, "{name}");
        assert_eq!(stored.completion_hash, None, "{name}");
        let retry = harness
            .callback(&format!(
                "code={}&state={}",
                harness.browser_code(&session),
                session.state
            ))
            .await;
        assert_static_failure_page(&retry);
        let finish = harness
            .finish(&session, &ed25519_public_key_line("alice"))
            .await;
        assert_eq!(finish.error_code(), "invalid_grant", "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn callbacks_without_a_known_state_show_the_static_page() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    let oversized = format!("code=abc&state={}", "a".repeat(9000));
    let queries = [
        "".to_owned(),
        "code=abc".to_owned(),
        "code=abc&state=".to_owned(),
        "code=abc&state=unknown".to_owned(),
        format!("code=abc&state={0}&state={0}", session.state),
        format!("code=abc&code=def&state={}", session.state),
        oversized,
    ];
    for query in queries {
        let reply = harness.get(&format!("/v1/login/callback?{query}")).await;
        assert_static_failure_page(&reply);
        assert!(!reply.text().contains("abc"));
    }
    let bare = harness.get("/v1/login/callback").await;
    assert_static_failure_page(&bare);
    assert_eq!(harness.control.pending_len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_state_shows_the_static_page_and_leaves_the_login_intact() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    let code = harness.browser_code(&session);
    let query = format!("code={code}&state={}", session.state);
    let accepted = harness.callback(&query).await;
    assert_eq!(accepted.status, StatusCode::FOUND);
    session.record_completion(accepted.location());

    let replay = harness.callback(&query).await;

    assert_static_failure_page(&replay);
    let finished = harness
        .finish(&session, &ed25519_public_key_line("alice"))
        .await;
    assert_eq!(finished.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_replayed_under_another_login_is_refused() {
    let harness = Harness::new().await;
    let first = harness.begin().await;
    let second = harness.begin().await;
    let code = harness.browser_code(&first);
    let accepted = harness
        .callback(&format!("code={code}&state={}", first.state))
        .await;
    assert_eq!(accepted.status, StatusCode::FOUND);

    let replay = harness
        .callback(&format!("code={code}&state={}", second.state))
        .await;

    assert_eq!(
        replay.location(),
        format!(
            "http://127.0.0.1:45123/callback?error=access_denied&login_id={}",
            second.login_id
        )
    );
    let stored = harness
        .store
        .login_requests()
        .get(&second.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
}

#[tokio::test(flavor = "multi_thread")]
async fn callback_for_an_expired_login_request_is_refused() {
    let harness = Harness::new().await;
    let session = harness.begin_on(41237).await;
    let code = harness.browser_code(&session);
    harness.clock.advance(LOGIN_TTL_SECS + 1);

    let reply = harness
        .callback(&format!("code={code}&state={}", session.state))
        .await;

    assert_eq!(
        reply.location(),
        format!(
            "http://127.0.0.1:41237/callback?error=invalid_request&login_id={}",
            session.login_id
        )
    );
    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.user_id, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_approval_gets_its_own_completion_code() {
    let harness = Harness::new().await;
    let first = harness.begin().await;
    let second = harness.begin().await;
    harness.approve(&first).await;
    harness.approve(&second).await;

    assert_ne!(first.completion_code(), second.completion_code());
    let requests = harness.store.login_requests();
    let first_hash = requests.get(&first.login_id).await.unwrap().unwrap();
    let second_hash = requests.get(&second.login_id).await.unwrap().unwrap();
    assert_ne!(first_hash.completion_hash, second_hash.completion_hash);
}

#[tokio::test]
async fn a_login_that_expires_during_the_provider_exchange_is_not_approved() {
    let harness = Harness::new().await;
    let session = harness.begin_on(41238).await;
    let clock = harness.clock.clone();
    harness
        .provider
        .on_token(move || clock.advance(LOGIN_TTL_SECS + 1));
    let code = harness.browser_code(&session);

    start_recording();
    let reply = harness
        .callback(&format!("code={code}&state={}", session.state))
        .await;
    let events = take_recording();

    assert_eq!(
        reply.location(),
        format!(
            "http://127.0.0.1:41238/callback?error=invalid_request&login_id={}",
            session.login_id
        )
    );
    let audit: Vec<(&str, Option<&str>)> = events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .map(|event| {
            (
                event["event"].as_str(),
                event.get("reason").map(String::as_str),
            )
        })
        .collect();
    assert_eq!(audit, [("login.denied", Some("approve_lost"))]);
    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.user_id, None);
    assert_eq!(stored.completion_hash, None);
    let finish = harness
        .finish(&session, &ed25519_public_key_line("alice"))
        .await;
    assert_eq!(finish.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callback_query_over_the_size_limit_is_refused_before_anything_is_consumed() {
    const LIMIT: usize = 8 * 1024;
    let harness = Harness::new().await;
    let session = harness.begin_on(41239).await;
    let code = harness.browser_code(&session);
    let head = format!("code={code}&state={}&pad=", session.state);
    let at_limit = format!("{head}{}", "a".repeat(LIMIT - head.len()));
    let over_limit = format!("{at_limit}a");
    assert_eq!(at_limit.len(), LIMIT);

    let refused = harness.callback(&over_limit).await;

    assert_static_failure_page(&refused);
    assert_eq!(harness.control.pending_len(), 1);
    let accepted = harness.callback(&at_limit).await;
    assert!(
        accepted.location().starts_with(&format!(
            "http://127.0.0.1:41239/callback?login_id={}&code=",
            session.login_id
        )),
        "{}",
        accepted.location()
    );
}
