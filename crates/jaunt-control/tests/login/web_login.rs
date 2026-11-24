use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};

use crate::provider::Identity;
use crate::support::{DEFAULT_PEER, Harness, sha256_hex};
use crate::web_support::{
    APPROVER_AND_OPS_ROLES, BROWSER, LOGIN_COOKIE, SESSION_COOKIE, SESSION_TTL_SECS, WebSignedIn,
    bob, cookie_value,
};

const SESSION_COOKIE_ATTRIBUTES: &str = "Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800";
const CLEARED_LOGIN_COOKIE: &str =
    "__Host-jaunt-web-login=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_login_ends_in_a_strict_host_cookie_and_a_session_with_the_policy_permissions() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);

    let start = harness.web_start("?return_to=/nodes").await;
    assert!(start.authorize_url.starts_with(&harness.provider.base));
    let started_cookie = start.reply.set_cookies().remove(0);
    assert_eq!(
        started_cookie,
        format!(
            "{}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300",
            start.login_cookie
        )
    );
    assert_eq!(cookie_value(&started_cookie).len(), 43);

    let reply = harness
        .web_callback(&start, Identity::alice(), Some(&start.login_cookie))
        .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.refresh_target(), "/nodes");
    assert!(reply.text().contains("<a href=\"/nodes\">Continue</a>"));
    let cookies = reply.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    let secret = cookie_value(&cookies[0]);
    assert_eq!(secret.len(), 43);
    assert_eq!(
        cookies[0],
        format!("{SESSION_COOKIE}={secret}; {SESSION_COOKIE_ATTRIBUTES}")
    );
    assert_eq!(cookies[1], CLEARED_LOGIN_COOKIE);
    let signed = WebSignedIn {
        reply,
        secret: secret.to_owned(),
    };

    let session = harness
        .web_get("/v1/web/session", Some(&signed.cookie()))
        .await;
    assert_eq!(session.status, StatusCode::OK, "{}", session.text());
    let body = session.json();
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["display_name"], "Alice Example");
    assert_eq!(body["groups"], serde_json::json!(["dev", "ops"]));
    assert_eq!(
        body["permissions"],
        serde_json::json!([
            "nodes.approve",
            "sessions.read",
            "recordings.read",
            "audit.read"
        ])
    );
    assert_eq!(
        body["expires_at"],
        harness.clock.now_secs() + i64::try_from(SESSION_TTL_SECS).unwrap()
    );
    assert_eq!(body["csrf_token"].as_str().unwrap().len(), 43);
    assert_eq!(
        harness.csrf_token(&signed).await,
        body["csrf_token"].as_str().unwrap()
    );

    let stored = harness
        .store
        .web_sessions()
        .get(&sha256_hex(&signed.secret))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.user_id, body["user_id"].as_str().unwrap());
    assert_eq!(stored.source_ip.as_deref(), Some("198.51.100.7"));
    assert_eq!(stored.user_agent.as_deref(), Some(BROWSER));
    assert_ne!(stored.csrf_token_hash, sha256_hex(&signed.secret));
    let all_stored = format!("{stored:?}");
    assert!(!all_stored.contains(&signed.secret));
    assert!(!all_stored.contains(body["csrf_token"].as_str().unwrap()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callback_without_the_binding_of_this_browser_is_refused_before_the_exchange() {
    let harness = Harness::with_web().await;
    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = exchanges.clone();
    harness.provider.on_token(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let bystander = harness.web_start("").await;
    let secret = cookie_value(&bystander.login_cookie).to_owned();
    let flipped = if secret.starts_with('A') { 'B' } else { 'A' };
    let wrong_but_well_formed = format!("{flipped}{}", &secret[1..]);
    let own = |value: &str| format!("{LOGIN_COOKIE}={value}");

    let attempts = [
        None,
        Some(bystander.login_cookie.clone()),
        Some(own(&wrong_but_well_formed)),
        Some(own("short")),
        Some(own("")),
        Some(format!("{}={secret}", LOGIN_COOKIE.to_lowercase())),
        Some(format!("{SESSION_COOKIE}={secret}")),
    ];
    for attempt in attempts {
        let victim = harness.web_start("").await;

        let reply = harness
            .web_callback(&victim, Identity::alice(), attempt.as_deref())
            .await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{attempt:?}");
        assert!(reply.text().contains("Sign-in failed"), "{attempt:?}");
        assert!(reply.set_cookies().is_empty(), "{attempt:?}");
    }

    let victim = harness.web_start("").await;
    let own_twice = format!("{0}; {0}", victim.login_cookie);
    let bystander_twice = format!("{0}; {0}", bystander.login_cookie);
    for jar in [own_twice.as_str(), bystander_twice.as_str()] {
        let again = harness.web_start("").await;
        let reply = harness
            .web_callback(&again, Identity::alice(), Some(jar))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{jar}");
    }
    let split_headers = harness
        .get_with_headers(
            &format!("/v1/login/callback?code=x&state={}", victim.state),
            &[
                ("cookie", victim.login_cookie.as_str()),
                ("cookie", victim.login_cookie.as_str()),
            ],
        )
        .await;
    assert_eq!(split_headers.status, StatusCode::BAD_REQUEST);

    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    harness.assert_alice_was_never_stored().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_callback_creates_no_session_and_burns_the_pending_login() {
    let harness = Harness::with_web().await;
    let victim = harness.web_start("").await;

    let refused = harness.web_callback(&victim, Identity::alice(), None).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.control.pending_len(), 0);

    let replay = harness
        .web_callback(&victim, Identity::alice(), Some(&victim.login_cookie))
        .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert!(replay.set_cookies().is_empty());
    harness.assert_alice_was_never_stored().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_return_target_is_kept_only_when_it_is_a_same_origin_path() {
    let harness = Harness::with_web().await;
    let too_long = format!("?return_to=%2F{}", "a".repeat(300));
    let cases = [
        ("?return_to=%2Fa", "/a"),
        ("?return_to=%2Fnodes%3Fid%3D7", "/nodes?id=7"),
        ("?return_to=%2F%2Fevil.example", "/"),
        ("?return_to=https%3A%2F%2Fevil.example", "/"),
        ("?return_to=%2F%5Cevil.example", "/"),
        ("?return_to=%2Fa%0D%0ASet-Cookie%3A%20x%3D1", "/"),
        ("?return_to=%2Fa%00b", "/"),
        (too_long.as_str(), "/"),
        ("?return_to=", "/"),
        ("", "/"),
        ("?return_to=%2Fa&return_to=%2Fb", "/"),
    ];

    for (query, expected) in cases {
        let signed = harness.web_sign_in_with(query, Identity::alice()).await;

        assert_eq!(signed.reply.refresh_target(), expected, "{query}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn every_sign_in_issues_a_new_session_and_ignores_a_cookie_sent_with_the_callback() {
    let harness = Harness::with_web().await;
    let first = harness.web_sign_in().await;
    let planted = format!("{SESSION_COOKIE}=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    for presented in [first.cookie(), planted.clone()] {
        let start = harness.web_start("").await;
        let jar = format!("{presented}; {}", start.login_cookie);
        let reply = harness
            .web_callback(&start, Identity::alice(), Some(&jar))
            .await;

        assert_eq!(reply.status, StatusCode::OK, "{presented}");
        let issued = reply.set_cookies();
        let secret = cookie_value(&issued[0]);
        assert_ne!(secret, cookie_value(&presented));
        let fresh = format!("{SESSION_COOKIE}={secret}");
        assert_eq!(
            harness
                .web_get("/v1/web/session", Some(&fresh))
                .await
                .status,
            StatusCode::OK
        );
    }
    assert_eq!(
        harness
            .web_get("/v1/web/session", Some(&planted))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_error_creates_no_session() {
    let harness = Harness::with_web().await;
    let start = harness.web_start("").await;

    let reply = harness
        .get_with_headers(
            &format!(
                "/v1/login/callback?error=access_denied&state={}",
                start.state
            ),
            &[("cookie", &start.login_cookie)],
        )
        .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.set_cookies().is_empty());
    harness.assert_alice_was_never_stored().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_pending_login_cannot_be_completed() {
    let harness = Harness::with_web().await;
    let start = harness.web_start("").await;
    harness.clock.advance(300);

    let reply = harness
        .web_callback(&start, Identity::alice(), Some(&start.login_cookie))
        .await;

    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.set_cookies().is_empty());
    harness.assert_alice_was_never_stored().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn web_login_coexists_with_the_loopback_and_device_flows() {
    let harness = Harness::with_web().await;
    harness.web_sign_in_with("", bob()).await;

    let issued = harness.login().await;
    let device = harness.device_start().await;

    assert!(issued["api_token"].as_str().unwrap().starts_with("jt_"));
    assert_eq!(
        device.body["verification_url"],
        "https://jaunt.example/login/device"
    );
    let reply = harness
        .request_as(
            axum::http::Method::GET,
            "/login/device",
            DEFAULT_PEER,
            &[],
            None,
        )
        .await;
    assert_eq!(
        reply.header("content-security-policy"),
        "default-src 'none'; form-action 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_get_starts_a_web_login() {
    let harness = Harness::with_web().await;

    for method in [
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
    ] {
        let reply = harness
            .request_as(method.clone(), "/v1/web/login", DEFAULT_PEER, &[], None)
            .await;

        assert_ne!(reply.status, StatusCode::FOUND, "{method}");
        assert!(reply.set_cookies().is_empty(), "{method}");
        assert_eq!(harness.control.pending_len(), 0, "{method}");
    }
    harness.web_start("").await;
    assert_eq!(harness.control.pending_len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_callback_needs_the_connection_address_and_a_refusal_consumes_nothing() {
    let harness = Harness::with_web().await;
    let callback = |code: &str, state: &str, cookie: Option<&str>| {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(format!("/v1/login/callback?code={code}&state={state}"));
        if let Some(cookie) = cookie {
            builder = builder.header("cookie", cookie);
        }
        builder.body(Body::empty()).unwrap()
    };

    let loopback = harness.begin().await;
    let code = harness.browser_code(&loopback);
    let refused = harness
        .send_without_peer(callback(&code, &loopback.state, None))
        .await;
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
    let approved = harness.send(callback(&code, &loopback.state, None)).await;
    assert_eq!(approved.status, StatusCode::FOUND);
    loopback.record_completion(approved.location());

    let start = harness.web_start("").await;
    let code = harness.provider.grant(&start.authorize_url, bob());
    let refused = harness
        .send_without_peer(callback(&code, &start.state, Some(&start.login_cookie)))
        .await;
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(refused.set_cookies().is_empty());
    let signed_in = harness
        .send(callback(&code, &start.state, Some(&start.login_cookie)))
        .await;
    assert_ne!(signed_in.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!signed_in.set_cookies().is_empty());

    let session = harness.device_start().await;
    let continued = harness.continue_flow(&session).await;
    let code = harness
        .provider
        .grant(&continued.authorize_url, Identity::alice());
    let refused = harness
        .send_without_peer(callback(&code, &continued.state, Some(&continued.cookie)))
        .await;
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
    let approval = harness
        .send(callback(&code, &continued.state, Some(&continued.cookie)))
        .await;
    assert_eq!(approval.status, StatusCode::OK, "{}", approval.text());
    assert!(
        approval
            .text()
            .contains("Approve sign-in for the Jaunt CLI?")
    );
}
