use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;
use jaunt_store::{LoginRequestState, NewUser};

use crate::device_support::hidden_field;
use crate::provider::Identity;
use crate::support::{Harness, ed25519_public_key_line};

const CLEARED_COOKIE: &str =
    "__Host-jaunt-device=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
const EXPECTED_CSP: &str = "default-src 'none'; form-action 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'";

async fn assert_pending_and_unapproved(harness: &Harness, login_id: &str) {
    let stored = harness
        .store
        .login_requests()
        .get(login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.user_id, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn continue_answers_200_with_a_link_a_refresh_header_and_the_browser_cookie() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;

    let continued = harness.continue_flow(&session).await;

    let reply = &continued.reply;
    assert_eq!(reply.status, StatusCode::OK);
    assert!(reply.headers.get("location").is_none());
    assert_eq!(
        reply.header("refresh"),
        format!("0; url={}", continued.authorize_url)
    );
    assert!(continued.authorize_url.starts_with(&harness.provider.base));
    for hostile in ['"', '<', '>', '\''] {
        assert!(!continued.authorize_url.contains(hostile));
    }
    let html = reply.text();
    let escaped = continued.authorize_url.replace('&', "&amp;");
    assert!(
        html.contains(&format!("href=\"{escaped}\">Continue to sign in</a>")),
        "{html}"
    );
    assert_eq!(html.matches(&escaped).count(), 1);
    assert!(!html.contains(&continued.authorize_url));
    assert_eq!(reply.header("content-security-policy"), EXPECTED_CSP);
    assert_eq!(reply.header("x-frame-options"), "DENY");
    assert_eq!(reply.header("cache-control"), "no-store");

    let cookies = reply.set_cookies();
    assert_eq!(cookies.len(), 1);
    let (pair, attributes) = cookies[0].split_once("; ").unwrap();
    let value = pair.strip_prefix("__Host-jaunt-device=").unwrap();
    assert_eq!(value.len(), 43);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert_eq!(
        attributes,
        "Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
    );
    assert!(!cookies[0].to_ascii_lowercase().contains("domain"));
}

#[tokio::test(flavor = "multi_thread")]
async fn each_continue_issues_a_different_cookie() {
    let harness = Harness::new().await;
    let first = harness.continue_flow(&harness.device_start().await).await;
    let second = harness.continue_flow(&harness.device_start().await).await;

    assert_ne!(first.cookie, second.cookie);
    assert_ne!(first.state, second.state);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_provider_url_handed_to_another_browser_never_reaches_the_approval_page() {
    let harness = Harness::new().await;
    let victim_session = harness.device_start().await;
    let victim = harness.continue_flow(&victim_session).await;
    let foreign_cookies = [
        None,
        Some(victim.cookie.as_str()),
        Some("__Host-jaunt-device=short"),
        Some("__Host-jaunt-device="),
        Some("__host-jaunt-device=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        Some("session=1"),
    ];

    for cookie in foreign_cookies {
        let attacker_session = harness.device_start().await;
        let attacker = harness.continue_flow(&attacker_session).await;

        let reply = harness
            .provider_callback(&attacker, Identity::alice(), cookie)
            .await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{cookie:?}");
        let html = reply.text();
        assert!(html.contains("Sign-in failed"), "{cookie:?}");
        assert!(!html.contains("Approve sign-in"), "{cookie:?}");
        assert!(!html.contains("name=\"token\""), "{cookie:?}");
        assert!(reply.set_cookies().is_empty(), "{cookie:?}");
        assert_pending_and_unapproved(&harness, &attacker_session.login_id).await;
        harness.clock.advance(5);
        let polled = harness
            .poll(&attacker_session, &ed25519_public_key_line("attacker@host"))
            .await;
        assert_eq!(polled.error_code(), "authorization_pending", "{cookie:?}");
    }

    let own = harness
        .provider_callback(&victim, Identity::alice(), Some(&victim.cookie))
        .await;
    assert_eq!(own.status, StatusCode::OK);
    assert!(own.text().contains("Approve sign-in for the Jaunt CLI?"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_callback_burns_the_provider_state_and_consumes_nothing_else() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let continued = harness.continue_flow(&session).await;
    assert_eq!(harness.control.pending_len(), 1);

    let refused = harness
        .provider_callback(&continued, Identity::alice(), None)
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(harness.control.pending_len(), 0);

    let replay = harness
        .provider_callback(&continued, Identity::alice(), Some(&continued.cookie))
        .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert!(!replay.text().contains("Approve sign-in"));
    assert_pending_and_unapproved(&harness, &session.login_id).await;

    let again = harness.continue_flow(&session).await;
    let approval = harness
        .provider_callback(&again, Identity::alice(), Some(&again.cookie))
        .await;
    assert_eq!(approval.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_cookie_is_found_among_other_cookies_and_cleared_at_every_later_step() {
    let harness = Harness::new().await;
    let approved = harness.device_start().await;
    let denied = harness.device_start().await;

    for (session, approve) in [(&approved, true), (&denied, false)] {
        let continued = harness.continue_flow(session).await;
        let jar = format!("theme=dark; {}; lang=en", continued.cookie);
        let page = harness
            .provider_callback(&continued, Identity::alice(), Some(&jar))
            .await;
        assert_eq!(page.status, StatusCode::OK);
        assert_eq!(page.set_cookies(), [CLEARED_COOKIE]);
        assert!(!page.text().contains(&continued.cookie));
        let token = hidden_field(&page.text(), "token");

        let result = if approve {
            harness.approve_device(&session.login_id, &token).await
        } else {
            harness.deny_device(&session.login_id, &token).await
        };
        assert_eq!(result.status, StatusCode::OK);
        assert_eq!(result.set_cookies(), [CLEARED_COOKIE]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_mismatch_stops_before_the_provider_exchange_and_creates_no_user() {
    let harness = Harness::new().await;
    let exchanges = Arc::new(AtomicUsize::new(0));
    let counter = exchanges.clone();
    harness.provider.on_token(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let session = harness.device_start().await;
    let continued = harness.continue_flow(&session).await;

    let refused = harness
        .provider_callback(&continued, Identity::alice(), None)
        .await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    let probe_time = harness.clock.now_secs() + 1_000;
    let probe = harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: harness.provider.base.clone(),
                subject: "user-1".to_owned(),
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            probe_time,
        )
        .await
        .unwrap();
    assert_eq!(probe.created_at, probe_time);

    let again = harness.continue_flow(&session).await;
    let accepted = harness
        .provider_callback(&again, Identity::alice(), Some(&again.cookie))
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_approvals_do_not_touch_the_cookie() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let page = harness.sign_in(&session).await;

    let refused = harness
        .approve_device(&session.login_id, "wrong-token")
        .await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.set_cookies().is_empty());
    assert_eq!(
        harness
            .approve_device(&session.login_id, &page.token)
            .await
            .status,
        StatusCode::OK
    );
}
