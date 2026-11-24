use axum::http::Method;

use crate::audit::{Captured, start_recording, take_recording};
use crate::provider::Identity;
use crate::support::{Harness, PUBLIC_ORIGIN, sha256_hex};
use crate::web_support::{APPROVER_AND_OPS_ROLES, SESSION_TTL_SECS, bob};

const LOGOUT: &str = "/v1/web/logout";

async fn scenario(harness: &Harness) -> Vec<String> {
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let alice = harness.web_sign_in().await;
    let alice_token = harness.csrf_token(&alice).await;
    let wrong_token = format!("{}A", &alice_token[1..]);

    harness
        .web_request(
            Method::POST,
            LOGOUT,
            Some(&alice.cookie()),
            &[("x-jaunt-csrf", &wrong_token), ("origin", PUBLIC_ORIGIN)],
        )
        .await;
    harness
        .web_request(
            Method::POST,
            LOGOUT,
            Some(&alice.cookie()),
            &[
                ("x-jaunt-csrf", &alice_token),
                ("origin", "https://evil.example"),
            ],
        )
        .await;

    let bob = harness.web_sign_in_with("", bob()).await;
    harness
        .web_get("/v1/admin/whoami", Some(&bob.cookie()))
        .await;

    let attacker_start = harness.web_start("").await;
    harness
        .web_callback(&attacker_start, Identity::alice(), None)
        .await;

    harness.web_post_with_csrf(LOGOUT, &alice).await;

    harness.clock.advance(SESSION_TTL_SECS);
    harness
        .web_get("/v1/web/session", Some(&bob.cookie()))
        .await;

    let swept = harness.web_sign_in().await;
    harness.clock.advance(SESSION_TTL_SECS);
    harness.control.purge_web_sessions().await.unwrap();

    vec![
        alice.secret.clone(),
        sha256_hex(&alice.secret),
        alice_token,
        wrong_token,
        bob.secret.clone(),
        sha256_hex(&bob.secret),
        swept.secret.clone(),
        sha256_hex(&swept.secret),
        attacker_start.state,
        attacker_start.login_cookie,
    ]
}

fn names(events: &[&Captured]) -> Vec<(String, Option<String>)> {
    events
        .iter()
        .map(|event| (event["event"].clone(), event.get("reason").cloned()))
        .collect()
}

fn pair(name: &str, reason: Option<&str>) -> (String, Option<String>) {
    (name.to_owned(), reason.map(str::to_owned))
}

#[tokio::test(flavor = "multi_thread")]
async fn web_audit_events_have_stable_fields_and_never_carry_secrets() {
    let harness = Harness::with_web().await;
    start_recording();

    let secrets = scenario(&harness).await;

    let events = take_recording();
    let audit: Vec<&Captured> = events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect();
    let signed_in = [
        pair("web.login.started", None),
        pair("login.approved", None),
        pair("web.session.created", None),
    ];
    let mut expected = Vec::new();
    expected.extend(signed_in.clone());
    expected.push(pair("web.csrf.denied", Some("csrf")));
    expected.push(pair("web.csrf.denied", Some("origin")));
    expected.extend(signed_in.clone());
    expected.push(pair("authz.deny", Some("policy_denied")));
    expected.push(pair("web.login.started", None));
    expected.push(pair("login.denied", Some("browser_mismatch")));
    expected.push(pair("web.session.ended", Some("logout")));
    expected.push(pair("web.session.ended", Some("expired")));
    expected.extend(signed_in);
    expected.push(pair("web.session.ended", Some("expired")));
    assert_eq!(names(&audit), expected);

    let field = |index: usize, name: &str| audit[index].get(name).map(String::as_str);
    let login_id = field(0, "login_id").unwrap();
    assert_eq!(field(1, "login_id"), Some(login_id));
    assert_eq!(field(2, "login_id"), Some(login_id));
    assert_eq!(field(1, "kind"), Some("web"));
    assert_eq!(field(1, "email"), Some("alice@example.com"));
    let alice_id = field(1, "user_id").unwrap();
    assert_eq!(field(2, "user_id"), Some(alice_id));
    assert_eq!(field(2, "ip"), Some("198.51.100.7"));
    assert!(field(2, "expires_at").is_some());
    assert_eq!(field(3, "user_id"), Some(alice_id));
    assert_eq!(field(4, "user_id"), Some(alice_id));

    let denied = &audit[8];
    assert_eq!(denied["phase"], "admin");
    assert_eq!(denied["permission"], "nodes.approve");
    assert_eq!(denied["policy_hash"].len(), 64);
    assert_ne!(denied["user_id"], alice_id);
    assert!(field(10, "login_id").is_some_and(|id| id != login_id));
    assert_eq!(field(11, "user_id"), Some(alice_id));

    let everything = format!("{events:?}");
    for secret in secrets {
        assert!(!everything.contains(&secret), "{secret} was logged");
    }
}
