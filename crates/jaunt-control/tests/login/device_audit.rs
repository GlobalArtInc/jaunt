use axum::http::StatusCode;

use crate::audit::{Captured, start_recording, take_recording};
use crate::device_support::hidden_field;
use crate::provider::Identity;
use crate::support::{Harness, LOGIN_TTL_SECS, ed25519_public_key_line};

const REQUESTER: &str = "203.0.113.9:40000";
const GUESSER: &str = "203.0.113.50:40000";

fn base64_part(line: &str) -> String {
    line.split(' ').nth(1).unwrap().to_owned()
}

fn cookie_value(pair: &str) -> String {
    pair.split_once('=').unwrap().1.to_owned()
}

async fn scenario() -> Vec<String> {
    let harness = Harness::new().await;
    let key = ed25519_public_key_line("alice@server");

    let first = harness
        .device_start_as(Some("build host"), REQUESTER, &[])
        .await;
    harness.enter_code_as("ZZZZ-ZZZZ", GUESSER, &[]).await;
    let continued = harness.continue_flow(&first).await;
    let provider_code = harness
        .provider
        .grant(&continued.authorize_url, Identity::alice());
    let page = harness
        .get_with_headers(
            &format!(
                "/v1/login/callback?code={provider_code}&state={}",
                continued.state
            ),
            &[("cookie", &continued.cookie)],
        )
        .await;
    let approval_token = hidden_field(&page.text(), "token");
    harness
        .approve_device(&first.login_id, &approval_token)
        .await;
    harness.clock.advance(5);
    let issued = harness.poll(&first, &key).await;
    assert_eq!(issued.status, StatusCode::OK);
    let issued = issued.json();
    harness
        .approve_device(&first.login_id, &approval_token)
        .await;

    let hijacked = harness.device_start().await;
    let hijacked_flow = harness.continue_flow(&hijacked).await;
    let refused = harness
        .provider_callback(&hijacked_flow, Identity::alice(), None)
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);

    let second = harness.device_start().await;
    let second_page = harness.sign_in(&second).await;
    harness
        .deny_device(&second.login_id, &second_page.token)
        .await;
    harness
        .poll_with(&second.login_id, &harness.next_verifier(), &key)
        .await;

    vec![
        first.user_code.clone(),
        first.user_code.replace('-', ""),
        hijacked.user_code.clone(),
        hijacked.user_code.replace('-', ""),
        second.user_code.clone(),
        second.user_code.replace('-', ""),
        first.verifier,
        second.verifier,
        continued.continue_token,
        approval_token,
        second_page.token,
        continued.state,
        hijacked_flow.state,
        provider_code,
        cookie_value(&continued.cookie),
        cookie_value(&hijacked_flow.cookie),
        base64_part(&key),
        base64_part(issued["certificate"].as_str().unwrap()),
        issued["api_token"].as_str().unwrap().to_owned(),
    ]
}

#[tokio::test]
async fn device_audit_events_have_stable_fields_and_never_carry_secrets() {
    start_recording();

    let secrets = scenario().await;

    let events = take_recording();
    let audit: Vec<&Captured> = events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect();
    let field = |index: usize, name: &str| audit[index].get(name).map(String::as_str);
    let names: Vec<(&str, Option<&str>)> = audit
        .iter()
        .map(|event| {
            (
                event["event"].as_str(),
                event.get("reason").map(String::as_str),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("login.device.started", None),
            ("login.device.code_failed", None),
            ("login.device.continued", None),
            ("login.approved", None),
            ("cert.issued", None),
            ("login.denied", Some("approval_rejected")),
            ("login.device.started", None),
            ("login.device.continued", None),
            ("login.denied", Some("browser_mismatch")),
            ("login.device.started", None),
            ("login.device.continued", None),
            ("login.denied", Some("user_denied")),
            ("login.finish_failed", Some("bad_verifier")),
        ]
    );

    let first_id = field(0, "login_id").unwrap();
    assert_eq!(field(0, "ip"), Some("203.0.113.9"));
    assert_eq!(field(1, "ip"), Some("203.0.113.50"));
    assert_eq!(field(1, "login_id"), None);
    assert_eq!(field(2, "login_id"), Some(first_id));
    assert_eq!(field(3, "login_id"), Some(first_id));
    assert_eq!(field(3, "kind"), Some("device"));
    assert_eq!(field(3, "email"), Some("alice@example.com"));
    let user_id = field(3, "user_id").unwrap();
    assert_eq!(field(4, "login_id"), Some(first_id));
    assert_eq!(field(4, "user_id"), Some(user_id));
    assert_eq!(field(4, "serial"), Some("1"));
    assert_eq!(field(5, "login_id"), Some(first_id));
    let hijacked_id = field(6, "login_id").unwrap();
    assert_ne!(hijacked_id, first_id);
    assert_eq!(field(7, "login_id"), Some(hijacked_id));
    assert_eq!(field(8, "login_id"), Some(hijacked_id));
    let second_id = field(9, "login_id").unwrap();
    assert_ne!(second_id, hijacked_id);
    assert_eq!(field(10, "login_id"), Some(second_id));
    assert_eq!(field(11, "login_id"), Some(second_id));
    assert_eq!(field(12, "login_id"), Some(second_id));

    let everything = format!("{events:?}");
    for secret in secrets {
        assert!(!everything.contains(&secret), "{secret} was logged");
    }
}

#[tokio::test]
async fn a_lockout_is_reported_once_per_window_with_the_address_and_a_reason() {
    start_recording();
    let harness = Harness::new().await;
    for _ in 0..10 {
        harness.enter_code("ZZZZ-ZZZZ").await;
    }
    for _ in 0..3 {
        let blocked = harness.enter_code("ZZZZ-ZZZZ").await;
        assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let elsewhere = harness
        .enter_code_as("ZZZZ-ZZZZ", "203.0.113.50:40000", &[])
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK);

    harness.clock.advance(LOGIN_TTL_SECS);
    for _ in 0..10 {
        harness.enter_code("ZZZZ-ZZZZ").await;
    }
    for _ in 0..2 {
        harness.enter_code("ZZZZ-ZZZZ").await;
    }

    let events = take_recording();
    let audit: Vec<&Captured> = events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect();
    let lockouts: Vec<&&Captured> = audit
        .iter()
        .filter(|event| event["event"] == "login.device.locked_out")
        .collect();
    assert_eq!(lockouts.len(), 2);
    for lockout in &lockouts {
        assert_eq!(lockout["ip"], "198.51.100.7");
        assert_eq!(lockout["reason"], "ip_limit");
        assert_eq!(lockout.len(), 4, "{lockout:?}");
    }
    let failures = audit
        .iter()
        .filter(|event| event["event"] == "login.device.code_failed")
        .count();
    assert_eq!(failures, 10 + 1 + 10);
}
