use axum::http::StatusCode;
use jaunt_ca::Uuid;
use jaunt_store::LoginRequestState;
use serde_json::{Value, json};

use crate::support::{Harness, LOGIN_TTL_SECS, Options, challenge_for};

fn valid_start(harness: &Harness) -> Value {
    json!({
        "code_challenge": challenge_for(&harness.next_verifier()),
        "code_challenge_method": "S256",
        "redirect_port": 45123,
    })
}

fn with(mut body: Value, key: &str, value: Value) -> Value {
    body[key] = value;
    body
}

#[tokio::test(flavor = "multi_thread")]
async fn start_creates_a_loopback_request_and_returns_the_provider_url() {
    let harness = Harness::new().await;
    let verifier = harness.next_verifier();
    let reply = harness
        .start_body(&json!({
            "code_challenge": challenge_for(&verifier),
            "code_challenge_method": "S256",
            "redirect_port": 45123,
            "client_label": "work laptop",
        }))
        .await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("content-type"), "application/json");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    let body = reply.json();
    let login_id = body["login_id"].as_str().unwrap();
    assert!(Uuid::parse_str(login_id).is_ok());
    assert!(
        body["authorize_url"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{}/authorize?", harness.provider.base))
    );

    let stored = harness
        .store
        .login_requests()
        .get(login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.kind, "loopback");
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.pkce_challenge, challenge_for(&verifier));
    assert_eq!(stored.client_label.as_deref(), Some("work laptop"));
    assert_eq!(stored.created_at, harness.clock.now_secs());
    assert_eq!(
        stored.expires_at,
        harness.clock.now_secs() + i64::try_from(LOGIN_TTL_SECS).unwrap()
    );
    assert_eq!(harness.control.pending_len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn start_accepts_the_boundary_values() {
    let harness = Harness::new().await;
    for (port, label) in [
        (json!(1024), Value::Null),
        (json!(65535), json!("x")),
        (json!(45123), json!("l".repeat(64))),
    ] {
        let body = with(
            with(valid_start(&harness), "redirect_port", port),
            "client_label",
            label,
        );
        let reply = harness.start_body(&body).await;
        assert_eq!(reply.status, StatusCode::OK, "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn start_rejects_malformed_requests() {
    let harness = Harness::new().await;
    let valid_challenge = challenge_for(&harness.next_verifier());
    let cases = [
        (
            "short challenge",
            with(
                valid_start(&harness),
                "code_challenge",
                json!(&valid_challenge[1..]),
            ),
        ),
        (
            "long challenge",
            with(
                valid_start(&harness),
                "code_challenge",
                json!(format!("{valid_challenge}A")),
            ),
        ),
        (
            "padded challenge",
            with(
                valid_start(&harness),
                "code_challenge",
                json!(format!("{}=", &valid_challenge[1..])),
            ),
        ),
        (
            "standard base64 challenge",
            with(
                valid_start(&harness),
                "code_challenge",
                json!(format!("{}+", &valid_challenge[1..])),
            ),
        ),
        (
            "plain method",
            with(
                valid_start(&harness),
                "code_challenge_method",
                json!("plain"),
            ),
        ),
        (
            "lowercase method",
            with(
                valid_start(&harness),
                "code_challenge_method",
                json!("s256"),
            ),
        ),
        (
            "port zero",
            with(valid_start(&harness), "redirect_port", json!(0)),
        ),
        (
            "port 80",
            with(valid_start(&harness), "redirect_port", json!(80)),
        ),
        (
            "port 1023",
            with(valid_start(&harness), "redirect_port", json!(1023)),
        ),
        (
            "port 65536",
            with(valid_start(&harness), "redirect_port", json!(65536)),
        ),
        (
            "port 70000",
            with(valid_start(&harness), "redirect_port", json!(70000)),
        ),
        (
            "negative port",
            with(valid_start(&harness), "redirect_port", json!(-1)),
        ),
        (
            "fractional port",
            with(valid_start(&harness), "redirect_port", json!(8080.5)),
        ),
        (
            "string port",
            with(valid_start(&harness), "redirect_port", json!("8080")),
        ),
        (
            "empty label",
            with(valid_start(&harness), "client_label", json!("")),
        ),
        (
            "long label",
            with(valid_start(&harness), "client_label", json!("l".repeat(65))),
        ),
        (
            "control character label",
            with(valid_start(&harness), "client_label", json!("a\u{7}b")),
        ),
        (
            "non-ascii label",
            with(valid_start(&harness), "client_label", json!("caf\u{e9}")),
        ),
        (
            "unknown field",
            with(
                valid_start(&harness),
                "redirect_host",
                json!("evil.example"),
            ),
        ),
        (
            "missing challenge",
            json!({"code_challenge_method": "S256", "redirect_port": 45123}),
        ),
    ];
    for (name, body) in cases {
        let reply = harness.start_body(&body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(reply.error_code(), "invalid_request", "{name}");
    }
    assert_eq!(harness.control.pending_len(), 0);

    let not_json = harness
        .post_raw("/v1/login/start", Some("application/json"), b"{".to_vec())
        .await;
    assert_eq!(not_json.status, StatusCode::BAD_REQUEST);
    let wrong_type = harness
        .post_raw(
            "/v1/login/start",
            Some("text/plain"),
            serde_json::to_vec(&valid_start(&harness)).unwrap(),
        )
        .await;
    assert_eq!(wrong_type.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong_type.error_code(), "invalid_request");
}

#[tokio::test(flavor = "multi_thread")]
async fn start_refuses_new_logins_when_the_pending_map_is_full() {
    let harness = Harness::with(Options {
        pending_capacity: 2,
        ..Options::default()
    })
    .await;
    harness.begin().await;
    harness.begin().await;

    let refused = harness.start_body(&valid_start(&harness)).await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.error_code(), "busy");
    assert_eq!(harness.control.pending_len(), 2);

    harness.clock.advance(LOGIN_TTL_SECS + 1);
    let accepted = harness.start_body(&valid_start(&harness)).await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(harness.control.pending_len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sweeping_drops_only_expired_pending_logins() {
    let harness = Harness::new().await;
    harness.begin().await;
    harness.clock.advance(LOGIN_TTL_SECS - 10);
    harness.begin().await;
    assert_eq!(harness.control.sweep_expired(), 0);

    harness.clock.advance(11);
    assert_eq!(harness.control.sweep_expired(), 1);
    assert_eq!(harness.control.pending_len(), 1);
}
