use axum::http::StatusCode;
use serde_json::json;

use crate::support::Harness;

#[tokio::test(flavor = "multi_thread")]
async fn every_response_carries_the_hardening_headers() {
    let harness = Harness::new().await;
    let replies = [
        (
            "json error",
            "application/json",
            harness.post_json("/v1/login/finish", &json!({})).await,
        ),
        (
            "html page",
            "text/html; charset=utf-8",
            harness.get("/v1/login/callback").await,
        ),
        (
            "plain text",
            "text/plain; charset=utf-8",
            harness.get("/healthz").await,
        ),
    ];
    for (name, content_type, reply) in &replies {
        assert_eq!(reply.header("content-type"), *content_type, "{name}");
    }

    let bare = harness.get("/v1/whoami").await;
    assert_eq!(bare.status, StatusCode::UNAUTHORIZED);
    for (name, _, reply) in &replies {
        assert_hardened(name, reply);
    }
    assert_hardened("empty 401", &bare);
}

fn assert_hardened(name: &str, reply: &crate::support::Reply) {
    assert_eq!(reply.header("x-content-type-options"), "nosniff", "{name}");
    assert_eq!(reply.header("cache-control"), "no-store", "{name}");
    assert_eq!(reply.header("referrer-policy"), "no-referrer", "{name}");
}
