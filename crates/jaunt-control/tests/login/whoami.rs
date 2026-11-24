use axum::http::StatusCode;
use serde_json::json;

use crate::support::{Harness, Options};

#[tokio::test(flavor = "multi_thread")]
async fn whoami_describes_the_user_until_the_certificate_expires() {
    let harness = Harness::with(Options {
        cert_ttl_secs: 3600,
        ..Options::default()
    })
    .await;
    let login = harness.login().await;
    let token = login["api_token"].as_str().unwrap();
    let issued_at = harness.clock.now_secs();

    let reply = harness.whoami(token).await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(
        reply.json(),
        json!({
            "user_id": login["user_id"],
            "email": "alice@example.com",
            "groups": ["dev", "ops"],
            "cert_serial": login["serial"],
            "token_expires_at": issued_at + 3600,
        })
    );

    harness.clock.advance(3599);
    assert_eq!(harness.whoami(token).await.status, StatusCode::OK);
    harness.clock.advance(1);
    let expired = harness.whoami(token).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn whoami_answers_a_bare_challenge_for_every_unusable_credential() {
    let harness = Harness::new().await;
    let login = harness.login().await;
    let token = login["api_token"].as_str().unwrap();
    let unknown = format!("jt_{}", "A".repeat(43));
    let single_header_cases = [
        ("garbage", "Bearer garbage".to_owned()),
        ("empty token", "Bearer ".to_owned()),
        ("unknown token", format!("Bearer {unknown}")),
        ("wrong scheme", format!("Basic {token}")),
        ("no scheme", token.to_owned()),
        ("double space", format!("Bearer  {token}")),
        ("trailing space", format!("Bearer {token} ")),
    ];
    for (name, authorization) in single_header_cases {
        let reply = harness
            .get_with_headers("/v1/whoami", &[("authorization", &authorization)])
            .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(reply.header("www-authenticate"), "Bearer", "{name}");
        assert!(reply.body.is_empty(), "{name}");
    }

    let none = harness.get("/v1/whoami").await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.header("www-authenticate"), "Bearer");
    assert!(none.body.is_empty());

    let bearer = format!("Bearer {token}");
    let twice = harness
        .get_with_headers(
            "/v1/whoami",
            &[("authorization", &bearer), ("authorization", &bearer)],
        )
        .await;
    assert_eq!(twice.status, StatusCode::UNAUTHORIZED);

    let lowercase = harness
        .get_with_headers(
            "/v1/whoami",
            &[("authorization", &format!("bearer {token}"))],
        )
        .await;
    assert_eq!(lowercase.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn health_check_answers_ok() {
    let harness = Harness::new().await;

    let reply = harness.get("/healthz").await;

    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.text(), "ok");
}
