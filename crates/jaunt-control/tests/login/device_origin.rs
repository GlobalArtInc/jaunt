use axum::http::StatusCode;
use serde_json::json;

use crate::device_pages::assert_hardened_page;
use crate::device_support::hidden_field;
use crate::provider::{Identity, form_pairs};
use crate::support::{
    DEFAULT_PEER, Harness, PUBLIC_ORIGIN, Reply, challenge_for, ed25519_public_key_line,
};

fn origin_a_browser_sends(page: &Reply) -> &'static str {
    match page.header("referrer-policy") {
        "no-referrer" => "null",
        _ => PUBLIC_ORIGIN,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_browser_posts_the_public_origin_from_every_page_and_the_post_is_accepted() {
    let harness = Harness::new().await;
    for approve in [true, false] {
        let session = harness.device_start().await;

        let entry = harness.get("/login/device").await;
        let confirmation = harness
            .post_form_as(
                "/login/device",
                DEFAULT_PEER,
                &[("origin", origin_a_browser_sends(&entry))],
                &[("user_code", session.user_code.as_str())],
            )
            .await;
        assert_eq!(
            confirmation.status,
            StatusCode::OK,
            "{}",
            confirmation.text()
        );
        assert!(confirmation.text().contains("Confirm this sign-in request"));
        let token = hidden_field(&confirmation.text(), "token");

        let continued = harness
            .post_form_as(
                "/login/device/continue",
                DEFAULT_PEER,
                &[("origin", origin_a_browser_sends(&confirmation))],
                &[
                    ("login_id", session.login_id.as_str()),
                    ("token", token.as_str()),
                ],
            )
            .await;
        let authorize_url = continued.refresh_target();
        let state = form_pairs(authorize_url.split_once('?').unwrap().1)["state"].clone();
        let cookies = continued.set_cookies();
        let cookie = cookies[0].split(';').next().unwrap();
        let code = harness.provider.grant(&authorize_url, Identity::alice());
        let approval = harness
            .get_with_headers(
                &format!("/v1/login/callback?code={code}&state={state}"),
                &[("cookie", cookie)],
            )
            .await;
        assert_eq!(approval.status, StatusCode::OK, "{}", approval.text());
        let token = hidden_field(&approval.text(), "token");

        let path = if approve {
            "/login/device/approve"
        } else {
            "/login/device/deny"
        };
        let result = harness
            .post_form_as(
                path,
                DEFAULT_PEER,
                &[("origin", origin_a_browser_sends(&approval))],
                &[
                    ("login_id", session.login_id.as_str()),
                    ("token", token.as_str()),
                ],
            )
            .await;
        assert_eq!(result.status, StatusCode::OK, "{path}: {}", result.text());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_opaque_null_origin_is_refused_on_every_form_post() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let token = harness.confirmation_token(&session).await;
    let null = [("origin", "null")];
    let code_form = [("user_code", session.user_code.as_str())];
    let flow = [
        ("login_id", session.login_id.as_str()),
        ("token", token.as_str()),
    ];

    for (path, fields) in [
        ("/login/device", &code_form[..]),
        ("/login/device/continue", &flow[..]),
        ("/login/device/approve", &flow[..]),
        ("/login/device/deny", &flow[..]),
    ] {
        let reply = harness
            .post_form_as(path, DEFAULT_PEER, &null, fields)
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{path}");
    }

    let own = [("origin", PUBLIC_ORIGIN)];
    let allowed = harness
        .post_form_as("/login/device/continue", DEFAULT_PEER, &own, &flow)
        .await;
    allowed.refresh_target();
}

#[tokio::test(flavor = "multi_thread")]
async fn api_responses_keep_no_referrer_while_pages_use_strict_origin() {
    let harness = Harness::new().await;
    let challenge = challenge_for("verifier-0000000000000000000000000000000000");
    let started = harness
        .post_json(
            "/v1/login/device/start",
            &json!({"code_challenge": challenge, "code_challenge_method": "S256"}),
        )
        .await;
    let rejected = harness
        .post_json("/v1/login/device/start", &json!({}))
        .await;
    let session = harness.device_start().await;
    let polled = harness
        .poll(&session, &ed25519_public_key_line("a@b"))
        .await;
    let page = harness.get("/login/device").await;
    let approval = harness.sign_in(&session).await.reply;

    for (name, reply) in [
        ("start", &started),
        ("rejected start", &rejected),
        ("poll", &polled),
    ] {
        assert_eq!(reply.header("content-type"), "application/json", "{name}");
        assert_eq!(reply.header("referrer-policy"), "no-referrer", "{name}");
        assert_eq!(reply.header("cache-control"), "no-store", "{name}");
    }
    for (name, reply) in [("entry", &page), ("approval", &approval)] {
        assert_eq!(reply.header("referrer-policy"), "strict-origin", "{name}");
        assert_eq!(reply.header("cache-control"), "no-store", "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_callback_failure_page_uses_the_strict_page_headers() {
    let harness = Harness::new().await;

    for (name, query) in [
        ("no query", ""),
        ("unknown state", "?code=x&state=never-issued"),
        ("no state", "?code=x"),
        ("duplicated state", "?state=a&state=b"),
    ] {
        let reply = harness.get(&format!("/v1/login/callback{query}")).await;

        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_hardened_page(name, &reply);
        assert!(reply.text().contains("Sign-in failed"), "{name}");
    }
}
