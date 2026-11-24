use axum::http::{Method, StatusCode};
use jaunt_store::LoginRequestState;
use serde_json::json;

use crate::device_support::hidden_field;
use crate::provider::Identity;
use crate::support::{DEFAULT_PEER, Harness, Options, PUBLIC_ORIGIN, Reply};

const EXPECTED_CSP: &str = "default-src 'none'; form-action 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'";
const EVIL_ORIGIN: &str = "https://evil.example";
const CLIENT_LABEL: &str = "Client label (unverified, supplied by the requester)";

pub fn assert_hardened_page(name: &str, reply: &Reply) {
    assert_eq!(
        reply.header("content-type"),
        "text/html; charset=utf-8",
        "{name}"
    );
    assert_eq!(
        reply.header("content-security-policy"),
        EXPECTED_CSP,
        "{name}"
    );
    assert_eq!(reply.header("x-frame-options"), "DENY", "{name}");
    assert_eq!(reply.header("cache-control"), "no-store", "{name}");
    assert_eq!(reply.header("referrer-policy"), "strict-origin", "{name}");
    assert_eq!(reply.header("x-content-type-options"), "nosniff", "{name}");
    let html = reply.text();
    for forbidden in ["<script", "<style", " style=", " onclick=", "javascript:"] {
        assert!(!html.contains(forbidden), "{name}: {forbidden}");
    }
    assert!(html.contains("href=\"/static/login.css\""), "{name}");
    for form in html.split("<form").skip(1) {
        assert!(
            form.starts_with(" method=\"post\" action=\"/login/device"),
            "{name}: {form}"
        );
    }
}

fn cell_after<'a>(html: &'a str, label: &str) -> &'a str {
    let marker = format!("<dt>{label}</dt><dd");
    let start = html
        .find(&marker)
        .unwrap_or_else(|| panic!("no {label} in {html}"))
        + marker.len();
    let content = html[start..].find('>').unwrap() + start + 1;
    let end = html[content..].find("</dd>").unwrap() + content;
    &html[content..end]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_confirmation_page_shows_who_is_asking_and_changes_no_state() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;

    let reply = harness.enter_code(&session.user_code).await;

    assert_eq!(reply.status, StatusCode::OK);
    let html = reply.text();
    assert_eq!(cell_after(&html, CLIENT_LABEL), "build host");
    assert_eq!(cell_after(&html, "Requested from"), "198.51.100.7");
    assert_eq!(cell_after(&html, "Code"), session.user_code);
    let when = cell_after(&html, "Requested at");
    assert_eq!(when.len(), 23, "{when}");
    assert!(when.starts_with("20") && when.ends_with(" UTC"), "{when}");
    assert!(html.contains("Continue to sign in"));
    assert!(html.contains("action=\"/login/device/continue\""));
    assert_eq!(hidden_field(&html, "login_id"), session.login_id);

    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.user_id, None);
    assert_eq!(harness.control.pending_len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_approval_page_names_the_identity_and_offers_both_buttons() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;

    let page = harness.sign_in(&session).await;

    let html = page.reply.text();
    assert!(html.contains("Approve sign-in for the Jaunt CLI?"));
    assert_eq!(cell_after(&html, "Signed in as"), "alice@example.com");
    assert_eq!(cell_after(&html, CLIENT_LABEL), "build host");
    assert_eq!(cell_after(&html, "Requested from"), "198.51.100.7");
    assert!(cell_after(&html, "Requested at").ends_with(" UTC"));
    assert!(html.contains("action=\"/login/device/approve\""));
    assert!(html.contains("action=\"/login/device/deny\""));
    assert!(html.contains(">Approve</button>") && html.contains(">Deny</button>"));
    assert_eq!(page.token.len(), 43);
    assert_eq!(hidden_field(&html, "login_id"), session.login_id);
    assert_eq!(html.matches(&page.token).count(), 2);
}

type Sent = &'static [(&'static str, &'static str)];
type AddressCase = (Option<&'static str>, Sent, &'static str);

const FORWARDED: Sent = &[("x-forwarded-for", "203.0.113.1, 192.0.2.77")];
const INVALID: Sent = &[("x-forwarded-for", "203.0.113.1, unknown")];
const REAL_IP: Sent = &[("x-real-ip", "192.0.2.9")];

#[tokio::test(flavor = "multi_thread")]
async fn the_requester_address_comes_from_the_configured_header_or_else_the_peer() {
    let cases: [AddressCase; 5] = [
        (Some("x-forwarded-for"), FORWARDED, "192.0.2.77"),
        (Some("x-forwarded-for"), INVALID, "198.51.100.7"),
        (Some("x-forwarded-for"), &[], "198.51.100.7"),
        (Some("x-real-ip"), REAL_IP, "192.0.2.9"),
        (None, FORWARDED, "198.51.100.7"),
    ];
    for (header, sent, shown) in cases {
        let harness = Harness::with(Options {
            client_ip_header: header,
            ..Options::default()
        })
        .await;
        let session = harness
            .device_start_as(Some("build host"), DEFAULT_PEER, sent)
            .await;

        let confirmation = harness.enter_code(&session.user_code).await.text();
        let approval = harness.sign_in(&session).await.reply.text();

        assert_eq!(
            cell_after(&confirmation, "Requested from"),
            shown,
            "{header:?} {sent:?}"
        );
        assert_eq!(
            cell_after(&approval, "Requested from"),
            shown,
            "{header:?} {sent:?}"
        );
        let stored = harness
            .store
            .login_requests()
            .get(&session.login_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.requester_ip.as_deref(), Some(shown));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn labels_and_identities_are_escaped_wherever_they_are_shown() {
    let harness = Harness::new().await;
    let label = "<script>alert('x')</script>&\"q\"";
    let session = harness
        .device_start_as(Some(label), DEFAULT_PEER, &[])
        .await;
    let identity = Identity {
        subject: "user-2".to_owned(),
        email: "o'brien&co@example.com".to_owned(),
        email_verified: true,
        username: "obrien".to_owned(),
    };

    let confirmation = harness.enter_code(&session.user_code).await.text();
    let approval = harness.sign_in_as(&session, identity).await.reply.text();

    let escaped_label = "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;&quot;q&quot;";
    for html in [&confirmation, &approval] {
        assert_eq!(cell_after(html, CLIENT_LABEL), escaped_label);
        assert!(!html.contains("<script"));
    }
    assert_eq!(
        cell_after(&approval, "Signed in as"),
        "o&#39;brien&amp;co@example.com"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_page_carries_the_hardening_headers_and_loads_only_the_local_stylesheet() {
    let harness = Harness::new().await;
    let denied = harness.device_start().await;
    let denied_page = harness.sign_in(&denied).await;
    let approved = harness.device_start().await;
    let approved_page = harness.sign_in(&approved).await;
    let provider_error = harness.device_start().await;
    let provider_error_flow = harness.continue_flow(&provider_error).await;
    let mismatch = harness.device_start().await;
    let mismatch_flow = harness.continue_flow(&mismatch).await;

    let replies = [
        ("entry", harness.get("/login/device").await),
        ("rejected code", harness.enter_code("ZZZZ-ZZZZ").await),
        (
            "confirmation",
            harness
                .enter_code(&harness.device_start().await.user_code)
                .await,
        ),
        ("approval", denied_page.reply),
        (
            "denied",
            harness
                .deny_device(&denied.login_id, &denied_page.token)
                .await,
        ),
        (
            "approved",
            harness
                .approve_device(&approved.login_id, &approved_page.token)
                .await,
        ),
        (
            "replay",
            harness
                .approve_device(&approved.login_id, &approved_page.token)
                .await,
        ),
        (
            "origin refused",
            harness
                .post_form_as(
                    "/login/device",
                    DEFAULT_PEER,
                    &[("origin", EVIL_ORIGIN)],
                    &[("user_code", "WXYZ-2345")],
                )
                .await,
        ),
        (
            "malformed",
            harness.post_form("/login/device/continue", &[]).await,
        ),
        (
            "provider error",
            harness
                .get_with_headers(
                    &format!(
                        "/v1/login/callback?error=access_denied&state={}",
                        provider_error_flow.state
                    ),
                    &[("cookie", &provider_error_flow.cookie)],
                )
                .await,
        ),
        (
            "browser mismatch",
            harness
                .callback(&format!(
                    "error=access_denied&state={}",
                    mismatch_flow.state
                ))
                .await,
        ),
        ("continue", provider_error_flow.reply),
    ];

    for (name, reply) in &replies {
        assert_hardened_page(name, reply);
    }
    let statuses: Vec<StatusCode> = replies.iter().map(|(_, reply)| reply.status).collect();
    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::OK,
            StatusCode::BAD_REQUEST,
            StatusCode::FORBIDDEN,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_REQUEST,
            StatusCode::OK,
        ]
    );

    let stylesheet = harness.get("/static/login.css").await;
    assert_eq!(stylesheet.status, StatusCode::OK);
    assert_eq!(stylesheet.header("content-type"), "text/css");
    assert_eq!(stylesheet.header("cache-control"), "no-store");
    assert_eq!(stylesheet.header("x-content-type-options"), "nosniff");
    assert!(stylesheet.text().contains("body{"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_busy_or_throttled_response_is_a_hardened_page_too() {
    let harness = Harness::new().await;
    for _ in 0..10 {
        harness.enter_code("ZZZZ-ZZZZ").await;
    }

    let throttled = harness.enter_code("ZZZZ-ZZZZ").await;

    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert_hardened_page("throttled", &throttled);
    assert_eq!(throttled.header("retry-after"), "300");
}

#[tokio::test(flavor = "multi_thread")]
async fn posts_from_another_origin_are_refused_before_they_do_anything() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let token = harness.confirmation_token(&session).await;
    let foreign = [("origin", EVIL_ORIGIN)];
    let own = [("origin", PUBLIC_ORIGIN)];

    let code_form = [("user_code", session.user_code.as_str())];
    let refused = harness
        .post_form_as("/login/device", DEFAULT_PEER, &foreign, &code_form)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert!(!refused.text().contains(&session.login_id));

    let flow = [
        ("login_id", session.login_id.as_str()),
        ("token", token.as_str()),
    ];
    let refused = harness
        .post_form_as("/login/device/continue", DEFAULT_PEER, &foreign, &flow)
        .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(harness.control.pending_len(), 0);
    let allowed = harness
        .post_form_as("/login/device/continue", DEFAULT_PEER, &own, &flow)
        .await;
    allowed.refresh_target();

    let page = harness.sign_in(&session).await;
    let flow = [
        ("login_id", session.login_id.as_str()),
        ("token", page.token.as_str()),
    ];
    for path in ["/login/device/approve", "/login/device/deny"] {
        let refused = harness
            .post_form_as(path, DEFAULT_PEER, &foreign, &flow)
            .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path}");
        let doubled = harness
            .post_form_as(
                path,
                DEFAULT_PEER,
                &[("origin", PUBLIC_ORIGIN), ("origin", PUBLIC_ORIGIN)],
                &flow,
            )
            .await;
        assert_eq!(doubled.status, StatusCode::FORBIDDEN, "{path}");
    }
    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);

    let approved = harness
        .post_form_as("/login/device/approve", DEFAULT_PEER, &own, &flow)
        .await;
    assert_eq!(approved.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_device_flag_every_device_route_is_absent_and_the_loopback_flow_works() {
    let harness = Harness::with(Options {
        device_login: false,
        ..Options::default()
    })
    .await;
    let routes = [
        (Method::POST, "/v1/login/device/start"),
        (Method::POST, "/v1/login/device/poll"),
        (Method::GET, "/login/device"),
        (Method::POST, "/login/device"),
        (Method::POST, "/login/device/continue"),
        (Method::POST, "/login/device/approve"),
        (Method::POST, "/login/device/deny"),
        (Method::GET, "/static/login.css"),
    ];

    for (method, path) in routes {
        let body = (method == Method::POST)
            .then(|| ("application/json", serde_json::to_vec(&json!({})).unwrap()));
        let reply = harness
            .request_as(method.clone(), path, DEFAULT_PEER, &[], body)
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(reply.body.is_empty(), "{method} {path}");
    }

    let session = harness.begin().await;
    assert_eq!(harness.approve(&session).await.status, StatusCode::FOUND);
    let reply = harness.get("/healthz").await;
    assert_eq!(reply.status, StatusCode::OK);
}
