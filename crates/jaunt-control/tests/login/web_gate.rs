use axum::Router;
use axum::http::{Method, StatusCode};
use axum::routing::get;
use jaunt_control::Control;

use crate::support::{Harness, Options, PUBLIC_ORIGIN};
use crate::web_support::{APPROVER_AND_OPS_ROLES, SESSION_COOKIE, SESSION_TTL_SECS, bob};

const METHODS: [Method; 7] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::PATCH,
    Method::DELETE,
    Method::OPTIONS,
];
const ADMIN_PATHS: [&str; 5] = [
    "/v1/admin/whoami",
    "/v1/admin/bare",
    "/v1/admin/nope",
    "/v1/admin",
    "/v1/admin/",
];

async fn bare() -> &'static str {
    "bare"
}

async fn harness_with_a_route_that_forgets_its_extractor() -> Harness {
    let extra: Router<Control> = Router::new().route("/v1/admin/bare", get(bare).post(bare));
    let harness = Harness::with(Options {
        web: true,
        extra_web_routes: Some(extra),
        ..Options::default()
    })
    .await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    harness
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_valid_session_every_admin_path_and_method_is_unauthorised() {
    let harness = harness_with_a_route_that_forgets_its_extractor().await;
    let expired = harness.web_sign_in().await;
    harness.clock.advance(SESSION_TTL_SECS);
    let unknown = format!("{SESSION_COOKIE}=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let cookies = [None, Some(unknown), Some(expired.cookie())];

    for cookie in &cookies {
        for method in &METHODS {
            for path in ADMIN_PATHS {
                let reply = harness
                    .web_request(
                        method.clone(),
                        path,
                        cookie.as_deref(),
                        &[("origin", PUBLIC_ORIGIN)],
                    )
                    .await;

                assert_eq!(
                    reply.status,
                    StatusCode::UNAUTHORIZED,
                    "{method} {path} {cookie:?}"
                );
                if method != Method::HEAD {
                    assert_eq!(reply.error_code(), "unauthorized", "{method} {path}");
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_session_opens_the_gate_but_each_route_still_checks_its_own_permission() {
    let harness = harness_with_a_route_that_forgets_its_extractor().await;
    let without_rights = harness.web_sign_in_with("", bob()).await;
    let with_rights = harness.web_sign_in().await;
    let token = harness.csrf_token(&without_rights).await;
    let guarded = [("x-jaunt-csrf", token.as_str()), ("origin", PUBLIC_ORIGIN)];
    let cookie = without_rights.cookie();

    for (method, path, status) in [
        (Method::GET, "/v1/admin/whoami", StatusCode::FORBIDDEN),
        (Method::HEAD, "/v1/admin/whoami", StatusCode::FORBIDDEN),
        (Method::GET, "/v1/admin/bare", StatusCode::OK),
        (Method::HEAD, "/v1/admin/bare", StatusCode::OK),
        (Method::GET, "/v1/admin/nope", StatusCode::NOT_FOUND),
        (Method::GET, "/v1/admin", StatusCode::NOT_FOUND),
    ] {
        let reply = harness
            .web_request(method.clone(), path, Some(&cookie), &[])
            .await;
        assert_eq!(reply.status, status, "{method} {path}");
    }
    let bare = harness
        .web_request(Method::GET, "/v1/admin/bare", Some(&cookie), &[])
        .await;
    assert_eq!(bare.text(), "bare");

    let no_token = harness
        .web_request(Method::POST, "/v1/admin/bare", Some(&cookie), &[])
        .await;
    assert_eq!(no_token.status, StatusCode::FORBIDDEN);
    let with_token = harness
        .web_request(Method::POST, "/v1/admin/bare", Some(&cookie), &guarded)
        .await;
    assert_eq!(with_token.status, StatusCode::OK);
    let wrong_method = harness
        .web_request(Method::PUT, "/v1/admin/bare", Some(&cookie), &guarded)
        .await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);

    for path in ["/v1/admin/whoami", "/v1/admin/bare"] {
        let reply = harness
            .web_request(Method::GET, path, Some(&with_rights.cookie()), &[])
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
    }
}
