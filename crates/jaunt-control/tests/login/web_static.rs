use axum::http::{Method, StatusCode};

use crate::provider::Identity;
use crate::support::{Harness, Options, Reply};
use crate::web_support::APPROVER_AND_OPS_ROLES;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

fn entry_bytes() -> &'static [u8] {
    jaunt_web::entry().unwrap().bytes
}

fn asset_bytes(path: &str) -> &'static [u8] {
    jaunt_web::find(path).unwrap().bytes
}

fn assert_secured(name: &str, reply: &Reply, cache_control: &str) {
    assert_eq!(reply.header("content-security-policy"), CSP, "{name}");
    assert_eq!(reply.header("x-content-type-options"), "nosniff", "{name}");
    assert_eq!(reply.header("x-frame-options"), "DENY", "{name}");
    assert_eq!(reply.header("referrer-policy"), "strict-origin", "{name}");
    assert_eq!(
        reply.header("cross-origin-opener-policy"),
        "same-origin",
        "{name}"
    );
    assert_eq!(
        reply.header("strict-transport-security"),
        "max-age=31536000",
        "{name}"
    );
    assert_eq!(reply.header("cache-control"), cache_control, "{name}");
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_json_assets_and_errors_all_carry_the_strict_headers() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let signed = harness.web_sign_in().await;
    let start = harness.web_start("").await;
    let refused = harness.web_callback(&start, Identity::alice(), None).await;
    let etag = harness.web_get("/assets/app.js", None).await;
    let tag = etag.header("etag").to_owned();

    let replies = [
        ("index page", harness.web_get("/", None).await, "no-cache"),
        (
            "spa route",
            harness.web_get("/nodes", None).await,
            "no-cache",
        ),
        ("asset", etag, "public, max-age=3600"),
        (
            "stylesheet",
            harness.web_get("/assets/app.css", None).await,
            "public, max-age=3600",
        ),
        (
            "json 401",
            harness.web_get("/v1/web/session", None).await,
            "no-store",
        ),
        (
            "json 200",
            harness
                .web_get("/v1/web/session", Some(&signed.cookie()))
                .await,
            "no-store",
        ),
        (
            "json 401 admin",
            harness.web_get("/v1/admin/whoami", None).await,
            "no-store",
        ),
        (
            "login redirect",
            harness.get("/v1/web/login").await,
            "no-store",
        ),
        (
            "404",
            harness.web_get("/assets/../x", None).await,
            "no-store",
        ),
        (
            "405",
            harness.web_request(Method::POST, "/", None, &[]).await,
            "no-store",
        ),
        (
            "304",
            harness
                .web_request(
                    Method::GET,
                    "/assets/app.js",
                    None,
                    &[("if-none-match", &tag)],
                )
                .await,
            "public, max-age=3600",
        ),
        ("sign-in page", signed.reply, "no-store"),
        ("sign-in failure page", refused, "no-store"),
    ];

    for (name, reply, cache_control) in &replies {
        assert_secured(name, reply, cache_control);
    }
    assert_eq!(
        replies[0].1.header("content-type"),
        "text/html; charset=utf-8"
    );
    assert_eq!(replies[4].1.header("content-type"), "application/json");
}

#[tokio::test(flavor = "multi_thread")]
async fn embedded_files_are_served_with_their_type_a_strong_etag_and_conditional_replies() {
    let harness = Harness::with_web().await;

    for (path, content_type) in [
        ("/assets/app.js", "text/javascript; charset=utf-8"),
        ("/assets/app.css", "text/css; charset=utf-8"),
    ] {
        let reply = harness.web_get(path, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.header("content-type"), content_type, "{path}");
        assert_eq!(
            reply.body,
            asset_bytes(path.trim_start_matches('/')),
            "{path}"
        );
        assert_eq!(reply.header("content-length"), reply.body.len().to_string());
        let etag = reply.header("etag").to_owned();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");

        for matching in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"other\", {etag}"),
            "*".to_owned(),
        ] {
            let not_modified = harness
                .web_request(Method::GET, path, None, &[("if-none-match", &matching)])
                .await;
            assert_eq!(not_modified.status, StatusCode::NOT_MODIFIED, "{matching}");
            assert!(not_modified.body.is_empty());
            assert_eq!(not_modified.header("etag"), etag);
        }
        let changed = harness
            .web_request(Method::GET, path, None, &[("if-none-match", "\"other\"")])
            .await;
        assert_eq!(changed.status, StatusCode::OK);
        assert_eq!(changed.body, reply.body);
    }
    let js = harness.web_get("/assets/app.js", None).await;
    let css = harness.web_get("/assets/app.css", None).await;
    assert_ne!(js.header("etag"), css.header("etag"));
}

#[tokio::test(flavor = "multi_thread")]
async fn head_returns_the_headers_of_get_without_a_body() {
    let harness = Harness::with_web().await;

    for path in ["/", "/assets/app.js", "/some/route"] {
        let get = harness.web_get(path, None).await;
        let head = harness.web_request(Method::HEAD, path, None, &[]).await;

        assert_eq!(head.status, StatusCode::OK, "{path}");
        assert!(head.body.is_empty(), "{path}");
        for name in ["content-type", "content-length", "etag", "cache-control"] {
            assert_eq!(head.header(name), get.header(name), "{path} {name}");
        }
        assert_eq!(head.header("content-length"), get.body.len().to_string());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn paths_that_try_to_leave_the_table_are_not_found() {
    let harness = Harness::with_web().await;
    let paths = [
        "/assets/../x",
        "/assets/..",
        "/assets/./app.js",
        "/assets/%2e%2e/x",
        "/assets/%2E%2E/x",
        "/%2e%2e/%2e%2e/etc/passwd",
        "/assets/..%2fx",
        "/assets/..%2Fx",
        "/assets/a%2fb",
        "/assets/a%5cb",
        "/assets/a%5Cb",
        "/assets/a%00b",
        "/assets//app.js",
        "/assets/app.js%20",
        "/assets/app.js;x",
    ];

    for path in paths {
        let reply = harness.web_get(path, None).await;

        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert!(reply.body.is_empty(), "{path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_paths_fall_back_to_the_entry_page_except_reserved_and_asset_paths() {
    let harness = Harness::with_web().await;

    for path in [
        "/",
        "/nodes",
        "/nodes/web-01/",
        "/index.html",
        "/a/b/c.d",
        "/login",
        "/Login",
        "/staticfiles",
        "/v1x",
    ] {
        let reply = harness.web_get(path, None).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.body, entry_bytes(), "{path}");
        assert_eq!(reply.header("cache-control"), "no-cache", "{path}");
    }
    for path in [
        "/v1",
        "/v1/",
        "/v1/nope",
        "/v1/web/nope",
        "/V1/web/session",
        "/V1",
        "/static",
        "/static/nope.css",
        "/STATIC/x",
        "/Static",
        "/assets",
        "/assets/",
        "/assets/missing.js",
        "/assets/app.js/",
        "/login/",
        "/login/other",
        "/Login/Device",
    ] {
        let reply = harness.web_get(path, None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert!(reply.body.is_empty(), "{path}");
    }
    let post = harness
        .web_request(Method::POST, "/v1/nope", None, &[])
        .await;
    assert_eq!(post.status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_device_login_off_its_pages_are_not_found_rather_than_the_spa_shell() {
    let harness = Harness::with(Options {
        web: true,
        device_login: false,
        ..Options::default()
    })
    .await;

    for (method, path) in [
        (Method::GET, "/login/device"),
        (Method::POST, "/login/device"),
        (Method::POST, "/login/device/continue"),
        (Method::POST, "/login/device/approve"),
        (Method::POST, "/login/device/deny"),
        (Method::GET, "/static/login.css"),
        (Method::POST, "/v1/login/device/start"),
        (Method::POST, "/v1/login/device/poll"),
    ] {
        let reply = harness.web_request(method.clone(), path, None, &[]).await;

        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(reply.body.is_empty(), "{method} {path}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn only_get_and_head_are_accepted_for_static_content() {
    let harness = Harness::with_web().await;

    for path in ["/", "/assets/app.js", "/nodes"] {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            let reply = harness.web_request(method.clone(), path, None, &[]).await;

            assert_eq!(
                reply.status,
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {path}"
            );
            assert_eq!(reply.header("allow"), "GET, HEAD");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_web_flag_off_no_web_route_exists() {
    let harness = Harness::new().await;

    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/nodes"),
        (Method::GET, "/assets/app.js"),
        (Method::GET, "/v1/web/login"),
        (Method::GET, "/v1/web/session"),
        (Method::POST, "/v1/web/logout"),
        (Method::GET, "/v1/admin/whoami"),
    ] {
        let reply = harness.web_request(method.clone(), path, None, &[]).await;

        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert!(reply.body.is_empty(), "{method} {path}");
        assert!(reply.headers.get("content-security-policy").is_none());
    }
    assert_eq!(harness.get("/healthz").await.status, StatusCode::OK);
}
