use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use http_body_util::channel::Channel;
use jaunt_audit::ScopedCapture;
use jaunt_control::RequestLimits;
use jaunt_limits::Rate;
use serde_json::json;

use crate::support::{Harness, Options};

#[tokio::test(flavor = "multi_thread")]
async fn each_unauthenticated_entry_point_limits_one_address_without_touching_another() {
    let one = Rate::new(1, 1).unwrap();
    let harness = Harness::with(Options {
        web: true,
        request_limits: RequestLimits {
            login_start: one,
            login_finish: one,
            device_start: one,
            device_poll: one,
            web_login: one,
            enroll: one,
            enroll_poll: one,
            enrolment_lookup: one,
            ..RequestLimits::default()
        },
        ..Options::default()
    })
    .await;
    let body = || Some(("application/json", b"{}".to_vec()));
    for (method, path) in [
        (Method::POST, "/v1/login/start"),
        (Method::POST, "/v1/login/finish"),
        (Method::POST, "/v1/login/device/start"),
        (Method::POST, "/v1/login/device/poll"),
        (Method::GET, "/v1/web/login"),
        (Method::POST, "/v1/agent/enroll"),
        (Method::POST, "/v1/agent/enroll/poll"),
        (Method::POST, "/v1/admin/enrolments/lookup"),
    ] {
        let send = |peer: &'static str| harness.request_as(method.clone(), path, peer, &[], body());
        let first = send("198.51.100.1:40000").await;
        assert_ne!(first.status, StatusCode::TOO_MANY_REQUESTS, "{path}");

        let second = send("[::ffff:198.51.100.1]:40001").await;
        assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS, "{path}");
        assert_eq!(second.header("retry-after"), "60", "{path}");
        assert_eq!(
            second.json(),
            json!({"error": "too_many_requests", "retry_after": 60}),
            "{path}"
        );
        assert_eq!(second.header("cache-control"), "no-store", "{path}");

        let other = send("198.51.100.2:40000").await;
        assert_ne!(other.status, StatusCode::TOO_MANY_REQUESTS, "{path}");
    }
}

async fn start_as(harness: &Harness, peer: &str, forwarded: &str) -> StatusCode {
    harness
        .request_as(
            Method::POST,
            "/v1/login/start",
            peer,
            &[("x-forwarded-for", forwarded)],
            Some(("application/json", b"{}".to_vec())),
        )
        .await
        .status
}

#[tokio::test(flavor = "multi_thread")]
async fn the_forwarded_address_is_believed_only_from_a_trusted_proxy_and_after_its_trusted_hops() {
    let harness = Harness::with(Options {
        client_ip_header: Some("x-forwarded-for"),
        trusted_proxies: Some(&["198.51.100.0/24"]),
        request_limits: RequestLimits {
            login_start: Rate::new(3, 1).unwrap(),
            ..RequestLimits::default()
        },
        ..Options::default()
    })
    .await;

    let mut rotated = Vec::new();
    for index in 0..10 {
        let forged = format!("192.0.2.{index}");
        rotated.push(start_as(&harness, "203.0.113.66:40000", &forged).await);
    }
    let expected = [
        vec![StatusCode::BAD_REQUEST; 3],
        vec![StatusCode::TOO_MANY_REQUESTS; 7],
    ]
    .concat();
    assert_eq!(rotated, expected);

    let proxy = "198.51.100.7:40000";
    for index in 0..10 {
        let forwarded = format!("192.0.2.{index}");
        let status = start_as(&harness, proxy, &forwarded).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{forwarded}");
    }

    for _ in 0..3 {
        let status = start_as(&harness, proxy, "192.0.2.200, 198.51.100.9").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    for chain in ["192.0.2.200", "10.9.9.9, 192.0.2.200, 198.51.100.1"] {
        let status = start_as(&harness, proxy, chain).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{chain}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn routes_without_their_own_limit_share_one_bucket_but_health_and_static_files_do_not() {
    let harness = Harness::with(Options {
        web: true,
        request_limits: RequestLimits {
            other: Rate::new(2, 1).unwrap(),
            ..RequestLimits::default()
        },
        ..Options::default()
    })
    .await;
    let get = |path: &'static str, peer: &'static str| {
        harness.request_as(Method::GET, path, peer, &[], None)
    };
    let noisy = "192.0.2.1:40000";
    assert_ne!(
        get("/v1/whoami", noisy).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_ne!(
        get("/v1/nodes", noisy).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    for path in [
        "/v1/web/session",
        "/v1/admin/whoami",
        "/v1/login/callback?state=x",
        "/login/device",
    ] {
        assert_eq!(
            get(path, noisy).await.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{path}"
        );
    }
    for path in [
        "/healthz",
        "/static/login.css",
        "/healthz",
        "/static/login.css",
    ] {
        assert_ne!(
            get(path, noisy).await.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{path}"
        );
    }
    assert_ne!(
        get("/v1/whoami", "192.0.2.2:40000").await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limited_address_is_refused_before_its_body_is_read() {
    let harness = Harness::with(Options {
        request_limits: RequestLimits {
            login_start: Rate::new(1, 1).unwrap(),
            ..RequestLimits::default()
        },
        ..Options::default()
    })
    .await;
    let peer = "192.0.2.9:40000";
    let first = start_as(&harness, peer, "").await;
    assert_eq!(first, StatusCode::BAD_REQUEST);

    let (_sender, body) = Channel::<Bytes, std::io::Error>::new(1);
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/v1/login/start")
        .header("content-type", "application/json")
        .body(Body::new(body))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    let refused = tokio::time::timeout(Duration::from_secs(5), harness.send(request))
        .await
        .expect("the limiter waited for a body that never comes");
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test(flavor = "multi_thread")]
async fn limits_follow_the_monotonic_ticker_whatever_the_wall_clock_does() {
    let ticks = Arc::new(AtomicU64::new(0));
    let reading = Arc::clone(&ticks);
    let harness = Harness::with(Options {
        request_limits: RequestLimits {
            login_start: Rate::new(1, 1).unwrap(),
            ..RequestLimits::default()
        },
        ticker: Some(Arc::new(move || {
            Duration::from_secs(reading.load(Ordering::SeqCst))
        })),
        ..Options::default()
    })
    .await;
    let peer = "192.0.2.9:40000";
    let retry_after = |reply: &crate::support::Reply| reply.json()["retry_after"].as_u64();

    harness.clock.advance(7_200);
    assert_eq!(start_as(&harness, peer, "").await, StatusCode::BAD_REQUEST);
    let limited = harness
        .request_as(Method::POST, "/v1/login/start", peer, &[], None)
        .await;
    assert_eq!(retry_after(&limited), Some(60));

    harness.clock.rewind(7_200);
    ticks.store(30, Ordering::SeqCst);
    let after_rewind = harness
        .request_as(Method::POST, "/v1/login/start", peer, &[], None)
        .await;
    assert_eq!(after_rewind.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(retry_after(&after_rewind), Some(30));

    harness.clock.advance(86_400);
    let after_leap = harness
        .request_as(Method::POST, "/v1/login/start", peer, &[], None)
        .await;
    assert_eq!(after_leap.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(retry_after(&after_leap), Some(30));

    ticks.store(60, Ordering::SeqCst);
    assert_eq!(start_as(&harness, peer, "").await, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_storm_of_unknown_callbacks_from_one_address_is_logged_once_and_counted() {
    let harness = Harness::new().await;
    let capture = ScopedCapture::start();
    for index in 0..20 {
        harness
            .callback(&format!("code=stray&state=unknown-{index}"))
            .await;
    }
    harness.clock.advance(10);
    harness.callback("code=stray&state=unknown-last").await;
    let events = capture.finish().await;

    let refused: Vec<_> = events
        .iter()
        .filter(|event| event.kind().name() == "login.callback_refused")
        .collect();
    assert_eq!(refused.len(), 2);
    assert_eq!(refused[0].int("suppressed"), Some(0));
    assert_eq!(refused[0].text("reason"), Some("unknown_state"));
    assert_eq!(refused[0].text("client"), Some("198.51.100.7"));
    assert_eq!(refused[1].int("suppressed"), Some(19));
}
