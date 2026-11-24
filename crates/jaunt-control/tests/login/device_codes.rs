use axum::http::StatusCode;

use crate::device_support::hidden_field;
use crate::support::{DEFAULT_PEER, Harness, LOGIN_TTL_SECS};

const WRONG_CODE: &str = "ZZZZ-ZZZZ";

fn peer(index: u32) -> String {
    format!("203.0.{}.{}:40000", index / 250, index % 250 + 1)
}

fn is_rejection(html: &str) -> bool {
    html.contains("The code was not recognised or has expired.")
}

fn is_confirmation(html: &str) -> bool {
    html.contains("Confirm this sign-in request")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_code_finds_its_own_request_whatever_the_case_hyphen_or_spacing() {
    let harness = Harness::new().await;
    let first = harness.device_start().await;
    let second = harness.device_start().await;
    assert_ne!(first.user_code, second.user_code);

    let plain = first.user_code.replace('-', "");
    let spaced = format!(" {} {} ", &plain[..4], &plain[4..]);
    for typed in [
        first.user_code.clone(),
        first.user_code.to_lowercase(),
        plain.clone(),
        plain.to_lowercase(),
        spaced,
    ] {
        let reply = harness.enter_code(&typed).await;
        assert_eq!(reply.status, StatusCode::OK, "{typed}");
        let html = reply.text();
        assert!(is_confirmation(&html), "{typed}");
        assert_eq!(hidden_field(&html, "login_id"), first.login_id, "{typed}");
    }
    let other = harness.enter_code(&second.user_code).await.text();
    assert_eq!(hidden_field(&other, "login_id"), second.login_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_malformed_and_expired_codes_all_look_the_same() {
    let harness = Harness::new().await;
    let stale = harness.device_start().await;
    harness.clock.advance(LOGIN_TTL_SECS);

    let mut pages = Vec::new();
    let stale_code = stale.user_code.as_str();
    for typed in [
        WRONG_CODE,
        "",
        "short",
        "0000-0000",
        "ILIL-OOOO",
        stale_code,
    ] {
        let reply = harness.enter_code(typed).await;
        assert_eq!(reply.status, StatusCode::OK, "{typed}");
        pages.push(reply.text());
    }

    assert!(is_rejection(&pages[0]));
    for page in &pages {
        assert_eq!(page, &pages[0]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ten_failures_lock_an_address_out_for_five_minutes_and_nobody_else() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    for _ in 0..10 {
        let reply = harness.enter_code(WRONG_CODE).await;
        assert_eq!(reply.status, StatusCode::OK);
    }

    let locked = harness.enter_code(&session.user_code).await;
    assert_eq!(locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(!is_confirmation(&locked.text()));
    let neighbour = harness
        .enter_code_as(&session.user_code, "198.51.100.8:40000", &[])
        .await;
    assert!(is_confirmation(&neighbour.text()));

    harness.clock.advance(LOGIN_TTL_SECS - 1);
    let still_locked = harness.enter_code(&session.user_code).await;
    assert_eq!(still_locked.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(still_locked.header("retry-after"), "1");

    harness.clock.advance(1);
    let fresh = harness.device_start().await;
    let free = harness.enter_code(&fresh.user_code).await;
    assert_eq!(free.status, StatusCode::OK);
    assert!(is_confirmation(&free.text()));
}

#[tokio::test(flavor = "multi_thread")]
async fn only_failures_count_against_the_budget() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    for _ in 0..30 {
        let reply = harness.enter_code(&session.user_code).await;
        assert!(is_confirmation(&reply.text()));
    }

    for _ in 0..9 {
        assert!(is_rejection(&harness.enter_code(WRONG_CODE).await.text()));
    }
    assert!(is_confirmation(
        &harness.enter_code(&session.user_code).await.text()
    ));
    assert!(is_rejection(&harness.enter_code(WRONG_CODE).await.text()));
    assert_eq!(
        harness.enter_code(WRONG_CODE).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn three_hundred_and_one_successful_entries_in_a_second_all_succeed() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;

    for attempt in 0..301 {
        let reply = harness.enter_code(&session.user_code).await;
        assert_eq!(reply.status, StatusCode::OK, "{attempt}");
        assert!(is_confirmation(&reply.text()), "{attempt}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn three_hundred_failures_in_a_minute_stop_every_address() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    for index in 0..30 {
        for _ in 0..10 {
            let reply = harness.enter_code_as(WRONG_CODE, &peer(index), &[]).await;
            assert_eq!(reply.status, StatusCode::OK);
        }
    }

    let stopped = harness
        .enter_code_as(&session.user_code, &peer(500), &[])
        .await;
    assert_eq!(stopped.status, StatusCode::TOO_MANY_REQUESTS);

    harness.clock.advance(60);
    let resumed = harness
        .enter_code_as(&session.user_code, &peer(500), &[])
        .await;
    assert!(is_confirmation(&resumed.text()));
}

#[tokio::test(flavor = "multi_thread")]
async fn failures_are_counted_per_forwarded_address_when_a_header_is_configured() {
    let harness = Harness::with(crate::support::Options {
        client_ip_header: Some("x-forwarded-for"),
        ..crate::support::Options::default()
    })
    .await;
    let session = harness.device_start().await;
    let noisy = [("x-forwarded-for", "192.0.2.50")];
    let quiet = [("x-forwarded-for", "192.0.2.51")];
    for _ in 0..10 {
        harness
            .enter_code_as(WRONG_CODE, DEFAULT_PEER, &noisy)
            .await;
    }

    let blocked = harness
        .enter_code_as(&session.user_code, DEFAULT_PEER, &noisy)
        .await;
    let allowed = harness
        .enter_code_as(&session.user_code, DEFAULT_PEER, &quiet)
        .await;

    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(is_confirmation(&allowed.text()));
}

#[tokio::test(flavor = "multi_thread")]
async fn structurally_broken_submissions_are_refused_without_costing_the_budget() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;

    for _ in 0..15 {
        let missing = harness.post_form("/login/device", &[("other", "x")]).await;
        assert_eq!(missing.status, StatusCode::BAD_REQUEST);
        let duplicated = harness
            .post_raw(
                "/login/device",
                Some("application/x-www-form-urlencoded"),
                b"user_code=A&user_code=B".to_vec(),
            )
            .await;
        assert_eq!(duplicated.status, StatusCode::BAD_REQUEST);
        let json = harness
            .post_raw("/login/device", Some("application/json"), b"{}".to_vec())
            .await;
        assert_eq!(json.status, StatusCode::BAD_REQUEST);
    }
    let oversized = harness
        .post_raw(
            "/login/device",
            Some("application/x-www-form-urlencoded"),
            vec![b'a'; 20 * 1024],
        )
        .await;
    assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);

    let reply = harness.enter_code(&session.user_code).await;
    assert!(is_confirmation(&reply.text()));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_entry_page_is_a_single_post_form_with_no_code_in_the_address() {
    let harness = Harness::new().await;
    let session = harness.device_start().await;
    let url = session.body["verification_url"].as_str().unwrap();
    assert!(!url.contains(&session.user_code) && !url.contains('?'));

    let page = harness.get("/login/device").await;

    assert_eq!(page.status, StatusCode::OK);
    let html = page.text();
    assert_eq!(html.matches("<form").count(), 1);
    assert!(html.contains("<form method=\"post\" action=\"/login/device\">"));
    assert!(html.contains("name=\"user_code\""));
    assert!(!is_rejection(&html));
}
