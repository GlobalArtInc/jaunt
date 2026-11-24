use std::time::{Duration, Instant};

use axum::http::{Method, StatusCode};
use sqlx::Connection;
use sqlx::sqlite::SqliteConnection;

use crate::audit::{Captured, start_recording, take_recording};
use crate::support::{Harness, PUBLIC_ORIGIN, sha256_hex};
use crate::web_support::{SESSION_COOKIE, SESSION_TTL_SECS, WebSignedIn, bob};

const WRITE_WAIT_LIMIT: Duration = Duration::from_secs(4);
const CLEARED_SESSION_COOKIE: &str =
    "__Host-jaunt=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";

async fn status_of(harness: &Harness, signed: &WebSignedIn) -> StatusCode {
    harness
        .web_get("/v1/web/session", Some(&signed.cookie()))
        .await
        .status
}

async fn stored_last_seen(harness: &Harness, signed: &WebSignedIn) -> i64 {
    harness
        .store
        .web_sessions()
        .get(&sha256_hex(&signed.secret))
        .await
        .unwrap()
        .unwrap()
        .last_seen_at
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_ends_exactly_eight_hours_after_creation_whatever_its_use() {
    let harness = Harness::with_web().await;
    let signed = harness.web_sign_in().await;

    harness.clock.advance(SESSION_TTL_SECS / 2);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    harness.clock.advance(SESSION_TTL_SECS / 2 - 1);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);

    harness.clock.advance(1);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::UNAUTHORIZED);
    assert!(
        harness
            .store
            .web_sessions()
            .get(&sha256_hex(&signed.secret))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_is_recorded_at_most_once_a_minute() {
    let harness = Harness::with_web().await;
    let signed = harness.web_sign_in().await;
    let created = harness.clock.now_secs();

    harness.clock.advance(59);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert_eq!(stored_last_seen(&harness, &signed).await, created);

    harness.clock.advance(1);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert_eq!(stored_last_seen(&harness, &signed).await, created + 60);

    harness.clock.advance(30);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert_eq!(stored_last_seen(&harness, &signed).await, created + 60);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_twenty_first_session_of_a_user_ends_the_oldest_one() {
    let harness = Harness::with_web().await;
    let mut sessions = Vec::new();
    for _ in 0..20 {
        sessions.push(harness.web_sign_in().await);
        harness.clock.advance(1);
    }
    let other_user = harness.web_sign_in_with("", bob()).await;
    for signed in &sessions {
        assert_eq!(status_of(&harness, signed).await, StatusCode::OK);
    }

    let newest = harness.web_sign_in().await;

    assert_eq!(
        status_of(&harness, &sessions[0]).await,
        StatusCode::UNAUTHORIZED
    );
    for signed in &sessions[1..] {
        assert_eq!(status_of(&harness, signed).await, StatusCode::OK);
    }
    assert_eq!(status_of(&harness, &newest).await, StatusCode::OK);
    assert_eq!(status_of(&harness, &other_user).await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sweeper_deletes_only_expired_sessions() {
    let harness = Harness::with_web().await;
    let old = harness.web_sign_in().await;
    harness.clock.advance(100);
    let recent = harness.web_sign_in().await;

    harness.clock.advance(SESSION_TTL_SECS - 100 - 1);
    assert_eq!(harness.control.purge_web_sessions().await.unwrap(), 0);
    harness.clock.advance(1);
    assert_eq!(harness.control.purge_web_sessions().await.unwrap(), 1);
    assert_eq!(harness.control.purge_web_sessions().await.unwrap(), 0);

    let sessions = harness.store.web_sessions();
    assert!(
        sessions
            .get(&sha256_hex(&old.secret))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        sessions
            .get(&sha256_hex(&recent.secret))
            .await
            .unwrap()
            .is_some()
    );
    harness.clock.advance(100);
    assert_eq!(harness.control.purge_web_sessions().await.unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_deletes_the_session_clears_the_cookie_and_kills_the_old_cookie() {
    let harness = Harness::with_web().await;
    let signed = harness.web_sign_in().await;
    let other = harness.web_sign_in().await;

    let reply = harness.web_post_with_csrf("/v1/web/logout", &signed).await;

    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert_eq!(reply.set_cookies(), [CLEARED_SESSION_COOKIE]);
    assert!(reply.body.is_empty());
    assert_eq!(status_of(&harness, &signed).await, StatusCode::UNAUTHORIZED);
    assert!(
        harness
            .store
            .web_sessions()
            .get(&sha256_hex(&signed.secret))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(status_of(&harness, &other).await, StatusCode::OK);
    let again = harness
        .web_request(
            Method::POST,
            "/v1/web/logout",
            Some(&signed.cookie()),
            &[("origin", PUBLIC_ORIGIN)],
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_malformed_expired_and_foreign_cookies_all_get_the_same_401() {
    let harness = Harness::with_web().await;
    let expired = harness.web_sign_in().await;
    harness.clock.advance(SESSION_TTL_SECS);
    let live = harness.web_sign_in().await;
    let hash_as_cookie = format!("{SESSION_COOKIE}={}", sha256_hex(&live.secret));
    let unknown = format!("{SESSION_COOKIE}=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let mut bodies = Vec::new();
    for cookie in [
        None,
        Some(expired.cookie()),
        Some(unknown),
        Some(hash_as_cookie),
        Some(format!("{SESSION_COOKIE}=")),
        Some(format!("{SESSION_COOKIE}=short")),
        Some(format!("{0}; {0}", live.cookie())),
        Some(format!("{}={}", SESSION_COOKIE.to_lowercase(), live.secret)),
        Some(format!("__Host-jaunt-device={}", live.secret)),
    ] {
        let reply = harness.web_get("/v1/web/session", cookie.as_deref()).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{cookie:?}");
        bodies.push(reply.text());
    }

    assert!(bodies.iter().all(|body| *body == bodies[0]), "{bodies:?}");
    assert_eq!(status_of(&harness, &live).await, StatusCode::OK);
}

async fn open_writer(harness: &Harness) -> SqliteConnection {
    SqliteConnection::connect(&format!(
        "sqlite://{}?mode=rw",
        harness.database_path().display()
    ))
    .await
    .unwrap()
}

async fn install_write_log(writer: &mut SqliteConnection) {
    for statement in [
        "CREATE TABLE write_log (kind TEXT NOT NULL)",
        "CREATE TRIGGER log_insert BEFORE INSERT ON web_sessions \
         BEGIN INSERT INTO write_log (kind) VALUES ('insert'); END",
        "CREATE TRIGGER log_update BEFORE UPDATE ON web_sessions \
         BEGIN INSERT INTO write_log (kind) VALUES ('update'); END",
        "CREATE TRIGGER log_delete BEFORE DELETE ON web_sessions \
         BEGIN INSERT INTO write_log (kind) VALUES ('delete'); END",
    ] {
        sqlx::query(statement).execute(&mut *writer).await.unwrap();
    }
}

async fn take_write_log(writer: &mut SqliteConnection) -> Vec<String> {
    let kinds = sqlx::query_scalar::<_, String>("SELECT kind FROM write_log ORDER BY rowid")
        .fetch_all(&mut *writer)
        .await
        .unwrap();
    sqlx::query("DELETE FROM write_log")
        .execute(&mut *writer)
        .await
        .unwrap();
    kinds
}

fn control_events(events: &[Captured]) -> Vec<&Captured> {
    events
        .iter()
        .filter(|event| event["target"] == "jaunt::control")
        .collect()
}

fn ended_sessions(events: &[Captured]) -> Vec<&Captured> {
    events
        .iter()
        .filter(|event| {
            event
                .get("event")
                .is_some_and(|name| name == "web.session.ended")
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn reading_requests_never_attempt_a_write_even_one_that_changes_no_row() {
    let harness = Harness::with_web().await;
    let mut writer = open_writer(&harness).await;
    install_write_log(&mut writer).await;
    let signed = harness.web_sign_in().await;
    assert_eq!(take_write_log(&mut writer).await, ["insert"]);
    let created = harness.clock.now_secs();

    start_recording();
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut writer)
        .await
        .unwrap();
    let started = Instant::now();
    for n in 0..10 {
        let unknown = format!("{SESSION_COOKIE}={n:0>43}");
        let reply = harness.web_get("/v1/web/session", Some(&unknown)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{n}");
    }
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    harness.clock.advance(59);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert!(
        started.elapsed() < WRITE_WAIT_LIMIT,
        "a request waited for the write lock"
    );
    let blocked = harness.store.web_sessions().delete("no-such-session").await;
    sqlx::query("ROLLBACK").execute(&mut writer).await.unwrap();
    assert!(
        blocked.is_err(),
        "a write that changes no row must still wait for the lock"
    );
    let failures = take_recording();
    assert!(control_events(&failures).is_empty(), "{failures:?}");

    for n in 0..30 {
        let unknown = format!("{SESSION_COOKIE}={n:0>43}");
        harness.web_get("/v1/web/session", Some(&unknown)).await;
    }
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert!(take_write_log(&mut writer).await.is_empty());
    assert_eq!(stored_last_seen(&harness, &signed).await, created);

    harness.clock.advance(1);
    assert_eq!(status_of(&harness, &signed).await, StatusCode::OK);
    assert_eq!(take_write_log(&mut writer).await, ["update"]);
    assert_eq!(stored_last_seen(&harness, &signed).await, created + 60);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_expired_cookie_removes_its_session_and_reports_the_end_once() {
    let harness = Harness::with_web().await;
    let mut writer = open_writer(&harness).await;
    install_write_log(&mut writer).await;
    let signed = harness.web_sign_in().await;
    take_write_log(&mut writer).await;
    harness.clock.advance(SESSION_TTL_SECS);

    start_recording();
    for _ in 0..3 {
        assert_eq!(status_of(&harness, &signed).await, StatusCode::UNAUTHORIZED);
    }
    let events = take_recording();

    assert_eq!(take_write_log(&mut writer).await, ["delete"]);
    let ended = ended_sessions(&events);
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["reason"], "expired");
}
