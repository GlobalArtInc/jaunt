use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use jaunt_audit::ScopedCapture;
use jaunt_control::RevokeRequest;
use jaunt_record::SessionKind;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::recording_support::{Gate, Rec, Session, cast_of, metadata_only, named, recorded, wire};
use crate::session_support::{NODE_NAME, apply_policy, holder, node, raw_pool, role};
use crate::support::{DEFAULT_PEER, Harness, Options, PUBLIC_ORIGIN, RecordingOptions, Reply};
use crate::web_support::{ADMIN_ROLES, Admin, Csrf, admin, call, get, plant_token, with_token};

const WATCHERS: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: watchers }\nspec:\n  \
     members: { users: [watcher@example.com, second@example.com] }\n  \
     admin: [sessions.read, recordings.read]\n";

async fn setup() -> Rec {
    setup_with(RecordingOptions::default()).await
}

async fn setup_with(recordings: RecordingOptions) -> Rec {
    let harness = Harness::with(Options {
        web: true,
        recordings: Some(recordings),
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    apply_policy(
        &harness,
        &[
            ADMIN_ROLES.to_owned(),
            WATCHERS.to_owned(),
            role("ops", "ops", false, true),
        ],
    );
    let alice = holder(&harness, "alice", &["ops"]).await;
    Rec {
        harness,
        alice,
        node_id,
    }
}

async fn stored(r: &Rec, raw: usize, seed: u64) -> (Session, Vec<u8>) {
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, raw, seed);
    for chunk in &chunks {
        let reply = r.chunk(&session, &wire(chunk)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }
    let reply = r.complete(&session, &manifest).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let cast = cast_of(&session.id, &chunks);
    (session, cast)
}

fn stream_path(session: &Session) -> String {
    format!("/v1/admin/sessions/{}/recording", session.id)
}

fn manifest_path(session: &Session) -> String {
    format!("/v1/admin/sessions/{}/recording/manifest", session.id)
}

async fn fetch(r: &Rec, path: &str, who: &Admin) -> Reply {
    get(&r.harness, path, who).await
}

fn assert_sandboxed(reply: &Reply, label: &str) {
    assert_eq!(
        reply.headers["content-security-policy"], "default-src 'none'; sandbox",
        "{label}"
    );
    assert_eq!(
        reply.headers["x-content-type-options"], "nosniff",
        "{label}"
    );
    assert_eq!(reply.headers["cache-control"], "no-store", "{label}");
}

#[tokio::test]
async fn both_routes_need_a_session_and_recordings_read_and_a_revoked_admin_is_refused() {
    let r = setup().await;
    let (session, _) = stored(&r, 20_000, 1).await;
    let watcher = admin(&r.harness, "watcher").await;
    let reader = admin(&r.harness, "reader").await;
    let approver = admin(&r.harness, "approver").await;
    let revoked = admin(&r.harness, "second").await;

    for path in [stream_path(&session), manifest_path(&session)] {
        let anonymous = call(&r.harness, Method::GET, &path, None, Csrf::Valid, None).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{path}");
        assert_sandboxed(&anonymous, &path);
        for stranger in [&reader, &approver] {
            let refused = fetch(&r, &path, stranger).await;
            assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(refused.json(), json!({"error": "forbidden"}), "{path}");
            assert_sandboxed(&refused, &path);
        }
        let allowed = fetch(&r, &path, &watcher).await;
        assert_eq!(allowed.status, StatusCode::OK, "{path}");
        assert_sandboxed(&allowed, &path);
        let foreign_origin = call(
            &r.harness,
            Method::GET,
            &path,
            Some(&watcher),
            Csrf::ForeignOrigin,
            None,
        )
        .await;
        assert_eq!(foreign_origin.status, StatusCode::OK, "{path}");
        for method in [Method::POST, Method::DELETE, Method::PUT] {
            let refused = call(&r.harness, method, &path, Some(&watcher), Csrf::Valid, None).await;
            assert_eq!(refused.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        }
    }

    let before = fetch(&r, &stream_path(&session), &revoked).await;
    assert_eq!(before.status, StatusCode::OK);
    r.harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: jaunt_store::RevocationKind::User,
                subject: revoked.user_id.clone(),
                reason: "left".to_owned(),
            },
            "cli:tester",
        )
        .await
        .unwrap();
    for path in [stream_path(&session), manifest_path(&session)] {
        let refused = fetch(&r, &path, &revoked).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{path}");
    }
}

#[tokio::test]
async fn the_stream_is_the_stored_cast_with_safe_headers_and_a_download_variant() {
    let r = setup().await;
    let (session, cast) = stored(&r, 3 * 1024 * 1024, 2).await;
    let watcher = admin(&r.harness, "watcher").await;

    let inline = fetch(&r, &stream_path(&session), &watcher).await;
    assert_eq!(inline.status, StatusCode::OK);
    assert_eq!(
        inline.headers["content-type"],
        "application/x-asciicast; charset=utf-8"
    );
    assert_eq!(
        inline.headers["content-disposition"],
        format!("attachment; filename=\"{}.cast\"", session.id)
    );
    assert_sandboxed(&inline, "inline");
    assert!(
        inline.body == cast,
        "the streamed cast differs from the stored one"
    );

    let download = fetch(
        &r,
        &format!("{}?download=1", stream_path(&session)),
        &watcher,
    )
    .await;
    assert_eq!(download.status, StatusCode::OK);
    assert_eq!(
        download.headers["content-disposition"],
        format!("attachment; filename=\"{}.cast\"", session.id)
    );
    assert!(download.body == cast);

    for query in [
        "download=0",
        "download=",
        "download=1&download=1",
        "x=1",
        "range=1",
    ] {
        let refused = fetch(&r, &format!("{}?{query}", stream_path(&session)), &watcher).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{query}");
    }
}

#[tokio::test]
async fn missing_pending_failed_and_malformed_recordings_get_their_own_refusal() {
    let r = setup().await;
    let watcher = admin(&r.harness, "watcher").await;
    let node_id = &r.node_id;
    let now = r.harness.clock.now_secs();

    let none = r.active().await;
    let receiving = r.active().await;
    r.harness
        .store
        .recordings()
        .begin(&receiving.id, node_id, now)
        .await
        .unwrap();
    let failed = r.active().await;
    r.harness
        .store
        .recordings()
        .begin(&failed.id, node_id, now)
        .await
        .unwrap();
    r.harness
        .store
        .recordings()
        .mark_failed(&failed.id, now)
        .await
        .unwrap();

    for session in [&none, &failed] {
        for path in [stream_path(session), manifest_path(session)] {
            let reply = fetch(&r, &path, &watcher).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(reply.json(), json!({"error": "not_found"}));
            assert_sandboxed(&reply, &path);
        }
    }
    for path in [stream_path(&receiving), manifest_path(&receiving)] {
        let reply = fetch(&r, &path, &watcher).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{path}");
        assert_eq!(reply.json(), json!({"error": "recording_not_ready"}));
    }
    for id in [
        "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11",
        "not-a-session",
        "..",
        "5F0C3A52-8A8E-4C55-9A51-2F6F0D1B8C11",
    ] {
        for suffix in ["recording", "recording/manifest"] {
            let reply = fetch(&r, &format!("/v1/admin/sessions/{id}/{suffix}"), &watcher).await;
            assert_eq!(reply.status, StatusCode::NOT_FOUND, "{id} {suffix}");
        }
    }
}

#[tokio::test]
async fn an_inline_view_over_the_limit_is_refused_while_the_download_and_the_manifest_still_work() {
    let r = setup().await;
    let (session, cast) = stored(&r, 200_000, 3).await;
    let watcher = admin(&r.harness, "watcher").await;
    r.harness.control.set_recording_playback_limit(10_000);

    let inline = fetch(&r, &stream_path(&session), &watcher).await;
    assert_eq!(inline.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(inline.json(), json!({"error": "recording_too_large"}));
    let download = fetch(
        &r,
        &format!("{}?download=1", stream_path(&session)),
        &watcher,
    )
    .await;
    assert_eq!(download.status, StatusCode::OK);
    assert!(download.body == cast);
    let manifest = fetch(&r, &manifest_path(&session), &watcher).await;
    assert_eq!(manifest.json()["playback_limit_bytes"], 10_000);
    assert!(manifest.json()["raw_bytes"].as_u64().unwrap() > 10_000);

    r.harness
        .control
        .set_recording_playback_limit(u64::try_from(cast.len()).unwrap());
    let at_limit = fetch(&r, &stream_path(&session), &watcher).await;
    assert_eq!(at_limit.status, StatusCode::OK);
}

#[tokio::test]
async fn the_manifest_carries_only_facts_safe_to_show_and_never_a_path_or_a_digest() {
    let r = setup().await;
    let (session, _) = stored(&r, 50_000, 4).await;
    let watcher = admin(&r.harness, "watcher").await;
    let reply = fetch(&r, &manifest_path(&session), &watcher).await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();

    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "chunks",
            "command",
            "dropped_chunks",
            "ended_at",
            "has_cast",
            "incomplete",
            "input_recorded",
            "kind",
            "playback_limit_bytes",
            "raw_bytes",
            "salvaged",
            "started_at",
            "state"
        ]
    );
    assert_eq!(body["state"], "complete");
    assert_eq!(body["kind"], "shell");
    assert_eq!(body["has_cast"], true);
    assert_eq!(body["incomplete"], false);
    assert_eq!(body["salvaged"], false);
    assert_eq!(body["input_recorded"], true);
    assert_eq!(body["started_at"], 1_700_000_000);
    assert_eq!(body["playback_limit_bytes"], 64 * 1024 * 1024);

    let row = r.row(&session).await.unwrap();
    let text = reply.text();
    for secret in [
        row.location.clone().unwrap(),
        row.cast_sha256.clone().unwrap(),
        row.manifest_sha256.clone().unwrap(),
        row.digest.clone().unwrap(),
        r.harness.recordings_dir.display().to_string(),
        r.node_id.clone(),
    ] {
        assert!(!text.contains(&secret), "{text}");
    }
}

#[tokio::test]
async fn incomplete_and_salvaged_recordings_are_served_with_their_flags() {
    let r = setup().await;
    let watcher = admin(&r.harness, "watcher").await;
    let (cut, cast) = stored(&r, 40_000, 5).await;
    r.end(&cut, true).await;
    let (salvaged, _) = stored(&r, 40_000, 6).await;
    sqlx::query("UPDATE recordings SET salvaged = 1 WHERE session_id = ?")
        .bind(&salvaged.id)
        .execute(&raw_pool(&r.harness).await)
        .await
        .unwrap();

    let manifest = fetch(&r, &manifest_path(&cut), &watcher).await.json();
    assert_eq!(manifest["state"], "incomplete");
    assert_eq!(manifest["incomplete"], true);
    assert_eq!(manifest["salvaged"], false);
    let stream = fetch(&r, &stream_path(&cut), &watcher).await;
    assert_eq!(stream.status, StatusCode::OK);
    assert!(stream.body == cast);

    let manifest = fetch(&r, &manifest_path(&salvaged), &watcher).await.json();
    assert_eq!(manifest["salvaged"], true);
    assert_eq!(
        fetch(&r, &stream_path(&salvaged), &watcher).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_metadata_only_recording_has_a_manifest_with_the_command_and_no_stream() {
    let r = setup().await;
    let watcher = admin(&r.harness, "watcher").await;
    let session = r.active().await;
    let manifest = metadata_only(&session, SessionKind::Exec);
    let reply = r.complete(&session, &manifest).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    let body = fetch(&r, &manifest_path(&session), &watcher).await.json();
    assert_eq!(body["kind"], "exec");
    assert_eq!(body["command"], "uptime");
    assert_eq!(body["has_cast"], false);
    let stream = fetch(&r, &stream_path(&session), &watcher).await;
    assert_eq!(stream.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_view_is_audited_once_per_actor_session_and_kind_each_minute_and_refusals_are_not_views()
{
    let r = setup().await;
    let (session, _) = stored(&r, 30_000, 7).await;
    let watcher = admin(&r.harness, "watcher").await;
    let second = admin(&r.harness, "second").await;
    let reader = admin(&r.harness, "reader").await;
    let (other, _) = stored(&r, 30_000, 8).await;
    let capture = ScopedCapture::start();

    for _ in 0..3 {
        fetch(&r, &stream_path(&session), &watcher).await;
    }
    fetch(&r, &manifest_path(&session), &watcher).await;
    fetch(
        &r,
        &format!("{}?download=1", stream_path(&session)),
        &watcher,
    )
    .await;
    fetch(&r, &stream_path(&session), &second).await;
    fetch(&r, &stream_path(&other), &watcher).await;
    fetch(&r, &stream_path(&session), &reader).await;
    fetch(
        &r,
        "/v1/admin/sessions/5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11/recording",
        &watcher,
    )
    .await;
    r.harness.control.set_recording_playback_limit(1);
    fetch(&r, &stream_path(&session), &watcher).await;
    r.harness
        .control
        .set_recording_playback_limit(64 * 1024 * 1024);
    r.harness.clock.advance(59);
    fetch(&r, &stream_path(&session), &watcher).await;
    r.harness.clock.advance(1);
    fetch(&r, &stream_path(&session), &watcher).await;
    let snapshot = capture.snapshot();
    let events = capture.finish().await;
    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );

    let viewed = named(&events, "recording.viewed");
    let seen: Vec<(String, Option<String>, String)> = viewed
        .iter()
        .map(|event| {
            (
                event.actor().as_wire(),
                event.session_id().map(str::to_owned),
                event.text("kind").unwrap().to_owned(),
            )
        })
        .collect();
    let id = |who: &Admin, session: &Session, kind: &str| {
        (
            who.user_id.clone(),
            Some(session.id.clone()),
            kind.to_owned(),
        )
    };
    assert_eq!(
        seen,
        [
            id(&watcher, &session, "stream"),
            id(&watcher, &session, "manifest"),
            id(&watcher, &session, "download"),
            id(&second, &session, "stream"),
            id(&watcher, &other, "stream"),
            id(&watcher, &session, "stream"),
        ]
    );
}

#[tokio::test]
async fn a_view_through_a_token_is_its_own_critical_event_naming_the_token() {
    let r = setup().await;
    let (session, _) = stored(&r, 30_000, 11).await;
    let watcher = admin(&r.harness, "watcher").await;
    let token = plant_token(
        &r.harness,
        &watcher.user_id,
        "watcherAAAA",
        &["recordings.read"],
    )
    .await;
    let path = stream_path(&session);
    let by_token = || with_token(&r.harness, Method::GET, &path, &token, None);
    let capture = ScopedCapture::start();

    let by_person = fetch(&r, &path, &watcher).await;
    let first_by_token = by_token().await;
    let again_by_token = by_token().await;
    let again_by_person = fetch(&r, &path, &watcher).await;
    let events = capture.finish().await;

    for reply in [
        &by_person,
        &first_by_token,
        &again_by_token,
        &again_by_person,
    ] {
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }
    let viewed = named(&events, "recording.viewed");
    assert_eq!(viewed.len(), 2);
    assert!(
        viewed
            .iter()
            .all(|event| event.kind().class() == jaunt_audit::Class::Critical)
    );
    assert_eq!(viewed[0].actor().as_wire(), watcher.user_id);
    assert_eq!(viewed[0].text("jat_id"), None);
    assert_eq!(viewed[1].actor().as_wire(), "token:watcherAAAA");
    assert_eq!(viewed[1].text("jat_id"), Some("watcherAAAA"));
    assert_eq!(viewed[1].session_id(), Some(session.id.as_str()));
}

#[tokio::test]
async fn no_body_names_the_storage_location_the_digests_or_the_session_secrets() {
    let r = setup().await;
    let (session, _) = stored(&r, 20_000, 9).await;
    let watcher = admin(&r.harness, "watcher").await;
    let row = r.row(&session).await.unwrap();
    let secrets: Vec<String> = vec![
        row.location.unwrap(),
        row.cast_sha256.unwrap(),
        row.manifest_sha256.unwrap(),
        watcher.cookie.split_once('=').unwrap().1.to_owned(),
        watcher.csrf.clone(),
    ];
    let mut replies: Vec<Value> = Vec::new();
    for path in [
        manifest_path(&session),
        format!("/v1/admin/sessions/{}", session.id),
    ] {
        let reply = fetch(&r, &path, &watcher).await;
        replies.push(Value::String(reply.text()));
    }
    for reply in replies {
        let text = reply.as_str().unwrap();
        for secret in &secrets {
            assert!(!text.contains(secret.as_str()), "{text}");
        }
    }
}

async fn delivered_before_the_end(r: &Rec, path: &str, who: &Admin) -> (usize, bool) {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::COOKIE, &who.cookie)
        .header("x-jaunt-csrf", &who.csrf)
        .header(header::ORIGIN, PUBLIC_ORIGIN)
        .body(Body::empty())
        .unwrap();
    let peer: SocketAddr = format!("{DEFAULT_PEER}:40000").parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = r.harness.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let mut delivered = 0;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => delivered += frame.into_data().map_or(0, |data| data.len()),
            Err(_) => return (delivered, true),
        }
    }
    (delivered, false)
}

#[tokio::test]
async fn an_inline_stream_is_cut_at_the_limit_even_when_the_row_understates_the_size() {
    let r = setup().await;
    let (session, cast) = stored(&r, 3_200_000, 10).await;
    let watcher = admin(&r.harness, "watcher").await;
    assert!(cast.len() > 3_000_000);
    sqlx::query("UPDATE recordings SET raw_bytes = 100 WHERE session_id = ?")
        .bind(&session.id)
        .execute(&raw_pool(&r.harness).await)
        .await
        .unwrap();
    r.harness.control.set_recording_playback_limit(10_000);

    let (delivered, cut) = delivered_before_the_end(&r, &stream_path(&session), &watcher).await;
    assert!(cut, "the inline stream ran to its end");
    assert!(delivered <= 10_000, "{delivered} bytes were delivered");

    let download = fetch(
        &r,
        &format!("{}?download=1", stream_path(&session)),
        &watcher,
    )
    .await;
    assert_eq!(download.status, StatusCode::OK);
    assert!(download.body == cast, "the download is not capped");
}

#[tokio::test]
async fn a_recording_marked_failed_is_hidden_even_though_its_files_are_still_on_disk() {
    let r = setup().await;
    let (session, _) = stored(&r, 30_000, 11).await;
    let watcher = admin(&r.harness, "watcher").await;
    assert_eq!(r.files().len(), 2);
    sqlx::query("UPDATE recordings SET state = 'failed' WHERE session_id = ?")
        .bind(&session.id)
        .execute(&raw_pool(&r.harness).await)
        .await
        .unwrap();

    for path in [
        stream_path(&session),
        format!("{}?download=1", stream_path(&session)),
        manifest_path(&session),
    ] {
        let reply = fetch(&r, &path, &watcher).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(r.files().len(), 2);
}

#[tokio::test]
async fn head_requests_are_refused_and_do_not_use_up_the_audit_window_of_the_get() {
    let r = setup().await;
    let (session, _) = stored(&r, 30_000, 12).await;
    let watcher = admin(&r.harness, "watcher").await;
    let capture = ScopedCapture::start();

    for path in [stream_path(&session), manifest_path(&session)] {
        let reply = call(
            &r.harness,
            Method::HEAD,
            &path,
            Some(&watcher),
            Csrf::Valid,
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_eq!(reply.headers["allow"], "GET", "{path}");
    }
    fetch(&r, &stream_path(&session), &watcher).await;
    let events = capture.finish().await;
    assert_eq!(named(&events, "recording.viewed").len(), 1);
}

#[tokio::test]
async fn a_storage_outage_while_opening_a_recording_answers_503_and_the_next_try_works() {
    let gate = std::sync::Arc::new(Gate::default());
    let r = setup_with(RecordingOptions {
        wrap: Some(gate.wrapper()),
        ..RecordingOptions::default()
    })
    .await;
    let (session, cast) = stored(&r, 200_000, 4).await;
    let watcher = admin(&r.harness, "watcher").await;
    gate.unavailable_opens_for(2);
    for path in [stream_path(&session), manifest_path(&session)] {
        let refused = fetch(&r, &path, &watcher).await;
        assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(refused.json()["error"], "storage_unavailable");
    }
    let served = fetch(&r, &stream_path(&session), &watcher).await;
    assert_eq!(served.status, StatusCode::OK);
    assert!(served.body == cast);
}
