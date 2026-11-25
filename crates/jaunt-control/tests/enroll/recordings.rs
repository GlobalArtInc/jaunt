use std::sync::Arc;

use axum::http::StatusCode;
use axum::http::header::RETRY_AFTER;
use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingSink, ScopedCapture, verify_stored};
use jaunt_control::{
    OVERDUE_MARGIN_SECS, PENDING_CHUNK_OVERHEAD, RecordingLimits, RecoveredRecordings,
    chunk_body_limit,
};
use jaunt_proto::{NodeCaller, SessionEnd};
use jaunt_record::{Chunk, ChunkQueue, Limits, Pushed, SessionKind};
use jaunt_store::{EndOutcome, EndSession, RecordingState};
use serde_json::{Value, json};
use sha2::Digest;

use crate::recording_support::{
    Gate, Rec, Session, SplitMix, Stage, cast_of, crafted, default_rec, manifest_for,
    metadata_only, named, reasons, rec, recorded, recorder, wire,
};
use crate::session_support::{NODE_NAME, node, plane, raw_pool};
use crate::support::{APPROVER, Harness, RecordingOptions, Reply};

const UNKNOWN: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

fn refused(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.text());
    assert_eq!(reply.error_code(), code);
}

fn acked(reply: &Reply) -> Option<u64> {
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()["acked_through"].as_u64()
}

async fn upload_queue(r: &Rec, session: &Session, queue: &mut ChunkQueue, lose_acks: bool) {
    while let Some(chunk) = queue.peek() {
        let body = wire(chunk);
        let mut reply = r.chunk(session, &body).await;
        if lose_acks {
            reply = r.chunk(session, &body).await;
        }
        let through = acked(&reply).unwrap();
        queue.ack_checked(through).unwrap();
    }
}

#[tokio::test]
async fn a_shuffled_twenty_mebibyte_session_with_duplicates_is_stored_byte_for_byte() {
    let r = default_rec().await;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20 * 1024 * 1024, 7);
    let expected = cast_of(&session.id, &chunks);
    let mut random = SplitMix::new(11);
    let mut order: Vec<&Chunk> = chunks.iter().collect();
    for _ in 0..chunks.len() / 8 {
        order.push(&chunks[random.below(chunks.len())]);
    }
    random.shuffle(&mut order);
    let capture = ScopedCapture::start();

    let mut previous = None;
    let mut highest_sent = 0;
    for chunk in order {
        highest_sent = highest_sent.max(chunk.seq);
        let through = acked(&r.chunk(&session, &wire(chunk)).await);
        assert!(through >= previous && through.is_none_or(|seq| seq <= highest_sent));
        previous = through;
    }
    assert_eq!(previous, Some(manifest.chunks - 1));
    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": manifest.chunks})
    );
    let snapshot = capture.snapshot();
    let events = capture.finish().await;
    assert_eq!((snapshot.fields_dropped, snapshot.unmapped), (0, 0));

    let location = r.key(&session).await.location();
    assert_eq!(
        r.files(),
        [
            format!("{location}.cast"),
            format!("{location}.manifest.json")
        ]
    );
    let stored = std::fs::read(r.harness.recordings_dir.join(format!("{location}.cast"))).unwrap();
    assert!(stored == expected, "the stored cast differs");
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Complete);
    assert_eq!(
        (row.chunks, row.raw_bytes),
        (manifest.chunks, manifest.raw_bytes)
    );
    assert_eq!(row.location.as_deref(), Some(location.as_str()));
    verify_stored(r.sink().as_ref(), &r.key(&session).await, &row).unwrap();
    let completed = named(&events, "recording.completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].session_id(), Some(session.id.as_str()));
    assert_eq!(
        completed[0].actor().as_wire(),
        format!("node:{}", session.node_id)
    );
    let chunks_field = i64::try_from(manifest.chunks).unwrap();
    assert_eq!(completed[0].int("chunks"), Some(chunks_field));
    assert_eq!(completed[0].flag("input_recorded"), Some(true));
    assert_eq!(completed[0].flag("incomplete"), Some(false));
    assert!(reasons(&events).is_empty());
}

#[tokio::test]
async fn the_agent_side_queue_drives_a_resumed_upload_to_a_complete_recording() {
    let r = default_rec().await;
    let session = r.active().await;
    let mut recorder = recorder(&session, false);
    let mut queue = ChunkQueue::default();
    let mut random = SplitMix::new(3);
    for round in 0..40 {
        recorder.push_output(&random.text(20_000)).unwrap();
        if round % 5 == 0 {
            recorder.resize(100, 30).unwrap();
            recorder.flush().unwrap();
        }
        for chunk in recorder.take_chunks() {
            assert_eq!(queue.push(chunk), Pushed::Pushed);
        }
        if round % 3 == 0 {
            upload_queue(&r, &session, &mut queue, round % 2 == 0).await;
        }
    }
    let mut manifest = recorder.finish(Some(0), 1_700_000_200).unwrap();
    for chunk in recorder.take_chunks() {
        assert_eq!(queue.push(chunk), Pushed::Pushed);
    }
    queue.mark_manifest(&mut manifest);
    upload_queue(&r, &session, &mut queue, true).await;
    assert!(queue.is_empty());

    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(receipt.json()["state"], "complete");
    r.end(&session, queue.incomplete()).await;
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Complete);
    assert_eq!(row.session_incomplete, Some(false));
    assert!(!row.input_recorded);
    verify_stored(r.sink().as_ref(), &r.key(&session).await, &row).unwrap();
}

#[tokio::test]
async fn uploads_outside_the_callers_own_recordable_sessions_are_refused_and_leave_nothing() {
    let r = default_rec().await;
    let other_node = node(&r.harness, "web-02").await;
    let routed = r.routed().await;
    let no_pty = r.active().await;
    r.without_pty(&no_pty).await;
    let long_ago = r.active().await;
    let recently = r.active().await;
    let foreign = r.active().await;
    r.end(&long_ago, false).await;
    r.harness.clock.advance(2 * 3600);
    r.end(&recently, false).await;
    r.harness.clock.advance(23 * 3600);
    let body = wire(&crafted(UNKNOWN, 0, b"[0.1,\"o\",\"x\"]\n", true));
    let capture = ScopedCapture::start();

    let cases: Vec<(&str, String, StatusCode, &str)> = vec![
        (
            other_node.as_str(),
            foreign.id.clone(),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            UNKNOWN.to_owned(),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            routed.id.clone(),
            StatusCode::CONFLICT,
            "session_not_recordable",
        ),
        (
            r.node_id.as_str(),
            long_ago.id.clone(),
            StatusCode::CONFLICT,
            "session_not_recordable",
        ),
        (
            r.node_id.as_str(),
            no_pty.id.clone(),
            StatusCode::CONFLICT,
            "session_not_recordable",
        ),
        (
            r.node_id.as_str(),
            "..%2F..%2Fetc%2Fpasswd".to_owned(),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            "..".to_owned(),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            format!("{}%00", &UNKNOWN[..35]),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            format!("{UNKNOWN}0"),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            format!("{}%C3%A9", &UNKNOWN[..34]),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
        (
            r.node_id.as_str(),
            UNKNOWN.to_uppercase(),
            StatusCode::NOT_FOUND,
            "session_unknown",
        ),
    ];
    for (caller, session_id, status, code) in &cases {
        let reply = r.chunk_as(caller, session_id, &body).await;
        refused(&reply, *status, code);
    }
    let accepted = r
        .chunk(&recently, &wire(&crafted(&recently.id, 0, b"x\n", false)))
        .await;
    assert_eq!(acked(&accepted), Some(0));
    let events = capture.finish().await;

    assert_eq!(
        reasons(&events),
        [
            "wrong_node",
            "unknown_session",
            "bad_state",
            "bad_state",
            "bad_state",
            "unknown_session",
        ]
    );
    let rejected = named(&events, "recording.rejected");
    let sessions: Vec<Option<&str>> = rejected.iter().map(|event| event.session_id()).collect();
    assert_eq!(sessions[0], Some(foreign.id.as_str()));
    assert_eq!(sessions[5], None);
    assert!(
        rejected
            .iter()
            .all(|event| event.int("suppressed") == Some(0))
    );
    let location = r.key(&recently).await.location();
    assert_eq!(r.files(), [format!("{location}.cast.part")]);
    for session in [&routed, &no_pty, &long_ago, &foreign] {
        assert!(r.row(session).await.is_none());
    }
}

#[tokio::test]
async fn tampered_chunks_close_the_upload_and_remove_the_staged_part() {
    let r = default_rec().await;
    let mut flipped = crafted(UNKNOWN, 0, b"payload\n", false);
    flipped.compressed[4] ^= 0x01;
    let mut wrong_len = crafted(UNKNOWN, 0, b"payload\n", false);
    wrong_len.raw_len += 1;
    let bomb = zstd::bulk::compress(&vec![0u8; 64 * 1024 * 1024], 3).unwrap();
    let declared_small = bomb_chunk(&bomb, 1024);
    let declared_at_limit = bomb_chunk(&bomb, Limits::default().max_chunk_raw);
    let declared_over = bomb_chunk(&bomb, Limits::default().max_chunk_raw + 1);
    let cases = [
        (
            flipped,
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_chunk",
            "bad_chunk",
        ),
        (
            wrong_len,
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_chunk",
            "bad_chunk",
        ),
        (
            declared_small,
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_chunk",
            "bad_chunk",
        ),
        (
            declared_at_limit,
            StatusCode::UNPROCESSABLE_ENTITY,
            "bad_chunk",
            "bad_chunk",
        ),
        (
            declared_over,
            StatusCode::PAYLOAD_TOO_LARGE,
            "recording_too_large",
            "limit",
        ),
    ];
    for (bad, status, code, reason) in cases {
        let session = r.active().await;
        let good = crafted(&session.id, 0, b"first\n", false);
        assert_eq!(acked(&r.chunk(&session, &wire(&good)).await), Some(0));
        let capture = ScopedCapture::start();
        let mut bad = bad;
        bad.seq = 1;
        refused(&r.chunk(&session, &wire(&bad)).await, status, code);
        let later = crafted(&session.id, 1, b"second\n", true);
        refused(
            &r.chunk(&session, &wire(&later)).await,
            StatusCode::CONFLICT,
            "recording_closed",
        );
        let events = capture.finish().await;
        assert_eq!(reasons(&events), [reason, "bad_state"], "{code}");
        assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
        assert!(r.files().is_empty(), "{:?}", r.files());
    }
}

fn bomb_chunk(bomb: &[u8], raw_len: u64) -> Chunk {
    let mut chunk = crafted(UNKNOWN, 0, b"x", false);
    chunk.compressed = bomb.to_vec();
    chunk.sha256 = crate::recording_support::hex(&sha2::Sha256::digest(bomb));
    chunk.raw_len = raw_len;
    chunk
}

#[tokio::test]
async fn a_conflicting_duplicate_is_refused_and_an_identical_one_is_acknowledged_again() {
    let r = default_rec().await;
    let session = r.active().await;
    let first = crafted(&session.id, 0, b"first\n", false);
    assert_eq!(acked(&r.chunk(&session, &wire(&first)).await), Some(0));
    assert_eq!(acked(&r.chunk(&session, &wire(&first)).await), Some(0));
    let other = crafted(&session.id, 0, b"other\n", false);
    refused(
        &r.chunk(&session, &wire(&other)).await,
        StatusCode::CONFLICT,
        "conflict",
    );
    refused(
        &r.chunk(&session, &wire(&first)).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
    assert!(r.files().is_empty());
}

#[tokio::test]
async fn non_canonical_base64_and_oversized_bodies_are_refused_while_a_full_chunk_fits() {
    let r = default_rec().await;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut line = 0;
    let padded = loop {
        let raw = format!("[0.{line},\"o\",\"x\"]\n");
        let chunk = crafted(UNKNOWN, 0, raw.as_bytes(), true);
        if chunk.compressed.len() % 3 == 1 {
            break raw;
        }
        line += 1;
    };
    let canonical = |session: &Session| wire(&crafted(&session.id, 0, padded.as_bytes(), true));
    let trailing_bits = |data: &str| {
        let mut bytes = data.as_bytes().to_vec();
        let at = bytes.len() - 3;
        let index = alphabet.iter().position(|c| *c == bytes[at]).unwrap();
        bytes[at] = alphabet[index | 1];
        String::from_utf8(bytes).unwrap()
    };
    for variant in 0..4 {
        let session = r.active().await;
        let mut body = canonical(&session);
        let data = body["data"].as_str().unwrap().to_owned();
        assert!(data.ends_with("=="));
        let changed = match variant {
            0 => data.trim_end_matches('=').to_owned(),
            1 => data[..data.len() - 1].to_owned(),
            2 => trailing_bits(&data),
            _ => format!("{data}\n"),
        };
        body["data"] = json!(changed);
        let reply = r.chunk(&session, &body).await;
        refused(&reply, StatusCode::UNPROCESSABLE_ENTITY, "bad_chunk");
        assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
    }
    let session = r.active().await;
    assert_eq!(
        acked(&r.chunk(&session, &canonical(&session)).await),
        Some(0)
    );

    let session = r.active().await;
    let mut random = SplitMix::new(5);
    let noise: Vec<u8> = (0..1_040_000)
        .map(|_| random.next().to_le_bytes()[0])
        .collect();
    let full = crafted(&session.id, 0, &noise, false);
    assert!(full.compressed.len() > 1_000_000);
    assert!(full.compressed.len() <= Limits::default().max_chunk_compressed);
    assert_eq!(acked(&r.chunk(&session, &wire(&full)).await), Some(0));

    let limit = chunk_body_limit(Limits::default().max_chunk_compressed);
    let path = format!("/v1/agent/recordings/{}/chunks", session.id);
    let oversized = r
        .post(Some(&session.node_id), &path, vec![b' '; limit + 1])
        .await;
    refused(
        &oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );
    let complete_path = format!("/v1/agent/recordings/{}/complete", session.id);
    let oversized = r
        .post(
            Some(&session.node_id),
            &complete_path,
            vec![b' '; 64 * 1024 + 1],
        )
        .await;
    refused(
        &oversized,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );
    let unknown_field = r
        .post(
            Some(&session.node_id),
            &path,
            br#"{"seq":1,"raw_len":1,"sha256":"a","is_last":false,"data":"QQ==","node_id":"x"}"#
                .to_vec(),
        )
        .await;
    refused(&unknown_field, StatusCode::BAD_REQUEST, "invalid_request");
}

#[tokio::test]
async fn a_gap_is_refused_unless_the_manifest_admits_it_and_then_it_is_stored_as_incomplete() {
    let r = default_rec().await;
    for admitted in [false, true] {
        let session = r.active().await;
        let all = [
            crafted(&session.id, 0, b"zero\n", false),
            crafted(&session.id, 1, b"one\n", false),
            crafted(&session.id, 2, b"two\n", true),
        ];
        let mut manifest = manifest_for(&session, &all);
        for chunk in [&all[0], &all[2]] {
            assert_eq!(acked(&r.chunk(&session, &wire(chunk)).await), Some(0));
        }
        manifest.incomplete = admitted;
        manifest.dropped_chunks = u64::from(admitted);
        let reply = r.complete(&session, &manifest).await;
        if admitted {
            assert_eq!(reply.json(), json!({"state": "incomplete", "chunks": 2}));
            let row = r.row(&session).await.unwrap();
            assert_eq!(row.state, RecordingState::Incomplete);
            assert_eq!((row.dropped_chunks, row.raw_bytes), (1, 9));
            let location = r.key(&session).await.location();
            let cast =
                std::fs::read(r.harness.recordings_dir.join(format!("{location}.cast"))).unwrap();
            assert_eq!(cast, b"zero\ntwo\n");
            verify_stored(r.sink().as_ref(), &r.key(&session).await, &row).unwrap();
        } else {
            refused(&reply, StatusCode::UNPROCESSABLE_ENTITY, "bad_chunk");
            assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
            assert!(r.files().is_empty());
        }
    }
}

#[tokio::test]
async fn a_manifest_that_disagrees_with_the_chunks_or_the_session_is_refused() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let good = manifest_for(&session, std::slice::from_ref(&chunk));
    let mut foreign_user = good.clone();
    foreign_user.user = "someone-else".to_owned();
    let mut foreign_login = good.clone();
    foreign_login.login = "root".to_owned();
    let mut foreign_node = good.clone();
    foreign_node.node = node(&r.harness, "web-02").await;
    for wrong in [foreign_user, foreign_login, foreign_node] {
        refused(
            &r.complete(&session, &wrong).await,
            StatusCode::CONFLICT,
            "conflict",
        );
    }
    let location = r.key(&session).await.location();
    assert_eq!(r.files(), [format!("{location}.cast.part")]);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(
        r.complete(&session, &good).await.json()["state"],
        "complete"
    );

    let other = r.active().await;
    let chunk = crafted(&other.id, 0, b"only\n", true);
    acked(&r.chunk(&other, &wire(&chunk)).await);
    let mut wrong_digest = manifest_for(&other, std::slice::from_ref(&chunk));
    wrong_digest.digest = Some("0".repeat(64));
    refused(
        &r.complete(&other, &wrong_digest).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_chunk",
    );
    assert_eq!(r.row(&other).await.unwrap().state, RecordingState::Failed);
}

#[tokio::test]
async fn completing_twice_is_idempotent_and_chunks_after_completion_are_refused() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    let first = r.complete(&session, &manifest).await;
    let again = r.complete(&session, &manifest).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.json(), again.json());
    let mut different = manifest.clone();
    different.exit_status = Some(1);
    refused(
        &r.complete(&session, &different).await,
        StatusCode::CONFLICT,
        "conflict",
    );
    refused(
        &r.chunk(&session, &wire(&chunk)).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Complete
    );
}

#[tokio::test]
async fn the_stricter_incomplete_flag_wins_whichever_report_arrives_second() {
    let r = default_rec().await;
    for end_first in [true, false] {
        let session = r.active().await;
        let chunk = crafted(&session.id, 0, b"only\n", true);
        acked(&r.chunk(&session, &wire(&chunk)).await);
        let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
        let capture = ScopedCapture::start();
        let receipt = if end_first {
            r.end(&session, true).await;
            r.complete(&session, &manifest).await
        } else {
            let receipt = r.complete(&session, &manifest).await;
            r.end(&session, true).await;
            receipt
        };
        let events = capture.finish().await;
        let expected_receipt = if end_first { "incomplete" } else { "complete" };
        assert_eq!(receipt.json()["state"], expected_receipt);
        let row = r.row(&session).await.unwrap();
        assert_eq!(row.state, RecordingState::Incomplete);
        assert_eq!(row.session_incomplete, Some(true));
        let mismatches = named(&events, "recording.mismatch");
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].flag("manifest_incomplete"), Some(false));
        assert_eq!(mismatches[0].flag("session_incomplete"), Some(true));
    }
}

#[tokio::test]
async fn kind_and_permission_rules_decide_what_a_session_may_store() {
    let r = rec(RecordingOptions::default(), false).await;

    let exec = r.active().await;
    r.without_pty(&exec).await;
    let receipt = r
        .complete(&exec, &metadata_only(&exec, SessionKind::Exec))
        .await;
    assert_eq!(receipt.json(), json!({"state": "complete", "chunks": 0}));
    let location = r.key(&exec).await.location();
    assert_eq!(r.files(), [format!("{location}.manifest.json")]);
    let row = r.row(&exec).await.unwrap();
    verify_stored(r.sink().as_ref(), &r.key(&exec).await, &row).unwrap();

    let shell_without_pty = r.active().await;
    r.without_pty(&shell_without_pty).await;
    let chunk = crafted(&shell_without_pty.id, 0, b"x\n", true);
    refused(
        &r.complete(
            &shell_without_pty,
            &manifest_for(&shell_without_pty, std::slice::from_ref(&chunk)),
        )
        .await,
        StatusCode::CONFLICT,
        "session_not_recordable",
    );

    let exec_with_cast = r.active().await;
    let chunk = crafted(&exec_with_cast.id, 0, b"x\n", true);
    acked(&r.chunk(&exec_with_cast, &wire(&chunk)).await);
    let mut manifest = manifest_for(&exec_with_cast, std::slice::from_ref(&chunk));
    manifest.kind = SessionKind::Exec;
    refused(
        &r.complete(&exec_with_cast, &manifest).await,
        StatusCode::CONFLICT,
        "session_not_recordable",
    );

    let with_input = r.active().await;
    let (chunks, manifest) = recorded(&with_input, 4096, 1);
    for chunk in &chunks {
        acked(&r.chunk(&with_input, &wire(chunk)).await);
    }
    assert!(manifest.input_recorded);
    let capture = ScopedCapture::start();
    refused(
        &r.complete(&with_input, &manifest).await,
        StatusCode::CONFLICT,
        "session_not_recordable",
    );
    assert_eq!(reasons(&capture.finish().await), ["bad_state"]);
    assert_eq!(
        r.row(&with_input).await.unwrap().state,
        RecordingState::Failed
    );
    assert_eq!(r.files(), [format!("{location}.manifest.json")]);
}

#[tokio::test]
async fn the_sixty_fifth_upload_of_one_node_is_refused_while_another_node_still_works() {
    let r = default_rec().await;
    let mut sessions = Vec::new();
    for _ in 0..65 {
        sessions.push(r.active().await);
    }
    for session in &sessions[..64] {
        let chunk = crafted(&session.id, 0, b"x\n", false);
        assert_eq!(acked(&r.chunk(session, &wire(&chunk)).await), Some(0));
    }
    let last = &sessions[64];
    let reply = r
        .chunk(last, &wire(&crafted(&last.id, 0, b"x\n", false)))
        .await;
    refused(&reply, StatusCode::TOO_MANY_REQUESTS, "too_many_recordings");
    assert_eq!(reply.headers[RETRY_AFTER], "60");

    let other_node = node(&r.harness, "web-02").await;
    let other = r.active_on("web-02", &other_node).await;
    let chunk = crafted(&other.id, 0, b"x\n", false);
    assert_eq!(acked(&r.chunk(&other, &wire(&chunk)).await), Some(0));

    let first = &sessions[0];
    let done = crafted(&first.id, 1, b"y\n", true);
    acked(&r.chunk(first, &wire(&done)).await);
    let manifest = manifest_for(first, &[crafted(&first.id, 0, b"x\n", false), done.clone()]);
    assert_eq!(r.complete(first, &manifest).await.status, StatusCode::OK);
    let retry = r
        .chunk(last, &wire(&crafted(&last.id, 0, b"x\n", false)))
        .await;
    assert_eq!(acked(&retry), Some(0));
}

#[tokio::test]
async fn the_global_upload_cap_and_the_pending_byte_budget_are_enforced() {
    let limits = RecordingLimits {
        max_uploads_total: 2,
        max_pending_bytes_per_node: 2048,
        ..RecordingLimits::default()
    };
    let r = rec(
        RecordingOptions {
            limits,
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let first = r.active().await;
    let second = r.active().await;
    let third = r.active().await;
    let mut random = SplitMix::new(9);
    let mut sent = 0;
    let mut reply = None;
    for seq in 1..10 {
        let chunk = crafted(&first.id, seq, &random.text(1000), false);
        let answer = r.chunk(&first, &wire(&chunk)).await;
        if answer.status != StatusCode::OK {
            reply = Some(answer);
            break;
        }
        sent += 1;
    }
    let reply = reply.unwrap();
    refused(&reply, StatusCode::TOO_MANY_REQUESTS, "too_many_recordings");
    assert!(sent >= 2, "{sent}");
    let in_order = crafted(&first.id, 0, b"zero\n", false);
    assert_eq!(acked(&r.chunk(&first, &wire(&in_order)).await), Some(sent));

    acked(
        &r.chunk(&second, &wire(&crafted(&second.id, 0, b"x\n", false)))
            .await,
    );
    refused(
        &r.chunk(&third, &wire(&crafted(&third.id, 0, b"x\n", false)))
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_recordings",
    );
}

#[tokio::test]
async fn an_active_session_keeps_its_upload_through_hours_of_silence() {
    let r = default_rec().await;
    let session = r.active().await;
    let first = crafted(&session.id, 0, b"x\n", false);
    acked(&r.chunk(&session, &wire(&first)).await);
    r.harness.clock.advance(3 * 3600);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 0);
    let second = crafted(&session.id, 1, b"y\n", false);
    assert_eq!(acked(&r.chunk(&session, &wire(&second)).await), Some(1));
    let row = r.row(&session).await.unwrap();
    assert_eq!(
        (row.state, row.chunks, row.raw_bytes),
        (RecordingState::Receiving, 2, 4)
    );
}

#[tokio::test]
async fn an_ended_sessions_quiet_upload_stores_its_delivered_prefix_as_incomplete() {
    let r = default_rec().await;
    let session = r.active().await;
    for (seq, raw) in [(0, b"zero\n".as_slice()), (1, b"one\n"), (3, b"three\n")] {
        acked(
            &r.chunk(&session, &wire(&crafted(&session.id, seq, raw, false)))
                .await,
        );
    }
    r.harness.clock.advance(3600);
    r.end(&session, false).await;
    r.harness.clock.advance(7199);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 0);
    r.harness.clock.advance(1);
    let capture = ScopedCapture::start();
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let events = capture.finish().await;

    let completed = named(&events, "recording.completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].flag("incomplete"), Some(true));
    assert_eq!(completed[0].int("chunks"), Some(2));
    let key = r.key(&session).await;
    let location = key.location();
    assert_eq!(
        r.files(),
        [
            format!("{location}.cast"),
            format!("{location}.manifest.json")
        ]
    );
    let cast = std::fs::read(r.harness.recordings_dir.join(format!("{location}.cast"))).unwrap();
    assert_eq!(cast, b"zero\none\n");
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert!(row.salvaged && row.digest.is_none());
    assert_eq!((row.chunks, row.raw_bytes), (2, 9));
    verify_stored(r.sink().as_ref(), &key, &row).unwrap();
    let manifest = r.sink().open(&key).unwrap().unwrap().manifest;
    assert!(manifest.incomplete && manifest.input_recorded);
    assert_eq!(manifest.user, session.user_id);
    assert_eq!(manifest.node, session.node_id);

    let later = crafted(&session.id, 2, b"two\n", true);
    refused(
        &r.chunk(&session, &wire(&later)).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
    refused(
        &r.complete(&session, &manifest_for(&session, &[later]))
            .await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
}

#[tokio::test]
async fn a_session_closed_by_the_control_sweep_has_its_quiet_upload_stored_as_incomplete() {
    let r = default_rec().await;
    let session = r.active().await;
    acked(
        &r.chunk(&session, &wire(&crafted(&session.id, 0, b"zero\n", false)))
            .await,
    );
    r.harness
        .clock
        .advance(43_200 + u64::try_from(OVERDUE_MARGIN_SECS).unwrap() + 1);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 0);
    assert_eq!(r.harness.control.sweep_sessions().await.unwrap().expired, 1);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 0);
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let row = r.row(&session).await.unwrap();
    assert_eq!(
        (row.state, row.chunks, row.raw_bytes),
        (RecordingState::Incomplete, 1, 5)
    );
    assert!(row.salvaged);
    verify_stored(r.sink().as_ref(), &r.key(&session).await, &row).unwrap();
}

#[tokio::test]
async fn a_quiet_upload_with_nothing_delivered_is_removed_and_refused_later() {
    let r = default_rec().await;
    let session = r.active().await;
    let out_of_order = crafted(&session.id, 1, b"one\n", false);
    assert_eq!(acked(&r.chunk(&session, &wire(&out_of_order)).await), None);
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    let capture = ScopedCapture::start();
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_eq!(reasons(&capture.finish().await), ["limit"]);
    assert!(r.files().is_empty());
    assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
    refused(
        &r.chunk(&session, &wire(&out_of_order)).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
}

#[tokio::test]
async fn a_restart_stores_what_was_delivered_and_fails_what_was_not() {
    let r = default_rec().await;
    let delivered = r.active().await;
    let nothing = r.active().await;
    let part_lost = r.active().await;
    let already_stored = r.active().await;
    let salvaged_before = r.active().await;
    let recordings = r.harness.store.recordings();
    let now = r.harness.clock.now_secs();
    for session in [
        &delivered,
        &nothing,
        &part_lost,
        &already_stored,
        &salvaged_before,
    ] {
        recordings
            .begin(&session.id, &session.node_id, now)
            .await
            .unwrap();
    }
    let previous_run = DirectorySink::create(
        &r.harness.recordings_dir,
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1024,
        },
    )
    .unwrap();
    let key = r.key(&delivered).await;
    let mut staged = previous_run.begin(&key).unwrap();
    staged.write(0, b"zero\n").unwrap();
    staged.write(1, b"one\n").unwrap();
    let prefix = staged.prefix_sha256();
    staged.write(2, b"tw").unwrap();
    std::mem::forget(staged);
    assert!(
        recordings
            .record_progress(&delivered.id, 2, 9, &prefix)
            .await
            .unwrap()
    );
    assert!(
        recordings
            .record_progress(&part_lost.id, 1, 5, &prefix)
            .await
            .unwrap()
    );
    let stored_chunk = crafted(&already_stored.id, 0, b"done\n", true);
    let stored_manifest = manifest_for(&already_stored, std::slice::from_ref(&stored_chunk));
    let mut finished = previous_run.begin(&r.key(&already_stored).await).unwrap();
    finished.write(0, b"done\n").unwrap();
    finished.commit(&stored_manifest).unwrap();
    let mut server_written =
        manifest_for(&salvaged_before, &[crafted(UNKNOWN, 0, b"half\n", false)]);
    server_written.incomplete = true;
    server_written.digest = None;
    let mut half = previous_run.begin(&r.key(&salvaged_before).await).unwrap();
    half.write(0, b"half\n").unwrap();
    half.commit(&server_written).unwrap();

    let capture = ScopedCapture::start();
    let recovered = r.harness.control.recover_recordings().await.unwrap();
    let events = capture.finish().await;
    assert_eq!(
        recovered,
        RecoveredRecordings {
            adopted: 2,
            salvaged: 1,
            failed: 2
        }
    );
    assert_eq!(named(&events, "recording.completed").len(), 3);
    let earlier = r.row(&salvaged_before).await.unwrap();
    assert!(earlier.salvaged && earlier.state == RecordingState::Incomplete);
    refused(
        &r.complete(&salvaged_before, &server_written).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
    let adopted = r.row(&already_stored).await.unwrap();
    assert_eq!(
        (adopted.state, adopted.chunks),
        (RecordingState::Complete, 1)
    );
    verify_stored(r.sink().as_ref(), &r.key(&already_stored).await, &adopted).unwrap();
    assert_eq!(
        r.complete(&already_stored, &stored_manifest).await.json(),
        json!({"state": "complete", "chunks": 1})
    );
    let location = key.location();
    let cast = std::fs::read(r.harness.recordings_dir.join(format!("{location}.cast"))).unwrap();
    assert_eq!(cast, b"zero\none\n");
    let row = r.row(&delivered).await.unwrap();
    assert_eq!(
        (row.state, row.chunks, row.raw_bytes),
        (RecordingState::Incomplete, 2, 9)
    );
    verify_stored(r.sink().as_ref(), &key, &row).unwrap();
    for session in [&nothing, &part_lost] {
        assert_eq!(r.row(session).await.unwrap().state, RecordingState::Failed);
    }
    refused(
        &r.chunk(
            &delivered,
            &wire(&crafted(&delivered.id, 2, b"two\n", true)),
        )
        .await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
}

#[tokio::test]
async fn a_stored_recording_whose_row_is_still_receiving_is_adopted_and_never_deleted() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"done\n", true);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    r.harness
        .store
        .recordings()
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let mut staged = r.sink().begin(&r.key(&session).await).unwrap();
    staged.write(0, b"done\n").unwrap();
    staged.commit(&manifest).unwrap();

    let capture = ScopedCapture::start();
    refused(
        &r.chunk(&session, &wire(&chunk)).await,
        StatusCode::CONFLICT,
        "recording_closed",
    );
    let retry = r.complete(&session, &manifest).await;
    let events = capture.finish().await;
    assert_eq!(retry.json(), json!({"state": "complete", "chunks": 1}));
    assert_eq!(named(&events, "recording.completed").len(), 1);
    let location = r.key(&session).await.location();
    assert_eq!(
        r.files(),
        [
            format!("{location}.cast"),
            format!("{location}.manifest.json")
        ]
    );
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Complete
    );
}

#[tokio::test]
async fn a_failed_progress_write_is_not_acked_and_the_retry_catches_the_row_up() {
    let r = default_rec().await;
    let session = r.active().await;
    let pool = raw_pool(&r.harness).await;
    sqlx::query(
        "CREATE TRIGGER refuse_progress BEFORE UPDATE OF progress_sha256 ON recordings \
         BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    let chunk = crafted(&session.id, 0, b"zero\n", false);
    refused(
        &r.chunk(&session, &wire(&chunk)).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
    );
    assert_eq!(r.row(&session).await.unwrap().chunks, 0);
    sqlx::query("DROP TRIGGER refuse_progress")
        .execute(&pool)
        .await
        .unwrap();

    assert_eq!(acked(&r.chunk(&session, &wire(&chunk)).await), Some(0));
    let row = r.row(&session).await.unwrap();
    assert_eq!((row.chunks, row.raw_bytes), (1, 5));
    let expected = crate::recording_support::hex(&sha2::Sha256::digest(b"zero\n"));
    assert_eq!(row.progress_sha256.as_deref(), Some(expected.as_str()));
    let after_restart = DirectorySink::open_existing(
        &r.harness.recordings_dir,
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1024,
        },
    )
    .unwrap();
    let resumed = after_restart
        .resume(&r.key(&session).await, row.raw_bytes, &expected)
        .unwrap()
        .unwrap();
    assert_eq!(resumed.written(), 5);
}

#[tokio::test]
async fn a_stored_manifest_that_does_not_match_its_session_is_not_adopted_and_kept() {
    let r = default_rec().await;
    let foreign_user = r.active().await;
    let oversized = r.active().await;
    let previous_run = DirectorySink::create(
        &r.harness.recordings_dir,
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1024,
        },
    )
    .unwrap();
    let now = r.harness.clock.now_secs();
    let mut stolen = manifest_for(&foreign_user, &[crafted(UNKNOWN, 0, b"done\n", true)]);
    stolen.user = "intruder".to_owned();
    let mut short = manifest_for(&oversized, &[crafted(UNKNOWN, 0, b"done\n", true)]);
    short.raw_bytes = 2;
    for (session, manifest) in [(&foreign_user, &stolen), (&oversized, &short)] {
        r.harness
            .store
            .recordings()
            .begin(&session.id, &session.node_id, now)
            .await
            .unwrap();
        let mut staged = previous_run.begin(&r.key(session).await).unwrap();
        staged.write(0, b"done\n").unwrap();
        staged.commit(manifest).unwrap();
    }
    let recovered = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(
        recovered,
        RecoveredRecordings {
            adopted: 0,
            salvaged: 0,
            failed: 2
        }
    );
    for session in [&foreign_user, &oversized] {
        assert_eq!(r.row(session).await.unwrap().state, RecordingState::Failed);
        let location = r.key(session).await.location();
        assert!(r.files().contains(&format!("{location}.manifest.json")));
        assert!(r.files().contains(&format!("{location}.cast")));
    }
}

#[tokio::test]
async fn a_refused_chunk_adopts_ready_files_instead_of_failing_the_recording() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"done\n", true);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    r.harness
        .store
        .recordings()
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let mut staged = r.sink().begin(&r.key(&session).await).unwrap();
    staged.write(0, b"done\n").unwrap();
    staged.commit(&manifest).unwrap();
    let mut body = wire(&chunk);
    body["data"] = json!("QR==");
    refused(
        &r.chunk(&session, &body).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_chunk",
    );
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Complete
    );
    assert_eq!(
        r.complete(&session, &manifest).await.json(),
        json!({"state": "complete", "chunks": 1})
    );
}

#[tokio::test]
async fn an_upload_whose_salvage_fails_still_frees_its_slot() {
    let gate = Arc::new(Gate::default());
    let r = rec(
        RecordingOptions {
            limits: RecordingLimits {
                max_uploads_per_node: 1,
                ..RecordingLimits::default()
            },
            wrap: Some(gate.wrapper()),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let quiet = r.active().await;
    let next = r.active().await;
    acked(
        &r.chunk(&quiet, &wire(&crafted(&quiet.id, 0, b"zero\n", false)))
            .await,
    );
    r.end(&quiet, false).await;
    r.harness.clock.advance(7200);
    gate.fail_next_commit();
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_eq!(r.row(&quiet).await.unwrap().state, RecordingState::Failed);
    assert!(r.files().is_empty());
    let chunk = crafted(&next.id, 0, b"zero\n", false);
    assert_eq!(acked(&r.chunk(&next, &wire(&chunk)).await), Some(0));
}

#[tokio::test]
async fn a_salvage_in_progress_turns_away_a_late_chunk_and_complete() {
    let gate = Arc::new(Gate::default());
    let r = rec(
        RecordingOptions {
            wrap: Some(gate.wrapper()),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let session = r.active().await;
    acked(
        &r.chunk(&session, &wire(&crafted(&session.id, 0, b"zero\n", false)))
            .await,
    );
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    gate.arm(Stage::Commit);
    let capture = ScopedCapture::start();
    let control = r.harness.control.clone();
    let sweep = tokio::spawn(async move { control.sweep_idle_recordings().await });
    gate.entered().await;
    let late_chunk = crafted(&session.id, 1, b"one\n", true);
    let chunk_request = tokio::spawn(crate::support::send(
        r.harness.agent_router.clone(),
        crate::support::request(
            &format!("/v1/agent/recordings/{}/chunks", session.id),
            &wire(&late_chunk),
            None,
            Some(&session.node_id),
        ),
    ));
    let complete_request = tokio::spawn(crate::support::send(
        r.harness.agent_router.clone(),
        crate::support::request(
            &format!("/v1/agent/recordings/{}/complete", session.id),
            &json!({ "manifest": manifest_for(&session, &[late_chunk]) }),
            None,
            Some(&session.node_id),
        ),
    ));
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while r.harness.control.recording_upload_waiters(&session.id) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the late requests never queued behind the salvage"
        );
        tokio::task::yield_now().await;
    }
    gate.release();
    assert_eq!(sweep.await.unwrap(), 1);
    for reply in [
        chunk_request.await.unwrap(),
        complete_request.await.unwrap(),
    ] {
        refused(&reply, StatusCode::CONFLICT, "recording_closed");
    }
    let events = capture.finish().await;
    assert_eq!(named(&events, "recording.completed").len(), 1);
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert!(row.salvaged);
    let location = r.key(&session).await.location();
    assert_eq!(
        r.files(),
        [
            format!("{location}.cast"),
            format!("{location}.manifest.json")
        ]
    );
}

#[tokio::test]
async fn progress_counts_only_the_contiguous_delivered_prefix() {
    let r = default_rec().await;
    let session = r.active().await;
    for (seq, raw) in [(2, b"two\n".as_slice()), (0, b"zero\n")] {
        acked(
            &r.chunk(&session, &wire(&crafted(&session.id, seq, raw, false)))
                .await,
        );
    }
    let row = r.row(&session).await.unwrap();
    assert_eq!((row.chunks, row.raw_bytes), (1, 5));
    assert!(row.progress_sha256.is_some());
}

#[tokio::test]
async fn a_legacy_sessions_salvaged_prefix_never_claims_recorded_input() {
    let r = default_rec().await;
    let session = r.active().await;
    r.legacy_permissions(&session).await;
    acked(
        &r.chunk(&session, &wire(&crafted(&session.id, 0, b"zero\n", false)))
            .await,
    );
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let manifest = r
        .sink()
        .open(&r.key(&session).await)
        .unwrap()
        .unwrap()
        .manifest;
    assert!(manifest.incomplete && !manifest.input_recorded);
    assert!(!r.row(&session).await.unwrap().input_recorded);
}

#[tokio::test]
async fn completing_with_a_gap_returns_the_held_back_bytes_to_the_budgets() {
    let probe = crafted(UNKNOWN, 2, b"two\n", true);
    let cost = u64::try_from(probe.compressed.len()).unwrap() + PENDING_CHUNK_OVERHEAD;
    let r = rec(
        RecordingOptions {
            limits: RecordingLimits {
                max_pending_bytes_per_node: 2 * cost + 10,
                max_pending_bytes_total: 2 * cost + 10,
                ..RecordingLimits::default()
            },
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let gapped = r.active().await;
    let all = [
        crafted(&gapped.id, 0, b"zero\n", false),
        crafted(&gapped.id, 1, b"one\n", false),
        crafted(&gapped.id, 2, b"two\n", true),
    ];
    for chunk in [&all[0], &all[2]] {
        acked(&r.chunk(&gapped, &wire(chunk)).await);
    }
    let mut manifest = manifest_for(&gapped, &all);
    manifest.incomplete = true;
    manifest.dropped_chunks = 1;
    assert_eq!(
        r.complete(&gapped, &manifest).await.json()["state"],
        "incomplete"
    );

    let next = r.active().await;
    for seq in [1, 2] {
        let ahead = crafted(&next.id, seq, b"two\n", false);
        assert_eq!(acked(&r.chunk(&next, &wire(&ahead)).await), None, "{seq}");
    }
}

#[tokio::test]
async fn a_late_end_after_the_control_sweep_reconciles_the_recording() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    assert_eq!(
        r.complete(&session, &manifest).await.json()["state"],
        "complete"
    );
    r.harness
        .clock
        .advance(43_200 + u64::try_from(OVERDUE_MARGIN_SECS).unwrap() + 1);
    assert_eq!(r.harness.control.sweep_sessions().await.unwrap().expired, 1);
    r.end(&session, true).await;
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert_eq!(row.session_incomplete, Some(true));
}

#[tokio::test]
async fn an_end_report_dropped_after_its_first_poll_still_reconciles() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    assert_eq!(
        r.complete(&session, &manifest).await.json()["state"],
        "complete"
    );
    let capture = ScopedCapture::start();
    let plane = plane(&r.harness);
    let mut report = plane.session_end(
        NodeCaller(session.node_id.clone()),
        SessionEnd {
            session_id: session.id.clone(),
            exit_status: Some(0),
            bytes_in: 1,
            bytes_out: 2,
            recording_incomplete: true,
        },
    );
    std::future::poll_fn(|cx| {
        assert!(report.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    drop(report);
    drop(plane);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while capture.snapshot().captured < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dropped end report never finished reconciling"
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        r.row(&session).await.unwrap().session_incomplete,
        Some(true)
    );
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Incomplete
    );
    assert_eq!(
        named(&capture.finish().await, "recording.mismatch").len(),
        1
    );
}

#[tokio::test]
async fn a_lost_reconcile_is_redone_by_the_repeated_end_and_reported_once() {
    let r = default_rec().await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    assert_eq!(
        r.complete(&session, &manifest).await.json()["state"],
        "complete"
    );
    let ended = r
        .harness
        .store
        .sessions()
        .end(EndSession {
            id: &session.id,
            node_id: &session.node_id,
            exit_status: Some(0),
            bytes_in: 1,
            bytes_out: 2,
            recording_incomplete: true,
            now: r.harness.clock.now_secs(),
        })
        .await
        .unwrap();
    assert!(matches!(ended, EndOutcome::Ended(_)));
    assert_eq!(r.row(&session).await.unwrap().session_incomplete, None);

    let capture = ScopedCapture::start();
    r.end(&session, true).await;
    r.end(&session, true).await;
    let events = capture.finish().await;
    assert_eq!(named(&events, "recording.mismatch").len(), 1);
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert_eq!(row.session_incomplete, Some(true));
}

#[tokio::test]
async fn sessions_authorized_before_the_migration_record_a_cast_but_never_input() {
    let r = default_rec().await;
    let legacy = r.active().await;
    r.legacy_permissions(&legacy).await;
    let chunk = crafted(&legacy.id, 0, b"only\n", true);
    assert_eq!(acked(&r.chunk(&legacy, &wire(&chunk)).await), Some(0));
    let manifest = manifest_for(&legacy, std::slice::from_ref(&chunk));
    assert_eq!(
        r.complete(&legacy, &manifest).await.json()["state"],
        "complete"
    );

    let with_input = r.active().await;
    r.legacy_permissions(&with_input).await;
    let chunk = crafted(&with_input.id, 0, b"only\n", true);
    acked(&r.chunk(&with_input, &wire(&chunk)).await);
    let mut manifest = manifest_for(&with_input, std::slice::from_ref(&chunk));
    manifest.input_recorded = true;
    refused(
        &r.complete(&with_input, &manifest).await,
        StatusCode::CONFLICT,
        "session_not_recordable",
    );
    assert_eq!(
        r.row(&with_input).await.unwrap().state,
        RecordingState::Failed
    );
}

#[tokio::test]
async fn a_removed_node_cannot_upload() {
    let r = default_rec().await;
    let session = r.active().await;
    r.harness
        .admin
        .remove_node(NODE_NAME, APPROVER)
        .await
        .unwrap();
    let chunk = crafted(&session.id, 0, b"only\n", true);
    refused(
        &r.chunk(&session, &wire(&chunk)).await,
        StatusCode::FORBIDDEN,
        "node_removed",
    );
    refused(
        &r.complete(&session, &manifest_for(&session, &[chunk]))
            .await,
        StatusCode::FORBIDDEN,
        "node_removed",
    );
    assert!(r.files().is_empty());
    assert!(r.row(&session).await.is_none());
}

#[tokio::test]
async fn the_global_pending_budget_is_shared_and_a_refused_chunk_gives_its_share_back() {
    let probe = crafted(UNKNOWN, 1, b"x\n", false);
    let cost = u64::try_from(probe.compressed.len()).unwrap() + PENDING_CHUNK_OVERHEAD;
    let r = rec(
        RecordingOptions {
            limits: RecordingLimits {
                max_pending_bytes_total: 2 * cost + 10,
                ..RecordingLimits::default()
            },
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let other_node = node(&r.harness, "web-02").await;
    let held = r.active().await;
    let tampered = r.active().await;
    let first_elsewhere = r.active_on("web-02", &other_node).await;
    let second_elsewhere = r.active_on("web-02", &other_node).await;
    let ahead = |session: &Session| wire(&crafted(&session.id, 1, b"x\n", false));

    assert_eq!(acked(&r.chunk(&held, &ahead(&held)).await), None);
    let mut bad = crafted(&tampered.id, 1, b"x\n", false);
    bad.compressed[3] ^= 0x01;
    refused(
        &r.chunk(&tampered, &wire(&bad)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_chunk",
    );
    assert_eq!(
        acked(&r.chunk(&first_elsewhere, &ahead(&first_elsewhere)).await),
        None
    );
    refused(
        &r.chunk(&second_elsewhere, &ahead(&second_elsewhere)).await,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_recordings",
    );
    let mut closing = crafted(&held.id, 0, b"y\n", false);
    closing.sha256 = "0".repeat(64);
    refused(
        &r.chunk(&held, &wire(&closing)).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "bad_chunk",
    );
    assert_eq!(
        acked(&r.chunk(&second_elsewhere, &ahead(&second_elsewhere)).await),
        None
    );
}

#[tokio::test]
async fn many_tiny_out_of_order_chunks_hit_the_pending_budget_through_their_overhead() {
    let budget = 16 * 1024;
    let r = rec(
        RecordingOptions {
            limits: RecordingLimits {
                max_pending_bytes_per_node: budget,
                ..RecordingLimits::default()
            },
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let session = r.active().await;
    let mut admitted = 0;
    let refusal = loop {
        let chunk = crafted(&session.id, admitted + 1, b"x\n", false);
        let reply = r.chunk(&session, &wire(&chunk)).await;
        if reply.status != StatusCode::OK {
            break reply;
        }
        admitted += 1;
        assert!(admitted <= budget / PENDING_CHUNK_OVERHEAD, "{admitted}");
    };
    refused(
        &refusal,
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_recordings",
    );
    assert!(
        admitted >= budget / (2 * PENDING_CHUNK_OVERHEAD),
        "{admitted}"
    );
}

#[tokio::test]
async fn a_dropped_chunk_request_finishes_its_write_and_leaves_a_consistent_upload() {
    let gate = Arc::new(Gate::default());
    let r = rec(
        RecordingOptions {
            wrap: Some(gate.wrapper()),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"zero\n", false);
    gate.arm(Stage::Write);
    let request = tokio::spawn(crate::support::send(
        r.harness.agent_router.clone(),
        crate::support::request(
            &format!("/v1/agent/recordings/{}/chunks", session.id),
            &wire(&chunk),
            None,
            Some(&session.node_id),
        ),
    ));
    gate.entered().await;
    request.abort();
    assert!(request.await.is_err_and(|err| err.is_cancelled()));
    gate.release();

    assert_eq!(acked(&r.chunk(&session, &wire(&chunk)).await), Some(0));
    let row = r.row(&session).await.unwrap();
    assert_eq!(
        (row.state, row.chunks, row.raw_bytes),
        (RecordingState::Receiving, 1, 5)
    );
    let next = crafted(&session.id, 1, b"one\n", true);
    assert_eq!(acked(&r.chunk(&session, &wire(&next)).await), Some(1));
}

#[tokio::test]
async fn a_dropped_complete_request_still_stores_the_recording_and_a_retry_sees_it() {
    let gate = Arc::new(Gate::default());
    let r = rec(
        RecordingOptions {
            wrap: Some(gate.wrapper()),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let session = r.active().await;
    let chunk = crafted(&session.id, 0, b"only\n", true);
    acked(&r.chunk(&session, &wire(&chunk)).await);
    let manifest = manifest_for(&session, std::slice::from_ref(&chunk));
    gate.arm(Stage::Commit);
    let request = tokio::spawn(crate::support::send(
        r.harness.agent_router.clone(),
        crate::support::request(
            &format!("/v1/agent/recordings/{}/complete", session.id),
            &json!({ "manifest": manifest }),
            None,
            Some(&session.node_id),
        ),
    ));
    gate.entered().await;
    request.abort();
    assert!(request.await.is_err_and(|err| err.is_cancelled()));
    gate.release();

    let retry = r.complete(&session, &manifest).await;
    assert_eq!(retry.json(), json!({"state": "complete", "chunks": 1}));
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Complete
    );
    let location = r.key(&session).await.location();
    assert_eq!(
        r.files(),
        [
            format!("{location}.cast"),
            format!("{location}.manifest.json")
        ]
    );
}

#[tokio::test]
async fn the_free_space_guard_refuses_new_recordings_and_reports_once_a_minute() {
    let r = rec(
        RecordingOptions {
            min_free_bytes: u64::MAX,
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let session = r.active().await;
    let capture = ScopedCapture::start();
    for _ in 0..2 {
        let reply = r
            .chunk(&session, &wire(&crafted(&session.id, 0, b"x\n", false)))
            .await;
        refused(
            &reply,
            StatusCode::INSUFFICIENT_STORAGE,
            "insufficient_storage",
        );
        assert_eq!(reply.headers[RETRY_AFTER], "60");
    }
    r.harness.clock.advance(60);
    let reply = r
        .chunk(&session, &wire(&crafted(&session.id, 0, b"x\n", false)))
        .await;
    refused(
        &reply,
        StatusCode::INSUFFICIENT_STORAGE,
        "insufficient_storage",
    );
    assert_eq!(reasons(&capture.finish().await), ["disk_full", "disk_full"]);
    assert!(r.files().is_empty());
    assert!(r.row(&session).await.is_none());
}

#[tokio::test]
async fn without_a_directory_recording_is_disabled_and_anonymous_callers_are_turned_away() {
    let harness = Harness::new().await;
    let node_id = node(&harness, "web-01").await;
    let body: Value = wire(&crafted(UNKNOWN, 0, b"x", true));
    let capture = ScopedCapture::start();
    let path = format!("/v1/agent/recordings/{UNKNOWN}/chunks");
    let disabled = crate::support::send(
        harness.agent_router.clone(),
        crate::support::request(&path, &body, None, Some(&node_id)),
    )
    .await;
    refused(&disabled, StatusCode::NOT_FOUND, "recording_disabled");
    let anonymous = crate::support::send(
        harness.agent_router.clone(),
        crate::support::request(&path, &body, None, None),
    )
    .await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reasons(&capture.finish().await), ["disabled"]);
}
