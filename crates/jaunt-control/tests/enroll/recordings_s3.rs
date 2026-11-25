use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingSink, ScopedCapture, verify_stored};
use jaunt_control::RecordingLimits;
use jaunt_record::{Chunk, Limits, SessionKind, SessionManifest};
use jaunt_recording_s3::Timer;
use jaunt_recording_s3::testing::MemoryStore;
use jaunt_store::RecordingState;
use serde_json::json;
use tempfile::TempDir;

use crate::recording_support::{
    Rec, Session, cast_of, crafted, files_in, manifest_for, metadata_only, named, reasons, rec,
    recorded, wire,
};
use crate::support::RecordingOptions;

struct S3Rec {
    rec: Rec,
    memory: Arc<MemoryStore>,
    staging: TempDir,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

struct ReadFlaky {
    inner: Arc<jaunt_recording_s3::S3Sink>,
    memory: Arc<MemoryStore>,
    armed: Arc<std::sync::atomic::AtomicBool>,
}

impl RecordingSink for ReadFlaky {
    fn begin(
        &self,
        key: &jaunt_audit::RecordingKey,
    ) -> Result<Box<dyn jaunt_audit::StagedRecording>, jaunt_audit::RecordingStoreError> {
        self.inner.begin(key)
    }

    fn resume(
        &self,
        key: &jaunt_audit::RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn jaunt_audit::StagedRecording>>, jaunt_audit::RecordingStoreError>
    {
        self.inner.resume(key, raw_bytes, prefix_sha256)
    }

    fn open(
        &self,
        key: &jaunt_audit::RecordingKey,
    ) -> Result<Option<jaunt_audit::StoredRecording>, jaunt_audit::RecordingStoreError> {
        let opened = self.inner.open(key);
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.memory.switch_off();
        }
        opened
    }

    fn holds_staged_manifest(&self, key: &jaunt_audit::RecordingKey) -> bool {
        self.inner.holds_staged_manifest(key)
    }

    fn holds_staged_part(&self, key: &jaunt_audit::RecordingKey) -> bool {
        self.inner.holds_staged_part(key)
    }
}

impl S3Rec {
    fn staged_files(&self) -> Vec<String> {
        files_in(&self.staging.path().join("staging"))
    }
}

async fn s3_rec(limits: RecordingLimits) -> S3Rec {
    let staging = tempfile::tempdir().unwrap();
    let directory = DirectorySink::create(
        &staging.path().join("staging"),
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1 << 30,
        },
    )
    .unwrap();
    let memory = Arc::new(MemoryStore::new(
        directory,
        tokio::runtime::Handle::current(),
        Duration::from_secs(120),
    ));
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flaky: Arc<dyn RecordingSink> = Arc::new(ReadFlaky {
        inner: memory.sink.clone(),
        memory: memory.clone(),
        armed: armed.clone(),
    });
    let rec = rec(
        RecordingOptions {
            limits,
            wrap: Some(Arc::new(move |_| flaky.clone())),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    S3Rec {
        rec,
        memory,
        staging,
        armed,
    }
}

async fn upload_all(r: &Rec, session: &Session, chunks: &[Chunk]) {
    for chunk in chunks {
        let reply = r.chunk(session, &wire(chunk)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(work).await.unwrap()
}

async fn stored_of(
    sink: &Arc<jaunt_recording_s3::S3Sink>,
    key: &jaunt_audit::RecordingKey,
) -> jaunt_audit::StoredRecording {
    let sink = sink.clone();
    let key = key.clone();
    blocking(move || sink.open(&key).unwrap().unwrap()).await
}

async fn verified(
    sink: &Arc<jaunt_recording_s3::S3Sink>,
    key: &jaunt_audit::RecordingKey,
    row: &jaunt_store::Recording,
) {
    let sink = sink.clone();
    let key = key.clone();
    let row = row.clone();
    blocking(move || verify_stored(sink.as_ref(), &key, &row).unwrap()).await;
}

fn unavailable(reply: &crate::support::Reply) {
    assert_eq!(
        reply.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        reply.text()
    );
    assert_eq!(reply.error_code(), "storage_unavailable");
}

async fn outage_through_idle_expiry(with_complete: bool) {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 60_000, 5);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    if with_complete {
        unavailable(&r.complete(&session, &manifest).await);
    }
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    let location = r.key(&session).await.location();
    for round in 0..40 {
        assert_eq!(
            r.harness.control.sweep_idle_recordings().await,
            1,
            "{round}"
        );
        let row = r.row(&session).await.unwrap();
        assert_eq!(row.state, RecordingState::Receiving, "{round}");
        let staged = s.staged_files();
        assert!(
            staged.contains(&format!("{location}.cast.part"))
                && staged.contains(&format!("{location}.manifest.pending")),
            "{staged:?}"
        );
        r.harness.clock.advance(301);
    }
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let capture = ScopedCapture::start();
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let events = capture.finish().await;
    assert_eq!(named(&events, "recording.completed").len(), 1);
    assert!(reasons(&events).is_empty());

    let key = r.key(&session).await;
    let row = r.row(&session).await.unwrap();
    let stored = stored_of(&s.memory.sink, &key).await;
    if with_complete {
        assert_eq!(row.state, RecordingState::Complete);
        assert!(!row.salvaged);
        assert_eq!(row.digest, manifest.digest);
        assert_eq!(stored.manifest, manifest);
    } else {
        assert_eq!(row.state, RecordingState::Incomplete);
        assert!(row.salvaged && stored.manifest.incomplete);
    }
    verified(&s.memory.sink, &key, &row).await;
    let mut cast = Vec::new();
    let mut reader = stored.cast.unwrap();
    let cast = blocking(move || {
        std::io::Read::read_to_end(&mut reader, &mut cast).unwrap();
        cast
    })
    .await;
    assert!(cast == cast_of(&session.id, &chunks));
    assert!(s.staged_files().is_empty(), "{:?}", s.staged_files());
}

#[tokio::test]
async fn idle_expiry_during_a_long_outage_keeps_the_staged_recording_and_stores_it_afterwards() {
    outage_through_idle_expiry(false).await;
}

#[tokio::test]
async fn idle_expiry_during_a_long_outage_keeps_the_real_manifest_of_a_finished_recording() {
    outage_through_idle_expiry(true).await;
}

#[tokio::test]
async fn the_agent_retry_after_an_outage_stores_the_real_manifest_through_the_real_staging() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 200_000, 6);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    let location = r.key(&session).await.location();
    for _ in 0..2 {
        unavailable(&r.complete(&session, &manifest).await);
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving
        );
        assert!(s.staged_files().contains(&format!("{location}.cast.part")));
    }
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let capture = ScopedCapture::start();
    let receipt = r.complete(&session, &manifest).await;
    let events = capture.finish().await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_eq!(named(&events, "recording.completed").len(), 1);
    assert!(reasons(&events).is_empty());
    let key = r.key(&session).await;
    assert_eq!(stored_of(&s.memory.sink, &key).await.manifest, manifest);
    let row = r.row(&session).await.unwrap();
    verified(&s.memory.sink, &key, &row).await;
    assert!(s.staged_files().is_empty());
}

#[tokio::test]
async fn two_simultaneous_completes_of_one_session_store_it_once() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 100_000, 7);
    upload_all(r, &session, &chunks).await;
    let capture = ScopedCapture::start();
    let (first, second) = tokio::join!(
        r.complete(&session, &manifest),
        r.complete(&session, &manifest)
    );
    let events = capture.finish().await;
    let expected = json!({"state": "complete", "chunks": chunks.len()});
    assert_eq!(first.json(), expected);
    assert_eq!(second.json(), expected);
    assert_eq!(named(&events, "recording.completed").len(), 1);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Complete
    );
    assert!(s.staged_files().is_empty());
}

#[tokio::test]
async fn a_late_chunk_after_an_unavailable_complete_gets_409_and_leaves_the_staging_alone() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", false),
        crafted(&session.id, 2, b"two\n", true),
    ];
    let mut manifest: SessionManifest = manifest_for(&session, &all);
    manifest.incomplete = true;
    manifest.dropped_chunks = 1;
    for chunk in [&all[0], &all[2]] {
        assert_eq!(r.chunk(&session, &wire(chunk)).await.status, StatusCode::OK);
    }
    s.memory.switch_off();
    unavailable(&r.complete(&session, &manifest).await);
    let location = r.key(&session).await.location();
    let late = r.chunk(&session, &wire(&all[1])).await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{}", late.text());
    assert_eq!(late.error_code(), "recording_closed");
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert!(s.staged_files().contains(&format!("{location}.cast.part")));
    assert_eq!(
        r.chunk(&session, &wire(&all[0])).await.status,
        StatusCode::OK
    );

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    assert_eq!(
        r.complete(&session, &manifest).await.json(),
        json!({"state": "incomplete", "chunks": 2})
    );
    let key = r.key(&session).await;
    let row = r.row(&session).await.unwrap();
    verified(&s.memory.sink, &key, &row).await;
}

#[tokio::test]
async fn a_recovery_during_an_outage_keeps_the_delivered_prefix_and_names_the_row() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let recordings = r.harness.store.recordings();
    recordings
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let key = r.key(&session).await;
    let sink = s.memory.sink.clone();
    let begun = key.clone();
    let prefix = blocking(move || {
        let mut staged = sink.begin(&begun).unwrap();
        staged.write(0, b"zero\n").unwrap();
        staged.write(1, b"one\n").unwrap();
        let prefix = staged.prefix_sha256();
        std::mem::forget(staged);
        prefix
    })
    .await;
    assert!(
        recordings
            .record_progress(&session.id, 2, 9, &prefix)
            .await
            .unwrap()
    );
    s.memory.switch_off();

    let first = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(first.left_receiving, std::slice::from_ref(&session.id));
    assert_eq!((first.adopted, first.salvaged, first.failed), (0, 0, 0));
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    let location = key.location();
    assert_eq!(s.staged_files(), [format!("{location}.cast.part")]);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let second = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!((second.salvaged, second.failed), (1, 0));
    assert!(second.left_receiving.is_empty());
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    verified(&s.memory.sink, &key, &row).await;
}

#[tokio::test]
async fn a_dead_store_does_not_hold_blocking_threads_for_every_recording_it_is_asked_about() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    s.memory.switch_off();
    let mut sessions = Vec::new();
    for _ in 0..4u64 {
        let session = r.active().await;
        let chunk = crafted(&session.id, 0, b"only\n", true);
        upload_all(r, &session, std::slice::from_ref(&chunk)).await;
        sessions.push((session, chunk));
    }
    let before = s.memory.timer.elapsed();
    for (session, chunk) in &sessions {
        let manifest = manifest_for(session, std::slice::from_ref(chunk));
        unavailable(&r.complete(session, &manifest).await);
    }
    let spent = s.memory.timer.elapsed() - before;
    assert!(spent <= Duration::from_secs(121), "{spent:?}");
}

async fn maintenance(
    s: &S3Rec,
) -> (
    jaunt_recording_s3::S3Recovery,
    jaunt_control::RecoveredRecordings,
) {
    let sink = s.memory.sink.clone();
    let recovery = blocking(move || sink.recover_pending()).await.unwrap();
    let recovered = s.rec.harness.control.recover_recordings().await.unwrap();
    (recovery, recovered)
}

async fn assert_stored_and_verifiable(s: &S3Rec, session: &Session, state: RecordingState) {
    let row = s.rec.row(session).await.unwrap();
    assert_eq!(row.state, state);
    assert!(row.cast_sha256.is_some(), "the row has no cast hash");
    let key = s.rec.key(session).await;
    verified(&s.memory.sink, &key, &row).await;
}

#[tokio::test]
async fn maintenance_does_not_touch_an_upload_that_is_alive_after_a_failed_complete() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 200_000, 6);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    unavailable(&r.complete(&session, &manifest).await);
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let staged = s.staged_files();
    let (recovery, recovered) = maintenance(&s).await;
    assert_eq!((recovery.published, recovery.live), (0, 1));
    assert_eq!(recovered.left_receiving, std::slice::from_ref(&session.id));
    assert_eq!(s.staged_files(), staged);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );

    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn maintenance_does_not_touch_a_deferred_idle_salvage_and_the_agent_can_still_complete() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 60_000, 5);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let staged = s.staged_files();
    let (recovery, _) = maintenance(&s).await;
    assert_eq!(recovery.published, 0);
    assert_eq!(s.staged_files(), staged);

    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    r.harness.clock.advance(301);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 0);
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn maintenance_then_the_idle_sweep_store_the_deferred_salvage_verifiably() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, _) = recorded(&session, 60_000, 5);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    maintenance(&s).await;
    r.harness.clock.advance(301);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Incomplete).await;
    assert!(r.row(&session).await.unwrap().salvaged);
}

#[tokio::test]
async fn after_a_restart_in_an_outage_the_first_agent_request_gets_503_and_the_recording_survives()
{
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", true),
    ];
    let manifest: SessionManifest = manifest_for(&session, &all);
    let recordings = r.harness.store.recordings();
    recordings
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let key = r.key(&session).await;
    s.memory.switch_off();
    let sink = s.memory.sink.clone();
    let (begun, committing) = (key.clone(), manifest.clone());
    let prefix = blocking(move || {
        let mut staged = sink.begin(&begun).unwrap();
        staged.write(0, b"zero\n").unwrap();
        staged.write(1, b"one\n").unwrap();
        let prefix = staged.prefix_sha256();
        assert!(staged.commit(&committing).is_err());
        drop(staged);
        prefix
    })
    .await;
    assert!(
        recordings
            .record_progress(&session.id, 2, 9, &prefix)
            .await
            .unwrap()
    );
    let first = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(first.left_receiving, std::slice::from_ref(&session.id));
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();

    unavailable(&r.complete(&session, &manifest).await);
    unavailable(&r.chunk(&session, &wire(&all[1])).await);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );

    maintenance(&s).await;
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    let again = r.complete(&session, &manifest).await;
    assert_eq!(again.json(), json!({"state": "complete", "chunks": 2}));
    let stored = stored_of(&s.memory.sink, &key).await;
    assert_eq!(stored.manifest, manifest);
}

#[tokio::test]
async fn a_stray_chunk_after_a_failed_complete_of_a_full_set_destroys_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 9);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    unavailable(&r.complete(&session, &manifest).await);
    let staged = s.staged_files();
    let stray = crafted(
        &session.id,
        u64::try_from(chunks.len()).unwrap() + 5,
        b"stray\n",
        false,
    );
    let reply = r.chunk(&session, &wire(&stray)).await;
    assert_ne!(reply.status, StatusCode::OK);
    assert_ne!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn a_late_in_order_chunk_after_a_deferred_idle_salvage_destroys_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", false),
        crafted(&session.id, 2, b"two\n", true),
    ];
    for chunk in &all[..2] {
        assert_eq!(r.chunk(&session, &wire(chunk)).await.status, StatusCode::OK);
    }
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let staged = s.staged_files();
    let late = r.chunk(&session, &wire(&all[2])).await;
    assert_eq!(late.status, StatusCode::CONFLICT, "{}", late.text());
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    r.harness.clock.advance(7200 + 301);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Incomplete).await;
}

#[tokio::test]
async fn a_restart_with_the_store_up_adopts_the_real_pending_manifest_and_does_not_salvage_over_it()
{
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", true),
    ];
    let manifest: SessionManifest = manifest_for(&session, &all);
    let recordings = r.harness.store.recordings();
    recordings
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let key = r.key(&session).await;
    s.memory.switch_off();
    let sink = s.memory.sink.clone();
    let (begun, committing) = (key.clone(), manifest.clone());
    let prefix = blocking(move || {
        let mut staged = sink.begin(&begun).unwrap();
        staged.write(0, b"zero\n").unwrap();
        staged.write(1, b"one\n").unwrap();
        let prefix = staged.prefix_sha256();
        let _ = staged.commit(&committing);
        drop(staged);
        prefix
    })
    .await;
    recordings
        .record_progress(&session.id, 2, 9, &prefix)
        .await
        .unwrap();
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    maintenance(&s).await;
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    let row = r.row(&session).await.unwrap();
    assert!(!row.salvaged);
    assert_eq!(row.digest, manifest.digest);
}

#[tokio::test]
async fn the_real_manifest_replaces_the_synthetic_pending_of_a_deferred_salvage() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 3);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let location = r.key(&session).await.location();
    let pending = s
        .staging
        .path()
        .join("staging")
        .join(format!("{location}.manifest.pending"));
    let synthetic = std::fs::read(&pending).unwrap();
    assert!(
        String::from_utf8(synthetic)
            .unwrap()
            .contains("\"incomplete\":true")
    );
    unavailable(&r.complete(&session, &manifest).await);
    assert_eq!(
        std::fs::read(&pending).unwrap(),
        jaunt_audit::manifest_bytes(&manifest).unwrap()
    );
}

#[tokio::test]
async fn a_recording_that_waits_longer_than_the_limit_is_dropped_and_frees_its_slot() {
    let s = s3_rec(RecordingLimits {
        max_uploads_per_node: 1,
        max_wait: Duration::from_secs(3600),
        ..RecordingLimits::default()
    })
    .await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, _) = recorded(&session, 20_000, 2);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    let next = r.active().await;
    let blocked = r
        .chunk(&next, &wire(&crafted(&next.id, 0, b"zero\n", false)))
        .await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);

    let capture = ScopedCapture::start();
    r.harness.clock.advance(3601);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let events = capture.finish().await;
    assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
    assert!(s.staged_files().is_empty());
    assert_eq!(reasons(&events), ["limit"]);
    let accepted = r
        .chunk(&next, &wire(&crafted(&next.id, 0, b"zero\n", false)))
        .await;
    assert_eq!(accepted.status, StatusCode::OK);
}

async fn protected_by_a_failed_complete(s: &S3Rec) -> (Session, Vec<Chunk>, SessionManifest) {
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 12);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    unavailable(&r.complete(&session, &manifest).await);
    (session, chunks, manifest)
}

async fn assert_untouched_then_completes(
    s: &S3Rec,
    session: &Session,
    chunks: &[Chunk],
    manifest: &SessionManifest,
    staged: &[String],
) {
    let r = &s.rec;
    assert_eq!(
        r.row(session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let receipt = r.complete(session, manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(s, session, RecordingState::Complete).await;
}

#[tokio::test]
async fn a_complete_of_another_kind_on_a_protected_upload_is_refused_and_destroys_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let (session, chunks, manifest) = protected_by_a_failed_complete(&s).await;
    let staged = s.staged_files();
    let exec = metadata_only(&session, SessionKind::Exec);
    let reply = s.rec.complete(&session, &exec).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.text());
    assert_eq!(reply.error_code(), "session_not_recordable");
    assert_untouched_then_completes(&s, &session, &chunks, &manifest, &staged).await;
}

#[tokio::test]
async fn a_complete_that_fails_verification_on_a_deferred_upload_destroys_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 13);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let staged = s.staged_files();
    let mut wrong = manifest.clone();
    wrong.digest = Some("ab".repeat(32));
    let reply = r.complete(&session, &wrong).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        reply.text()
    );
    assert_eq!(reply.error_code(), "bad_chunk");
    assert_untouched_then_completes(&s, &session, &chunks, &manifest, &staged).await;
}

#[tokio::test]
async fn a_chunk_over_the_session_budget_on_a_protected_upload_is_refused_and_destroys_nothing() {
    let defaults = RecordingLimits::default();
    let s = s3_rec(RecordingLimits {
        chunk: Limits {
            max_pending_bytes: 300,
            ..defaults.chunk
        },
        ..defaults
    })
    .await;
    let (session, chunks, manifest) = protected_by_a_failed_complete(&s).await;
    let staged = s.staged_files();
    let big = crafted(
        &session.id,
        u64::try_from(chunks.len()).unwrap() + 10,
        &crate::recording_support::SplitMix::new(77).text(6000),
        false,
    );
    let reply = s.rec.chunk(&session, &wire(&big)).await;
    assert_eq!(
        reply.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        reply.text()
    );
    assert_untouched_then_completes(&s, &session, &chunks, &manifest, &staged).await;
}

#[tokio::test]
async fn a_chunk_with_bad_base64_on_a_protected_upload_is_refused_and_destroys_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let (session, chunks, manifest) = protected_by_a_failed_complete(&s).await;
    let staged = s.staged_files();
    let mut body = wire(&chunks[0]);
    body["data"] = json!("***");
    let reply = s.rec.chunk(&session, &body).await;
    assert_eq!(
        reply.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        reply.text()
    );
    assert_eq!(reply.error_code(), "bad_chunk");
    assert_untouched_then_completes(&s, &session, &chunks, &manifest, &staged).await;
}

#[tokio::test]
async fn a_finished_recording_that_waited_past_the_limit_keeps_its_files_and_is_stored_when_the_store_returns()
 {
    let s = s3_rec(RecordingLimits {
        max_uploads_per_node: 1,
        max_wait: Duration::from_secs(3600),
        ..RecordingLimits::default()
    })
    .await;
    let r = &s.rec;
    let (session, chunks, manifest) = protected_by_a_failed_complete(&s).await;
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    let staged = s.staged_files();
    assert_eq!(r.harness.control.recordings_given_up(), 0);

    r.harness.clock.advance(3601);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_eq!(r.harness.control.recordings_given_up(), 1);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);
    assert!(!s.memory.sink.is_live(&session.id));

    let next = r.active().await;
    let accepted = r
        .chunk(&next, &wire(&crafted(&next.id, 0, b"zero\n", false)))
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "the slot was not freed");
    unavailable(&r.complete(&session, &manifest).await);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let (recovery, _) = maintenance(&s).await;
    assert_eq!(recovery.published, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    let row = r.row(&session).await.unwrap();
    assert!(!row.salvaged);
    assert_eq!(row.digest, manifest.digest);
    assert!(
        s.staged_files()
            .iter()
            .all(|file| !file.contains(&session.id)),
        "{:?}",
        s.staged_files()
    );
    let late = r.complete(&session, &manifest).await;
    assert_eq!(
        late.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
}

#[tokio::test]
async fn a_synthetic_manifest_already_in_the_bucket_is_adopted_when_the_real_complete_arrives() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 30_000, 14);
    upload_all(r, &session, &chunks).await;
    let cast = cast_of(&session.id, &chunks);
    let mut synthetic = manifest.clone();
    synthetic.incomplete = true;
    synthetic.digest = None;
    synthetic.exit_status = None;
    synthetic.chunks = u64::try_from(chunks.len()).unwrap();
    synthetic.raw_bytes = u64::try_from(cast.len()).unwrap();
    let other_staging = tempfile::tempdir().unwrap();
    let sibling = s.memory.sibling_sink(
        DirectorySink::create(
            &other_staging.path().join("staging"),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1 << 30,
            },
        )
        .unwrap(),
        tokio::runtime::Handle::current(),
    );
    let key = r.key(&session).await;
    blocking(move || {
        let mut staged = sibling.begin(&key).unwrap();
        staged.write(0, &cast).unwrap();
        staged.commit(&synthetic).unwrap();
    })
    .await;

    let reply = r.complete(&session, &manifest).await;
    assert_eq!(
        reply.json(),
        json!({"state": "incomplete", "chunks": chunks.len()}),
        "{}",
        reply.text()
    );
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Incomplete);
    assert!(row.salvaged);
    assert!(s.staged_files().is_empty());
    assert_stored_and_verifiable(&s, &session, RecordingState::Incomplete).await;
}

fn limits_with_wait() -> RecordingLimits {
    RecordingLimits {
        max_wait: Duration::from_secs(3600),
        ..RecordingLimits::default()
    }
}

async fn given_up(s: &S3Rec) -> (Session, SessionManifest) {
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 12);
    upload_all(r, &session, &chunks).await;
    s.memory.switch_off();
    unavailable(&r.complete(&session, &manifest).await);
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    r.harness.clock.advance(3601);
    assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
    assert_eq!(r.harness.control.recordings_given_up(), 1);
    (session, manifest)
}

#[tokio::test]
async fn a_recover_after_a_give_up_leaves_the_real_pending_manifest_alone_and_the_publish_stores_it()
 {
    let s = s3_rec(limits_with_wait()).await;
    let r = &s.rec;
    let (session, manifest) = given_up(&s).await;
    let staged = s.staged_files();
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let recovered = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(recovered.left_receiving, std::slice::from_ref(&session.id));
    assert_eq!(
        (recovered.adopted, recovered.salvaged, recovered.failed),
        (0, 0, 0)
    );
    let row = r.row(&session).await.unwrap();
    assert_eq!(row.state, RecordingState::Receiving);
    assert!(!row.salvaged);
    assert_eq!(s.staged_files(), staged);

    let (recovery, _) = maintenance(&s).await;
    assert_eq!(recovery.published, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    let key = r.key(&session).await;
    assert_eq!(stored_of(&s.memory.sink, &key).await.manifest, manifest);
    assert!(!r.row(&session).await.unwrap().salvaged);
}

#[tokio::test]
async fn a_late_request_with_the_store_up_after_a_give_up_does_not_fail_the_kept_recording() {
    let s = s3_rec(limits_with_wait()).await;
    let r = &s.rec;
    let (session, manifest) = given_up(&s).await;
    let staged = s.staged_files();
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    unavailable(&r.complete(&session, &manifest).await);
    let stray = crafted(&session.id, 500, b"stray\n", false);
    unavailable(&r.chunk(&session, &wire(&stray)).await);
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);
    let (recovery, _) = maintenance(&s).await;
    assert_eq!(recovery.published, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

struct Foreign {
    _staging: TempDir,
}

async fn put_into_the_bucket(
    s: &S3Rec,
    session: &Session,
    cast: Vec<u8>,
    manifest: SessionManifest,
) -> Foreign {
    let staging = tempfile::tempdir().unwrap();
    let sibling = s.memory.sibling_sink(
        DirectorySink::create(
            &staging.path().join("staging"),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1 << 30,
            },
        )
        .unwrap(),
        tokio::runtime::Handle::current(),
    );
    let key = s.rec.key(session).await;
    blocking(move || {
        let mut staged = sibling.begin(&key).unwrap();
        staged.write(0, &cast).unwrap();
        staged.commit(&manifest).unwrap();
    })
    .await;
    Foreign { _staging: staging }
}

async fn assert_conflict_kept_everything(
    s: &S3Rec,
    session: &Session,
    reply: crate::support::Reply,
    bucket_manifest: &SessionManifest,
    bucket_cast_len: usize,
) {
    let r = &s.rec;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.text());
    assert_eq!(reply.error_code(), "conflict");
    assert_eq!(r.harness.control.recordings_conflicts(), 1);
    let row = r.row(session).await.unwrap();
    assert_eq!(row.state, RecordingState::Receiving);
    let location = r.key(session).await.location();
    let staged = s.staged_files();
    assert!(
        staged.contains(&format!("{location}.cast.part"))
            && staged.contains(&format!("{location}.manifest.pending")),
        "{staged:?}"
    );
    let key = r.key(session).await;
    let stored = stored_of(&s.memory.sink, &key).await;
    assert_eq!(&stored.manifest, bucket_manifest);
    let mut cast = Vec::new();
    let mut reader = stored.cast.unwrap();
    let cast = blocking(move || {
        std::io::Read::read_to_end(&mut reader, &mut cast).unwrap();
        cast
    })
    .await;
    assert_eq!(cast.len(), bucket_cast_len);

    let late = r
        .chunk(session, &wire(&crafted(&session.id, 99, b"late\n", false)))
        .await;
    assert_eq!(late.status, StatusCode::CONFLICT);
    assert_eq!(late.error_code(), "conflict");
    s.memory.wait_out_the_breaker();
    maintenance(s).await;
    let hashed = s.memory.sink.staged_hash_runs();
    for _ in 0..2 {
        s.memory.wait_out_the_breaker();
        maintenance(s).await;
    }
    assert_eq!(s.memory.sink.staged_hash_runs(), hashed);
    assert_eq!(
        r.row(session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(s.staged_files(), staged);
    let again = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(again.left_receiving, std::slice::from_ref(&session.id));
    assert_eq!(again.salvaged + again.adopted + again.failed, 0);
}

#[tokio::test]
async fn a_truncated_object_in_the_bucket_never_replaces_the_verified_staging() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", false),
        crafted(&session.id, 2, b"two\n", true),
    ];
    upload_all(r, &session, &all).await;
    let manifest = manifest_for(&session, &all);
    let prefix = cast_of(&session.id, &all[..2]);
    let mut synthetic = manifest.clone();
    synthetic.incomplete = true;
    synthetic.digest = None;
    synthetic.exit_status = None;
    synthetic.chunks = 2;
    synthetic.raw_bytes = u64::try_from(prefix.len()).unwrap();
    let length = prefix.len();
    let _foreign = put_into_the_bucket(&s, &session, prefix, synthetic.clone()).await;
    let reply = r.complete(&session, &manifest).await;
    assert_conflict_kept_everything(&s, &session, reply, &synthetic, length).await;
}

#[tokio::test]
async fn another_recording_of_the_same_node_in_the_bucket_never_replaces_the_verified_staging() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", true),
    ];
    upload_all(r, &session, &all).await;
    let manifest = manifest_for(&session, &all);
    let foreign_all = [
        crafted(&session.id, 0, b"FOREIGN\n", false),
        crafted(&session.id, 1, b"x\n", true),
    ];
    let foreign_cast = cast_of(&session.id, &foreign_all);
    let foreign = manifest_for(&session, &foreign_all);
    let length = foreign_cast.len();
    let _kept = put_into_the_bucket(&s, &session, foreign_cast, foreign.clone()).await;
    let reply = r.complete(&session, &manifest).await;
    assert_conflict_kept_everything(&s, &session, reply, &foreign, length).await;
    assert_ne!(r.row(&session).await.unwrap().digest, foreign.digest);
}

#[tokio::test]
async fn a_manifest_of_another_node_in_the_bucket_never_replaces_the_verified_staging() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let all = [
        crafted(&session.id, 0, b"zero\n", false),
        crafted(&session.id, 1, b"one\n", true),
    ];
    upload_all(r, &session, &all).await;
    let manifest = manifest_for(&session, &all);
    let cast = cast_of(&session.id, &all);
    let mut foreign = manifest.clone();
    foreign.node = "another-node".to_owned();
    foreign.digest = Some("ef".repeat(32));
    let length = cast.len();
    let _kept = put_into_the_bucket(&s, &session, cast, foreign.clone()).await;
    let reply = r.complete(&session, &manifest).await;
    assert_conflict_kept_everything(&s, &session, reply, &foreign, length).await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Empty,
    Identical,
    Synthetic,
    OtherManifest,
    OtherCast,
    PrefixCast,
    OtherNode,
    MidRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
    Live,
    Salvage,
    Publish,
    Recover,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outcome {
    state: RecordingState,
    kept: bool,
    conflicts: u64,
    refused: u64,
    status: Option<u16>,
}

fn outcome(
    state: RecordingState,
    kept: bool,
    conflicts: u64,
    refused: u64,
    status: Option<u16>,
) -> Outcome {
    Outcome {
        state,
        kept,
        conflicts,
        refused,
        status,
    }
}

fn expected(caller: Caller, bucket: Bucket) -> Outcome {
    use Bucket::*;
    use Caller::*;
    use RecordingState::{Complete, Incomplete, Receiving};
    let conflict = matches!(bucket, OtherManifest | OtherCast | PrefixCast | OtherNode);
    match (caller, bucket) {
        (Live, Empty | Identical) => outcome(Complete, false, 0, 0, Some(200)),
        (Live, Synthetic) => outcome(Incomplete, false, 0, 0, Some(200)),
        (Live, MidRead) => outcome(Receiving, true, 0, 0, Some(503)),
        (Live, _) if conflict => outcome(Receiving, true, 1, 0, Some(409)),
        (Salvage, Empty | Identical | Synthetic) => outcome(Incomplete, false, 0, 0, None),
        (Salvage, MidRead) => outcome(Receiving, true, 0, 0, None),
        (Salvage, _) if conflict => outcome(Receiving, true, 1, 0, None),
        (Publish, Empty | Identical) => outcome(Complete, false, 0, 0, None),
        (Publish, Synthetic) => outcome(Incomplete, false, 0, 0, None),
        (Publish, MidRead) => outcome(Receiving, true, 0, 0, None),
        (Publish, _) if conflict => outcome(Receiving, true, 0, 1, None),
        (Recover, Empty | Synthetic) => outcome(Incomplete, false, 0, 0, None),
        (Recover, Identical) => outcome(Complete, false, 0, 0, None),
        (Recover, MidRead) => outcome(Receiving, true, 0, 0, None),
        (Recover, _) if conflict => outcome(Receiving, true, 1, 0, None),
        _ => unreachable!(),
    }
}

fn synthetic_of(real: &SessionManifest, chunks: usize, cast_len: usize) -> SessionManifest {
    let mut synthetic = real.clone();
    synthetic.incomplete = true;
    synthetic.digest = None;
    synthetic.exit_status = None;
    synthetic.chunks = u64::try_from(chunks).unwrap();
    synthetic.raw_bytes = u64::try_from(cast_len).unwrap();
    synthetic
}

fn bucket_content(
    caller: Caller,
    bucket: Bucket,
    real: &SessionManifest,
    chunks: usize,
    cast: &[u8],
) -> Option<(Vec<u8>, SessionManifest)> {
    let synthetic = synthetic_of(real, chunks, cast.len());
    match bucket {
        Bucket::Empty => None,
        Bucket::Identical => Some((
            cast.to_vec(),
            if caller == Caller::Salvage {
                synthetic
            } else {
                real.clone()
            },
        )),
        Bucket::Synthetic | Bucket::MidRead => Some((cast.to_vec(), synthetic)),
        Bucket::OtherManifest => {
            let mut other = real.clone();
            other.digest = Some("ef".repeat(32));
            other.chunks = 999;
            Some((cast.to_vec(), other))
        }
        Bucket::OtherCast => {
            let mut flipped = cast.to_vec();
            let last = flipped.len() - 1;
            flipped[last] ^= 1;
            Some((flipped, synthetic))
        }
        Bucket::PrefixCast => {
            let prefix = cast[..cast.len() / 2].to_vec();
            let mut short = synthetic;
            short.chunks = 1;
            short.raw_bytes = u64::try_from(prefix.len()).unwrap();
            Some((prefix, short))
        }
        Bucket::OtherNode => {
            let mut other = real.clone();
            other.node = "another-node".to_owned();
            Some((cast.to_vec(), other))
        }
    }
}

async fn run_cell(caller: Caller, bucket: Bucket) -> Outcome {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, real) = recorded(&session, 30_000, 41);
    let cast = cast_of(&session.id, &chunks);
    let content = bucket_content(caller, bucket, &real, chunks.len(), &cast);
    let key = r.key(&session).await;
    let mut status = None;
    let mut refused = 0;
    let _foreign;
    match caller {
        Caller::Live | Caller::Salvage => {
            upload_all(r, &session, &chunks).await;
            _foreign = match content {
                Some((bytes, manifest)) => {
                    Some(put_into_the_bucket(&s, &session, bytes, manifest).await)
                }
                None => None,
            };
            if bucket == Bucket::MidRead {
                s.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            if caller == Caller::Live {
                let reply = r.complete(&session, &real).await;
                status = Some(reply.status.as_u16());
            } else {
                r.end(&session, false).await;
                r.harness.clock.advance(7200);
                assert_eq!(r.harness.control.sweep_idle_recordings().await, 1);
            }
        }
        Caller::Publish | Caller::Recover => {
            let recordings = r.harness.store.recordings();
            recordings
                .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
                .await
                .unwrap();
            let sink = s.memory.sink.clone();
            let (begun, committing, bytes) = (key.clone(), real.clone(), cast.clone());
            let publish = caller == Caller::Publish;
            if publish {
                s.memory.switch_off();
            }
            let prefix = blocking(move || {
                let mut staged = sink.begin(&begun).unwrap();
                staged.write(0, &bytes).unwrap();
                let prefix = staged.prefix_sha256();
                if publish {
                    assert!(staged.commit(&committing).is_err());
                } else {
                    staged.keep_files();
                }
                drop(staged);
                prefix
            })
            .await;
            assert!(
                recordings
                    .record_progress(
                        &session.id,
                        u64::try_from(chunks.len()).unwrap(),
                        u64::try_from(cast.len()).unwrap(),
                        &prefix
                    )
                    .await
                    .unwrap()
            );
            if publish {
                s.memory.switch_on();
                s.memory.wait_out_the_breaker();
            }
            _foreign = match content {
                Some((bytes, manifest)) => {
                    Some(put_into_the_bucket(&s, &session, bytes, manifest).await)
                }
                None => None,
            };
            if bucket == Bucket::MidRead {
                if publish {
                    s.memory.down_after_gets(4);
                } else {
                    s.armed.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            if publish {
                let (recovery, _) = maintenance(&s).await;
                refused = recovery.refused;
            } else {
                let recovered = r.harness.control.recover_recordings().await.unwrap();
                s.memory
                    .sink
                    .staging()
                    .remove_leftovers_except(&recovered.left_receiving)
                    .unwrap();
            }
        }
    }
    let row = r.row(&session).await.unwrap();
    let location = key.location();
    let kept = s
        .staged_files()
        .iter()
        .any(|file| file.contains(&location) && !file.ends_with(".manifest.json.part"));
    Outcome {
        state: row.state,
        kept,
        conflicts: r.harness.control.recordings_conflicts(),
        refused,
        status,
    }
}

#[tokio::test]
async fn the_same_cases_decide_the_same_way_in_every_caller() {
    use Bucket::*;
    use Caller::*;
    let mut wrong = Vec::new();
    for caller in [Live, Salvage, Publish, Recover] {
        for bucket in [
            Empty,
            Identical,
            Synthetic,
            OtherManifest,
            OtherCast,
            PrefixCast,
            OtherNode,
            MidRead,
        ] {
            let got = run_cell(caller, bucket).await;
            let want = expected(caller, bucket);
            if got != want {
                wrong.push(format!(
                    "{caller:?} x {bucket:?}: got {got:?}, want {want:?}"
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

async fn put_manifest_only(s: &S3Rec, session: &Session, manifest: SessionManifest) -> Foreign {
    let staging = tempfile::tempdir().unwrap();
    let sibling = s.memory.sibling_sink(
        DirectorySink::create(
            &staging.path().join("staging"),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1 << 30,
            },
        )
        .unwrap(),
        tokio::runtime::Handle::current(),
    );
    let key = s.rec.key(session).await;
    blocking(move || {
        sibling.begin(&key).unwrap().commit(&manifest).unwrap();
    })
    .await;
    Foreign { _staging: staging }
}

#[tokio::test]
async fn a_recording_without_a_cast_compares_its_metadata_with_what_the_bucket_holds() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    for (changed, expect_conflict) in [(false, false), (true, true)] {
        let session = r.active().await;
        let manifest = metadata_only(&session, SessionKind::Exec);
        let mut bucket = manifest.clone();
        if changed {
            bucket.command = Some("reboot".to_owned());
        }
        let _kept = put_manifest_only(&s, &session, bucket).await;
        let reply = r.complete(&session, &manifest).await;
        if expect_conflict {
            assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.text());
            assert_eq!(reply.error_code(), "conflict");
            assert_eq!(
                r.row(&session).await.unwrap().state,
                RecordingState::Receiving
            );
        } else {
            assert_eq!(reply.json(), json!({"state": "complete", "chunks": 0}));
            assert_eq!(
                r.row(&session).await.unwrap().state,
                RecordingState::Complete
            );
        }
    }
    assert_eq!(r.harness.control.recordings_conflicts(), 1);
}

#[tokio::test]
async fn a_manifest_of_another_recording_without_its_cast_is_a_conflict_and_keeps_the_staging() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 52);
    upload_all(r, &session, &chunks).await;
    let mut other = manifest.clone();
    other.raw_bytes += 1;
    let _kept = put_manifest_only(&s, &session, other).await;
    let reply = r.complete(&session, &manifest).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.text());
    assert_eq!(reply.error_code(), "conflict");
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    let location = r.key(&session).await.location();
    assert!(s.staged_files().contains(&format!("{location}.cast.part")));
}

#[tokio::test]
async fn a_synthetic_manifest_without_its_cast_is_a_lost_acknowledgement_once_the_staged_cast_is_stored()
 {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 54);
    upload_all(r, &session, &chunks).await;
    let cast = cast_of(&session.id, &chunks);
    let synthetic = synthetic_of(&manifest, chunks.len(), cast.len());
    let _kept = put_manifest_only(&s, &session, synthetic).await;
    let reply = r.complete(&session, &manifest).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Incomplete
    );
    assert_eq!(r.harness.control.recordings_conflicts(), 0);
}

#[tokio::test]
async fn a_row_that_moved_during_an_adoption_keeps_the_staged_files_of_the_real_staging() {
    let gate = Arc::new(crate::recording_support::Gate::default());
    let staging = tempfile::tempdir().unwrap();
    let directory = DirectorySink::create(
        &staging.path().join("staging"),
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1 << 30,
        },
    )
    .unwrap();
    let memory = Arc::new(MemoryStore::new(
        directory,
        tokio::runtime::Handle::current(),
        Duration::from_secs(120),
    ));
    let gated = (gate.wrapper())(memory.sink.clone());
    let rec = rec(
        RecordingOptions {
            limits: RecordingLimits {
                max_uploads_per_node: 1,
                ..RecordingLimits::default()
            },
            wrap: Some(Arc::new(move |_| gated.clone())),
            ..RecordingOptions::default()
        },
        true,
    )
    .await;
    let s = S3Rec {
        rec,
        memory,
        staging,
        armed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 20_000, 53);
    upload_all(r, &session, &chunks).await;
    let cast = cast_of(&session.id, &chunks);
    let synthetic = synthetic_of(&manifest, chunks.len(), cast.len());
    let _kept = put_into_the_bucket(&s, &session, cast, synthetic).await;
    let pool = crate::session_support::raw_pool(&r.harness).await;
    let handle = tokio::runtime::Handle::current();
    let id = session.id.clone();
    gate.on_commit(Arc::new(move || {
        handle
            .block_on(
                sqlx::query("UPDATE recordings SET state = 'failed' WHERE session_id = ?")
                    .bind(&id)
                    .execute(&pool),
            )
            .unwrap();
    }));
    let staged = s.staged_files();
    let reply = r.complete(&session, &manifest).await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.text());
    assert_eq!(reply.error_code(), "recording_closed");
    assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
    let location = r.key(&session).await.location();
    let after = s.staged_files();
    assert!(
        after.contains(&format!("{location}.cast.part")),
        "{after:?}"
    );
    assert!(after.len() >= staged.len(), "{after:?} {staged:?}");
    let next = r.active().await;
    let accepted = r
        .chunk(&next, &wire(&crafted(&next.id, 0, b"zero\n", false)))
        .await;
    assert_eq!(accepted.status, StatusCode::OK, "the slot was not released");
}

#[tokio::test]
async fn a_corrupt_pending_manifest_ends_in_the_quarantine_and_a_failed_row_after_five_cycles() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    r.harness
        .store
        .recordings()
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let key = r.key(&session).await;
    let sink = s.memory.sink.clone();
    blocking(move || {
        let mut staged = sink.staging().begin_staged(&key).unwrap();
        jaunt_audit::StagedRecording::write(&mut staged, 0, b"delivered\n").unwrap();
        staged.stash_manifest(b"garbage").unwrap();
        staged.release();
    })
    .await;
    for cycle in 1..=4 {
        maintenance(&s).await;
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving,
            "{cycle}"
        );
        assert_eq!(s.staged_files().len(), 2, "{cycle}");
    }
    let (recovery, _) = maintenance(&s).await;
    assert_eq!(recovery.quarantined_ids, std::slice::from_ref(&session.id));
    let files = s.staged_files();
    assert!(
        files.iter().all(|file| file.starts_with("quarantine/")),
        "{files:?}"
    );
    assert_eq!(files.len(), 2);
    maintenance(&s).await;
    assert_eq!(r.row(&session).await.unwrap().state, RecordingState::Failed);
}

fn part_of(s: &S3Rec, location: &str) -> std::path::PathBuf {
    s.staging
        .path()
        .join("staging")
        .join(format!("{location}.cast.part"))
}

fn lock_down(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(path).is_ok() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        return false;
    }
    true
}

fn unlock(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn assert_keeps(now: &[String], before: &[String]) {
    for file in before {
        assert!(now.contains(file), "{file} is gone: {now:?}");
    }
}

fn make_fifo(path: &std::path::Path) {
    let made = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(made.success());
}

#[tokio::test]
async fn a_local_read_error_on_the_part_keeps_the_live_complete_retryable() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, manifest) = recorded(&session, 30_000, 41);
    upload_all(r, &session, &chunks).await;
    let location = r.key(&session).await.location();
    let part = part_of(&s, &location);
    if !lock_down(&part) {
        return;
    }
    let staged = s.staged_files();
    for _ in 0..2 {
        unavailable(&r.complete(&session, &manifest).await);
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving
        );
        assert_keeps(&s.staged_files(), &staged);
        r.harness.clock.advance(301);
    }
    unlock(&part);
    let receipt = r.complete(&session, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn a_directory_or_a_fifo_in_place_of_the_part_keeps_the_live_complete_retryable() {
    for kind in ["directory", "fifo"] {
        let s = s3_rec(RecordingLimits::default()).await;
        let r = &s.rec;
        let session = r.active().await;
        let (chunks, manifest) = recorded(&session, 30_000, 41);
        upload_all(r, &session, &chunks).await;
        let location = r.key(&session).await.location();
        let part = part_of(&s, &location);
        let moved = part.with_extension("moved");
        std::fs::rename(&part, &moved).unwrap();
        match kind {
            "directory" => std::fs::create_dir(&part).unwrap(),
            _ => make_fifo(&part),
        }
        unavailable(&r.complete(&session, &manifest).await);
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving,
            "{kind}"
        );
        assert!(part.symlink_metadata().is_ok(), "{kind}");
        match kind {
            "directory" => std::fs::remove_dir(&part).unwrap(),
            _ => std::fs::remove_file(&part).unwrap(),
        }
        std::fs::rename(&moved, &part).unwrap();
        r.harness.clock.advance(301);
        let receipt = r.complete(&session, &manifest).await;
        assert_eq!(
            receipt.json(),
            json!({"state": "complete", "chunks": chunks.len()}),
            "{kind}"
        );
        assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
    }
}

#[tokio::test]
async fn a_local_read_error_on_the_part_keeps_the_idle_salvage_deferred_and_loses_nothing() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, _) = recorded(&session, 30_000, 41);
    upload_all(r, &session, &chunks).await;
    let location = r.key(&session).await.location();
    let part = part_of(&s, &location);
    if !lock_down(&part) {
        return;
    }
    let staged = s.staged_files();
    r.end(&session, false).await;
    r.harness.clock.advance(7200);
    r.harness.control.sweep_idle_recordings().await;
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_keeps(&s.staged_files(), &staged);
    unlock(&part);
    r.harness.clock.advance(301);
    r.harness.control.sweep_idle_recordings().await;
    assert_stored_and_verifiable(&s, &session, RecordingState::Incomplete).await;
}

async fn crashed_with_progress(s: &S3Rec, session: &Session, chunks: &[Chunk], cast: &[u8]) {
    let r = &s.rec;
    let recordings = r.harness.store.recordings();
    recordings
        .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
        .await
        .unwrap();
    let key = r.key(session).await;
    let sink = s.memory.sink.clone();
    let bytes = cast.to_vec();
    let prefix = blocking(move || {
        let mut staged = sink.begin(&key).unwrap();
        staged.write(0, &bytes).unwrap();
        let prefix = staged.prefix_sha256();
        staged.keep_files();
        drop(staged);
        prefix
    })
    .await;
    assert!(
        recordings
            .record_progress(
                &session.id,
                u64::try_from(chunks.len()).unwrap(),
                u64::try_from(cast.len()).unwrap(),
                &prefix
            )
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_local_read_error_on_the_part_leaves_a_recovered_row_receiving_with_its_files() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, _) = recorded(&session, 30_000, 41);
    let cast = cast_of(&session.id, &chunks);
    crashed_with_progress(&s, &session, &chunks, &cast).await;
    let location = r.key(&session).await.location();
    let part = part_of(&s, &location);
    if !lock_down(&part) {
        return;
    }
    let staged = s.staged_files();
    for _ in 0..3 {
        let recovered = r.harness.control.recover_recordings().await.unwrap();
        assert_eq!(recovered.left_receiving, std::slice::from_ref(&session.id));
        assert_eq!(recovered.failed, 0);
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving
        );
        assert_eq!(s.staged_files(), staged);
    }
    unlock(&part);
    let recovered = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(recovered.salvaged, 1);
    assert_stored_and_verifiable(&s, &session, RecordingState::Incomplete).await;
}

fn synthetic_for(real: &SessionManifest, chunks: &[Chunk], cast: &[u8]) -> SessionManifest {
    synthetic_of(real, chunks.len(), cast.len())
}

#[tokio::test]
async fn an_acceptable_object_met_while_the_store_was_unreadable_is_never_a_false_conflict_later() {
    for variant in ["synthetic", "other_exit"] {
        let s = s3_rec(RecordingLimits {
            max_wait: Duration::from_secs(3600),
            ..RecordingLimits::default()
        })
        .await;
        let r = &s.rec;
        let session = r.active().await;
        let (chunks, real) = recorded(&session, 30_000, 41);
        upload_all(r, &session, &chunks).await;
        let cast = cast_of(&session.id, &chunks);
        let bucket = if variant == "synthetic" {
            synthetic_for(&real, &chunks, &cast)
        } else {
            let mut other = real.clone();
            other.exit_status = Some(137);
            other
        };
        let _kept = put_into_the_bucket(&s, &session, cast.clone(), bucket).await;
        s.armed.store(true, std::sync::atomic::Ordering::SeqCst);
        unavailable(&r.complete(&session, &real).await);
        r.end(&session, false).await;
        r.harness.clock.advance(7200);
        r.harness.control.sweep_idle_recordings().await;
        r.harness.clock.advance(3601);
        r.harness.control.sweep_idle_recordings().await;
        s.memory.switch_on();
        for _ in 0..3 {
            s.memory.wait_out_the_breaker();
            r.harness.clock.advance(301);
            let (recovery, _) = maintenance(&s).await;
            assert_eq!(recovery.refused, 0, "{variant}");
        }
        let row = r.row(&session).await.unwrap();
        let expected = if variant == "synthetic" {
            RecordingState::Incomplete
        } else {
            RecordingState::Complete
        };
        assert_eq!(row.state, expected, "{variant}");
        assert_eq!(r.harness.control.recordings_conflicts(), 0, "{variant}");
        assert!(s.staged_files().is_empty(), "{variant}");
    }
}

async fn given_up_with_the_store_off(s: &S3Rec, session: &Session, real: &SessionManifest) {
    let r = &s.rec;
    s.memory.switch_off();
    unavailable(&r.complete(session, real).await);
    r.end(session, false).await;
    r.harness.clock.advance(7200);
    r.harness.control.sweep_idle_recordings().await;
    r.harness.clock.advance(3601);
    r.harness.control.sweep_idle_recordings().await;
}

fn patient() -> RecordingLimits {
    RecordingLimits {
        max_wait: Duration::from_secs(3600),
        ..RecordingLimits::default()
    }
}

#[tokio::test]
async fn an_outage_or_a_local_fault_that_lasts_for_many_cycles_never_quarantines_or_fails() {
    let s = s3_rec(patient()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, real) = recorded(&session, 30_000, 41);
    upload_all(r, &session, &chunks).await;
    given_up_with_the_store_off(&s, &session, &real).await;
    let staged = s.staged_files();
    for cycle in 0..7 {
        s.memory.wait_out_the_breaker();
        r.harness.clock.advance(301);
        let (recovery, _) = maintenance(&s).await;
        assert_eq!(recovery.quarantined, 0, "outage {cycle}");
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving,
            "outage {cycle}"
        );
        assert_eq!(s.staged_files(), staged, "outage {cycle}");
    }
    s.memory.switch_on();
    let location = r.key(&session).await.location();
    let part = part_of(&s, &location);
    if lock_down(&part) {
        for cycle in 0..7 {
            s.memory.wait_out_the_breaker();
            r.harness.clock.advance(301);
            let (recovery, _) = maintenance(&s).await;
            assert_eq!(recovery.quarantined, 0, "fault {cycle}");
            assert_eq!(
                r.row(&session).await.unwrap().state,
                RecordingState::Receiving,
                "fault {cycle}"
            );
            assert_eq!(s.staged_files(), staged, "fault {cycle}");
        }
        unlock(&part);
    }
    s.memory.wait_out_the_breaker();
    r.harness.clock.advance(301);
    maintenance(&s).await;
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn a_hash_read_error_on_the_staged_cast_never_quarantines_through_the_control_cycle() {
    let s = s3_rec(patient()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, real) = recorded(&session, 30_000, 41);
    upload_all(r, &session, &chunks).await;
    given_up_with_the_store_off(&s, &session, &real).await;
    s.memory.switch_on();
    s.memory.sink.fail_staged_hash_reads(7);
    let staged = s.staged_files();
    for cycle in 0..7 {
        s.memory.wait_out_the_breaker();
        r.harness.clock.advance(301);
        let (recovery, _) = maintenance(&s).await;
        assert_eq!(recovery.quarantined, 0, "{cycle}");
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving,
            "{cycle}"
        );
        assert_eq!(s.staged_files(), staged, "{cycle}");
    }
    s.memory.wait_out_the_breaker();
    r.harness.clock.advance(301);
    maintenance(&s).await;
    assert_stored_and_verifiable(&s, &session, RecordingState::Complete).await;
}

#[tokio::test]
async fn a_recovery_without_staging_adopts_only_a_well_formed_manifest() {
    type Mutate = fn(&mut SessionManifest, usize);
    let cases: [(&str, bool, Mutate); 6] = [
        ("complete without a digest", true, |m, _| m.digest = None),
        (
            "complete with more raw bytes than the cast",
            true,
            |m, len| {
                m.raw_bytes = u64::try_from(len).unwrap() + 1000;
            },
        ),
        ("complete with dropped chunks", true, |m, _| {
            m.dropped_chunks = 5;
        }),
        ("complete without any cast object", false, |_, _| {}),
        ("incomplete without any cast object", false, |m, len| {
            m.incomplete = true;
            m.digest = None;
            m.exit_status = None;
            m.raw_bytes = u64::try_from(len).unwrap();
        }),
        ("an unknown manifest version", true, |m, _| m.version = 99),
    ];
    for (name, with_cast, mutate) in cases {
        let s = s3_rec(RecordingLimits::default()).await;
        let r = &s.rec;
        let session = r.active().await;
        let (chunks, real) = recorded(&session, 30_000, 41);
        let cast = cast_of(&session.id, &chunks);
        let mut manifest = real.clone();
        mutate(&mut manifest, cast.len());
        let _kept = if with_cast {
            put_into_the_bucket(&s, &session, cast.clone(), manifest).await
        } else {
            put_manifest_only(&s, &session, manifest).await
        };
        r.harness
            .store
            .recordings()
            .begin(&session.id, &session.node_id, r.harness.clock.now_secs())
            .await
            .unwrap();
        let recovered = r.harness.control.recover_recordings().await.unwrap();
        assert_eq!(recovered.adopted, 0, "{name}");
        assert_eq!(
            recovered.left_receiving,
            std::slice::from_ref(&session.id),
            "{name}"
        );
        assert_eq!(
            r.row(&session).await.unwrap().state,
            RecordingState::Receiving,
            "{name}"
        );
        assert_eq!(r.harness.control.recordings_conflicts(), 1, "{name}");
    }
}

#[tokio::test]
async fn a_recovery_with_staging_and_progress_refuses_a_complete_manifest_of_another_chunk_count() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let session = r.active().await;
    let (chunks, real) = recorded(&session, 30_000, 41);
    let cast = cast_of(&session.id, &chunks);
    let mut other = real.clone();
    other.digest = Some("ef".repeat(32));
    other.chunks = 999;
    let _kept = put_into_the_bucket(&s, &session, cast.clone(), other).await;
    crashed_with_progress(&s, &session, &chunks, &cast).await;
    let staged = s.staged_files();
    let recovered = r.harness.control.recover_recordings().await.unwrap();
    assert_eq!(recovered.adopted, 0);
    assert_eq!(recovered.left_receiving, std::slice::from_ref(&session.id));
    assert_eq!(
        r.row(&session).await.unwrap().state,
        RecordingState::Receiving
    );
    assert_eq!(r.harness.control.recordings_conflicts(), 1);
    assert_eq!(s.staged_files(), staged);
}

mod timelines {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum T {
        Live,
        LiveDown,
        Expire,
        GiveUp,
        SalvageOnly,
        Crash,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum B {
        Empty,
        IdenticalReal,
        Synthetic,
        OtherManifest,
        OtherCast,
        PrefixCast,
        OtherNode,
        OrphanCast,
        OrphanOtherCast,
        ManifestOnlySynth,
        OtherSession,
        OtherUser,
        OtherLogin,
        OtherExit,
    }

    impl B {
        fn foreign(self) -> bool {
            matches!(
                self,
                B::OtherManifest
                    | B::OtherCast
                    | B::PrefixCast
                    | B::OtherNode
                    | B::OtherSession
                    | B::OtherUser
                    | B::OtherLogin
            )
        }
    }

    async fn inject(
        s: &S3Rec,
        session: &Session,
        b: B,
        real: &SessionManifest,
        chunks: &[Chunk],
        cast: &[u8],
    ) -> Option<Foreign> {
        let synthetic = synthetic_of(real, chunks.len(), cast.len());
        let (c, m): (Option<Vec<u8>>, SessionManifest) = match b {
            B::Empty => return None,
            B::IdenticalReal | B::OrphanCast => (Some(cast.to_vec()), real.clone()),
            B::Synthetic => (Some(cast.to_vec()), synthetic),
            B::OtherManifest => {
                let mut other = real.clone();
                other.digest = Some("ef".repeat(32));
                other.chunks = 999;
                (Some(cast.to_vec()), other)
            }
            B::OtherCast => {
                let mut foreign = cast.to_vec();
                let last = foreign.len() - 1;
                foreign[last] ^= 1;
                (Some(foreign), synthetic)
            }
            B::PrefixCast => {
                let prefix = cast[..cast.len() / 2].to_vec();
                let mut m = synthetic;
                m.chunks = 1;
                m.raw_bytes = u64::try_from(prefix.len()).unwrap();
                (Some(prefix), m)
            }
            B::OtherNode => {
                let mut other = real.clone();
                other.node = "another-node".to_owned();
                (Some(cast.to_vec()), other)
            }
            B::OrphanOtherCast => {
                let mut foreign = cast.to_vec();
                foreign[0] ^= 1;
                (Some(foreign), real.clone())
            }
            B::ManifestOnlySynth => (None, synthetic),
            B::OtherSession => {
                let mut other = real.clone();
                other.session_id = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11".to_owned();
                (Some(cast.to_vec()), other)
            }
            B::OtherUser => {
                let mut other = real.clone();
                other.user = "someone-else".to_owned();
                (Some(cast.to_vec()), other)
            }
            B::OtherLogin => {
                let mut other = real.clone();
                other.login = "root".to_owned();
                (Some(cast.to_vec()), other)
            }
            B::OtherExit => {
                let mut other = real.clone();
                other.exit_status = Some(137);
                (Some(cast.to_vec()), other)
            }
        };
        if b == B::OtherSession {
            let key = s.rec.key(session).await;
            let base = format!("recordings/{}", key.location());
            s.memory
                .put_object(&format!("{base}.cast"), c.unwrap())
                .await;
            s.memory
                .put_object(
                    &format!("{base}.manifest.json"),
                    jaunt_audit::manifest_bytes(&m).unwrap(),
                )
                .await;
            return Some(Foreign {
                _staging: tempfile::tempdir().unwrap(),
            });
        }
        let kept = match c {
            Some(c) => put_into_the_bucket(s, session, c, m).await,
            None => put_manifest_only(s, session, m).await,
        };
        if matches!(b, B::OrphanCast | B::OrphanOtherCast) {
            let key = s.rec.key(session).await;
            s.memory
                .delete_object(&format!("recordings/{}.manifest.json", key.location()))
                .await;
        }
        Some(kept)
    }

    async fn snapshot(s: &S3Rec, session: &Session) -> Vec<Option<Vec<u8>>> {
        let key = s.rec.key(session).await;
        let base = format!("recordings/{}", key.location());
        let mut out = Vec::new();
        for suffix in [".cast", ".manifest.json"] {
            out.push(s.memory.object_bytes(&format!("{base}{suffix}")).await);
        }
        out
    }

    async fn settle_all(s: &S3Rec) {
        s.memory.switch_on();
        for _ in 0..3 {
            s.memory.wait_out_the_breaker();
            s.rec.harness.clock.advance(301);
            maintenance(s).await;
        }
    }

    struct Cell {
        state: RecordingState,
        has_staging: bool,
        verify: Option<String>,
        changed: bool,
    }

    async fn run(t: T, b: B) -> Cell {
        let s = s3_rec(patient()).await;
        let r = &s.rec;
        let session = r.active().await;
        let (chunks, real) = recorded(&session, 30_000, 41);
        let cast = cast_of(&session.id, &chunks);
        let key = r.key(&session).await;
        let _foreign;
        match t {
            T::Live => {
                upload_all(r, &session, &chunks).await;
                _foreign = inject(&s, &session, b, &real, &chunks, &cast).await;
                if r.complete(&session, &real).await.status == StatusCode::SERVICE_UNAVAILABLE {
                    s.memory.switch_on();
                    s.memory.wait_out_the_breaker();
                    r.complete(&session, &real).await;
                }
            }
            T::LiveDown => {
                upload_all(r, &session, &chunks).await;
                s.memory.switch_off();
                r.complete(&session, &real).await;
                s.memory.switch_on();
                s.memory.wait_out_the_breaker();
                _foreign = inject(&s, &session, b, &real, &chunks, &cast).await;
                r.complete(&session, &real).await;
                s.memory.wait_out_the_breaker();
                r.complete(&session, &real).await;
            }
            T::Expire | T::GiveUp => {
                upload_all(r, &session, &chunks).await;
                s.memory.switch_off();
                r.complete(&session, &real).await;
                r.end(&session, false).await;
                r.harness.clock.advance(7200);
                r.harness.control.sweep_idle_recordings().await;
                if t == T::GiveUp {
                    r.harness.clock.advance(3601);
                    r.harness.control.sweep_idle_recordings().await;
                }
                s.memory.switch_on();
                s.memory.wait_out_the_breaker();
                _foreign = inject(&s, &session, b, &real, &chunks, &cast).await;
                s.memory.wait_out_the_breaker();
                r.harness.clock.advance(301);
                r.harness.control.sweep_idle_recordings().await;
            }
            T::SalvageOnly => {
                upload_all(r, &session, &chunks).await;
                _foreign = inject(&s, &session, b, &real, &chunks, &cast).await;
                r.end(&session, false).await;
                r.harness.clock.advance(7200);
                r.harness.control.sweep_idle_recordings().await;
            }
            T::Crash => {
                crashed_with_progress(&s, &session, &chunks, &cast).await;
                _foreign = inject(&s, &session, b, &real, &chunks, &cast).await;
                let recovered = r.harness.control.recover_recordings().await.unwrap();
                s.memory
                    .sink
                    .staging()
                    .remove_leftovers_except(&recovered.left_receiving)
                    .unwrap();
            }
        }
        let before = snapshot(&s, &session).await;
        settle_all(&s).await;
        r.harness.control.sweep_idle_recordings().await;
        let after = snapshot(&s, &session).await;
        let row = r.row(&session).await.unwrap();
        let location = key.location();
        let has_staging = s
            .staged_files()
            .iter()
            .any(|file| file.contains(&location) && file.ends_with(".cast.part"));
        let verify = if row.state.is_stored() {
            let sink = s.memory.sink.clone();
            let (k, stored) = (key.clone(), row.clone());
            blocking(move || verify_stored(sink.as_ref(), &k, &stored))
                .await
                .err()
                .map(|error| error.to_string())
        } else {
            None
        };
        Cell {
            state: row.state,
            has_staging,
            verify,
            changed: before != after,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_timeline_destroys_leaks_or_misstores_a_recording_whatever_the_bucket_holds() {
        let timelines = [
            T::Live,
            T::LiveDown,
            T::Expire,
            T::GiveUp,
            T::SalvageOnly,
            T::Crash,
        ];
        let buckets = [
            B::Empty,
            B::IdenticalReal,
            B::Synthetic,
            B::OtherManifest,
            B::OtherCast,
            B::PrefixCast,
            B::OtherNode,
            B::OrphanCast,
            B::OrphanOtherCast,
            B::ManifestOnlySynth,
            B::OtherSession,
            B::OtherUser,
            B::OtherLogin,
            B::OtherExit,
        ];
        let mut wrong = Vec::new();
        for b in buckets {
            for t in timelines {
                let cell = run(t, b).await;
                if cell.state == RecordingState::Failed {
                    wrong.push(format!("{t:?} x {b:?}: the row failed"));
                }
                if cell.state == RecordingState::Receiving && !cell.has_staging {
                    wrong.push(format!("{t:?} x {b:?}: a receiving row lost its staging"));
                }
                if let Some(error) = &cell.verify {
                    wrong.push(format!("{t:?} x {b:?}: stored but unverifiable: {error}"));
                }
                if b.foreign() && cell.changed {
                    wrong.push(format!("{t:?} x {b:?}: the foreign objects were changed"));
                }
                if b.foreign() && cell.state.is_stored() {
                    wrong.push(format!("{t:?} x {b:?}: a foreign recording was adopted"));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}

#[tokio::test]
async fn an_open_error_while_the_part_is_being_uploaded_keeps_the_live_and_the_salvage_paths() {
    let s = s3_rec(RecordingLimits::default()).await;
    let r = &s.rec;
    let live = r.active().await;
    let (chunks, manifest) = recorded(&live, 30_000, 41);
    upload_all(r, &live, &chunks).await;
    s.memory.sink.fail_staged_opens_while_storing(1);
    unavailable(&r.complete(&live, &manifest).await);
    assert_eq!(r.row(&live).await.unwrap().state, RecordingState::Receiving);
    let location = r.key(&live).await.location();
    assert!(s.staged_files().contains(&format!("{location}.cast.part")));
    r.harness.clock.advance(301);
    let receipt = r.complete(&live, &manifest).await;
    assert_eq!(
        receipt.json(),
        json!({"state": "complete", "chunks": chunks.len()})
    );
    assert_stored_and_verifiable(&s, &live, RecordingState::Complete).await;

    let idle = r.active().await;
    let (idle_chunks, _) = recorded(&idle, 30_000, 42);
    upload_all(r, &idle, &idle_chunks).await;
    s.memory.sink.fail_staged_opens_while_storing(1);
    r.end(&idle, false).await;
    r.harness.clock.advance(7200);
    r.harness.control.sweep_idle_recordings().await;
    assert_eq!(r.row(&idle).await.unwrap().state, RecordingState::Receiving);
    let idle_location = r.key(&idle).await.location();
    assert!(
        s.staged_files()
            .contains(&format!("{idle_location}.cast.part"))
    );
    r.harness.clock.advance(301);
    r.harness.control.sweep_idle_recordings().await;
    assert_stored_and_verifiable(&s, &idle, RecordingState::Incomplete).await;
}
