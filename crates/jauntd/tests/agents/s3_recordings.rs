use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingKey, RecordingSink, verify_stored};
use jaunt_control::RecordingLimits;
use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
use jaunt_recording_s3::testing::MemoryStore;
use jaunt_store::RecordingState;
use jauntd::recordings::{PreparedRecordings, RecordingsStartError};

use crate::recordings::{RecordedSession, active_session_with_row};
use crate::support::{Harness, Options};

struct Stand {
    harness: Harness,
    memory: Arc<MemoryStore>,
    staging: std::path::PathBuf,
    session: RecordedSession,
    _dir: tempfile::TempDir,
}

async fn stand() -> Stand {
    let dir = tempfile::tempdir().unwrap();
    let staging = dir.path().join("staging");
    let directory = DirectorySink::create(
        &staging,
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
    let prepared = PreparedRecordings::for_s3_sink(
        memory.sink.clone(),
        RecordingLimits::default(),
        staging.clone(),
    );
    let harness = Harness::start(Options {
        prepared: Some(prepared),
        ..Options::default()
    })
    .await;
    let session = active_session_with_row(&harness).await;
    Stand {
        harness,
        memory,
        staging,
        session,
        _dir: dir,
    }
}

impl Stand {
    fn key(&self) -> RecordingKey {
        RecordingKey::new(&self.session.id, self.session.started).unwrap()
    }

    fn prepared(&self) -> &PreparedRecordings {
        self.harness.recordings.as_ref().unwrap()
    }

    fn staged_names(&self) -> Vec<String> {
        let month = self.staging.join(self.key().location());
        let month = month.parent().unwrap().to_path_buf();
        let mut names: Vec<String> = std::fs::read_dir(month)
            .map(|entries| {
                entries
                    .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    async fn state(&self) -> RecordingState {
        self.harness
            .store
            .recordings()
            .get(&self.session.id)
            .await
            .unwrap()
            .unwrap()
            .state
    }

    async fn deliver_prefix(&self) {
        let sink = self.memory.sink.clone();
        let key = self.key();
        let prefix = tokio::task::spawn_blocking(move || {
            let mut staged = sink.begin(&key).unwrap();
            staged.write(0, b"zero\n").unwrap();
            staged.write(1, b"one\n").unwrap();
            let prefix = staged.prefix_sha256();
            std::mem::forget(staged);
            prefix
        })
        .await
        .unwrap();
        assert!(
            self.harness
                .store
                .recordings()
                .record_progress(&self.session.id, 2, 9, &prefix)
                .await
                .unwrap()
        );
    }
}

fn manifest_of(session: &RecordedSession, chunks: u64, raw_bytes: u64) -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: session.id.clone(),
        kind: SessionKind::Shell,
        node: session.node_id.clone(),
        user: session.user_id.clone(),
        login: "deploy".to_owned(),
        started_at: u64::try_from(session.started).unwrap(),
        ended_at: Some(u64::try_from(session.started).unwrap() + 5),
        exit_status: Some(3),
        command: None,
        bytes_out: raw_bytes,
        bytes_in: 0,
        input_recorded: false,
        chunks,
        raw_bytes,
        incomplete: false,
        dropped_chunks: 0,
        digest: Some("d".repeat(64)),
    }
}

#[tokio::test]
async fn a_start_while_the_store_is_down_keeps_the_delivered_prefix_of_a_receiving_row() {
    let s = stand().await;
    s.deliver_prefix().await;
    s.memory.switch_off();

    jauntd::recordings::recover(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    assert_eq!(s.state().await, RecordingState::Receiving);
    assert_eq!(s.staged_names(), [format!("{}.cast.part", s.session.id)]);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    jauntd::recordings::retry_staged(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    assert_eq!(s.state().await, RecordingState::Incomplete);
    assert!(s.staged_names().is_empty(), "{:?}", s.staged_names());
    let sink = s.memory.sink.clone();
    let key = s.key();
    let row = s
        .harness
        .store
        .recordings()
        .get(&s.session.id)
        .await
        .unwrap()
        .unwrap();
    tokio::task::spawn_blocking(move || verify_stored(sink.as_ref(), &key, &row).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_finished_recording_waiting_for_the_store_is_published_with_its_real_manifest_by_the_retry()
 {
    let s = stand().await;
    s.memory.switch_off();
    let real = manifest_of(&s.session, 2, 9);
    let sink = s.memory.sink.clone();
    let key = s.key();
    let committing = real.clone();
    let prefix = tokio::task::spawn_blocking(move || {
        let mut staged = sink.begin(&key).unwrap();
        staged.write(0, b"zero\n").unwrap();
        staged.write(1, b"one\n").unwrap();
        let prefix = staged.prefix_sha256();
        assert!(staged.commit(&committing).is_err());
        drop(staged);
        prefix
    })
    .await
    .unwrap();
    s.harness
        .store
        .recordings()
        .record_progress(&s.session.id, 2, 9, &prefix)
        .await
        .unwrap();
    assert_eq!(
        s.staged_names(),
        [
            format!("{}.cast.part", s.session.id),
            format!("{}.manifest.pending", s.session.id)
        ]
    );

    jauntd::recordings::recover(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    assert_eq!(s.state().await, RecordingState::Receiving);
    assert_eq!(s.staged_names().len(), 2);

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    jauntd::recordings::retry_staged(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    let row = s
        .harness
        .store
        .recordings()
        .get(&s.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, RecordingState::Complete);
    assert_eq!(row.digest, real.digest);
    assert!(!row.salvaged);
    assert!(s.staged_names().is_empty());
    let sink = s.memory.sink.clone();
    let key = s.key();
    let stored = tokio::task::spawn_blocking(move || sink.open(&key).unwrap().unwrap())
        .await
        .unwrap();
    assert_eq!(stored.manifest, real);
}

#[tokio::test]
async fn the_startup_probe_stops_on_a_rejection_and_only_warns_when_the_store_is_unreachable() {
    let s = stand().await;
    let probe = |s: &Stand| {
        let prepared = s.prepared().clone();
        async move { jauntd::recordings::probe(&prepared).await }
    };
    probe(&s).await.unwrap();

    s.memory.switch_off();
    probe(&s).await.unwrap();

    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    s.memory.reject_writes();
    let refused = probe(&s).await.unwrap_err();
    assert!(
        matches!(
            refused,
            RecordingsStartError::Probe(jaunt_recording_s3::ProbeError::Rejected(_))
        ),
        "{refused}"
    );
    s.memory.accept_writes();
    probe(&s).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_periodic_retry_runs_every_interval_and_not_before() {
    let ticks = Arc::new(AtomicU64::new(0));
    let counter = ticks.clone();
    let task = tokio::spawn(jauntd::recordings::every(
        jauntd::recordings::RETRY_INTERVAL,
        move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        },
    ));
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(ticks.load(Ordering::SeqCst), 0);
    tokio::time::advance(jauntd::recordings::RETRY_INTERVAL - Duration::from_secs(1)).await;
    settle().await;
    assert_eq!(ticks.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(ticks.load(Ordering::SeqCst), 1);
    tokio::time::advance(jauntd::recordings::RETRY_INTERVAL).await;
    settle().await;
    assert_eq!(ticks.load(Ordering::SeqCst), 2);
    task.abort();
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn the_maintenance_task_retries_a_waiting_recording_on_its_own() {
    let s = stand().await;
    s.deliver_prefix().await;
    s.memory.switch_off();
    jauntd::recordings::recover(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();
    let maintenance = jauntd::recordings::start_maintenance(
        Some(s.prepared()),
        &s.harness.control,
        Duration::from_millis(50),
        jauntd::recordings::SCAN_INTERVAL,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while s.state().await == RecordingState::Receiving {
        assert!(
            std::time::Instant::now() < deadline,
            "the retry never stored the recording"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(s.state().await, RecordingState::Incomplete);
    maintenance.stop();
}

#[tokio::test]
async fn a_start_with_the_store_up_publishes_the_real_pending_manifest_before_it_adopts() {
    let s = stand().await;
    s.memory.switch_off();
    let real = manifest_of(&s.session, 2, 9);
    let sink = s.memory.sink.clone();
    let key = s.key();
    let committing = real.clone();
    let prefix = tokio::task::spawn_blocking(move || {
        let mut staged = sink.begin(&key).unwrap();
        staged.write(0, b"zero\n").unwrap();
        staged.write(1, b"one\n").unwrap();
        let prefix = staged.prefix_sha256();
        assert!(staged.commit(&committing).is_err());
        drop(staged);
        prefix
    })
    .await
    .unwrap();
    s.harness
        .store
        .recordings()
        .record_progress(&s.session.id, 2, 9, &prefix)
        .await
        .unwrap();
    s.memory.switch_on();
    s.memory.wait_out_the_breaker();

    jauntd::recordings::recover(s.prepared(), &s.harness.control)
        .await
        .unwrap();
    let row = s
        .harness
        .store
        .recordings()
        .get(&s.session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, RecordingState::Complete);
    assert!(!row.salvaged);
    assert_eq!(row.digest, real.digest);
    assert!(s.staged_names().is_empty());
}

#[tokio::test]
async fn the_orphan_scan_runs_again_every_interval_and_not_only_at_the_start() {
    let s = stand().await;
    let late_orphan = object_store::path::Path::parse(format!(
        "recordings/{}/{}.cast",
        s.key().location().rsplit_once('/').unwrap().0,
        "5f0c3a52-8a8e-4c55-9a51-0000000000aa"
    ))
    .unwrap();
    let far_future = i64::MAX / 4;
    let now = move || far_future.min(jaunt_audit::Timestamp::now().millis() / 1000 + 7200);
    let scans =
        jauntd::recordings::start_scans(s.memory.sink.clone(), Duration::from_millis(50), now);
    tokio::time::sleep(Duration::from_millis(150)).await;
    object_store::ObjectStoreExt::put(
        s.memory.store.as_ref(),
        &late_orphan,
        object_store::PutPayload::from(b"orphan".to_vec()),
    )
    .await
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let found = object_store::ObjectStoreExt::head(s.memory.store.as_ref(), &late_orphan).await;
        if matches!(found, Err(object_store::Error::NotFound { .. })) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a later scan never removed the orphan"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    scans.abort();
}

#[tokio::test]
async fn the_maintenance_task_repeats_the_scan_at_the_scan_interval_it_is_given() {
    let s = stand().await;
    let maintenance = jauntd::recordings::start_maintenance(
        Some(s.prepared()),
        &s.harness.control,
        jauntd::recordings::RETRY_INTERVAL,
        Duration::from_millis(50),
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while s.memory.list_calls() < 10 {
        assert!(
            std::time::Instant::now() < deadline,
            "the scan did not repeat: {} listings",
            s.memory.list_calls()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    maintenance.stop();
}
