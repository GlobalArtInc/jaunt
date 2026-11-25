use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use jaunt_audit::{
    DirectoryLimits, DirectorySink, FreeSpace, Leftovers, RecordingKey, RecordingSink,
    RecordingStoreError, VerifyFailure, verify_stored,
};
use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
use jaunt_store::{Recording, RecordingState};
use tempfile::TempDir;

const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";
const OTHER: &str = "0b1c2d3e-4f50-4617-8829-3a4b5c6d7e8f";
const STARTED: i64 = 1_764_028_800;
const MONTH: &str = "2025/11";

fn limits() -> DirectoryLimits {
    DirectoryLimits {
        min_free_bytes: 0,
        max_total_raw: 1024,
    }
}

fn sink(dir: &TempDir) -> DirectorySink {
    DirectorySink::create(&dir.path().join("recordings"), limits()).unwrap()
}

fn key(id: &str) -> RecordingKey {
    RecordingKey::new(id, STARTED).unwrap()
}

fn month_dir(dir: &TempDir) -> PathBuf {
    dir.path().join("recordings").join(MONTH)
}

fn manifest(id: &str, chunks: u64, raw_bytes: u64) -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: id.to_owned(),
        kind: SessionKind::Shell,
        node: "node-1".to_owned(),
        user: "user-1".to_owned(),
        login: "deploy".to_owned(),
        started_at: 1,
        ended_at: Some(2),
        exit_status: Some(0),
        command: None,
        bytes_out: 10,
        bytes_in: 0,
        input_recorded: false,
        chunks,
        raw_bytes,
        incomplete: false,
        dropped_chunks: 0,
        digest: Some("d".repeat(64)),
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    found.sort();
    found
}

fn row(id: &str, committed: &jaunt_audit::Committed, manifest: &SessionManifest) -> Recording {
    Recording {
        session_id: id.to_owned(),
        node_id: "node-1".to_owned(),
        state: RecordingState::Complete,
        chunks: manifest.chunks,
        raw_bytes: committed.cast_bytes,
        progress_sha256: None,
        digest: manifest.digest.clone(),
        input_recorded: manifest.input_recorded,
        incomplete: false,
        session_incomplete: None,
        salvaged: false,
        dropped_chunks: 0,
        location: Some(committed.location.clone()),
        cast_sha256: committed.cast_sha256.clone(),
        manifest_sha256: Some(committed.manifest_sha256.clone()),
        created_at: STARTED,
        completed_at: Some(STARTED),
    }
}

#[test]
fn a_committed_recording_reads_back_byte_for_byte_and_leaves_no_part_files() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut staged = sink.begin(&key(ID)).unwrap();
    assert!(sink.open(&key(ID)).unwrap().is_none());
    for (seq, part) in [b"first\n".as_slice(), b"", b"third\n"].iter().enumerate() {
        staged.write(u64::try_from(seq).unwrap(), part).unwrap();
    }
    assert_eq!(names(&month_dir(&dir)), [format!("{ID}.cast.part")]);
    let written = manifest(ID, 3, 12);
    let committed = staged.commit(&written).unwrap();
    assert_eq!(committed.location, format!("{MONTH}/{ID}"));
    assert_eq!(committed.cast_bytes, 12);
    assert_eq!(
        names(&month_dir(&dir)),
        [format!("{ID}.cast"), format!("{ID}.manifest.json")]
    );

    let mut stored = sink.open(&key(ID)).unwrap().unwrap();
    assert_eq!(stored.manifest, written);
    assert_eq!(stored.manifest_sha256, committed.manifest_sha256);
    let mut cast = String::new();
    stored
        .cast
        .take()
        .unwrap()
        .read_to_string(&mut cast)
        .unwrap();
    assert_eq!(cast, "first\nthird\n");
    let verified = verify_stored(&sink, &key(ID), &row(ID, &committed, &written)).unwrap();
    assert_eq!(verified.cast_sha256, committed.cast_sha256);

    assert!(matches!(
        sink.begin(&key(ID)).map(|_| ()),
        Err(RecordingStoreError::Exists)
    ));
}

#[test]
fn a_metadata_only_recording_stores_just_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut metadata = manifest(ID, 0, 0);
    metadata.kind = SessionKind::Exec;
    metadata.digest = None;
    let committed = sink.begin(&key(ID)).unwrap().commit(&metadata).unwrap();
    assert_eq!(committed.cast_sha256, None);
    assert_eq!(names(&month_dir(&dir)), [format!("{ID}.manifest.json")]);
    let stored = sink.open(&key(ID)).unwrap().unwrap();
    assert!(stored.cast.is_none());
    verify_stored(&sink, &key(ID), &row(ID, &committed, &metadata)).unwrap();
}

#[test]
fn abort_and_drop_remove_the_staged_part() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut aborted = sink.begin(&key(ID)).unwrap();
    aborted.write(0, b"data").unwrap();
    aborted.abort().unwrap();
    let mut dropped = sink.begin(&key(OTHER)).unwrap();
    dropped.write(0, b"data").unwrap();
    drop(dropped);
    assert!(names(&month_dir(&dir)).is_empty());
}

#[test]
fn the_size_order_and_free_space_limits_refuse_writes() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(3, b"a").unwrap();
    assert!(matches!(
        staged.write(3, b"b"),
        Err(RecordingStoreError::OutOfOrder { seq: 3 })
    ));
    assert!(matches!(
        staged.write(4, &[0u8; 1024]),
        Err(RecordingStoreError::TooLarge)
    ));
    staged.write(4, &[0u8; 1023]).unwrap();

    let full = DirectorySink::create(
        &dir.path().join("full"),
        DirectoryLimits {
            min_free_bytes: u64::MAX,
            max_total_raw: 1024,
        },
    )
    .unwrap();
    assert!(matches!(
        full.begin(&key(ID)).map(|_| ()),
        Err(RecordingStoreError::DiskFull)
    ));
    assert!(names(&dir.path().join("full")).is_empty());
}

#[test]
fn a_symlink_planted_at_either_target_is_refused_and_never_written_through() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let victim = dir.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();

    let mut staged = sink.begin(&key(ID)).unwrap();
    symlink(&victim, month_dir(&dir).join(format!("{ID}.cast.part"))).unwrap();
    assert!(matches!(
        staged.write(0, b"payload"),
        Err(RecordingStoreError::Exists)
    ));
    drop(staged);

    let mut staged = sink.begin(&key(OTHER)).unwrap();
    staged.write(0, b"payload").unwrap();
    symlink(&victim, month_dir(&dir).join(format!("{OTHER}.cast"))).unwrap();
    assert!(matches!(
        staged.commit(&manifest(OTHER, 1, 7)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert_eq!(
        names(&month_dir(&dir)),
        [format!("{OTHER}.cast"), format!("{ID}.cast.part")]
    );
    assert!(matches!(
        sink.open(&key(OTHER)).map(|stored| stored.is_none()),
        Ok(true)
    ));

    let year = dir.path().join("recordings").join("2026");
    symlink(dir.path(), &year).unwrap();
    let january = RecordingKey::new(ID, 1_767_225_600).unwrap();
    assert!(matches!(
        sink.begin(&january).map(|_| ()),
        Err(RecordingStoreError::UnsafePath)
    ));
}

#[test]
fn a_failed_manifest_write_leaves_no_recording_because_the_manifest_comes_last() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"payload").unwrap();
    let blocker = month_dir(&dir).join(format!("{ID}.manifest.json.part"));
    fs::create_dir(&blocker).unwrap();
    assert!(matches!(
        staged.commit(&manifest(ID, 1, 7)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(
        names(&month_dir(&dir)),
        [format!("{ID}.manifest.json.part")]
    );
    assert!(sink.open(&key(ID)).unwrap().is_none());
}

#[test]
fn leftovers_of_a_previous_run_are_removed_but_stored_recordings_stay() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut kept = sink.begin(&key(ID)).unwrap();
    kept.write(0, b"kept").unwrap();
    let committed = kept.commit(&manifest(ID, 1, 4)).unwrap();
    let month = month_dir(&dir);
    let crash = "8c7d6e5f-4a3b-4c2d-9e1f-0a1b2c3d4e5f";
    for name in [
        format!("{OTHER}.cast.part"),
        format!("{OTHER}.manifest.json.part"),
        format!("{crash}.cast"),
        "notes.txt".to_owned(),
        "escape.cast.part".to_owned(),
    ] {
        fs::write(month.join(name), b"x").unwrap();
    }
    let elsewhere = dir.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::write(elsewhere.join(format!("{OTHER}.cast.part")), b"x").unwrap();
    symlink(&elsewhere, dir.path().join("recordings").join("2024")).unwrap();

    assert_eq!(
        sink.remove_leftovers().unwrap(),
        Leftovers {
            parts: 2,
            orphan_casts: 1
        }
    );
    assert_eq!(
        names(&month),
        [
            format!("{ID}.cast"),
            format!("{ID}.manifest.json"),
            "escape.cast.part".to_owned(),
            "notes.txt".to_owned(),
        ]
    );
    assert_eq!(names(&elsewhere), [format!("{OTHER}.cast.part")]);
    verify_stored(&sink, &key(ID), &row(ID, &committed, &manifest(ID, 1, 4))).unwrap();
}

#[test]
fn verification_catches_a_flipped_bit_a_changed_manifest_and_a_wrong_row() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let written = manifest(ID, 1, 7);
    let committed = {
        let mut staged = sink.begin(&key(ID)).unwrap();
        staged.write(0, b"payload").unwrap();
        staged.commit(&written).unwrap()
    };
    let good = row(ID, &committed, &written);
    verify_stored(&sink, &key(ID), &good).unwrap();

    let wrong_rows = [
        Recording {
            state: RecordingState::Failed,
            ..good.clone()
        },
        Recording {
            location: Some(format!("2025/10/{ID}")),
            ..good.clone()
        },
        Recording {
            digest: None,
            ..good.clone()
        },
        Recording {
            raw_bytes: 8,
            ..good.clone()
        },
    ];
    for wrong in &wrong_rows {
        assert!(verify_stored(&sink, &key(ID), wrong).is_err(), "{wrong:?}");
    }

    let cast = month_dir(&dir).join(format!("{ID}.cast"));
    let mut bytes = fs::read(&cast).unwrap();
    bytes[3] ^= 0x01;
    fs::write(&cast, &bytes).unwrap();
    assert!(matches!(
        verify_stored(&sink, &key(ID), &good),
        Err(VerifyFailure::CastChanged)
    ));
    bytes[3] ^= 0x01;
    fs::write(&cast, &bytes).unwrap();
    verify_stored(&sink, &key(ID), &good).unwrap();

    let path = month_dir(&dir).join(format!("{ID}.manifest.json"));
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replace("\"bytes_out\":10", "\"bytes_out\":11")).unwrap();
    assert!(matches!(
        verify_stored(&sink, &key(ID), &good),
        Err(VerifyFailure::ManifestChanged)
    ));
    fs::write(&path, text.replace(ID, OTHER)).unwrap();
    assert!(matches!(
        verify_stored(&sink, &key(ID), &good),
        Err(VerifyFailure::Storage(RecordingStoreError::InvalidManifest))
    ));
    fs::remove_file(&path).unwrap();
    symlink(&cast, &path).unwrap();
    assert!(matches!(
        sink.open(&key(ID)).map(|_| ()),
        Err(RecordingStoreError::UnsafePath)
    ));
}

#[test]
fn the_free_space_reserve_is_checked_again_for_every_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let available = Arc::new(AtomicU64::new(1_000_000));
    let probe = available.clone();
    let free_space: FreeSpace = Arc::new(move |_| Ok(probe.load(Ordering::SeqCst)));
    let sink = DirectorySink::create(
        &dir.path().join("recordings"),
        DirectoryLimits {
            min_free_bytes: 1000,
            max_total_raw: 1024,
        },
    )
    .unwrap()
    .with_free_space(free_space);
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"first\n").unwrap();
    available.store(1005, Ordering::SeqCst);
    assert!(matches!(
        staged.write(1, b"second\n"),
        Err(RecordingStoreError::DiskFull)
    ));
    staged.write(1, b"two\n").unwrap();
    assert_eq!(staged.written(), 10);
}

#[test]
fn an_interrupted_part_resumes_cut_to_the_delivered_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    assert!(sink.resume(&key(ID), 6, "x").unwrap().is_none());
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"first\n").unwrap();
    staged.write(1, b"second\n").unwrap();
    let prefix = staged.prefix_sha256();
    staged.write(2, b"tor").unwrap();
    std::mem::forget(staged);

    assert!(sink.resume(&key(ID), 100, &prefix).unwrap().is_none());
    let resumed = sink.resume(&key(ID), 13, &prefix).unwrap().unwrap();
    assert_eq!(resumed.written(), 13);
    let mut salvaged = manifest(ID, 2, 13);
    salvaged.incomplete = true;
    salvaged.digest = None;
    let committed = resumed.commit(&salvaged).unwrap();
    let cast = fs::read(month_dir(&dir).join(format!("{ID}.cast"))).unwrap();
    assert_eq!(cast, b"first\nsecond\n");
    let row = Recording {
        incomplete: true,
        salvaged: true,
        ..row(ID, &committed, &salvaged)
    };
    verify_stored(&sink, &key(ID), &row).unwrap();
    let complete_without_digest = Recording {
        incomplete: false,
        ..row.clone()
    };
    assert!(matches!(
        verify_stored(&sink, &key(ID), &complete_without_digest),
        Err(VerifyFailure::DigestMissing)
    ));
    assert!(matches!(
        sink.resume(&key(ID), 13, &prefix).map(|_| ()),
        Err(RecordingStoreError::Exists)
    ));
}

#[test]
fn a_part_whose_delivered_prefix_changed_on_disk_is_not_resumed_and_is_removed() {
    let dir = tempfile::tempdir().unwrap();
    let sink = sink(&dir);
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"first\n").unwrap();
    staged.write(1, b"second\n").unwrap();
    let prefix = staged.prefix_sha256();
    std::mem::forget(staged);
    let part = month_dir(&dir).join(format!("{ID}.cast.part"));
    let mut bytes = fs::read(&part).unwrap();
    for byte in &mut bytes[9..13] {
        *byte = 0;
    }
    fs::write(&part, &bytes).unwrap();
    assert!(matches!(
        sink.resume(&key(ID), 13, &prefix).map(|_| ()),
        Err(RecordingStoreError::PrefixMismatch)
    ));
    assert!(names(&month_dir(&dir)).is_empty());
}
