use std::io::Read;
use std::time::Duration;

use jaunt_audit::{RecordingKey, RecordingSink, RecordingStoreError, VerifyFailure, verify_stored};
use jaunt_recording_s3::{OrphanSweep, S3Sink, ScanBudget};

use crate::chaos::{Fault, Rule};
use crate::harness::{
    Backend, Harness, ID, OTHER, SplitMix, THIRD, down_rules, key, manifest, row, sha_hex, started,
    write_pieces,
};

fn rule(op: &'static str, path_has: &'static str, remaining: Option<u32>, fault: Fault) -> Rule {
    Rule {
        op,
        path_has,
        remaining,
        fault,
    }
}

fn sweep(sink: &S3Sink, now: i64) -> OrphanSweep {
    sink.sweep_orphans(now, ScanBudget::default()).unwrap()
}

fn read_all(sink: &S3Sink, key: &RecordingKey) -> (jaunt_record::SessionManifest, Option<Vec<u8>>) {
    let mut stored = sink.open(key).unwrap().unwrap();
    let cast = stored.cast.take().map(|mut reader| {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        bytes
    });
    (stored.manifest, cast)
}

fn store_small(h: &Harness, sink: &S3Sink, id: &str, data: &[u8]) -> jaunt_audit::Committed {
    let mut staged = sink.begin(&key(id)).unwrap();
    let chunks = write_pieces(staged.as_mut(), data, 3);
    let committed = staged
        .commit(&manifest(id, chunks, data.len() as u64))
        .unwrap();
    assert!(h.staging_files().is_empty(), "{:?}", h.staging_files());
    committed
}

pub fn a_large_recording_is_stored_byte_for_byte_with_the_manifest_last_and_verifies(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(1).bytes(20 * 1024 * 1024 + 4097);
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 7);
    let written = manifest(ID, chunks, data.len() as u64);
    let committed = staged.commit(&written).unwrap();
    assert_eq!(committed.location, key(ID).location());
    assert_eq!(committed.cast_bytes, data.len() as u64);
    assert_eq!(
        committed.cast_sha256.as_deref(),
        Some(sha_hex(&data).as_str())
    );
    assert!(h.staging_files().is_empty(), "{:?}", h.staging_files());

    let log = h.chaos.log();
    let cast_done = log
        .iter()
        .rposition(|entry| entry == "complete:cast" || entry == "put:cast")
        .unwrap();
    let manifest_put = log
        .iter()
        .position(|entry| entry == "put:manifest")
        .unwrap();
    assert!(cast_done < manifest_put, "{log:?}");
    let sizes: Vec<usize> = log
        .iter()
        .filter_map(|entry| entry.strip_prefix("part:cast:"))
        .map(|size| size.parse().unwrap())
        .collect();
    assert!(sizes.len() >= 2);
    assert_eq!(sizes.iter().sum::<usize>(), data.len());
    assert!(
        sizes[..sizes.len() - 1]
            .iter()
            .all(|size| *size == backend.part_size)
    );
    assert!(
        sizes
            .last()
            .is_some_and(|last| *last > 0 && *last <= backend.part_size)
    );

    let (stored_manifest, cast) = read_all(&sink, &key(ID));
    assert_eq!(stored_manifest, written);
    assert!(cast.as_deref() == Some(data.as_slice()));
    let recorded = row(&committed, &written);
    verify_stored(&sink, &key(ID), &recorded).unwrap();

    let mut flipped = data.clone();
    flipped[1234] ^= 1;
    h.raw_put(ID, ".cast", flipped);
    assert!(matches!(
        verify_stored(&sink, &key(ID), &recorded),
        Err(VerifyFailure::CastChanged)
    ));
}

pub fn an_existing_recording_is_never_overwritten_and_an_identical_retry_is_accepted(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let first = store_small(&h, &sink, ID, b"first\nsecond\n");
    let cast_before = h.raw_get(ID, ".cast");
    let manifest_before = h.raw_get(ID, ".manifest.json");

    let mut other = sink.begin(&key(ID)).unwrap();
    other.write(0, b"other content\n").unwrap();
    assert!(matches!(
        other.commit(&manifest(ID, 1, 14)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.staging_files().len(), 2, "{:?}", h.staging_files());
    other.abort().unwrap();
    assert!(h.staging_files().is_empty());

    let mut same_cast = sink.begin(&key(ID)).unwrap();
    same_cast.write(0, b"first\nsecond\n").unwrap();
    let mut changed_manifest = manifest(ID, 1, 13);
    changed_manifest.exit_status = Some(9);
    assert!(matches!(
        same_cast.commit(&changed_manifest),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.staging_files().len(), 2);
    same_cast.abort().unwrap();

    let mut identical = sink.begin(&key(ID)).unwrap();
    identical.write(0, b"first\nsecond\n").unwrap();
    let again = identical.commit(&manifest(ID, 1, 13)).unwrap();
    assert_eq!(again.manifest_sha256, first.manifest_sha256);
    assert_eq!(h.raw_get(ID, ".cast"), cast_before);
    assert_eq!(h.raw_get(ID, ".manifest.json"), manifest_before);
    assert!(h.staging_files().is_empty());
}

pub fn a_metadata_only_recording_stores_just_the_manifest(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let mut metadata = manifest(ID, 0, 0);
    metadata.digest = None;
    let committed = sink.begin(&key(ID)).unwrap().commit(&metadata).unwrap();
    assert_eq!(committed.cast_sha256, None);
    assert_eq!(h.objects_of(ID), [".manifest.json"]);
    let stored = sink.open(&key(ID)).unwrap().unwrap();
    assert!(stored.cast.is_none() && stored.manifest == metadata);
    assert!(sink.open(&key(OTHER)).unwrap().is_none());
}

pub fn a_crash_between_the_two_puts_is_finished_from_the_staged_files_at_the_next_start(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let crashed_data = SplitMix::new(5).bytes(300_000);
    let kept_data = SplitMix::new(6).bytes(2_000);
    h.chaos
        .fail(rule("put", ".manifest.json", None, Fault::Transient));
    let mut crashed = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(crashed.as_mut(), &crashed_data, 1);
    let real_manifest = manifest(ID, chunks, crashed_data.len() as u64);
    assert!(matches!(
        crashed.commit(&real_manifest),
        Err(RecordingStoreError::Unavailable)
    ));
    std::mem::forget(crashed);
    h.settle();
    let mut dropped = sink.begin(&key(OTHER)).unwrap();
    let dropped_chunks = write_pieces(dropped.as_mut(), &kept_data, 2);
    let dropped_manifest = manifest(OTHER, dropped_chunks, kept_data.len() as u64);
    assert!(matches!(
        dropped.commit(&dropped_manifest),
        Err(RecordingStoreError::Unavailable)
    ));
    drop(dropped);

    assert_eq!(h.objects_of(ID), [".cast"]);
    assert_eq!(h.objects_of(OTHER), [".cast"]);
    assert_eq!(h.staging_files().len(), 4, "{:?}", h.staging_files());
    h.settle();
    assert!(sink.open(&key(ID)).unwrap().is_none());

    h.chaos.clear();
    let restarted = h.sink();
    let recovery = restarted.recover_pending().unwrap();
    assert_eq!(
        (recovery.published, recovery.deferred, recovery.refused),
        (2, 0, 0)
    );
    let (stored_manifest, cast) = read_all(&restarted, &key(ID));
    assert_eq!(stored_manifest, real_manifest);
    assert!(cast.as_deref() == Some(crashed_data.as_slice()));
    let (other_manifest, other_cast) = read_all(&restarted, &key(OTHER));
    assert_eq!(other_manifest, dropped_manifest);
    assert!(other_cast.as_deref() == Some(kept_data.as_slice()));
    assert!(h.staging_files().is_empty(), "{:?}", h.staging_files());
    assert_eq!(restarted.recover_pending().unwrap().published, 0);
}

pub fn recovery_keeps_staged_recordings_while_the_store_is_down(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(8).bytes(5_000);
    h.chaos
        .fail(rule("put", ".manifest.json", None, Fault::Transient));
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 1);
    assert!(staged.commit(&manifest(ID, chunks, 5_000)).is_err());
    std::mem::forget(staged);
    let restarted = h.sink();
    let recovery = restarted.recover_pending().unwrap();
    assert_eq!((recovery.published, recovery.deferred), (0, 1));
    assert_eq!(h.staging_files().len(), 2);
    h.chaos.clear();
    h.settle();
    assert_eq!(restarted.recover_pending().unwrap().published, 1);
    assert!(h.staging_files().is_empty());
    let (stored_manifest, cast) = read_all(&restarted, &key(ID));
    assert_eq!(stored_manifest, manifest(ID, chunks, 5_000));
    assert!(cast.as_deref() == Some(data.as_slice()));
}

pub fn orphan_casts_are_removed_only_when_old_unstaged_and_without_a_manifest(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    h.raw_put(ID, ".cast", b"orphan".to_vec());
    h.raw_put(OTHER, ".cast", b"stored".to_vec());
    h.raw_put(OTHER, ".manifest.json", b"{}".to_vec());
    h.raw_put(THIRD, ".cast", b"staged".to_vec());
    let mut staged = sink.begin(&key(THIRD)).unwrap();
    staged.write(0, b"staged").unwrap();
    std::mem::forget(staged);

    assert_eq!(sweep(&sink, started()).removed, 0);
    assert_eq!(h.objects_of(ID), [".cast"]);

    let swept = sweep(&sink, started() + 7200);
    assert_eq!(swept.removed, 1);
    assert!(h.objects_of(ID).is_empty());
    assert_eq!(h.objects_of(OTHER), [".cast", ".manifest.json"]);
    assert_eq!(h.objects_of(THIRD), [".cast"]);
    assert_eq!(h.staging_files().len(), 1);
}

pub fn an_interrupted_upload_resumes_from_its_prefix_and_a_changed_prefix_is_refused(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let mut interrupted = sink.begin(&key(ID)).unwrap();
    interrupted.write(0, b"zero\n").unwrap();
    interrupted.write(1, b"one\n").unwrap();
    let prefix = interrupted.prefix_sha256();
    interrupted.write(2, b"tw").unwrap();
    std::mem::forget(interrupted);

    let restarted = h.sink();
    assert!(restarted.resume(&key(ID), 100, &prefix).unwrap().is_none());
    let mut resumed = restarted.resume(&key(ID), 9, &prefix).unwrap().unwrap();
    let mut salvaged = manifest(ID, 2, 9);
    salvaged.incomplete = true;
    salvaged.digest = None;
    let committed = resumed.commit(&salvaged).unwrap();
    assert_eq!(committed.cast_bytes, 9);
    let (stored_manifest, cast) = read_all(&restarted, &key(ID));
    assert_eq!(stored_manifest, salvaged);
    assert_eq!(cast.as_deref(), Some(b"zero\none\n".as_slice()));

    let mut tampered = sink.begin(&key(OTHER)).unwrap();
    tampered.write(0, b"zero\n").unwrap();
    tampered.write(1, b"one\n").unwrap();
    let prefix = tampered.prefix_sha256();
    std::mem::forget(tampered);
    let part = h
        .staging_root()
        .join(key(OTHER).location())
        .with_extension("cast.part");
    let mut bytes = std::fs::read(&part).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&part, bytes).unwrap();
    assert!(matches!(
        restarted
            .resume(&key(OTHER), 9, &prefix)
            .map(|staged| staged.is_some()),
        Err(RecordingStoreError::PrefixMismatch)
    ));
    assert!(h.staging_files().is_empty(), "{:?}", h.staging_files());
    assert!(h.objects_of(OTHER).is_empty());
}

pub fn an_unreachable_store_fails_the_commit_cleanly_and_a_later_retry_succeeds(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(9).bytes(10_000);
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 4);
    let real = manifest(ID, chunks, data.len() as u64);
    for down in down_rules() {
        h.chaos.fail(down);
    }
    assert!(matches!(
        staged.commit(&real),
        Err(RecordingStoreError::Unavailable)
    ));
    if let Some(spent) = h.virtual_elapsed() {
        assert!(
            spent > Duration::from_secs(100) && spent <= backend.deadline,
            "{spent:?}"
        );
    }
    assert!(h.objects_of(ID).is_empty());
    assert_eq!(h.staging_files().len(), 2, "{:?}", h.staging_files());
    assert!(matches!(
        staged.write(99, b"late"),
        Err(RecordingStoreError::Finished)
    ));
    assert!(matches!(
        staged.commit(&real),
        Err(RecordingStoreError::Unavailable)
    ));

    h.chaos.clear();
    h.settle();
    let committed = staged.commit(&real).unwrap();
    assert!(h.staging_files().is_empty());
    assert_eq!(h.objects_of(ID), [".cast", ".manifest.json"]);
    let (stored_manifest, cast) = read_all(&sink, &key(ID));
    assert_eq!(stored_manifest, real);
    assert!(cast.as_deref() == Some(data.as_slice()));
    verify_stored(&sink, &key(ID), &row(&committed, &real)).unwrap();
}

pub fn a_store_that_recovers_inside_the_deadline_completes_the_commit(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    h.chaos
        .fail(rule("put", ".cast", Some(3), Fault::Transient));
    h.chaos
        .fail(rule("put", ".manifest.json", Some(2), Fault::Transient));
    let committed = store_small(&h, &sink, ID, b"retried\n");
    assert_eq!(h.chaos.count("put:cast"), 4);
    assert_eq!(h.chaos.count("put:manifest"), 3);
    assert_eq!(committed.cast_bytes, 8);
    assert_eq!(h.objects_of(ID), [".cast", ".manifest.json"]);
}

pub fn a_failed_multipart_upload_is_aborted_and_leaves_no_object(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(11).bytes(backend.part_size * 2 + 17);
    h.chaos.fail(rule("part", ".cast", None, Fault::Transient));
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 5);
    assert!(matches!(
        staged.commit(&manifest(ID, chunks, data.len() as u64)),
        Err(RecordingStoreError::Unavailable)
    ));
    let attempts = h.chaos.count("multipart:cast");
    assert!(attempts >= 2, "{attempts}");
    assert_eq!(h.chaos.count("abort:cast"), attempts);
    assert!(h.objects_of(ID).is_empty());
    assert_eq!(h.chaos.count("put:manifest"), 0);
    assert_eq!(h.staging_files().len(), 2);
}

pub fn a_staged_cast_that_no_longer_matches_its_hash_is_never_published(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    for (id, len) in [(ID, 3_000usize), (OTHER, backend.part_size * 2 + 5)] {
        let data = SplitMix::new(13).bytes(len);
        let mut staged = sink.begin(&key(id)).unwrap();
        let chunks = write_pieces(staged.as_mut(), &data, 6);
        let part = h
            .staging_root()
            .join(key(id).location())
            .with_extension("cast.part");
        let mut on_disk = std::fs::read(&part).unwrap();
        let last = on_disk.len() - 1;
        on_disk[last] ^= 1;
        std::fs::write(&part, on_disk).unwrap();
        assert!(matches!(
            staged.commit(&manifest(id, chunks, len as u64)),
            Err(RecordingStoreError::PrefixMismatch)
        ));
        assert!(h.objects_of(id).is_empty(), "{id}");
    }
    assert_eq!(h.chaos.count("abort:cast"), h.chaos.count("multipart:cast"));
    assert!(h.staging_files().is_empty(), "{:?}", h.staging_files());
}

pub fn rejected_credentials_fail_at_once_as_unavailable_without_retries(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    h.chaos.fail(rule("head", "", None, Fault::Denied));
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"secret recording\n").unwrap();
    assert!(matches!(
        staged.commit(&manifest(ID, 1, 17)),
        Err(RecordingStoreError::Unavailable)
    ));
    assert_eq!(h.chaos.count("head:cast"), 1);
    if let Some(spent) = h.virtual_elapsed() {
        assert_eq!(spent, Duration::ZERO);
    }
}

pub fn reading_a_recording_reports_absence_outages_and_a_missing_cast(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    assert!(sink.open(&key(ID)).unwrap().is_none());
    h.chaos
        .fail(rule("get", ".manifest.json", None, Fault::Transient));
    assert!(matches!(
        sink.open(&key(ID)),
        Err(RecordingStoreError::Unavailable)
    ));
    h.chaos.clear();
    h.settle();
    let mut metadata = manifest(OTHER, 0, 0);
    metadata.digest = None;
    sink.begin(&key(OTHER)).unwrap().commit(&metadata).unwrap();
    let stored = sink.open(&key(OTHER)).unwrap().unwrap();
    assert!(stored.cast.is_none());
}

fn replace_with(
    h: &Harness,
    id: &'static str,
    suffix: &'static str,
    bytes: Vec<u8>,
    with_sha: bool,
) -> crate::chaos::Action {
    let store = h.backend.store.clone();
    let path = h.object_path(id, suffix);
    std::sync::Arc::new(move || {
        let store = store.clone();
        let path = path.clone();
        let bytes = bytes.clone();
        Box::pin(async move {
            let mut attributes = object_store::Attributes::new();
            if with_sha {
                attributes.insert(
                    object_store::Attribute::Metadata("sha256".into()),
                    object_store::AttributeValue::from(sha_hex(&bytes)),
                );
            }
            object_store::ObjectStore::put_opts(
                store.as_ref(),
                &path,
                object_store::PutPayload::from(bytes),
                object_store::PutOptions {
                    attributes,
                    ..object_store::PutOptions::default()
                },
            )
            .await
            .unwrap();
        })
    })
}

pub fn an_identical_object_that_appears_during_the_put_is_accepted_and_a_different_one_is_not(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = b"raced cast\n".to_vec();
    h.chaos.after(crate::chaos::Hook {
        op: "head",
        path_has: ".cast",
        once: true,
        action: replace_with(&h, ID, ".cast", data.clone(), true),
    });
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, &data).unwrap();
    staged.commit(&manifest(ID, 1, data.len() as u64)).unwrap();
    assert_eq!(h.chaos.count("delete:cast"), 0);
    assert_eq!(h.objects_of(ID), [".cast", ".manifest.json"]);
    assert_eq!(h.raw_get(ID, ".cast"), Some(data));
    assert!(h.staging_files().is_empty());

    h.chaos.after(crate::chaos::Hook {
        op: "head",
        path_has: ".cast",
        once: true,
        action: replace_with(&h, OTHER, ".cast", b"someone else\n".to_vec(), true),
    });
    let mut other = sink.begin(&key(OTHER)).unwrap();
    other.write(0, b"mine\n").unwrap();
    assert!(matches!(
        other.commit(&manifest(OTHER, 1, 5)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.raw_get(OTHER, ".cast"), Some(b"someone else\n".to_vec()));
    assert!(h.objects_of(OTHER) == [".cast"]);
}

pub fn an_object_damaged_right_after_the_upload_is_noticed_and_replaced_before_the_manifest(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = b"checked after the upload\n".to_vec();
    h.chaos.after(crate::chaos::Hook {
        op: "put",
        path_has: ".cast",
        once: true,
        action: replace_with(&h, ID, ".cast", b"damaged\n".to_vec(), false),
    });
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, &data).unwrap();
    staged.commit(&manifest(ID, 1, data.len() as u64)).unwrap();
    assert_eq!(h.raw_get(ID, ".cast"), Some(data));
    assert_eq!(h.chaos.count("put:cast"), 2);
    assert_eq!(h.chaos.count("delete:cast"), 1);
    let log = h.chaos.log();
    let last_cast = log.iter().rposition(|entry| entry == "put:cast").unwrap();
    let manifest_put = log
        .iter()
        .position(|entry| entry == "put:manifest")
        .unwrap();
    assert!(last_cast < manifest_put, "{log:?}");
}

pub fn a_foreign_object_created_during_a_multipart_upload_is_never_overwritten(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(21).bytes(backend.part_size * 2 + 9);
    h.chaos.after(crate::chaos::Hook {
        op: "part",
        path_has: ".cast",
        once: true,
        action: replace_with(&h, ID, ".cast", b"foreign\n".to_vec(), true),
    });
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 8);
    assert!(matches!(
        staged.commit(&manifest(ID, chunks, data.len() as u64)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.raw_get(ID, ".cast"), Some(b"foreign\n".to_vec()));
    assert_eq!(h.chaos.count("abort:cast"), h.chaos.count("multipart:cast"));
    assert_eq!(h.chaos.count("put:manifest"), 0);
}

pub fn an_old_cast_with_other_content_and_no_manifest_is_replaced_by_the_commit(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    h.raw_put_with_sha(ID, ".cast", b"stale partial cast\n".to_vec());
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"the real cast\n").unwrap();
    staged.commit(&manifest(ID, 1, 14)).unwrap();
    assert_eq!(h.raw_get(ID, ".cast"), Some(b"the real cast\n".to_vec()));
    assert_eq!(h.chaos.count("delete:cast"), 1);

    h.raw_put_with_sha(OTHER, ".cast", b"stale\n".to_vec());
    h.raw_put(OTHER, ".manifest.json", b"{}".to_vec());
    let mut guarded = sink.begin(&key(OTHER)).unwrap();
    guarded.write(0, b"new\n").unwrap();
    assert!(matches!(
        guarded.commit(&manifest(OTHER, 1, 4)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.raw_get(OTHER, ".cast"), Some(b"stale\n".to_vec()));
}

pub fn a_manifest_that_is_oversize_or_belongs_to_another_session_is_refused(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let committed = store_small(&h, &sink, ID, b"cast\n");
    let valid = h.raw_get(ID, ".manifest.json").unwrap();
    assert!(!committed.manifest_sha256.is_empty());

    h.raw_put(
        ID,
        ".manifest.json",
        vec![b' '; jaunt_audit::MAX_MANIFEST_BYTES + 1],
    );
    assert!(matches!(
        sink.open(&key(ID)),
        Err(RecordingStoreError::InvalidManifest)
    ));

    let foreign = serde_json::to_vec(&manifest(OTHER, 1, 5)).unwrap();
    h.raw_put(ID, ".manifest.json", foreign);
    assert!(matches!(
        sink.open(&key(ID)),
        Err(RecordingStoreError::InvalidManifest)
    ));

    h.raw_put(ID, ".manifest.json", b"not json".to_vec());
    assert!(matches!(
        sink.open(&key(ID)),
        Err(RecordingStoreError::InvalidManifest)
    ));

    h.raw_put(ID, ".manifest.json", valid);
    assert!(sink.open(&key(ID)).unwrap().is_some());
}

pub fn a_replaced_object_is_never_mixed_into_a_stream_that_is_being_read(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(31).bytes(3 * 1024 * 1024 + 11);
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 9);
    staged
        .commit(&manifest(ID, chunks, data.len() as u64))
        .unwrap();
    let mut stored = sink.open(&key(ID)).unwrap().unwrap();
    let mut reader = stored.cast.take().unwrap();
    let mut first = vec![0u8; 16];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(first, data[..16]);
    let replacement = SplitMix::new(32).bytes(data.len());
    h.raw_put(ID, ".cast", replacement);
    let mut rest = Vec::new();
    let error = reader.read_to_end(&mut rest).unwrap_err();
    assert!(!error.to_string().is_empty());
    assert!(rest.len() < data.len());
}

pub fn probing_writes_and_removes_a_marker_and_names_what_is_wrong(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    sink.probe().unwrap();
    assert_eq!(h.chaos.count("put:other"), 1);
    assert_eq!(h.chaos.count("delete:other"), 1);
    assert!(h.staging_files().is_empty());
}

pub fn maintenance_leaves_the_files_of_an_upload_that_is_still_alive_in_memory(backend: &Backend) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let data = SplitMix::new(41).bytes(20_000);
    h.chaos
        .fail(rule("put", ".manifest.json", None, Fault::Transient));
    let mut staged = sink.begin(&key(ID)).unwrap();
    let chunks = write_pieces(staged.as_mut(), &data, 3);
    let real = manifest(ID, chunks, data.len() as u64);
    assert!(matches!(
        staged.commit(&real),
        Err(RecordingStoreError::Unavailable)
    ));
    assert!(sink.is_live(ID));
    h.chaos.clear();
    h.settle();
    let recovery = sink.recover_pending().unwrap();
    assert_eq!((recovery.live, recovery.published), (1, 0));
    assert_eq!(h.staging_files().len(), 2, "{:?}", h.staging_files());
    assert!(h.objects_of(ID) == [".cast"]);

    let committed = staged.commit(&real).unwrap();
    assert_eq!(committed.cast_bytes, data.len() as u64);
    assert_eq!(
        committed.cast_sha256.as_deref(),
        Some(sha_hex(&data).as_str())
    );
    assert!(h.staging_files().is_empty());
    drop(staged);
    assert!(!sink.is_live(ID));
    let (stored, cast) = read_all(&sink, &key(ID));
    assert_eq!(stored, real);
    assert!(cast.as_deref() == Some(data.as_slice()));
    verify_stored(&sink, &key(ID), &row(&committed, &real)).unwrap();
}

pub fn a_commit_whose_staged_cast_vanished_fails_instead_of_storing_a_manifest_alone(
    backend: &Backend,
) {
    let h = Harness::new(backend);
    let sink = h.sink();
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"delivered\n").unwrap();
    std::fs::remove_file(
        h.staging_root()
            .join(key(ID).location())
            .with_extension("cast.part"),
    )
    .unwrap();
    assert!(matches!(
        staged.commit(&manifest(ID, 1, 10)),
        Err(RecordingStoreError::Io { .. })
    ));
    assert!(h.objects_of(ID).is_empty());
    assert_eq!(h.chaos.count("put:manifest"), 0);
}
