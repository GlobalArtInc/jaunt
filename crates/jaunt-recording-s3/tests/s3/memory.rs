use std::sync::Arc;
use std::time::Duration;

use jaunt_audit::{RecordingSink, RecordingStoreError};
use jaunt_recording_s3::{RetryPolicy, S3Sink, SinkOptions, SystemTimer};

use crate::chaos::{Fault, Rule};
use crate::harness::{Backend, Harness, ID, OTHER, THIRD, key, manifest};
use crate::scenarios;

const SMALL_PART: usize = 1024;
const REAL_PART: usize = 5 * 1024 * 1024;

#[test]
fn a_large_recording_is_stored_byte_for_byte_with_the_manifest_last_and_verifies() {
    scenarios::a_large_recording_is_stored_byte_for_byte_with_the_manifest_last_and_verifies(
        &Backend::memory(REAL_PART),
    );
}

#[test]
fn an_existing_recording_is_never_overwritten_and_an_identical_retry_is_accepted() {
    scenarios::an_existing_recording_is_never_overwritten_and_an_identical_retry_is_accepted(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_metadata_only_recording_stores_just_the_manifest() {
    scenarios::a_metadata_only_recording_stores_just_the_manifest(&Backend::memory(SMALL_PART));
}

#[test]
fn a_crash_between_the_two_puts_is_finished_from_the_staged_files_at_the_next_start() {
    scenarios::a_crash_between_the_two_puts_is_finished_from_the_staged_files_at_the_next_start(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn recovery_keeps_staged_recordings_while_the_store_is_down() {
    scenarios::recovery_keeps_staged_recordings_while_the_store_is_down(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn orphan_casts_are_removed_only_when_old_unstaged_and_without_a_manifest() {
    scenarios::orphan_casts_are_removed_only_when_old_unstaged_and_without_a_manifest(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn an_interrupted_upload_resumes_from_its_prefix_and_a_changed_prefix_is_refused() {
    scenarios::an_interrupted_upload_resumes_from_its_prefix_and_a_changed_prefix_is_refused(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn an_unreachable_store_fails_the_commit_cleanly_and_a_later_retry_succeeds() {
    scenarios::an_unreachable_store_fails_the_commit_cleanly_and_a_later_retry_succeeds(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_store_that_recovers_inside_the_deadline_completes_the_commit() {
    scenarios::a_store_that_recovers_inside_the_deadline_completes_the_commit(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn a_failed_multipart_upload_is_aborted_and_leaves_no_object() {
    scenarios::a_failed_multipart_upload_is_aborted_and_leaves_no_object(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn a_staged_cast_that_no_longer_matches_its_hash_is_never_published() {
    scenarios::a_staged_cast_that_no_longer_matches_its_hash_is_never_published(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn rejected_credentials_fail_at_once_as_unavailable_without_retries() {
    scenarios::rejected_credentials_fail_at_once_as_unavailable_without_retries(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn reading_a_recording_reports_absence_outages_and_a_missing_cast() {
    scenarios::reading_a_recording_reports_absence_outages_and_a_missing_cast(&Backend::memory(
        SMALL_PART,
    ));
}

#[test]
fn the_cast_goes_up_in_one_put_up_to_the_part_size_and_in_exact_parts_above_it() {
    let cases: [(usize, &[usize]); 4] = [
        (SMALL_PART - 1, &[]),
        (SMALL_PART, &[]),
        (SMALL_PART + 1, &[SMALL_PART, 1]),
        (SMALL_PART * 2, &[SMALL_PART, SMALL_PART]),
    ];
    for (len, parts) in cases {
        let h = Harness::new(&Backend::memory(SMALL_PART));
        let sink = h.sink();
        let mut staged = sink.begin(&key(ID)).unwrap();
        staged.write(0, &vec![b'x'; len]).unwrap();
        staged.commit(&manifest(ID, 1, len as u64)).unwrap();
        let log = h.chaos.log();
        let sizes: Vec<usize> = log
            .iter()
            .filter_map(|entry| entry.strip_prefix("part:cast:"))
            .map(|size| size.parse().unwrap())
            .collect();
        assert_eq!(sizes, parts, "{len}");
        assert_eq!(
            h.chaos.count("put:cast"),
            usize::from(parts.is_empty()),
            "{len}"
        );
    }
}

#[test]
fn without_conditional_put_the_object_is_checked_first_and_never_replaced() {
    let backend = Backend::memory(SMALL_PART);
    let h = Harness::new(&backend);
    let sink = S3Sink::with_store(
        backend.store.clone(),
        SinkOptions {
            prefix: backend.prefix.clone(),
            part_size: SMALL_PART,
            conditional_put: false,
            retry: RetryPolicy::new(Duration::from_secs(5)),
            secrets: Vec::new(),
            breaker_window: Duration::from_secs(15),
        },
        jaunt_audit::DirectorySink::create(
            &h.staging_root(),
            jaunt_audit::DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1 << 20,
            },
        )
        .unwrap(),
        h.runtime.handle().clone(),
        Arc::new(SystemTimer::new()),
    );
    let mut first = sink.begin(&key(ID)).unwrap();
    first.write(0, b"one\n").unwrap();
    first.commit(&manifest(ID, 1, 4)).unwrap();
    let mut second = sink.begin(&key(ID)).unwrap();
    second.write(0, b"two\n").unwrap();
    assert!(matches!(
        second.commit(&manifest(ID, 1, 4)),
        Err(RecordingStoreError::Exists)
    ));
    assert_eq!(h.raw_get(ID, ".cast"), Some(b"one\n".to_vec()));
}

#[test]
fn every_attempt_of_a_downed_store_is_bounded_by_the_deadline() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.chaos.fail(Rule {
        op: "head",
        path_has: "",
        remaining: None,
        fault: Fault::Transient,
    });
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"x").unwrap();
    assert!(staged.commit(&manifest(ID, 1, 1)).is_err());
    let attempts = h.chaos.count("head:cast");
    assert!((8..=20).contains(&attempts), "{attempts}");
}

#[test]
fn an_endpoint_nobody_listens_on_is_reported_as_unreachable_and_the_commit_stays_retryable() {
    use jaunt_recording_s3::{Credentials, ProbeError, S3Config, Secret};

    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let config = S3Config {
        endpoint: Some(format!("http://127.0.0.1:{port}")),
        allow_insecure_http: true,
        path_style: true,
        upload_deadline: Duration::from_secs(1),
        ..S3Config::new("us-east-1", "recordings")
    };
    let credentials = Credentials {
        access_key: "throwaway-access".to_owned(),
        secret_key: Secret::new("throwaway-secret".to_owned()),
        session_token: None,
    };
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let staging = jaunt_audit::DirectorySink::create(
        &h.staging_root(),
        jaunt_audit::DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1 << 20,
        },
    )
    .unwrap();
    let sink = S3Sink::connect(&config, &credentials, staging, h.runtime.handle().clone()).unwrap();
    let probed = sink.probe().unwrap_err();
    assert!(matches!(probed, ProbeError::Unreachable(_)), "{probed}");
    assert!(!probed.to_string().contains("throwaway-secret"));
    let mut staged = sink.begin(&key(ID)).unwrap();
    staged.write(0, b"kept\n").unwrap();
    assert!(matches!(
        staged.commit(&manifest(ID, 1, 5)),
        Err(RecordingStoreError::Unavailable)
    ));
    assert_eq!(h.staging_files().len(), 2);
}

#[test]
fn the_client_builds_for_every_valid_configuration_and_refuses_an_invalid_one() {
    use jaunt_recording_s3::{Credentials, S3Config, Secret, Sse, build_store};

    let credentials = Credentials {
        access_key: "throwaway-access".to_owned(),
        secret_key: Secret::new("throwaway-secret".to_owned()),
        session_token: Some(Secret::new("throwaway-token".to_owned())),
    };
    for (sse, conditional_put, path_style) in [
        (Sse::None, true, false),
        (Sse::Aes256, true, true),
        (Sse::Aes256, false, false),
    ] {
        let config = S3Config {
            sse,
            conditional_put,
            path_style,
            endpoint: Some("https://s3.example.test".to_owned()),
            ..S3Config::new("eu-west-1", "recordings")
        };
        assert!(build_store(&config, &credentials).is_ok());
    }
    let invalid = S3Config {
        prefix: "../x/".to_owned(),
        ..S3Config::new("eu-west-1", "recordings")
    };
    assert!(build_store(&invalid, &credentials).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sink_runs_on_blocking_tasks_of_the_runtime_that_drives_it() {
    let backend = Backend::memory(SMALL_PART);
    let staging = tempfile::tempdir().unwrap();
    let handle = tokio::runtime::Handle::current();
    let store = backend.store.clone();
    let timer = backend.timer.clone();
    let staging_root = staging.path().join("staging");
    let outcome = tokio::task::spawn_blocking(move || {
        let sink = S3Sink::with_store(
            store,
            SinkOptions {
                prefix: "recordings/".to_owned(),
                part_size: SMALL_PART,
                conditional_put: true,
                retry: RetryPolicy::new(Duration::from_secs(5)),
                secrets: Vec::new(),
                breaker_window: Duration::from_secs(15),
            },
            jaunt_audit::DirectorySink::create(
                &staging_root,
                jaunt_audit::DirectoryLimits {
                    min_free_bytes: 0,
                    max_total_raw: 1 << 20,
                },
            )
            .unwrap(),
            handle,
            timer,
        );
        let mut staged = sink.begin(&key(ID)).unwrap();
        staged.write(0, &vec![b'y'; SMALL_PART * 3]).unwrap();
        staged
            .commit(&manifest(ID, 1, (SMALL_PART * 3) as u64))
            .unwrap();
        let mut stored = sink.open(&key(ID)).unwrap().unwrap();
        let mut cast = Vec::new();
        std::io::Read::read_to_end(&mut stored.cast.take().unwrap(), &mut cast).unwrap();
        (cast.len(), sink.recover_pending().unwrap())
    })
    .await
    .unwrap();
    assert_eq!(outcome.0, SMALL_PART * 3);
    assert_eq!(outcome.1.published, 0);
}

#[test]
fn an_identical_object_that_appears_during_the_put_is_accepted_and_a_different_one_is_not() {
    scenarios::an_identical_object_that_appears_during_the_put_is_accepted_and_a_different_one_is_not(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn an_object_damaged_right_after_the_upload_is_noticed_and_replaced_before_the_manifest() {
    scenarios::an_object_damaged_right_after_the_upload_is_noticed_and_replaced_before_the_manifest(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_foreign_object_created_during_a_multipart_upload_is_never_overwritten() {
    scenarios::a_foreign_object_created_during_a_multipart_upload_is_never_overwritten(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn an_old_cast_with_other_content_and_no_manifest_is_replaced_by_the_commit() {
    scenarios::an_old_cast_with_other_content_and_no_manifest_is_replaced_by_the_commit(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_manifest_that_is_oversize_or_belongs_to_another_session_is_refused() {
    scenarios::a_manifest_that_is_oversize_or_belongs_to_another_session_is_refused(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_replaced_object_is_never_mixed_into_a_stream_that_is_being_read() {
    scenarios::a_replaced_object_is_never_mixed_into_a_stream_that_is_being_read(&Backend::memory(
        REAL_PART,
    ));
}

#[test]
fn probing_writes_and_removes_a_marker_and_names_what_is_wrong() {
    scenarios::probing_writes_and_removes_a_marker_and_names_what_is_wrong(&Backend::memory(
        SMALL_PART,
    ));
}

fn fail_everything(h: &Harness, fault: Fault) {
    for op in [
        "head",
        "get",
        "put",
        "multipart",
        "part",
        "complete",
        "delete",
        "list",
    ] {
        h.chaos.fail(Rule {
            op,
            path_has: "",
            remaining: None,
            fault,
        });
    }
}

fn staged_small(sink: &S3Sink, id: &str) -> Box<dyn jaunt_audit::StagedRecording> {
    let mut staged = sink.begin(&key(id)).unwrap();
    staged.write(0, b"small cast\n").unwrap();
    staged
}

#[test]
fn a_dead_store_trips_the_breaker_so_the_next_calls_fail_without_touching_the_network() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    fail_everything(&h, Fault::Transient);
    let mut first = staged_small(&sink, ID);
    assert!(first.commit(&manifest(ID, 1, 11)).is_err());
    let spent = h.virtual_elapsed().unwrap();
    assert!(spent >= Duration::from_secs(100), "{spent:?}");
    let calls = h.chaos.log().len();

    let mut second = staged_small(&sink, OTHER);
    assert!(matches!(
        second.commit(&manifest(OTHER, 1, 11)),
        Err(RecordingStoreError::Unavailable)
    ));
    assert!(matches!(
        sink.open(&key(ID)),
        Err(RecordingStoreError::Unavailable)
    ));
    assert_eq!(h.chaos.log().len(), calls);
    assert_eq!(h.virtual_elapsed().unwrap(), spent);

    h.advance(Duration::from_secs(16));
    assert!(second.commit(&manifest(OTHER, 1, 11)).is_err());
    assert!(h.chaos.log().len() > calls);

    h.chaos.clear();
    h.settle();
    assert!(second.commit(&manifest(OTHER, 1, 11)).is_ok());
    let mut third = staged_small(&sink, THIRD);
    assert!(third.commit(&manifest(THIRD, 1, 11)).is_ok());
}

#[test]
fn a_start_with_a_dead_store_costs_one_deadline_for_all_staged_recordings() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    fail_everything(&h, Fault::Transient);
    for (index, id) in [ID, OTHER, THIRD].into_iter().enumerate() {
        let mut staged = staged_small(&sink, id);
        h.advance(Duration::from_secs(16));
        assert!(staged.commit(&manifest(id, 1, 11)).is_err(), "{index}");
        std::mem::forget(staged);
    }
    h.advance(Duration::from_secs(16));
    let restarted = h.sink();
    let before = h.virtual_elapsed().unwrap();
    let recovery = restarted.recover_pending().unwrap();
    assert_eq!((recovery.published, recovery.deferred), (0, 3));
    let spent = h.virtual_elapsed().unwrap() - before;
    assert!(spent <= Duration::from_secs(120), "{spent:?}");
    assert_eq!(h.staging_files().len(), 6);

    h.chaos.clear();
    h.settle();
    assert_eq!(restarted.recover_pending().unwrap().published, 3);
}

#[test]
fn a_permanent_rejection_is_not_retried_and_keeps_the_breaker_open_longer() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.chaos.fail(Rule {
        op: "head",
        path_has: "",
        remaining: None,
        fault: Fault::Status(501),
    });
    let mut staged = staged_small(&sink, ID);
    assert!(matches!(
        staged.commit(&manifest(ID, 1, 11)),
        Err(RecordingStoreError::Unavailable)
    ));
    assert_eq!(h.chaos.count("head:cast"), 1);
    assert_eq!(h.virtual_elapsed().unwrap(), Duration::ZERO);

    h.advance(Duration::from_secs(16));
    assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
    assert_eq!(h.chaos.count("head:cast"), 1);
    h.advance(Duration::from_secs(120));
    assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
    assert_eq!(h.chaos.count("head:cast"), 2);
}

#[test]
fn every_status_a_retry_cannot_cure_is_permanent_and_the_others_are_transient() {
    for (status, attempts) in [
        (501u16, 1usize),
        (400, 1),
        (405, 1),
        (415, 1),
        (301, 1),
        (308, 1),
    ] {
        let h = Harness::new(&Backend::memory(SMALL_PART));
        let sink = h.sink();
        h.chaos.fail(Rule {
            op: "head",
            path_has: "",
            remaining: None,
            fault: Fault::Status(status),
        });
        let mut staged = staged_small(&sink, ID);
        assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
        assert_eq!(h.chaos.count("head:cast"), attempts, "{status}");
    }
    for status in [500u16, 502, 503, 504, 429, 408] {
        let h = Harness::new(&Backend::memory(SMALL_PART));
        let sink = h.sink();
        h.chaos.fail(Rule {
            op: "head",
            path_has: "",
            remaining: None,
            fault: Fault::Status(status),
        });
        let mut staged = staged_small(&sink, ID);
        assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
        assert!(h.chaos.count("head:cast") > 3, "{status}");
    }
}

#[test]
fn the_probe_tells_a_permanent_rejection_from_a_denial_and_from_a_network_failure() {
    let cases: [(&'static str, Fault, &str); 3] = [
        ("put", Fault::Status(501), "rejected"),
        ("put", Fault::Denied, "denied"),
        ("list", Fault::Transient, "unreachable"),
    ];
    for (op, fault, expected) in cases {
        let h = Harness::new(&Backend::memory(SMALL_PART));
        let sink = h.sink();
        h.chaos.fail(Rule {
            op,
            path_has: "",
            remaining: None,
            fault,
        });
        let error = sink.probe().unwrap_err();
        let kind = match &error {
            jaunt_recording_s3::ProbeError::Rejected(_) => "rejected",
            jaunt_recording_s3::ProbeError::Denied(_) => "denied",
            jaunt_recording_s3::ProbeError::Unreachable(_) => "unreachable",
            jaunt_recording_s3::ProbeError::BucketMissing => "missing",
        };
        assert_eq!(kind, expected, "{error}");
        if kind == "denied" {
            assert!(error.to_string().contains("PutObject"), "{error}");
        }
    }
}

#[test]
fn the_orphan_scan_matches_manifests_from_the_listing_and_asks_only_about_real_orphans() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    let ids: Vec<String> = (0..40)
        .map(|index| format!("5f0c3a52-8a8e-4c55-9a51-{index:012x}"))
        .collect();
    for id in &ids {
        h.raw_put(id, ".cast", b"cast".to_vec());
        h.raw_put(id, ".manifest.json", b"{}".to_vec());
    }
    let orphan = "7a7a7a7a-1111-4222-8333-555555555555";
    h.raw_put(orphan, ".cast", b"orphan".to_vec());
    let later = "ffffffff-1111-4222-8333-555555555555";
    h.raw_put(later, ".cast", b"orphan at the end".to_vec());
    let far = crate::harness::started() + 7200;
    let swept = sink
        .sweep_orphans(far, jaunt_recording_s3::ScanBudget::default())
        .unwrap();
    assert_eq!(swept.removed, 2);
    assert_eq!(swept.scanned, 82);
    assert!(!swept.truncated);
    assert_eq!(h.chaos.count("head:manifest"), 2);
    assert!(h.objects_of(orphan).is_empty() && h.objects_of(later).is_empty());
    assert!(ids.iter().all(|id| h.objects_of(id).len() == 2));

    let budget = jaunt_recording_s3::ScanBudget {
        max_objects: 10,
        ..jaunt_recording_s3::ScanBudget::default()
    };
    let cut = sink.sweep_orphans(far, budget).unwrap();
    assert!(cut.truncated && cut.scanned == 10, "{cut:?}");
}

#[test]
fn an_orphan_cast_is_kept_while_young_staged_or_waiting_for_its_pending_manifest() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    let far = crate::harness::started() + 7200;
    h.raw_put(ID, ".cast", b"waits for its manifest".to_vec());
    let mut waiting = staged_small(&sink, ID);
    fail_everything(&h, Fault::Status(501));
    assert!(waiting.commit(&manifest(ID, 1, 11)).is_err());
    std::mem::forget(waiting);
    h.chaos.clear();
    h.advance(Duration::from_secs(121));
    let part = h
        .staging_root()
        .join(key(ID).location())
        .with_extension("cast.part");
    std::fs::remove_file(part).unwrap();
    assert_eq!(h.staging_files().len(), 1);
    let swept = sink
        .sweep_orphans(far, jaunt_recording_s3::ScanBudget::default())
        .unwrap();
    assert_eq!(swept.removed, 0);
    assert_eq!(h.objects_of(ID), [".cast"]);

    let slow = Backend {
        deadline: Duration::from_secs(3600),
        ..Backend::memory(SMALL_PART)
    };
    let h = Harness::new(&slow);
    let sink = h.sink();
    h.raw_put(OTHER, ".cast", b"half an hour old".to_vec());
    let old_enough_for_one_hour = crate::harness::started() + 5400;
    let swept = sink
        .sweep_orphans(
            old_enough_for_one_hour,
            jaunt_recording_s3::ScanBudget::default(),
        )
        .unwrap();
    assert_eq!(swept.removed, 0);
    let swept = sink
        .sweep_orphans(
            crate::harness::started() + 8000,
            jaunt_recording_s3::ScanBudget::default(),
        )
        .unwrap();
    assert_eq!(swept.removed, 1);
}

#[test]
fn maintenance_leaves_the_files_of_an_upload_that_is_still_alive_in_memory() {
    scenarios::maintenance_leaves_the_files_of_an_upload_that_is_still_alive_in_memory(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_commit_whose_staged_cast_vanished_fails_instead_of_storing_a_manifest_alone() {
    scenarios::a_commit_whose_staged_cast_vanished_fails_instead_of_storing_a_manifest_alone(
        &Backend::memory(SMALL_PART),
    );
}

#[test]
fn a_read_of_a_missing_or_forbidden_object_does_not_trip_the_breaker_but_a_denied_write_does() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.chaos.fail(Rule {
        op: "get",
        path_has: ".manifest.json",
        remaining: Some(3),
        fault: Fault::Denied,
    });
    for _ in 0..3 {
        assert!(sink.open(&key(ID)).is_err());
    }
    let calls = h.chaos.log().len();
    let mut staged = staged_small(&sink, ID);
    staged.commit(&manifest(ID, 1, 11)).unwrap();
    assert!(h.chaos.log().len() > calls);

    h.chaos.fail(Rule {
        op: "put",
        path_has: ".cast",
        remaining: Some(1),
        fault: Fault::Denied,
    });
    let mut denied = staged_small(&sink, OTHER);
    assert!(denied.commit(&manifest(OTHER, 1, 11)).is_err());
    let before = h.chaos.log().len();
    let mut waiting = staged_small(&sink, THIRD);
    assert!(waiting.commit(&manifest(THIRD, 1, 11)).is_err());
    assert_eq!(h.chaos.log().len(), before);
}

#[test]
fn the_scan_stops_at_its_deadline_on_the_injected_clock() {
    let backend = Backend::memory(SMALL_PART);
    let h = Harness::new(&backend);
    let sink = h.sink();
    for index in 0..6 {
        h.raw_put(
            &format!("5f0c3a52-8a8e-4c55-9a51-{index:012x}"),
            ".cast",
            b"orphan".to_vec(),
        );
    }
    let timer = backend.virtual_timer.clone().unwrap();
    h.chaos.after(crate::chaos::Hook {
        op: "head",
        path_has: ".manifest.json",
        once: false,
        action: std::sync::Arc::new(move || {
            let timer = timer.clone();
            Box::pin(async move { timer.advance(Duration::from_secs(250)) })
        }),
    });
    let swept = sink
        .sweep_orphans(
            crate::harness::started() + 7200,
            jaunt_recording_s3::ScanBudget::default(),
        )
        .unwrap();
    assert!(swept.truncated, "{swept:?}");
    assert!(swept.removed >= 2 && swept.removed < 6, "{swept:?}");
}

fn far_sweep(sink: &S3Sink) -> jaunt_recording_s3::OrphanSweep {
    sink.sweep_orphans(
        crate::harness::started() + 7200,
        jaunt_recording_s3::ScanBudget::default(),
    )
    .unwrap()
}

fn assert_only_the_unprotected_orphan_is_removed(h: &Harness, sink: &S3Sink) {
    h.raw_put(OTHER, ".cast", b"orphan".to_vec());
    let swept = far_sweep(sink);
    assert_eq!(swept.removed, 1, "{swept:?}");
    assert!(h.objects_of(OTHER).is_empty());
    assert_eq!(h.objects_of(ID), [".cast"]);
}

#[test]
fn the_scan_keeps_an_orphan_whose_upload_is_alive_in_memory() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.raw_put(ID, ".cast", b"orphan".to_vec());
    let _alive = sink.begin(&key(ID)).unwrap();
    assert!(h.staging_files().is_empty());
    assert_only_the_unprotected_orphan_is_removed(&h, &sink);
}

#[test]
fn the_scan_keeps_an_orphan_that_has_a_pending_manifest_on_disk() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.raw_put(ID, ".cast", b"orphan".to_vec());
    let mut staged = sink.staging().begin_staged(&key(ID)).unwrap();
    staged.stash_manifest(b"{}").unwrap();
    staged.release();
    drop(staged);
    assert!(!sink.is_live(ID));
    assert_eq!(h.staging_files().len(), 1);
    assert_only_the_unprotected_orphan_is_removed(&h, &sink);
}

#[test]
fn the_scan_keeps_an_orphan_that_has_a_staged_part_on_disk() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    h.raw_put(ID, ".cast", b"orphan".to_vec());
    let mut staged = sink.staging().begin_staged(&key(ID)).unwrap();
    jaunt_audit::StagedRecording::write(&mut staged, 0, b"delivered").unwrap();
    staged.release();
    drop(staged);
    assert!(!sink.is_live(ID));
    assert_eq!(h.staging_files().len(), 1);
    assert_only_the_unprotected_orphan_is_removed(&h, &sink);
}

#[test]
fn an_open_breaker_means_no_staged_cast_is_hashed() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    fail_everything(&h, Fault::Transient);
    let mut staged = staged_small(&sink, ID);
    assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
    drop(staged);
    assert_eq!(sink.staged_hash_runs(), 0);
    let waiting = sink.recover_pending().unwrap();
    assert_eq!((waiting.deferred, waiting.published), (1, 0));
    assert_eq!(sink.staged_hash_runs(), 0);

    h.chaos.clear();
    h.settle();
    let published = sink.recover_pending().unwrap();
    assert_eq!(published.published, 1);
    assert_eq!(sink.staged_hash_runs(), 1);
}

#[test]
fn a_refused_recording_is_hashed_once_and_then_left_alone() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let first = h.sink();
    fail_everything(&h, Fault::Transient);
    let mut staged = staged_small(&first, ID);
    assert!(staged.commit(&manifest(ID, 1, 11)).is_err());
    drop(staged);
    h.chaos.clear();
    h.raw_put_with_sha(ID, ".cast", b"another recording\n".to_vec());
    h.raw_put(ID, ".manifest.json", b"{}".to_vec());

    let restarted = h.sink();
    for round in 0..3 {
        let recovery = restarted.recover_pending().unwrap();
        assert_eq!((recovery.refused, recovery.published), (1, 0), "{round}");
        assert_eq!(restarted.staged_hash_runs(), 1, "{round}");
    }
    assert_eq!(h.staging_files().len(), 2);
    assert_eq!(h.raw_get(ID, ".manifest.json"), Some(b"{}".to_vec()));
}

#[test]
fn a_failure_in_the_middle_of_a_cast_read_keeps_its_kind_for_the_caller() {
    use std::io::Read;

    use jaunt_recording_s3::RemoteError;

    for (fault, kind, expected) in [
        (Fault::Transient, std::io::ErrorKind::TimedOut, "transient"),
        (
            Fault::Denied,
            std::io::ErrorKind::PermissionDenied,
            "denied",
        ),
    ] {
        let h = Harness::new(&Backend::memory(REAL_PART));
        let sink = h.sink();
        let data = crate::harness::SplitMix::new(51).bytes(3 * 1024 * 1024);
        let mut staged = sink.begin(&key(ID)).unwrap();
        staged.write(0, &data).unwrap();
        staged.commit(&manifest(ID, 1, data.len() as u64)).unwrap();
        let mut stored = sink.open(&key(ID)).unwrap().unwrap();
        let mut reader = stored.cast.take().unwrap();
        let mut first = vec![0u8; 16];
        reader.read_exact(&mut first).unwrap();
        h.chaos.fail(Rule {
            op: "get",
            path_has: ".cast",
            remaining: None,
            fault,
        });
        let mut rest = Vec::new();
        let error = reader.read_to_end(&mut rest).unwrap_err();
        assert_eq!(error.kind(), kind);
        let carried = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<RemoteError>())
            .unwrap_or_else(|| panic!("the failure lost its kind: {error}"));
        match (expected, carried) {
            ("transient", RemoteError::Transient(_)) | ("denied", RemoteError::Denied(_)) => {}
            (_, other) => panic!("{expected}: {other:?}"),
        }
        assert!(rest.len() < data.len());
    }
}

fn stage_pending(h: &Harness, sink: &S3Sink, pending: &[u8]) {
    let mut staged = sink.staging().begin_staged(&key(ID)).unwrap();
    jaunt_audit::StagedRecording::write(&mut staged, 0, b"delivered\n").unwrap();
    staged.stash_manifest(pending).unwrap();
    staged.release();
    drop(staged);
    assert_eq!(h.staging_files().len(), 2);
}

#[test]
fn a_corrupt_pending_manifest_is_quarantined_after_five_attempts_and_nothing_is_deleted() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    stage_pending(&h, &sink, b"this is not a manifest");
    for attempt in 1..=4 {
        let recovery = sink.recover_pending().unwrap();
        assert_eq!(
            (recovery.deferred, recovery.quarantined),
            (1, 0),
            "{attempt}"
        );
        assert_eq!(h.staging_files().len(), 2, "{attempt}");
    }
    let fifth = sink.recover_pending().unwrap();
    assert_eq!((fifth.quarantined, fifth.deferred), (1, 0));
    assert_eq!(fifth.quarantined_ids, [ID]);
    let files = h.staging_files();
    assert_eq!(files.len(), 2, "{files:?}");
    assert!(
        files.iter().all(|file| file.starts_with("quarantine/")),
        "{files:?}"
    );
    assert_eq!(
        sink.recover_pending().unwrap(),
        jaunt_recording_s3::S3Recovery::default()
    );
    assert!(!sink.staging().holds_staged_part(&key(ID)));
}

#[test]
fn a_manifest_that_does_not_fit_its_staged_cast_counts_toward_the_quarantine_too() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    let long = serde_json::to_vec(&manifest(ID, 1, 3)).unwrap();
    stage_pending(&h, &sink, &long);
    for _ in 0..4 {
        assert_eq!(sink.recover_pending().unwrap().quarantined, 0);
    }
    assert_eq!(sink.recover_pending().unwrap().quarantined, 1);
}

#[test]
fn a_temporary_local_read_error_defers_and_never_makes_the_recording_refused() {
    use std::os::unix::fs::PermissionsExt;

    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    let real = serde_json::to_vec(&manifest(ID, 1, 10)).unwrap();
    stage_pending(&h, &sink, &real);
    let part = h
        .staging_root()
        .join(key(ID).location())
        .with_extension("cast.part");
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&part).is_ok() {
        std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o640)).unwrap();
        return;
    }
    for _ in 0..7 {
        let recovery = sink.recover_pending().unwrap();
        assert_eq!(
            (recovery.deferred, recovery.refused, recovery.quarantined),
            (1, 0, 0)
        );
        assert_eq!(h.staging_files().len(), 2);
    }
    std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o640)).unwrap();
    let recovery = sink.recover_pending().unwrap();
    assert_eq!((recovery.published, recovery.refused), (1, 0));
    assert!(h.staging_files().is_empty());
    assert_eq!(h.objects_of(ID), [".cast", ".manifest.json"]);
}

#[test]
fn a_read_error_while_hashing_the_staged_cast_defers_and_never_counts_toward_the_quarantine() {
    let h = Harness::new(&Backend::memory(SMALL_PART));
    let sink = h.sink();
    let real = serde_json::to_vec(&manifest(ID, 1, 10)).unwrap();
    stage_pending(&h, &sink, &real);
    sink.fail_staged_hash_reads(7);
    for cycle in 0..7 {
        let recovery = sink.recover_pending().unwrap();
        assert_eq!(
            (recovery.deferred, recovery.refused, recovery.quarantined),
            (1, 0, 0),
            "{cycle}"
        );
        assert_eq!(h.staging_files().len(), 2, "{cycle}");
    }
    let recovery = sink.recover_pending().unwrap();
    assert_eq!((recovery.published, recovery.refused), (1, 0));
    assert!(h.staging_files().is_empty());
}

#[test]
fn a_directory_a_fifo_or_a_symlink_in_place_of_the_part_defers_and_loses_nothing() {
    for kind in ["directory", "fifo", "symlink"] {
        let h = Harness::new(&Backend::memory(SMALL_PART));
        let sink = h.sink();
        let real = serde_json::to_vec(&manifest(ID, 1, 10)).unwrap();
        stage_pending(&h, &sink, &real);
        let part = h
            .staging_root()
            .join(key(ID).location())
            .with_extension("cast.part");
        let saved = std::fs::read(&part).unwrap();
        let elsewhere = h.staging_root().join("elsewhere.cast");
        std::fs::remove_file(&part).unwrap();
        match kind {
            "directory" => std::fs::create_dir(&part).unwrap(),
            "fifo" => assert!(
                std::process::Command::new("mkfifo")
                    .arg(&part)
                    .status()
                    .unwrap()
                    .success()
            ),
            _ => {
                std::fs::write(&elsewhere, &saved).unwrap();
                std::os::unix::fs::symlink(&elsewhere, &part).unwrap();
            }
        }
        for cycle in 0..7 {
            let recovery = sink.recover_pending().unwrap();
            assert_eq!(
                (recovery.deferred, recovery.refused, recovery.quarantined),
                (1, 0, 0),
                "{kind} {cycle}"
            );
            assert!(h.objects_of(ID).is_empty(), "{kind}");
        }
        assert!(part.symlink_metadata().is_ok(), "{kind}");
        assert!(
            h.staging_root()
                .join(key(ID).location())
                .with_extension("manifest.pending")
                .exists(),
            "{kind}"
        );
        match kind {
            "directory" => std::fs::remove_dir(&part).unwrap(),
            _ => std::fs::remove_file(&part).unwrap(),
        }
        std::fs::write(&part, &saved).unwrap();
        let recovery = sink.recover_pending().unwrap();
        assert_eq!((recovery.published, recovery.refused), (1, 0), "{kind}");
    }
}
