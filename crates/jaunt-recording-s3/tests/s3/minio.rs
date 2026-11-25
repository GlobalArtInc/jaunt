use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingSink, RecordingStoreError};
use jaunt_recording_s3::{Credentials, ProbeError, S3Config, S3Sink, Secret, build_store};

use crate::harness::{Backend, Harness, ID, key, manifest};
use crate::scenarios;

const REAL_PART: usize = 5 * 1024 * 1024;
const WRONG_SECRET: &str = "wrong-secret-for-the-throwaway-minio-test";

fn setting(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set: run just s3-tests"))
}

fn config(prefix: &str) -> S3Config {
    S3Config {
        endpoint: Some(setting("JAUNT_S3_TEST_ENDPOINT")),
        bucket: setting("JAUNT_S3_TEST_BUCKET"),
        prefix: prefix.to_owned(),
        path_style: true,
        allow_insecure_http: true,
        ..S3Config::new("us-east-1", "placeholder")
    }
}

fn credentials(secret: String) -> Credentials {
    Credentials {
        access_key: setting("JAUNT_S3_TEST_ACCESS_KEY"),
        secret_key: Secret::new(secret),
        session_token: None,
    }
}

fn backend(part_size: usize) -> Backend {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let prefix = format!(
        "t{}-{}/",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    );
    let store = build_store(
        &config(&prefix),
        &credentials(setting("JAUNT_S3_TEST_SECRET_KEY")),
    )
    .unwrap();
    Backend::real(store, part_size, prefix)
}

macro_rules! minio_scenarios {
    ($($name:ident: $part:expr),* $(,)?) => {
        $(
            #[test]
            #[ignore = "needs MinIO: run just s3-tests"]
            fn $name() {
                scenarios::$name(&backend($part));
            }
        )*
    };
}

minio_scenarios! {
    a_large_recording_is_stored_byte_for_byte_with_the_manifest_last_and_verifies: REAL_PART,
    an_existing_recording_is_never_overwritten_and_an_identical_retry_is_accepted: REAL_PART,
    a_metadata_only_recording_stores_just_the_manifest: REAL_PART,
    a_crash_between_the_two_puts_is_finished_from_the_staged_files_at_the_next_start: REAL_PART,
    recovery_keeps_staged_recordings_while_the_store_is_down: REAL_PART,
    orphan_casts_are_removed_only_when_old_unstaged_and_without_a_manifest: REAL_PART,
    an_interrupted_upload_resumes_from_its_prefix_and_a_changed_prefix_is_refused: REAL_PART,
    an_unreachable_store_fails_the_commit_cleanly_and_a_later_retry_succeeds: REAL_PART,
    a_store_that_recovers_inside_the_deadline_completes_the_commit: REAL_PART,
    a_failed_multipart_upload_is_aborted_and_leaves_no_object: REAL_PART,
    a_staged_cast_that_no_longer_matches_its_hash_is_never_published: REAL_PART,
    rejected_credentials_fail_at_once_as_unavailable_without_retries: REAL_PART,
    reading_a_recording_reports_absence_outages_and_a_missing_cast: REAL_PART,
}

fn connected(config: &S3Config, credentials: &Credentials, h: &Harness) -> S3Sink {
    let staging = DirectorySink::create(
        &h.staging_root(),
        DirectoryLimits {
            min_free_bytes: 0,
            max_total_raw: 1 << 24,
        },
    )
    .unwrap();
    S3Sink::connect(config, credentials, staging, h.runtime.handle().clone()).unwrap()
}

#[test]
#[ignore = "needs MinIO: run just s3-tests"]
fn wrong_credentials_are_refused_at_the_probe_and_never_echoed() {
    let h = Harness::new(&backend(REAL_PART));
    let good = config("probe/");
    let sink = connected(&good, &credentials(setting("JAUNT_S3_TEST_SECRET_KEY")), &h);
    sink.probe().unwrap();

    let bad_credentials = credentials(WRONG_SECRET.to_owned());
    let bad = connected(&good, &bad_credentials, &h);
    let denied = bad.probe().unwrap_err();
    assert!(matches!(denied, ProbeError::Denied(_)), "{denied}");
    let shown = format!("{denied} {denied:?} {bad:?} {bad_credentials:?} {good:?}");
    assert!(!shown.contains(WRONG_SECRET), "{shown}");

    let mut staged = bad.begin(&key(ID)).unwrap();
    staged.write(0, b"recording\n").unwrap();
    let err = staged.commit(&manifest(ID, 1, 10)).unwrap_err();
    assert!(matches!(err, RecordingStoreError::Unavailable), "{err}");
    assert!(!format!("{err:?}").contains(WRONG_SECRET));
}

#[test]
#[ignore = "needs MinIO: run just s3-tests"]
fn a_missing_bucket_is_named_at_the_probe() {
    let h = Harness::new(&backend(REAL_PART));
    let missing = S3Config {
        bucket: "jaunt-no-such-bucket".to_owned(),
        ..config("probe/")
    };
    let sink = connected(
        &missing,
        &credentials(setting("JAUNT_S3_TEST_SECRET_KEY")),
        &h,
    );
    assert!(matches!(sink.probe(), Err(ProbeError::BucketMissing)));
}

minio_scenarios! {
    maintenance_leaves_the_files_of_an_upload_that_is_still_alive_in_memory: REAL_PART,
    a_commit_whose_staged_cast_vanished_fails_instead_of_storing_a_manifest_alone: REAL_PART,
    an_identical_object_that_appears_during_the_put_is_accepted_and_a_different_one_is_not: REAL_PART,
    an_object_damaged_right_after_the_upload_is_noticed_and_replaced_before_the_manifest: REAL_PART,
    a_foreign_object_created_during_a_multipart_upload_is_never_overwritten: REAL_PART,
    an_old_cast_with_other_content_and_no_manifest_is_replaced_by_the_commit: REAL_PART,
    a_manifest_that_is_oversize_or_belongs_to_another_session_is_refused: REAL_PART,
    a_replaced_object_is_never_mixed_into_a_stream_that_is_being_read: REAL_PART,
    probing_writes_and_removes_a_marker_and_names_what_is_wrong: REAL_PART,
}

#[test]
#[ignore = "needs MinIO: run just s3-tests"]
fn encryption_the_server_cannot_provide_stops_the_probe_as_a_permanent_rejection() {
    let h = Harness::new(&backend(REAL_PART));
    let with_sse = S3Config {
        sse: jaunt_recording_s3::Sse::Aes256,
        ..config("sse/")
    };
    let sink = connected(
        &with_sse,
        &credentials(setting("JAUNT_S3_TEST_SECRET_KEY")),
        &h,
    );
    let error = sink.probe().unwrap_err();
    assert!(matches!(error, ProbeError::Rejected(_)), "{error}");
}
