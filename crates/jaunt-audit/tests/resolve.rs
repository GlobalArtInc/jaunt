use std::io;

use jaunt_audit::{
    CastProof, Identity, LocalProof, RecordingStoreError, Resolution, StoreProof, resolve_existing,
};
use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};

const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

fn shell() -> SessionManifest {
    SessionManifest {
        version: MANIFEST_VERSION,
        session_id: ID.to_owned(),
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
        chunks: 14,
        raw_bytes: 100,
        incomplete: false,
        dropped_chunks: 0,
        digest: Some("d".repeat(64)),
    }
}

fn exec() -> SessionManifest {
    SessionManifest {
        kind: SessionKind::Exec,
        command: Some("uptime".to_owned()),
        chunks: 0,
        raw_bytes: 0,
        digest: None,
        ..shell()
    }
}

fn synthetic(of: &SessionManifest, chunks: u64) -> SessionManifest {
    SessionManifest {
        incomplete: true,
        digest: None,
        exit_status: None,
        chunks,
        ..of.clone()
    }
}

fn identity() -> Identity {
    Identity {
        session_id: ID.to_owned(),
        node: "node-1".to_owned(),
        user: "user-1".to_owned(),
        login: Some("deploy".to_owned()),
    }
}

fn cast(content: &str, bytes: u64) -> Option<CastProof> {
    CastProof::of(bytes, content)
}

fn found(
    manifest: SessionManifest,
    cast: Option<CastProof>,
) -> Result<Option<StoreProof>, RecordingStoreError> {
    Ok(Some(StoreProof {
        manifest,
        manifest_sha256: "m".repeat(64),
        cast_bytes: cast.as_ref().map_or(0, |proof| proof.bytes),
        cast_sha256: cast.map(|proof| proof.sha256),
    }))
}

fn judge(
    local: Option<(&SessionManifest, Option<CastProof>)>,
    found: Result<Option<StoreProof>, RecordingStoreError>,
) -> Resolution {
    match local {
        Some((manifest, cast)) => {
            let proof = LocalProof {
                manifest: Some(manifest),
                cast: cast.as_ref(),
                chunks: None,
            };
            resolve_existing(&identity(), Some(&proof), &found)
        }
        None => resolve_existing(&identity(), None, &found),
    }
}

fn is_conflict(resolution: Resolution) -> bool {
    matches!(resolution, Resolution::Conflict(_))
}

#[test]
fn reading_failures_are_a_retry_and_only_unreadable_content_is_a_conflict() {
    let real = shell();
    let local = || Some((&real, cast("a", 100)));
    for error in [
        RecordingStoreError::Unavailable,
        RecordingStoreError::Io {
            operation: "read",
            source: io::Error::from(io::ErrorKind::TimedOut),
        },
        RecordingStoreError::Io {
            operation: "read",
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        },
        RecordingStoreError::Finished,
    ] {
        assert_eq!(judge(local(), Err(error)), Resolution::Retry);
    }
    for error in [
        RecordingStoreError::InvalidManifest,
        RecordingStoreError::UnsafePath,
    ] {
        assert!(is_conflict(judge(local(), Err(error))));
    }
    assert_eq!(judge(local(), Ok(None)), Resolution::Nothing);
    assert_eq!(judge(None, Ok(None)), Resolution::Nothing);
}

#[test]
fn identity_and_length_are_checked_for_every_caller() {
    let real = shell();
    let mut cases: Vec<SessionManifest> = Vec::new();
    for change in 0..4 {
        let mut other = real.clone();
        match change {
            0 => other.session_id = "0b1c2d3e-4f50-4617-8829-3a4b5c6d7e8f".to_owned(),
            1 => other.node = "node-2".to_owned(),
            2 => other.user = "user-2".to_owned(),
            _ => other.login = "root".to_owned(),
        }
        cases.push(other);
    }
    for other in cases {
        assert!(is_conflict(judge(
            None,
            found(other.clone(), cast("a", 100))
        )));
        assert!(is_conflict(judge(
            Some((&real, cast("a", 100))),
            found(other, cast("a", 100))
        )));
    }
    let mut short = real.clone();
    short.raw_bytes = 50;
    assert!(is_conflict(judge(None, found(short, cast("a", 100)))));
    assert_eq!(
        judge(None, found(real.clone(), cast("a", 100))),
        Resolution::Adopt
    );
    assert_eq!(
        judge(None, found(synthetic(&real, 3), cast("zzz", 7))),
        Resolution::Adopt
    );
}

#[test]
fn a_manifest_that_is_not_a_well_formed_record_of_its_cast_is_a_conflict_for_every_caller() {
    let real = shell();
    let mutations: Vec<(&str, SessionManifest, Option<CastProof>)> = vec![
        (
            "complete without a digest",
            SessionManifest {
                digest: None,
                ..real.clone()
            },
            cast("a", 100),
        ),
        (
            "complete with more raw bytes than the cast",
            SessionManifest {
                raw_bytes: 200,
                ..real.clone()
            },
            cast("a", 100),
        ),
        (
            "complete with dropped chunks",
            SessionManifest {
                dropped_chunks: 5,
                ..real.clone()
            },
            cast("a", 100),
        ),
        ("complete without any cast object", real.clone(), None),
        (
            "incomplete without any cast object",
            synthetic(&real, 3),
            None,
        ),
        (
            "an unknown version",
            SessionManifest {
                version: 99,
                ..real.clone()
            },
            cast("a", 100),
        ),
    ];
    for (name, manifest, stored) in mutations {
        assert!(
            is_conflict(judge(None, found(manifest.clone(), stored.clone()))),
            "{name}: without a local proof"
        );
        assert!(
            is_conflict(judge(
                Some((&manifest, cast("a", 100))),
                found(manifest.clone(), stored.clone())
            )),
            "{name}: with a verified local proof"
        );
    }
}

#[test]
fn a_prefix_proof_with_the_delivered_chunk_count_rejects_a_complete_manifest_of_another_count() {
    let real = shell();
    let proof = cast("a", 100);
    let local = |chunks| LocalProof {
        manifest: None,
        cast: proof.as_ref(),
        chunks,
    };
    let stored = || found(real.clone(), cast("a", 100));
    assert_eq!(
        resolve_existing(&identity(), Some(&local(Some(14))), &stored()),
        Resolution::Adopt
    );
    assert!(is_conflict(resolve_existing(
        &identity(),
        Some(&local(Some(13))),
        &stored()
    )));
    assert_eq!(
        resolve_existing(
            &identity(),
            Some(&local(Some(13))),
            &found(synthetic(&real, 13), cast("a", 100))
        ),
        Resolution::Adopt
    );
}

#[test]
fn the_cast_must_match_by_length_and_hash() {
    let real = shell();
    let staged = || Some((&real, cast("a", 100)));
    assert_eq!(
        judge(staged(), found(real.clone(), cast("a", 100))),
        Resolution::Adopt
    );
    assert!(is_conflict(judge(
        staged(),
        found(real.clone(), cast("b", 100))
    )));
    assert!(is_conflict(judge(
        staged(),
        found(real.clone(), cast("a", 99))
    )));
    assert!(is_conflict(judge(
        staged(),
        found(real.clone(), cast("a", 60))
    )));
    assert!(is_conflict(judge(staged(), found(real.clone(), None))));
    let nothing_staged = || Some((&real, None));
    assert!(is_conflict(judge(
        nothing_staged(),
        found(real.clone(), cast("a", 100))
    )));
    let mut empty = real.clone();
    empty.raw_bytes = 0;
    assert_eq!(
        judge(Some((&empty, None)), found(empty.clone(), None)),
        Resolution::Adopt
    );
}

#[test]
fn a_prefix_proof_without_a_manifest_judges_the_cast_alone() {
    let real = shell();
    let proof = cast("a", 100);
    let local = LocalProof {
        manifest: None,
        cast: proof.as_ref(),
        chunks: None,
    };
    let same = found(synthetic(&real, 3), cast("a", 100));
    assert_eq!(
        resolve_existing(&identity(), Some(&local), &same),
        Resolution::Adopt
    );
    let other = found(real, cast("b", 100));
    assert!(is_conflict(resolve_existing(
        &identity(),
        Some(&local),
        &other
    )));
}

#[test]
fn the_manifest_must_agree_with_the_verified_one_or_be_a_lost_acknowledgement() {
    let real = shell();
    let staged = || Some((&real, cast("a", 100)));
    assert_eq!(
        judge(staged(), found(real.clone(), cast("a", 100))),
        Resolution::Adopt
    );
    for chunks in [0, 1, 14] {
        assert_eq!(
            judge(staged(), found(synthetic(&real, chunks), cast("a", 100))),
            Resolution::Adopt,
            "{chunks}"
        );
    }
    assert!(is_conflict(judge(
        staged(),
        found(synthetic(&real, 15), cast("a", 100))
    )));
    let mut other_kind = synthetic(&real, 3);
    other_kind.kind = SessionKind::Exec;
    assert!(is_conflict(judge(
        staged(),
        found(other_kind, cast("a", 100))
    )));
    let mut with_digest = synthetic(&real, 3);
    with_digest.digest = Some("e".repeat(64));
    assert!(is_conflict(judge(
        staged(),
        found(with_digest, cast("a", 100))
    )));

    let mut changed = Vec::new();
    for change in 0..6 {
        let mut other = real.clone();
        match change {
            0 => other.digest = Some("e".repeat(64)),
            1 => other.chunks = 999,
            2 => other.raw_bytes = 101,
            3 => other.incomplete = true,
            4 => other.dropped_chunks = 1,
            _ => other.input_recorded = true,
        }
        changed.push(other);
    }
    for other in changed {
        assert!(is_conflict(judge(staged(), found(other, cast("a", 100)))));
    }
}

#[test]
fn a_recording_without_a_cast_compares_its_metadata_fields() {
    let real = exec();
    let staged = || Some((&real, None));
    assert_eq!(
        judge(staged(), found(real.clone(), None)),
        Resolution::Adopt
    );
    let mut changed = Vec::new();
    for change in 0..5 {
        let mut other = real.clone();
        match change {
            0 => other.command = Some("reboot".to_owned()),
            1 => other.bytes_out = 11,
            2 => other.bytes_in = 1,
            3 => other.exit_status = Some(137),
            _ => other.kind = SessionKind::Sftp,
        }
        changed.push(other);
    }
    for other in changed {
        assert!(is_conflict(judge(staged(), found(other, None))));
    }
    assert!(is_conflict(judge(
        staged(),
        found(real.clone(), cast("a", 1))
    )));
}
