use jaunt_record::{Limits, MetadataOnly, Recorder, SessionKind, SessionManifest, VerifyError};

use crate::common::{SESSION, VecSink, accept_all, assembler, forged, three_chunk_session};

type Tamper = fn(&mut SessionManifest);

fn metadata_manifest(kind: SessionKind) -> SessionManifest {
    Recorder::metadata_only(MetadataOnly {
        session_id: SESSION.to_owned(),
        kind,
        node: "n".to_owned(),
        user: "u".to_owned(),
        login: "l".to_owned(),
        command: (kind == SessionKind::Exec).then(|| "uptime".to_owned()),
        started_at: 1,
        ended_at: Some(2),
        exit_status: Some(0),
        bytes_out: 5,
        bytes_in: 6,
    })
    .unwrap()
}

fn flagged(mut manifest: SessionManifest, dropped: u64) -> SessionManifest {
    manifest.incomplete = true;
    manifest.dropped_chunks = dropped;
    manifest
}

fn complete(
    chunks: &[jaunt_record::Chunk],
    manifest: &SessionManifest,
) -> (Result<jaunt_record::Verified, VerifyError>, VecSink) {
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    for chunk in chunks {
        assembler.accept(chunk, &mut sink).unwrap();
    }
    (assembler.complete(manifest, true, &mut sink), sink)
}

#[test]
fn a_gap_is_an_error_unless_the_manifest_says_incomplete() {
    let (chunks, manifest) = three_chunk_session();
    let received = [chunks[0].clone(), chunks[2].clone()];
    assert_eq!(
        complete(&received, &manifest).0,
        Err(VerifyError::Gap { missing: 1 })
    );

    let (verified, sink) = complete(
        &[chunks[2].clone(), chunks[0].clone()],
        &flagged(manifest, 1),
    );
    let verified = verified.unwrap();
    assert!(verified.incomplete);
    assert_eq!(verified.dropped_chunks, 1);
    assert_eq!(verified.missing_chunks, 1);
    assert_eq!(verified.received_chunks, 2);
    assert_eq!(verified.digest, None);
    assert_eq!(sink.seqs(), [0, 2]);
}

#[test]
fn incomplete_manifests_must_account_for_every_missing_chunk() {
    let (chunks, manifest) = three_chunk_session();
    let with_gap = [chunks[0].clone(), chunks[2].clone()];
    assert_eq!(
        complete(&with_gap, &flagged(manifest.clone(), 0)).0,
        Err(VerifyError::ChunkCountMismatch)
    );

    let mut wrong_total = flagged(manifest.clone(), 2);
    wrong_total.chunks = 4;
    assert_eq!(
        complete(&with_gap, &wrong_total).0,
        Err(VerifyError::ChunkCountMismatch)
    );

    let mut too_small = flagged(manifest.clone(), 1);
    too_small.raw_bytes = chunks[0].raw_len + chunks[2].raw_len - 1;
    assert_eq!(
        complete(&with_gap, &too_small).0,
        Err(VerifyError::RawBytesMismatch)
    );
    let mut exact = flagged(manifest.clone(), 1);
    exact.raw_bytes = chunks[0].raw_len + chunks[2].raw_len;
    assert!(complete(&with_gap, &exact).0.is_ok());
}

#[test]
fn an_incomplete_set_with_a_chunk_beyond_the_declared_total_is_rejected() {
    let (_, manifest) = three_chunk_session();
    let mut declared = flagged(manifest, 0);
    declared.chunks = 2;
    let received = [forged(0, b"a", false), forged(5, b"b", false)];
    assert_eq!(
        complete(&received, &declared).0,
        Err(VerifyError::ChunkCountMismatch)
    );
}

#[test]
fn a_lost_last_chunk_is_missing_last_unless_flagged() {
    let (chunks, manifest) = three_chunk_session();
    assert_eq!(
        complete(&chunks[..2], &manifest).0,
        Err(VerifyError::MissingLast)
    );
    let (verified, _) = complete(&chunks[..2], &flagged(manifest, 1));
    let verified = verified.unwrap();
    assert!(verified.incomplete);
    assert_eq!(verified.missing_chunks, 0);
}

#[test]
fn a_full_set_flagged_incomplete_must_not_report_drops() {
    let (chunks, manifest) = three_chunk_session();
    assert_eq!(
        complete(&chunks, &flagged(manifest.clone(), 99)).0,
        Err(VerifyError::InconsistentManifest)
    );
    let (verified, _) = complete(&chunks, &flagged(manifest, 0));
    assert!(verified.unwrap().incomplete);
}

#[test]
fn tampered_manifests_are_rejected() {
    let (chunks, manifest) = three_chunk_session();
    let cases: Vec<(&str, Tamper, VerifyError)> = vec![
        (
            "digest",
            |m| m.digest = Some("0".repeat(64)),
            VerifyError::DigestMismatch,
        ),
        (
            "digest missing",
            |m| m.digest = None,
            VerifyError::DigestMismatch,
        ),
        ("chunks", |m| m.chunks += 1, VerifyError::ChunkCountMismatch),
        (
            "raw bytes",
            |m| m.raw_bytes += 1,
            VerifyError::RawBytesMismatch,
        ),
        (
            "version",
            |m| m.version = 2,
            VerifyError::UnsupportedVersion(2),
        ),
        (
            "session",
            |m| m.session_id = "other".to_owned(),
            VerifyError::SessionMismatch,
        ),
        (
            "dropped without incomplete",
            |m| m.dropped_chunks = 1,
            VerifyError::InconsistentManifest,
        ),
    ];
    for (name, tamper, expected) in cases {
        let mut tampered = manifest.clone();
        tamper(&mut tampered);
        assert_eq!(complete(&chunks, &tampered).0, Err(expected), "{name}");
    }
}

#[test]
fn a_terminal_session_with_no_chunks_is_never_verified() {
    for kind in [SessionKind::Shell, SessionKind::Exec, SessionKind::Sftp] {
        let mut manifest = metadata_manifest(SessionKind::Exec);
        manifest.kind = kind;
        manifest.bytes_out = 123_456_789;
        for candidate in [manifest.clone(), flagged(manifest.clone(), 0)] {
            assert_eq!(
                complete(&[], &candidate).0,
                Err(VerifyError::NoRecording),
                "{kind:?}"
            );
        }
        let mut all_dropped = flagged(manifest, 3);
        all_dropped.chunks = 3;
        assert_eq!(complete(&[], &all_dropped).0, Err(VerifyError::NoRecording));
    }
}

#[test]
fn a_session_without_a_terminal_verifies_only_as_pure_metadata() {
    for kind in [SessionKind::Exec, SessionKind::Sftp] {
        let manifest = metadata_manifest(kind);
        let verified = assembler(Limits::default())
            .complete(&manifest, false, &mut VecSink::default())
            .unwrap();
        assert_eq!((verified.received_chunks, verified.missing_chunks), (0, 0));
        assert_eq!(verified.digest, None);
    }
}

#[test]
fn metadata_only_manifests_that_claim_recording_data_are_rejected() {
    let cases: Vec<(&str, Tamper)> = vec![
        ("chunks", |m| m.chunks = 1),
        ("raw bytes", |m| m.raw_bytes = 1),
        ("digest", |m| m.digest = Some("0".repeat(64))),
        ("dropped", |m| {
            m.incomplete = true;
            m.dropped_chunks = 1;
        }),
    ];
    for (name, tamper) in cases {
        let mut manifest = metadata_manifest(SessionKind::Exec);
        tamper(&mut manifest);
        let result =
            assembler(Limits::default()).complete(&manifest, false, &mut VecSink::default());
        assert_eq!(result, Err(VerifyError::MetadataOnlyMismatch), "{name}");
    }
}

#[test]
fn a_node_can_still_flag_a_session_without_terminal_expectation_as_incomplete() {
    let mut manifest = flagged(metadata_manifest(SessionKind::Exec), 0);
    manifest.bytes_out = 123_456_789;
    let verified = assembler(Limits::default())
        .complete(&manifest, false, &mut VecSink::default())
        .unwrap();
    assert!(verified.incomplete);
}

#[test]
fn a_session_that_expected_no_terminal_still_verifies_when_chunks_arrive_and_match() {
    let (chunks, manifest) = three_chunk_session();
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    accept_all(&mut assembler, &chunks, &mut sink);
    assert!(assembler.complete(&manifest, false, &mut sink).is_ok());
}
