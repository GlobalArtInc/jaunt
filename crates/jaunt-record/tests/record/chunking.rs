use jaunt_record::{
    CHUNK_TARGET_BYTES, MAX_EVENT_TEXT_BYTES, MetadataOnly, RecordError, Recorder, SessionKind,
};
use sha2::{Digest, Sha256};

use crate::common::{TestClock, config, finish_cast, inflate, parse_cast, recorder};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn cuts_at_the_target_size_on_line_boundaries() {
    let (mut recorder, _clock) = recorder(false);
    let line = vec![b'x'; 99];
    for _ in 0..2_000 {
        recorder.push_output(&line).unwrap();
    }
    let (_, manifest, chunks) = finish_cast(recorder);
    assert!(chunks.len() >= 3);
    for chunk in &chunks[..chunks.len() - 1] {
        let raw = inflate(chunk);
        assert!(raw.len() >= CHUNK_TARGET_BYTES);
        assert!(raw.len() < CHUNK_TARGET_BYTES + 200);
        assert_eq!(raw.last(), Some(&b'\n'));
        assert!(parse_cast_lines(&raw));
    }
    assert!(chunks[0].compressed.len() < inflate(&chunks[0]).len());
    assert_eq!(manifest.chunks, chunks.len() as u64);
}

fn parse_cast_lines(raw: &[u8]) -> bool {
    let text = std::str::from_utf8(raw).unwrap();
    text.split_terminator('\n').all(|line| {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        value.is_array() || value.is_object()
    })
}

#[test]
fn a_huge_single_push_is_split_into_bounded_events_and_chunks() {
    let (mut recorder, _clock) = recorder(false);
    recorder.push_output(&vec![b'\n'; 3 * 1024 * 1024]).unwrap();
    let (cast, _, chunks) = finish_cast(recorder);
    assert!(chunks.len() > 1);
    let bound = CHUNK_TARGET_BYTES + 6 * MAX_EVENT_TEXT_BYTES + 100;
    assert!(chunks.iter().all(|chunk| (chunk.raw_len as usize) < bound));
    let parsed = parse_cast(&cast).unwrap();
    assert!(
        parsed
            .events
            .iter()
            .all(|event| event.data.len() <= MAX_EVENT_TEXT_BYTES)
    );
}

#[test]
fn flush_cuts_early_and_is_a_no_op_when_nothing_is_pending() {
    let (mut recorder, _clock) = recorder(false);
    recorder.push_output(b"hello").unwrap();
    recorder.flush().unwrap();
    recorder.flush().unwrap();
    let early = recorder.take_chunks();
    assert_eq!(early.len(), 1);
    assert!(!early[0].is_last);
    assert!(inflate(&early[0]).starts_with(b"{\"version\":2"));

    let manifest = recorder.finish(None, 10).unwrap();
    let rest = recorder.take_chunks();
    assert_eq!(rest.len(), 1);
    assert!(rest[0].is_last);
    assert_eq!(rest[0].seq, 1);
    assert_eq!(rest[0].raw_len, 0);
    assert!(inflate(&rest[0]).is_empty());
    assert_eq!(manifest.chunks, 2);
}

#[test]
fn empty_session_still_has_a_last_chunk_with_the_header() {
    let (recorder, _clock) = recorder(false);
    let (cast, manifest, chunks) = finish_cast(recorder);
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].is_last);
    assert_eq!(chunks[0].seq, 0);
    assert!(cast.starts_with(b"{\"version\":2"));
    assert_eq!(manifest.chunks, 1);
}

#[test]
fn seq_hashes_digest_and_counts_are_correct() {
    let (mut recorder, clock) = recorder(false);
    let mut rng = crate::common::seeded(3);
    crate::common::drive(&mut recorder, &clock, &mut rng, 600_000);
    let (_, manifest, chunks) = finish_cast(recorder);
    let mut digests = Sha256::new();
    let mut raw_total = 0;
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.seq, index as u64);
        assert_eq!(chunk.is_last, index + 1 == chunks.len());
        assert_eq!(chunk.session_id, "sess-1");
        let digest = Sha256::digest(&chunk.compressed);
        assert_eq!(chunk.sha256, hex(&digest));
        assert_eq!(chunk.raw_len as usize, inflate(chunk).len());
        digests.update(digest);
        raw_total += chunk.raw_len;
    }
    assert_eq!(manifest.digest, Some(hex(&digests.finalize())));
    assert_eq!(manifest.chunks, chunks.len() as u64);
    assert_eq!(manifest.raw_bytes, raw_total);
    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.ended_at, Some(1_700_000_100));
    assert_eq!(manifest.exit_status, Some(0));
    assert!(!manifest.incomplete);
    assert_eq!(manifest.dropped_chunks, 0);
}

#[test]
fn every_operation_after_finish_is_an_error() {
    let (mut recorder, _clock) = recorder(true);
    recorder.finish(Some(0), 1).unwrap();
    assert_eq!(recorder.push_output(b"x"), Err(RecordError::Finished));
    assert_eq!(recorder.push_input(b"x"), Err(RecordError::Finished));
    assert_eq!(recorder.resize(1, 1), Err(RecordError::Finished));
    assert_eq!(recorder.marker("m"), Err(RecordError::Finished));
    assert_eq!(recorder.flush(), Err(RecordError::Finished));
    assert_eq!(recorder.finish(Some(0), 2), Err(RecordError::Finished));
}

#[test]
fn a_marker_at_the_limit_is_accepted_and_one_byte_more_is_rejected() {
    let (mut recorder, _clock) = recorder(false);
    let exact = "m".repeat(jaunt_record::MAX_MARKER_BYTES);
    assert_eq!(recorder.marker(&exact), Ok(()));
    let over = "m".repeat(jaunt_record::MAX_MARKER_BYTES + 1);
    assert_eq!(recorder.marker(&over), Err(RecordError::MarkerTooLong));
}

fn chunks_after_filling_pending_to(missing_from_target: usize) -> Vec<jaunt_record::Chunk> {
    let (empty, _clock) = recorder(false);
    let header_len = finish_cast(empty).0.len();
    let event_overhead = "[0.0, \"o\", \"\"]\n".len();
    let events = 4;
    let last = CHUNK_TARGET_BYTES
        - missing_from_target
        - header_len
        - events * event_overhead
        - 3 * MAX_EVENT_TEXT_BYTES;
    let (mut recorder, _clock) = recorder(false);
    for size in [
        MAX_EVENT_TEXT_BYTES,
        MAX_EVENT_TEXT_BYTES,
        MAX_EVENT_TEXT_BYTES,
        last,
    ] {
        recorder.push_output(&vec![b'x'; size]).unwrap();
    }
    recorder.take_chunks()
}

#[test]
fn pending_text_exactly_at_the_target_is_cut_and_one_byte_less_is_not() {
    assert!(chunks_after_filling_pending_to(1).is_empty());
    let cut = chunks_after_filling_pending_to(0);
    assert_eq!(cut.len(), 1);
    assert_eq!(cut[0].raw_len as usize, CHUNK_TARGET_BYTES);
    assert!(!cut[0].is_last);
}

fn metadata(kind: SessionKind, command: Option<&str>) -> MetadataOnly {
    MetadataOnly {
        session_id: "sess-2".to_owned(),
        kind,
        node: "node-a".to_owned(),
        user: "alice".to_owned(),
        login: "root".to_owned(),
        command: command.map(str::to_owned),
        started_at: 100,
        ended_at: Some(110),
        exit_status: Some(3),
        bytes_out: 11,
        bytes_in: 7,
    }
}

#[test]
fn metadata_only_manifests_have_no_chunks() {
    let exec = Recorder::metadata_only(metadata(SessionKind::Exec, Some("uptime"))).unwrap();
    assert_eq!(exec.command.as_deref(), Some("uptime"));
    assert_eq!(exec.exit_status, Some(3));
    assert_eq!((exec.bytes_out, exec.bytes_in), (11, 7));
    assert_eq!((exec.chunks, exec.raw_bytes, exec.digest), (0, 0, None));
    assert!(!exec.input_recorded && !exec.incomplete);

    let sftp = Recorder::metadata_only(metadata(SessionKind::Sftp, None)).unwrap();
    assert_eq!(sftp.kind, SessionKind::Sftp);
    assert_eq!(sftp.chunks, 0);
}

#[test]
fn kind_and_command_combinations_are_validated() {
    assert_eq!(
        Recorder::metadata_only(metadata(SessionKind::Shell, None)),
        Err(RecordError::ShellNeedsTerminal)
    );
    assert_eq!(
        Recorder::metadata_only(metadata(SessionKind::Sftp, Some("ls"))),
        Err(RecordError::CommandNotAllowed)
    );
    let mut sftp = config(false);
    sftp.kind = SessionKind::Sftp;
    assert_eq!(
        Recorder::new(sftp, Box::new(TestClock::new())).err(),
        Some(RecordError::SftpHasNoCast)
    );
    let mut shell = config(false);
    shell.command = Some("ls".to_owned());
    assert_eq!(
        Recorder::new(shell, Box::new(TestClock::new())).err(),
        Some(RecordError::CommandNotAllowed)
    );
}
