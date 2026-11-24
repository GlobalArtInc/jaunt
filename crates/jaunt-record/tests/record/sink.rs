use std::error::Error;

use jaunt_record::{Accepted, AssembleError, Assembler, Limits, SinkError, VerifyError};

use crate::common::{FlakySink, assembler, cast_of, forged, three_chunk_session};

fn state(assembler: &Assembler) -> String {
    format!("{assembler:?}")
}

#[test]
fn a_failing_sink_on_the_first_middle_and_last_delivery_is_retryable() {
    for failing_seq in 0..3_u64 {
        let (chunks, manifest) = three_chunk_session();
        let mut assembler = assembler(Limits::default());
        let mut sink = FlakySink::failing_at(failing_seq);
        for chunk in &chunks {
            if chunk.seq != failing_seq {
                assert_eq!(assembler.accept(chunk, &mut sink), Ok(Accepted::New));
                continue;
            }
            let result = assembler.accept(chunk, &mut sink);
            assert!(
                matches!(result, Err(AssembleError::Sink(_))),
                "{failing_seq}"
            );
            let shown = state(&assembler);
            assert!(
                shown.contains(&format!("next_deliver: {failing_seq}")),
                "{shown}"
            );
            assert!(
                shown.contains(&format!("received_chunks: {failing_seq}")),
                "{shown}"
            );
            assert!(shown.contains("reordered_bytes: 0"), "{shown}");
            sink.recover();
            assert_eq!(assembler.accept(chunk, &mut sink), Ok(Accepted::New));
        }
        assembler.complete(&manifest, true, &mut sink).unwrap();
        assert_eq!(sink.inner.seqs(), [0, 1, 2]);
        assert_eq!(sink.inner.bytes(), cast_of(&chunks));
    }
}

#[test]
fn a_sink_failure_while_draining_keeps_the_reorder_accounting_and_recovers_on_retry() {
    let (chunks, manifest) = three_chunk_session();
    let pending = chunks[1].compressed.len() + chunks[2].compressed.len();
    let mut assembler = assembler(Limits::default());
    let mut sink = FlakySink::failing_at(1);
    assert_eq!(assembler.accept(&chunks[2], &mut sink), Ok(Accepted::New));
    assert_eq!(assembler.accept(&chunks[1], &mut sink), Ok(Accepted::New));

    let result = assembler.accept(&chunks[0], &mut sink);
    assert!(matches!(result, Err(AssembleError::Sink(_))));
    assert_eq!(sink.inner.seqs(), [0]);
    let shown = state(&assembler);
    assert!(shown.contains("reordered_chunks: 2"), "{shown}");
    assert!(
        shown.contains(&format!("reordered_bytes: {pending}")),
        "{shown}"
    );
    assert!(shown.contains("next_deliver: 1"), "{shown}");

    sink.recover();
    assert_eq!(
        assembler.accept(&chunks[0], &mut sink),
        Ok(Accepted::Duplicate)
    );
    assert_eq!(sink.inner.seqs(), [0, 1, 2]);
    let shown = state(&assembler);
    assert!(shown.contains("reordered_chunks: 0"), "{shown}");
    assert!(shown.contains("reordered_bytes: 0"), "{shown}");
    assert!(shown.contains("next_deliver: 3"), "{shown}");
    assembler.complete(&manifest, true, &mut sink).unwrap();
    assert_eq!(sink.inner.bytes(), cast_of(&chunks));
}

#[test]
fn a_sink_failure_in_complete_is_reported_and_complete_can_be_retried() {
    let (chunks, mut manifest) = three_chunk_session();
    manifest.incomplete = true;
    manifest.dropped_chunks = 1;
    let mut assembler = assembler(Limits::default());
    let mut sink = FlakySink::failing_at(2);
    assert_eq!(assembler.accept(&chunks[0], &mut sink), Ok(Accepted::New));
    assert_eq!(assembler.accept(&chunks[2], &mut sink), Ok(Accepted::New));

    let result = assembler.complete(&manifest, true, &mut sink);
    assert!(matches!(result, Err(VerifyError::Sink(_))));
    assert_eq!(sink.inner.seqs(), [0]);
    assert!(state(&assembler).contains("reordered_chunks: 1"));

    sink.recover();
    let verified = assembler.complete(&manifest, true, &mut sink).unwrap();
    assert!(verified.incomplete);
    assert_eq!(sink.inner.seqs(), [0, 2]);
}

#[test]
fn sink_errors_never_show_chunk_bytes_or_the_payload_text() {
    let chunk = forged(0, b"TOPSECRETDATA TOPSECRETDATA", false);
    let mut sink = FlakySink::failing_at(0);
    let error = assembler(Limits::default())
        .accept(&chunk, &mut sink)
        .unwrap_err();
    let shown = format!("{error} | {error:?}");
    assert!(!shown.contains("TOPSECRET"), "{shown}");
    assert!(!shown.contains("PAYLOADSECRET"), "{shown}");
    assert_eq!(error.to_string(), "delivering the chunk to the sink failed");

    let sink_error = SinkError::new("PAYLOADSECRET");
    assert_eq!(sink_error.to_string(), "sink write failed");
    assert_eq!(format!("{sink_error:?}"), "SinkError");
    assert_eq!(
        sink_error.source().map(ToString::to_string).as_deref(),
        Some("PAYLOADSECRET")
    );
}
