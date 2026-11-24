use jaunt_record::{Accepted, AssembleError, Assembler, Chunk, Limits, SessionManifest};
use rand::RngExt;

use crate::common::{
    VecSink, accept_all, assembler, cast_of, drive, finish_cast, forged, forged_from_compressed,
    recorder, seeded, three_chunk_session,
};

fn session(seed: u64, bytes: usize) -> (Vec<Chunk>, SessionManifest) {
    let (mut recorder, clock) = recorder(false);
    let mut rng = seeded(seed);
    drive(&mut recorder, &clock, &mut rng, bytes);
    let (_, manifest, chunks) = finish_cast(recorder);
    (chunks, manifest)
}

fn rle_bomb(blocks: usize) -> Vec<u8> {
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38];
    for index in 0..blocks {
        let last = u32::from(index + 1 == blocks);
        let header = (131_072_u32 << 3) | (1 << 1) | last;
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(0);
    }
    frame
}

#[test]
fn shuffled_chunks_with_duplicates_reproduce_the_cast_exactly() {
    let (chunks, manifest) = session(11, 2_000_000);
    assert!(chunks.len() > 10);
    let mut rng = seeded(12);
    let mut arrivals: Vec<&Chunk> = chunks.iter().chain(chunks.iter().step_by(3)).collect();
    for index in (1..arrivals.len()).rev() {
        arrivals.swap(index, rng.random_range(0..=index));
    }
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    let mut duplicates = 0;
    for chunk in arrivals {
        if assembler.accept(chunk, &mut sink).unwrap() == Accepted::Duplicate {
            duplicates += 1;
        }
    }
    assert_eq!(duplicates, chunks.len().div_ceil(3));
    let verified = assembler.complete(&manifest, true, &mut sink).unwrap();
    assert_eq!(sink.bytes(), cast_of(&chunks));
    assert_eq!(sink.seqs(), (0..chunks.len() as u64).collect::<Vec<_>>());
    assert_eq!(verified.received_chunks, chunks.len() as u64);
    assert_eq!(verified.missing_chunks, 0);
    assert_eq!(verified.digest, manifest.digest);
    assert!(!verified.incomplete);
}

#[test]
fn sink_only_sees_the_contiguous_prefix_in_order() {
    let (chunks, manifest) = three_chunk_session();
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    assembler.accept(&chunks[2], &mut sink).unwrap();
    assert!(sink.written.is_empty());
    assembler.accept(&chunks[0], &mut sink).unwrap();
    assert_eq!(sink.seqs(), [0]);
    assembler.accept(&chunks[1], &mut sink).unwrap();
    assert_eq!(sink.seqs(), [0, 1, 2]);
    assembler.complete(&manifest, true, &mut sink).unwrap();
}

#[test]
fn the_sink_is_called_before_complete_verifies_the_manifest() {
    let (chunks, mut manifest) = three_chunk_session();
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    accept_all(&mut assembler, &chunks, &mut sink);
    assert_eq!(sink.seqs(), [0, 1, 2]);
    manifest.digest = Some("0".repeat(64));
    assert!(assembler.complete(&manifest, true, &mut sink).is_err());
    assert_eq!(sink.seqs(), [0, 1, 2]);
}

#[test]
fn a_flipped_bit_is_rejected_and_the_good_chunk_is_still_accepted() {
    let (chunks, _) = three_chunk_session();
    let mut tampered = chunks[0].clone();
    tampered.compressed[0] ^= 0x01;
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    assert_eq!(
        assembler.accept(&tampered, &mut sink),
        Err(AssembleError::ChecksumMismatch)
    );
    assert_eq!(assembler.accept(&chunks[0], &mut sink), Ok(Accepted::New));
}

#[test]
fn a_wrong_raw_len_is_rejected() {
    let honest = forged(0, b"some terminal output", false);
    for declared in [honest.raw_len - 1, honest.raw_len + 1, 0] {
        let mut chunk = honest.clone();
        chunk.raw_len = declared;
        assert_eq!(
            assembler(Limits::default()).accept(&chunk, &mut VecSink::default()),
            Err(AssembleError::RawLenMismatch),
            "declared {declared}"
        );
    }
}

#[test]
fn a_small_frame_that_expands_to_a_gibibyte_is_rejected_at_the_limit() {
    let bomb = rle_bomb(8192);
    assert!(bomb.len() < 64 * 1024);
    let small = rle_bomb(4);
    assert_eq!(
        zstd::stream::decode_all(&small[..]).unwrap(),
        vec![0_u8; 4 * 131_072]
    );
    let mut sink = VecSink::default();
    let mut assembler = assembler(Limits::default());
    for declared in [4096, 8 * 1024 * 1024] {
        let chunk = forged_from_compressed(0, declared, bomb.clone(), false);
        assert_eq!(
            assembler.accept(&chunk, &mut sink),
            Err(AssembleError::RawLenMismatch),
            "declared {declared}"
        );
    }
    let honest = forged_from_compressed(0, 1 << 30, bomb.clone(), false);
    assert_eq!(
        assembler.accept(&honest, &mut sink),
        Err(AssembleError::RawTooLarge)
    );
    let tight = Limits {
        max_chunk_raw: 1024 * 1024,
        ..Limits::default()
    };
    let at_limit = forged_from_compressed(0, 1024 * 1024, bomb, false);
    assert_eq!(
        self::assembler(tight).accept(&at_limit, &mut sink),
        Err(AssembleError::RawLenMismatch)
    );
    assert!(sink.written.is_empty());
}

#[test]
fn a_differing_duplicate_is_a_conflict_and_an_equal_one_is_ignored() {
    let mut assembler = assembler(Limits::default());
    let mut sink = VecSink::default();
    let first = forged(0, b"first", false);
    assert_eq!(assembler.accept(&first, &mut sink), Ok(Accepted::New));
    assert_eq!(assembler.accept(&first, &mut sink), Ok(Accepted::Duplicate));
    assert_eq!(
        assembler.accept(&forged(0, b"other", false), &mut sink),
        Err(AssembleError::Conflict { seq: 0 })
    );
    let mut relabeled = first.clone();
    relabeled.is_last = true;
    assert_eq!(
        assembler.accept(&relabeled, &mut sink),
        Err(AssembleError::Conflict { seq: 0 })
    );
    let mut longer = first.clone();
    longer.raw_len += 1;
    assert_eq!(
        assembler.accept(&longer, &mut sink),
        Err(AssembleError::Conflict { seq: 0 })
    );
    assert_eq!(sink.seqs(), [0]);
}

#[test]
fn the_expected_session_is_pinned_from_the_first_chunk() {
    let (chunks, _) = three_chunk_session();
    let mut sink = VecSink::default();
    let mut pinned = Assembler::new("another-session", Limits::default());
    assert_eq!(
        pinned.accept(&chunks[0], &mut sink),
        Err(AssembleError::SessionMismatch)
    );
    assert!(sink.written.is_empty());

    let mut assembler = assembler(Limits::default());
    assembler.accept(&chunks[0], &mut sink).unwrap();
    let mut foreign = chunks[1].clone();
    foreign.session_id = "other".to_owned();
    assert_eq!(
        assembler.accept(&foreign, &mut sink),
        Err(AssembleError::SessionMismatch)
    );
}

#[test]
fn limits_are_enforced() {
    let defaults = Limits::default();
    let mut sink = VecSink::default();

    let mut one = assembler(Limits {
        max_chunks: 2,
        ..defaults
    });
    assert_eq!(
        one.accept(&forged(2, b"x", false), &mut sink),
        Err(AssembleError::SeqLimit)
    );

    let mut two = assembler(Limits {
        max_total_raw: 200,
        ..defaults
    });
    assert_eq!(
        two.accept(&forged(0, &[b'a'; 100], false), &mut sink),
        Ok(Accepted::New)
    );
    assert_eq!(
        two.accept(&forged(1, &[b'b'; 100], false), &mut sink),
        Ok(Accepted::New)
    );
    assert_eq!(
        two.accept(&forged(2, b"c", false), &mut sink),
        Err(AssembleError::TotalRawLimit)
    );

    let mut three = assembler(Limits {
        max_chunk_raw: 99,
        ..defaults
    });
    assert_eq!(
        three.accept(&forged(0, &[b'a'; 100], false), &mut sink),
        Err(AssembleError::RawTooLarge)
    );
    let mut exact_raw = assembler(Limits {
        max_chunk_raw: 100,
        ..defaults
    });
    assert_eq!(
        exact_raw.accept(&forged(0, &[b'a'; 100], false), &mut sink),
        Ok(Accepted::New)
    );

    let big = forged(0, &[b'a'; 100], false);
    let mut four = assembler(Limits {
        max_chunk_compressed: big.compressed.len() - 1,
        ..defaults
    });
    assert_eq!(
        four.accept(&big, &mut sink),
        Err(AssembleError::CompressedTooLarge)
    );
    let mut exact_compressed = assembler(Limits {
        max_chunk_compressed: big.compressed.len(),
        ..defaults
    });
    assert_eq!(exact_compressed.accept(&big, &mut sink), Ok(Accepted::New));
}

#[test]
fn the_reorder_buffer_limit_is_exact_and_frees_space_after_a_drain() {
    let early = forged(1, &[b'a'; 100], false);
    let mut sink = VecSink::default();
    let mut exact = assembler(Limits {
        max_pending_bytes: early.compressed.len(),
        ..Limits::default()
    });
    assert_eq!(exact.accept(&early, &mut sink), Ok(Accepted::New));

    let mut over = assembler(Limits {
        max_pending_bytes: early.compressed.len() - 1,
        ..Limits::default()
    });
    assert_eq!(
        over.accept(&early, &mut sink),
        Err(AssembleError::PendingLimit)
    );

    let second = forged(2, &[b'b'; 100], false);
    let fourth = forged(4, &[b'c'; 200], false);
    let mut drained = assembler(Limits {
        max_pending_bytes: second.compressed.len() + fourth.compressed.len() - 1,
        ..Limits::default()
    });
    for chunk in [
        &second,
        &forged(0, b"zero", false),
        &forged(1, b"one", false),
    ] {
        assert_eq!(drained.accept(chunk, &mut sink), Ok(Accepted::New));
    }
    assert_eq!(drained.accept(&fourth, &mut sink), Ok(Accepted::New));
}

#[test]
fn last_chunk_markers_must_be_consistent() {
    let mut sink = VecSink::default();

    let mut assembler_a = assembler(Limits::default());
    assembler_a
        .accept(&forged(2, b"x", true), &mut sink)
        .unwrap();
    assert_eq!(
        assembler_a.accept(&forged(5, b"x", false), &mut sink),
        Err(AssembleError::AfterLast { seq: 5 })
    );
    assert_eq!(
        assembler_a.accept(&forged(1, b"x", true), &mut sink),
        Err(AssembleError::ConflictingLast)
    );

    let mut assembler_b = assembler(Limits::default());
    assembler_b
        .accept(&forged(5, b"x", false), &mut sink)
        .unwrap();
    assert_eq!(
        assembler_b.accept(&forged(2, b"x", true), &mut sink),
        Err(AssembleError::LastNotFinal { seq: 2 })
    );
}

#[test]
fn debug_output_of_a_loaded_assembler_holds_no_recorded_bytes() {
    let mut assembler = assembler(Limits::default());
    let chunk = forged(1, b"TOPSECRETDATA TOPSECRETDATA", false);
    assembler.accept(&chunk, &mut VecSink::default()).unwrap();
    let shown = format!("{assembler:?}");
    assert!(shown.contains("reordered_chunks: 1"));
    assert!(!shown.contains("TOPSECRET"));
    assert!(!shown.contains("40, 181"));
    assert!(!format!("{chunk:?}").contains("40, 181"));
}
