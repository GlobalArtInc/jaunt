use jaunt_record::{
    AckError, Chunk, ChunkQueue, DEFAULT_QUEUE_MAX_BYTES, Pushed, Recorder, SessionKind,
};

fn chunk(seq: u64, size: usize, is_last: bool) -> Chunk {
    Chunk {
        session_id: "sess-1".to_owned(),
        seq,
        raw_len: 0,
        compressed: vec![0; size],
        sha256: String::new(),
        is_last,
    }
}

fn manifest() -> jaunt_record::SessionManifest {
    Recorder::metadata_only(jaunt_record::MetadataOnly {
        session_id: "sess-1".to_owned(),
        kind: SessionKind::Exec,
        node: "n".to_owned(),
        user: "u".to_owned(),
        login: "l".to_owned(),
        command: None,
        started_at: 0,
        ended_at: None,
        exit_status: None,
        bytes_out: 0,
        bytes_in: 0,
    })
    .unwrap()
}

#[test]
fn drops_new_chunks_when_full_and_keeps_the_oldest() {
    let mut queue = ChunkQueue::new(10);
    assert_eq!(queue.push(chunk(0, 4, false)), Pushed::Pushed);
    assert_eq!(queue.push(chunk(1, 4, false)), Pushed::Pushed);
    assert_eq!(queue.push(chunk(2, 4, false)), Pushed::Dropped);
    assert_eq!(queue.pending_bytes(), 8);
    assert_eq!(queue.len(), 2);
    assert_eq!(queue.dropped(), 1);
    assert!(queue.incomplete());
    assert_eq!(queue.peek().map(|c| c.seq), Some(0));
}

#[test]
fn a_chunk_larger_than_the_whole_queue_is_dropped() {
    let mut queue = ChunkQueue::new(10);
    assert_eq!(queue.push(chunk(0, 11, false)), Pushed::Dropped);
    assert!(queue.is_empty());
}

#[test]
fn incomplete_stays_set_after_the_queue_drains() {
    let mut queue = ChunkQueue::new(4);
    queue.push(chunk(0, 4, false));
    queue.push(chunk(1, 4, false));
    assert_eq!(queue.ack(0), 1);
    assert_eq!(queue.push(chunk(2, 4, false)), Pushed::Pushed);
    assert!(queue.incomplete());
    assert_eq!(queue.dropped(), 1);
}

#[test]
fn ack_removes_everything_up_to_and_including_seq_and_order_is_kept() {
    let mut queue = ChunkQueue::new(100);
    for seq in 0..5 {
        queue.push(chunk(seq, 10, false));
    }
    assert_eq!(queue.ack(1), 2);
    assert_eq!(queue.pending_bytes(), 30);
    assert_eq!(queue.ack(1), 0);
    assert_eq!(queue.peek().map(|c| c.seq), Some(2));
    assert_eq!(queue.peek().map(|c| c.seq), Some(2));
    assert_eq!(queue.ack(0), 0);
    assert_eq!(queue.ack(4), 3);
    assert!(queue.is_empty());
    assert_eq!(queue.pending_bytes(), 0);
    assert!(!queue.incomplete());
}

#[test]
fn unchecked_ack_above_everything_queued_clears_the_whole_queue() {
    let mut queue = ChunkQueue::new(100);
    for seq in 0..3 {
        queue.push(chunk(seq, 10, false));
    }
    assert_eq!(queue.ack(100), 3);
    assert!(queue.is_empty());
}

#[test]
fn checked_ack_rejects_a_seq_above_the_highest_queued_chunk() {
    let mut queue = ChunkQueue::new(100);
    assert_eq!(queue.ack_checked(0), Err(AckError::AboveHighest { seq: 0 }));
    for seq in 0..3 {
        queue.push(chunk(seq, 10, false));
    }
    assert_eq!(queue.ack_checked(3), Err(AckError::AboveHighest { seq: 3 }));
    assert_eq!(queue.len(), 3);
    assert_eq!(queue.ack_checked(1), Ok(2));
    assert_eq!(queue.ack_checked(1), Ok(0));
    assert_eq!(queue.ack_checked(2), Ok(1));
    assert_eq!(queue.ack_checked(2), Ok(0));
    assert_eq!(queue.ack_checked(3), Err(AckError::AboveHighest { seq: 3 }));
}

#[test]
fn a_dropped_last_chunk_is_counted_and_marks_the_manifest() {
    let mut queue = ChunkQueue::new(8);
    queue.push(chunk(0, 8, false));
    assert_eq!(queue.push(chunk(1, 1, true)), Pushed::Dropped);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.dropped(), 1);
    let mut manifest = manifest();
    queue.mark_manifest(&mut manifest);
    assert!(manifest.incomplete);
    assert_eq!(manifest.dropped_chunks, 1);

    let clean = ChunkQueue::default();
    let mut untouched = self::manifest();
    clean.mark_manifest(&mut untouched);
    assert!(!untouched.incomplete);
    assert_eq!(untouched.dropped_chunks, 0);
}

#[test]
fn default_capacity_is_64_mib() {
    assert_eq!(DEFAULT_QUEUE_MAX_BYTES, 64 * 1024 * 1024);
    let mut queue = ChunkQueue::default();
    assert_eq!(
        queue.push(chunk(0, DEFAULT_QUEUE_MAX_BYTES, false)),
        Pushed::Pushed
    );
    assert_eq!(queue.push(chunk(1, 1, false)), Pushed::Dropped);
}
