use jaunt_record::{Assembler, Chunk, ChunkQueue, Limits, Pushed};
use rand::RngExt;

use crate::common::{VecSink, drive, parse_cast, recorder, seeded};

const SESSION_BYTES: usize = 50 * 1024 * 1024;

#[test]
fn fifty_mib_session_round_trips_through_queue_reorder_and_assembler() {
    let (mut recorder, clock) = recorder(false);
    let mut rng = seeded(2024);
    let mut queue = ChunkQueue::new(usize::MAX);
    let mut sent: Vec<Chunk> = Vec::new();
    let mut output = Vec::with_capacity(SESSION_BYTES + 200_000);

    while output.len() < SESSION_BYTES {
        let step = drive(&mut recorder, &clock, &mut rng, 1_000_000);
        output.extend_from_slice(&step.output);
        for chunk in recorder.take_chunks() {
            sent.push(chunk.clone());
            assert_eq!(queue.push(chunk), Pushed::Pushed);
        }
    }
    let manifest = recorder.finish(Some(0), 1_700_000_100).unwrap();
    for chunk in recorder.take_chunks() {
        sent.push(chunk.clone());
        assert_eq!(queue.push(chunk), Pushed::Pushed);
    }

    let mut delivered: Vec<Chunk> = Vec::new();
    while let Some(chunk) = queue.peek() {
        delivered.push(chunk.clone());
        let seq = chunk.seq;
        queue.ack(seq);
    }
    assert_eq!(delivered, sent);

    for index in (1..delivered.len()).rev() {
        delivered.swap(index, rng.random_range(0..=index));
    }
    let mut assembler = Assembler::new("sess-1", Limits::default());
    let mut sink = VecSink::default();
    for chunk in delivered.iter().chain(sent.iter().step_by(5)) {
        assembler.accept(chunk, &mut sink).unwrap();
    }
    let verified = assembler.complete(&manifest, true, &mut sink).unwrap();
    assert_eq!(verified.received_chunks, sent.len() as u64);
    assert_eq!(sink.seqs(), (0..sent.len() as u64).collect::<Vec<_>>());

    let cast = sink.bytes();
    assert_eq!(cast.len() as u64, manifest.raw_bytes);
    let parsed = parse_cast(&cast).unwrap();
    let text: String = parsed
        .events
        .iter()
        .filter(|event| event.kind == "o")
        .map(|event| event.data.as_str())
        .collect();
    assert_eq!(text, String::from_utf8_lossy(&output));
    assert_eq!(manifest.bytes_out, output.len() as u64);
}
