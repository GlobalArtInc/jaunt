use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::Sig;
use tokio::sync::mpsc;

use super::{ExitSignal, OutputError, OutputEvent, OutputQueue, OutputReader};
use crate::bridge::signal_text;
use crate::intake::{SessionGone, WindowGrant};
use crate::observer::OutputStream::{Stderr, Stdout};

#[derive(Clone, Default)]
struct Grants {
    log: Arc<Mutex<Vec<u32>>>,
    gone: Arc<AtomicBool>,
}

impl Grants {
    fn granted(&self) -> Vec<u32> {
        self.log.lock().unwrap().clone()
    }
}

impl WindowGrant for Grants {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone> {
        if self.gone.load(Ordering::SeqCst) {
            return Err(SessionGone);
        }
        self.log.lock().unwrap().push(bytes);
        Ok(())
    }
}

const STEP: Duration = Duration::from_secs(10);

async fn next(reader: &mut OutputReader) -> Option<OutputEvent> {
    tokio::time::timeout(STEP, reader.next())
        .await
        .expect("the output reader hung")
}

fn describe(event: Option<OutputEvent>) -> String {
    match event {
        Some(OutputEvent::Stdout(bytes)) => format!("out:{}", String::from_utf8_lossy(&bytes)),
        Some(OutputEvent::Stderr(bytes)) => format!("err:{}", String::from_utf8_lossy(&bytes)),
        Some(OutputEvent::Eof) => "eof".to_owned(),
        Some(OutputEvent::ExitStatus(status)) => format!("exit:{status}"),
        Some(OutputEvent::ExitSignal(signal)) => format!("signal:{}", signal_text(&signal.name)),
        Some(OutputEvent::Close) => "close".to_owned(),
        Some(OutputEvent::Gone) => "gone".to_owned(),
        None => "end".to_owned(),
    }
}

async fn drain(reader: &mut OutputReader) -> Vec<String> {
    let mut seen = Vec::new();
    loop {
        let event = next(reader).await;
        let done = event.is_none();
        seen.push(describe(event));
        if done {
            return seen;
        }
    }
}

fn term() -> ExitSignal {
    ExitSignal {
        name: Sig::TERM,
        core_dumped: false,
        message: String::new(),
        lang: String::new(),
    }
}

async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + STEP;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn streams_interleave_in_order_and_adjacent_chunks_of_one_stream_merge() {
    let (queue, mut reader) = OutputQueue::new(1024, Grants::default());
    for (stream, data) in [
        (Stdout, "a"),
        (Stdout, "b"),
        (Stderr, "c"),
        (Stdout, ""),
        (Stderr, "d"),
        (Stdout, "e"),
    ] {
        queue.push_data(stream, data.as_bytes()).unwrap();
    }
    queue.push_eof();
    queue.push_exit_status(0);
    queue.push_close();
    assert_eq!(
        drain(&mut reader).await,
        ["out:ab", "err:cd", "out:e", "eof", "exit:0", "close", "end"]
    );
}

#[tokio::test]
async fn markers_come_out_at_the_offset_they_arrived_at() {
    let (queue, mut reader) = OutputQueue::new(1024, Grants::default());
    queue.push_data(Stdout, b"ab").unwrap();
    queue.push_exit_status(3);
    queue.push_data(Stdout, b"cd").unwrap();
    queue.push_data(Stderr, b"x").unwrap();
    queue.push_eof();
    queue.push_close();
    assert_eq!(
        drain(&mut reader).await,
        ["out:ab", "exit:3", "out:cd", "err:x", "eof", "close", "end"]
    );
}

#[tokio::test]
async fn only_the_first_exit_and_eof_count_and_nothing_follows_the_end() {
    let (queue, mut reader) = OutputQueue::new(1024, Grants::default());
    queue.push_exit_signal(term());
    queue.push_exit_status(1);
    queue.push_eof();
    queue.push_eof();
    queue.push_gone();
    queue.push_close();
    queue.push_eof();
    assert_eq!(
        queue.push_data(Stdout, b"late"),
        Err(OutputError::DataAfterClose)
    );
    assert_eq!(queue.discard_extended(4), Err(OutputError::DataAfterClose));
    assert_eq!(
        drain(&mut reader).await,
        ["eof", "signal:TERM", "gone", "end"]
    );
}

#[tokio::test]
async fn data_is_handed_out_in_bounded_chunks() {
    let (queue, mut reader) = OutputQueue::new(256 * 1024, Grants::default());
    queue.push_data(Stdout, &vec![7; 100 * 1024]).unwrap();
    queue.push_data(Stderr, &[8; 10]).unwrap();
    let sizes: Vec<_> = [
        next(&mut reader).await,
        next(&mut reader).await,
        next(&mut reader).await,
    ]
    .into_iter()
    .map(|event| match event {
        Some(OutputEvent::Stdout(bytes)) => ("out", bytes.len()),
        Some(OutputEvent::Stderr(bytes)) => ("err", bytes.len()),
        other => panic!("expected data, got {other:?}"),
    })
    .collect();
    assert_eq!(sizes, [("out", 64 * 1024), ("out", 36 * 1024), ("err", 10)]);
}

#[tokio::test]
async fn sshd_cannot_send_past_the_window_and_gets_it_back_only_after_consumption() {
    let grants = Grants::default();
    let (queue, mut reader) = OutputQueue::new(1000, grants.clone());
    queue.push_data(Stdout, &[1; 600]).unwrap();
    assert_eq!(
        queue.push_data(Stderr, &[1; 401]),
        Err(OutputError::WindowOverrun)
    );
    queue.push_data(Stderr, &[1; 400]).unwrap();
    assert!(
        matches!(next(&mut reader).await, Some(OutputEvent::Stdout(bytes)) if bytes.len() == 600)
    );
    assert!(
        matches!(next(&mut reader).await, Some(OutputEvent::Stderr(bytes)) if bytes.len() == 400)
    );
    assert!(grants.granted().is_empty());
    assert_eq!(
        queue.push_data(Stdout, &[1]),
        Err(OutputError::WindowOverrun)
    );
    reader.consumed(249).unwrap();
    assert!(grants.granted().is_empty());
    reader.consumed(1).unwrap();
    assert_eq!(grants.granted(), [250]);
    queue.push_data(Stdout, &[1; 250]).unwrap();
    assert_eq!(
        queue.push_data(Stdout, &[1]),
        Err(OutputError::WindowOverrun)
    );
    reader.consumed(5000).unwrap();
    assert_eq!(grants.granted(), [250, 750]);
    assert!(
        matches!(next(&mut reader).await, Some(OutputEvent::Stdout(bytes)) if bytes.len() == 250)
    );
    reader.consumed(10).unwrap();
    let waiting = tokio::spawn(async move {
        let event = next(&mut reader).await;
        (reader, event)
    });
    until("idle flush", || grants.granted() == [250, 750, 10]).await;
    queue.push_close();
    let (_, event) = tokio::time::timeout(STEP, waiting)
        .await
        .expect("the output reader hung")
        .unwrap();
    assert!(matches!(event, Some(OutputEvent::Close)));
}

#[tokio::test]
async fn single_bytes_alternating_between_streams_stay_ordered_within_the_memory_bound() {
    let window: u32 = 64 * 1024;
    let (queue, mut reader) = OutputQueue::new(window, Grants::default());
    let byte = |index: u32| u8::try_from(index % 251).unwrap();
    let stream = |index: u32| {
        if index.is_multiple_of(3) {
            Stderr
        } else {
            Stdout
        }
    };
    for index in 0..window {
        queue.push_data(stream(index), &[byte(index)]).unwrap();
    }
    assert_eq!(
        queue.push_data(Stdout, &[0]),
        Err(OutputError::WindowOverrun)
    );
    assert_eq!(reader.footprint(), (window as usize, window as usize / 64));
    queue.push_close();
    let mut index = 0;
    loop {
        let (expected, data) = match next(&mut reader).await {
            Some(OutputEvent::Stdout(data)) => (Stdout, data),
            Some(OutputEvent::Stderr(data)) => (Stderr, data),
            Some(OutputEvent::Close) => break,
            other => panic!("unexpected {other:?} at byte {index}"),
        };
        for value in data.iter() {
            assert_eq!(
                (stream(index), byte(index)),
                (expected, *value),
                "byte {index}"
            );
            index += 1;
        }
    }
    assert_eq!(index, window);
}

#[tokio::test]
async fn other_extended_data_is_dropped_and_its_window_comes_back_at_once() {
    let grants = Grants::default();
    let (queue, _reader) = OutputQueue::new(1000, grants.clone());
    queue.push_data(Stdout, &[0; 900]).unwrap();
    queue.discard_extended(100).unwrap();
    assert_eq!(grants.granted(), [100]);
    assert_eq!(queue.discard_extended(101), Err(OutputError::WindowOverrun));
    queue.discard_extended(0).unwrap();
    assert_eq!(grants.granted(), [100]);
    grants.gone.store(true, Ordering::SeqCst);
    assert_eq!(queue.discard_extended(1), Err(OutputError::SessionGone));
}

#[tokio::test]
async fn a_dropped_writer_or_a_gone_session_ends_the_reader() {
    let (queue, mut reader) = OutputQueue::new(1024, Grants::default());
    queue.push_data(Stdout, b"tail").unwrap();
    drop(queue);
    assert_eq!(drain(&mut reader).await, ["out:tail", "end"]);

    let grants = Grants::default();
    let (queue, mut reader) = OutputQueue::new(1000, grants.clone());
    queue.push_data(Stdout, &[0; 10]).unwrap();
    assert!(next(&mut reader).await.is_some());
    grants.gone.store(true, Ordering::SeqCst);
    reader.consumed(10).unwrap();
    assert!(next(&mut reader).await.is_none());
}

#[tokio::test]
async fn an_eof_repeated_after_delivery_is_still_ignored() {
    let (queue, mut reader) = OutputQueue::new(1024, Grants::default());
    queue.push_eof();
    assert_eq!(describe(next(&mut reader).await), "eof");
    queue.push_eof();
    queue.push_close();
    assert_eq!(drain(&mut reader).await, ["close", "end"]);
}

struct Refills(mpsc::UnboundedSender<u32>);

impl WindowGrant for Refills {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone> {
        self.0.send(bytes).map_err(|_| SessionGone)
    }
}

#[tokio::test]
async fn the_buffers_keep_their_size_while_sshd_refills_what_the_user_consumed() {
    let window: u32 = 4096;
    let total: u32 = 512 * 1024;
    let (refills, mut granted) = mpsc::unbounded_channel();
    let (queue, mut reader) = OutputQueue::new(window, Refills(refills));
    let footprint = reader.footprint();
    assert_eq!(footprint, (4096, 64));
    let piece = |index: u32| -> (crate::observer::OutputStream, Vec<u8>) {
        let len = 1 + (index * 37) % 700;
        let stream = if (index / 3).is_multiple_of(2) {
            Stdout
        } else {
            Stderr
        };
        (
            stream,
            (0..len)
                .map(|n| u8::try_from((index + n) % 251).unwrap())
                .collect(),
        )
    };
    let sshd = tokio::spawn(async move {
        let mut credit = window;
        let mut sent = Vec::new();
        let mut index = 0;
        while sent.len() < total as usize {
            let (stream, data) = piece(index);
            let len = u32::try_from(data.len()).unwrap();
            while credit < len {
                credit += granted.recv().await.expect("the reader went away");
            }
            queue.push_data(stream, &data).unwrap();
            credit -= len;
            sent.extend(data.iter().map(|byte| (stream, *byte)));
            index += 1;
        }
        queue.push_close();
        (sent, granted)
    });
    let mut received = Vec::new();
    let mut reads = 0usize;
    loop {
        let (stream, data) = match next(&mut reader).await {
            Some(OutputEvent::Stdout(data)) => (Stdout, data),
            Some(OutputEvent::Stderr(data)) => (Stderr, data),
            Some(OutputEvent::Close) => break,
            other => panic!("unexpected {other:?}"),
        };
        received.extend(data.iter().map(|byte| (stream, *byte)));
        reads += 1;
        let partial = if reads.is_multiple_of(2) {
            data.len()
        } else {
            data.len() / 2
        };
        reader.consumed(partial).unwrap();
        reader.consumed(data.len() - partial).unwrap();
        assert_eq!(reader.footprint(), footprint);
    }
    let (sent, _granted) = tokio::time::timeout(STEP, sshd)
        .await
        .expect("sshd hung")
        .unwrap();
    assert_eq!(received.len(), sent.len());
    assert!(received == sent, "the byte or stream order changed");
    assert!(reads > (total / window) as usize);
}
