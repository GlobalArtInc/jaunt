use std::time::{Duration, Instant};

use jaunt_record::{Assembler, Limits, Recorder, RecorderConfig, SessionKind};
use jaunt_ssh::{ChannelExit, Recording, SessionObserver};

use super::super::session::GAP_ALLOWANCE_BYTES;
use super::super::upload::{FLUSH_INTERVAL, Next, RETRY_WINDOW, backoff, classify, honored};
use super::super::{DISABLED_FOR, RecordingLimits, SHUTDOWN_GRACE};
use super::{
    Bench, LOGIN, NODE, Seen, Step, StepClock, USER, VecSink, limits, out, parse_cast, shell, start,
};
use crate::clock::unix_secs;
use crate::run::api::ApiError;
use crate::testkit::eventually;

const SECOND: Duration = Duration::from_secs(1);

pub(super) fn text(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b' ' + u8::try_from(state % 95).unwrap()
        })
        .collect()
}

fn status(status: u16, code: &str, retry_after: Option<u64>) -> ApiError {
    ApiError::Status {
        status,
        code: code.to_owned(),
        retry_after: retry_after.map(Duration::from_secs),
    }
}

pub(super) fn chunk_requests(bench: &Bench, session_id: &str) -> Vec<u64> {
    bench
        .server
        .seen()
        .into_iter()
        .filter_map(|seen| match seen {
            Seen::Chunk(id, seq) if id == session_id => Some(seq),
            _ => None,
        })
        .collect()
}

pub(super) fn shell_session(
    bench: &Bench,
    session_id: &str,
    output: &[u8],
) -> Box<dyn SessionObserver> {
    let mut observer = bench.open(session_id, false);
    observer.channel_start(0, &shell(80, 24));
    for piece in output.chunks(16 * 1024) {
        out(&mut *observer, 0, piece);
    }
    observer
}

pub(super) async fn settle(bench: &Bench, session_id: &str) {
    eventually("the upload to end", || {
        bench.recordings.active_uploads() == 0 || bench.server.manifest(session_id).is_some()
    })
    .await;
}

#[test]
fn every_answer_class_has_a_fixed_retry_decision() {
    let cases: [(ApiError, Next); 17] = [
        (ApiError::CallTimeout, Next::Retry(None)),
        (ApiError::ConnectTimeout, Next::Retry(None)),
        (ApiError::BadResponse, Next::Retry(None)),
        (ApiError::Unauthorized, Next::Retry(None)),
        (status(500, "internal", None), Next::Retry(None)),
        (status(503, "", None), Next::Retry(None)),
        (status(403, "forbidden", None), Next::Retry(None)),
        (
            status(429, "too_many_recordings", Some(60)),
            Next::Retry(Some(Duration::from_secs(60))),
        ),
        (
            status(507, "insufficient_storage", Some(5)),
            Next::Retry(Some(Duration::from_secs(5))),
        ),
        (status(422, "bad_chunk", None), Next::Final("bad_chunk")),
        (
            status(413, "recording_too_large", None),
            Next::Final("recording_too_large"),
        ),
        (
            status(409, "recording_closed", None),
            Next::Final("recording_closed"),
        ),
        (
            status(409, "session_not_recordable", None),
            Next::Final("session_not_recordable"),
        ),
        (status(409, "other", None), Next::Final("conflict")),
        (
            status(404, "session_unknown", None),
            Next::Final("session_unknown"),
        ),
        (status(404, "recording_disabled", None), Next::Disabled),
        (ApiError::NodeRemoved, Next::Final("node_removed")),
    ];
    for (error, expected) in cases {
        assert_eq!(classify(&error), expected, "{error}");
    }
    assert_eq!(classify(&ApiError::Shutdown), Next::Stop);
    assert_eq!(backoff(0, 1.0), SECOND);
    assert_eq!(backoff(0, 0.0), SECOND / 2);
    assert_eq!(backoff(3, 1.0), 8 * SECOND);
    assert_eq!(backoff(40, 1.0), 60 * SECOND);
    assert_eq!(backoff(40, f64::NAN), 60 * SECOND);
    assert_eq!(honored(Duration::ZERO), SECOND);
    assert_eq!(
        honored(Duration::from_secs(86_400)),
        Duration::from_secs(3600)
    );
    assert_eq!(DISABLED_FOR, Duration::from_secs(600));
    assert_eq!(SHUTDOWN_GRACE, Duration::from_secs(10));
    assert_eq!(RETRY_WINDOW, Duration::from_secs(86_400));
    assert_eq!(FLUSH_INTERVAL, Duration::from_secs(5));
    assert_eq!(GAP_ALLOWANCE_BYTES, 16 * 1024 * 1024);
}

#[tokio::test]
async fn retry_after_and_backoff_schedule_the_next_attempt_on_the_injected_clock() {
    let bench = Bench::new(limits());
    bench.server.script_chunks(&[
        Step::Refuse(429, "too_many_recordings", Some(7)),
        Step::Network,
    ]);
    let mut observer = shell_session(&bench, "retry-1", b"hello");
    observer.channel_end(0, &ChannelExit::Status(0));
    observer.finish();

    bench.clock.wait_for_sleeper(start() + 5 * SECOND).await;
    bench.clock.advance(5 * SECOND);
    bench.clock.wait_for_sleeper(start() + 7 * SECOND).await;
    assert_eq!(chunk_requests(&bench, "retry-1"), [0]);
    bench.clock.advance(2 * SECOND);
    bench.clock.wait_for_sleeper(start() + 9 * SECOND).await;
    assert_eq!(chunk_requests(&bench, "retry-1"), [0, 0]);
    bench.clock.advance(2 * SECOND);
    eventually("the recording to be stored", || {
        bench.server.manifest("retry-1").is_some()
    })
    .await;
    assert_eq!(chunk_requests(&bench, "retry-1"), [0, 0, 0]);
}

#[tokio::test]
async fn a_final_refusal_drops_the_recording_and_frees_its_memory_without_retrying() {
    for (code_status, code) in [
        (422, "bad_chunk"),
        (413, "recording_too_large"),
        (409, "recording_closed"),
        (409, "conflict"),
        (409, "session_not_recordable"),
        (404, "session_unknown"),
    ] {
        let bench = Bench::new(limits());
        bench
            .server
            .script_chunks(&[Step::Refuse(code_status, code, None)]);
        let mut observer = shell_session(&bench, "final-1", &text(1, 100_000));
        eventually("the refusal", || bench.recordings.active_uploads() == 0).await;
        assert_eq!(bench.recordings.memory_in_use(), 0, "{code}");
        out(&mut *observer, 0, &text(2, 200_000));
        assert_eq!(observer.finish(), Recording::Incomplete, "{code}");
        assert_eq!(chunk_requests(&bench, "final-1"), [0], "{code}");
        assert!(
            !bench
                .server
                .seen()
                .contains(&Seen::Complete("final-1".to_owned()))
        );
        assert_eq!(bench.recordings.memory_in_use(), 0, "{code}");
    }
}

#[tokio::test]
async fn recording_disabled_pauses_every_upload_for_ten_minutes_then_probes_again() {
    let bench = Bench::new(limits());
    bench
        .server
        .script_chunks(&[Step::Refuse(404, "recording_disabled", None)]);
    let mut waiting = shell_session(&bench, "disabled-live", b"queued but never sent");
    let mut first = shell_session(&bench, "disabled-1", &text(3, 100_000));
    eventually("both uploads to stop", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(first.finish(), Recording::Incomplete);
    assert_eq!(waiting.finish(), Recording::Incomplete);
    assert_eq!(bench.recordings.memory_in_use(), 0);

    let mut paused = shell_session(&bench, "disabled-2", b"not recorded");
    assert_eq!(bench.recordings.active_uploads(), 0);
    assert_eq!(paused.finish(), Recording::Incomplete);

    bench.clock.advance(DISABLED_FOR);
    let mut probe = shell_session(&bench, "disabled-3", b"recorded again");
    probe.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(probe.finish(), Recording::Complete);
    settle(&bench, "disabled-3").await;
    assert!(bench.server.manifest("disabled-3").is_some());
    assert_eq!(chunk_requests(&bench, "disabled-live"), Vec::<u64>::new());
    assert_eq!(chunk_requests(&bench, "disabled-2"), Vec::<u64>::new());
}

#[tokio::test]
async fn acks_release_only_what_was_sent_even_when_the_server_claims_more() {
    let bench = Bench::new(limits());
    bench.server.always(Some(Step::Ack(Some(1_000_000))));
    let mut observer = shell_session(&bench, "ack-1", &text(4, 400_000));
    observer.channel_end(0, &ChannelExit::Status(0));
    observer.finish();
    settle(&bench, "ack-1").await;

    let manifest = bench.server.manifest("ack-1").unwrap();
    assert!(manifest.chunks >= 4);
    assert!(!manifest.incomplete);
    let expected: Vec<u64> = (0..manifest.chunks).collect();
    assert_eq!(chunk_requests(&bench, "ack-1"), expected);
}

fn local_cast(output: &[u8]) -> Vec<u8> {
    let mut recorder = Recorder::new(
        RecorderConfig {
            session_id: "resume-1".to_owned(),
            kind: SessionKind::Shell,
            node: NODE.to_owned(),
            user: USER.to_owned(),
            login: LOGIN.to_owned(),
            command: None,
            started_at: u64::try_from(unix_secs(start())).unwrap(),
            width: 80,
            height: 24,
            shell: String::new(),
            term: "xterm-256color".to_owned(),
            record_input: false,
        },
        Box::new(StepClock::default()),
    )
    .unwrap();
    recorder.marker("channel 0 shell start").unwrap();
    for piece in output.chunks(16 * 1024) {
        recorder.push_output(piece).unwrap();
    }
    recorder.marker("channel 0 exit 0").unwrap();
    let manifest = recorder.finish(Some(0), 0).unwrap();
    let mut assembler = Assembler::new("resume-1", Limits::default());
    let mut sink = VecSink::default();
    for chunk in recorder.take_chunks() {
        assembler.accept(&chunk, &mut sink).unwrap();
    }
    assembler.complete(&manifest, true, &mut sink).unwrap();
    sink.0
}

#[tokio::test]
async fn a_lost_connection_resumes_and_the_server_keeps_the_exact_local_cast() {
    let bench = Bench::new(limits());
    bench.server.script_chunks(&[
        Step::Ack(None),
        Step::Network,
        Step::Network,
        Step::LostReply,
        Step::Ack(None),
        Step::Network,
    ]);
    bench
        .server
        .script_complete(&[Step::Network, Step::LostReply]);
    let output = text(5, 300_000);
    let mut observer = shell_session(&bench, "resume-1", &output);
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Complete);

    let deadline = Instant::now() + Duration::from_secs(30);
    while bench.server.manifest("resume-1").is_none() {
        assert!(Instant::now() < deadline, "the upload never resumed");
        bench.clock.advance(61 * SECOND);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    settle(&bench, "resume-1").await;
    let stored = bench.server.cast("resume-1");
    assert_eq!(stored, local_cast(&output));
    parse_cast(&stored).unwrap();
    assert!(!bench.server.manifest("resume-1").unwrap().incomplete);
    eventually("the uploader to end", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(bench.recordings.memory_in_use(), 0);
}

#[tokio::test]
async fn full_queues_and_an_exhausted_budget_make_the_recording_incomplete() {
    let mib = 1024 * 1024;
    for (queue, budget) in [(mib, 64 * mib), (64 * mib, mib)] {
        let bench = Bench::new(RecordingLimits {
            session_queue_bytes: queue,
            memory_budget_bytes: budget,
            max_uploads: 4,
        });
        bench.server.always(Some(Step::Network));
        let mut observer = shell_session(&bench, "full-1", &text(6, 6 * mib));
        observer.channel_end(0, &ChannelExit::Status(0));
        assert!(bench.recordings.memory_in_use() <= mib);
        assert_eq!(observer.finish(), Recording::Incomplete);

        bench.server.always(None);
        let deadline = Instant::now() + Duration::from_secs(30);
        while bench.server.manifest("full-1").is_none() {
            assert!(Instant::now() < deadline, "the upload never finished");
            bench.clock.advance(61 * SECOND);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let manifest = bench.server.manifest("full-1").unwrap();
        assert!(manifest.incomplete);
        assert!(manifest.dropped_chunks > 0);
        parse_cast(&bench.server.cast("full-1")).unwrap();
        eventually("the uploader to end", || {
            bench.recordings.active_uploads() == 0
        })
        .await;
        assert_eq!(bench.recordings.memory_in_use(), 0);
    }
}
