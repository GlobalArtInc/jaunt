use std::time::{Duration, Instant};

use jaunt_ssh::{ChannelExit, Recording, SessionObserver};

use super::super::session::{End, GAP_ALLOWANCE_BYTES};
use super::super::{RecordingLimits, SHUTDOWN_GRACE, path_safe};
use super::upload::{chunk_requests, settle, shell_session, text};
use super::{Bench, Seen, Step, limits, out, parse_cast, shell, start};
use crate::testkit::{eventually, soon};

const SECOND: Duration = Duration::from_secs(1);
const HOUR: Duration = Duration::from_secs(3600);
const MIB: usize = 1024 * 1024;

fn sized(queue: usize, budget: usize, uploads: usize) -> RecordingLimits {
    RecordingLimits {
        session_queue_bytes: queue,
        memory_budget_bytes: budget,
        max_uploads: uploads,
    }
}

async fn stored_after_retries(bench: &Bench, session_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while bench.server.manifest(session_id).is_none() {
        assert!(Instant::now() < deadline, "the upload never finished");
        bench.clock.advance(61 * SECOND);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn drained(bench: &Bench) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while bench
        .recordings
        .snapshots()
        .first()
        .is_some_and(|snapshot| snapshot.queued_chunks > 0)
    {
        assert!(Instant::now() < deadline, "the queue never drained");
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn the_final_chunk_is_sent_even_when_the_queue_takes_nothing() {
    let bench = Bench::new(sized(1, 256 * MIB, 4));
    let mut observer = shell_session(&bench, "last-1", &text(20, 300_000));
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Incomplete);
    settle(&bench, "last-1").await;

    let manifest = bench.server.manifest("last-1").unwrap();
    assert!(manifest.incomplete);
    assert!(manifest.chunks >= 5);
    assert_eq!(manifest.dropped_chunks, manifest.chunks - 1);
    assert_eq!(chunk_requests(&bench, "last-1"), [manifest.chunks - 1]);
    let accepted = bench.server.accepted("last-1");
    assert_eq!(accepted.len(), 1);
    assert!(accepted[0].2);
}

#[tokio::test]
async fn the_final_chunk_holds_its_budget_share_until_acknowledged() {
    let bench = Bench::new(limits());
    bench.server.always(Some(Step::Network));
    let mut observer = shell_session(&bench, "held-1", b"short session");
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Complete);
    eventually("the first attempt", || {
        !chunk_requests(&bench, "held-1").is_empty()
    })
    .await;
    assert!(bench.recordings.memory_in_use() > 0);
    bench.server.always(None);
    stored_after_retries(&bench, "held-1").await;
    settle(&bench, "held-1").await;
    eventually("the uploader to end", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(bench.recordings.memory_in_use(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn after_a_gap_at_most_sixteen_mib_more_is_sent_and_the_last_chunk_always_follows() {
    for (queue, budget) in [(MIB, 256 * MIB), (256 * MIB, MIB)] {
        let bench = Bench::new(sized(queue, budget, 4));
        bench.server.always(Some(Step::Network));
        let early = text(8, 3 * MIB);
        let mut observer = shell_session(&bench, "gap-1", &early);
        let opened = bench.recordings.snapshots()[0];
        assert!(opened.queue_dropped + opened.withheld > 0);
        bench.server.always(None);
        bench.clock.advance(2 * SECOND);
        for piece in text(9, 24 * MIB).chunks(64 * 1024) {
            out(&mut *observer, 0, piece);
            drained(&bench).await;
        }
        observer.channel_end(0, &ChannelExit::Status(0));
        assert_eq!(observer.finish(), Recording::Incomplete);
        stored_after_retries(&bench, "gap-1").await;

        let manifest = bench.server.manifest("gap-1").unwrap();
        assert!(manifest.incomplete && manifest.dropped_chunks > 0);
        let accepted = bench.server.accepted("gap-1");
        let gap = (0..)
            .find(|seq| !accepted.iter().any(|(got, _, _)| got == seq))
            .unwrap();
        assert!(gap > 0);
        let beyond: usize = accepted
            .iter()
            .filter(|(seq, _, last)| *seq > gap && !last)
            .map(|(_, len, _)| len)
            .sum();
        assert!(beyond <= GAP_ALLOWANCE_BYTES, "{beyond}");
        assert!(beyond > GAP_ALLOWANCE_BYTES - MIB / 2, "{beyond}");
        assert!(
            accepted
                .iter()
                .any(|(seq, _, last)| *last && *seq + 1 == manifest.chunks)
        );
        let cast = parse_cast(&bench.server.cast("gap-1")).unwrap();
        assert_eq!(cast.markers()[0], "channel 0 shell start");
        assert!(
            cast.joined("o")
                .starts_with(std::str::from_utf8(&early[..1024]).unwrap())
        );
        assert!(cast.markers().contains(&"channel 0 exit 0"));
        eventually("the uploader to end", || {
            bench.recordings.active_uploads() == 0
        })
        .await;
        assert_eq!(bench.recordings.memory_in_use(), 0);
    }
}

#[tokio::test]
async fn an_upload_failing_for_a_day_gives_up_without_spinning() {
    let bench = Bench::new(limits());
    bench.server.always(Some(Step::Network));
    let mut observer = shell_session(&bench, "day-1", &text(10, 100_000));
    eventually("the first attempt", || {
        chunk_requests(&bench, "day-1").len() == 1
    })
    .await;
    for attempt in 2..=24 {
        bench.clock.advance(HOUR);
        eventually("another attempt", || {
            chunk_requests(&bench, "day-1").len() == attempt
        })
        .await;
    }
    assert_eq!(bench.recordings.active_uploads(), 1);
    bench.clock.advance(HOUR);
    eventually("the upload to give up", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(chunk_requests(&bench, "day-1").len(), 24);
    assert_eq!(bench.recordings.memory_in_use(), 0);
    out(&mut *observer, 0, b"after the deadline");
    assert_eq!(observer.finish(), Recording::Incomplete);
}

#[tokio::test]
async fn sessions_beyond_the_uploader_cap_are_not_recorded() {
    let bench = Bench::new(sized(64 * MIB, 256 * MIB, 2));
    let mut first = shell_session(&bench, "cap-1", b"one");
    let mut second = shell_session(&bench, "cap-2", b"two");
    let mut third = shell_session(&bench, "cap-3", b"three");
    assert_eq!(bench.recordings.active_uploads(), 2);
    assert_eq!(third.finish(), Recording::Incomplete);
    for observer in [&mut first, &mut second] {
        observer.channel_end(0, &ChannelExit::Status(0));
        assert_eq!(observer.finish(), Recording::Complete);
    }
    settle(&bench, "cap-1").await;
    settle(&bench, "cap-2").await;
    eventually("the slots to free", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    let mut fourth = shell_session(&bench, "cap-4", b"four");
    fourth.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(fourth.finish(), Recording::Complete);
    settle(&bench, "cap-4").await;
    assert!(bench.server.manifest("cap-4").is_some());
    assert!(bench.server.manifest("cap-3").is_none());
    assert!(chunk_requests(&bench, "cap-3").is_empty());
}

#[tokio::test]
async fn session_ids_unsafe_in_a_url_path_are_never_uploaded() {
    let long = "a".repeat(129);
    for (id, safe) in [
        ("4f1c2a8e-5d3b-4c6a-9e7f-0a1b2c3d4e5f", true),
        ("stand-session-7.b_c", true),
        (&"a".repeat(128), true),
        ("", false),
        (".", false),
        ("..", false),
        ("-", false),
        ("../etc", false),
        ("a/b", false),
        ("a b", false),
        ("a%2fb", false),
        ("a?b", false),
        ("caf\u{e9}", false),
        (long.as_str(), false),
    ] {
        assert_eq!(path_safe(id), safe, "{id:?}");
    }
    let bench = Bench::new(limits());
    let mut observer = shell_session(&bench, "../etc", &text(11, 100_000));
    assert_eq!(bench.recordings.active_uploads(), 0);
    assert_eq!(observer.finish(), Recording::Incomplete);
    assert!(bench.server.seen().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finish_wakes_hundreds_of_idle_uploaders_on_a_multi_threaded_runtime() {
    let bench = Bench::new(sized(64 * MIB, 256 * MIB, 512));
    let ids: Vec<String> = (0..300).map(|n| format!("wake-{n}")).collect();
    let mut observers: Vec<Box<dyn SessionObserver>> = ids
        .iter()
        .map(|id| shell_session(&bench, id, b"idle until the end"))
        .collect();
    eventually("every uploader to wait idle", || {
        bench.clock.sleepers().len() >= ids.len()
    })
    .await;
    assert!(bench.server.seen().is_empty());
    for observer in &mut observers {
        observer.channel_end(0, &ChannelExit::Status(0));
        assert_eq!(observer.finish(), Recording::Complete);
    }
    eventually("every recording to be stored", || {
        ids.iter().all(|id| bench.server.manifest(id).is_some())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_upload_never_slows_the_data_path_and_memory_stays_bounded() {
    let bench = Bench::new(sized(4 * MIB, 6 * MIB, 4));
    bench.server.always(Some(Step::Hang));
    let mut first = bench.open("flood-1", false);
    let mut second = bench.open("flood-2", false);
    first.channel_start(0, &shell(80, 24));
    second.channel_start(0, &shell(80, 24));
    let piece = text(7, 64 * 1024);
    let mut slowest = Duration::ZERO;
    let mut peak = 0;
    for _ in 0..(100 * MIB / piece.len()) {
        for observer in [&mut first, &mut second] {
            let call = Instant::now();
            out(&mut **observer, 0, &piece);
            slowest = slowest.max(call.elapsed());
        }
        peak = peak.max(bench.recordings.memory_in_use());
    }
    assert!(slowest < Duration::from_secs(2), "slowest call {slowest:?}");
    assert!(peak <= 6 * MIB, "peak {peak}");
    for id in ["flood-1", "flood-2"] {
        eventually("the uploader to make its request", || {
            !chunk_requests(&bench, id).is_empty()
        })
        .await;
        assert_eq!(chunk_requests(&bench, id), [0]);
    }
    let snapshots = bench.recordings.snapshots();
    assert_eq!(snapshots.len(), 2);
    for snapshot in &snapshots {
        assert!(snapshot.queued_bytes <= 4 * MIB);
        assert!(snapshot.queue_dropped + snapshot.withheld > 0);
        assert_eq!(snapshot.end, None::<End>);
    }
    assert!(snapshots.iter().any(|snapshot| snapshot.withheld > 0));
    assert_eq!(first.finish(), Recording::Incomplete);
    assert_eq!(second.finish(), Recording::Incomplete);
}

#[tokio::test]
async fn each_upload_gets_ten_seconds_from_the_later_of_its_finish_and_the_drain() {
    let bench = Bench::new(limits());
    let mut done = shell_session(&bench, "shutdown-done", b"finished in time");
    bench.recordings.begin_shutdown();
    done.channel_end(0, &ChannelExit::Status(0));
    done.finish();
    settle(&bench, "shutdown-done").await;
    assert!(bench.server.manifest("shutdown-done").is_some());
    let mut late = bench.open("shutdown-late", false);
    assert_eq!(late.finish(), Recording::Incomplete);
    assert!(soon("the drain", bench.recordings.drain()).await);

    let bench = Bench::new(limits());
    bench.server.always(Some(Step::Hang));
    let mut early = shell_session(&bench, "early", b"finished before the shutdown");
    let mut closing = shell_session(&bench, "closing", b"still open at the drain");
    early.channel_end(0, &ChannelExit::Status(0));
    early.finish();
    eventually("the first request", || {
        !chunk_requests(&bench, "early").is_empty()
    })
    .await;
    bench.recordings.begin_shutdown();
    bench.clock.advance(15 * SECOND);
    eventually("the open session to flush after the clock moved", || {
        !chunk_requests(&bench, "closing").is_empty()
    })
    .await;
    assert_eq!(bench.recordings.snapshots().len(), 2);

    let recordings = bench.recordings.clone();
    let drain = tokio::spawn(async move { recordings.drain().await });
    let drain_started = start() + 15 * SECOND;
    bench
        .clock
        .wait_for_sleeper(drain_started + SHUTDOWN_GRACE)
        .await;
    bench.clock.advance(5 * SECOND);
    closing.channel_end(0, &ChannelExit::Status(0));
    closing.finish();
    bench
        .clock
        .wait_for_sleeper(start() + 20 * SECOND + SHUTDOWN_GRACE)
        .await;
    bench.clock.advance(5 * SECOND);
    eventually("the early upload to stop at its own deadline", || {
        bench.recordings.snapshots().len() == 1
    })
    .await;
    assert!(!drain.is_finished());
    bench.clock.advance(5 * SECOND);
    assert!(soon("the drain", drain).await.unwrap());
    assert!(bench.recordings.snapshots().is_empty());
    assert_eq!(bench.recordings.memory_in_use(), 0);
    assert!(bench.server.manifest("early").is_none());
    assert!(
        !bench
            .server
            .seen()
            .contains(&Seen::Complete("closing".to_owned()))
    );
}

#[tokio::test]
async fn a_panicking_upload_task_releases_its_memory() {
    let bench = Bench::new(limits());
    bench.server.script_chunks(&[Step::Panic]);
    let mut observer = shell_session(&bench, "panic-upload", &text(12, 100_000));
    eventually("the upload task to end", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(bench.recordings.memory_in_use(), 0);
    out(&mut *observer, 0, &text(13, 100_000));
    assert_eq!(observer.finish(), Recording::Incomplete);
    assert_eq!(bench.recordings.memory_in_use(), 0);
}
