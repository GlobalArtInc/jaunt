use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use jaunt_proto::{
    AGENT_EVENTS_MAX_BODY_BYTES, AgentEventBatch, AgentEventValue, AgentEventsAccepted,
};
use jaunt_tunnel::{BoxFuture, ClientEvent};
use tokio::sync::{Notify, broadcast};
use tokio_util::sync::CancellationToken;

use super::support::fixed;
use crate::clock::Clock;
use crate::run::api::{ApiError, EventsAnswer};
use crate::runtime::events::{
    EventSink, EventTransport, SINK_LIMITS, SessionEvent, SinkCounters, SinkLimits,
    follow_connections,
};
use crate::testkit::{LogCapture, ManualClock, eventually, soon};

type Phase = (&'static [(bool, &'static str)], &'static [&'static str]);

const A: &str = "0b0f4c6e-1d2a-4b3c-8d4e-5f6a7b8c9d0e";
const B: &str = "k-0123456789abcdef0123456789abcdef";
const START_SECS: u64 = 1_800_000_000;
const FIRST_SEQ: u64 = START_SECS * 1000 * 1000;

#[derive(Clone)]
enum Step {
    Accept,
    Status(u16),
    RetryAfter(u64),
    Refuse(Vec<String>),
    Gate(Arc<Notify>),
    GateRefuse(Arc<Notify>, Vec<String>),
    Hold,
}

struct FakeTransport {
    steps: Mutex<VecDeque<Step>>,
    standing: Mutex<Step>,
    batches: Mutex<Vec<AgentEventBatch>>,
}

impl FakeTransport {
    fn script(&self, steps: &[Step]) {
        self.steps.lock().unwrap().extend(steps.iter().cloned());
    }

    fn standing(&self, step: Step) {
        *self.standing.lock().unwrap() = step;
    }

    fn batches(&self) -> Vec<AgentEventBatch> {
        self.batches.lock().unwrap().clone()
    }
}

impl EventTransport for FakeTransport {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        self.batches.lock().unwrap().push(batch.clone());
        let step = self
            .steps
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| self.standing.lock().unwrap().clone());
        let accepted = u64::try_from(batch.events.len()).unwrap();
        Box::pin(async move {
            let refusal = |status, retry_after| ApiError::Status {
                status,
                code: "refused".to_owned(),
                retry_after,
            };
            let delivered = EventsAnswer::Accepted(AgentEventsAccepted {
                accepted,
                ..AgentEventsAccepted::default()
            });
            match step {
                Step::Accept => Ok(delivered),
                Step::Status(status) => Err(refusal(status, None)),
                Step::RetryAfter(secs) => Err(refusal(429, Some(Duration::from_secs(secs)))),
                Step::Refuse(sessions) => Ok(EventsAnswer::SessionsRefused(sessions)),
                Step::Gate(gate) => {
                    gate.notified().await;
                    Ok(delivered)
                }
                Step::GateRefuse(gate, sessions) => {
                    gate.notified().await;
                    Ok(EventsAnswer::SessionsRefused(sessions))
                }
                Step::Hold => std::future::pending().await,
            }
        })
    }
}

struct Stand {
    sink: EventSink,
    transport: Arc<FakeTransport>,
    clock: Arc<ManualClock>,
    _stop: tokio_util::sync::DropGuard,
}

fn stand_with(limits: SinkLimits, sample: f64) -> Stand {
    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(START_SECS));
    let transport = Arc::new(FakeTransport {
        steps: Mutex::new(VecDeque::new()),
        standing: Mutex::new(Step::Accept),
        batches: Mutex::new(Vec::new()),
    });
    let sink = EventSink::new(transport.clone(), clock.clone(), fixed(sample), limits);
    let stop = CancellationToken::new();
    tokio::spawn(sink.clone().run(stop.clone()));
    Stand {
        sink,
        transport,
        clock,
        _stop: stop.drop_guard(),
    }
}

fn stand() -> Stand {
    stand_with(SINK_LIMITS, 1.0)
}

fn small(queue_events: usize) -> SinkLimits {
    SinkLimits {
        queue_events,
        ..SINK_LIMITS
    }
}

fn event(name: &'static str, field: &str, value: &str) -> SessionEvent {
    SessionEvent {
        name,
        fields: BTreeMap::from([(field.to_owned(), AgentEventValue::Text(value.to_owned()))]),
    }
}

fn noisy(label: &str) -> SessionEvent {
    event("kube.request", "verb", label)
}

fn critical(label: &str) -> SessionEvent {
    event("kube.exec.start", "pod", label)
}

fn labels(batch: &AgentEventBatch) -> Vec<String> {
    batch
        .events
        .iter()
        .map(|event| match event.fields.values().next() {
            Some(AgentEventValue::Text(text)) => text.clone(),
            other => panic!("unexpected field {other:?}"),
        })
        .collect()
}

fn seqs(batch: &AgentEventBatch) -> Vec<u64> {
    batch
        .events
        .iter()
        .map(|event| event.seq - FIRST_SEQ)
        .collect()
}

async fn sent(stand: &Stand, count: usize) -> Vec<AgentEventBatch> {
    eventually("the expected batches", || {
        stand.transport.batches().len() >= count
    })
    .await;
    let batches = stand.transport.batches();
    assert_eq!(batches.len(), count);
    batches
}

#[tokio::test]
async fn emit_returns_at_once_under_a_stalled_control_and_the_queue_keeps_its_bounds() {
    let stand = stand();
    stand.transport.standing(Step::Hold);
    for index in 0..5000 {
        stand.sink.emit(A, noisy(&index.to_string()));
    }
    assert_eq!(stand.sink.queue_len(), 4096);
    sent(&stand, 1).await;
    for index in 0..10 {
        stand.sink.emit(B, critical(&index.to_string()));
    }
    stand.sink.emit(B, noisy("late"));
    assert_eq!(stand.sink.queue_len(), 4096);
    assert_eq!(
        stand.sink.counters(),
        SinkCounters {
            emitted: 5011,
            dropped: 904 + 10 + 1,
            ..SinkCounters::default()
        }
    );

    let heavy = stand_with(SINK_LIMITS, 1.0);
    heavy.transport.standing(Step::Hold);
    let query = "q".repeat(4000);
    for _ in 0..2000 {
        heavy.sink.emit(A, event("db.query", "text", &query));
    }
    let held = heavy.sink.queue_len();
    assert!((900..1100).contains(&held), "{held}");
    assert_eq!(
        heavy.sink.counters().dropped,
        2000 - u64::try_from(held).unwrap()
    );
}

#[tokio::test]
async fn noisy_events_are_dropped_first_and_critical_ones_only_when_nothing_else_is_left() {
    let stand = stand_with(small(3), 1.0);
    let phases: [Phase; 3] = [
        (
            &[(false, "n1"), (false, "n2"), (true, "c1"), (false, "n3")],
            &["c1", "n1", "n2"],
        ),
        (
            &[(false, "n4"), (false, "n5"), (true, "c2"), (true, "c3")],
            &["c2", "c3", "n4"],
        ),
        (
            &[(true, "c4"), (true, "c5"), (true, "c6"), (true, "c7")],
            &["c4", "c5", "c6"],
        ),
    ];
    for (index, (emitted, expected)) in phases.into_iter().enumerate() {
        for (lifecycle, label) in emitted {
            let made = if *lifecycle {
                critical(label)
            } else {
                noisy(label)
            };
            stand.sink.emit(A, made);
        }
        assert_eq!(stand.sink.queue_len(), 3, "{index}");
        assert_eq!(
            stand.sink.counters().dropped,
            u64::try_from(index + 1).unwrap()
        );
        stand.clock.advance(Duration::from_secs(1));
        let batches = sent(&stand, index + 1).await;
        let batch = &batches[index];
        assert_eq!(labels(batch), expected, "{index}");
        assert_eq!(batch.dropped.len(), 1);
        assert_eq!(
            (batch.dropped[0].session_id.as_str(), batch.dropped[0].count),
            (A, 1)
        );
        eventually("the batch to be delivered", || stand.sink.queue_len() == 0).await;
    }
    let all: Vec<u64> = stand.transport.batches().iter().flat_map(seqs).collect();
    assert_eq!(all, (1..=9).collect::<Vec<_>>());
}

#[tokio::test]
async fn a_failed_batch_is_kept_and_gives_up_its_noisy_events_before_a_critical_one_is_lost() {
    let stand = stand_with(small(2), 1.0);
    stand.transport.script(&[Step::Status(503)]);
    stand.sink.emit(A, critical("c1"));
    stand.sink.emit(A, noisy("n1"));
    stand.clock.advance(Duration::from_secs(1));
    let first = sent(&stand, 1).await;
    assert_eq!(labels(&first[0]), ["c1", "n1"]);
    eventually("the failure to be counted", || {
        stand.sink.counters().failures == 1
    })
    .await;
    stand.sink.emit(B, critical("c2"));
    assert_eq!(stand.sink.queue_len(), 2);
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 3).await;
    assert_eq!(labels(&batches[1]), ["c1"]);
    assert_eq!(seqs(&batches[1]), [1]);
    assert_eq!(labels(&batches[2]), ["c2"]);
    assert_eq!(seqs(&batches[2]), [3]);
    assert_eq!(batches[2].dropped[0].session_id, A);
    assert_eq!(batches[2].dropped[0].count, 1);
}

#[tokio::test]
async fn failed_sends_back_off_from_one_to_thirty_seconds_and_resend_the_same_batch() {
    let stand = stand();
    stand.transport.script(&vec![Step::Status(503); 7]);
    let start = stand.clock.now();
    stand.sink.emit(A, critical("c1"));
    stand.clock.advance(Duration::from_secs(1));
    let mut at = start + Duration::from_secs(1);
    for (attempt, delay) in [1, 2, 4, 8, 16, 30, 30].into_iter().enumerate() {
        sent(&stand, attempt + 1).await;
        at += Duration::from_secs(delay);
        stand.clock.wait_for_sleeper(at).await;
        stand.clock.set(at);
    }
    let batches = sent(&stand, 8).await;
    assert!(batches.iter().all(|batch| seqs(batch) == [1]));
    eventually("the batch to be delivered", || {
        stand.sink.counters().sent == 1
    })
    .await;
    assert_eq!(stand.sink.counters().failures, 7);
    assert_eq!(stand.sink.queue_len(), 0);

    let jittered = stand_with(SINK_LIMITS, 0.5);
    jittered
        .transport
        .script(&[Step::Status(503), Step::Status(503)]);
    let start = jittered.clock.now();
    jittered.sink.emit(A, critical("c1"));
    jittered.clock.advance(Duration::from_secs(1));
    sent(&jittered, 1).await;
    let first = start + Duration::from_secs(2);
    jittered.clock.wait_for_sleeper(first).await;
    jittered.clock.set(first);
    sent(&jittered, 2).await;
    jittered
        .clock
        .wait_for_sleeper(first + Duration::from_millis(1500))
        .await;
}

#[tokio::test]
async fn a_refused_batch_is_dropped_once_and_never_sent_again() {
    let stand = stand();
    stand.transport.script(&[Step::Status(400)]);
    stand.sink.emit(A, critical("c1"));
    stand.sink.emit(A, noisy("n1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    eventually("the refusal to be counted", || {
        stand.sink.counters().refused == 2
    })
    .await;
    assert_eq!(stand.sink.queue_len(), 0);
    stand.clock.advance(Duration::from_secs(60));
    stand.sink.emit(A, critical("c2"));
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 2).await;
    assert_eq!(labels(&batches[1]), ["c2"]);
    assert_eq!(seqs(&batches[1]), [3]);
}

#[tokio::test]
async fn too_many_requests_waits_exactly_the_time_control_asks_for() {
    let stand = stand();
    stand.transport.script(&[Step::RetryAfter(7)]);
    let start = stand.clock.now();
    stand.sink.emit(A, critical("c1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    let resume = start + Duration::from_secs(8);
    stand.clock.wait_for_sleeper(resume).await;
    stand.clock.set(resume - Duration::from_secs(1));
    tokio::task::yield_now().await;
    assert_eq!(stand.transport.batches().len(), 1);
    stand.clock.set(resume);
    let batches = sent(&stand, 2).await;
    assert_eq!(seqs(&batches[1]), [1]);
    eventually("the batch to be delivered", || {
        stand.sink.counters().sent == 1
    })
    .await;
    assert_eq!(stand.sink.counters().failures, 0);
}

#[tokio::test]
async fn a_flush_sends_at_once_and_gives_up_at_its_deadline() {
    let stand = stand();
    let now = stand.clock.now();
    assert!(soon("the empty flush", stand.sink.flush(A, now)).await);
    stand.sink.emit(A, critical("c1"));
    assert!(
        soon(
            "the flush",
            stand.sink.flush(A, now + Duration::from_secs(2))
        )
        .await
    );
    assert_eq!(stand.sink.counters().sent, 1);

    stand.transport.standing(Step::Hold);
    stand.sink.emit(A, critical("c2"));
    let deadline = now + Duration::from_secs(2);
    let sink = stand.sink.clone();
    let flushing = tokio::spawn(async move { sink.flush(A, deadline).await });
    stand.clock.wait_for_sleeper(deadline).await;
    assert!(!flushing.is_finished());
    stand.clock.set(deadline);
    assert!(!soon("the flush deadline", flushing).await.unwrap());
    assert_eq!(stand.sink.queue_len(), 1);
}

#[tokio::test]
async fn retry_after_waits_at_least_the_first_retry_and_at_most_five_minutes() {
    for (asked, expected) in [(0, 1), (7, 7), (100_000, 300)] {
        let stand = stand();
        stand.transport.script(&[Step::RetryAfter(asked)]);
        stand.sink.emit(A, critical("c1"));
        stand.clock.advance(Duration::from_secs(1));
        sent(&stand, 1).await;
        let resume = stand.clock.now() + Duration::from_secs(expected);
        stand.clock.wait_for_sleeper(resume).await;
        stand.clock.set(resume - Duration::from_millis(1));
        tokio::task::yield_now().await;
        assert_eq!(stand.transport.batches().len(), 1, "{asked}");
        stand.clock.set(resume);
        sent(&stand, 2).await;
    }
}

#[tokio::test]
async fn the_observed_time_of_an_event_is_the_clock_in_milliseconds() {
    let stand = stand();
    stand.clock.advance(Duration::from_millis(1234));
    let expected = i64::try_from(START_SECS * 1000 + 1234).unwrap();
    stand.sink.emit(A, critical("c1"));
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 1).await;
    assert_eq!(batches[0].events[0].observed_at, expected);
}

#[tokio::test]
async fn the_backoff_starts_over_after_a_delivered_batch() {
    let stand = stand();
    stand.transport.script(&[
        Step::Status(503),
        Step::Status(503),
        Step::Accept,
        Step::Status(503),
    ]);
    stand.sink.emit(A, critical("c1"));
    stand.clock.advance(Duration::from_secs(1));
    for (attempt, delay) in [(1, 1), (2, 2)] {
        sent(&stand, attempt).await;
        let at = stand.clock.now() + Duration::from_secs(delay);
        stand.clock.wait_for_sleeper(at).await;
        stand.clock.set(at);
    }
    sent(&stand, 3).await;
    eventually("the batch to be delivered", || {
        stand.sink.counters().sent == 1
    })
    .await;
    stand.sink.emit(A, critical("c2"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 4).await;
    let again = stand.clock.now() + Duration::from_secs(1);
    stand.clock.wait_for_sleeper(again).await;
}

#[tokio::test]
async fn a_batch_in_flight_is_never_evicted_and_a_critical_event_is_dropped_instead() {
    let stand = stand_with(small(2), 1.0);
    let gate = Arc::new(Notify::new());
    stand.transport.script(&[Step::Gate(gate.clone())]);
    stand.sink.emit(A, noisy("n1"));
    stand.sink.emit(A, noisy("n2"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    stand.sink.emit(B, critical("c1"));
    assert_eq!(stand.sink.counters().dropped, 1);
    gate.notify_one();
    eventually("the batch in flight to be delivered", || {
        stand.sink.counters().sent == 2
    })
    .await;
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 2).await;
    assert_eq!(labels(&batches[0]), ["n1", "n2"]);
    assert!(batches[1].events.is_empty());
    assert_eq!(batches[1].dropped[0].session_id, B);
}

#[tokio::test]
async fn a_held_batch_of_critical_events_keeps_them_and_a_new_critical_event_is_dropped() {
    let stand = stand_with(small(2), 1.0);
    stand.transport.script(&[Step::Status(503)]);
    stand.sink.emit(A, critical("c1"));
    stand.sink.emit(A, critical("c2"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    eventually("the failure to be counted", || {
        stand.sink.counters().failures == 1
    })
    .await;
    stand.sink.emit(A, critical("c3"));
    assert_eq!(stand.sink.counters().dropped, 1);
    assert_eq!(stand.sink.queue_len(), 2);
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 3).await;
    assert_eq!(labels(&batches[1]), ["c1", "c2"]);
    assert_eq!(seqs(&batches[1]), [1, 2]);
    assert!(batches[2].events.is_empty());
    assert_eq!(batches[2].dropped[0].count, 1);
}

#[tokio::test]
async fn reports_for_three_hundred_sessions_go_out_two_hundred_fifty_six_at_a_time() {
    let stand = stand();
    for index in 0..300 {
        let session = format!("00000000-0000-4000-8000-{index:012x}");
        stand.sink.emit(&session, event("session.start", "x", "y"));
    }
    stand.clock.advance(Duration::from_secs(1));
    let both = sent(&stand, 2).await;
    assert_eq!(both[0].dropped.len(), 256);
    assert_eq!(both[1].dropped.len(), 44);
}

#[tokio::test]
async fn every_batch_fits_the_body_limit_of_control() {
    let stand = stand();
    for index in 0..300 {
        let session = format!("{index:a>64}");
        stand.sink.emit(&session, event("session.start", "x", "y"));
    }
    stand
        .sink
        .emit(A, event("db.query", "text", &"q".repeat(236_000)));
    assert_eq!(stand.sink.counters().dropped, 301);
    stand
        .sink
        .emit(A, event("db.query", "text", &"q".repeat(229_000)));
    for _ in 0..6 {
        stand
            .sink
            .emit(A, event("db.query", "text", &"\"".repeat(60_000)));
    }
    assert_eq!(stand.sink.queue_len(), 7);
    let deadline = stand.clock.now() + Duration::from_secs(2);
    assert!(soon("the flush", stand.sink.flush(A, deadline)).await);
    stand.clock.advance(Duration::from_secs(1));
    eventually("the last reports", || {
        stand
            .transport
            .batches()
            .iter()
            .map(|batch| batch.dropped.len())
            .sum::<usize>()
            == 301
    })
    .await;
    let batches = stand.transport.batches();
    assert!(batches.len() >= 3);
    for batch in &batches {
        let size = serde_json::to_vec(batch).unwrap().len();
        assert!(size <= AGENT_EVENTS_MAX_BODY_BYTES, "{size}");
    }
    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.events.len())
            .sum::<usize>(),
        7
    );
}

#[tokio::test]
async fn sequence_numbers_start_from_the_clock_so_a_restarted_agent_never_repeats_them() {
    let first = stand();
    for index in 0..300 {
        first.sink.emit(A, critical(&index.to_string()));
    }
    first.clock.advance(Duration::from_secs(1));
    let deadline = first.clock.now() + Duration::from_secs(2);
    assert!(soon("the flush", first.sink.flush(A, deadline)).await);
    let last = first
        .transport
        .batches()
        .iter()
        .flat_map(|batch| batch.events.iter().map(|event| event.seq))
        .max()
        .unwrap();
    assert_eq!(last, FIRST_SEQ + 300);

    let later = stand();
    later.clock.advance(Duration::from_millis(1));
    let restarted = EventSink::new(
        later.transport.clone(),
        later.clock.clone(),
        fixed(1.0),
        SINK_LIMITS,
    );
    let stop = CancellationToken::new();
    tokio::spawn(restarted.clone().run(stop.clone()));
    restarted.emit(A, critical("after"));
    let deadline = later.clock.now() + Duration::from_secs(2);
    assert!(soon("the flush", restarted.flush(A, deadline)).await);
    let resumed = later.transport.batches()[0].events[0].seq;
    assert!(resumed > last, "{resumed} {last}");
    stop.cancel();
}

#[tokio::test]
async fn a_control_without_the_route_is_asked_again_and_gets_the_counts_after_it_learns_it() {
    for status in [404, 405] {
        let log = LogCapture::default();
        let _guard = log.install();
        let stand = stand();
        stand
            .transport
            .script(&[Step::Status(status), Step::Status(status)]);
        stand.sink.emit(A, critical("c1"));
        stand.sink.emit(A, noisy("n1"));
        stand.clock.advance(Duration::from_secs(1));
        sent(&stand, 1).await;
        eventually("the sink to switch to counting", || {
            stand.sink.counters().unsupported == 2
        })
        .await;
        for index in 0..300 {
            stand.sink.emit(B, critical(&index.to_string()));
        }
        assert_eq!(stand.sink.queue_len(), 0);
        let now = stand.clock.now();
        assert!(
            !soon(
                "the flush",
                stand.sink.flush(B, now + Duration::from_secs(2))
            )
            .await
        );
        let probe = now + Duration::from_secs(5);
        stand.clock.wait_for_sleeper(probe).await;
        stand.clock.set(probe - Duration::from_millis(1));
        tokio::task::yield_now().await;
        assert_eq!(stand.transport.batches().len(), 1, "{status}");
        stand.clock.set(probe);
        let probed = sent(&stand, 2).await;
        assert!(probed[1].events.is_empty());
        stand
            .clock
            .wait_for_sleeper(probe + Duration::from_secs(10))
            .await;
        stand.sink.reconnected();
        let third = sent(&stand, 3).await;
        let mut counted: Vec<(String, u64)> = third[2]
            .dropped
            .iter()
            .map(|report| (report.session_id.clone(), report.count))
            .collect();
        counted.sort();
        assert_eq!(
            counted,
            [(A.to_owned(), 2), (B.to_owned(), 300)],
            "{status}"
        );
        eventually("the route to be used again", || {
            stand.sink.counters().sent == 0 && stand.sink.queue_len() == 0
        })
        .await;
        stand.sink.emit(A, critical("c2"));
        stand.clock.advance(Duration::from_secs(1));
        let resumed = sent(&stand, 4).await;
        assert_eq!(labels(&resumed[3]), ["c2"]);
        let counters = stand.sink.counters();
        assert_eq!(
            (counters.unsupported, counters.dropped),
            (302, 0),
            "{status}"
        );
        let warnings = log
            .text()
            .matches("does not take audit events of service sessions")
            .count();
        assert_eq!(warnings, 1, "{status}");
    }
}

#[tokio::test]
async fn a_new_connection_asks_a_control_without_the_route_again() {
    let stand = stand();
    stand.transport.script(&[Step::Status(404)]);
    stand.sink.emit(A, critical("c1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    eventually("the sink to switch to counting", || {
        stand.sink.counters().unsupported == 1
    })
    .await;
    let (events, receiver) = broadcast::channel(4);
    let stop = CancellationToken::new();
    let following = tokio::spawn(follow_connections(
        receiver,
        stand.sink.clone(),
        stop.clone(),
    ));
    events
        .send(ClientEvent::Disconnected {
            lasted: Duration::from_secs(1),
        })
        .unwrap();
    tokio::task::yield_now().await;
    assert_eq!(stand.transport.batches().len(), 1);
    events.send(ClientEvent::Connected).unwrap();
    let batches = sent(&stand, 2).await;
    assert_eq!(batches[1].dropped[0].session_id, A);
    stop.cancel();
    soon("the follower to stop", following).await.unwrap();
}

#[tokio::test]
async fn sessions_control_does_not_know_are_cut_out_of_the_batch_and_the_rest_is_sent_again() {
    let stand = stand();
    stand
        .transport
        .script(&[Step::Refuse(vec![B.to_owned(), "other".to_owned()])]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, critical("b1"));
    stand.sink.emit(A, noisy("a2"));
    stand.sink.emit(B, event("session.start", "x", "y"));
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 2).await;
    assert_eq!(labels(&batches[0]), ["a1", "b1", "a2"]);
    assert_eq!(batches[0].dropped.len(), 1);
    assert_eq!(labels(&batches[1]), ["a1", "a2"]);
    assert_eq!(seqs(&batches[1]), [1, 3]);
    assert!(batches[1].dropped.is_empty());
    eventually("the rest to be delivered", || {
        stand.sink.counters().sent == 2
    })
    .await;
    stand.sink.emit(B, critical("b2"));
    assert_eq!(stand.sink.queue_len(), 0);
    assert_eq!(stand.sink.counters().refused, 2);

    let stray = stand_with(SINK_LIMITS, 1.0);
    stray
        .transport
        .script(&[Step::Refuse(vec!["nobody".to_owned()])]);
    stray.sink.emit(A, critical("a1"));
    stray.clock.advance(Duration::from_secs(1));
    sent(&stray, 1).await;
    eventually("the batch to be dropped", || {
        stray.sink.counters().refused == 1
    })
    .await;
    stray.clock.advance(Duration::from_secs(60));
    tokio::task::yield_now().await;
    assert_eq!(stray.transport.batches().len(), 1);
}

#[tokio::test]
async fn unknown_names_oversized_events_and_bad_session_ids_never_reach_the_queue() {
    let stand = stand();
    stand.sink.emit(A, event("session.start", "x", "y"));
    stand
        .sink
        .emit(A, event("db.query", "text", &"q".repeat(300 * 1024)));
    stand.sink.emit("", critical("c1"));
    stand.sink.emit(&"s".repeat(65), critical("c1"));
    assert_eq!(stand.sink.queue_len(), 0);
    let counters = stand.sink.counters();
    assert_eq!((counters.dropped, counters.unreported), (2, 2));
    let deadline = stand.clock.now() + Duration::from_secs(2);
    assert!(soon("the flush", stand.sink.flush(A, deadline)).await);
    let batches = sent(&stand, 1).await;
    assert!(batches[0].events.is_empty());
    assert_eq!(batches[0].dropped[0].count, 2);
}

#[tokio::test]
async fn control_naming_seventy_sessions_cuts_out_at_most_sixty_four() {
    let stand = stand();
    let sessions: Vec<String> = (0..70)
        .map(|index| format!("00000000-0000-4000-8000-{index:012x}"))
        .collect();
    stand.transport.script(&[Step::Refuse(sessions.clone())]);
    for session in &sessions {
        stand.sink.emit(session, critical(session));
    }
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 2).await;
    assert_eq!(batches[0].events.len(), 70);
    let kept: Vec<&str> = batches[1]
        .events
        .iter()
        .map(|event| event.session_id.as_str())
        .collect();
    let expected: Vec<&str> = sessions[64..].iter().map(String::as_str).collect();
    assert_eq!(kept, expected);
    assert_eq!(stand.sink.counters().refused, 64);
    stand.sink.emit(&sessions[0], critical("late"));
    stand.sink.emit(&sessions[69], critical("late"));
    assert_eq!(stand.sink.queue_len(), 1);
}

#[tokio::test]
async fn events_of_a_rejected_session_never_reach_a_later_batch() {
    let stand = stand();
    stand.transport.script(&[Step::Refuse(vec![B.to_owned()])]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, critical("b1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 2).await;
    eventually("the rest to be delivered", || {
        stand.sink.counters().sent == 1
    })
    .await;
    stand.sink.emit(B, critical("b2"));
    stand.sink.emit(A, critical("a2"));
    stand.sink.emit(B, noisy("b3"));
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 3).await;
    assert_eq!(labels(&batches[2]), ["a2"]);
    assert!(
        batches
            .iter()
            .skip(1)
            .all(|batch| { batch.events.iter().all(|event| event.session_id != B) })
    );
}

#[tokio::test]
async fn the_queue_of_a_rejected_session_is_cleaned_when_the_refusal_arrives() {
    let stand = stand();
    let refusal = Arc::new(Notify::new());
    let resend = Arc::new(Notify::new());
    stand.transport.script(&[
        Step::GateRefuse(refusal.clone(), vec![B.to_owned()]),
        Step::Gate(resend.clone()),
    ]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, critical("b1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    for index in 0..5 {
        stand.sink.emit(B, critical(&format!("b-queued-{index}")));
    }
    stand.sink.emit(A, critical("a-queued"));
    assert_eq!(stand.sink.queue_len(), 8);
    refusal.notify_one();
    eventually("the refusal to clean the queue", || {
        stand.sink.queue_len() == 2
    })
    .await;
    assert_eq!(stand.sink.counters().refused, 6);
    let batches = sent(&stand, 2).await;
    assert_eq!(labels(&batches[1]), ["a1"]);
    resend.notify_one();
}

#[tokio::test]
async fn a_rejected_session_is_forgotten_when_it_ends_or_after_an_hour() {
    let stand = stand();
    stand
        .transport
        .script(&[Step::Refuse(vec![A.to_owned(), B.to_owned()])]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, critical("b1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    eventually("both sessions to be refused", || {
        stand.sink.counters().refused == 2
    })
    .await;
    stand.sink.emit(A, critical("a2"));
    stand.sink.emit(B, critical("b2"));
    assert_eq!(stand.sink.queue_len(), 0);
    stand.sink.session_ended(A);
    stand.sink.emit(A, critical("a3"));
    assert_eq!(stand.sink.queue_len(), 1);
    stand.clock.advance(Duration::from_secs(3600));
    stand.sink.emit(B, critical("b3"));
    assert_eq!(stand.sink.queue_len(), 2);
}

#[tokio::test]
async fn a_session_named_for_its_drop_count_alone_is_remembered_and_its_later_events_dropped() {
    let stand = stand();
    stand.transport.script(&[Step::Refuse(vec![B.to_owned()])]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, event("session.start", "x", "y"));
    stand.clock.advance(Duration::from_secs(1));
    let batches = sent(&stand, 2).await;
    assert!(batches[0].events.iter().all(|event| event.session_id == A));
    assert_eq!(batches[0].dropped[0].session_id, B);
    assert_eq!(labels(&batches[1]), ["a1"]);
    assert!(batches[1].dropped.is_empty());
    eventually("the rest to be delivered", || {
        stand.sink.counters().sent == 1
    })
    .await;
    assert_eq!(stand.sink.rejected_sessions(), 1);
    stand.sink.emit(B, critical("b1"));
    assert_eq!(stand.sink.queue_len(), 0);
    assert_eq!(stand.sink.counters().refused, 1);
}

#[tokio::test]
async fn refusals_older_than_an_hour_are_cleaned_by_the_events_of_any_session() {
    let stand = stand();
    stand
        .transport
        .script(&[Step::Refuse(vec![A.to_owned(), B.to_owned()])]);
    stand.sink.emit(A, critical("a1"));
    stand.sink.emit(B, critical("b1"));
    stand.clock.advance(Duration::from_secs(1));
    sent(&stand, 1).await;
    eventually("both sessions to be refused", || {
        stand.sink.rejected_sessions() == 2
    })
    .await;
    let other = "00000000-0000-4000-8000-000000000001";
    stand.clock.advance(Duration::from_secs(1800));
    stand.sink.emit(other, critical("c1"));
    assert_eq!(stand.sink.rejected_sessions(), 2);
    stand.clock.advance(Duration::from_secs(1800));
    stand.sink.emit(other, critical("c2"));
    assert_eq!(stand.sink.rejected_sessions(), 0);
}
