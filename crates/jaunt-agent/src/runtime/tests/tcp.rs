use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use jaunt_proto::{
    AgentEvent, AgentEventValue, AnnouncedService, ServiceAccess, ServiceAnnouncement, ServiceEnd,
    ServiceKind, ServiceOutcome, TcpSettings,
};
use jaunt_tunnel::{BoxFuture, ServiceName, StreamKind};
use rustix::net::sockopt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::support::{
    CLIENT, Harness, HarnessOptions, Opened, approved, dns_name, handshake, service_id, wait_until,
};
use crate::clock::Clock;
use crate::runtime::directory::ApprovedService;
use crate::runtime::handler::ServiceSession;
use crate::runtime::tcp::{
    CLIENT_ADDR_BYTES, Connect, DialFailure, EndReason, Ledger, TCP_LIMITS, TcpHandler, TcpLimits,
    bounded, dial,
};
use crate::testkit::{LogCapture, ManualClock, soon};

const SERVICE: &str = "grafana";
const TCP: StreamKind = StreamKind::Tcp;

fn declared(name: &str, address: &str, idle_timeout_secs: Option<u64>) -> AnnouncedService {
    AnnouncedService {
        kind: ServiceKind::Tcp,
        name: name.to_owned(),
        labels: BTreeMap::new(),
        address: Some(address.to_owned()),
        kubernetes: None,
        postgres: None,
        tcp: idle_timeout_secs.map(|idle_timeout_secs| TcpSettings { idle_timeout_secs }),
    }
}

fn announcement(address: Option<&str>, idle_timeout_secs: Option<u64>) -> ServiceAnnouncement {
    ServiceAnnouncement {
        ssh_enabled: false,
        services: address
            .map(|address| declared(SERVICE, address, idle_timeout_secs))
            .into_iter()
            .collect(),
    }
}

#[derive(Debug, Clone, Copy)]
enum Step {
    Hang,
    Fail,
}

#[derive(Default)]
struct Script {
    steps: Mutex<VecDeque<Step>>,
    dialed: Mutex<Vec<String>>,
}

impl Script {
    fn push(&self, steps: &[Step]) {
        self.steps.lock().unwrap().extend(steps.iter().copied());
    }

    fn dialed(&self) -> Vec<String> {
        self.dialed.lock().unwrap().clone()
    }
}

impl Connect for Script {
    fn connect<'a>(&'a self, address: &'a str) -> BoxFuture<'a, io::Result<TcpStream>> {
        self.dialed.lock().unwrap().push(address.to_owned());
        let step = self.steps.lock().unwrap().pop_front();
        Box::pin(async move {
            match step {
                Some(Step::Hang) => std::future::pending().await,
                Some(Step::Fail) => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                None => TcpStream::connect(address).await,
            }
        })
    }
}

struct Setup {
    harness: Harness,
    tcp: Arc<TcpHandler>,
}

fn setup(local: &ServiceAnnouncement, limits: TcpLimits) -> Setup {
    let services = vec![approved(TCP, SERVICE)];
    scripted(local, limits, Arc::new(Script::default()), services)
}

fn scripted(
    local: &ServiceAnnouncement,
    limits: TcpLimits,
    script: Arc<Script>,
    services: Vec<ApprovedService>,
) -> Setup {
    let clock = ManualClock::new(SystemTime::now());
    let tcp = Arc::new(TcpHandler::with_connect(
        local,
        clock.clone(),
        limits,
        script,
    ));
    let harness = Harness::with(HarnessOptions {
        services,
        handled: Vec::new(),
        clock: Some(clock),
        tcp: Some(tcp.clone()),
        ..HarnessOptions::default()
    });
    Setup { harness, tcp }
}

impl Setup {
    async fn connect(&self, session: &str) -> (TlsStream<DuplexStream>, Opened) {
        self.connect_to(SERVICE, session, CLIENT).await
    }

    async fn connect_to(
        &self,
        service: &str,
        session: &str,
        client: &str,
    ) -> (TlsStream<DuplexStream>, Opened) {
        let mut opened = self.harness.open_from(TCP, service, session, client);
        let config = self.harness.client_config(Some(&self.harness.user()), &[]);
        let stream = handshake(opened.take(), &dns_name(TCP, service), config)
            .await
            .unwrap();
        (stream, opened)
    }

    async fn refused(&self, session: &str) -> String {
        let (mut client, opened) = self.connect(session).await;
        closed(&mut client).await;
        opened.finished().await;
        let (reason, outcome) = self.reason(session);
        assert_eq!(outcome, ServiceOutcome::UpstreamError, "{session}");
        reason
    }

    fn events(&self, session: &str) -> Vec<AgentEvent> {
        events_of(&self.harness, session)
    }

    fn ended(&self, session: &str) -> (BTreeMap<String, AgentEventValue>, ServiceEnd) {
        let events = self.events(session);
        let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
        assert_eq!(names, ["tcp.session.start", "tcp.session.end"], "{session}");
        let ends: Vec<ServiceEnd> = self
            .harness
            .control
            .ends()
            .into_iter()
            .filter(|end| end.session_id == session)
            .collect();
        assert_eq!(ends.len(), 1, "{session}");
        (events[1].fields.clone(), ends[0].clone())
    }

    fn reason(&self, session: &str) -> (String, ServiceOutcome) {
        let (fields, end) = self.ended(session);
        (text(&fields, "reason"), end.outcome)
    }
}

fn events_of(harness: &Harness, session: &str) -> Vec<AgentEvent> {
    let mut events: Vec<AgentEvent> = harness
        .control
        .batches()
        .into_iter()
        .flat_map(|batch| batch.events)
        .filter(|event| event.session_id == session)
        .collect();
    events.sort_by_key(|event| event.seq);
    events
}

async fn still_running<T>(task: &JoinHandle<T>) {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished());
}

fn text(fields: &BTreeMap<String, AgentEventValue>, key: &str) -> String {
    match fields.get(key) {
        Some(AgentEventValue::Text(value)) => value.clone(),
        other => panic!("{key}: {other:?}"),
    }
}

fn int(fields: &BTreeMap<String, AgentEventValue>, key: &str) -> i64 {
    match fields.get(key) {
        Some(AgentEventValue::Int(value)) => *value,
        other => panic!("{key}: {other:?}"),
    }
}

async fn echo_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let accepted = Arc::new(AtomicUsize::new(0));
    tokio::spawn(echo_on(listener, accepted.clone()));
    (address, accepted)
}

async fn echo_on(listener: TcpListener, accepted: Arc<AtomicUsize>) {
    while let Ok((stream, _)) = listener.accept().await {
        accepted.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let (mut read, mut write) = stream.into_split();
            drop(tokio::io::copy(&mut read, &mut write).await);
            drop(write.shutdown().await);
        });
    }
}

async fn manual_upstream() -> (String, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (listener.local_addr().unwrap().to_string(), listener)
}

async fn echo_once(stream: &mut TlsStream<DuplexStream>, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
    let mut back = vec![0_u8; bytes.len()];
    soon("the echo", stream.read_exact(&mut back))
        .await
        .unwrap();
    assert_eq!(back, bytes);
}

async fn closed(stream: &mut TlsStream<DuplexStream>) {
    let mut rest = Vec::new();
    let read = soon(
        "the agent to close the stream",
        stream.read_to_end(&mut rest),
    )
    .await;
    assert!(read.is_err() || rest.is_empty(), "{rest:?}");
}

#[tokio::test]
async fn four_mebibytes_pass_both_ways_and_the_session_is_reported_once_without_content_or_address()
{
    let logs = LogCapture::default();
    let _guard = logs.install();
    let (address, _) = echo_server().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    let (stream, opened) = setup.connect("s-bulk").await;
    let mut payload = b"CONTENT-MARKER-".to_vec();
    payload.extend((0..4 * 1024 * 1024_u32).map(|at| (at % 251) as u8));
    let (mut read, mut write) = tokio::io::split(stream);
    let sent = payload.clone();
    let writer = tokio::spawn(async move {
        write.write_all(&sent).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let mut back = Vec::new();
    soon("the echoed bytes", read.read_to_end(&mut back))
        .await
        .unwrap();
    soon("the writer", writer).await.unwrap();
    assert!(back == payload, "{} of {} bytes", back.len(), payload.len());
    opened.finished().await;

    let events = setup.events("s-bulk");
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].fields,
        BTreeMap::from([
            (
                "client_addr".to_owned(),
                AgentEventValue::Text(CLIENT.to_owned())
            ),
            (
                "service".to_owned(),
                AgentEventValue::Text(SERVICE.to_owned())
            ),
        ])
    );
    let (fields, end) = setup.ended("s-bulk");
    let length = i64::try_from(payload.len()).unwrap();
    assert_eq!(
        fields.keys().map(String::as_str).collect::<Vec<_>>(),
        ["bytes_down", "bytes_up", "duration_ms", "reason", "service"]
    );
    assert_eq!(
        (
            int(&fields, "bytes_up"),
            int(&fields, "bytes_down"),
            int(&fields, "duration_ms"),
            text(&fields, "reason"),
        ),
        (length, length, 0, "closed".to_owned())
    );
    assert_eq!(end.outcome, ServiceOutcome::Closed);
    assert_eq!(
        (end.bytes_in, end.bytes_out),
        (length as u64, length as u64)
    );

    let wire = serde_json::to_string(&setup.harness.control.batches()).unwrap();
    let log = logs.text();
    assert!(log.contains("a TCP session ended"), "{log}");
    for (place, written) in [("events", &wire), ("log", &log)] {
        assert!(!written.contains("CONTENT-MARKER"), "{place}");
        assert!(!written.contains(&address), "{place}");
    }
}

#[tokio::test]
async fn either_side_may_close_its_direction_first_and_the_other_still_finishes() {
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);

    let (mut client, opened) = setup.connect("s-client-first").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut got = Vec::new();
    soon("the request", upstream.read_to_end(&mut got))
        .await
        .unwrap();
    assert_eq!(got, b"request");
    upstream
        .write_all(b"answer after the client closed")
        .await
        .unwrap();
    upstream.shutdown().await.unwrap();
    let mut back = Vec::new();
    soon("the answer", client.read_to_end(&mut back))
        .await
        .unwrap();
    assert_eq!(back, b"answer after the client closed");
    opened.finished().await;
    let (fields, end) = setup.ended("s-client-first");
    assert_eq!(
        (
            text(&fields, "reason"),
            int(&fields, "bytes_up"),
            int(&fields, "bytes_down")
        ),
        ("closed".to_owned(), 7, 30)
    );
    assert_eq!(end.outcome, ServiceOutcome::Closed);

    let (mut client, opened) = setup.connect("s-upstream-first").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    upstream.write_all(b"banner").await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut banner = Vec::new();
    soon("the banner", client.read_to_end(&mut banner))
        .await
        .unwrap();
    assert_eq!(banner, b"banner");
    client.write_all(b"late request").await.unwrap();
    client.shutdown().await.unwrap();
    let mut late = Vec::new();
    soon("the late request", upstream.read_to_end(&mut late))
        .await
        .unwrap();
    assert_eq!(late, b"late request");
    opened.finished().await;
    let (fields, _) = setup.ended("s-upstream-first");
    assert_eq!(
        (
            text(&fields, "reason"),
            int(&fields, "bytes_up"),
            int(&fields, "bytes_down")
        ),
        ("closed".to_owned(), 12, 6)
    );
}

#[tokio::test]
async fn a_silent_peer_after_the_first_close_gets_only_the_grace_and_every_slot_is_freed() {
    assert_eq!(TCP_LIMITS.half_close_grace, Duration::from_secs(30));
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    let (mut client, opened) = setup.connect("s-grace").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    upstream.write_all(b"bye").await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut bye = Vec::new();
    soon("the upstream close", client.read_to_end(&mut bye))
        .await
        .unwrap();
    assert_eq!(bye, b"bye");
    assert_eq!(setup.tcp.sessions_held(SERVICE), 1);

    let clock = &setup.harness.clock;
    let grace_over = clock.now() + TCP_LIMITS.half_close_grace;
    clock.wait_for_sleeper(grace_over).await;
    clock.set(grace_over - Duration::from_millis(1));
    still_running(&opened.serving).await;
    clock.set(grace_over);
    let mut rest = Vec::new();
    assert_eq!(
        soon(
            "the agent to close the upstream",
            upstream.read_to_end(&mut rest)
        )
        .await
        .unwrap(),
        0
    );
    opened.finished().await;
    assert_eq!(
        setup.reason("s-grace"),
        ("half_close_timeout".to_owned(), ServiceOutcome::Closed)
    );
    assert_eq!(setup.tcp.sessions_held(SERVICE), 0);
    assert_eq!(
        setup
            .harness
            .runtime
            .gauges()
            .connections_held(&service_id(SERVICE)),
        0
    );
}

#[tokio::test]
async fn a_session_without_bytes_for_the_idle_timeout_is_closed_and_traffic_restarts_the_wait() {
    let defaults = TcpHandler::new(
        &announcement(Some("127.0.0.1:1"), None),
        ManualClock::new(SystemTime::now()),
        TCP_LIMITS,
    );
    assert_eq!(
        defaults.idle_timeout(SERVICE),
        Some(Duration::from_secs(3600))
    );
    let (address, _) = echo_server().await;
    let setup = setup(&announcement(Some(&address), Some(60)), TCP_LIMITS);
    assert_eq!(
        setup.tcp.idle_timeout(SERVICE),
        Some(Duration::from_secs(60))
    );
    let (mut client, opened) = setup.connect("s-idle").await;
    echo_once(&mut client, b"ping").await;

    let clock = &setup.harness.clock;
    let start = clock.now();
    clock
        .wait_for_sleeper(start + Duration::from_secs(60))
        .await;
    clock.set(start + Duration::from_secs(30));
    echo_once(&mut client, b"again").await;
    clock.set(start + Duration::from_secs(60));
    clock
        .wait_for_sleeper(start + Duration::from_secs(90))
        .await;
    still_running(&opened.serving).await;
    clock.set(start + Duration::from_secs(90));
    closed(&mut client).await;
    opened.finished().await;
    let (fields, end) = setup.ended("s-idle");
    assert_eq!(
        (text(&fields, "reason"), int(&fields, "duration_ms")),
        ("idle_timeout".to_owned(), 90_000)
    );
    assert_eq!(end.outcome, ServiceOutcome::IdleTimeout);
}

#[tokio::test]
async fn the_idle_timeout_also_ends_a_half_closed_session() {
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), Some(10)), TCP_LIMITS);
    let (mut client, opened) = setup.connect("s-idle-half").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    upstream.write_all(b"bye").await.unwrap();
    upstream.shutdown().await.unwrap();
    let mut bye = Vec::new();
    soon("the upstream close", client.read_to_end(&mut bye))
        .await
        .unwrap();
    let clock = &setup.harness.clock;
    let start = clock.now();
    clock
        .wait_for_sleeper(start + TCP_LIMITS.half_close_grace)
        .await;
    clock
        .wait_for_sleeper(start + Duration::from_secs(10))
        .await;
    clock.set(start + Duration::from_secs(10));
    opened.finished().await;
    assert_eq!(
        setup.reason("s-idle-half"),
        ("idle_timeout".to_owned(), ServiceOutcome::IdleTimeout)
    );
}

#[tokio::test]
async fn a_cancelled_session_ends_within_a_second() {
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    let (mut client, opened) = setup.connect("s-cancel").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    client.write_all(b"x").await.unwrap();
    client.flush().await.unwrap();
    let mut one = [0_u8; 1];
    soon("the first byte", upstream.read_exact(&mut one))
        .await
        .unwrap();

    let cancelled_at = Instant::now();
    opened.cancel.cancel();
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(1), upstream.read_to_end(&mut rest))
        .await
        .expect("the upstream connection was not closed within a second");
    assert!(read.is_err() || rest.is_empty());
    assert!(cancelled_at.elapsed() < Duration::from_secs(1));
    opened.finished().await;
    let (fields, end) = setup.ended("s-cancel");
    assert_eq!(
        (text(&fields, "reason"), int(&fields, "bytes_up")),
        ("cancelled".to_owned(), 1)
    );
    assert_eq!(end.outcome, ServiceOutcome::Closed);
}

#[tokio::test]
async fn the_granted_duration_ends_the_session_through_the_runtime() {
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    setup
        .harness
        .control
        .allow_by_default(ServiceAccess::Tcp, 90);
    let clock = &setup.harness.clock;
    let start = clock.now();
    let (mut client, opened) = setup.connect("s-granted").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    upstream.write_all(b"hello").await.unwrap();
    let mut hello = [0_u8; 5];
    soon("the greeting", client.read_exact(&mut hello))
        .await
        .unwrap();

    clock
        .wait_for_sleeper(start + Duration::from_secs(90))
        .await;
    clock.set(start + Duration::from_secs(90));
    let mut rest = Vec::new();
    drop(
        soon(
            "the agent to close the upstream",
            upstream.read_to_end(&mut rest),
        )
        .await,
    );
    opened.finished().await;
    let (fields, end) = setup.ended("s-granted");
    assert_eq!(
        (
            text(&fields, "reason"),
            int(&fields, "bytes_down"),
            int(&fields, "duration_ms")
        ),
        ("max_duration".to_owned(), 5, 90_000)
    );
    assert_eq!(end.outcome, ServiceOutcome::MaxDuration);
    assert_eq!(setup.tcp.sessions_held(SERVICE), 0);
}

#[tokio::test]
async fn sessions_over_the_cap_of_a_service_are_refused_before_dialing() {
    assert_eq!(TCP_LIMITS.sessions_per_service, 256);
    let (address, accepted) = echo_server().await;
    let limits = TcpLimits {
        sessions_per_service: 2,
        ..TCP_LIMITS
    };
    let setup = setup(&announcement(Some(&address), None), limits);
    let (mut first, first_opened) = setup.connect("s-cap-1").await;
    echo_once(&mut first, b"one").await;
    let (mut second, _second_opened) = setup.connect("s-cap-2").await;
    echo_once(&mut second, b"two").await;

    let (mut third, third_opened) = setup.connect("s-cap-3").await;
    closed(&mut third).await;
    third_opened.finished().await;
    assert_eq!(
        setup.reason("s-cap-3"),
        ("service_limit".to_owned(), ServiceOutcome::UpstreamError)
    );
    assert_eq!(setup.tcp.sessions_held(SERVICE), 2);

    first.shutdown().await.unwrap();
    closed(&mut first).await;
    first_opened.finished().await;
    let (mut fourth, _fourth_opened) = setup.connect("s-cap-4").await;
    echo_once(&mut fourth, b"four").await;
    assert_eq!(accepted.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn dial_failures_pause_new_sessions_for_exactly_the_pause_and_a_success_resets_the_count() {
    assert_eq!(
        (TCP_LIMITS.failures_before_pause, TCP_LIMITS.failure_pause),
        (5, Duration::from_secs(5))
    );
    let logs = LogCapture::default();
    let _guard = logs.install();
    let (address, _) = echo_server().await;
    let script = Arc::new(Script::default());
    script.push(&[Step::Fail; 5]);
    let setup = scripted(
        &announcement(Some(&address), None),
        TCP_LIMITS,
        script.clone(),
        vec![approved(TCP, SERVICE)],
    );
    let clock = &setup.harness.clock;

    for attempt in 0..5 {
        assert_eq!(
            setup.refused(&format!("s-fail-{attempt}")).await,
            "upstream_error"
        );
    }
    assert_eq!(setup.refused("s-paused").await, "upstream_unavailable");
    clock.advance(TCP_LIMITS.failure_pause - Duration::from_millis(1));
    assert_eq!(setup.refused("s-almost").await, "upstream_unavailable");
    assert_eq!(script.dialed().len(), 5);
    clock.advance(Duration::from_millis(1));
    script.push(&[Step::Fail]);
    assert_eq!(setup.refused("s-retry").await, "upstream_error");
    assert_eq!(script.dialed().len(), 6);
    assert_eq!(
        setup.refused("s-paused-again").await,
        "upstream_unavailable"
    );

    clock.advance(TCP_LIMITS.failure_pause);
    let (mut client, opened) = setup.connect("s-recovered").await;
    echo_once(&mut client, b"back").await;
    client.shutdown().await.unwrap();
    closed(&mut client).await;
    opened.finished().await;
    script.push(&[Step::Fail]);
    assert_eq!(setup.refused("s-one-failure").await, "upstream_error");
    let (mut client, _opened) = setup.connect("s-dials-again").await;
    echo_once(&mut client, b"again").await;
    assert_eq!(script.dialed(), vec![address.clone(); 9]);

    let log = logs.text();
    assert!(
        log.contains("connecting to a TCP service failed") && log.contains("\"stage\":\"connect\""),
        "{log}"
    );
    assert!(log.contains("upstream_unavailable"), "{log}");
    assert!(!log.contains(&address), "{log}");
}

#[tokio::test]
async fn dial_timeouts_count_into_the_failure_budget() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let script = Arc::new(Script::default());
    script.push(&[Step::Hang; 5]);
    let setup = scripted(
        &announcement(Some("127.0.0.1:9"), None),
        TCP_LIMITS,
        script.clone(),
        vec![approved(TCP, SERVICE)],
    );
    let clock = &setup.harness.clock;
    for attempt in 0..5 {
        let session = format!("s-timeout-{attempt}");
        let (mut client, opened) = setup.connect(&session).await;
        wait_until("the dial to start", || script.dialed().len() == attempt + 1).await;
        let deadline = clock.now() + TCP_LIMITS.connect_timeout;
        clock.wait_for_sleeper(deadline).await;
        clock.set(deadline);
        closed(&mut client).await;
        opened.finished().await;
        assert_eq!(
            setup.reason(&session),
            ("upstream_error".to_owned(), ServiceOutcome::UpstreamError)
        );
    }
    assert_eq!(
        setup.refused("s-after-timeouts").await,
        "upstream_unavailable"
    );
    assert_eq!(script.dialed().len(), 5);
    let log = logs.text();
    assert!(log.contains("\"stage\":\"connect_timeout\""), "{log}");
}

#[tokio::test]
async fn a_dial_that_does_not_connect_in_time_fails_as_timed_out() {
    assert_eq!(TCP_LIMITS.connect_timeout, Duration::from_secs(10));
    let clock = ManualClock::new(SystemTime::now());
    let deadline = clock.now() + TCP_LIMITS.connect_timeout;
    let dialing = {
        let clock = clock.clone();
        tokio::spawn(async move {
            dial(
                std::future::pending::<std::io::Result<TcpStream>>(),
                &TCP_LIMITS,
                clock.as_ref(),
            )
            .await
            .map(drop)
        })
    };
    clock.wait_for_sleeper(deadline).await;
    clock.set(deadline - Duration::from_millis(1));
    still_running(&dialing).await;
    clock.set(deadline);
    assert_eq!(
        soon("the dial to time out", dialing).await.unwrap(),
        Err(DialFailure::TimedOut)
    );
}

#[tokio::test]
async fn each_service_reaches_only_its_own_address_and_an_unconfigured_name_reaches_none() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let (grafana, grafana_accepted) = echo_server().await;
    let (loki, loki_accepted) = echo_server().await;
    let local = ServiceAnnouncement {
        ssh_enabled: false,
        services: vec![
            declared("grafana", &grafana, Some(60)),
            declared("loki", &loki, Some(120)),
        ],
    };
    let script = Arc::new(Script::default());
    let setup = scripted(
        &local,
        TCP_LIMITS,
        script.clone(),
        vec![
            approved(TCP, "grafana"),
            approved(TCP, "loki"),
            approved(TCP, "orphan"),
        ],
    );
    let clock = &setup.harness.clock;
    let start = clock.now();

    let (mut first, _first) = setup.connect_to("grafana", "s-grafana", CLIENT).await;
    echo_once(&mut first, b"to grafana").await;
    clock
        .wait_for_sleeper(start + Duration::from_secs(60))
        .await;
    let (mut second, _second) = setup.connect_to("loki", "s-loki", CLIENT).await;
    echo_once(&mut second, b"to loki").await;
    clock
        .wait_for_sleeper(start + Duration::from_secs(120))
        .await;
    assert_eq!(script.dialed(), [grafana.clone(), loki.clone()]);

    let (mut orphan, opened) = setup.connect_to("orphan", "s-orphan", CLIENT).await;
    closed(&mut orphan).await;
    opened.finished().await;
    assert_eq!(
        setup.reason("s-orphan"),
        ("upstream_error".to_owned(), ServiceOutcome::UpstreamError)
    );
    assert_eq!(script.dialed().len(), 2);
    let (mut third, _third) = setup.connect_to("grafana", "s-grafana-2", CLIENT).await;
    echo_once(&mut third, b"again").await;
    assert_eq!(
        (
            grafana_accepted.load(Ordering::SeqCst),
            loki_accepted.load(Ordering::SeqCst)
        ),
        (2, 1)
    );
    let log = logs.text();
    assert!(
        log.contains("has no address in the agent configuration"),
        "{log}"
    );
    assert!(!log.contains(&grafana) && !log.contains(&loki), "{log}");
}

#[tokio::test]
async fn a_broken_side_ends_the_session_with_the_side_that_failed() {
    let (address, listener) = manual_upstream().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);

    let (mut client, opened) = setup.connect("s-client-gone").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    echo_through(&mut client, &mut upstream).await;
    drop(client);
    opened.finished().await;
    assert_eq!(
        setup.reason("s-client-gone"),
        ("client_error".to_owned(), ServiceOutcome::ProtocolError)
    );

    let (mut client, opened) = setup.connect("s-upstream-reset").await;
    let (mut upstream, _) = soon("the upstream", listener.accept()).await.unwrap();
    echo_through(&mut client, &mut upstream).await;
    upstream.set_zero_linger().unwrap();
    drop(upstream);
    closed(&mut client).await;
    opened.finished().await;
    assert_eq!(
        setup.reason("s-upstream-reset"),
        ("upstream_error".to_owned(), ServiceOutcome::UpstreamError)
    );
}

async fn echo_through(client: &mut TlsStream<DuplexStream>, upstream: &mut TcpStream) {
    client.write_all(b"q").await.unwrap();
    client.flush().await.unwrap();
    let mut one = [0_u8; 1];
    soon("the client byte", upstream.read_exact(&mut one))
        .await
        .unwrap();
    upstream.write_all(b"a").await.unwrap();
    soon("the upstream byte", client.read_exact(&mut one))
        .await
        .unwrap();
}

#[tokio::test]
async fn the_upstream_socket_has_tcp_keepalive() {
    let (address, _) = echo_server().await;
    let clock = ManualClock::new(SystemTime::now());
    let stream = dial(TcpStream::connect(&address), &TCP_LIMITS, clock.as_ref())
        .await
        .unwrap();
    assert!(sockopt::socket_keepalive(&stream).unwrap());
    assert!(sockopt::tcp_nodelay(&stream).unwrap());
    assert_eq!(
        (
            sockopt::tcp_keepidle(&stream).unwrap(),
            sockopt::tcp_keepintvl(&stream).unwrap(),
            sockopt::tcp_keepcnt(&stream).unwrap(),
        ),
        (Duration::from_secs(60), Duration::from_secs(20), 3)
    );
}

#[test]
fn a_long_client_address_is_cut_to_the_audit_limit_at_a_character_boundary() {
    assert_eq!(CLIENT_ADDR_BYTES, 64);
    for (address, kept) in [
        (CLIENT.to_owned(), CLIENT.len()),
        ("1".repeat(128), 64),
        (format!("{}\u{e9}", "1".repeat(63)), 63),
    ] {
        let cut = bounded(&address, CLIENT_ADDR_BYTES);
        assert_eq!(cut.len(), kept, "{address}");
        assert!(address.starts_with(&cut));
    }
}

#[tokio::test]
async fn a_long_client_address_reaches_the_start_event_cut_to_the_audit_limit() {
    let (address, _) = echo_server().await;
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    let long = format!("[{}]:40000", "f".repeat(120));
    assert_eq!(long.len(), jaunt_tunnel::MAX_CLIENT_ADDRESS_LEN);
    let (mut client, opened) = setup.connect_to(SERVICE, "s-long-client", &long).await;
    client.shutdown().await.unwrap();
    closed(&mut client).await;
    opened.finished().await;
    let events = setup.events("s-long-client");
    assert_eq!(
        events[0].fields.get("client_addr"),
        Some(&AgentEventValue::Text(long[..CLIENT_ADDR_BYTES].to_owned()))
    );
}

fn ledger_session(harness: &Harness, session_id: &str) -> ServiceSession {
    ServiceSession {
        session_id: session_id.to_owned(),
        service: ServiceName::new(SERVICE).unwrap(),
        cancel: CancellationToken::new(),
        events: harness.events.session(session_id),
    }
}

async fn end_reason(harness: &Harness, session_id: &str) -> String {
    let deadline = harness.clock.now() + Duration::from_secs(3600);
    assert!(soon("the events", harness.events.flush(session_id, deadline)).await);
    let events = events_of(harness, session_id);
    let names: Vec<&str> = events.iter().map(|event| event.name.as_str()).collect();
    assert_eq!(
        names,
        ["tcp.session.start", "tcp.session.end"],
        "{session_id}"
    );
    text(&events[1].fields, "reason")
}

#[tokio::test]
async fn an_aborted_session_reports_cancelled_or_max_duration_and_a_panic_an_upstream_error() {
    let harness = Harness::new();
    for (session_id, cancelled, expected) in [
        ("s-abort-cancelled", true, "cancelled"),
        ("s-abort-deadline", false, "max_duration"),
    ] {
        let session = ledger_session(&harness, session_id);
        let cancel = session.cancel.clone();
        let clock: Arc<dyn Clock> = harness.clock.clone();
        let emitted = harness.events.counters().emitted;
        let task = tokio::spawn(async move {
            let _ledger = Ledger::open(clock, &session, CLIENT);
            std::future::pending::<()>().await;
        });
        wait_until("the ledger to open", || {
            harness.events.counters().emitted > emitted
        })
        .await;
        if cancelled {
            cancel.cancel();
        }
        task.abort();
        assert!(
            soon("the aborted task", task)
                .await
                .unwrap_err()
                .is_cancelled()
        );
        assert_eq!(end_reason(&harness, session_id).await, expected);
    }

    let session = ledger_session(&harness, "s-panic");
    let clock: Arc<dyn Clock> = harness.clock.clone();
    let panicked = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ledger = Ledger::open(clock, &session, CLIENT);
        panic!("the handler fails on purpose");
    }));
    assert!(panicked.is_err());
    assert_eq!(end_reason(&harness, "s-panic").await, "upstream_error");

    let mut closed_once = Ledger::open(
        harness.clock.clone(),
        &ledger_session(&harness, "s-once"),
        CLIENT,
    );
    closed_once.close(EndReason::Closed);
    drop(closed_once);
    assert_eq!(end_reason(&harness, "s-once").await, "closed");
}

#[test]
fn the_agent_registers_the_tcp_handler() {
    let handlers = crate::run::service_handlers(
        &announcement(Some("127.0.0.1:1"), None),
        ManualClock::new(SystemTime::now()),
    )
    .unwrap();
    assert!(handlers.get(TCP).is_some());
}

#[tokio::test]
async fn an_ipv6_address_is_dialed_as_configured() {
    let Ok(listener) = TcpListener::bind("[::1]:0").await else {
        eprintln!("skipped: ::1 cannot be bound on this host");
        return;
    };
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(echo_on(listener, Arc::new(AtomicUsize::new(0))));
    let setup = setup(&announcement(Some(&address), None), TCP_LIMITS);
    let (mut client, _opened) = setup.connect("s-ipv6").await;
    echo_once(&mut client, b"over ipv6").await;
}
