use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use jaunt_proto::SessionPermissions;
use jaunt_ssh::{EndReason, OutputStream, SessionOutcome};
use russh::client;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::sshd::{LoginMode, SshdOptions, SshdStats};
use crate::support::{
    Client, Decision, Event, Fixture, LOGIN, Options, Severable, TRANSPORT, permissions,
    read_until, reply, transcript, until,
};

#[tokio::test(flavor = "multi_thread")]
async fn the_time_limit_warns_on_stderr_disconnects_and_ends_once() {
    let fixture = Fixture::new(Options {
        decision: Decision::Allow(SessionPermissions {
            max_duration_secs: 1,
            ..permissions()
        }),
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = client.exec("cat").await;
    let seen = transcript(&mut channel).await;
    assert_eq!(seen.stderr, b"jaunt: session time limit reached\r\n");
    let disconnect = Arc::clone(&client.seen);
    until("the user was disconnected", || {
        disconnect.disconnect.lock().unwrap().is_some()
    })
    .await;
    assert_eq!(
        disconnect.disconnect.lock().unwrap().as_deref(),
        Some("jaunt: session time limit reached")
    );
    let outcome = client.outcome().await;
    assert_eq!(outcome.reason, EndReason::TimeLimit);
    assert_eq!(fixture.authority.ends().len(), 1);
    until("the inner connection closed", || {
        SshdStats::count(&fixture.sshd.stats.live) == 0
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_stream_frees_a_pump_stuck_on_the_user_window_and_leaves_no_task() {
    let fixture = Fixture::new(Options::default()).await;
    let cut = CancellationToken::new();
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let (serve, leftover) = fixture.serve_apart(Severable::new(agent_io, &cut));
    let unread = client::Config {
        window_size: 1,
        ..client::Config::default()
    };
    let mut client = fixture.connect_over(client_io, serve, unread).await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    let _channel = client.exec("echo hello").await;
    until("the output pump waits for the user window", || {
        fixture
            .events()
            .iter()
            .any(|event| matches!(event, Event::Output(_, OutputStream::Stdout, 6)))
    })
    .await;
    let started = Instant::now();
    cut.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(1), &mut client.serve)
        .await
        .expect("the bridge outlived its stream by a second")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(outcome.reason, EndReason::TransportFailed);
    assert_eq!(leftover.get(), Some(&0));
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn no_task_outlives_serve() {
    let fixture = Fixture::new(Options::default()).await;
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let (serve, leftover) = fixture.serve_apart(agent_io);
    let mut client = fixture
        .connect_over(client_io, serve, client::Config::default())
        .await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    let mut channel = client.exec("cat").await;
    channel.data(&b"x"[..]).await.unwrap();
    read_until(&mut channel, "x").await;
    let outcome = client.finish().await;
    assert_eq!(outcome.reason, EndReason::ClientClosed);
    assert_eq!(leftover.get(), Some(&0));
}

fn end_calls(fixture: &Fixture) -> usize {
    fixture.authority.end_calls.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_serve_aborted_inside_the_drain_still_reports_the_end_once() {
    let fixture = Fixture::new(Options {
        slow_observer: true,
        skip_outputs: 1,
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = client.exec("cat").await;
    channel.data(&b"x"[..]).await.unwrap();
    read_until(&mut channel, "x").await;
    channel.data(&b"y"[..]).await.unwrap();
    until("the output pump is held inside the observer", || {
        fixture.stalled.load(Ordering::SeqCst)
    })
    .await;
    client.cancel.cancel();
    until("the agent dropped the transport and is draining", || {
        client.handle.is_closed()
    })
    .await;
    assert!(!client.serve.is_finished());
    assert_eq!(end_calls(&fixture), 0);
    client.serve.abort();
    until("the end was reported", || {
        fixture.authority.ends().len() == 1
    })
    .await;
    assert_eq!(end_calls(&fixture), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_serve_aborted_while_the_end_is_in_flight_still_delivers_it() {
    let fixture = Fixture::new(Options {
        end_delay: Duration::from_millis(600),
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let _channel = client.exec("echo hello").await;
    client
        .handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    until("session_end is in flight", || end_calls(&fixture) == 1).await;
    assert!(fixture.authority.ends().is_empty());
    client.serve.abort();
    until("the end was delivered", || {
        fixture.authority.ends().len() == 1
    })
    .await;
    assert_eq!(end_calls(&fixture), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_observer_ends_the_session_with_an_incomplete_recording() {
    let fixture = Fixture::new(Options {
        panic_on_output: true,
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = client.exec("echo hello").await;
    transcript(&mut channel).await;
    let outcome = client.outcome().await;
    assert_eq!(outcome.reason, EndReason::ObserverFailed);
    let ends = fixture.authority.ends();
    assert_eq!(ends.len(), 1);
    assert!(ends[0].recording_incomplete);
}

#[tokio::test(flavor = "multi_thread")]
async fn input_the_observer_failed_on_never_reaches_sshd() {
    let fixture = Fixture::new(Options {
        panic_on_input: true,
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let channel = client.exec("stall").await;
    channel.data(&b"secret"[..]).await.unwrap();
    let outcome = client.outcome().await;
    assert_eq!(outcome.reason, EndReason::ObserverFailed);
    assert_eq!(outcome.bytes_in, 0);
    assert_eq!(SshdStats::count(&fixture.sshd.stats.stalled), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_node_closing_the_inner_connection_disconnects_the_user() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    channel.exec(true, "crash").await.unwrap();
    assert!(!reply(&mut channel).await);
    let seen = Arc::clone(&client.seen);
    until("the user was disconnected", || {
        seen.disconnect.lock().unwrap().is_some()
    })
    .await;
    assert_eq!(
        seen.disconnect.lock().unwrap().as_deref(),
        Some("jaunt: the node closed the session")
    );
    let outcome = client.outcome().await;
    assert_eq!(outcome.reason, EndReason::NodeClosed);
    assert_eq!(fixture.authority.ends().len(), 1);
}

fn login_in_background(
    fixture: &Fixture,
    client: Client,
) -> (JoinHandle<SessionOutcome>, CancellationToken) {
    let Client {
        mut handle,
        serve,
        cancel,
        key,
        ..
    } = client;
    let cert = fixture.cert.clone();
    tokio::spawn(async move {
        let attempt = handle.authenticate_openssh_cert(LOGIN, key, cert).await;
        (attempt.is_ok_and(|result| result.success()), handle)
    });
    (serve, cancel)
}

async fn cancel_promptly(
    serve: JoinHandle<SessionOutcome>,
    cancel: CancellationToken,
) -> SessionOutcome {
    let started = Instant::now();
    cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(3), serve)
        .await
        .expect("serve ignored the cancellation")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(outcome.reason, EndReason::Cancelled);
    outcome
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_during_authorize_ends_serve_without_a_session_end() {
    let fixture = Fixture::new(Options {
        decision: Decision::Hang,
        ..Options::default()
    })
    .await;
    let (serve, cancel) = login_in_background(&fixture, fixture.connect().await);
    until("authorize is pending", || {
        fixture.authority.requests().len() == 1
    })
    .await;
    let outcome = cancel_promptly(serve, cancel).await;
    assert!(!outcome.authorized);
    assert!(fixture.authority.ends().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_during_the_inner_login_ends_serve_and_reports_once() {
    let fixture = Fixture::new(Options {
        sshd: SshdOptions {
            login: LoginMode::Stall,
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let (serve, cancel) = login_in_background(&fixture, fixture.connect().await);
    until("the inner login is pending", || {
        SshdStats::count(&fixture.sshd.stats.attempts) == 1
    })
    .await;
    let outcome = cancel_promptly(serve, cancel).await;
    assert!(outcome.authorized);
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_during_an_sshd_reply_ends_serve_and_reports_once() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let channel = client.open().await;
    channel.exec(true, "hang").await.unwrap();
    until("sshd holds the reply", || {
        fixture
            .sshd
            .stats
            .requests()
            .contains(&"exec:hang".to_owned())
    })
    .await;
    cancel_promptly(client.serve, client.cancel).await;
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_never_logs_in_is_cut_at_the_login_deadline() {
    let fixture = Fixture::new(Options::default()).await;
    let (_silent, agent_io) = tokio::io::duplex(TRANSPORT);
    let serve = fixture.serve_on(agent_io, CancellationToken::new());
    let outcome = tokio::time::timeout(Duration::from_secs(60), serve.task)
        .await
        .expect("the login deadline never fired")
        .unwrap();
    assert_eq!(outcome.reason, EndReason::LoginTimeout);
    assert!(!outcome.authorized);
}
