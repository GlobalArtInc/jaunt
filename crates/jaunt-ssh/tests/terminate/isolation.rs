use std::time::{Duration, Instant};

use jaunt_ssh::{ChannelExit, ChannelProgram, ChannelStart};
use russh::{Channel, ChannelMsg, client};
use tokio_util::sync::CancellationToken;

use crate::sshd::SshdStats;
use crate::support::{
    Client, Event, Fixture, LOGIN, OUTPUT_WINDOW, Options, STEP, TRANSPORT, TestClient, read_until,
    reply, transcript, until,
};

const PROMPT: Duration = Duration::from_secs(2);
const MIB: usize = 1024 * 1024;

async fn granting_client(fixture: &Fixture, window: u32) -> Client {
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let serve = fixture.serve_on(agent_io, CancellationToken::new());
    let config = client::Config {
        window_size: window,
        manual_window: true,
        ..client::Config::default()
    };
    let mut client = fixture.connect_over(client_io, serve, config).await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    client
}

#[derive(Debug, Default)]
struct Drained {
    bytes: usize,
    exit_status: Option<u32>,
}

async fn drain_granting(
    handle: &client::Handle<TestClient>,
    channel: &mut Channel<client::Msg>,
    pause: Option<Duration>,
    stop: &CancellationToken,
) -> Drained {
    let mut seen = Drained::default();
    let id = channel.id();
    loop {
        let message = tokio::select! {
            () = stop.cancelled() => return seen,
            message = tokio::time::timeout(STEP, channel.wait()) => {
                message.expect("the channel went silent")
            }
        };
        match message {
            Some(ChannelMsg::Data { data }) => {
                seen.bytes += data.len();
                if let Some(pause) = pause {
                    tokio::time::sleep(pause).await;
                }
                handle
                    .grant_window(id, u32::try_from(data.len()).unwrap())
                    .unwrap();
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => seen.exit_status = Some(exit_status),
            Some(ChannelMsg::Close) | None => return seen,
            Some(_) => {}
        }
    }
}

async fn messages(channel: &mut Channel<client::Msg>) -> Vec<String> {
    let mut seen = Vec::new();
    let reading = async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => seen.push("success".to_owned()),
                Some(ChannelMsg::Failure) => seen.push("failure".to_owned()),
                Some(ChannelMsg::Data { data }) => {
                    seen.push(format!("data:{}", String::from_utf8_lossy(&data)))
                }
                Some(ChannelMsg::Eof) => seen.push("eof".to_owned()),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    seen.push(format!("exit:{exit_status}"))
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(STEP, reading)
        .await
        .expect("the channel never closed");
    seen
}

#[tokio::test(flavor = "multi_thread")]
async fn pipelined_requests_get_their_replies_in_order_and_the_command_runs() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.set_env(false, "LANG", "C.UTF-8").await.unwrap();
    channel.exec(true, "echo ok").await.unwrap();
    assert_eq!(
        messages(&mut channel).await,
        ["success", "success", "data:ok\n", "eof", "exit:0"]
    );
    assert_eq!(
        fixture.sshd.stats.requests(),
        ["pty", "env:LANG", "exec:echo ok"]
    );
    client.finish().await;
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_channel_gets_a_terminal_promptly_while_the_first_floods_a_slow_reader() {
    let fixture = Fixture::new(Options::default()).await;
    let client = granting_client(&fixture, 64 * 1024).await;
    let mut flooding = client.exec("flood 64").await;
    let stats = &fixture.sshd.stats;
    let stop = CancellationToken::new();
    let slow = drain_granting(
        &client.handle,
        &mut flooding,
        Some(Duration::from_millis(10)),
        &stop,
    );
    let second = async {
        until("the flood backs up behind the slow reader", || {
            SshdStats::count(&stats.written) >= 2 * OUTPUT_WINDOW
        })
        .await;
        let started = Instant::now();
        let mut terminal = client.open().await;
        terminal
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        assert!(reply(&mut terminal).await);
        let replied = started.elapsed();
        terminal.request_shell(true).await.unwrap();
        assert!(reply(&mut terminal).await);
        terminal.data(&b"hi\n"[..]).await.unwrap();
        let echoed = read_until(&mut terminal, "hi").await;
        let finished = started.elapsed();
        stop.cancel();
        (replied, finished, echoed)
    };
    let (flooded, (replied, finished, echoed)) = tokio::join!(slow, second);
    assert!(replied < PROMPT, "the terminal reply took {replied:?}");
    assert!(finished < PROMPT, "the terminal echo took {finished:?}");
    assert!(echoed.starts_with("pty xterm 80x24\r\n"), "{echoed:?}");
    assert!(flooded.bytes < 64 * MIB);
    client.finish().await;
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_channel_without_any_window_neither_blocks_another_nor_loses_its_output() {
    let fixture = Fixture::new(Options::default()).await;
    let client = granting_client(&fixture, 4 * 1024).await;
    let mut stuck = client.exec("floodsmall 8").await;
    let stats = &fixture.sshd.stats;
    until(
        "sshd filled the agent window of the stuck channel in small packets",
        || SshdStats::count(&stats.written) >= OUTPUT_WINDOW,
    )
    .await;
    let started = Instant::now();
    let mut quick = client.exec("echo ok").await;
    let seen = transcript(&mut quick).await;
    let elapsed = started.elapsed();
    assert_eq!(
        (seen.stdout.as_slice(), seen.exit_status),
        (&b"ok\n"[..], Some(0))
    );
    assert!(elapsed < PROMPT, "the second channel took {elapsed:?}");
    let drained = drain_granting(&client.handle, &mut stuck, None, &CancellationToken::new()).await;
    assert_eq!(drained.bytes, 8 * MIB);
    assert_eq!(drained.exit_status, Some(0));
    let outcome = client.finish().await;
    assert_eq!(outcome.bytes_out, u64::try_from(8 * MIB + 3).unwrap());
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_exit_status_counts_when_the_user_leaves_before_reading_the_output() {
    let fixture = Fixture::new(Options::default()).await;
    let client = granting_client(&fixture, 4 * 1024).await;
    let spilled = client.exec("spill 512 7").await;
    let number = spilled.id().number();
    let stats = &fixture.sshd.stats;
    until("sshd sent the exit status and closed", || {
        SshdStats::count(&stats.finished) == 1
    })
    .await;
    let mut barrier = client.open().await;
    barrier
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut barrier).await);
    let outcome = client.finish().await;
    assert_eq!(outcome.exit_status, Some(7));
    assert!(outcome.bytes_out < 512 * 1024, "{}", outcome.bytes_out);
    let ends = fixture.authority.ends();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].exit_status, Some(7));
    let events = fixture.events();
    let started = events.iter().position(|event| {
        *event
            == Event::Start(
                number,
                ChannelStart {
                    program: ChannelProgram::Exec(b"spill 512 7".to_vec()),
                    terminal: None,
                },
            )
    });
    let ended = events
        .iter()
        .position(|event| *event == Event::End(number, ChannelExit::Status(7)));
    assert!(
        matches!((started, ended), (Some(start), Some(end)) if start < end),
        "{events:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sshd_writes_at_most_the_output_window_while_the_user_grants_nothing() {
    let fixture = Fixture::new(Options::default()).await;
    let client = granting_client(&fixture, 0).await;
    let _stuck = client.exec("flood 8").await;
    let stats = &fixture.sshd.stats;
    until("sshd filled the agent window", || {
        SshdStats::count(&stats.written) >= OUTPUT_WINDOW
    })
    .await;
    let mut barrier = client.open().await;
    barrier
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut barrier).await);
    let written = SshdStats::count(&stats.written);
    assert!(
        written <= OUTPUT_WINDOW + 64 * 1024,
        "sshd wrote {written} bytes with no window from the user"
    );
    client.finish().await;
    assert_eq!(fixture.authority.ends().len(), 1);
}
