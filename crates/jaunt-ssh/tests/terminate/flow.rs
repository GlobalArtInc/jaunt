use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use russh::ChannelMsg;

use crate::sshd::{SshdOptions, SshdStats};
use russh::client;
use tokio_util::sync::CancellationToken;

use crate::support::{
    Fixture, LOGIN, OUTPUT_WINDOW, Options, TRANSPORT, Tap, alive_tasks, transcript, until,
};

const CHUNK: usize = 32 * 1024;
const CYCLE: usize = 251;
const DEADLINE: Duration = Duration::from_secs(60);

fn pattern_table() -> Arc<Vec<u8>> {
    Arc::new(
        (0..CYCLE + 2 * CHUNK)
            .map(|index| u8::try_from(index % CYCLE).unwrap())
            .collect(),
    )
}

fn slice(table: &[u8], offset: usize, len: usize) -> &[u8] {
    let start = offset % CYCLE;
    &table[start..start + len]
}

async fn echo_through_a_slow_reader(total: usize, pause_every: usize) -> Duration {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let channel = client.exec("cat").await;
    let (mut read_half, write_half) = channel.split();
    let table = pattern_table();
    let source = Arc::clone(&table);
    let started = Instant::now();
    let writer = tokio::spawn(async move {
        for offset in (0..total).step_by(CHUNK) {
            let chunk = Bytes::copy_from_slice(slice(&source, offset, CHUNK));
            write_half.data_bytes(chunk).await.unwrap();
        }
        write_half.eof().await.unwrap();
        write_half
    });
    let mut received = 0;
    let mut messages = 0;
    let reading = async {
        while let Some(message) = read_half.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    assert_eq!(data.as_ref(), slice(&table, received, data.len()));
                    received += data.len();
                    messages += 1;
                    if messages % pause_every == 0 {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
                ChannelMsg::Eof => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(DEADLINE, reading)
        .await
        .expect("the bridge deadlocked");
    let elapsed = started.elapsed();
    assert_eq!(received, total);
    writer.await.unwrap();
    let outcome = client.finish().await;
    assert_eq!(outcome.bytes_in, u64::try_from(total).unwrap());
    assert_eq!(outcome.bytes_out, u64::try_from(total).unwrap());
    assert_eq!(fixture.authority.ends().len(), 1);
    elapsed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_64_mib_echo_with_a_slow_reader_does_not_deadlock_the_two_hops() {
    let elapsed = echo_through_a_slow_reader(64 * 1024 * 1024, 1).await;
    eprintln!("64 MiB echo through both hops: {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_256_mib_echo_with_a_slow_reader_does_not_deadlock_the_two_hops() {
    let elapsed = echo_through_a_slow_reader(256 * 1024 * 1024, 4).await;
    eprintln!("256 MiB echo through both hops: {elapsed:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_program_holds_the_user_at_the_two_windows_until_the_user_closes() {
    let sshd_window = 1024 * 1024;
    let outer_window = 2 * 1024 * 1024;
    let fixture = Fixture::new(Options {
        sshd: SshdOptions {
            window: u32::try_from(sshd_window).unwrap(),
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let baseline = alive_tasks();
    let channel = client.exec("stall").await;
    let (_read_half, write_half) = channel.split();
    let write_half = Arc::new(write_half);
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let pushing = Arc::clone(&write_half);
    let writer = tokio::spawn(async move {
        for _ in 0..512 {
            pushing
                .data_bytes(Bytes::from(vec![1u8; CHUNK]))
                .await
                .unwrap();
            counter.fetch_add(CHUNK, Ordering::SeqCst);
        }
    });
    let stats = Arc::clone(&fixture.sshd.stats);
    until("sshd received its whole window", || {
        SshdStats::count(&stats.stalled) == sshd_window
    })
    .await;
    until("the client filled the agent window", || {
        sent.load(Ordering::SeqCst) >= outer_window + sshd_window / 2
    })
    .await;
    let plateau = sent.load(Ordering::SeqCst);
    assert!(
        plateau <= outer_window + sshd_window,
        "{plateau} bytes left the client"
    );
    assert_eq!(SshdStats::count(&stats.stalled), sshd_window);
    assert!(!writer.is_finished());
    writer.abort();
    let closed_at = Instant::now();
    write_half.close().await.unwrap();
    until("sshd saw the channel close", || {
        SshdStats::count(&stats.closes) == 1
    })
    .await;
    assert!(closed_at.elapsed() < Duration::from_secs(2));
    until("the bridge tasks ended", || alive_tasks() <= baseline).await;
    let outcome = client.finish().await;
    assert!(outcome.authorized);
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tunnel_stream_carries_only_ciphertext() {
    let fixture = Fixture::new(Options::default()).await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let serve = fixture.serve_on(
        Tap::new(agent_io, Arc::clone(&seen)),
        CancellationToken::new(),
    );
    let mut client = fixture
        .connect_over(client_io, serve, client::Config::default())
        .await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    let marker = b"jaunt-plaintext-marker-5f3c9a";
    let mut channel = client.exec("cat").await;
    channel.data(&marker[..]).await.unwrap();
    channel.eof().await.unwrap();
    assert_eq!(transcript(&mut channel).await.stdout, marker);
    client.finish().await;
    let seen = seen.lock().unwrap();
    assert!(seen.len() > 1000);
    assert!(!seen.windows(marker.len()).any(|window| window == marker));
    let alice = b"alice@example.com";
    assert!(!seen.windows(alice.len()).any(|window| window == alice));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_close_reaches_sshd_while_its_output_is_blocked() {
    let fixture = Fixture::new(Options::default()).await;
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let serve = fixture.serve_on(agent_io, CancellationToken::new());
    let unread = client::Config {
        window_size: 1,
        ..client::Config::default()
    };
    let mut client = fixture.connect_over(client_io, serve, unread).await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    let stats = &fixture.sshd.stats;
    for round in 1..=5 {
        let before = SshdStats::count(&stats.written);
        let channel = client.exec("flood 8").await;
        until("sshd output is blocked", || {
            SshdStats::count(&stats.written) >= before + OUTPUT_WINDOW
        })
        .await;
        channel.close().await.unwrap();
        until("sshd saw the close", || {
            SshdStats::count(&stats.closes) == round
        })
        .await;
    }
    client.finish().await;
}
