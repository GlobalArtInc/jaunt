use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use jaunt_ssh::{AgentLimits, EndReason, ForwardTarget};
use russh::{Channel, ChannelMsg, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::sshd::{SshdOptions, SshdStats};
use crate::support::{
    CLIENT_ADDR, Client, Decision, Event, Fixture, Options, STEP, alive_tasks, forwarding,
    read_until, transcript, until,
};

const NOT_PERMITTED: &str = "jaunt: port forwarding is not allowed by your roles";
const LOOPBACK_ONLY: &str = "jaunt: forwarding is limited to localhost on the node";
const TOO_MANY: &str = "jaunt: too many open sessions";

#[derive(Clone, Copy)]
enum Behaviour {
    Echo,
    Banner,
}

struct Service {
    addr: SocketAddr,
    live: Arc<AtomicUsize>,
    received: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Service {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Service {
    async fn start(behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(AtomicUsize::new(0));
        let counters = (Arc::clone(&live), Arc::clone(&received));
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (live, received) = (Arc::clone(&counters.0), Arc::clone(&counters.1));
                live.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    serve(tcp, behaviour, &received).await;
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            addr,
            live,
            received,
            task,
        }
    }

    fn port(&self) -> u32 {
        u32::from(self.addr.port())
    }

    fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }
}

async fn serve(mut tcp: TcpStream, behaviour: Behaviour, received: &AtomicUsize) {
    let (mut reader, mut writer) = tcp.split();
    if let Behaviour::Banner = behaviour {
        let _ = writer.write_all(b"banner\n").await;
        let _ = writer.shutdown().await;
    }
    let mut buffer = vec![0; 64 * 1024];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                received.fetch_add(read, Ordering::SeqCst);
                if let Behaviour::Echo = behaviour
                    && writer.write_all(&buffer[..read]).await.is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

fn with_forwarding() -> Options {
    Options {
        decision: Decision::Allow(forwarding()),
        ..Options::default()
    }
}

async fn forward(
    client: &Client,
    host: &str,
    port: u32,
) -> Result<Channel<client::Msg>, russh::Error> {
    tokio::time::timeout(
        STEP,
        client
            .handle
            .channel_open_direct_tcpip(host, port, "127.0.0.1", 50000),
    )
    .await
    .expect("the forward open hung")
}

async fn reopen(client: &Client, port: u32) -> Channel<client::Msg> {
    let deadline = Instant::now() + STEP;
    loop {
        if let Ok(channel) = forward(client, "localhost", port).await {
            return channel;
        }
        assert!(
            Instant::now() < deadline,
            "the forward slot was never freed"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn ended(channel: &mut Channel<client::Msg>) {
    let closing = async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(STEP, closing)
        .await
        .expect("the channel never closed");
}

async fn refusals(client: &Client, count: usize) -> (Vec<String>, Vec<u32>) {
    until("the open failures arrived", || {
        client.seen.open_codes.lock().unwrap().len() == count
    })
    .await;
    (
        client.seen.open_failures.lock().unwrap().clone(),
        client.seen.open_codes.lock().unwrap().clone(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_permitted_forward_reaches_the_loopback_service_through_sshd() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let port = service.port();
    let message = b"ping through the node";
    let mut asked = Vec::new();
    for (host, seen_by_sshd) in [
        ("localhost", "localhost"),
        ("LOCALHOST.", "localhost"),
        ("127.0.0.1", "127.0.0.1"),
    ] {
        let mut channel = forward(&client, host, port).await.unwrap();
        channel.data(&message[..]).await.unwrap();
        channel.eof().await.unwrap();
        let seen = transcript(&mut channel).await;
        assert_eq!(seen.stdout, message, "{host}");
        assert_eq!(seen.order, ["eof"], "{host}");
        asked.push(format!("direct-tcpip:{seen_by_sshd}:{port}"));
    }
    let outcome = client.finish().await;
    let total = u64::try_from(3 * message.len()).unwrap();
    assert_eq!((outcome.bytes_in, outcome.bytes_out), (total, total));
    assert_eq!(fixture.sshd.stats.requests(), asked);
    assert_eq!(fixture.authority.ends()[0].bytes_in, total);
    let client_ip = CLIENT_ADDR.split(':').next().unwrap().to_owned();
    assert_eq!(
        *fixture.sshd.stats.originators.lock().unwrap(),
        vec![(client_ip, 0); 3]
    );
    let events = fixture.events();
    let opened: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::ForwardOpen(number, target) => Some((*number, target.clone())),
            _ => None,
        })
        .collect();
    let closed: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::ForwardClose(number) => Some(*number),
            _ => None,
        })
        .collect();
    assert_eq!(opened.len(), 3);
    assert_eq!(
        opened[2].1,
        ForwardTarget {
            host: "127.0.0.1".to_owned(),
            port: u16::try_from(port).unwrap(),
        }
    );
    let mut opened_numbers: Vec<_> = opened.iter().map(|(number, _)| *number).collect();
    let mut closed_numbers = closed.clone();
    opened_numbers.sort_unstable();
    closed_numbers.sort_unstable();
    assert_eq!(opened_numbers, closed_numbers);
    assert!(
        events
            .iter()
            .all(|event| !matches!(event, Event::Input(..) | Event::Output(..)))
    );
    assert_eq!(events.last(), Some(&Event::Finish));
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_without_the_permission_or_off_the_loopback_never_reach_sshd() {
    let service = Service::start(Behaviour::Echo).await;
    let denied = Fixture::new(Options::default()).await;
    let client = denied.login().await;
    assert!(forward(&client, "localhost", service.port()).await.is_err());
    assert!(forward(&client, "10.0.0.1", 80).await.is_err());
    assert_eq!(
        refusals(&client, 2).await,
        (vec![NOT_PERMITTED.to_owned(); 2], vec![1, 1])
    );
    client.finish().await;
    assert!(denied.sshd.stats.requests().is_empty());

    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let targets = [
        ("10.0.0.1", 80),
        ("node1.jaunt.test", 22),
        ("localhost.localdomain", 80),
        ("0:0:0:0:0:0:0:1", 80),
        ("::ffff:127.0.0.1", 80),
        ("127.0.0.1.", 80),
        ("localhost", 0),
        ("localhost", 70_000),
    ];
    for (host, port) in targets {
        assert!(forward(&client, host, port).await.is_err(), "{host}:{port}");
    }
    let (texts, codes) = refusals(&client, targets.len()).await;
    assert!(texts.iter().all(|text| text == LOOPBACK_ONLY), "{texts:?}");
    assert!(codes.iter().all(|code| *code == 1), "{codes:?}");
    assert_eq!(service.live(), 0);
    client.finish().await;
    assert!(fixture.sshd.stats.requests().is_empty());
}

fn with_one_forward(sshd: SshdOptions) -> Options {
    Options {
        sshd,
        limits: AgentLimits {
            max_forwards: 1,
            ..AgentLimits::default()
        },
        ..with_forwarding()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_by_sshd_reaches_the_user_with_its_kind_and_frees_the_slot() {
    let fixture = Fixture::new(with_one_forward(SshdOptions {
        refuse_forwards: true,
        ..SshdOptions::default()
    }))
    .await;
    let client = fixture.login().await;
    for _ in 0..5 {
        assert!(forward(&client, "localhost", 8080).await.is_err());
    }
    assert_eq!(refusals(&client, 5).await.1, [1; 5]);
    let mut channel = client.exec("echo still-works").await;
    assert_eq!(transcript(&mut channel).await.stdout, b"still-works\n");
    client.finish().await;

    let closed_port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        u32::from(listener.local_addr().unwrap().port())
    };
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    assert!(forward(&client, "127.0.0.1", closed_port).await.is_err());
    assert_eq!(refusals(&client, 1).await.1, [2]);
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn forwards_are_limited_and_a_closed_one_frees_its_slot() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_forwards: 2,
            ..AgentLimits::default()
        },
        ..with_forwarding()
    })
    .await;
    let client = fixture.login().await;
    let first = forward(&client, "localhost", service.port()).await.unwrap();
    let _second = forward(&client, "localhost", service.port()).await.unwrap();
    assert!(forward(&client, "localhost", service.port()).await.is_err());
    assert_eq!(
        refusals(&client, 1).await,
        (vec![TOO_MANY.to_owned()], vec![4])
    );
    let _session = client.exec("cat").await;
    first.close().await.unwrap();
    let deadline = Instant::now() + STEP;
    let mut third = loop {
        if let Ok(channel) = forward(&client, "localhost", service.port()).await {
            break channel;
        }
        assert!(
            Instant::now() < deadline,
            "the closed forward kept its slot"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    third.data(&b"third"[..]).await.unwrap();
    assert_eq!(read_until(&mut third, "third").await, "third");
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forward_closed_by_the_service_frees_its_slot_without_a_user_close() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_one_forward(SshdOptions::default())).await;
    let client = fixture.login().await;
    let mut first = forward(&client, "localhost", service.port()).await.unwrap();
    first.data(&b"once"[..]).await.unwrap();
    first.eof().await.unwrap();
    ended(&mut first).await;
    let mut second = reopen(&client, service.port()).await;
    second.data(&b"twice"[..]).await.unwrap();
    assert_eq!(read_until(&mut second, "twice").await, "twice");
    drop(first);
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forward_open_past_its_deadline_is_closed_late_and_frees_its_slot() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_forwards: 1,
            inner_login_timeout: Duration::from_secs(2),
            ..AgentLimits::default()
        },
        sshd: SshdOptions {
            forward_delay: Some(Duration::from_secs(3)),
            ..SshdOptions::default()
        },
        ..with_forwarding()
    })
    .await;
    let client = fixture.login().await;
    assert!(forward(&client, "localhost", service.port()).await.is_err());
    assert_eq!(refusals(&client, 1).await.1, [2]);
    let stats = Arc::clone(&fixture.sshd.stats);
    until("the late inner channel was closed", || {
        SshdStats::count(&stats.closes) == 1
    })
    .await;
    let mut channel = reopen(&client, service.port()).await;
    channel.data(&b"after"[..]).await.unwrap();
    assert_eq!(read_until(&mut channel, "after").await, "after");
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forward_carries_no_exit_status_and_credits_extended_data() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(Options {
        sshd: SshdOptions {
            forward_exit_status: Some(9),
            ..SshdOptions::default()
        },
        ..with_forwarding()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = forward(&client, "localhost", service.port()).await.unwrap();
    let flooding = async {
        for _ in 0..128 {
            channel
                .extended_data(1, &vec![3u8; 32 * 1024][..])
                .await
                .unwrap();
        }
    };
    tokio::time::timeout(STEP, flooding)
        .await
        .expect("the window of extended data never came back");
    channel.data(&b"after"[..]).await.unwrap();
    channel.eof().await.unwrap();
    let seen = transcript(&mut channel).await;
    assert_eq!(seen.stdout, b"after");
    assert_eq!(seen.exit_status, None);
    until("the service saw only data", || service.received() == 5).await;
    let outcome = client.finish().await;
    assert_eq!(outcome.exit_status, None);
    assert_eq!(fixture.authority.ends()[0].exit_status, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reader_frozen_for_seconds_loses_nothing() {
    const TOTAL: usize = 8 * 1024 * 1024;
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let channel = forward(&client, "localhost", service.port()).await.unwrap();
    let (mut read_half, write_half) = channel.split();
    let writer = tokio::spawn(async move {
        for _ in 0..TOTAL / (32 * 1024) {
            write_half
                .data_bytes(Bytes::from(vec![5u8; 32 * 1024]))
                .await
                .unwrap();
        }
        write_half.eof().await.unwrap();
        write_half
    });
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut received = 0;
    let reading = async {
        while let Some(message) = read_half.wait().await {
            match message {
                ChannelMsg::Data { data } => received += data.len(),
                ChannelMsg::Eof => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(STEP, reading)
        .await
        .expect("the frozen reader never got the rest");
    assert_eq!(received, TOTAL);
    writer.await.unwrap();
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn half_close_works_in_both_directions_on_a_forward() {
    let banner = Service::start(Behaviour::Banner).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let channel = forward(&client, "localhost", banner.port()).await.unwrap();
    let (mut read_half, write_half) = channel.split();
    let mut text = Vec::new();
    let reading = async {
        loop {
            match read_half.wait().await {
                Some(ChannelMsg::Data { data }) => text.extend_from_slice(&data),
                Some(ChannelMsg::Eof) => break,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                other => panic!("unexpected {other:?} before the service EOF"),
            }
        }
    };
    tokio::time::timeout(STEP, reading).await.unwrap();
    assert_eq!(text, b"banner\n");
    let late = vec![7u8; 300 * 1024];
    write_half
        .data_bytes(Bytes::from(late.clone()))
        .await
        .unwrap();
    write_half.eof().await.unwrap();
    until("the service read everything after its own EOF", || {
        banner.received() == late.len()
    })
    .await;
    let closing = async {
        loop {
            match read_half.wait().await {
                Some(ChannelMsg::Close) | None => break,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                other => panic!("unexpected {other:?} after the service EOF"),
            }
        }
    };
    tokio::time::timeout(STEP, closing).await.unwrap();
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_64_mib_echo_through_a_forward_survives_a_slow_reader() {
    const TOTAL: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 32 * 1024;
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let channel = forward(&client, "localhost", service.port()).await.unwrap();
    let (mut read_half, write_half) = channel.split();
    let pattern = |offset: usize| u8::try_from(offset % 251).unwrap();
    let started = Instant::now();
    let writer = tokio::spawn(async move {
        for offset in (0..TOTAL).step_by(CHUNK) {
            let chunk: Vec<u8> = (offset..offset + CHUNK).map(pattern).collect();
            write_half.data_bytes(Bytes::from(chunk)).await.unwrap();
        }
        write_half.eof().await.unwrap();
        write_half
    });
    let mut received = 0;
    let reading = async {
        while let Some(message) = read_half.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    assert!(
                        data.iter()
                            .enumerate()
                            .all(|(index, byte)| *byte == pattern(received + index))
                    );
                    received += data.len();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                ChannelMsg::Eof => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), reading)
        .await
        .expect("the forward deadlocked");
    eprintln!("64 MiB echo through a forward: {:?}", started.elapsed());
    assert_eq!(received, TOTAL);
    writer.await.unwrap();
    let outcome = client.finish().await;
    let total = u64::try_from(TOTAL).unwrap();
    assert_eq!((outcome.bytes_in, outcome.bytes_out), (total, total));
}

#[tokio::test(flavor = "multi_thread")]
async fn closing_a_forward_mid_transfer_closes_the_service_socket_and_frees_its_tasks() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let baseline = alive_tasks();
    let channel = forward(&client, "localhost", service.port()).await.unwrap();
    let (_read_half, write_half) = channel.split();
    for _ in 0..64 {
        write_half
            .data_bytes(Bytes::from(vec![1u8; 32 * 1024]))
            .await
            .unwrap();
    }
    until("the service is busy", || service.received() > 0).await;
    write_half.close().await.unwrap();
    until("the service socket closed", || service.live() == 0).await;
    until("the forward tasks ended", || alive_tasks() <= baseline).await;
    let stats = Arc::clone(&fixture.sshd.stats);
    until("sshd saw the channel close", || {
        SshdStats::count(&stats.closes) == 1
    })
    .await;
    let outcome = client.finish().await;
    assert!(outcome.bytes_in > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_the_session_closes_every_forward_on_both_sides() {
    let service = Service::start(Behaviour::Echo).await;
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let mut channels = Vec::new();
    for _ in 0..3 {
        let mut channel = forward(&client, "localhost", service.port()).await.unwrap();
        channel.data(&b"up"[..]).await.unwrap();
        read_until(&mut channel, "up").await;
        channels.push(channel);
    }
    assert_eq!(service.live(), 3);
    client.cancel.cancel();
    for channel in &mut channels {
        let ended = async {
            loop {
                match channel.wait().await {
                    Some(ChannelMsg::Close) | None => break,
                    Some(_) => {}
                }
            }
        };
        tokio::time::timeout(STEP, ended).await.unwrap();
    }
    until("every service socket closed", || service.live() == 0).await;
    let stats = Arc::clone(&fixture.sshd.stats);
    until("sshd lost the inner connection", || {
        SshdStats::count(&stats.live) == 0
    })
    .await;
    let outcome = client.outcome().await;
    assert_eq!(outcome.reason, EndReason::Cancelled);
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn remote_and_socket_forwarding_are_refused() {
    let fixture = Fixture::new(with_forwarding()).await;
    let client = fixture.login().await;
    let remote = tokio::time::timeout(STEP, client.handle.tcpip_forward("127.0.0.1", 9000)).await;
    assert!(!matches!(remote, Ok(Ok(_))), "{remote:?}");
    let socket = tokio::time::timeout(
        STEP,
        client.handle.streamlocal_forward("/tmp/jaunt-test.sock"),
    )
    .await;
    assert!(!matches!(socket, Ok(Ok(()))), "{socket:?}");
    let streamlocal = tokio::time::timeout(
        STEP,
        client
            .handle
            .channel_open_direct_streamlocal("/run/docker.sock"),
    )
    .await
    .unwrap();
    assert!(streamlocal.is_err());
    assert_eq!(
        refusals(&client, 1).await,
        (vec![LOOPBACK_ONLY.to_owned()], vec![1])
    );
    let mut channel = client.exec("echo still-works").await;
    assert_eq!(transcript(&mut channel).await.stdout, b"still-works\n");
    client.finish().await;
    assert!(
        fixture
            .sshd
            .stats
            .requests()
            .iter()
            .all(|request| request.starts_with("exec:"))
    );
}
