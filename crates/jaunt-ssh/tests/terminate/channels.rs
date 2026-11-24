use std::time::{Duration, Instant};

use bytes::Bytes;
use jaunt_proto::{SessionEnd, SessionPermissions};
use jaunt_ssh::{
    AgentLimits, ChannelExit, ChannelProgram, ChannelStart, EndReason, OutputStream, Terminal,
    TerminalSize,
};
use russh::{Sig, client};
use tokio_util::sync::CancellationToken;

use crate::sshd::{SshdOptions, SshdStats};
use crate::support::{
    Decision, Event, Fixture, LOGIN, OUTPUT_WINDOW, Options, SESSION_ID, STEP, TRANSPORT,
    permissions, read_until, reply, transcript, until,
};

#[tokio::test(flavor = "multi_thread")]
async fn an_exec_exit_status_reaches_the_user_the_observer_and_the_session_end() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("exit 7").await;
    let seen = transcript(&mut channel).await;
    assert_eq!(
        (seen.exit_status, seen.order.as_slice()),
        (Some(7), ["eof", "exit"].as_slice())
    );
    let outcome = client.finish().await;
    assert_eq!(outcome.exit_status, Some(7));
    assert_eq!(outcome.reason, EndReason::ClientClosed);
    assert_eq!(
        fixture.authority.ends(),
        [SessionEnd {
            session_id: SESSION_ID.to_owned(),
            exit_status: Some(7),
            bytes_in: 0,
            bytes_out: 0,
            recording_incomplete: false,
        }]
    );
    let number = channel.id().number();
    assert_eq!(
        fixture.events(),
        [
            Event::Start(
                number,
                ChannelStart {
                    program: ChannelProgram::Exec(b"exit 7".to_vec()),
                    terminal: None,
                }
            ),
            Event::End(number, ChannelExit::Status(7)),
            Event::Finish,
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_with_a_terminal_follows_window_changes() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(reply(&mut channel).await);
    channel.request_shell(true).await.unwrap();
    assert!(reply(&mut channel).await);
    read_until(&mut channel, "pty xterm 80x24").await;
    channel.window_change(100, 40, 0, 0).await.unwrap();
    read_until(&mut channel, "size 100x40").await;
    channel.data(&b"hi"[..]).await.unwrap();
    read_until(&mut channel, "hi").await;
    channel.eof().await.unwrap();
    assert_eq!(transcript(&mut channel).await.exit_status, Some(0));
    client.finish().await;
    let number = channel.id().number();
    let size = |columns, rows| TerminalSize {
        columns,
        rows,
        pixel_width: 0,
        pixel_height: 0,
    };
    let events = fixture.events();
    assert_eq!(
        events[0],
        Event::Start(
            number,
            ChannelStart {
                program: ChannelProgram::Shell,
                terminal: Some(Terminal {
                    term: "xterm".to_owned(),
                    size: size(80, 24),
                }),
            }
        )
    );
    assert!(events.contains(&Event::Resize(number, size(100, 40))));
    assert!(events.contains(&Event::Input(number, 2)));
    assert!(events.contains(&Event::Output(number, OutputStream::Stdout, 2)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_terminal_refused_by_policy_is_explained_once_on_stderr() {
    let fixture = Fixture::new(Options {
        decision: Decision::Allow(SessionPermissions {
            pty: false,
            ..permissions()
        }),
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(!reply(&mut channel).await);
    channel.request_shell(true).await.unwrap();
    assert!(reply(&mut channel).await);
    channel.eof().await.unwrap();
    let seen = transcript(&mut channel).await;
    assert_eq!(
        seen.stderr,
        b"jaunt: a terminal is not allowed by your roles\r\n"
    );
    assert!(seen.stdout.is_empty());
    client.finish().await;
    let certificates = fixture.sshd.stats.certificates.lock().unwrap().clone();
    assert!(certificates[0].1.extensions().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn signals_reach_the_program() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("wait-signal").await;
    channel.signal(Sig::USR1).await.unwrap();
    let seen = transcript(&mut channel).await;
    assert_eq!(seen.stdout, b"got USR1\n");
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn only_a_bounded_number_of_locale_variables_reach_sshd() {
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_env: 2,
            ..AgentLimits::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    for (name, accepted) in [
        ("LANG", true),
        ("FOO", false),
        ("LD_PRELOAD", false),
        ("LC_ALL", true),
        ("LC_TIME", false),
    ] {
        channel.set_env(true, name, "C").await.unwrap();
        assert_eq!(reply(&mut channel).await, accepted, "{name}");
    }
    channel.exec(true, "env").await.unwrap();
    assert!(reply(&mut channel).await);
    assert_eq!(
        transcript(&mut channel).await.stdout,
        b"[LANG=C,LC_ALL=C]\n"
    );
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sftp_is_the_only_subsystem() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut sftp = client.open().await;
    sftp.request_subsystem(true, "sftp").await.unwrap();
    assert!(reply(&mut sftp).await);
    sftp.data(&b"init"[..]).await.unwrap();
    sftp.eof().await.unwrap();
    assert_eq!(transcript(&mut sftp).await.stdout, b"init");
    let mut other = client.open().await;
    other.request_subsystem(true, "netconf").await.unwrap();
    assert!(!reply(&mut other).await);
    client.finish().await;
    assert_eq!(fixture.sshd.stats.requests(), ["subsystem:sftp"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn x11_agent_forwarding_and_port_forwarding_are_refused() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.open().await;
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "0123456789abcdef", 0)
        .await
        .unwrap();
    assert!(!reply(&mut channel).await);
    channel.agent_forward(true).await.unwrap();
    assert!(!reply(&mut channel).await);
    let forward = client
        .handle
        .channel_open_direct_tcpip("localhost", 8080, "127.0.0.1", 50000)
        .await;
    assert!(forward.is_err());
    until("open failure recorded", || {
        !client.seen.open_failures.lock().unwrap().is_empty()
    })
    .await;
    let failures = client.seen.open_failures.lock().unwrap().clone();
    assert_eq!(
        failures,
        ["jaunt: port forwarding is not allowed by your roles"]
    );
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exit_signal_reaches_the_user_and_leaves_no_exit_status() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("kill TERM").await;
    let seen = transcript(&mut channel).await;
    assert_eq!(seen.exit_signal.as_deref(), Some("TERM"));
    assert_eq!(seen.order, ["eof", "signal"]);
    let outcome = client.finish().await;
    assert_eq!(outcome.exit_status, None);
    assert!(fixture.events().contains(&Event::End(
        channel.id().number(),
        ChannelExit::Signal("TERM".to_owned())
    )));
}

#[tokio::test(flavor = "multi_thread")]
async fn half_close_works_in_both_directions() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut early = client.exec("count").await;
    early.data(&[7u8; 200][..]).await.unwrap();
    early.eof().await.unwrap();
    let seen = transcript(&mut early).await;
    assert_eq!(
        (seen.order.as_slice(), seen.exit_status),
        (["eof", "exit"].as_slice(), Some(200))
    );
    let mut cat = client.exec("cat").await;
    cat.data(&b"hello"[..]).await.unwrap();
    cat.eof().await.unwrap();
    let seen = transcript(&mut cat).await;
    assert_eq!(seen.stdout, b"hello");
    assert_eq!(
        (seen.order.as_slice(), seen.exit_status),
        (["eof", "exit"].as_slice(), Some(0))
    );
    let outcome = client.finish().await;
    assert_eq!((outcome.bytes_in, outcome.bytes_out), (205, 5));
}

#[tokio::test(flavor = "multi_thread")]
async fn many_small_packets_arrive_intact_and_in_order() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let channel = client.exec("cat").await;
    let (mut read_half, write_half) = channel.split();
    let sent: Vec<u8> = (0..4000u32).flat_map(|n| n.to_be_bytes()).collect();
    let packets: Vec<Bytes> = sent.chunks(7).map(Bytes::copy_from_slice).collect();
    let writer = tokio::spawn(async move {
        for packet in packets {
            write_half.data_bytes(packet).await.unwrap();
        }
        write_half.eof().await.unwrap();
        write_half
    });
    let mut received = Vec::new();
    let reading = async {
        while let Some(message) = read_half.wait().await {
            match message {
                russh::ChannelMsg::Data { data } => received.extend_from_slice(&data),
                russh::ChannelMsg::Eof => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(crate::support::STEP, reading)
        .await
        .expect("the echo stalled");
    assert_eq!(received, sent);
    writer.await.unwrap();
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn session_channels_are_limited_but_finished_ones_free_their_slot() {
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_sessions: 2,
            ..AgentLimits::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    for round in 0..6 {
        let mut channel = client.exec("echo again").await;
        assert_eq!(
            transcript(&mut channel).await.stdout,
            b"again\n",
            "round {round}"
        );
    }
    let first = client.open().await;
    let _second = client.open().await;
    assert!(client.handle.channel_open_session().await.is_err());
    first.close().await.unwrap();
    let mut third = client.exec("echo again").await;
    assert_eq!(transcript(&mut third).await.stdout, b"again\n");
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_after_the_start_never_reach_sshd() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("cat").await;
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(!reply(&mut channel).await);
    channel.exec(true, "echo again").await.unwrap();
    assert!(!reply(&mut channel).await);
    channel.request_shell(true).await.unwrap();
    assert!(!reply(&mut channel).await);
    channel.set_env(true, "LANG", "C").await.unwrap();
    assert!(!reply(&mut channel).await);
    channel.eof().await.unwrap();
    assert_eq!(transcript(&mut channel).await.exit_status, Some(0));
    client.finish().await;
    assert_eq!(fixture.sshd.stats.requests(), ["exec:cat"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn client_extended_data_is_dropped_but_its_window_comes_back() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("cat").await;
    let beyond_the_window = vec![0u8; 3 * 1024 * 1024];
    tokio::time::timeout(STEP, channel.extended_data(1, &beyond_the_window[..]))
        .await
        .expect("the window spent on extended data never came back")
        .unwrap();
    channel.data(&b"ok"[..]).await.unwrap();
    channel.eof().await.unwrap();
    assert_eq!(transcript(&mut channel).await.stdout, b"ok");
    let outcome = client.finish().await;
    assert_eq!(outcome.bytes_in, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn sshd_extended_data_other_than_stderr_is_dropped_but_its_window_comes_back() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let mut channel = client.exec("ext2 64").await;
    let seen = transcript(&mut channel).await;
    assert_eq!(
        (
            seen.stdout.as_slice(),
            seen.stderr.as_slice(),
            seen.exit_status
        ),
        (&b"ok\n"[..], &b""[..], Some(0))
    );
    let outcome = client.finish().await;
    assert_eq!(outcome.bytes_out, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_late_inner_channel_holds_its_slot_until_it_is_closed() {
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_sessions: 1,
            inner_login_timeout: Duration::from_millis(500),
            ..AgentLimits::default()
        },
        sshd: SshdOptions {
            open_delay: Some(Duration::from_millis(1000)),
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let started = Instant::now();
    assert!(client.handle.channel_open_session().await.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(client.handle.channel_open_session().await.is_err());
    let stats = &fixture.sshd.stats;
    assert_eq!(SshdStats::count(&stats.opens), 1);
    until("sshd closed the late channel", || {
        SshdStats::count(&stats.closes) == 1
    })
    .await;
    let deadline = Instant::now() + STEP;
    let mut next = loop {
        if let Ok(channel) = client.handle.channel_open_session().await {
            break channel;
        }
        assert!(Instant::now() < deadline, "the slot was never released");
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    next.exec(true, "echo again").await.unwrap();
    assert!(reply(&mut next).await);
    assert_eq!(transcript(&mut next).await.stdout, b"again\n");
    assert_eq!(SshdStats::count(&stats.opens), 2);
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_channel_opens_while_the_first_streams() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let (mut streaming, _input) = client.exec("flood 64").await.split();
    let reader = tokio::spawn(async move { while streaming.wait().await.is_some() {} });
    let stats = &fixture.sshd.stats;
    until("the first channel streams", || {
        SshdStats::count(&stats.written) >= 8 * 1024 * 1024
    })
    .await;
    let started = Instant::now();
    let _second = client.open().await;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(SshdStats::count(&stats.opens), 2);
    reader.abort();
    client.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reply_timeout_closes_the_channel_on_both_sides() {
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            reply_timeout: Duration::from_millis(300),
            ..AgentLimits::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    let mut terminal = client.open().await;
    terminal
        .request_pty(true, "hang", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    assert!(!reply(&mut terminal).await);
    assert!(transcript(&mut terminal).await.stdout.is_empty());
    let mut late = client.open().await;
    let started = Instant::now();
    late.exec(true, "late").await.unwrap();
    assert!(!reply(&mut late).await);
    assert!(started.elapsed() < Duration::from_secs(5));
    let typed = late.data(&b"typed after the failure"[..]).await;
    let seen = transcript(&mut late).await;
    assert!(
        seen.stdout.is_empty() && seen.exit_status.is_none(),
        "{typed:?} {seen:?}"
    );
    until("sshd saw both channels closed", || {
        SshdStats::count(&fixture.sshd.stats.closes) == 2
    })
    .await;
    let mut alive = client.exec("echo alive").await;
    assert_eq!(transcript(&mut alive).await.stdout, b"alive\n");
    client.finish().await;
    assert_eq!(
        fixture.sshd.stats.requests(),
        ["pty", "exec:late", "exec:echo alive"]
    );
    let alive = alive.id().number();
    assert!(fixture.events().iter().all(|event| match event {
        Event::Start(channel, _)
        | Event::Input(channel, _)
        | Event::Output(channel, ..)
        | Event::End(channel, _) => *channel == alive,
        Event::Resize(..) | Event::Finish => true,
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_requests_on_an_idle_channel_next_to_a_stuck_one_is_answered_promptly() {
    let fixture = Fixture::new(Options::default()).await;
    let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
    let serve = fixture.serve_on(agent_io, CancellationToken::new());
    let unread = client::Config {
        window_size: 1,
        ..client::Config::default()
    };
    let mut client = fixture.connect_over(client_io, serve, unread).await;
    assert!(client.authenticate(LOGIN, fixture.cert.clone()).await);
    let mut idle = client.open().await;
    let _streaming = client.exec("flood 8").await;
    until("sshd is stuck behind the closed user window", || {
        SshdStats::count(&fixture.sshd.stats.written) >= OUTPUT_WINDOW
    })
    .await;
    for _ in 0..300 {
        idle.signal(Sig::USR1).await.unwrap();
    }
    let started = Instant::now();
    idle.exec(true, "echo again").await.unwrap();
    reply(&mut idle).await;
    assert!(started.elapsed() < Duration::from_secs(2));
    client.finish().await;
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn data_sent_before_eof_and_close_still_reaches_sshd_with_window() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let channel = client.exec("stall").await;
    channel.data(&vec![3u8; 16 * 1024][..]).await.unwrap();
    channel.eof().await.unwrap();
    channel.close().await.unwrap();
    until("sshd received the whole upload", || {
        SshdStats::count(&fixture.sshd.stats.stalled) == 16 * 1024
    })
    .await;
    client.finish().await;
}

#[tokio::test]
async fn a_hung_inner_open_gives_its_slot_back_after_twice_the_open_deadline() {
    let fixture = Fixture::new(Options {
        limits: AgentLimits {
            max_sessions: 1,
            inner_login_timeout: Duration::from_secs(10),
            ..AgentLimits::default()
        },
        sshd: SshdOptions {
            open_delay: Some(Duration::from_secs(24 * 3600)),
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    assert!(client.handle.channel_open_session().await.is_err());
    tokio::time::sleep_until(started + Duration::from_millis(29_900)).await;
    assert!(client.handle.channel_open_session().await.is_err());
    tokio::time::sleep_until(started + Duration::from_millis(30_100)).await;
    tokio::time::resume();
    let mut next = client.exec("echo again").await;
    assert_eq!(transcript(&mut next).await.stdout, b"again\n");
    let stats = &fixture.sshd.stats;
    assert_eq!(
        (
            SshdStats::count(&stats.opens),
            SshdStats::count(&stats.closes)
        ),
        (2, 0)
    );
    client.finish().await;
}
