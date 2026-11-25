use jaunt_proto::{RecordingKind, RecordingManifest};
use jaunt_ssh::{
    ChannelExit, ChannelProgram, ChannelStart, ForwardTarget, OutputStream, Recording, Terminal,
    TerminalSize,
};

use super::{
    Bench, Cast, LOGIN, NODE, Seen, USER, exec, exec_with_terminal, limits, out, panic_clocks,
    parse_cast, shell, start,
};
use crate::clock::unix_secs;
use crate::testkit::eventually;

async fn stored(bench: &Bench, session_id: &str) -> (Vec<u8>, RecordingManifest) {
    eventually("the server to store the recording", || {
        bench.server.manifest(session_id).is_some()
    })
    .await;
    let manifest = bench.server.manifest(session_id).unwrap();
    (bench.server.cast(session_id), manifest)
}

async fn stored_cast(bench: &Bench, session_id: &str) -> (Cast, RecordingManifest) {
    let (bytes, manifest) = stored(bench, session_id).await;
    (parse_cast(&bytes).unwrap(), manifest)
}

fn size(columns: u32, rows: u32) -> TerminalSize {
    TerminalSize {
        columns,
        rows,
        pixel_width: 0,
        pixel_height: 0,
    }
}

#[tokio::test]
async fn a_shell_channel_becomes_a_cast_the_reference_parser_accepts() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("shell-1", false);
    observer.channel_start(0, &shell(120, 40));
    out(&mut *observer, 0, b"$ ");
    observer.input(0, b"echo hi\r");
    out(&mut *observer, 0, "echo hi\r\nhi \u{2713}\r\n".as_bytes());
    observer.resize(0, size(100, 30));
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Complete);

    let (cast, manifest) = stored_cast(&bench, "shell-1").await;
    assert_eq!((cast.width, cast.height), (120, 40));
    assert_eq!(cast.joined("o"), "$ echo hi\r\nhi \u{2713}\r\n");
    assert_eq!(cast.joined("r"), "100x30");
    assert_eq!(
        cast.markers(),
        ["channel 0 shell start", "channel 0 exit 0"]
    );
    assert_eq!(manifest.kind, RecordingKind::Shell);
    assert_eq!(
        (
            manifest.node.as_str(),
            manifest.user.as_str(),
            manifest.login.as_str()
        ),
        (NODE, USER, LOGIN)
    );
    assert_eq!(manifest.session_id, "shell-1");
    assert_eq!(
        manifest.started_at,
        u64::try_from(unix_secs(start())).unwrap()
    );
    assert_eq!(manifest.exit_status, Some(0));
    assert!(!manifest.incomplete && !manifest.input_recorded);
    assert_eq!(bench.recordings.memory_in_use(), 0);
}

#[tokio::test]
async fn input_is_in_the_cast_only_when_the_role_records_it() {
    for record_input in [false, true] {
        let bench = Bench::new(limits());
        let mut observer = bench.open("input-1", record_input);
        observer.channel_start(0, &shell(80, 24));
        observer.input(0, b"PASSWORD-7f3a9c\r");
        out(&mut *observer, 0, b"\r\n$ ");
        observer.channel_end(0, &ChannelExit::Status(0));
        observer.finish();

        let (bytes, manifest) = stored(&bench, "input-1").await;
        let found = bytes
            .windows("PASSWORD-7f3a9c".len())
            .any(|window| window == b"PASSWORD-7f3a9c");
        assert_eq!(found, record_input, "record_input = {record_input}");
        let cast = parse_cast(&bytes).unwrap();
        let expected_input = if record_input {
            "PASSWORD-7f3a9c\r"
        } else {
            ""
        };
        assert_eq!(cast.joined("i"), expected_input);
        assert_eq!(manifest.input_recorded, record_input);
        assert_eq!(manifest.bytes_in, 16);
    }
}

#[tokio::test]
async fn two_shells_on_one_connection_share_one_cast_with_markers() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("multi-1", false);
    observer.channel_start(0, &shell(80, 24));
    out(&mut *observer, 0, b"first-shell ");
    observer.channel_start(1, &shell(132, 50));
    out(&mut *observer, 1, b"second-shell ");
    out(&mut *observer, 0, b"first-again ");
    observer.channel_end(1, &ChannelExit::Status(3));
    observer.channel_end(0, &ChannelExit::Signal("TERM".to_owned()));
    observer.finish();

    let (cast, manifest) = stored_cast(&bench, "multi-1").await;
    assert_eq!(cast.joined("o"), "first-shell second-shell first-again ");
    assert_eq!(
        cast.markers(),
        [
            "channel 0 shell start",
            "channel 1 shell start",
            "channel 1 exit 3",
            "channel 0 signal TERM",
        ]
    );
    assert_eq!((cast.width, cast.height), (80, 24));
    assert_eq!(manifest.kind, RecordingKind::Shell);
    assert_eq!(manifest.exit_status, None);
}

#[tokio::test]
async fn an_exec_before_a_shell_does_not_hide_what_the_shell_shows() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("mixed-1", false);
    observer.channel_start(0, &exec("uptime"));
    out(&mut *observer, 0, b"load average: 0.00");
    observer.channel_end(0, &ChannelExit::Status(0));
    observer.channel_start(1, &shell(80, 24));
    out(&mut *observer, 1, b"typed-in-the-shell");
    observer.channel_end(1, &ChannelExit::Status(0));
    observer.finish();

    let (cast, manifest) = stored_cast(&bench, "mixed-1").await;
    assert_eq!(cast.joined("o"), "typed-in-the-shell");
    assert_eq!(
        cast.markers(),
        [
            "channel 0 exec uptime",
            "channel 0 exit 0",
            "channel 1 shell start",
            "channel 1 exit 0",
        ]
    );
    assert_eq!(manifest.kind, RecordingKind::Shell);
    assert_eq!(manifest.command, None);
}

#[tokio::test]
async fn sessions_without_a_shell_send_only_a_metadata_manifest() {
    let sftp = ChannelStart {
        program: ChannelProgram::Subsystem("sftp".to_owned()),
        terminal: None,
    };
    let cases = [
        (
            exec("mysql -psecret"),
            RecordingKind::Exec,
            Some("mysql -psecret"),
        ),
        (sftp, RecordingKind::Sftp, None),
    ];
    for (start, kind, command) in cases {
        let bench = Bench::new(limits());
        let mut observer = bench.open("meta-1", false);
        observer.channel_start(0, &start);
        observer.input(0, b"abcd");
        out(&mut *observer, 0, b"0123456789");
        observer.channel_end(0, &ChannelExit::Status(3));
        assert_eq!(observer.finish(), Recording::Complete);

        let (bytes, manifest) = stored(&bench, "meta-1").await;
        assert!(bytes.is_empty());
        assert_eq!(manifest.kind, kind);
        assert_eq!(manifest.command.as_deref(), command);
        assert_eq!(manifest.exit_status, Some(3));
        assert_eq!((manifest.bytes_out, manifest.bytes_in), (10, 4));
        assert_eq!((manifest.chunks, manifest.raw_bytes), (0, 0));
        assert_eq!(manifest.digest, None);
        assert!(!manifest.input_recorded && !manifest.incomplete);
    }
}

#[tokio::test]
async fn forwards_and_early_events_become_markers_with_a_bounded_buffer() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("early-1", false);
    for channel in 0..70 {
        observer.forward_open(
            channel,
            &ForwardTarget {
                host: "127.0.0.1".to_owned(),
                port: 8080,
            },
        );
    }
    observer.channel_start(100, &shell(80, 24));
    observer.forward_close(3);
    observer.channel_end(100, &ChannelExit::Unknown);
    observer.finish();

    let (cast, _) = stored_cast(&bench, "early-1").await;
    let markers = cast.markers();
    assert_eq!(markers.len(), 64 + 4);
    assert_eq!(markers[0], "channel 0 forward 127.0.0.1:8080");
    assert_eq!(markers[63], "channel 63 forward 127.0.0.1:8080");
    assert_eq!(
        markers[64..],
        [
            "6 earlier markers omitted",
            "channel 100 shell start",
            "channel 3 forward closed",
            "channel 100 closed",
        ]
    );
}

#[tokio::test]
async fn a_panicking_recorder_marks_the_recording_incomplete_and_never_escapes() {
    let bench = Bench::with_clocks(limits(), panic_clocks(3));
    let mut observer = bench.open("panic-1", false);
    observer.channel_start(0, &shell(80, 24));
    out(&mut *observer, 0, b"one");
    out(&mut *observer, 0, b"two");
    out(&mut *observer, 0, b"three");
    observer.input(0, b"still typing");
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Incomplete);

    eventually("the uploader to stop", || {
        bench.recordings.active_uploads() == 0
    })
    .await;
    assert_eq!(bench.recordings.memory_in_use(), 0);
    assert!(bench.server.manifest("panic-1").is_none());
}

#[tokio::test]
async fn any_channel_with_a_terminal_is_cast_and_an_exec_names_its_command() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("pty-exec-1", false);
    observer.channel_start(0, &exec("hostname"));
    out(&mut *observer, 0, b"node1\n");
    observer.channel_end(0, &ChannelExit::Status(0));
    observer.channel_start(1, &exec_with_terminal("sudo -i"));
    out(&mut *observer, 1, b"root@node1:~# ");
    observer.channel_end(1, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Complete);

    let (cast, manifest) = stored_cast(&bench, "pty-exec-1").await;
    assert_eq!((cast.width, cast.height), (100, 30));
    assert_eq!(cast.joined("o"), "root@node1:~# ");
    assert_eq!(
        cast.markers(),
        [
            "channel 0 exec hostname",
            "channel 0 exit 0",
            "channel 1 exec sudo -i",
            "channel 1 exit 0",
        ]
    );
    assert_eq!(manifest.kind, RecordingKind::Shell);
    assert_eq!(manifest.command, None);
}

#[tokio::test]
async fn a_role_without_pty_never_gets_a_cast_and_records_metadata_only() {
    let cases = [
        (
            vec![ChannelStart {
                program: ChannelProgram::Shell,
                terminal: None,
            }],
            None,
        ),
        (
            vec![
                ChannelStart {
                    program: ChannelProgram::Shell,
                    terminal: None,
                },
                exec("uptime"),
            ],
            Some("uptime"),
        ),
    ];
    for (starts, command) in cases {
        let bench = Bench::new(limits());
        let mut observer = bench.open_without_pty("nopty-1");
        for (channel, start) in (0u32..).zip(&starts) {
            observer.channel_start(channel, start);
            out(&mut *observer, channel, &[b'x'; 100_000]);
            observer.input(channel, b"typed");
            observer.channel_end(channel, &ChannelExit::Status(0));
        }
        bench.clock.advance(std::time::Duration::from_secs(6));
        assert_eq!(observer.finish(), Recording::Complete);

        let (bytes, manifest) = stored(&bench, "nopty-1").await;
        assert!(bytes.is_empty());
        assert_eq!(manifest.kind, RecordingKind::Exec);
        assert_eq!(manifest.command.as_deref(), command);
        assert_eq!((manifest.chunks, manifest.raw_bytes), (0, 0));
        let sessions = u64::try_from(starts.len()).unwrap();
        assert_eq!(manifest.bytes_out, 100_000 * sessions);
        assert_eq!(manifest.bytes_in, 5 * sessions);
        assert!(
            !bench
                .server
                .seen()
                .iter()
                .any(|seen| matches!(seen, Seen::Chunk(..)))
        );
    }
}

#[tokio::test]
async fn a_character_split_across_packets_survives_the_output_of_another_channel() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("utf8-1", true);
    observer.channel_start(0, &shell(80, 24));
    observer.channel_start(1, &shell(80, 24));
    out(&mut *observer, 0, &[0xE2, 0x82]);
    out(&mut *observer, 1, b"x");
    out(&mut *observer, 0, &[0xAC]);
    observer.output(0, OutputStream::Stderr, &[0xC3]);
    out(&mut *observer, 0, b"z");
    observer.output(0, OutputStream::Stderr, &[0xA9]);
    observer.input(0, &[0xE2, 0x82]);
    observer.input(1, b"y");
    observer.input(0, &[0xAC]);
    out(&mut *observer, 1, &[0xE2]);
    observer.channel_end(1, &ChannelExit::Status(0));
    observer.input(0, &[0xF0, 0x9F]);
    assert_eq!(observer.finish(), Recording::Complete);

    let (cast, _) = stored_cast(&bench, "utf8-1").await;
    assert_eq!(cast.joined("o"), "x\u{20ac}z\u{e9}\u{fffd}");
    assert_eq!(cast.joined("i"), "y\u{20ac}\u{fffd}");
    let exit = cast
        .events
        .iter()
        .position(|event| event.data == "channel 1 exit 0")
        .unwrap();
    let replacement = cast
        .events
        .iter()
        .position(|event| event.kind == "o" && event.data == "\u{fffd}")
        .unwrap();
    assert!(replacement < exit);
}

#[tokio::test]
async fn client_supplied_text_is_bounded_in_markers_the_manifest_and_the_header() {
    let bench = Bench::new(limits());
    let mut observer = bench.open("bounds-1", false);
    observer.channel_start(0, &exec(&"a".repeat(10_000)));
    observer.channel_end(0, &ChannelExit::Status(0));
    observer.finish();
    let (_, manifest) = stored(&bench, "bounds-1").await;
    assert_eq!(manifest.command.unwrap(), "a".repeat(4096));

    let bench = Bench::new(limits());
    let mut observer = bench.open("bounds-2", false);
    observer.channel_start(
        0,
        &ChannelStart {
            program: ChannelProgram::Shell,
            terminal: Some(Terminal {
                term: "t".repeat(1000),
                size: TerminalSize {
                    columns: 80,
                    rows: 24,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            }),
        },
    );
    observer.channel_start(1, &exec_with_terminal(&"\u{e9}".repeat(5_000)));
    observer.channel_start(
        2,
        &ChannelStart {
            program: ChannelProgram::Subsystem("s".repeat(9_000)),
            terminal: None,
        },
    );
    observer.channel_end(1, &ChannelExit::Status(0));
    observer.channel_end(2, &ChannelExit::Status(0));
    observer.channel_end(0, &ChannelExit::Status(0));
    assert_eq!(observer.finish(), Recording::Complete);

    let (bytes, _) = stored(&bench, "bounds-2").await;
    let header: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&bytes).unwrap().lines().next().unwrap()).unwrap();
    assert_eq!(header["env"]["TERM"], "t".repeat(256));
    let cast = parse_cast(&bytes).unwrap();
    let markers = cast.markers();
    let exec_marker = markers[1];
    assert!(exec_marker.starts_with("channel 1 exec \u{e9}"));
    assert!(exec_marker.len() <= 4096 && exec_marker.len() > 4000);
    assert!(markers[2].starts_with("channel 2 subsystem sss"));
    assert_eq!(markers[2].len(), 4096);
}
