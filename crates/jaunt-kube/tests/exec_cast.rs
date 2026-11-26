use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_kube::{
    ChannelProtocol, Direction, EXEC_CHANNELS, ExecCast, ExecCastError, ExecStatus,
    MAX_RESIZE_PENDING_BYTES, MAX_STATUS_BYTES, Opcode, RESIZE, STATUS, STDERR, STDIN, STDOUT,
    WsError, WsMessage, WsReader, encode_frame,
};
use jaunt_record::{Chunk, Clock, Recorder, RecorderConfig, SessionKind};

const STARTED_AT: u64 = 1_700_000_000;

struct CallerClock(Arc<AtomicU64>);

impl Clock for CallerClock {
    fn elapsed(&self) -> Duration {
        Duration::from_micros(self.0.load(Ordering::SeqCst))
    }
}

fn recorder(record_input: bool) -> (Recorder, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(0));
    let config = RecorderConfig {
        session_id: "exec-1".to_owned(),
        kind: SessionKind::Exec,
        node: "kube-stage".to_owned(),
        user: "alice@example.com".to_owned(),
        login: "alice@example.com".to_owned(),
        command: Some("sh".to_owned()),
        started_at: STARTED_AT,
        width: 80,
        height: 24,
        shell: String::new(),
        term: "xterm".to_owned(),
        record_input,
    };
    let recorder = Recorder::new(config, Box::new(CallerClock(now.clone()))).unwrap();
    (recorder, now)
}

fn message(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut message = vec![channel];
    message.extend_from_slice(payload);
    message
}

fn cast_text(chunks: &[Chunk]) -> String {
    chunks
        .iter()
        .map(|chunk| {
            String::from_utf8(zstd::stream::decode_all(&chunk.compressed[..]).unwrap()).unwrap()
        })
        .collect()
}

const EXIT_THREE: &[u8] = br#"{"metadata":{},"status":"Failure","message":"command terminated with non-zero exit code: exit status 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#;

enum From {
    Client,
    Server,
}

#[test]
fn an_exec_session_becomes_the_expected_cast() {
    let (mut recorder, now) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    let (status_head, status_tail) = EXIT_THREE.split_at(40);
    let steps: Vec<(u64, From, Vec<u8>)> = vec![
        (
            0,
            From::Client,
            message(RESIZE, br#"{"Width":100,"Height":30}"#),
        ),
        (250_000, From::Server, message(STDOUT, b"$ ")),
        (1_000_000, From::Client, message(STDIN, b"ls\r")),
        (1_100_000, From::Server, message(STDOUT, b"ls\r\ncaf\xc3")),
        (1_200_000, From::Server, message(STDERR, b"warn\n")),
        (1_300_000, From::Server, message(STDOUT, b"\xa9\r\n")),
        (1_350_000, From::Server, Vec::new()),
        (1_400_000, From::Client, vec![255, STDIN]),
        (1_500_000, From::Client, message(STDIN, b"after close")),
        (1_600_000, From::Server, message(STATUS, status_head)),
        (1_600_000, From::Server, message(STATUS, status_tail)),
    ];
    for (micros, from, bytes) in steps {
        now.store(micros, Ordering::SeqCst);
        match from {
            From::Client => cast.client_message(&mut recorder, &bytes).unwrap(),
            From::Server => cast.server_message(&mut recorder, &bytes).unwrap(),
        }
    }
    let outcome = cast.finish(&mut recorder, STARTED_AT + 2).unwrap();
    assert_eq!(outcome.status, ExecStatus::Exited(3));
    assert_eq!(outcome.manifest.exit_status, Some(3));
    assert_eq!(outcome.manifest.bytes_in, 3);
    assert_eq!(outcome.manifest.bytes_out, 18);
    assert!(outcome.manifest.input_recorded);
    let expected = concat!(
        "{\"version\":2,\"width\":80,\"height\":24,\"timestamp\":1700000000,\"env\":{\"SHELL\":\"\",\"TERM\":\"xterm\"}}\n",
        "[0.0, \"r\", \"100x30\"]\n",
        "[0.25, \"o\", \"$ \"]\n",
        "[1.0, \"i\", \"ls\\r\"]\n",
        "[1.1, \"o\", \"ls\\r\\ncaf\"]\n",
        "[1.2, \"o\", \"warn\\n\"]\n",
        "[1.3, \"o\", \"\u{e9}\\r\\n\"]\n",
    );
    assert_eq!(cast_text(&recorder.take_chunks()), expected);
}

#[test]
fn input_stays_out_of_the_cast_unless_the_caller_allows_it() {
    let (mut recorder, _) = recorder(false);
    let mut cast = ExecCast::new(ChannelProtocol::V4, true);
    cast.client_message(&mut recorder, &message(STDIN, b"secret\r"))
        .unwrap();
    cast.server_message(&mut recorder, &message(STDOUT, b"ok"))
        .unwrap();
    let outcome = cast.finish(&mut recorder, STARTED_AT).unwrap();
    assert_eq!(outcome.status, ExecStatus::Missing);
    assert_eq!(outcome.manifest.exit_status, None);
    assert_eq!(outcome.manifest.bytes_in, 7);
    let text = cast_text(&recorder.take_chunks());
    assert!(!text.contains("secret"));
    assert!(text.contains("\"ok\""));
}

#[test]
fn an_unfinished_character_is_flushed_on_finish() {
    let (mut recorder, _) = recorder(false);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    cast.server_message(&mut recorder, &message(STDOUT, b"a\xe2\x82"))
        .unwrap();
    cast.finish(&mut recorder, STARTED_AT).unwrap();
    let text = cast_text(&recorder.take_chunks());
    assert!(
        text.contains("\"a\"") && text.contains("\"\u{fffd}\""),
        "{text}"
    );
}

#[test]
fn the_status_channel_decodes_like_the_client() {
    for (payload, status) in [
        (&br#"{"metadata":{},"status":"Success"}"#[..], ExecStatus::Exited(0)),
        (EXIT_THREE, ExecStatus::Exited(3)),
        (br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"Other","message":"9"},{"reason":"ExitCode","message":"255"}]}}"#, ExecStatus::Exited(255)),
        (br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"256"}]}}"#, ExecStatus::Malformed),
        (br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"+3"}]}}"#, ExecStatus::Malformed),
        (br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"-1"}]}}"#, ExecStatus::Malformed),
        (br#"{"status":"Failure","reason":"NonZeroExitCode"}"#, ExecStatus::Malformed),
        (br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":null}}"#, ExecStatus::Malformed),
        (br#"{"status":"Failure","reason":"InternalError","message":"container not found"}"#, ExecStatus::Failed),
        (br#"{"status":"Pending"}"#, ExecStatus::Malformed),
        (br#"{"metadata":{}}"#, ExecStatus::Malformed),
        (br#"{"status":"Success"} trailing"#, ExecStatus::Malformed),
        (b"not json", ExecStatus::Malformed),
        (b"[]", ExecStatus::Malformed),
    ] {
        let (mut recorder, _) = recorder(false);
        let mut cast = ExecCast::new(ChannelProtocol::V5, true);
        cast.server_message(&mut recorder, &message(STATUS, payload))
            .unwrap();
        assert_eq!(cast.status(), status, "{}", String::from_utf8_lossy(payload));
    }
}

#[test]
fn an_oversize_status_is_refused_and_marked_malformed() {
    let (mut recorder, _) = recorder(false);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    let filler = vec![b' '; MAX_STATUS_BYTES];
    cast.server_message(&mut recorder, &message(STATUS, &filler))
        .unwrap();
    assert_eq!(
        cast.server_message(&mut recorder, &message(STATUS, b"x")),
        Err(ExecCastError::StatusTooLarge)
    );
    assert_eq!(cast.status(), ExecStatus::Malformed);
}

type ResizeCase<'a> = (&'a [&'a [u8]], &'a [&'a str], bool);

fn resize_events(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_once(", \"r\", \""))
        .map(|(_, rest)| rest.trim_end_matches("\"]").to_owned())
        .collect()
}

#[test]
fn resize_messages_are_read_as_a_stream_like_the_server() {
    let oversize = vec![b' '; MAX_RESIZE_PENDING_BYTES + 1];
    let cases: &[ResizeCase<'_>] = &[
        (&[br#"{"Width":120,"Height":40}"#], &["120x40"], false),
        (&[br#"{"width":120,"HEIGHT":40}"#], &["120x40"], false),
        (&[br#"{"Width":120}"#], &["120x0"], false),
        (
            &[br#"{"Width":65535,"Height":1,"Extra":[true]}"#],
            &["65535x1"],
            false,
        ),
        (&[br#"{"Width":80,"width":81}"#], &["81x0"], false),
        (&[br#"{"Width":null,"Height":5}"#], &["0x5"], false),
        (&[b"null"], &["0x0"], false),
        (&[b""], &[], false),
        (
            &[br#"{"Width":1,"Height":2}{"Width":3,"Height":4}"#],
            &["1x2", "3x4"],
            false,
        ),
        (&[br#"{"Width":1,"#, br#""Height":2}"#], &["1x2"], false),
        (
            &[br#"{"Width":1} "#, b"", br#" {"Width":2}"#],
            &["1x0", "2x0"],
            false,
        ),
        (&[br#"{"Width":65536}"#], &[], true),
        (&[br#"{"Width":-1}"#], &[], true),
        (&[br#"{"Width":1.5}"#], &[], true),
        (&[br#"{"Width":"80"}"#], &[], true),
        (&[b"[80,24]"], &[], true),
        (&[br#"{"Width":1}junk"#, br#"{"Width":2}"#], &["1x0"], true),
        (&[&oversize], &[], true),
    ];
    for (messages, sizes, errored) in cases {
        let (mut recorder, _) = recorder(false);
        let mut cast = ExecCast::new(ChannelProtocol::V5, true);
        let mut failed = false;
        for payload in *messages {
            match cast.client_message(&mut recorder, &message(RESIZE, payload)) {
                Ok(()) => {}
                Err(error) => {
                    assert_eq!(error, ExecCastError::InvalidResize);
                    failed = true;
                }
            }
        }
        cast.finish(&mut recorder, STARTED_AT).unwrap();
        let text = cast_text(&recorder.take_chunks());
        assert_eq!(resize_events(&text), *sizes, "{messages:?}");
        assert_eq!(failed, *errored, "{messages:?}");
    }
}

#[test]
fn closed_or_disabled_streams_are_not_recorded() {
    let (mut recorder, _) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V5, false);
    cast.client_message(&mut recorder, &message(STDIN, b"dropped by the server"))
        .unwrap();
    cast.client_message(&mut recorder, &message(RESIZE, br#"{"Width":10,"#))
        .unwrap();
    cast.client_message(&mut recorder, &[255, RESIZE]).unwrap();
    cast.client_message(&mut recorder, &message(RESIZE, br#""Height":5}"#))
        .unwrap();
    cast.client_message(
        &mut recorder,
        &message(RESIZE, br#"{"Width":1,"Height":1}"#),
    )
    .unwrap();
    let outcome = cast.finish(&mut recorder, STARTED_AT).unwrap();
    assert_eq!(outcome.manifest.bytes_in, 0);
    let text = cast_text(&recorder.take_chunks());
    assert!(!text.contains("dropped"), "{text}");
    assert!(resize_events(&text).is_empty(), "{text}");
}

#[test]
fn closing_a_channel_exec_lacks_breaks_the_client_side() {
    for channel in [EXEC_CHANNELS, 9, 254, 255] {
        let (mut recorder, _) = recorder(true);
        let mut cast = ExecCast::new(ChannelProtocol::V5, true);
        cast.client_message(&mut recorder, &message(STDIN, b"before"))
            .unwrap();
        let broken = Err(ExecCastError::UnknownChannelClosed { channel });
        assert_eq!(cast.client_message(&mut recorder, &[255, channel]), broken);
        assert_eq!(
            cast.client_message(&mut recorder, &message(STDIN, b"never delivered")),
            broken
        );
        cast.server_message(&mut recorder, &message(STDOUT, b"late output"))
            .unwrap();
        cast.finish(&mut recorder, STARTED_AT).unwrap();
        let text = cast_text(&recorder.take_chunks());
        assert!(
            text.contains("\"before\"") && text.contains("\"late output\""),
            "{text}"
        );
        assert!(!text.contains("never delivered"), "{text}");
    }
    let (mut recorder, _) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V4, true);
    cast.client_message(&mut recorder, &[255, 9]).unwrap();
    cast.client_message(&mut recorder, &message(STDIN, b"v4 has no close"))
        .unwrap();
}

#[test]
fn closing_another_channel_keeps_stdin_recorded() {
    let (mut recorder, _) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    cast.client_message(&mut recorder, &[255, STDOUT]).unwrap();
    cast.client_message(&mut recorder, &message(STDIN, b"still typed"))
        .unwrap();
    cast.finish(&mut recorder, STARTED_AT).unwrap();
    let text = cast_text(&recorder.take_chunks());
    assert!(text.contains("\"i\", \"still typed\""), "{text}");
}

#[test]
fn input_hidden_in_a_continuation_frame_breaks_the_stream() {
    let mask = [1, 2, 3, 4];
    let mut stream = encode_frame(Opcode::Binary, false, &[5], Some(mask)).unwrap();
    stream.extend(encode_frame(Opcode::Continuation, true, b"\x00rm -rf /\n", Some(mask)).unwrap());
    let (mut recorder, _) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    let mut reader = WsReader::new(Direction::ClientToServer, 4096);
    let mut messages = Vec::new();
    assert_eq!(
        reader.feed(&stream, &mut messages),
        Err(WsError::FragmentedMessage)
    );
    for message in &messages {
        if let WsMessage::Binary(bytes) = message {
            cast.client_message(&mut recorder, bytes).unwrap();
        }
    }
    assert!(messages.is_empty());
    assert_eq!(reader.end_of_stream(), Err(WsError::FragmentedMessage));
}

#[test]
fn a_bad_close_signal_is_an_error_and_wrong_way_channels_are_ignored() {
    let (mut recorder, _) = recorder(true);
    let mut cast = ExecCast::new(ChannelProtocol::V5, true);
    assert!(matches!(
        cast.client_message(&mut recorder, &[255]),
        Err(ExecCastError::Channel(_))
    ));
    cast.client_message(&mut recorder, &message(STDOUT, b"spoofed output"))
        .unwrap();
    cast.client_message(&mut recorder, &message(STATUS, br#"{"status":"Success"}"#))
        .unwrap();
    cast.server_message(&mut recorder, &message(STDIN, b"spoofed input"))
        .unwrap();
    let outcome = cast.finish(&mut recorder, STARTED_AT).unwrap();
    assert_eq!(outcome.status, ExecStatus::Missing);
    let text = cast_text(&recorder.take_chunks());
    assert!(!text.contains("spoofed"), "{text}");
}
