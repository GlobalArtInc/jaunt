#![no_main]

use std::time::Duration;

use jaunt_kube::{
    ChannelProtocol, Direction, ExecCast, WsMessage, WsReader, build_channel_message,
    parse_channel_message,
};
use jaunt_record::{Clock, Recorder, RecorderConfig, SessionKind};
use libfuzzer_sys::fuzz_target;

const LIMIT: usize = 4096;

struct StillClock;

impl Clock for StillClock {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
}

fn recorder() -> Recorder {
    let config = RecorderConfig {
        session_id: "fuzz".to_owned(),
        kind: SessionKind::Exec,
        node: "kube".to_owned(),
        user: "user".to_owned(),
        login: "user".to_owned(),
        command: Some("sh".to_owned()),
        started_at: 0,
        width: 80,
        height: 24,
        shell: String::new(),
        term: "xterm".to_owned(),
        record_input: true,
    };
    Recorder::new(config, Box::new(StillClock)).expect("a fixed config is valid")
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, stream)) = data.split_first() else {
        return;
    };
    let direction = if control & 1 == 0 {
        Direction::ClientToServer
    } else {
        Direction::ServerToClient
    };
    let protocol = if control & 2 == 0 {
        ChannelProtocol::V4
    } else {
        ChannelProtocol::V5
    };
    let step = usize::from(control >> 2) + 1;

    let mut whole = WsReader::new(direction, LIMIT);
    let mut whole_out = Vec::new();
    let whole_result = whole.feed(stream, &mut whole_out);

    let mut split = WsReader::new(direction, LIMIT);
    let mut split_out = Vec::new();
    let mut split_result = Ok(());
    for piece in stream.chunks(step) {
        split_result = split.feed(piece, &mut split_out);
        if split_result.is_err() {
            break;
        }
    }
    assert_eq!(split_result, whole_result);
    assert_eq!(split_out, whole_out);
    assert_eq!(split.end_of_stream(), whole.end_of_stream());

    let mut recorder = recorder();
    let mut cast = ExecCast::new(protocol, control & 0x80 == 0);
    for message in &whole_out {
        let WsMessage::Binary(bytes) = message else {
            continue;
        };
        assert!(bytes.len() <= LIMIT);
        if let Ok(frame) = parse_channel_message(protocol, bytes) {
            assert_eq!(
                build_channel_message(protocol, &frame).as_deref(),
                Ok(bytes.as_slice())
            );
        }
        let _ = match direction {
            Direction::ClientToServer => cast.client_message(&mut recorder, bytes),
            Direction::ServerToClient => cast.server_message(&mut recorder, bytes),
        };
    }
    let _ = cast.status();
    let _ = cast.finish(&mut recorder, 1);
});
