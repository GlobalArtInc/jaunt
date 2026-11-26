use jaunt_kube::{
    CLOSE_SIGNAL, ChannelError, ChannelFrame, ChannelProtocol, Direction, Opcode, RESIZE, STDIN,
    STDOUT, WsError, WsMessage, WsReader, build_channel_message, encode_frame,
    parse_channel_message,
};

const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];
const LIMIT: usize = 1024;

fn client(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    encode_frame(opcode, fin, payload, Some(MASK)).unwrap()
}

fn server(opcode: Opcode, fin: bool, payload: &[u8]) -> Vec<u8> {
    encode_frame(opcode, fin, payload, None).unwrap()
}

fn read_all(direction: Direction, bytes: &[u8]) -> (Vec<WsMessage>, Result<(), WsError>) {
    let mut reader = WsReader::new(direction, LIMIT);
    let mut out = Vec::new();
    let result = reader.feed(bytes, &mut out);
    (out, result)
}

#[test]
fn messages_survive_any_split_of_the_byte_stream() {
    let long = vec![7u8; 300];
    let mut stream = Vec::new();
    stream.extend(client(Opcode::Binary, true, b"\x00ls\r"));
    stream.extend(client(Opcode::Ping, true, b"hi"));
    stream.extend(client(Opcode::Binary, true, b"\x00partial"));
    stream.extend(client(Opcode::Pong, true, b""));
    stream.extend(client(Opcode::Binary, true, &long));
    stream.extend(client(Opcode::Binary, true, b""));
    stream.extend(client(Opcode::Close, true, &[0x03, 0xe8, b'o', b'k']));
    let expected = vec![
        WsMessage::Binary(b"\x00ls\r".to_vec()),
        WsMessage::Ping(b"hi".to_vec()),
        WsMessage::Binary(b"\x00partial".to_vec()),
        WsMessage::Pong(Vec::new()),
        WsMessage::Binary(long.clone()),
        WsMessage::Binary(Vec::new()),
        WsMessage::Close(Some(1000)),
    ];
    for step in [1, 2, 3, 5, 13, stream.len()] {
        let mut reader = WsReader::new(Direction::ClientToServer, LIMIT);
        let mut out = Vec::new();
        for piece in stream.chunks(step) {
            reader.feed(piece, &mut out).unwrap();
        }
        assert_eq!(out, expected, "split into {step}-byte pieces");
        assert!(reader.is_closed());
        assert_eq!(reader.end_of_stream(), Ok(()));
    }
}

#[test]
fn every_length_encoding_round_trips() {
    for len in [0usize, 125, 126, 65535, 65536] {
        let payload: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
        let mut reader = WsReader::new(Direction::ServerToClient, 70_000);
        let mut out = Vec::new();
        reader
            .feed(&server(Opcode::Binary, true, &payload), &mut out)
            .unwrap();
        assert_eq!(out, vec![WsMessage::Binary(payload)], "length {len}");
    }
}

#[test]
fn malformed_frames_fail_with_a_typed_error() {
    let mut reserved = server(Opcode::Binary, true, b"x");
    reserved[0] |= 0x40;
    let mut unknown_opcode = server(Opcode::Binary, true, b"x");
    unknown_opcode[0] = 0x83;
    let mut huge_length = vec![0x82, 0x7f];
    huge_length.extend_from_slice(&u64::MAX.to_be_bytes());
    let mut fragmented_ping = server(Opcode::Ping, true, b"x");
    fragmented_ping[0] &= 0x7f;
    let mut long_ping = vec![0x89, 126];
    long_ping.extend_from_slice(&126u16.to_be_bytes());
    let over_limit = server(Opcode::Binary, true, &vec![0; LIMIT + 1]);
    let mut after_close = server(Opcode::Close, true, b"");
    after_close.extend(server(Opcode::Binary, true, b"x"));
    let cases: Vec<(&str, Direction, Vec<u8>, WsError)> = vec![
        (
            "reserved bits",
            Direction::ServerToClient,
            reserved,
            WsError::ReservedBits,
        ),
        (
            "unknown opcode",
            Direction::ServerToClient,
            unknown_opcode,
            WsError::UnknownOpcode,
        ),
        (
            "unmasked client frame",
            Direction::ClientToServer,
            server(Opcode::Binary, true, b"x"),
            WsError::Unmasked,
        ),
        (
            "masked server frame",
            Direction::ServerToClient,
            client(Opcode::Binary, true, b"x"),
            WsError::Masked,
        ),
        (
            "length with the top bit",
            Direction::ServerToClient,
            huge_length,
            WsError::InvalidLength,
        ),
        (
            "fragmented control",
            Direction::ServerToClient,
            fragmented_ping,
            WsError::FragmentedControl,
        ),
        (
            "long control",
            Direction::ServerToClient,
            long_ping,
            WsError::ControlTooLong,
        ),
        (
            "text message",
            Direction::ServerToClient,
            server(Opcode::Text, true, b"x"),
            WsError::TextMessage,
        ),
        (
            "oversize frame",
            Direction::ServerToClient,
            over_limit,
            WsError::TooLarge { limit: LIMIT },
        ),
        (
            "one byte close payload",
            Direction::ServerToClient,
            server(Opcode::Close, true, b"\x03"),
            WsError::InvalidClose,
        ),
        (
            "close reason not utf-8",
            Direction::ServerToClient,
            server(Opcode::Close, true, b"\x03\xe8\xff"),
            WsError::InvalidClose,
        ),
        (
            "frame after close",
            Direction::ServerToClient,
            after_close,
            WsError::AfterClose,
        ),
    ];
    for (label, direction, bytes, error) in cases {
        let (_, result) = read_all(direction, &bytes);
        assert_eq!(result, Err(error), "{label}");
    }
}

#[test]
fn an_oversize_frame_is_refused_from_its_header_alone() {
    let mut reader = WsReader::new(Direction::ServerToClient, LIMIT);
    let mut header = vec![0x82, 0x7f];
    header.extend_from_slice(&(1u64 << 40).to_be_bytes());
    let mut out = Vec::new();
    assert_eq!(
        reader.feed(&header, &mut out),
        Err(WsError::TooLarge { limit: LIMIT })
    );
}

#[test]
fn a_failed_reader_stays_failed_and_keeps_earlier_messages() {
    let mut stream = server(Opcode::Binary, true, b"\x01ok");
    stream.extend(server(Opcode::Text, true, b"no"));
    let mut reader = WsReader::new(Direction::ServerToClient, LIMIT);
    let mut out = Vec::new();
    assert_eq!(reader.feed(&stream, &mut out), Err(WsError::TextMessage));
    assert_eq!(out, vec![WsMessage::Binary(b"\x01ok".to_vec())]);
    assert_eq!(
        reader.feed(&server(Opcode::Binary, true, b"x"), &mut out),
        Err(WsError::TextMessage)
    );
    assert_eq!(reader.end_of_stream(), Err(WsError::TextMessage));
    assert_eq!(out.len(), 1);
}

#[test]
fn a_stream_cut_inside_a_frame_is_truncated() {
    let frame = server(Opcode::Binary, true, b"\x01hello");
    for (label, bytes) in [
        ("inside the header", &frame[..1]),
        ("inside the extended length", &[0x82, 126, 0][..]),
        ("inside the payload", &frame[..frame.len() - 1]),
    ] {
        let mut reader = WsReader::new(Direction::ServerToClient, LIMIT);
        let mut out = Vec::new();
        reader.feed(bytes, &mut out).unwrap();
        assert!(out.is_empty(), "{label}");
        assert_eq!(reader.end_of_stream(), Err(WsError::Truncated), "{label}");
    }
    let mut reader = WsReader::new(Direction::ServerToClient, LIMIT);
    reader.feed(&frame, &mut Vec::new()).unwrap();
    assert_eq!(reader.end_of_stream(), Ok(()));
}

#[test]
fn fragmented_messages_are_refused_in_both_directions() {
    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        let frame = |opcode, fin, payload: &[u8]| match direction {
            Direction::ClientToServer => client(opcode, fin, payload),
            Direction::ServerToClient => server(opcode, fin, payload),
        };
        let mut continued = frame(Opcode::Binary, false, b"\x05");
        continued.extend(frame(Opcode::Continuation, true, b"\x00rm -rf /\n"));
        let mut after_message = frame(Opcode::Binary, true, b"\x00a");
        after_message.extend(frame(Opcode::Continuation, true, b"\x00b"));
        for (label, bytes) in [
            ("binary without fin", frame(Opcode::Binary, false, b"\x00a")),
            (
                "empty binary without fin",
                frame(Opcode::Binary, false, b""),
            ),
            ("text without fin", frame(Opcode::Text, false, b"0a")),
            (
                "lone continuation",
                frame(Opcode::Continuation, true, b"\x00a"),
            ),
            (
                "unfinished continuation",
                frame(Opcode::Continuation, false, b""),
            ),
            ("continuation after a message", after_message),
            ("continuation hiding stdin", continued),
        ] {
            let (out, result) = read_all(direction, &bytes);
            assert_eq!(
                result,
                Err(WsError::FragmentedMessage),
                "{direction:?} {label}"
            );
            let expected: Vec<WsMessage> = if label == "continuation after a message" {
                vec![WsMessage::Binary(b"\x00a".to_vec())]
            } else {
                Vec::new()
            };
            assert_eq!(out, expected, "{direction:?} {label}");
        }
    }
}

#[test]
fn every_frame_is_its_own_message() {
    let mut stream = client(Opcode::Binary, true, b"\x00a");
    stream.extend(client(Opcode::Binary, true, b"\x05b"));
    let (out, result) = read_all(Direction::ClientToServer, &stream);
    assert_eq!(result, Ok(()));
    assert_eq!(
        out,
        vec![
            WsMessage::Binary(b"\x00a".to_vec()),
            WsMessage::Binary(b"\x05b".to_vec()),
        ]
    );
}

#[test]
fn an_error_inside_a_completed_frame_poisons_the_reader() {
    let mut stream = server(Opcode::Close, true, b"\x03");
    stream.extend(server(Opcode::Binary, true, b"\x01after"));
    let mut reader = WsReader::new(Direction::ServerToClient, LIMIT);
    let mut out = Vec::new();
    assert_eq!(reader.feed(&stream, &mut out), Err(WsError::InvalidClose));
    assert_eq!(
        reader.feed(&server(Opcode::Binary, true, b"\x01x"), &mut out),
        Err(WsError::InvalidClose)
    );
    assert!(out.is_empty());
    assert!(!reader.is_closed());
}

#[test]
fn debug_output_never_shows_terminal_bytes() {
    let secret = b"\x00hunter2-password";
    let mut reader = WsReader::new(Direction::ClientToServer, LIMIT);
    let frame = client(Opcode::Binary, true, secret);
    let mut out = Vec::new();
    reader.feed(&frame[..frame.len() - 3], &mut out).unwrap();
    let message = WsMessage::Binary(secret.to_vec());
    let channel = parse_channel_message(ChannelProtocol::V5, secret).unwrap();
    for shown in [
        format!("{reader:?}"),
        format!("{message:?}"),
        format!("{:?}", WsMessage::Ping(b"hunter2".to_vec())),
        format!("{channel:?}"),
    ] {
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(!shown.contains("104, 117"), "{shown}");
    }
    assert!(format!("{message:?}").contains("bytes: 17"));
    assert!(format!("{channel:?}").contains("bytes: 16"));
}

#[test]
fn control_frames_cannot_be_built_out_of_spec() {
    assert_eq!(
        encode_frame(Opcode::Ping, true, &[0; 126], None),
        Err(WsError::ControlTooLong)
    );
    assert_eq!(
        encode_frame(Opcode::Close, false, b"", None),
        Err(WsError::FragmentedControl)
    );
}

#[test]
fn channel_messages_parse_and_build_back() {
    for (protocol, message, frame) in [
        (
            ChannelProtocol::V4,
            &b"\x00ls\n"[..],
            ChannelFrame::Data {
                channel: STDIN,
                payload: b"ls\n",
            },
        ),
        (
            ChannelProtocol::V5,
            b"\x01out",
            ChannelFrame::Data {
                channel: STDOUT,
                payload: b"out",
            },
        ),
        (
            ChannelProtocol::V5,
            b"\x04{}",
            ChannelFrame::Data {
                channel: RESIZE,
                payload: b"{}",
            },
        ),
        (
            ChannelProtocol::V5,
            b"\x00",
            ChannelFrame::Data {
                channel: STDIN,
                payload: b"",
            },
        ),
        (
            ChannelProtocol::V5,
            b"\x09x",
            ChannelFrame::Data {
                channel: 9,
                payload: b"x",
            },
        ),
        (
            ChannelProtocol::V5,
            b"\xff\x00",
            ChannelFrame::Close { channel: STDIN },
        ),
        (
            ChannelProtocol::V4,
            b"\xff\x00",
            ChannelFrame::Data {
                channel: CLOSE_SIGNAL,
                payload: b"\x00",
            },
        ),
    ] {
        assert_eq!(
            parse_channel_message(protocol, message),
            Ok(frame),
            "{message:?}"
        );
        assert_eq!(
            build_channel_message(protocol, &frame).unwrap(),
            message,
            "{message:?}"
        );
    }
}

#[test]
fn bad_channel_messages_are_typed_errors() {
    for (protocol, message, error) in [
        (ChannelProtocol::V4, &b""[..], ChannelError::Empty),
        (ChannelProtocol::V5, b"", ChannelError::Empty),
        (
            ChannelProtocol::V5,
            b"\xff",
            ChannelError::InvalidCloseSignal,
        ),
        (
            ChannelProtocol::V5,
            b"\xff\x00\x01",
            ChannelError::InvalidCloseSignal,
        ),
    ] {
        assert_eq!(
            parse_channel_message(protocol, message),
            Err(error),
            "{message:?}"
        );
    }
    assert_eq!(
        build_channel_message(
            ChannelProtocol::V5,
            &ChannelFrame::Data {
                channel: CLOSE_SIGNAL,
                payload: b"x"
            }
        ),
        Err(ChannelError::ReservedChannel)
    );
    assert_eq!(
        build_channel_message(ChannelProtocol::V4, &ChannelFrame::Close { channel: STDIN }),
        Err(ChannelError::CloseUnsupported)
    );
}

#[test]
fn only_binary_channel_subprotocols_are_known() {
    for (name, protocol) in [
        ("v4.channel.k8s.io", Some(ChannelProtocol::V4)),
        ("v5.channel.k8s.io", Some(ChannelProtocol::V5)),
        ("base64.channel.k8s.io", None),
        ("v4.base64.channel.k8s.io", None),
        ("V5.channel.k8s.io", None),
        ("channel.k8s.io", None),
    ] {
        assert_eq!(ChannelProtocol::from_subprotocol(name), protocol, "{name}");
        if let Some(protocol) = protocol {
            assert_eq!(protocol.as_str(), name);
        }
    }
}
