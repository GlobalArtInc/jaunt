mod support;

use jaunt_pgwire::{
    BackendDecoder, BackendMessage, Bind, CancelRequest, CopyFail, DecodeError, Event, Execute,
    FrontendDecoder, FrontendMessage, Limits, LimitsError, PasswordKind, PasswordVariant, Problem,
    ProtocolVersion, Target, TargetKind,
};
use support::*;

fn small_limits() -> Limits {
    Limits {
        max_data_message: 2048,
        max_statement_message: 1024,
        max_startup_message: 300,
        max_startup_parameters: 4,
        max_pending: 4096,
    }
}

fn malformed(message: &'static str, problem: Problem) -> DecodeError {
    DecodeError::Malformed { message, problem }
}

fn bind_body(portal: &str, statement: &str, formats: &[i16], values: &[&[u8]]) -> Vec<u8> {
    let mut body = cstr(portal);
    body.extend(cstr(statement));
    body.extend(i16s(&[i16::try_from(formats.len()).expect("small")]));
    body.extend(i16s(formats));
    body.extend(i16s(&[i16::try_from(values.len()).expect("small")]));
    for value in values {
        body.extend(i32s(&[i32::try_from(value.len()).expect("small")]));
        body.extend_from_slice(value);
    }
    body.extend(i16s(&[0]));
    body
}

#[test]
fn negotiation_requests_precede_the_startup_message() {
    let mut input = packet(GSSENC_REQUEST, &[]);
    input.extend(packet(SSL_REQUEST, &[]));
    input.extend(startup(&[
        ("user", "app"),
        ("database", "orders"),
        ("application_name", "psql"),
    ]));
    let messages = frontend(&input).only();
    assert_eq!(messages.len(), 3);
    assert!(matches!(messages[0], FrontendMessage::GssEncRequest));
    assert!(matches!(messages[1], FrontendMessage::SslRequest));
    let FrontendMessage::Startup(startup) = &messages[2] else {
        panic!("expected a startup message, got {:?}", messages[2]);
    };
    assert_eq!(startup.version(), ProtocolVersion::V3_0);
    assert_eq!(startup.parameter("user"), Some("app"));
    assert_eq!(startup.parameter("database"), Some("orders"));
    assert_eq!(startup.parameter("application_name"), Some("psql"));
    assert_eq!(startup.parameters().count(), 3);
}

#[test]
fn protocol_versions() {
    let cases: [(u32, Result<ProtocolVersion, DecodeError>); 5] = [
        (V3_0, Ok(ProtocolVersion::V3_0)),
        (V3_2, Ok(ProtocolVersion::V3_2)),
        (
            2 << 16,
            Err(DecodeError::UnsupportedProtocol { major: 2, minor: 0 }),
        ),
        (
            4 << 16,
            Err(DecodeError::UnsupportedProtocol { major: 4, minor: 0 }),
        ),
        (
            (1234 << 16) | 9999,
            Err(DecodeError::UnsupportedProtocol {
                major: 1234,
                minor: 9999,
            }),
        ),
    ];
    for (code, expected) in cases {
        let outcome = frontend(&startup_version(code, &[("user", "app")]));
        let actual = match outcome.error {
            Some(error) => Err(error),
            None => match &outcome.messages[0].0 {
                FrontendMessage::Startup(startup) => Ok(startup.version()),
                other => panic!("unexpected {other:?}"),
            },
        };
        assert_eq!(actual, expected, "code {code:#x}");
    }
}

#[test]
fn cancel_request_keys() {
    let cases: [(usize, bool); 5] = [(4, true), (32, true), (256, true), (3, false), (257, false)];
    for (key_length, accepted) in cases {
        let mut body = i32s(&[4242]);
        body.extend(vec![7u8; key_length]);
        let outcome = frontend(&packet(CANCEL_REQUEST, &body));
        if accepted {
            let messages = outcome.only();
            let FrontendMessage::Cancel(cancel) = &messages[0] else {
                panic!("expected a cancel request");
            };
            assert_eq!(cancel.process_id(), 4242);
            assert_eq!(cancel.secret_key(), vec![7u8; key_length].as_slice());
        } else {
            assert_eq!(
                outcome.error,
                Some(malformed("CancelRequest", Problem::InvalidLength)),
                "key of {key_length} bytes"
            );
        }
    }
}

#[test]
fn nothing_may_follow_a_cancel_request_or_terminate() {
    let mut cancel = packet(CANCEL_REQUEST, &i32s(&[1, 2]));
    cancel.push(b'Q');
    let terminate = after_startup(&[&message(b'X', &[]), &message(b'S', &[])]);
    for input in [cancel, terminate] {
        assert_eq!(frontend(&input).error, Some(DecodeError::DataAfterEnd));
    }
}

#[test]
fn negotiation_requests_may_not_repeat() {
    for (code, name) in [
        (SSL_REQUEST, "SSLRequest"),
        (GSSENC_REQUEST, "GSSENCRequest"),
    ] {
        let mut input = packet(code, &[]);
        input.extend(packet(code, &[]));
        assert_eq!(
            frontend(&input).error,
            Some(DecodeError::RepeatedNegotiation { message: name })
        );
    }
}

#[test]
fn regular_messages() {
    let mut parse = cstr("s1");
    parse.extend(cstr("SELECT $1"));
    parse.extend(i16s(&[1]));
    parse.extend(i32s(&[23]));
    let mut execute = cstr("p1");
    execute.extend(i32s(&[10]));
    let mut describe = vec![b'S'];
    describe.extend(cstr("s1"));
    let mut close = vec![b'P'];
    close.extend(cstr("p1"));
    let parts: Vec<Vec<u8>> = vec![
        message(b'Q', &cstr("SELECT 1")),
        message(b'P', &parse),
        message(b'B', &bind_body("p1", "s1", &[1], &[b"42"])),
        message(b'D', &describe),
        message(b'E', &execute),
        message(b'C', &close),
        message(b'S', &[]),
        message(b'H', &[]),
        message(b'd', b"1\t2\n"),
        message(b'c', &[]),
        message(b'f', &cstr("aborted")),
        message(b'p', &cstr("never")),
        message(b'X', &[]),
    ];
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    let outcome = frontend(&after_startup(&refs));
    assert_eq!(outcome.error, None);
    let regular = &outcome.messages[1..];
    for ((_, bytes), original) in regular.iter().zip(&parts) {
        assert_eq!(bytes, original);
    }
    let kinds: Vec<String> = regular
        .iter()
        .map(|(message, _)| match message {
            FrontendMessage::Query(statement) => {
                format!("Q {}", statement.excerpt(100).text)
            }
            FrontendMessage::Parse(parse) => format!(
                "P {} {} {}",
                parse.name,
                parse.statement.excerpt(100).text,
                parse.parameter_type_count
            ),
            other => format!("{other:?}"),
        })
        .collect();
    let expected: Vec<String> = vec![
        "Q SELECT 1".into(),
        "P s1 SELECT $1 1".into(),
        format!(
            "{:?}",
            FrontendMessage::Bind(Bind {
                portal: "p1".into(),
                statement: "s1".into(),
                parameter_format_count: 1,
                parameter_count: 1,
            })
        ),
        format!(
            "{:?}",
            FrontendMessage::Describe(Target {
                kind: TargetKind::Statement,
                name: "s1".into()
            })
        ),
        format!(
            "{:?}",
            FrontendMessage::Execute(Execute {
                portal: "p1".into(),
                max_rows: 10
            })
        ),
        format!(
            "{:?}",
            FrontendMessage::Close(Target {
                kind: TargetKind::Portal,
                name: "p1".into()
            })
        ),
        format!("{:?}", FrontendMessage::Sync),
        format!("{:?}", FrontendMessage::Flush),
        format!("{:?}", FrontendMessage::CopyData { length: 4 }),
        format!("{:?}", FrontendMessage::CopyDone),
        format!(
            "{:?}",
            FrontendMessage::CopyFail(CopyFail {
                message: "aborted".into()
            })
        ),
        "Password(PasswordResponse { length: 6, body: \"[redacted]\" })".into(),
        format!("{:?}", FrontendMessage::Terminate),
    ];
    assert_eq!(kinds, expected);
}

#[test]
fn bind_values_are_streamed_and_never_parsed() {
    let value = vec![b'v'; 1500];
    let body = bind_body("", "s1", &[], &[&value, b"x"]);
    let input = after_startup(&[&message(b'B', &body)]);
    let mut decoder = FrontendDecoder::new(small_limits()).expect("valid limits");
    decoder.push(&input).expect("fits the pending limit");
    decoder.next_event().expect("startup").expect("an event");
    let Some(Event::Frame(frame)) = decoder.next_event().expect("bind") else {
        panic!("expected a frame");
    };
    let prefix = 5 + 1 + 3 + 2 + 2;
    assert_eq!(frame.raw().len(), prefix);
    assert_eq!(frame.remaining(), body.len() + 5 - prefix);
    let FrontendMessage::Bind(bind) = frame.message() else {
        panic!("expected a bind");
    };
    assert_eq!(
        bind,
        &Bind {
            portal: String::new(),
            statement: "s1".into(),
            parameter_format_count: 0,
            parameter_count: 2,
        }
    );
    let Some(Event::Continuation(chunk)) = decoder.next_event().expect("values") else {
        panic!("expected a continuation");
    };
    assert_eq!(chunk.bytes().len(), frame.remaining());
    assert!(!format!("{frame:?}{chunk:?}").contains("vvvv"));
    assert!(matches!(decoder.next_event(), Ok(None)));
    assert_eq!(decoder.pending(), 0);
}

#[test]
fn copy_data_is_streamed_in_chunks() {
    let payload = vec![b'r'; 1800];
    let input = after_startup(&[&message(b'd', &payload)]);
    let mut decoder = FrontendDecoder::new(small_limits()).expect("valid limits");
    let outcome = run(&mut decoder, &input, 700);
    assert_eq!(outcome.error, None);
    assert!(matches!(
        outcome.messages[1].0,
        FrontendMessage::CopyData { length: 1800 }
    ));
    assert_eq!(outcome.messages[1].1, message(b'd', &payload));
}

#[test]
fn malformed_input_is_refused() {
    let mut inner_nul = b"SELECT 1".to_vec();
    inner_nul.push(0);
    inner_nul.extend(cstr("x"));
    let mut parse_trailing = cstr("");
    parse_trailing.extend(cstr("SELECT 1"));
    parse_trailing.extend(i16s(&[0]));
    parse_trailing.push(0);
    let mut negative_formats = cstr("");
    negative_formats.extend(cstr(""));
    negative_formats.extend(i16s(&[-1]));
    let mut truncated_bind = cstr("");
    truncated_bind.extend(cstr(""));
    truncated_bind.push(0);
    let cases: Vec<(Vec<u8>, DecodeError)> = vec![
        (
            after_startup(&[&message(b'Q', b"SELECT 1")]),
            malformed("Query", Problem::MissingTerminator),
        ),
        (
            after_startup(&[&message(b'Q', &inner_nul)]),
            malformed("Query", Problem::TrailingBytes),
        ),
        (
            after_startup(&[&message(b'S', b"x")]),
            malformed("Sync", Problem::InvalidLength),
        ),
        (
            after_startup(&[&message(b'D', &[b'X', 0])]),
            malformed("Describe", Problem::InvalidValue),
        ),
        (
            after_startup(&[&message(b'P', &parse_trailing)]),
            malformed("Parse", Problem::TrailingBytes),
        ),
        (
            after_startup(&[&message(b'B', &negative_formats)]),
            malformed("Bind", Problem::NegativeCount),
        ),
        (
            after_startup(&[&message(b'B', &truncated_bind)]),
            malformed("Bind", Problem::Truncated),
        ),
        (
            after_startup(&[&message(b'B', b"portal")]),
            malformed("Bind", Problem::MissingTerminator),
        ),
        (
            after_startup(&[&[b'Q', 0xff, 0xff, 0xff, 0xff]]),
            malformed("message", Problem::InvalidLength),
        ),
        (
            after_startup(&[&[b'Q', 0, 0, 0, 3]]),
            malformed("message", Problem::InvalidLength),
        ),
        (
            after_startup(&[&message(b'Z', &[])]),
            DecodeError::UnknownMessage { tag: b'Z' },
        ),
        (
            after_startup(&[&message(b'F', &i32s(&[1]))]),
            DecodeError::FunctionCallRefused,
        ),
        (
            vec![0, 0, 0, 4],
            malformed("startup packet", Problem::InvalidLength),
        ),
        (
            packet(V3_0, &cstr("user")),
            malformed("StartupMessage", Problem::MissingTerminator),
        ),
        (
            packet(V3_0, &[]),
            malformed("StartupMessage", Problem::MissingTerminator),
        ),
        (
            packet(V3_0, b"user\0app\0\0x"),
            malformed("StartupMessage", Problem::TrailingBytes),
        ),
        (
            startup(&[("user", "a"), ("application_name", "x"), ("User", "b")]),
            DecodeError::DuplicateStartupParameter,
        ),
        (
            packet(V3_0, b"user\0\xff\0\0"),
            malformed("StartupMessage", Problem::InvalidUtf8),
        ),
        (
            packet(SSL_REQUEST, &[0]),
            malformed("SSLRequest", Problem::InvalidLength),
        ),
        (
            startup(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]),
            DecodeError::TooManyStartupParameters { limit: 4 },
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(frontend_with(small_limits(), &input).error, Some(expected));
    }
}

#[test]
fn oversize_messages_poison_the_decoder() {
    let long_query = cstr(&"x".repeat(1100));
    let mut long_portal = vec![b'a'; 1100];
    long_portal.push(0);
    let mut many_formats = cstr("");
    many_formats.extend(cstr(""));
    many_formats.extend(i16s(&[600]));
    let cases: Vec<(Vec<u8>, DecodeError)> = vec![
        (
            after_startup(&[&message(b'Q', &long_query)]),
            DecodeError::TooLarge {
                message: "Query",
                length: 1105,
                limit: 1024,
            },
        ),
        (
            after_startup(&[&message(b'd', &vec![0; 2045])]),
            DecodeError::TooLarge {
                message: "CopyData",
                length: 2049,
                limit: 2048,
            },
        ),
        (
            startup(&[("user", &"u".repeat(300))]),
            DecodeError::TooLarge {
                message: "startup packet",
                length: 315,
                limit: 300,
            },
        ),
        (
            after_startup(&[&message(b'B', &long_portal)]),
            DecodeError::BindPrefixTooLarge { limit: 1024 },
        ),
        (
            after_startup(&[&message(b'B', &many_formats)]),
            DecodeError::BindPrefixTooLarge { limit: 1024 },
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(
            frontend_with(small_limits(), &input).error,
            Some(expected.clone())
        );
        let mut decoder = FrontendDecoder::new(small_limits()).expect("valid limits");
        decoder.push(&input).expect("fits the pending limit");
        let first_error = (0..4).find_map(|_| decoder.next_event().err());
        assert_eq!(first_error, Some(expected));
        assert!(decoder.is_poisoned());
        assert_eq!(decoder.pending(), 0);
        assert_eq!(decoder.next_event().err(), Some(DecodeError::Poisoned));
        assert_eq!(
            decoder.push(&message(b'S', &[])),
            Err(DecodeError::Poisoned)
        );
    }
}

#[test]
fn pending_input_is_bounded() {
    let mut decoder = FrontendDecoder::new(small_limits()).expect("valid limits");
    decoder.push(&[0; 4000]).expect("below the limit");
    assert_eq!(
        decoder.push(&[0; 97]),
        Err(DecodeError::PendingTooLarge {
            length: 4097,
            limit: 4096
        })
    );
    assert_eq!(decoder.next_event().err(), Some(DecodeError::Poisoned));
}

#[test]
fn limits_are_validated() {
    let cases = [
        (Limits::default(), Ok(())),
        (
            Limits {
                max_statement_message: 512,
                ..Limits::default()
            },
            Err(LimitsError::BelowMinimum {
                limit: "max_statement_message",
                minimum: 1024,
            }),
        ),
        (
            Limits {
                max_startup_message: 100,
                ..Limits::default()
            },
            Err(LimitsError::BelowMinimum {
                limit: "max_startup_message",
                minimum: 268,
            }),
        ),
        (
            Limits {
                max_data_message: usize::MAX,
                ..Limits::default()
            },
            Err(LimitsError::AboveWireMaximum {
                limit: "max_data_message",
            }),
        ),
        (
            Limits {
                max_pending: 1024 * 1024,
                ..Limits::default()
            },
            Err(LimitsError::PendingTooSmall {
                required: 1024 * 1024 + 1,
            }),
        ),
    ];
    for (limits, expected) in cases {
        assert_eq!(limits.validate(), expected);
        assert_eq!(FrontendDecoder::new(limits).err(), expected.err());
    }
}

#[test]
fn password_responses_are_interpreted_without_exposing_data() {
    let mut sasl_initial = cstr("SCRAM-SHA-256");
    sasl_initial.extend(i32s(&[5]));
    sasl_initial.extend(b"n,,n=");
    let mut no_data = cstr("SCRAM-SHA-256");
    no_data.extend(i32s(&[-1]));
    let mut short = cstr("SCRAM-SHA-256");
    short.extend(i32s(&[9]));
    short.extend(b"n,,");
    let cases: Vec<(Vec<u8>, PasswordKind, Result<PasswordVariant, DecodeError>)> = vec![
        (
            cstr("hunter2"),
            PasswordKind::Password,
            Ok(PasswordVariant::Password),
        ),
        (
            b"hunter2".to_vec(),
            PasswordKind::Password,
            Err(malformed("password response", Problem::MissingTerminator)),
        ),
        (
            sasl_initial,
            PasswordKind::SaslInitial,
            Ok(PasswordVariant::SaslInitial {
                mechanism: "SCRAM-SHA-256".into(),
                data_length: Some(5),
            }),
        ),
        (
            no_data,
            PasswordKind::SaslInitial,
            Ok(PasswordVariant::SaslInitial {
                mechanism: "SCRAM-SHA-256".into(),
                data_length: None,
            }),
        ),
        (
            short,
            PasswordKind::SaslInitial,
            Err(malformed("password response", Problem::Truncated)),
        ),
        (
            b"c=biws,r=abc".to_vec(),
            PasswordKind::Sasl,
            Ok(PasswordVariant::Sasl { data_length: 12 }),
        ),
        (
            vec![1, 2, 3],
            PasswordKind::Gss,
            Ok(PasswordVariant::Gss { data_length: 3 }),
        ),
    ];
    for (body, kind, expected) in cases {
        let messages = frontend(&after_startup(&[&message(b'p', &body)])).only();
        let FrontendMessage::Password(response) = &messages[1] else {
            panic!("expected a password response");
        };
        assert_eq!(response.length(), body.len());
        assert_eq!(response.interpret(kind), expected);
    }
}

#[test]
fn debug_output_redacts_secrets() {
    let mut cancel_body = i32s(&[77]);
    cancel_body.extend(b"KEYKEYKEY");
    let input = after_startup(&[
        &message(b'p', &cstr("hunter2-secret")),
        &message(b'Q', &cstr("ALTER ROLE app PASSWORD 'hunter2-secret'")),
        &message(b'B', &bind_body("", "", &[], &[b"hunter2-secret"])),
    ]);
    let mut decoder = FrontendDecoder::new(Limits::default()).expect("valid limits");
    decoder.push(&input).expect("fits");
    let mut events = Vec::new();
    while let Some(event) = decoder.next_event().expect("valid input") {
        events.push(event);
    }
    let cancel = frontend(&packet(CANCEL_REQUEST, &cancel_body)).only();
    let rendered = format!("{events:?} {events:#?} {cancel:?}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(!rendered.contains("KEYKEY"), "{rendered}");
    assert!(rendered.contains("[redacted]"));
}

#[test]
fn captured_psql_sessions_decode() {
    let v30 = include_bytes!("fixtures/psql-v3.0-frontend.bin");
    let messages = frontend(v30).only();
    let summary: Vec<String> = messages
        .iter()
        .map(|message| match message {
            FrontendMessage::Startup(startup) => format!("startup {:?}", startup.version()),
            FrontendMessage::Query(statement) => format!("Q {:?}", statement.kind()),
            FrontendMessage::Parse(parse) => format!("P {:?}", parse.statement.kind()),
            FrontendMessage::Bind(bind) => format!("B {}", bind.parameter_count),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        summary,
        [
            "SslRequest",
            "startup ProtocolVersion { major: 3, minor: 0 }",
            "Q Select",
            "P Select",
            "B 1",
            "Describe(Target { kind: Portal, name: \"\" })",
            "Execute(Execute { portal: \"\", max_rows: 0 })",
            "Sync",
            "Q Copy",
            "Q Ddl",
            "Q Copy",
            "CopyData { length: 2 }",
            "CopyDone",
            "Q Select",
            "Q Other",
            "Terminate",
        ]
    );
    let v32 = include_bytes!("fixtures/psql-v3.2-frontend.bin");
    let messages = frontend(v32).only();
    let FrontendMessage::Startup(startup) = &messages[0] else {
        panic!("expected a startup message");
    };
    assert_eq!(startup.version(), ProtocolVersion::V3_2);
    assert_eq!(messages.len(), 3);
}

#[test]
fn oversize_headers_fail_before_the_body_arrives() {
    let header = |tag: u8, length: i32| {
        let mut bytes = vec![tag];
        bytes.extend(i32s(&[length]));
        bytes
    };
    let cases: Vec<(Vec<u8>, DecodeError)> = vec![
        (
            after_startup(&[&header(b'Q', 1025)]),
            DecodeError::TooLarge {
                message: "Query",
                length: 1025,
                limit: 1024,
            },
        ),
        (
            after_startup(&[&header(b'P', 1025)]),
            DecodeError::TooLarge {
                message: "Parse",
                length: 1025,
                limit: 1024,
            },
        ),
        (
            after_startup(&[&header(b'B', 2049)]),
            DecodeError::TooLarge {
                message: "Bind",
                length: 2049,
                limit: 2048,
            },
        ),
        (
            i32s(&[301, 3 << 16]),
            DecodeError::TooLarge {
                message: "startup packet",
                length: 301,
                limit: 300,
            },
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(frontend_with(small_limits(), &input).error, Some(expected));
    }
}

trait AmbiguousIfPartialEq<Marker> {
    fn check() {}
}

impl<T: ?Sized> AmbiguousIfPartialEq<()> for T {}

struct ImplementsPartialEq;

impl<T: ?Sized + PartialEq> AmbiguousIfPartialEq<ImplementsPartialEq> for T {}

#[test]
fn cancel_keys_have_no_public_equality() {
    <CancelRequest as AmbiguousIfPartialEq<_>>::check();
    <jaunt_pgwire::BackendKeyData as AmbiguousIfPartialEq<_>>::check();
    <FrontendMessage as AmbiguousIfPartialEq<_>>::check();
    <BackendMessage as AmbiguousIfPartialEq<_>>::check();
}

#[test]
fn cancel_requests_match_backend_key_data() {
    let key_data = |process_id: i32, key: &[u8]| {
        let mut body = i32s(&[process_id]);
        body.extend_from_slice(key);
        let mut decoder = BackendDecoder::new(Limits::default()).expect("valid limits");
        decoder.push(&message(b'K', &body)).expect("fits");
        match decoder.next_event() {
            Ok(Some(Event::Frame(frame))) => match frame.into_message() {
                BackendMessage::BackendKeyData(data) => data,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    };
    let cancel = |process_id: i32, key: &[u8]| {
        let mut body = i32s(&[process_id]);
        body.extend_from_slice(key);
        match frontend(&packet(CANCEL_REQUEST, &body)).only().remove(0) {
            FrontendMessage::Cancel(cancel) => cancel,
            other => panic!("unexpected {other:?}"),
        }
    };
    let issued = key_data(7, &[1; 32]);
    let cases: [(i32, &[u8], bool); 5] = [
        (7, &[1; 32], true),
        (8, &[1; 32], false),
        (7, &[2; 32], false),
        (7, &[1; 31], false),
        (7, &[1; 4], false),
    ];
    for (process_id, key, expected) in cases {
        assert_eq!(cancel(process_id, key).matches(&issued), expected);
    }
}

fn streamed(input: &[u8], step: usize) -> (Vec<(FrontendMessage, Vec<u8>)>, Option<DecodeError>) {
    let mut decoder = FrontendDecoder::with_streamed_queries(small_limits()).expect("valid limits");
    let outcome = run(&mut decoder, input, step);
    (outcome.messages, outcome.error)
}

#[test]
fn streamed_queries_pass_through_in_pieces_and_check_their_terminator() {
    let long = "x".repeat(1500);
    let valid = after_startup(&[&message(b'Q', &cstr(&long)), &message(b'S', &[])]);
    let (whole, error) = streamed(&valid, valid.len());
    assert_eq!(error, None);
    assert!(matches!(
        whole[1],
        (FrontendMessage::QueryText { length: 1501 }, _)
    ));
    assert_eq!(whole[1].1, message(b'Q', &cstr(&long)));
    assert!(matches!(whole[2].0, FrontendMessage::Sync));
    let (bytewise, error) = streamed(&valid, 7);
    assert_eq!(error, None);
    assert_eq!(bytewise.len(), whole.len());
    assert_eq!(bytewise[1].1, whole[1].1);

    let mut inner = b"SELECT 1".to_vec();
    inner.push(0);
    inner.extend_from_slice(b"DROP TABLE t");
    inner.push(0);
    let unterminated = b"SELECT 1".to_vec();
    let cases: [(Vec<u8>, DecodeError); 4] = [
        (
            message(b'Q', &inner),
            malformed("Query", Problem::TrailingBytes),
        ),
        (
            message(b'Q', &unterminated),
            malformed("Query", Problem::MissingTerminator),
        ),
        (
            message(b'Q', &[]),
            malformed("Query", Problem::MissingTerminator),
        ),
        (
            message(b'Q', &vec![b'x'; 2048]),
            DecodeError::TooLarge {
                message: "Query",
                length: 2052,
                limit: 2048,
            },
        ),
    ];
    for (bad, expected) in cases {
        let input = after_startup(&[&bad]);
        for step in [1, input.len()] {
            let (messages, error) = streamed(&input, step);
            assert_eq!(error.as_ref(), Some(&expected), "{bad:?}");
            let passed: usize = messages.iter().map(|(_, bytes)| bytes.len()).sum();
            assert!(!input[..passed].ends_with(b"DROP TABLE t\0"));
        }
    }
}

#[test]
fn buffered_queries_stay_the_default() {
    let input = after_startup(&[&message(b'Q', &cstr("SELECT 1"))]);
    let messages = frontend(&input).only();
    let FrontendMessage::Query(statement) = &messages[1] else {
        panic!("expected a buffered query, got {:?}", messages[1]);
    };
    assert_eq!(statement.as_bytes(), b"SELECT 1");
}
