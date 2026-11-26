mod support;

use jaunt_pgwire::{
    Authentication, BackendDecoder, BackendMessage, CommandComplete, CopyFormat, CopyResponse,
    DecodeError, Limits, NegotiateProtocolVersion, Notice, ParameterStatus, Problem,
    ProtocolVersion, TransactionStatus,
};
use support::*;

fn malformed(message: &'static str, problem: Problem) -> DecodeError {
    DecodeError::Malformed { message, problem }
}

fn authentication(code: i32, extra: &[u8]) -> Vec<u8> {
    let mut body = i32s(&[code]);
    body.extend_from_slice(extra);
    message(b'R', &body)
}

fn fields(fields: &[(u8, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (code, value) in fields {
        body.push(*code);
        body.extend(cstr(value));
    }
    body.push(0);
    body
}

type TaggedNotice = Result<(u8, Notice), DecodeError>;

fn debug<T: std::fmt::Debug>(value: T) -> String {
    format!("{value:?}")
}

fn single(input: &[u8]) -> Result<BackendMessage, DecodeError> {
    let outcome = backend(input);
    match outcome.error {
        Some(error) => Err(error),
        None => {
            assert_eq!(outcome.messages.len(), 1);
            assert_eq!(outcome.messages[0].1, input);
            Ok(outcome.messages.into_iter().next().expect("one message").0)
        }
    }
}

#[test]
fn authentication_requests() {
    let mut mechanisms = cstr("SCRAM-SHA-256-PLUS");
    mechanisms.extend(cstr("SCRAM-SHA-256"));
    mechanisms.push(0);
    let cases: Vec<(Vec<u8>, Result<Authentication, DecodeError>)> = vec![
        (authentication(0, &[]), Ok(Authentication::Ok)),
        (authentication(2, &[]), Ok(Authentication::KerberosV5)),
        (
            authentication(3, &[]),
            Ok(Authentication::CleartextPassword),
        ),
        (authentication(5, b"salt"), Ok(Authentication::Md5Password)),
        (authentication(7, &[]), Ok(Authentication::Gss)),
        (authentication(8, b"token"), Ok(Authentication::GssContinue)),
        (authentication(9, &[]), Ok(Authentication::Sspi)),
        (
            authentication(10, &mechanisms),
            Ok(Authentication::Sasl {
                mechanisms: vec!["SCRAM-SHA-256-PLUS".into(), "SCRAM-SHA-256".into()],
            }),
        ),
        (
            authentication(11, b"r=nonce"),
            Ok(Authentication::SaslContinue),
        ),
        (
            authentication(12, b"v=proof"),
            Ok(Authentication::SaslFinal),
        ),
        (
            authentication(6, &[]),
            Err(DecodeError::UnknownAuthentication { code: 6 }),
        ),
        (
            authentication(0, &[0]),
            Err(malformed("Authentication", Problem::TrailingBytes)),
        ),
        (
            authentication(5, b"sa"),
            Err(malformed("Authentication", Problem::Truncated)),
        ),
        (
            authentication(10, &cstr("SCRAM-SHA-256")),
            Err(malformed("Authentication", Problem::MissingTerminator)),
        ),
    ];
    for (input, expected) in cases {
        let actual = single(&input).map(|message| match message {
            BackendMessage::Authentication(request) => request,
            other => panic!("unexpected {other:?}"),
        });
        assert_eq!(actual, expected);
        if let Ok(request) = actual {
            assert_eq!(request.is_ok(), request == Authentication::Ok);
        }
    }
}

#[test]
fn backend_key_data_keys() {
    for (key_length, accepted) in [(4, true), (32, true), (256, true), (3, false), (257, false)] {
        let mut body = i32s(&[9001]);
        body.extend(vec![5u8; key_length]);
        match single(&message(b'K', &body)) {
            Ok(BackendMessage::BackendKeyData(data)) => {
                assert!(accepted, "key of {key_length} bytes");
                assert_eq!(data.process_id(), 9001);
                assert_eq!(data.secret_key(), vec![5u8; key_length].as_slice());
                let rendered = format!("{data:?}");
                assert!(!rendered.contains("x05"), "{rendered}");
                assert!(rendered.contains("[redacted]"), "{rendered}");
            }
            Ok(other) => panic!("unexpected {other:?}"),
            Err(error) => {
                assert!(!accepted, "key of {key_length} bytes");
                assert_eq!(error, malformed("BackendKeyData", Problem::InvalidLength));
            }
        }
    }
}

#[test]
fn status_messages() {
    let mut parameter = cstr("server_version");
    parameter.extend(cstr("18.1"));
    let mut negotiate = i32s(&[0x0003_0002, 1]);
    negotiate.extend(cstr("_pq_.unknown"));
    let mut copy_out = vec![1];
    copy_out.extend(i16s(&[2, 1, 1]));
    let cases: Vec<(Vec<u8>, Result<BackendMessage, DecodeError>)> = vec![
        (
            message(b'S', &parameter),
            Ok(BackendMessage::ParameterStatus(ParameterStatus {
                name: "server_version".into(),
                value: "18.1".into(),
            })),
        ),
        (
            message(b'Z', b"I"),
            Ok(BackendMessage::ReadyForQuery(TransactionStatus::Idle)),
        ),
        (
            message(b'Z', b"T"),
            Ok(BackendMessage::ReadyForQuery(
                TransactionStatus::InTransaction,
            )),
        ),
        (
            message(b'Z', b"E"),
            Ok(BackendMessage::ReadyForQuery(TransactionStatus::Failed)),
        ),
        (
            message(b'Z', b"X"),
            Err(malformed("ReadyForQuery", Problem::InvalidValue)),
        ),
        (
            message(b'Z', b"II"),
            Err(malformed("ReadyForQuery", Problem::TrailingBytes)),
        ),
        (
            message(b'G', &[0, 0, 1, 0, 0]),
            Ok(BackendMessage::CopyInResponse(CopyResponse {
                format: CopyFormat::Text,
                column_count: 1,
            })),
        ),
        (
            message(b'H', &copy_out),
            Ok(BackendMessage::CopyOutResponse(CopyResponse {
                format: CopyFormat::Binary,
                column_count: 2,
            })),
        ),
        (
            message(b'W', &[0, 0, 0]),
            Ok(BackendMessage::CopyBothResponse(CopyResponse {
                format: CopyFormat::Text,
                column_count: 0,
            })),
        ),
        (
            message(b'G', &[2, 0, 0]),
            Err(malformed("CopyInResponse", Problem::InvalidValue)),
        ),
        (
            message(b'G', &[0, 0, 1, 0, 2]),
            Err(malformed("CopyInResponse", Problem::InvalidValue)),
        ),
        (
            message(b'v', &negotiate),
            Ok(BackendMessage::NegotiateProtocolVersion(
                NegotiateProtocolVersion {
                    newest_version: ProtocolVersion::V3_2,
                    unrecognized_options: vec!["_pq_.unknown".into()],
                },
            )),
        ),
        (
            message(b'v', &i32s(&[0x0003_0000, -1])),
            Err(malformed(
                "NegotiateProtocolVersion",
                Problem::NegativeCount,
            )),
        ),
        (
            message(b'v', &i32s(&[0x0003_0000, 3])),
            Err(malformed(
                "NegotiateProtocolVersion",
                Problem::MissingTerminator,
            )),
        ),
        (
            message(b'D', &[0, 1, 0, 0, 0, 1, b'1']),
            Ok(BackendMessage::DataRow { length: 7 }),
        ),
        (
            message(b'd', b"1\n"),
            Ok(BackendMessage::CopyData { length: 2 }),
        ),
        (
            message(b'T', &[0, 0]),
            Ok(BackendMessage::Other {
                tag: b'T',
                length: 2,
            }),
        ),
        (
            message(b'1', &[]),
            Ok(BackendMessage::Other {
                tag: b'1',
                length: 0,
            }),
        ),
        (
            message(b'2', &[0]),
            Err(malformed("backend message", Problem::InvalidLength)),
        ),
        (
            message(b'Q', &[]),
            Err(DecodeError::UnknownMessage { tag: b'Q' }),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(debug(single(&input)), debug(expected));
    }
}

#[test]
fn error_and_notice_fields() {
    let full = fields(&[
        (b'S', "FEHLER"),
        (b'V', "ERROR"),
        (b'C', "42P01"),
        (b'M', "relation does not exist"),
        (b'P', "15"),
    ]);
    let localized_only = fields(&[(b'S', "WARNING"), (b'C', "01000"), (b'M', "careful")]);
    let missing_code = fields(&[(b'V', "ERROR"), (b'M', "no code")]);
    let cases: Vec<(Vec<u8>, TaggedNotice)> = vec![
        (
            message(b'E', &full),
            Ok((
                b'E',
                Notice {
                    severity: "ERROR".into(),
                    code: "42P01".into(),
                    message: "relation does not exist".into(),
                },
            )),
        ),
        (
            message(b'N', &localized_only),
            Ok((
                b'N',
                Notice {
                    severity: "WARNING".into(),
                    code: "01000".into(),
                    message: "careful".into(),
                },
            )),
        ),
        (
            message(b'E', &missing_code),
            Err(malformed("ErrorResponse", Problem::MissingField)),
        ),
        (
            message(b'E', b"SERROR\0"),
            Err(malformed("ErrorResponse", Problem::Truncated)),
        ),
    ];
    for (input, expected) in cases {
        let actual = single(&input).map(|message| match message {
            BackendMessage::ErrorResponse(notice) => (b'E', notice),
            BackendMessage::NoticeResponse(notice) => (b'N', notice),
            other => panic!("unexpected {other:?}"),
        });
        assert_eq!(actual, expected);
    }
}

#[test]
fn command_tags_and_row_counts() {
    let cases: [(&str, &str, Option<u64>); 8] = [
        ("SELECT 3", "SELECT", Some(3)),
        ("INSERT 0 5", "INSERT", Some(5)),
        ("UPDATE 12", "UPDATE", Some(12)),
        ("DELETE 0", "DELETE", Some(0)),
        ("COPY 1", "COPY", Some(1)),
        ("MERGE 2", "MERGE", Some(2)),
        ("CREATE TABLE", "CREATE TABLE", None),
        ("SELECT x", "SELECT x", None),
    ];
    for (tag, command, rows) in cases {
        let actual = single(&message(b'C', &cstr(tag))).map(|message| match message {
            BackendMessage::CommandComplete(complete) => complete,
            other => panic!("unexpected {other:?}"),
        });
        assert_eq!(
            actual,
            Ok(CommandComplete {
                command: command.into(),
                rows,
            })
        );
    }
}

#[test]
fn oversize_messages_poison_the_decoder() {
    let limits = Limits {
        max_data_message: 2048,
        max_statement_message: 1024,
        max_startup_message: 300,
        max_startup_parameters: 4,
        max_pending: 4096,
    };
    let long_error = fields(&[(b'M', &"m".repeat(1100))]);
    let cases: Vec<(Vec<u8>, DecodeError)> = vec![
        (
            message(b'D', &vec![0; 2045]),
            DecodeError::TooLarge {
                message: "DataRow",
                length: 2049,
                limit: 2048,
            },
        ),
        (
            message(b'E', &long_error),
            DecodeError::TooLarge {
                message: "ErrorResponse",
                length: long_error.len() + 4,
                limit: 1024,
            },
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(backend_with(limits, &input).error, Some(expected.clone()));
        let mut decoder = BackendDecoder::new(limits).expect("valid limits");
        decoder.push(&input).expect("fits the pending limit");
        assert_eq!(decoder.next_event().err(), Some(expected));
        assert!(decoder.is_poisoned());
        assert_eq!(decoder.next_event().err(), Some(DecodeError::Poisoned));
        assert_eq!(
            decoder.push(&message(b'Z', b"I")),
            Err(DecodeError::Poisoned)
        );
    }
}

#[test]
fn captured_psql_sessions_decode() {
    for (fixture, key_length) in [
        (
            include_bytes!("fixtures/psql-v3.0-backend.bin").as_slice(),
            4,
        ),
        (
            include_bytes!("fixtures/psql-v3.2-backend.bin").as_slice(),
            32,
        ),
    ] {
        let input = fixture.strip_prefix(b"N").unwrap_or(fixture);
        let messages = backend(input).only();
        assert!(matches!(
            messages[0],
            BackendMessage::Authentication(Authentication::Ok)
        ));
        let key = messages
            .iter()
            .find_map(|message| match message {
                BackendMessage::BackendKeyData(data) => Some(data.secret_key().len()),
                _ => None,
            })
            .expect("backend key data");
        assert_eq!(key, key_length);
        assert!(matches!(
            messages.last(),
            Some(BackendMessage::ReadyForQuery(TransactionStatus::Idle))
        ));
    }
    let v30 = include_bytes!("fixtures/psql-v3.0-backend.bin");
    let messages = backend(&v30[1..]).only();
    let notable: Vec<String> = messages
        .iter()
        .filter_map(|message| match message {
            BackendMessage::CommandComplete(complete) => {
                Some(format!("C {} {:?}", complete.command, complete.rows))
            }
            BackendMessage::ErrorResponse(notice) => Some(format!("E {}", notice.code)),
            BackendMessage::NoticeResponse(notice) => Some(format!("N {}", notice.message)),
            BackendMessage::CopyOutResponse(_) => Some("H".into()),
            BackendMessage::CopyInResponse(_) => Some("G".into()),
            _ => None,
        })
        .collect();
    assert_eq!(
        notable,
        [
            "C SELECT Some(1)",
            "C SELECT Some(1)",
            "H",
            "C COPY Some(1)",
            "C CREATE TABLE None",
            "G",
            "C COPY Some(1)",
            "E 22012",
            "N hello",
            "C DO None",
        ]
    );
}

#[test]
fn negotiate_protocol_version_from_a_real_server() {
    let downgrade_with_option: &[u8] = &[
        0x76, 0x00, 0x00, 0x00, 0x16, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'_', b'p',
        b'q', b'_', b'.', b't', b'e', b's', b't', 0x00,
    ];
    let answer_to_3_3: &[u8] = &[
        0x76, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    ];
    let cases = [
        (
            downgrade_with_option,
            ProtocolVersion::V3_0,
            vec!["_pq_.test"],
        ),
        (answer_to_3_3, ProtocolVersion::V3_2, vec![]),
    ];
    for (input, version, options) in cases {
        let Ok(BackendMessage::NegotiateProtocolVersion(negotiate)) = single(input) else {
            panic!("expected NegotiateProtocolVersion");
        };
        assert_eq!(negotiate.newest_version, version);
        assert_eq!(negotiate.unrecognized_options, options);
    }
}

#[test]
fn notice_debug_hides_the_message_text() {
    let notice = Notice {
        severity: "ERROR".into(),
        code: "23505".into(),
        message: "Key (email)=(alice@example.org) already exists.".into(),
    };
    let rendered = format!(
        "{notice:?} {:?}",
        BackendMessage::ErrorResponse(notice.clone())
    );
    assert!(!rendered.contains("alice"), "{rendered}");
    assert!(rendered.contains("23505") && rendered.contains("ERROR"));
    assert!(rendered.contains(&format!("message_length: {}", notice.message.len())));
}

#[test]
fn oversize_headers_fail_before_the_body_arrives() {
    let limits = Limits {
        max_data_message: 2048,
        max_statement_message: 1024,
        max_startup_message: 300,
        max_startup_parameters: 4,
        max_pending: 4096,
    };
    for (tag, message) in [(b'E', "ErrorResponse"), (b'N', "NoticeResponse")] {
        let mut header = vec![tag];
        header.extend(i32s(&[1025]));
        assert_eq!(
            backend_with(limits, &header).error,
            Some(DecodeError::TooLarge {
                message,
                length: 1025,
                limit: 1024,
            })
        );
    }
}
