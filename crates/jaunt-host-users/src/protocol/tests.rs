use super::{
    EnsureRequest, FailedStage, ProtocolError, Reference, Response, SessionLabel, encode_request,
    encode_response, parse_request, parse_response,
};
use crate::line::MAX_REQUEST_BYTES;
use crate::rules::Reason;
use crate::testing::name;

type Expected = fn(&ProtocolError) -> bool;

const DESIGN_REQUEST: &str =
    r#"{"v":1,"op":"ensure","login":"alice","ref":"H-9D0311FE","session":"s-1"}"#;

#[test]
fn the_design_request_parses_and_encodes_byte_for_byte() {
    let request = parse_request(DESIGN_REQUEST.as_bytes()).unwrap();
    assert_eq!(
        request,
        EnsureRequest {
            login: "alice".to_owned(),
            reference: Reference::parse("H-9D0311FE").unwrap(),
            session: SessionLabel::parse("s-1").unwrap(),
        }
    );
    let encoded = encode_request(&request).unwrap();
    assert_eq!(encoded, format!("{DESIGN_REQUEST}\n").into_bytes());
}

#[test]
fn requests_are_strict_and_leave_the_login_to_the_rules() {
    let long_session = "s".repeat(65);
    let oversized = format!(
        r#"{{"v":1,"op":"ensure","login":"{}","ref":"H-9D0311FE","session":"s"}}"#,
        "a".repeat(MAX_REQUEST_BYTES)
    );
    let refused: Vec<(String, Expected)> = vec![
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FE","session":"s","uid":0}"#.into(),
            |error| matches!(error, ProtocolError::Malformed),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FE"}"#.into(),
            |error| matches!(error, ProtocolError::Malformed),
        ),
        (
            r#"{"v":1,"op":"delete","login":"a","ref":"H-9D0311FE","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Malformed),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","login":"b","ref":"H-9D0311FE","session":"s"}"#
                .into(),
            |error| matches!(error, ProtocolError::Malformed),
        ),
        (
            r#"{"op":"ensure","login":"a","ref":"H-9D0311FE","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Malformed),
        ),
        ("not json".into(), |error| {
            matches!(error, ProtocolError::Malformed)
        }),
        (
            r#"{"v":2,"op":"ensure","login":"a","ref":"H-9D0311FE","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Version),
        ),
        (
            r#"{"v":2,"op":"ensure","login":"a","ref":"H-9D0311FE","session":"s","new":1}"#.into(),
            |error| matches!(error, ProtocolError::Version),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9d0311fe","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Reference(_)),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311F","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Reference(_)),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"D-9D0311FE","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Reference(_)),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FEA","session":"s"}"#.into(),
            |error| matches!(error, ProtocolError::Reference(_)),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FE","session":""}"#.into(),
            |error| matches!(error, ProtocolError::Session(_)),
        ),
        (
            r#"{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FE","session":"a b"}"#.into(),
            |error| matches!(error, ProtocolError::Session(_)),
        ),
        (
            format!(
                r#"{{"v":1,"op":"ensure","login":"a","ref":"H-9D0311FE","session":"{long_session}"}}"#
            ),
            |error| matches!(error, ProtocolError::Session(_)),
        ),
        (oversized, |error| {
            matches!(
                error,
                ProtocolError::TooLong {
                    limit: MAX_REQUEST_BYTES
                }
            )
        }),
    ];
    for (line, expected) in refused {
        let error = parse_request(line.as_bytes()).unwrap_err();
        assert!(expected(&error), "{line}: {error}");
    }

    let odd = parse_request(
        br#"{"v":1,"op":"ensure","login":"Root\n\u0000","ref":"H-00000000","session":"s"}"#,
    )
    .unwrap();
    assert_eq!(odd.login, "Root\n\u{0}");
    let shown = format!("{odd:?}");
    assert!(!shown.contains('\n') && !shown.contains('\u{0}'), "{shown}");
}

#[test]
fn every_response_has_one_wire_shape_and_round_trips() {
    for (response, wire) in [
        (Response::Exists, r#"{"v":1,"result":"exists"}"#),
        (Response::Disabled, r#"{"v":1,"result":"disabled"}"#),
        (
            Response::Created {
                uid: 30001,
                home: "/home/alice".to_owned(),
                groups: vec![name("devs"), name("sudo")],
            },
            r#"{"v":1,"result":"created","uid":30001,"home":"/home/alice","groups":["devs","sudo"]}"#,
        ),
        (
            Response::Refused {
                reason: Reason::ReservedName,
            },
            r#"{"v":1,"result":"refused","reason":"reserved_name"}"#,
        ),
        (
            Response::Failed {
                stage: FailedStage::Useradd,
                exit_code: Some(12),
            },
            r#"{"v":1,"result":"failed","stage":"useradd","exit_code":12}"#,
        ),
        (
            Response::Failed {
                stage: FailedStage::Busy,
                exit_code: None,
            },
            r#"{"v":1,"result":"failed","stage":"busy"}"#,
        ),
    ] {
        let encoded = encode_response(&response).unwrap();
        assert_eq!(encoded, format!("{wire}\n").into_bytes());
        assert_eq!(parse_response(wire.as_bytes()).unwrap(), response, "{wire}");
    }
}

#[test]
fn reason_and_stage_codes_are_the_fixed_sets() {
    let reasons = [
        (Reason::NameRule, "name_rule"),
        (Reason::ReservedName, "reserved_name"),
        (Reason::GroupCollision, "group_collision"),
        (Reason::HomeExists, "home_exists"),
        (Reason::MaxUsers, "max_users"),
        (Reason::RateLimit, "rate_limit"),
        (Reason::UidRange, "uid_range"),
    ];
    for (reason, code) in reasons {
        assert_eq!(serde_json::to_value(reason).unwrap(), code);
        assert_eq!(reason.as_str(), code);
    }
    let stages = [
        (FailedStage::Busy, "busy"),
        (FailedStage::Request, "request"),
        (FailedStage::State, "state"),
        (FailedStage::Lookup, "lookup"),
        (FailedStage::Tool, "tool"),
        (FailedStage::Useradd, "useradd"),
        (FailedStage::Verify, "verify"),
        (FailedStage::Partial, "partial"),
    ];
    for (stage, code) in stages {
        assert_eq!(serde_json::to_value(stage).unwrap(), code);
        assert_eq!(stage.as_str(), code);
    }
}

#[test]
fn responses_are_strict() {
    let refused: [(&str, Expected); 9] = [
        (r#"{"v":1,"result":"exists","uid":1}"#, |error| {
            matches!(error, ProtocolError::Inconsistent)
        }),
        (r#"{"v":1,"result":"refused"}"#, |error| {
            matches!(error, ProtocolError::Inconsistent)
        }),
        (
            r#"{"v":1,"result":"failed","stage":"busy","reason":"max_users"}"#,
            |error| matches!(error, ProtocolError::Inconsistent),
        ),
        (
            r#"{"v":1,"result":"created","uid":1,"home":"/home/a"}"#,
            |error| matches!(error, ProtocolError::Inconsistent),
        ),
        (
            r#"{"v":1,"result":"created","uid":1,"home":"home/a","groups":[]}"#,
            |error| matches!(error, ProtocolError::Inconsistent),
        ),
        (
            r#"{"v":1,"result":"created","uid":1,"home":"/home/a","groups":["Bad"]}"#,
            |error| matches!(error, ProtocolError::Malformed),
        ),
        (r#"{"v":1,"result":"refused","reason":"other"}"#, |error| {
            matches!(error, ProtocolError::Malformed)
        }),
        (r#"{"v":1,"result":"exists","extra":true}"#, |error| {
            matches!(error, ProtocolError::Malformed)
        }),
        (r#"{"v":2,"result":"exists"}"#, |error| {
            matches!(error, ProtocolError::Version)
        }),
    ];
    for (line, expected) in refused {
        let error = parse_response(line.as_bytes()).unwrap_err();
        assert!(expected(&error), "{line}: {error}");
    }
    let bad_home = Response::Created {
        uid: 1,
        home: "/home/a b".to_owned(),
        groups: Vec::new(),
    };
    assert!(matches!(
        encode_response(&bad_home),
        Err(ProtocolError::Inconsistent)
    ));
}

#[test]
fn references_are_h_and_eight_upper_case_hex_digits() {
    assert_eq!(Reference::from_random(0x9D03_11FE).as_str(), "H-9D0311FE");
    assert_eq!(Reference::from_random(0).as_str(), "H-00000000");
    assert_eq!(Reference::from_random(u32::MAX).as_str(), "H-FFFFFFFF");
    for value in ["H-9D0311FE", "H-00000000"] {
        assert_eq!(Reference::parse(value).unwrap().as_str(), value);
    }
    for value in [
        "",
        "H-",
        "h-9D0311FE",
        "H-9D0311FG",
        "H-9D0311F",
        "H-+D0311FE",
    ] {
        assert!(Reference::parse(value).is_err(), "{value:?}");
    }
}
