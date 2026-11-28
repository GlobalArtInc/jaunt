mod support;

use jaunt_pgwire::{
    FrontendMessage, ProtocolVersion, StartupMessage, StartupPolicy, StartupRefusal, StartupRequest,
};
use support::*;

type Parameters<'a> = Vec<(&'a str, &'a str)>;
type Names<'a> = Result<(&'a str, &'a str), StartupRefusal>;

fn decoded(parameters: &[(&str, &str)]) -> StartupMessage {
    decoded_version(V3_0, parameters)
}

fn decoded_version(code: u32, parameters: &[(&str, &str)]) -> StartupMessage {
    match frontend(&startup_version(code, parameters))
        .only()
        .remove(0)
    {
        FrontendMessage::Startup(startup) => startup,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn startup_policy_table() {
    let long_name = "n".repeat(64);
    let longest_name = "n".repeat(63);
    let many: Vec<(String, String)> = (0..17)
        .map(|index| (format!("p{index}"), String::new()))
        .collect();
    let mut many_refs: Vec<(&str, &str)> = vec![("user", "app")];
    many_refs.extend(
        many.iter()
            .take(16)
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let big_value = "v".repeat(4096);
    let cases: Vec<(Parameters, Names)> = vec![
        (vec![("user", "app")], Ok(("app", "app"))),
        (vec![("user", "app"), ("database", "")], Ok(("app", "app"))),
        (
            vec![
                ("user", "app"),
                ("database", "orders"),
                ("application_name", "psql"),
                ("datestyle", "ISO"),
            ],
            Ok(("app", "orders")),
        ),
        (
            vec![("user", "app"), ("replication", "database")],
            Err(StartupRefusal::Replication),
        ),
        (
            vec![("user", "app"), ("Replication", "false")],
            Err(StartupRefusal::Replication),
        ),
        (
            vec![("user", "app"), ("options", "-c role=admin")],
            Err(StartupRefusal::ParameterNotAllowed {
                name: "options".into(),
            }),
        ),
        (
            vec![("user", "app"), ("_pq_.extension", "1")],
            Err(StartupRefusal::ParameterNotAllowed {
                name: "_pq_.extension".into(),
            }),
        ),
        (
            vec![("USER", "admin")],
            Err(StartupRefusal::ParameterNotAllowed {
                name: "USER".into(),
            }),
        ),
        (
            vec![("database", "orders")],
            Err(StartupRefusal::MissingUser),
        ),
        (vec![("user", "")], Err(StartupRefusal::MissingUser)),
        (
            vec![("user", longest_name.as_str())],
            Ok((longest_name.as_str(), longest_name.as_str())),
        ),
        (
            vec![("user", "app"), ("client_encoding", "utf8")],
            Ok(("app", "app")),
        ),
        (
            vec![("user", "app"), ("Client_Encoding", "UNICODE")],
            Ok(("app", "app")),
        ),
        (
            vec![("user", "app"), ("client_encoding", "LATIN1")],
            Err(StartupRefusal::ClientEncodingNotAllowed),
        ),
        (
            vec![("user", "app"), ("CLIENT_ENCODING", "SQL_ASCII")],
            Err(StartupRefusal::ClientEncodingNotAllowed),
        ),
        (
            vec![("user", long_name.as_str())],
            Err(StartupRefusal::NameTooLong {
                parameter: "user",
                limit: 63,
            }),
        ),
        (
            vec![("user", "app"), ("database", long_name.as_str())],
            Err(StartupRefusal::NameTooLong {
                parameter: "database",
                limit: 63,
            }),
        ),
        (
            many_refs,
            Err(StartupRefusal::TooManyParameters {
                count: 17,
                limit: 16,
            }),
        ),
        (
            vec![("user", "app"), ("application_name", big_value.as_str())],
            Err(StartupRefusal::ParametersTooLarge {
                bytes: 4 + 3 + 16 + 4096 + 4,
                limit: 4096,
            }),
        ),
    ];
    let policy = StartupPolicy::default();
    for (parameters, expected) in cases {
        let startup = decoded(&parameters);
        let actual = policy
            .inspect(&startup)
            .map(|request| (request.user, request.database));
        assert_eq!(actual, expected, "{parameters:?}");
    }
}

#[test]
fn rewrite_checks_the_authorized_names_and_normalizes() {
    let policy = StartupPolicy::default();
    let startup = decoded_version(
        V3_2,
        &[
            ("application_name", "psql"),
            ("user", "app"),
            ("client_encoding", "UTF8"),
        ],
    );
    assert_eq!(
        policy.inspect(&startup),
        Ok(StartupRequest {
            user: "app",
            database: "app",
            application_name: Some("psql"),
        })
    );
    assert_eq!(
        policy.rewrite(&startup, "other", "app"),
        Err(StartupRefusal::UserMismatch)
    );
    assert_eq!(
        policy.rewrite(&startup, "app", "orders"),
        Err(StartupRefusal::DatabaseMismatch)
    );
    assert_eq!(
        policy.rewrite(&startup, "App", "app"),
        Err(StartupRefusal::UserMismatch)
    );
    let rewritten = policy.rewrite(&startup, "app", "app").expect("allowed");
    assert_eq!(rewritten.version(), ProtocolVersion::V3_2);
    assert_eq!(
        rewritten.parameters().collect::<Vec<_>>(),
        [
            ("user", "app"),
            ("database", "app"),
            ("application_name", "psql"),
            ("client_encoding", "UTF8"),
        ]
    );
    let encoded = rewritten.encode().expect("small");
    let again = match frontend(&encoded).only().remove(0) {
        FrontendMessage::Startup(startup) => startup,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(again, rewritten);
    assert_eq!(policy.rewrite(&again, "app", "app"), Ok(rewritten));
}

#[test]
fn custom_allow_list_never_admits_replication() {
    let policy = StartupPolicy::new(["replication", "options"], 8, 1024);
    let options = decoded(&[("user", "app"), ("options", "-c x=y")]);
    assert!(policy.inspect(&options).is_ok());
    let replication = decoded(&[("user", "app"), ("replication", "true")]);
    assert_eq!(
        policy.inspect(&replication),
        Err(StartupRefusal::Replication)
    );
    let default_only = decoded(&[("user", "app"), ("DateStyle", "ISO")]);
    assert_eq!(
        policy.inspect(&default_only),
        Err(StartupRefusal::ParameterNotAllowed {
            name: "DateStyle".into()
        })
    );
}

#[test]
fn refusal_names_are_bounded() {
    let long = "x".repeat(500);
    let startup = decoded(&[("user", "app"), (long.as_str(), "1")]);
    let policy = StartupPolicy::new(Vec::<String>::new(), 8, 8192);
    let Err(StartupRefusal::ParameterNotAllowed { name }) = policy.inspect(&startup) else {
        panic!("expected a refusal");
    };
    assert_eq!(name.len(), 64);
}

#[test]
fn allow_list_spelling_never_admits_reserved_names() {
    let policy = StartupPolicy::new(["USER", "Database"], 8, 1024);
    let cases: [(Parameters, &str); 2] = [
        (vec![("USER", "admin")], "USER"),
        (vec![("user", "app"), ("Database", "admin")], "Database"),
    ];
    for (parameters, name) in cases {
        let startup = decoded(&parameters);
        assert_eq!(
            policy.inspect(&startup),
            Err(StartupRefusal::ParameterNotAllowed { name: name.into() })
        );
    }
}

#[test]
fn parameter_names_are_matched_without_case_and_rewritten_canonically() {
    let policy = StartupPolicy::default();
    let startup = decoded(&[
        ("user", "app"),
        ("Application_Name", "hidden"),
        ("datestyle", "ISO"),
        ("client_ENCODING", "Utf8"),
    ]);
    assert_eq!(
        policy
            .inspect(&startup)
            .map(|request| request.application_name),
        Ok(Some("hidden"))
    );
    let rewritten = policy.rewrite(&startup, "app", "app").expect("allowed");
    assert_eq!(
        rewritten.parameters().collect::<Vec<_>>(),
        [
            ("user", "app"),
            ("database", "app"),
            ("application_name", "hidden"),
            ("DateStyle", "ISO"),
            ("client_encoding", "Utf8"),
        ]
    );
}

#[test]
fn forward_takes_the_given_names_and_keeps_only_allowed_parameters() {
    let policy = StartupPolicy::default();
    let startup = decoded_version(
        V3_2,
        &[
            ("user", "app"),
            ("database", "orders"),
            ("Application_Name", "psql"),
        ],
    );
    let forwarded = policy
        .forward(&startup, "reporting", "analytics")
        .expect("allowed");
    assert_eq!(forwarded.version(), ProtocolVersion::V3_2);
    assert_eq!(
        forwarded.parameters().collect::<Vec<_>>(),
        [
            ("user", "reporting"),
            ("database", "analytics"),
            ("application_name", "psql"),
            ("client_encoding", "UTF8"),
        ]
    );
    let unicode = decoded(&[("user", "app"), ("Client_Encoding", "unicode")]);
    assert_eq!(
        policy
            .forward(&unicode, "app", "app")
            .expect("allowed")
            .parameters()
            .collect::<Vec<_>>(),
        [
            ("user", "app"),
            ("database", "app"),
            ("client_encoding", "UTF8"),
        ]
    );
    let sjis = decoded(&[("user", "app"), ("client_encoding", "SJIS")]);
    assert_eq!(
        policy.forward(&sjis, "app", "app"),
        Err(StartupRefusal::ClientEncodingNotAllowed)
    );
    let long = "n".repeat(64);
    let cases: [(&str, &str, StartupRefusal); 4] = [
        (
            "",
            "analytics",
            StartupRefusal::InvalidName { parameter: "user" },
        ),
        (
            "rep\0replication\0true",
            "analytics",
            StartupRefusal::InvalidName { parameter: "user" },
        ),
        (
            "reporting",
            "a\0b",
            StartupRefusal::InvalidName {
                parameter: "database",
            },
        ),
        (
            "reporting",
            &long,
            StartupRefusal::NameTooLong {
                parameter: "database",
                limit: 63,
            },
        ),
    ];
    for (user, database, expected) in cases {
        assert_eq!(policy.forward(&startup, user, database), Err(expected));
    }
    let replication = decoded(&[("user", "app"), ("replication", "database")]);
    assert_eq!(
        policy.forward(&replication, "app", "app"),
        Err(StartupRefusal::Replication)
    );
}
