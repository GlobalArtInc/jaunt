use jaunt_pgwire::BackendMessage;
use jaunt_proto::ServiceOutcome;

use super::fake_pg::{Mode, message};
use super::harness::{DbHarness, default_startup, fatal, query, startup, text};
use crate::db::wire::ENCODING_REFUSED;

type Case = (Vec<u8>, &'static str, &'static [u8], Option<&'static str>);

#[tokio::test]
async fn malformed_lying_and_out_of_state_client_messages_end_the_session() {
    let mut inner_nul = b"SELECT 1".to_vec();
    inner_nul.push(0);
    inner_nul.extend_from_slice(b"DROP TABLE t");
    inner_nul.push(0);
    let mut lying = vec![b'E'];
    lying.extend((2_u32 * 1024 * 1024).to_be_bytes());
    let mut short = vec![b'S'];
    short.extend(3_u32.to_be_bytes());
    let cases: [Case; 6] = [
        (message(b'Q', &inner_nul), "client_malformed", b"Q", None),
        (lying, "client_too_large", b"QX", None),
        (short, "client_malformed", b"QX", None),
        (
            message(b'p', b"hunter2\0"),
            "client_unexpected_message",
            b"QX",
            None,
        ),
        (
            message(b'F', &[0; 10]),
            "client_function_call",
            b"QX",
            Some("0A000"),
        ),
        (message(b'Z', b"I"), "client_malformed", b"QX", None),
    ];
    for (bytes, reason, database_saw, answer) in cases {
        let harness = DbHarness::new().await;
        let (opened, mut client, _) = harness.login("s-broken").await;
        client.send(&query("SELECT 1")).await;
        client.until_ready().await;
        client.send(&bytes).await;
        let rest = client.rest().await;
        assert_eq!(
            fatal(&rest).map(|(code, _)| code).as_deref(),
            answer,
            "{reason}"
        );
        assert_eq!(rest.len(), usize::from(answer.is_some()), "{reason}");
        opened.finished().await;
        assert_eq!(
            harness.ended("s-broken").await.outcome,
            ServiceOutcome::ProtocolError,
            "{reason}"
        );
        let problems = harness.named("s-broken", "db.protocol_error");
        assert_eq!(problems.len(), 1, "{reason}");
        assert_eq!(text(&problems[0], "reason").as_deref(), Some(reason));
        let seen = harness
            .pg
            .wait("the database connection to close", |seen| seen.closed == 1)
            .await;
        let tags: Vec<u8> = seen.messages.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, database_saw, "{reason}");
    }
}

#[tokio::test]
async fn an_unsafe_parameter_status_in_the_middle_of_a_session_is_not_forwarded() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-hint").await;
    client.send(&query("SET hint")).await;
    let reply = client.until_ready().await;
    let names: Vec<&str> = reply
        .iter()
        .filter_map(|message| match message {
            BackendMessage::ParameterStatus(status) => Some(status.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["application_name"]);
}

#[tokio::test]
async fn authentication_key_data_or_negotiation_in_the_middle_of_a_session_ends_it() {
    for statement in ["WRONG STATE", "SEND K", "SEND v"] {
        let harness = DbHarness::new().await;
        let (opened, mut client, _) = harness.login("s-server").await;
        client.send(&query(statement)).await;
        assert!(client.rest().await.is_empty(), "{statement}");
        opened.finished().await;
        assert_eq!(
            harness.ended("s-server").await.outcome,
            ServiceOutcome::ProtocolError,
            "{statement}"
        );
        let problems = harness.named("s-server", "db.protocol_error");
        assert_eq!(
            text(&problems[0], "reason").as_deref(),
            Some("server_unexpected_message"),
            "{statement}"
        );
    }
}

#[tokio::test]
async fn a_client_encoding_other_than_utf8_ends_the_session() {
    let harness = DbHarness::new().await;
    harness.pg.set_mode(Mode::Encoding("SJIS"));
    let (opened, mut client) = harness.connect("s-sjis-login").await;
    client.send(&startup(&default_startup())).await;
    let answer = client.rest().await;
    assert_eq!(
        fatal(&answer),
        Some((ENCODING_REFUSED.0.to_owned(), ENCODING_REFUSED.1.to_owned()))
    );
    opened.finished().await;
    harness.ended("s-sjis-login").await;
    let problems = harness.named("s-sjis-login", "db.protocol_error");
    assert_eq!(
        text(&problems[0], "reason").as_deref(),
        Some("client_encoding")
    );

    let harness = DbHarness::new().await;
    let (opened, mut client, _) = harness.login("s-sjis").await;
    client.send(&query("SET encoding UNICODE")).await;
    assert!(fatal(&client.until_ready().await).is_none());
    client.send(&query("SET encoding SJIS")).await;
    let answer = client.rest().await;
    assert_eq!(
        fatal(&answer).map(|(code, _)| code).as_deref(),
        Some(ENCODING_REFUSED.0)
    );
    assert!(
        !answer
            .iter()
            .any(|message| matches!(message, BackendMessage::ParameterStatus(_)))
    );
    opened.finished().await;
    assert_eq!(
        harness.ended("s-sjis").await.outcome,
        ServiceOutcome::ProtocolError
    );
    let problems = harness.named("s-sjis", "db.protocol_error");
    assert_eq!(
        text(&problems[0], "reason").as_deref(),
        Some("client_encoding")
    );
    let seen = harness
        .pg
        .wait("the database connection to close", |seen| seen.closed == 1)
        .await;
    assert_eq!(seen.messages.last().map(|(tag, _)| *tag), Some(b'X'));
}

#[tokio::test]
async fn an_oversized_dollar_tag_or_statement_name_ends_the_session_before_it_runs() {
    let tag = "t".repeat(4097);
    let mut long_name = vec![b'n'; 64 * 1024 + 1];
    long_name.push(0);
    long_name.extend_from_slice(b"SELECT 1\0\0\0");
    let cases: [(Vec<u8>, &[u8]); 2] = [
        (query(&format!("SELECT ${tag}$x${tag}$")), b""),
        (message(b'P', &long_name), b"X"),
    ];
    for (bytes, database_saw) in cases {
        let harness = DbHarness::new().await;
        let (opened, mut client, _) = harness.login("s-oversized").await;
        client.send(&bytes).await;
        assert!(client.rest().await.is_empty());
        opened.finished().await;
        assert_eq!(
            harness.ended("s-oversized").await.outcome,
            ServiceOutcome::ProtocolError
        );
        let problems = harness.named("s-oversized", "db.protocol_error");
        assert_eq!(
            text(&problems[0], "reason").as_deref(),
            Some("client_malformed")
        );
        assert!(harness.named("s-oversized", "db.query").is_empty());
        let seen = harness
            .pg
            .wait("the database connection to close", |seen| seen.closed == 1)
            .await;
        let tags: Vec<u8> = seen.messages.iter().map(|(tag, _)| *tag).collect();
        assert_eq!(tags, database_saw);
    }
}
