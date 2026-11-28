use jaunt_proto::{AgentEventValue, PostgresAudit, QueryAudit};
use tokio::io::AsyncWriteExt;

use super::fake_pg::{cstr, message};
use super::harness::{DbHarness, DbOptions, PgClient, query, text};
use crate::keys::sha256_hex;
use crate::runtime::events::SINK_LIMITS;
use crate::testkit::LogCapture;

const BIND_VALUE: &str = "bind-value-7f3a91";

fn extended(statement: &str, value: &str) -> Vec<u8> {
    let mut parse = cstr("");
    parse.extend(cstr(statement));
    parse.extend(0_i16.to_be_bytes());
    let mut bind = cstr("");
    bind.extend(cstr(""));
    bind.extend(0_i16.to_be_bytes());
    bind.extend(1_i16.to_be_bytes());
    bind.extend(i32::try_from(value.len()).unwrap().to_be_bytes());
    bind.extend_from_slice(value.as_bytes());
    bind.extend(0_i16.to_be_bytes());
    let mut execute = cstr("");
    execute.extend(0_i32.to_be_bytes());
    let mut out = message(b'P', &parse);
    out.extend(message(b'B', &bind));
    out.extend(message(b'E', &execute));
    out.extend(message(b'S', &[]));
    out
}

async fn finish(harness: &DbHarness, client: &mut PgClient, session: &str) {
    client.send(&message(b'X', &[])).await;
    assert!(client.rest().await.is_empty());
    harness.ended(session).await;
}

fn audit(queries: QueryAudit, max_query_bytes: u32) -> DbOptions {
    DbOptions {
        audit: PostgresAudit {
            queries,
            max_query_bytes,
        },
        ..DbOptions::default()
    }
}

#[tokio::test]
async fn simple_extended_and_copy_statements_become_events_without_bind_values() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-events").await;
    client.send(&query("SELECT 1")).await;
    client.until_ready().await;
    client.send(&extended("SELECT $1", BIND_VALUE)).await;
    client.until_ready().await;
    client.send(&query("COPY t FROM STDIN")).await;
    assert!(client.next().await.is_some());
    let mut rows = Vec::new();
    for row in ["1\n", "2\n", "3\n"] {
        rows.extend(message(b'd', row.as_bytes()));
    }
    rows.extend(message(b'c', &[]));
    client.send(&rows).await;
    client.until_ready().await;
    client.send(&query("FAIL now")).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-events").await;
    assert_eq!(harness.pg.seen().copied, b"1\n2\n3\n");

    let events = harness.session_events("s-events");
    let starts = harness.named("s-events", "db.session.start");
    let ends = harness.named("s-events", "db.session.end");
    assert_eq!((starts.len(), ends.len()), (1, 1));
    let start = &starts[0];
    assert_eq!(text(start, "db_user").as_deref(), Some("app"));
    assert_eq!(text(start, "db_name").as_deref(), Some("main"));
    assert_eq!(text(start, "application_name").as_deref(), Some("psql"));
    assert_eq!(text(start, "server"), Some(harness.pg.address.clone()));
    let queries = harness.named("s-events", "db.query");
    let summary: Vec<(String, String, String)> = queries
        .iter()
        .map(|fields| {
            (
                text(fields, "text").unwrap(),
                text(fields, "protocol").unwrap(),
                text(fields, "command").unwrap(),
            )
        })
        .collect();
    let expected = [
        ("SELECT 1", "simple", "select"),
        ("SELECT $1", "extended", "select"),
        ("COPY t FROM STDIN", "simple", "copy"),
        ("FAIL now", "simple", "other"),
    ];
    assert_eq!(
        summary,
        expected.map(|(a, b, c)| (a.to_owned(), b.to_owned(), c.to_owned()))
    );
    assert_eq!(text(&queries[0], "sha256"), Some(sha256_hex(b"SELECT 1")));
    assert_eq!(queries[0]["truncated"], AgentEventValue::Bool(false));
    let errors = harness.named("s-events", "db.error");
    assert_eq!(text(&errors[0], "sqlstate").as_deref(), Some("42601"));
    assert!(
        text(&errors[0], "error_message")
            .unwrap()
            .starts_with("syntax error")
    );
    let end = &ends[0];
    assert_eq!(end["queries"], AgentEventValue::Int(4));
    assert_eq!(end["errors"], AgentEventValue::Int(1));
    assert!(matches!(end["bytes"], AgentEventValue::Int(bytes) if bytes > 100));
    assert!(end.contains_key("duration_ms"));
    for (name, fields) in &events {
        assert!(
            !fields.contains_key("service") && !fields.contains_key("observed_at"),
            "{name}"
        );
        for value in fields.values() {
            assert!(!matches!(value, AgentEventValue::Text(text) if text.contains(BIND_VALUE)));
        }
    }
}

#[tokio::test]
async fn query_text_is_cut_on_a_character_boundary_and_hashed_whole() {
    let harness = DbHarness::with(audit(QueryAudit::Text, 10)).await;
    let (_opened, mut client, _) = harness.login("s-cut").await;
    let statement = "SELECT 'ééé'";
    client.send(&query(statement)).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-cut").await;
    let queries = harness.named("s-cut", "db.query");
    assert_eq!(text(&queries[0], "text").as_deref(), Some("SELECT 'é"));
    assert_eq!(queries[0]["truncated"], AgentEventValue::Bool(true));
    assert_eq!(
        text(&queries[0], "sha256"),
        Some(sha256_hex(statement.as_bytes()))
    );
}

#[tokio::test]
async fn digest_mode_writes_the_command_and_digest_but_no_text() {
    let harness = DbHarness::with(audit(QueryAudit::Digest, 4096)).await;
    let (_opened, mut client, _) = harness.login("s-digest").await;
    client.send(&query("SELECT 1")).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-digest").await;
    let queries = harness.named("s-digest", "db.query");
    let mut keys: Vec<&str> = queries[0].keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["command", "length", "protocol", "sha256"]);
}

async fn fields_and_errors(harness: &DbHarness, session: &str) -> (Vec<Vec<String>>, Vec<bool>) {
    harness.ended(session).await;
    let queries = harness
        .named(session, "db.query")
        .into_iter()
        .map(|fields| {
            let mut keys: Vec<String> = fields.keys().cloned().collect();
            keys.sort_unstable();
            keys
        })
        .collect();
    let errors = harness
        .named(session, "db.error")
        .iter()
        .map(|fields| fields.contains_key("error_message"))
        .collect();
    (queries, errors)
}

fn keys(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[tokio::test]
async fn statements_that_name_a_password_are_written_masked_without_digest_or_length() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-secret").await;
    for statement in [
        "AlTeR/**/RoLe app\n\tPASSWORD 'hunter2'",
        "SELECT dblink_connect('postgresql://u:hunter2@h/db')",
        "FAIL ALTER ROLE app PASSWORD hunter2",
        "FAIL plain",
        "SELECT 1",
        "DROP TABLE payments -- password",
    ] {
        client.send(&query(statement)).await;
        client.until_ready().await;
    }
    client
        .send(&extended("CREATE ROLE ops PASSWORD 'hunter2'", "x"))
        .await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-secret").await;
    let (queries, errors) = fields_and_errors(&harness, "s-secret").await;
    let secret = keys(&["command", "protocol", "text", "truncated"]);
    let plain = keys(&[
        "command",
        "length",
        "protocol",
        "sha256",
        "text",
        "truncated",
    ]);
    assert_eq!(
        queries,
        [
            secret.clone(),
            secret.clone(),
            secret.clone(),
            plain.clone(),
            plain,
            secret.clone(),
            secret
        ]
    );
    assert_eq!(errors, [false, true]);
    let events = harness.named("s-secret", "db.query");
    let texts: Vec<Option<String>> = events.iter().map(|fields| text(fields, "text")).collect();
    assert_eq!(
        texts,
        [
            "AlTeR RoLe app PASSWORD '?'",
            "SELECT dblink_connect('?')",
            "FAIL ALTER ROLE app PASSWORD '?'",
            "FAIL plain",
            "SELECT 1",
            "DROP TABLE payments",
            "CREATE ROLE ops PASSWORD '?'",
        ]
        .map(|expected| Some(expected.to_owned()))
    );
    assert_eq!(text(&events[4], "sha256"), Some(sha256_hex(b"SELECT 1")));
}

#[tokio::test]
async fn a_password_after_eight_kib_is_masked_the_same_through_query_and_parse() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-padded").await;
    let statement = format!(
        "SELECT /* {} */ dblink_connect('host=h password=hunter2')",
        "x".repeat(9000)
    );
    client.send(&query(&statement)).await;
    client.until_ready().await;
    client.send(&extended(&statement, "x")).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-padded").await;
    let (queries, _) = fields_and_errors(&harness, "s-padded").await;
    let secret = keys(&["command", "protocol", "text", "truncated"]);
    assert_eq!(queries, [secret.clone(), secret]);
    let texts: Vec<Option<String>> = harness
        .named("s-padded", "db.query")
        .iter()
        .map(|fields| text(fields, "text"))
        .collect();
    let masked = Some("SELECT dblink_connect('?')".to_owned());
    assert_eq!(texts, [masked.clone(), masked]);
}

fn parse(name: &str, statement: &str) -> Vec<u8> {
    let mut body = cstr(name);
    body.extend(cstr(statement));
    body.extend(0_i16.to_be_bytes());
    message(b'P', &body)
}

fn bind_execute_sync(statement: &str) -> Vec<u8> {
    let mut bind = cstr("");
    bind.extend(cstr(statement));
    bind.extend(0_i16.to_be_bytes());
    bind.extend(0_i16.to_be_bytes());
    bind.extend(0_i16.to_be_bytes());
    let mut execute = cstr("");
    execute.extend(0_i32.to_be_bytes());
    let mut out = message(b'B', &bind);
    out.extend(message(b'E', &execute));
    out.extend(message(b'S', &[]));
    out
}

#[tokio::test]
async fn the_error_that_answers_a_password_statement_loses_its_message_when_pipelined() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-pipelined").await;
    client
        .send(&extended("FAIL ALTER ROLE app PASSWORD hunter2", "x"))
        .await;
    client.until_ready().await;
    let mut batch = parse("", "SELECT 1");
    batch.extend(message(b'S', &[]));
    batch.extend(query("FAIL ALTER ROLE app PASSWORD hunter2"));
    batch.extend(query("FAIL plain"));
    client.send(&batch).await;
    for _ in 0..3 {
        client.until_ready().await;
    }
    finish(&harness, &mut client, "s-pipelined").await;
    let (_, errors) = fields_and_errors(&harness, "s-pipelined").await;
    assert_eq!(errors, [false, false, true]);
}

#[tokio::test]
async fn an_error_of_a_password_statement_executed_in_a_later_cycle_loses_its_message() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-later").await;
    for (name, statement) in [
        ("secret", "EXECFAIL ALTER ROLE app PASSWORD hunter2"),
        ("", "EXECFAIL CREATE ROLE ops PASSWORD 'hunter2'"),
        ("plain", "EXECFAIL plain"),
    ] {
        let mut prepare = parse(name, statement);
        prepare.extend(message(b'S', &[]));
        client.send(&prepare).await;
        client.until_ready().await;
        client.send(&bind_execute_sync(name)).await;
        client.until_ready().await;
    }
    let mut closing = message(b'C', b"Ssecret\0");
    closing.extend(message(b'S', &[]));
    client.send(&closing).await;
    client.until_ready().await;
    client.send(&bind_execute_sync("secret")).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-later").await;
    let (_, errors) = fields_and_errors(&harness, "s-later").await;
    assert_eq!(errors, [false, false, true, true]);
}

#[tokio::test]
async fn query_text_bind_values_and_database_errors_never_reach_the_log() {
    let log = LogCapture::default();
    let _guard = log.install();
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-log").await;
    client.send(&query("SELECT 'log-canary-51c2'")).await;
    client.until_ready().await;
    client.send(&extended("SELECT $1", BIND_VALUE)).await;
    client.until_ready().await;
    client.send(&query("FAIL log")).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-log").await;
    let written = log.text();
    assert!(written.contains("s-log"));
    for secret in ["log-canary-51c2", BIND_VALUE, "hunter2", "SELECT $1"] {
        assert!(!written.contains(secret), "{secret}");
    }
}

#[tokio::test]
async fn events_beyond_a_full_queue_are_dropped_and_counted() {
    let harness = DbHarness::with(DbOptions {
        sink: crate::runtime::events::SinkLimits {
            queue_events: 4,
            ..SINK_LIMITS
        },
        ..DbOptions::default()
    })
    .await;
    harness.control.stall_events();
    let (_opened, mut client, _) = harness.login("s-flood").await;
    for _ in 0..12 {
        client.send(&query("SELECT 1")).await;
        client.until_ready().await;
    }
    assert!(harness.events.counters().dropped >= 8);
}

#[tokio::test]
async fn a_one_mebibyte_query_streams_through_and_is_cut_for_the_audit() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-large").await;
    let statement = format!("SELECT '{}'", "a".repeat(1024 * 1024));
    let bytes = query(&statement);
    let (head, tail) = bytes.split_at(256 * 1024);
    client.stream.write_all(head).await.unwrap();
    client.stream.flush().await.unwrap();
    harness
        .pg
        .wait("the database to see the start of the query", |seen| {
            seen.query_bytes >= 128 * 1024
        })
        .await;
    assert!(harness.pg.seen().messages.is_empty());
    client.send(tail).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-large").await;
    let queries = harness.named("s-large", "db.query");
    let kept = text(&queries[0], "text").unwrap();
    assert_eq!(kept.len(), 4096);
    assert!(statement.starts_with(&kept));
    assert_eq!(queries[0]["truncated"], AgentEventValue::Bool(true));
    assert_eq!(
        text(&queries[0], "sha256"),
        Some(sha256_hex(statement.as_bytes()))
    );
    let seen = harness.pg.seen();
    assert_eq!(seen.messages[0].1.len(), statement.len() + 1);
}

fn bind(portal: &str, statement: &str) -> Vec<u8> {
    let mut body = cstr(portal);
    body.extend(cstr(statement));
    body.extend(0_i16.to_be_bytes());
    body.extend(0_i16.to_be_bytes());
    body.extend(0_i16.to_be_bytes());
    message(b'B', &body)
}

fn execute(portal: &str) -> Vec<u8> {
    let mut body = cstr(portal);
    body.extend(0_i32.to_be_bytes());
    message(b'E', &body)
}

fn sync() -> Vec<u8> {
    message(b'S', &[])
}

async fn exchange(client: &mut PgClient, parts: &[Vec<u8>]) {
    client.send(&parts.concat()).await;
    client.until_ready().await;
}

#[tokio::test]
async fn each_use_of_a_password_statement_hides_the_message_of_its_error() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-uses").await;
    let secret = "ALTER ROLE app PASSWORD hunter2";
    exchange(
        &mut client,
        &[parse("", &format!("EXECFAIL {secret}")), sync()],
    )
    .await;
    exchange(
        &mut client,
        &[
            parse("", "EXECFAIL plain"),
            bind("", ""),
            execute(""),
            sync(),
        ],
    )
    .await;
    exchange(
        &mut client,
        &[
            parse("s", &format!("EXECFAIL {secret}")),
            bind("p", "s"),
            sync(),
        ],
    )
    .await;
    exchange(&mut client, &[execute("p"), sync()]).await;
    exchange(
        &mut client,
        &[parse("b", &format!("BINDFAIL {secret}")), sync()],
    )
    .await;
    exchange(&mut client, &[bind("", "b"), sync()]).await;
    exchange(&mut client, &[parse("c", "BINDFAIL plain"), sync()]).await;
    exchange(&mut client, &[bind("", "c"), sync()]).await;
    exchange(
        &mut client,
        &[parse("d", &format!("DESCFAIL {secret}")), sync()],
    )
    .await;
    exchange(&mut client, &[message(b'D', b"Sd\0"), sync()]).await;
    finish(&harness, &mut client, "s-uses").await;
    let (_, errors) = fields_and_errors(&harness, "s-uses").await;
    assert_eq!(errors, [true, false, false, true, false]);
}

#[tokio::test]
async fn both_readings_of_backslashes_are_compared_whatever_the_database_reports() {
    let harness = DbHarness::new().await;
    harness.pg.set_mode(super::fake_pg::Mode::ScsOff);
    let (_opened, mut client, _) = harness.login("s-scs").await;
    let clear = "ALTER ROLE app PASSWORD 'a\\b'";
    let doubtful = "ALTER ROLE app PASSWORD 'a\\' hunter2 '";
    for statement in [
        clear,
        doubtful,
        "SET scs on",
        clear,
        doubtful,
        "SET scs off",
        clear,
    ] {
        client.send(&query(statement)).await;
        client.until_ready().await;
    }
    finish(&harness, &mut client, "s-scs").await;
    let texts: Vec<Option<String>> = harness
        .named("s-scs", "db.query")
        .iter()
        .map(|fields| text(fields, "text"))
        .collect();
    let masked = Some("ALTER ROLE app PASSWORD '?'".to_owned());
    let set = |value: &str| Some(format!("SET scs {value}"));
    assert_eq!(
        texts,
        [
            masked.clone(),
            None,
            set("on"),
            masked.clone(),
            None,
            set("off"),
            masked
        ]
    );
    for fields in harness.named("s-scs", "db.query") {
        for value in fields.values() {
            assert!(!matches!(value, AgentEventValue::Text(text) if text.contains("hunter2")));
        }
    }
}

fn high_bytes() -> Vec<Vec<u8>> {
    let mut big5 = b"SELECT '$a$".to_vec();
    big5.extend_from_slice(&[0xa4, 0xee, 0xa7, 0xc0]);
    big5.extend_from_slice(b";SELECT 1/0 AS zqx9;");
    big5.push(0xea);
    big5.extend_from_slice(b"\\''/*");
    big5.extend_from_slice(&[0xc5, 0xa3]);
    big5.push(b'\'');
    let mut gbk = b"SELECT '".to_vec();
    gbk.push(0xe3);
    gbk.extend_from_slice(b"\\'");
    gbk.push(0xc3);
    gbk.extend_from_slice(b"~;SELECT 1/0 AS zqx9; --'");
    let mut sjis = b"SELECT E'".to_vec();
    sjis.extend_from_slice(&[0x83, 0x5c]);
    sjis.extend_from_slice(b"';SELECT 1/0 AS zqx9; --'");
    let mut katakana = b"SELECT E'".to_vec();
    katakana.extend_from_slice(&[0xb1, 0x5c]);
    katakana.extend_from_slice(b"';SELECT 1/0 AS zqx9; --'");
    vec![big5, gbk, sjis, katakana]
}

fn raw_query(text: &[u8]) -> Vec<u8> {
    let mut body = text.to_vec();
    body.push(0);
    message(b'Q', &body)
}

#[tokio::test]
async fn statements_with_high_bytes_behind_unconfirmed_ones_keep_only_their_command() {
    let harness = DbHarness::new().await;
    let (_opened, mut client, _) = harness.login("s-pipelined-bytes").await;
    for statement in high_bytes() {
        let mut batch = query("SELECT 1");
        batch.extend(raw_query(&statement));
        client.send(&batch).await;
        client.until_ready().await;
        client.until_ready().await;
        client.send(&raw_query(&statement)).await;
        client.until_ready().await;
    }
    let mut batch = query("SELECT 1");
    batch.extend(query("SELECT 'a\\' FROM t"));
    client.send(&batch).await;
    client.until_ready().await;
    client.until_ready().await;
    let mut extended_batch = parse("", "SELECT 1");
    extended_batch.extend(bind("", ""));
    extended_batch.extend(execute(""));
    extended_batch.extend(parse("", "SELECT 'caf\u{e9}'"));
    extended_batch.extend(sync());
    client.send(&extended_batch).await;
    client.until_ready().await;
    finish(&harness, &mut client, "s-pipelined-bytes").await;
    let texts: Vec<bool> = harness
        .named("s-pipelined-bytes", "db.query")
        .iter()
        .map(|fields| fields.contains_key("text"))
        .collect();
    let mut expected = Vec::new();
    for _ in 0..4 {
        expected.extend([true, false, true]);
    }
    expected.extend([true, true, true, false]);
    assert_eq!(texts, expected);
}
