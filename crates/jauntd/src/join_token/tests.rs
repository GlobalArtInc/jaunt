use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use jaunt_audit::{
    AuditTap, keep_callsites_enabled_for_scoped_capture, system_clock as audit_clock,
};
use jaunt_control::Clock;
use jaunt_store::{AuditQuery, Store};
use sqlx::Row;
use tempfile::TempDir;
use tracing_subscriber::Registry;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;

use super::{CreateOptions, JoinTokenAction, TtlError, execute, parse_ttl};
use crate::logging::{build_filter, subscriber};
use crate::node::Terminal;

const NOW: u64 = 1_700_000_000;

struct Fixture {
    dir: TempDir,
    config: PathBuf,
}

struct Outcome {
    code: u8,
    stdout: String,
    stderr: String,
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Captured;

    fn make_writer(&self) -> Captured {
        self.clone()
    }
}

fn clock() -> Clock {
    Arc::new(|| UNIX_EPOCH + Duration::from_secs(NOW))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("jauntd.yaml");
    std::fs::write(&config, format!("data_dir: {}\n", dir.path().display())).unwrap();
    runtime().block_on(async {
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
    });
    Fixture { dir, config }
}

fn run(fixture: &Fixture, action: JoinTokenAction) -> Outcome {
    run_with_tap(fixture, action, &AuditTap::new(audit_clock()))
}

fn run_audited(fixture: &Fixture, action: JoinTokenAction) -> Outcome {
    keep_callsites_enabled_for_scoped_capture();
    let tap = AuditTap::new(audit_clock());
    let _guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));
    run_with_tap(fixture, action, &tap)
}

fn run_with_tap(fixture: &Fixture, action: JoinTokenAction, tap: &AuditTap) -> Outcome {
    let mut input: &[u8] = b"";
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = execute(
        &fixture.config,
        action,
        "cli:tester",
        clock(),
        &mut Terminal {
            input: &mut input,
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
        tap,
    );
    Outcome {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn run_logged(fixture: &Fixture, action: JoinTokenAction) -> (Outcome, String) {
    keep_callsites_enabled_for_scoped_capture();
    let captured = Captured::default();
    let tap = AuditTap::new(audit_clock());
    let logs = subscriber(
        build_filter(Some("trace")).unwrap(),
        captured.clone(),
        Some(&tap),
    );
    let outcome = tracing::subscriber::with_default(logs, || {
        let mut input: &[u8] = b"";
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = execute(
            &fixture.config,
            action,
            "cli:tester",
            clock(),
            &mut Terminal {
                input: &mut input,
                stdout: &mut stdout,
                stderr: &mut stderr,
            },
            &tap,
        );
        Outcome {
            code,
            stdout: String::from_utf8(stdout).unwrap(),
            stderr: String::from_utf8(stderr).unwrap(),
        }
    });
    (outcome, captured.text())
}

fn create(name: Option<&str>, prefix: Option<&str>, labels: &[&str], uses: u32) -> JoinTokenAction {
    JoinTokenAction::Create(CreateOptions {
        name: name.map(str::to_owned),
        name_prefix: prefix.map(str::to_owned),
        labels: labels.iter().map(|label| (*label).to_owned()).collect(),
        uses,
        ttl: Duration::from_secs(3600),
        allow_replace: false,
    })
}

fn stored_hashes(fixture: &Fixture) -> Vec<String> {
    runtime().block_on(async {
        let pool = sqlx::SqlitePool::connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(fixture.dir.path().join("jaunt.db")),
        )
        .await
        .unwrap();
        sqlx::query("SELECT hash FROM join_tokens ORDER BY created_at, id")
            .fetch_all(&pool)
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<String, _>("hash"))
            .collect()
    })
}

fn sha256_hex(text: &str) -> String {
    use jaunt_ca::ssh_key::sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn create_prints_the_token_once_on_stdout_and_its_id_and_expiry_on_stderr_and_keeps_only_its_hash()
{
    let fixture = fixture();

    let (created, logs) = run_logged(
        &fixture,
        create(None, Some("web-"), &["env=prod", "team=core"], 2),
    );

    assert_eq!(created.code, 0, "{}", created.stderr);
    let token = created.stdout.strip_suffix('\n').unwrap();
    assert!(token.starts_with("jt1.") && token.len() == 47, "{token}");
    assert!(!token.contains('\n'));
    let hash = sha256_hex(token);
    assert_eq!(stored_hashes(&fixture), vec![hash.clone()]);
    for text in [&created.stderr, &logs] {
        assert!(!text.contains(token), "{text}");
        assert!(!text.contains(&hash), "{text}");
    }
    assert!(
        created.stderr.contains("2023-11-14T23:13:20Z"),
        "{}",
        created.stderr
    );
    assert!(created.stderr.contains("node names starting with web-"));
    assert!(created.stderr.contains("env=prod,team=core"));
    assert!(logs.contains("\"event\":\"join_token.created\""), "{logs}");

    let listed = run(&fixture, JoinTokenAction::List);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    let id = listed
        .stdout
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    assert!(
        created
            .stderr
            .contains(&format!("created join token {id} ")),
        "{}",
        created.stderr
    );
    assert!(logs.contains(id), "{logs}");
}

#[test]
fn create_and_rm_are_written_to_the_audit_table_with_the_operator_and_without_the_token() {
    let fixture = fixture();

    let created = run_audited(&fixture, create(None, Some("web-"), &["env=prod"], 2));
    let token = created.stdout.trim().to_owned();
    let listed = run(&fixture, JoinTokenAction::List);
    let id = listed
        .stdout
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().next())
        .unwrap()
        .to_owned();
    let removed = run_audited(&fixture, JoinTokenAction::Remove { id: id.clone() });

    assert_eq!(created.code, 0, "{}", created.stderr);
    assert_eq!(removed.code, 0, "{}", removed.stderr);
    let rows = runtime().block_on(async {
        let store = Store::open(&fixture.dir.path().join("jaunt.db"))
            .await
            .unwrap();
        store
            .audit_events()
            .query(&AuditQuery::newest(10))
            .await
            .unwrap()
    });
    let shown: Vec<(&str, &str)> = rows
        .iter()
        .map(|row| (row.event_type.as_str(), row.actor.as_str()))
        .collect();
    assert_eq!(
        shown,
        [
            ("join_token.revoked", "cli:tester"),
            ("join_token.created", "cli:tester")
        ]
    );
    let payload =
        |index: usize| -> serde_json::Value { serde_json::from_str(&rows[index].payload).unwrap() };
    let created_payload = payload(1);
    for (field, expected) in [
        ("join_id", serde_json::json!(id)),
        ("name_prefix", serde_json::json!("web-")),
        ("labels", serde_json::json!("env=prod")),
        ("max_uses", serde_json::json!(2)),
        ("allow_replace", serde_json::json!(false)),
    ] {
        assert_eq!(
            created_payload[field], expected,
            "{field}: {created_payload}"
        );
    }
    assert_eq!(payload(0)["join_id"], serde_json::json!(id));
    assert_eq!(payload(0)["uses_left"], serde_json::json!(2));
    let hash = sha256_hex(&token);
    for row in &rows {
        let stored = format!("{row:?}");
        assert!(
            !stored.contains(&token) && !stored.contains(&hash),
            "{stored}"
        );
    }
}

#[test]
fn list_shows_scope_labels_uses_expiry_and_revocation_but_never_a_token_or_hash() {
    let fixture = fixture();
    let first = run(&fixture, create(Some("db-01"), None, &[], 1));
    let second = run(&fixture, create(None, Some("web-"), &["env=prod"], 3));
    let tokens = [first.stdout.trim(), second.stdout.trim()];

    let before = run(&fixture, JoinTokenAction::List);
    let web_id = before
        .stdout
        .lines()
        .find(|line| line.contains("web-*"))
        .and_then(|line| line.split_whitespace().next())
        .unwrap()
        .to_owned();
    let removed = run(&fixture, JoinTokenAction::Remove { id: web_id.clone() });
    let after = run(&fixture, JoinTokenAction::List);

    assert_eq!(removed.code, 0, "{}", removed.stderr);
    assert!(
        removed.stdout.contains("3 of 3 uses were left"),
        "{}",
        removed.stdout
    );
    let mut rows: Vec<Vec<&str>> = after
        .stdout
        .lines()
        .map(|line| line.split_whitespace().collect())
        .collect();
    assert_eq!(
        rows[0],
        [
            "ID", "NAME", "LABELS", "USES", "EXPIRES", "REVOKED", "REPLACE"
        ]
    );
    rows[1..].sort_by_key(|row| row[1]);
    assert_eq!(
        rows[1][1..],
        ["db-01", "-", "1/1", "2023-11-14T23:13:20Z", "-", "no"]
    );
    assert_eq!(rows[2][0], web_id);
    assert_eq!(
        rows[2][1..],
        [
            "web-*",
            "env=prod",
            "3/3",
            "2023-11-14T23:13:20Z",
            "2023-11-14T22:13:20Z",
            "no"
        ]
    );
    for listed in [&before.stdout, &after.stdout] {
        for token in tokens {
            assert!(!listed.contains(token));
        }
        for hash in stored_hashes(&fixture) {
            assert!(!listed.contains(&hash), "{listed}");
        }
    }
}

#[test]
fn rm_refuses_an_unknown_or_already_revoked_token() {
    let fixture = fixture();
    run(&fixture, create(Some("db-01"), None, &[], 1));
    let listed = run(&fixture, JoinTokenAction::List);
    let id = listed
        .stdout
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();

    assert_eq!(
        run(&fixture, JoinTokenAction::Remove { id: id.clone() }).code,
        0
    );
    let twice = run(&fixture, JoinTokenAction::Remove { id });
    let unknown = run(
        &fixture,
        JoinTokenAction::Remove {
            id: "absent".to_owned(),
        },
    );

    assert_eq!(twice.code, 1);
    assert!(twice.stderr.contains("already revoked"), "{}", twice.stderr);
    assert_eq!(unknown.code, 1);
    assert!(
        unknown.stderr.contains("no join token has this id"),
        "{}",
        unknown.stderr
    );
}

#[test]
fn bad_create_arguments_are_usage_errors_and_create_nothing() {
    let fixture = fixture();
    for (action, expected) in [
        (
            create(None, None, &[], 1),
            "exactly one of --name and --name-prefix",
        ),
        (
            create(Some("db-01"), Some("db-"), &[], 1),
            "exactly one of --name and --name-prefix",
        ),
        (create(Some("Db-01"), None, &[], 1), "node name"),
        (create(None, Some("-web"), &[], 1), "name prefix"),
        (create(Some("db-01"), None, &[], 0), "number of uses"),
        (create(Some("db-01"), None, &[], 1001), "number of uses"),
        (
            create(Some("db-01"), None, &["Env=prod"], 1),
            "invalid --label",
        ),
        (
            create(Some("db-01"), None, &["env=prod,team=core"], 1),
            "invalid --label",
        ),
        (
            create(Some("db-01"), None, &["env=prod", "env=dev"], 1),
            "invalid --label",
        ),
        (create(Some("db-01"), None, &[""], 1), "invalid --label"),
    ] {
        let outcome = run(&fixture, action);
        assert_eq!(outcome.code, 2, "{expected}: {}", outcome.stderr);
        assert!(
            outcome.stderr.contains(expected),
            "{expected}: {}",
            outcome.stderr
        );
        assert!(outcome.stdout.is_empty());
    }
    assert!(stored_hashes(&fixture).is_empty());
}

#[test]
fn durations_are_whole_numbers_with_a_unit_up_to_seven_days() {
    for (text, expected) in [
        ("90s", Ok(Duration::from_secs(90))),
        ("30m", Ok(Duration::from_secs(1800))),
        ("1h", Ok(Duration::from_secs(3600))),
        ("7d", Ok(Duration::from_secs(7 * 86_400))),
        ("168h", Ok(Duration::from_secs(7 * 86_400))),
        ("604801s", Err(TtlError::OutOfRange)),
        ("8d", Err(TtlError::OutOfRange)),
        ("0m", Err(TtlError::OutOfRange)),
        ("99999999999999d", Err(TtlError::OutOfRange)),
        ("", Err(TtlError::Malformed)),
        ("h", Err(TtlError::Malformed)),
        ("10", Err(TtlError::Malformed)),
        ("1w", Err(TtlError::Malformed)),
        ("-1h", Err(TtlError::Malformed)),
        ("+1h", Err(TtlError::Malformed)),
        ("1.5h", Err(TtlError::Malformed)),
        ("1 h", Err(TtlError::Malformed)),
        ("1H", Err(TtlError::Malformed)),
        ("1\u{e9}", Err(TtlError::Malformed)),
    ] {
        assert_eq!(parse_ttl(text), expected, "{text:?}");
    }
}
