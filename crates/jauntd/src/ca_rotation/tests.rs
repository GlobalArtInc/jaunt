use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use jaunt_audit::{
    AuditEvent, AuditTap, keep_callsites_enabled_for_scoped_capture, system_clock as audit_clock,
};
use jaunt_ca::ssh_key::PrivateKey;
use jaunt_ca::ssh_key::sha2::{Digest, Sha256};
use jaunt_ca::{CaKind, CaLock, ClientCa, FileBackend, IDENTITY_FILE_VAR, fingerprint_hex};
use jaunt_store::{AuditQuery, Store};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

use super::{ChangeStep, Context, LAST_LINE, RESTART_LINE, RotationAction, Streams, execute};
use crate::ca::load_authorities;

const NOW: i64 = 1_700_000_000;

const OPERATOR: &str = "cli:tester";

struct Fixture {
    _dir: TempDir,
    config: PathBuf,
    data_dir: PathBuf,
}

struct Outcome {
    code: u8,
    stdout: String,
    stderr: String,
}

impl Fixture {
    fn ca_dir(&self) -> PathBuf {
        self.data_dir.join("ca")
    }

    fn slot(&self, kind: CaKind) -> PathBuf {
        self.ca_dir().join(kind.as_str())
    }

    fn database(&self) -> PathBuf {
        self.data_dir.join("jaunt.db")
    }
}

fn no_env(_: &str) -> Option<OsString> {
    None
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let config = data_dir.join("jauntd.yaml");
    fs::write(&config, format!("data_dir: {}\n", data_dir.display())).unwrap();
    let initialized = crate::ca::run(
        &data_dir,
        true,
        &no_env,
        UNIX_EPOCH + Duration::from_secs(NOW.unsigned_abs()),
    );
    assert_eq!(initialized.code, 0);
    let fixture = Fixture {
        _dir: dir,
        config,
        data_dir,
    };
    runtime().block_on(async {
        let store = Store::open(&fixture.database()).await.unwrap();
        store.migrate().await.unwrap();
        let pool = raw_pool(&fixture.database()).await;
        sqlx::query(
            "INSERT INTO users (id, issuer, subject, email, display_name, groups, created_at, \
             updated_at) VALUES ('u1', 'https://idp.example', 's1', 'ada@example.com', NULL, \
             '[]', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();
    });
    fixture
}

async fn raw_pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .unwrap()
}

fn sql(fixture: &Fixture, statement: &str) {
    runtime().block_on(async {
        let pool = raw_pool(&fixture.database()).await;
        sqlx::query(sqlx::AssertSqlSafe(statement.to_owned()))
            .execute(&pool)
            .await
            .unwrap();
    });
}

fn change(kind: CaKind, step: ChangeStep) -> RotationAction {
    RotationAction::Change { kind, step }
}

fn run_with(
    fixture: &Fixture,
    action: RotationAction,
    now: i64,
    env: &dyn Fn(&str) -> Option<OsString>,
    tap: &AuditTap,
) -> Outcome {
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = execute(
        &fixture.config,
        action,
        &Context {
            operator: OPERATOR,
            clock: Arc::new(move || UNIX_EPOCH + Duration::from_secs(now.unsigned_abs())),
            env,
            tap,
        },
        &mut Streams {
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    Outcome {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn run(fixture: &Fixture, action: RotationAction) -> Outcome {
    run_at(fixture, action, NOW)
}

fn run_at(fixture: &Fixture, action: RotationAction, now: i64) -> Outcome {
    run_with(fixture, action, now, &no_env, &AuditTap::new(audit_clock()))
}

fn run_audited(fixture: &Fixture, action: RotationAction) -> Outcome {
    keep_callsites_enabled_for_scoped_capture();
    let tap = AuditTap::new(audit_clock());
    let _guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));
    run_with(fixture, action, NOW, &no_env, &tap)
}

fn status(fixture: &Fixture) -> String {
    let outcome = run(fixture, RotationAction::Status { json: false });
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    outcome.stdout
}

fn section(text: &str, kind: CaKind) -> String {
    let mut lines = text.lines().skip_while(|line| *line != kind.as_str());
    lines.next();
    lines
        .take_while(|line| line.starts_with("  "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn audit_events(fixture: &Fixture) -> Vec<AuditEvent> {
    runtime().block_on(async {
        let store = Store::open(&fixture.database()).await.unwrap();
        store
            .audit_events()
            .query(&AuditQuery::newest(50))
            .await
            .unwrap()
            .iter()
            .map(|record| AuditEvent::from_record(record).unwrap())
            .collect()
    })
}

fn assert_applied(outcome: &Outcome, context: &str) {
    assert_ends_with(outcome, context, LAST_LINE);
}

fn assert_ends_with(outcome: &Outcome, context: &str, line: &str) {
    assert_eq!(outcome.code, 0, "{context}: {}", outcome.stderr);
    assert_eq!(
        outcome.stdout.lines().last(),
        Some(line),
        "{context}: {}",
        outcome.stdout
    );
}

#[test]
fn both_authorities_rotate_through_the_commands_and_the_server_still_loads() {
    let fixture = fixture();
    for kind in [CaKind::User, CaKind::Host] {
        assert!(section(&status(&fixture), kind).ends_with("  add-next: ready"));

        let added = run(&fixture, change(kind, ChangeStep::AddNext));
        assert_applied(&added, "add-next");
        let next = fs::read_to_string(fixture.slot(kind).join("next")).unwrap();
        let next = next.trim_end();
        assert_eq!(
            added.stdout.lines().next(),
            Some(format!("{kind} key {next} added as next").as_str())
        );
        let shown = section(&status(&fixture), kind);
        assert!(shown.contains(&format!("  next      {next}")), "{shown}");
        assert!(shown.ends_with("  promote: ready"), "{shown}");
        assert!(load_authorities(&fixture.data_dir, &no_env).is_ok());

        let promoted = run(&fixture, change(kind, ChangeStep::Promote { force: false }));
        assert_applied(&promoted, "promote");
        assert_eq!(promoted.stdout.lines().next(), Some("promote: ready"));
        let shown = section(&status(&fixture), kind);
        assert!(shown.contains(&format!("  active    {next}")), "{shown}");
        assert!(shown.contains("  previous  "), "{shown}");
        assert!(shown.ends_with("  retire: ready"), "{shown}");
        let authorities = load_authorities(&fixture.data_dir, &no_env).unwrap();
        let signer = match kind {
            CaKind::User => &authorities.user,
            _ => &authorities.host,
        };
        assert_eq!(fingerprint_hex(jaunt_ca::Signer::public_key(signer)), next);

        let retired = run(&fixture, change(kind, ChangeStep::Retire { force: false }));
        assert_applied(&retired, "retire");
        let shown = section(&status(&fixture), kind);
        assert!(shown.contains("  retired   "), "{shown}");
        assert!(!shown.contains("  previous  "), "{shown}");
        assert!(shown.ends_with("  add-next: ready"), "{shown}");
        let left = FileBackend::read_slot(&fixture.ca_dir(), kind).unwrap();
        assert_eq!(left.trust.keys().len(), 1);
        assert_eq!(left.retired.len(), 1);
        let age_files = fs::read_dir(fixture.slot(kind))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".age")
            })
            .count();
        assert_eq!(age_files, 1);
        assert!(load_authorities(&fixture.data_dir, &no_env).is_ok());
    }
}

#[test]
fn refusals_by_state_exit_with_one_and_change_nothing() {
    let fixture = fixture();
    let user = CaKind::User;
    let refused = |action: RotationAction, expected: &str| {
        let before = FileBackend::read_slot(&fixture.ca_dir(), user)
            .unwrap()
            .trust
            .set_id();
        let outcome = run(&fixture, action);
        assert_eq!(outcome.code, 1, "{expected}: {}", outcome.stdout);
        assert!(outcome.stderr.contains(expected), "{}", outcome.stderr);
        assert!(!outcome.stdout.contains(LAST_LINE));
        let after = FileBackend::read_slot(&fixture.ca_dir(), user)
            .unwrap()
            .trust
            .set_id();
        assert_eq!(before, after, "{expected}");
    };

    refused(
        change(user, ChangeStep::Promote { force: true }),
        "no next key",
    );
    refused(
        change(user, ChangeStep::Retire { force: true }),
        "no previous key",
    );
    for step in [
        ChangeStep::AddNext,
        ChangeStep::Promote { force: true },
        ChangeStep::Retire { force: true },
    ] {
        refused(
            change(CaKind::Internal, step),
            "not supported in v1, see the runbook",
        );
    }
    assert_applied(
        &run(&fixture, change(user, ChangeStep::AddNext)),
        "add-next",
    );
    refused(change(user, ChangeStep::AddNext), "already has a next key");
    assert_applied(
        &run(&fixture, change(user, ChangeStep::Promote { force: false })),
        "promote",
    );
    assert_applied(
        &run(&fixture, change(user, ChangeStep::AddNext)),
        "add-next",
    );
    refused(
        change(user, ChangeStep::Promote { force: true }),
        "still has a previous key",
    );
    assert!(status(&fixture).contains("  promote: blocked: retire the previous key first\n"));
}

#[test]
fn a_blocked_retire_exits_with_three_and_a_forced_one_is_audited() {
    let fixture = fixture();
    let user = CaKind::User;
    assert_applied(
        &run_audited(&fixture, change(user, ChangeStep::AddNext)),
        "add-next",
    );
    assert_applied(
        &run_audited(&fixture, change(user, ChangeStep::Promote { force: false })),
        "promote",
    );
    let old = FileBackend::read_slot(&fixture.ca_dir(), user)
        .unwrap()
        .trust
        .previous()
        .map(fingerprint_hex)
        .next()
        .unwrap();
    sql(
        &fixture,
        &format!(
            "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, valid_before, \
             issued_at) VALUES (7, 'u1', 'user', 'k', 1, {}, 1)",
            NOW + 3600
        ),
    );

    let blocked = run_audited(&fixture, change(user, ChangeStep::Retire { force: false }));

    assert_eq!(blocked.code, 3, "{}", blocked.stderr);
    assert_eq!(
        blocked.stdout,
        "retire: blocked: 1 unexpired user certificate signed by a previous key or before \
         rotation tracking\n"
    );
    assert!(blocked.stderr.contains("so it was not applied"));
    assert!(fixture.slot(user).join(format!("{old}.age")).exists());
    assert!(
        audit_events(&fixture)
            .iter()
            .all(|event| event.kind().name() != "ca.key.retired")
    );

    let forced = run_audited(&fixture, change(user, ChangeStep::Retire { force: true }));

    assert_applied(&forced, "forced retire");
    assert!(forced.stdout.contains("forced past the check\n"));
    assert!(!fixture.slot(user).join(format!("{old}.age")).exists());
    let events = audit_events(&fixture);
    let names: Vec<&str> = events.iter().map(|event| event.kind().name()).collect();
    assert_eq!(names, ["ca.key.retired", "ca.key.promoted", "ca.key.added"]);
    for event in &events {
        assert_eq!(event.actor().as_wire(), OPERATOR);
        assert_eq!(event.text("kind"), Some("user"));
        assert_eq!(event.text("fp").map(str::len), Some(64));
    }
    let retired = &events[0];
    assert_eq!(retired.text("fp"), Some(old.as_str()));
    assert_eq!(retired.flag("forced"), Some(true));
    assert_eq!(retired.flag("blocked"), Some(true));
    assert_eq!(retired.int("old_unexpired"), Some(1));
    let promoted = &events[1];
    assert_eq!(promoted.flag("forced"), Some(false));
    assert_eq!(promoted.flag("blocked"), Some(false));
    assert_eq!(promoted.int("nodes_behind"), Some(0));
}

#[test]
fn promote_waits_for_nodes_that_were_served_an_older_trust_set() {
    let fixture = fixture();
    let user = CaKind::User;
    sql(
        &fixture,
        &format!(
            "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, ssh_host_public_key, \
             tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, created_at, \
             trust_served_id, trust_served_at) VALUES ('n1', 'web-01', '{{}}', 'h', 't', 's', \
             'f', 'f', 'active', 'cli:root', 1, 'stale', {}), ('n2', 'db-01', '{{}}', 'h', 't', \
             's', 'f', 'f', 'active', 'cli:root', 1, 'stale', {})",
            NOW - 60,
            NOW - 3600
        ),
    );
    assert_applied(
        &run(&fixture, change(user, ChangeStep::AddNext)),
        "add-next",
    );

    let shown = section(&status(&fixture), user);
    assert!(
        shown.contains("  nodes     0 current, 1 behind, 1 offline"),
        "{shown}"
    );
    assert!(shown.contains("  behind    web-01"), "{shown}");
    assert!(shown.contains("  offline   db-01"), "{shown}");
    assert!(shown.ends_with("  promote: blocked: 1 node behind (web-01)"));
    let blocked = run(&fixture, change(user, ChangeStep::Promote { force: false }));
    assert_eq!(blocked.code, 3);
    assert_eq!(blocked.stdout, "promote: blocked: 1 node behind (web-01)\n");

    let current = FileBackend::read_slot(&fixture.ca_dir(), user)
        .unwrap()
        .trust
        .set_id();
    sql(
        &fixture,
        &format!("UPDATE nodes SET trust_served_id = '{current}' WHERE id = 'n1'"),
    );
    assert_applied(
        &run(&fixture, change(user, ChangeStep::Promote { force: false })),
        "promote",
    );
}

#[test]
fn host_promote_waits_until_user_certificates_from_before_add_next_expire() {
    let fixture = fixture();
    let host = CaKind::Host;
    sql(
        &fixture,
        &format!(
            "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, valid_before, \
             issued_at) VALUES (9, 'u1', 'user', 'k', 1, {}, 1)",
            NOW + 60
        ),
    );
    assert_applied(
        &run(&fixture, change(host, ChangeStep::AddNext)),
        "add-next",
    );

    let blocked = run_at(
        &fixture,
        change(host, ChangeStep::Promote { force: false }),
        NOW + 59,
    );
    assert_eq!(blocked.code, 3, "{}", blocked.stderr);
    assert!(
        blocked
            .stdout
            .starts_with("promote: blocked: 1 unexpired user certificate")
    );

    let expired = run_at(
        &fixture,
        change(host, ChangeStep::Promote { force: false }),
        NOW + 60,
    );
    assert_applied(&expired, "promote at valid_before");
}

#[test]
fn a_second_command_is_refused_while_the_lock_is_held() {
    let fixture = fixture();
    let lock = CaLock::acquire(&fixture.ca_dir()).unwrap();

    let refused = run(&fixture, change(CaKind::User, ChangeStep::AddNext));

    assert_eq!(refused.code, 1);
    assert!(
        refused
            .stderr
            .contains("another certificate authority command is running"),
        "{}",
        refused.stderr
    );
    assert!(!fixture.slot(CaKind::User).join("next").exists());
    drop(lock);
    assert_applied(
        &run(&fixture, change(CaKind::User, ChangeStep::AddNext)),
        "after release",
    );
}

#[test]
fn status_json_reports_keys_counters_and_the_next_step() {
    let fixture = fixture();
    assert_applied(
        &run(&fixture, change(CaKind::Host, ChangeStep::AddNext)),
        "add-next",
    );

    let outcome = run(&fixture, RotationAction::Status { json: true });

    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    assert_eq!(value["user"]["keys"][0]["state"], "active");
    assert_eq!(value["user"]["keys"].as_array().unwrap().len(), 1);
    assert_eq!(value["user"]["trust_id"].as_str().unwrap().len(), 64);
    assert_eq!(value["user"]["nodes"]["behind"], 0);
    assert_eq!(value["user"]["old_certificates"]["count"], 0);
    assert!(value["user"]["old_certificates"]["farthest_valid_before"].is_null());
    assert_eq!(value["version"], 1);
    assert_eq!(
        value["user"]["steps"][0],
        serde_json::json!({"step": "add-next", "allowed": true, "reasons": [], "line": "add-next: ready"})
    );
    assert_eq!(
        value["user"]["nodes"]["offline_names"],
        serde_json::json!([])
    );
    let host_states: Vec<&str> = value["host"]["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["state"].as_str().unwrap())
        .collect();
    assert_eq!(host_states, ["active", "next"]);
    assert_eq!(value["host"]["old_host_trust_certificates"]["count"], 0);
    assert_eq!(value["host"]["nodes_on_previous_host_keys"]["count"], 0);
    assert_eq!(value["host"]["steps"][0]["line"], "promote: ready");
    assert_eq!(value["host"]["steps"][0]["allowed"], true);
}

#[test]
fn private_key_material_never_reaches_output_errors_or_audit() {
    let fixture = fixture();
    let user = CaKind::User;
    let added = run_audited(&fixture, change(user, ChangeStep::AddNext));
    let secrets = private_material(&fixture, user);
    let stranger = fixture.data_dir.join("stranger.txt");
    jaunt_ca::AgeIdentity::generate()
        .write_new_file(&stranger)
        .unwrap();
    let wrong_identity = run_with(
        &fixture,
        change(user, ChangeStep::Promote { force: false }),
        NOW,
        &|name| (name == IDENTITY_FILE_VAR).then(|| stranger.clone().into_os_string()),
        &AuditTap::new(audit_clock()),
    );
    assert_eq!(wrong_identity.code, 1);
    let promoted = run_audited(&fixture, change(user, ChangeStep::Promote { force: false }));
    let retired = run_audited(&fixture, change(user, ChangeStep::Retire { force: true }));
    let json = run(&fixture, RotationAction::Status { json: true });

    let mut printed = String::new();
    for outcome in [&added, &wrong_identity, &promoted, &retired, &json] {
        printed.push_str(&outcome.stdout);
        printed.push_str(&outcome.stderr);
    }
    runtime().block_on(async {
        let store = Store::open(&fixture.database()).await.unwrap();
        for record in store
            .audit_events()
            .query(&AuditQuery::newest(50))
            .await
            .unwrap()
        {
            printed.push_str(&format!("{record:?}"));
        }
    });

    assert!(!printed.contains("PRIVATE KEY"));
    assert!(!printed.to_uppercase().contains("AGE-SECRET-KEY"));
    for secret in &secrets {
        assert!(!printed.to_lowercase().contains(secret.as_str()));
    }
    assert!(printed.contains("ca.key.retired"));
}

fn private_material(fixture: &Fixture, kind: CaKind) -> Vec<String> {
    let identity_text = fs::read_to_string(fixture.ca_dir().join("age-identity.txt")).unwrap();
    let identity_line = identity_text
        .lines()
        .find(|line| line.starts_with("AGE-SECRET-KEY-"))
        .unwrap();
    let identity = age::x25519::Identity::from_str(identity_line).unwrap();
    let mut private_hex = Vec::new();
    let mut pem_lines = Vec::new();
    for entry in fs::read_dir(fixture.slot(kind)).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "age") {
            continue;
        }
        let pem = age::decrypt(&identity, &fs::read(&path).unwrap()).unwrap();
        let key = PrivateKey::from_openssh(&pem).unwrap();
        let private = key.key_data().ed25519().unwrap().private.to_bytes();
        private_hex.push(private.iter().map(|byte| format!("{byte:02x}")).collect());
        let pem = String::from_utf8(pem).unwrap();
        pem_lines.extend(
            pem.lines()
                .filter(|line| line.len() > 20 && !line.starts_with("-----"))
                .map(str::to_lowercase),
        );
    }
    assert_eq!(private_hex.len(), 2);
    private_hex.extend(pem_lines);
    private_hex
}

#[test]
fn a_retire_that_fails_halfway_still_audits_the_keys_it_removed() {
    let fixture = fixture();
    let user = CaKind::User;
    assert_applied(
        &run(&fixture, change(user, ChangeStep::AddNext)),
        "add-next",
    );
    assert_applied(
        &run(&fixture, change(user, ChangeStep::Promote { force: false })),
        "promote",
    );
    add_stray_previous(&fixture);
    let mut previous: Vec<String> = FileBackend::read_slot(&fixture.ca_dir(), user)
        .unwrap()
        .trust
        .previous()
        .map(fingerprint_hex)
        .collect();
    previous.sort();
    assert_eq!(previous.len(), 2);
    let obstacle = fixture
        .slot(user)
        .join("retired")
        .join(format!("{}.pub", previous[1]));
    fs::create_dir_all(obstacle.join("inside")).unwrap();

    let failed = run_audited(&fixture, change(user, ChangeStep::Retire { force: false }));

    assert_eq!(failed.code, 1, "{}", failed.stdout);
    assert!(
        failed.stderr.contains("took effect anyway"),
        "{}",
        failed.stderr
    );
    let retired: Vec<String> = audit_events(&fixture)
        .iter()
        .filter(|event| event.kind().name() == "ca.key.retired")
        .map(|event| event.text("fp").unwrap().to_owned())
        .collect();
    assert_eq!(retired, [previous[0].clone()]);
    let left = FileBackend::read_slot(&fixture.ca_dir(), user).unwrap();
    assert_eq!(
        left.trust
            .previous()
            .map(fingerprint_hex)
            .collect::<Vec<_>>(),
        [previous[1].clone()]
    );

    fs::remove_dir_all(&obstacle).unwrap();
    assert_applied(
        &run(&fixture, change(user, ChangeStep::Retire { force: false })),
        "second retire",
    );
}

fn add_stray_previous(fixture: &Fixture) -> String {
    let identity =
        jaunt_ca::AgeIdentity::read_file(&fixture.ca_dir().join("age-identity.txt")).unwrap();
    let other = fixture.data_dir.join("other");
    let extra =
        fingerprint_hex(&FileBackend::init(&other, CaKind::User, &identity.recipient()).unwrap());
    for suffix in [".pub", ".age"] {
        fs::copy(
            other.join("user").join(format!("{extra}{suffix}")),
            fixture.slot(CaKind::User).join(format!("{extra}{suffix}")),
        )
        .unwrap();
    }
    extra
}

fn interrupt_retire(fixture: &Fixture) -> String {
    let user = CaKind::User;
    assert_applied(&run(fixture, change(user, ChangeStep::AddNext)), "add-next");
    assert_applied(
        &run(fixture, change(user, ChangeStep::Promote { force: false })),
        "promote",
    );
    let old = FileBackend::read_slot(&fixture.ca_dir(), user)
        .unwrap()
        .trust
        .previous()
        .map(fingerprint_hex)
        .next()
        .unwrap();
    let retired = fixture.slot(user).join("retired");
    fs::create_dir(&retired).unwrap();
    fs::rename(
        fixture.slot(user).join(format!("{old}.pub")),
        retired.join(format!("{old}.pub")),
    )
    .unwrap();
    old
}

fn finished_line(old: &str) -> String {
    format!(
        "user key {old} was already out of the trust set: removed the private key an \
         interrupted retire left behind\n"
    )
}

#[test]
fn an_interrupted_retire_is_finished_printed_and_audited() {
    let fixture = fixture();
    let old = interrupt_retire(&fixture);

    let finished = run_audited(
        &fixture,
        change(CaKind::User, ChangeStep::Retire { force: false }),
    );

    assert_applied(&finished, "finish");
    assert_eq!(
        finished.stdout,
        format!("{}applied within 10 s\n", finished_line(&old))
    );
    assert!(
        !fixture
            .slot(CaKind::User)
            .join(format!("{old}.age"))
            .exists()
    );
    let events = audit_events(&fixture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind().name(), "ca.key.retired");
    assert_eq!(events[0].text("fp"), Some(old.as_str()));
    assert_eq!(events[0].flag("forced"), Some(false));
    assert_eq!(events[0].flag("blocked"), Some(false));
}

#[test]
fn a_blocked_retire_reports_the_interrupted_retire_it_finished_on_its_own_line() {
    let fixture = fixture();
    let old = interrupt_retire(&fixture);
    let extra = add_stray_previous(&fixture);
    sql(
        &fixture,
        &format!(
            "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, valid_before, \
             issued_at) VALUES (11, 'u1', 'user', 'k', 1, {}, 1)",
            NOW + 3600
        ),
    );

    let blocked = run(
        &fixture,
        change(CaKind::User, ChangeStep::Retire { force: false }),
    );

    assert_eq!(blocked.code, 3, "{}", blocked.stderr);
    assert_eq!(
        blocked.stdout,
        format!(
            "{}retire: blocked: 1 unexpired user certificate signed by a previous key or \
             before rotation tracking\n",
            finished_line(&old)
        )
    );
    assert!(blocked.stderr.contains("so it was not applied"));
    assert!(!blocked.stderr.contains("nothing was changed"));
    assert!(
        !fixture
            .slot(CaKind::User)
            .join(format!("{old}.age"))
            .exists()
    );
    let left = FileBackend::read_slot(&fixture.ca_dir(), CaKind::User).unwrap();
    assert_eq!(
        left.trust
            .previous()
            .map(fingerprint_hex)
            .collect::<Vec<_>>(),
        [extra]
    );
}

#[test]
fn client_authorities_rotate_through_the_commands_at_the_ca_level() {
    let fixture = fixture();
    for kind in [CaKind::UserX509, CaKind::DbClient] {
        let last = if kind == CaKind::DbClient {
            RESTART_LINE
        } else {
            LAST_LINE
        };
        let assert_applied = |outcome: &Outcome, context: &str| {
            assert_ends_with(outcome, context, last);
            assert_eq!(
                outcome.stdout.contains(LAST_LINE),
                kind != CaKind::DbClient,
                "{context}: {}",
                outcome.stdout
            );
        };
        let shown = section(&status(&fixture), kind);
        assert!(shown.starts_with("  active    "), "{shown}");
        assert!(shown.contains("  trust id  "), "{shown}");
        assert!(
            !shown.contains("nodes") && !shown.contains("certificates"),
            "{shown}"
        );
        assert!(shown.ends_with("  add-next: ready"), "{shown}");

        let added = run_audited(&fixture, change(kind, ChangeStep::AddNext));
        assert_applied(&added, "add-next");
        let next = fs::read_to_string(fixture.slot(kind).join("next")).unwrap();
        let next = next.trim_end().to_owned();
        assert_eq!(
            added.stdout.lines().next(),
            Some(format!("{kind} key {next} added as next").as_str())
        );
        let (_, roots) = ClientCa::read_roots(&fixture.ca_dir(), kind).unwrap();
        assert_eq!(roots.len(), 2);
        let next_root: String = Sha256::digest(&roots[1].certificate_der)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            added.stdout.lines().nth(1),
            Some(format!("{kind} root sha256:{next_root}").as_str())
        );
        let event = audit_events(&fixture)
            .into_iter()
            .find(|event| event.text("fp") == Some(next.as_str()))
            .unwrap();
        assert_eq!(event.kind().name(), "ca.key.added");
        assert_eq!(event.text("kind"), Some(kind.as_str()));
        let shown = section(&status(&fixture), kind);
        assert!(shown.contains(&format!("  next      {next}")), "{shown}");
        assert!(
            shown.ends_with(&format!("  {}", not_measured("promote"))),
            "{shown}"
        );

        let active = fingerprint_hex(
            FileBackend::read_slot(&fixture.ca_dir(), kind)
                .unwrap()
                .trust
                .active(),
        );
        assert_not_measured(
            &fixture,
            kind,
            ChangeStep::Promote { force: false },
            "promote",
        );
        let forced = run_audited(&fixture, change(kind, ChangeStep::Promote { force: true }));
        assert_applied(&forced, "promote --force");
        assert_eq!(
            forced.stdout.lines().take(2).collect::<Vec<_>>(),
            [not_measured("promote").as_str(), "forced past the check"]
        );
        assert_forced_event(&fixture, "ca.key.promoted", &next);
        let authorities = load_authorities(&fixture.data_dir, &no_env).unwrap();
        let slot = match kind {
            CaKind::UserX509 => authorities.user_x509.unwrap(),
            _ => authorities.db_client.unwrap(),
        };
        assert_eq!(fingerprint_hex(slot.trust.active()), next);
        assert_eq!(
            slot.ca.root_der(),
            fs::read(fixture.slot(kind).join(format!("{next}.root.der"))).unwrap()
        );
        let shown = section(&status(&fixture), kind);
        assert!(
            shown.ends_with(&format!("  {}", not_measured("retire"))),
            "{shown}"
        );

        assert_not_measured(
            &fixture,
            kind,
            ChangeStep::Retire { force: false },
            "retire",
        );
        let retired = run_audited(&fixture, change(kind, ChangeStep::Retire { force: true }));
        assert_applied(&retired, "retire --force");
        assert_forced_event(&fixture, "ca.key.retired", &active);
        let shown = section(&status(&fixture), kind);
        assert!(shown.contains("  retired   "), "{shown}");
        assert!(shown.ends_with("  add-next: ready"), "{shown}");
        let retired_dir = fixture.slot(kind).join("retired");
        let mut names: Vec<String> = fs::read_dir(&retired_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names.len(), 2);
        assert!(names[0].ends_with(".pub") && names[1].ends_with(".root.der"));
        assert_eq!(
            ClientCa::read_roots(&fixture.ca_dir(), kind)
                .unwrap()
                .1
                .len(),
            1
        );
    }

    let outcome = run(&fixture, RotationAction::Status { json: true });
    let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
    for kind in ["user-x509", "db-client"] {
        assert_eq!(value[kind]["keys"][0]["state"], "active");
        assert_eq!(value[kind]["trust_id"].as_str().unwrap().len(), 64);
        assert_eq!(value[kind]["steps"][0]["line"], "add-next: ready");
        assert!(value[kind]["nodes"].is_null());
    }
}

#[test]
fn status_of_an_installation_without_the_client_authorities_skips_them() {
    let fixture = fixture();
    for kind in [CaKind::UserX509, CaKind::DbClient] {
        fs::remove_dir_all(fixture.slot(kind)).unwrap();
    }

    let text = status(&fixture);
    let json = run(&fixture, RotationAction::Status { json: true });
    let refused = run(&fixture, change(CaKind::DbClient, ChangeStep::AddNext));

    assert!(
        !text.contains("user-x509") && !text.contains("db-client"),
        "{text}"
    );
    assert!(section(&text, CaKind::User).ends_with("  add-next: ready"));
    let value: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    assert!(value["user-x509"].is_null() && value["db-client"].is_null());
    assert!(value["host"]["keys"].is_array());
    assert_eq!(refused.code, 1);
    assert!(
        refused
            .stderr
            .contains("the db-client certificate authority is not initialized"),
        "{}",
        refused.stderr
    );
}

fn not_measured(step: &str) -> String {
    format!("{step}: blocked: use of this authority is not measured yet")
}

fn assert_not_measured(fixture: &Fixture, kind: CaKind, step: ChangeStep, name: &str) {
    let before = snapshot_slot(fixture, kind);
    let blocked = run(fixture, change(kind, step));
    assert_eq!(blocked.code, 3, "{name}: {}", blocked.stderr);
    assert_eq!(blocked.stdout, format!("{}\n", not_measured(name)));
    assert!(
        blocked.stderr.contains("so it was not applied"),
        "{}",
        blocked.stderr
    );
    assert_eq!(snapshot_slot(fixture, kind), before, "{name}");
}

fn snapshot_slot(fixture: &Fixture, kind: CaKind) -> Vec<(String, Vec<u8>)> {
    let dir = fixture.slot(kind);
    let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&path).unwrap())
        })
        .collect();
    files.sort();
    files
}

fn assert_forced_event(fixture: &Fixture, name: &str, fp: &str) {
    let event = audit_events(fixture)
        .into_iter()
        .find(|event| event.kind().name() == name && event.text("fp") == Some(fp))
        .unwrap_or_else(|| panic!("no {name} event for {fp}"));
    assert_eq!(event.flag("forced"), Some(true));
    assert_eq!(event.flag("blocked"), Some(true));
}
