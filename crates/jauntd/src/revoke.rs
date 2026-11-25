use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use jaunt_audit::{AuditTap, system_clock as audit_clock};
use jaunt_control::{
    Clock, ListRevocationsError, MAX_LIST_PAGE, REVOCATION_WATCH_INTERVAL, RevocationAdmin,
    RevokeError, RevokeRequest, UnrevokeError, system_clock,
};
use jaunt_store::{Revocation, RevocationKind, Store, StoreError};

use crate::audit::{self, AuditStartError, Surface};
use crate::config;
use crate::logging;
use crate::node::{Terminal, approver_from_env, format_utc, printable};

const DATABASE_FILE: &str = "jaunt.db";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeAction {
    Revoke {
        kind: RevocationKind,
        subject: String,
        reason: String,
    },
    List,
    Remove {
        id: String,
    },
}

#[derive(Debug, thiserror::Error)]
enum RevokeCommandError {
    #[error("{0}")]
    Config(String),
    #[error("the database {} does not exist: start the daemon once to create it", .0.display())]
    NoDatabase(PathBuf),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot open the database {}: {source}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: StoreError,
    },
    #[error("cannot migrate the database: {0}")]
    Migrate(#[source] StoreError),
    #[error("cannot look up the node: {0}")]
    Node(#[source] StoreError),
    #[error(transparent)]
    Audit(#[from] AuditStartError),
    #[error("cannot write the output: {0}")]
    Output(#[source] io::Error),
    #[error(transparent)]
    Revoke(#[from] RevokeError),
    #[error(transparent)]
    Remove(#[from] UnrevokeError),
    #[error(transparent)]
    List(#[from] ListRevocationsError),
}

impl RevokeCommandError {
    fn exit_code(&self) -> u8 {
        match self {
            RevokeCommandError::Revoke(
                RevokeError::InvalidSubject(_) | RevokeError::InvalidReason,
            ) => EXIT_USAGE,
            _ => EXIT_FAILED,
        }
    }
}

pub fn run(config_path: &Path, action: RevokeAction) -> ExitCode {
    let env = |name: &str| std::env::var_os(name);
    let tap = AuditTap::new(audit_clock());
    if let Err(err) = logging::init(&env, &tap) {
        eprintln!("{err}");
        return ExitCode::from(EXIT_FAILED);
    }
    let author = approver_from_env(&env);
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut terminal = Terminal {
        input: &mut input,
        stdout: &mut stdout,
        stderr: &mut stderr,
    };
    ExitCode::from(execute(
        config_path,
        action,
        &author,
        system_clock(),
        &mut terminal,
        &tap,
    ))
}

pub fn execute(
    config_path: &Path,
    action: RevokeAction,
    author: &str,
    clock: Clock,
    terminal: &mut Terminal<'_>,
    tap: &AuditTap,
) -> u8 {
    match attempt(config_path, action, author, clock, terminal, tap) {
        Ok(()) => EXIT_OK,
        Err(err) => {
            let code = err.exit_code();
            if writeln!(terminal.stderr, "{err}").is_err() {
                return EXIT_FAILED;
            }
            code
        }
    }
}

fn attempt(
    config_path: &Path,
    action: RevokeAction,
    author: &str,
    clock: Clock,
    terminal: &mut Terminal<'_>,
    tap: &AuditTap,
) -> Result<(), RevokeCommandError> {
    let config = config::load(config_path).map_err(RevokeCommandError::Config)?;
    let database = config.data_dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Err(RevokeCommandError::NoDatabase(database));
    }
    let audit_settings = if matches!(action, RevokeAction::List) {
        None
    } else {
        Some(
            config
                .audit
                .into_settings()
                .map_err(|err| RevokeCommandError::Config(err.to_string()))?,
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(RevokeCommandError::Runtime)?;
    let outcome = runtime.block_on(async {
        let store = Store::open(&database)
            .await
            .map_err(|source| RevokeCommandError::Open {
                path: database.clone(),
                source,
            })?;
        store.migrate().await.map_err(RevokeCommandError::Migrate)?;
        let audit = audit_settings
            .map(|settings| audit::start(&settings, Surface::Cli, &store, tap, audit_clock()))
            .transpose()?;
        let admin = RevocationAdmin::new(store.clone(), clock);
        let outcome = match action {
            RevokeAction::Revoke {
                kind,
                subject,
                reason,
            } => match resolve_node(&store, kind, subject).await {
                Ok(subject) => revoke(&admin, kind, subject, reason, author, terminal).await,
                Err(err) => Err(err),
            },
            RevokeAction::List => list(&admin, terminal).await,
            RevokeAction::Remove { id } => remove(&admin, &id, author, terminal).await,
        };
        if let Some(audit) = audit {
            audit.shutdown(audit::FLUSH_DEADLINE).await;
        }
        outcome
    });
    audit::finish_runtime(runtime, audit::RUNTIME_GRACE);
    outcome
}

async fn resolve_node(
    store: &Store,
    kind: RevocationKind,
    subject: String,
) -> Result<String, RevokeCommandError> {
    if kind != RevocationKind::Node {
        return Ok(subject);
    }
    let nodes = store.nodes();
    if nodes
        .get(&subject)
        .await
        .map_err(RevokeCommandError::Node)?
        .is_some()
    {
        return Ok(subject);
    }
    Ok(nodes
        .get_active_by_name(&subject)
        .await
        .map_err(RevokeCommandError::Node)?
        .map_or(subject, |node| node.id))
}

async fn revoke(
    admin: &RevocationAdmin,
    kind: RevocationKind,
    subject: String,
    reason: String,
    author: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), RevokeCommandError> {
    let revoked = admin
        .revoke(
            &RevokeRequest {
                kind,
                subject,
                reason,
            },
            author,
        )
        .await?;
    let revocation = &revoked.revocation;
    let headline = if revoked.created {
        format!(
            "revoked {} {} (revocation {})\n",
            revocation.kind.as_str(),
            printable(&revocation.subject),
            printable(&revocation.id)
        )
    } else {
        format!(
            "{} {} was already revoked (revocation {})\n",
            revocation.kind.as_str(),
            printable(&revocation.subject),
            printable(&revocation.id)
        )
    };
    say(terminal, &headline)?;
    say(
        terminal,
        &format!(
            "if a jauntd that uses this database is running, it refuses new connections for it \
             at once and closes its live sessions within about {}, at its next revocation check\n",
            spoken(REVOCATION_WATCH_INTERVAL)
        ),
    )
}

fn spoken(interval: Duration) -> String {
    match interval.as_secs() {
        0 | 1 => "a second".to_owned(),
        secs => format!("{secs} seconds"),
    }
}

async fn remove(
    admin: &RevocationAdmin,
    id: &str,
    author: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), RevokeCommandError> {
    let removed = admin.remove(id, author).await?;
    say(
        terminal,
        &format!(
            "removed revocation {} of {} {}\n",
            printable(&removed.id),
            removed.kind.as_str(),
            printable(&removed.subject),
        ),
    )?;
    let note = match removed.kind {
        RevocationKind::Node => {
            "the node stays removed: its agent must enrol again and be approved to come back\n"
        }
        RevocationKind::User => {
            "if a jauntd that uses this database is running, it accepts new connections for it at once\n\
             the web sessions and API tokens of the user were deleted: the user signs in again to get new ones\n"
        }
        RevocationKind::Serial => {
            "if a jauntd that uses this database is running, it accepts new connections for it at once\n"
        }
    };
    say(terminal, note)
}

async fn list(
    admin: &RevocationAdmin,
    terminal: &mut Terminal<'_>,
) -> Result<(), RevokeCommandError> {
    let mut all = Vec::new();
    let mut cursor = None;
    loop {
        let page = admin.list(cursor.as_ref(), MAX_LIST_PAGE).await?;
        all.extend(page.revocations);
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    say(terminal, &render(&all))
}

fn render(revocations: &[Revocation]) -> String {
    let mut rows = vec![[
        "ID".to_owned(),
        "KIND".to_owned(),
        "SUBJECT".to_owned(),
        "CREATED BY".to_owned(),
        "CREATED".to_owned(),
        "REASON".to_owned(),
    ]];
    for revocation in revocations {
        rows.push([
            printable(&revocation.id),
            revocation.kind.as_str().to_owned(),
            printable(&revocation.subject),
            printable(&revocation.created_by),
            format_utc(revocation.created_at),
            printable(&revocation.reason),
        ]);
    }
    let mut widths = [0_usize; 6];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut text = String::new();
    for row in &rows {
        let line: Vec<String> = row
            .iter()
            .zip(widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        text.push_str(line.join("  ").trim_end());
        text.push('\n');
    }
    text
}

fn say(terminal: &mut Terminal<'_>, text: &str) -> Result<(), RevokeCommandError> {
    terminal
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| terminal.stdout.flush())
        .map_err(RevokeCommandError::Output)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use jaunt_audit::{AuditTap, system_clock as audit_clock};
    use jaunt_control::Clock;
    use jaunt_store::{NewCertificate, NewUser, NodeState, RevocationKind, Store};
    use tempfile::TempDir;

    use super::{RevokeAction, execute};
    use crate::node::Terminal;

    const NOW: i64 = 1_700_000_000;
    const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
        ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
        created_at) VALUES ('node-1', 'web-01', '{}', 'h', 't', 's', 'f', 'f', 'active', \
        'cli:root', 1)";

    struct Fixture {
        dir: TempDir,
        config: PathBuf,
        user_id: String,
        serial: i64,
    }

    struct Outcome {
        code: u8,
        stdout: String,
        stderr: String,
    }

    fn clock() -> Clock {
        Arc::new(|| UNIX_EPOCH + Duration::from_secs(u64::try_from(NOW).unwrap()))
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn open(dir: &Path) -> Store {
        let store = Store::open(&dir.join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("jauntd.yaml");
        std::fs::write(
            &config,
            format!(
                "data_dir: {}\npublic_url: https://jaunt.example.com\n\
                 ssh_suffix: jaunt.example.com\nagent_endpoint: agents.example.com:443\n\
                 oidc:\n  issuer_url: https://idp.example.com\n  client_id: jaunt\n",
                dir.path().display()
            ),
        )
        .unwrap();
        let (user_id, serial) = runtime().block_on(async {
            let store = open(dir.path()).await;
            let user = store
                .users()
                .upsert(
                    &NewUser {
                        issuer: "https://idp.example".to_owned(),
                        subject: "alice".to_owned(),
                        email: "alice@example.com".to_owned(),
                        username: "alice".to_owned(),
                        display_name: None,
                        groups: Vec::new(),
                    },
                    NOW,
                )
                .await
                .unwrap();
            let serial = store.certificates().allocate_serial().await.unwrap();
            store
                .certificates()
                .record(&NewCertificate {
                    serial,
                    user_id: user.id.clone(),
                    kind: "user".to_owned(),
                    key_id: format!("jaunt:alice@example.com:{serial}"),
                    valid_after: NOW - 60,
                    valid_before: NOW + 3600,
                    issued_at: NOW,
                    ca_fingerprint: None,
                    host_trust_id: None,
                    subject_fingerprint: None,
                })
                .await
                .unwrap();
            let raw = sqlx::SqlitePool::connect_with(
                sqlx::sqlite::SqliteConnectOptions::new().filename(dir.path().join("jaunt.db")),
            )
            .await
            .unwrap();
            sqlx::query(RAW_NODE).execute(&raw).await.unwrap();
            (user.id, serial)
        });
        Fixture {
            dir,
            config,
            user_id,
            serial,
        }
    }

    fn run(fixture: &Fixture, action: RevokeAction) -> Outcome {
        let mut input: &[u8] = b"";
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
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
            &AuditTap::new(audit_clock()),
        );
        Outcome {
            code,
            stdout: String::from_utf8(stdout).unwrap(),
            stderr: String::from_utf8(stderr).unwrap(),
        }
    }

    fn revoke(kind: RevocationKind, subject: &str) -> RevokeAction {
        RevokeAction::Revoke {
            kind,
            subject: subject.to_owned(),
            reason: "lost laptop".to_owned(),
        }
    }

    #[test]
    fn revoke_list_and_rm_work_on_the_database_and_say_when_the_daemon_applies_them() {
        let fixture = fixture();

        let user = run(&fixture, revoke(RevocationKind::User, &fixture.user_id));
        assert_eq!(user.code, 0, "{}", user.stderr);
        assert!(
            user.stdout
                .starts_with(&format!("revoked user {} (revocation ", fixture.user_id)),
            "{}",
            user.stdout
        );
        assert!(
            user.stdout.contains(
                "if a jauntd that uses this database is running, it refuses new connections for it at once"
            ),
            "{}",
            user.stdout
        );
        assert!(
            user.stdout
                .contains("closes its live sessions within about a second, at its next"),
            "{}",
            user.stdout
        );
        let again = run(&fixture, revoke(RevocationKind::User, &fixture.user_id));
        assert_eq!(again.code, 0);
        assert!(
            again.stdout.contains("was already revoked"),
            "{}",
            again.stdout
        );
        let serial = run(
            &fixture,
            revoke(RevocationKind::Serial, &fixture.serial.to_string()),
        );
        assert_eq!(serial.code, 0, "{}", serial.stderr);
        let node = run(&fixture, revoke(RevocationKind::Node, "web-01"));
        assert_eq!(node.code, 0, "{}", node.stderr);
        assert!(
            node.stdout.starts_with("revoked node node-1 "),
            "{}",
            node.stdout
        );

        let listed = run(&fixture, RevokeAction::List);
        assert_eq!(listed.code, 0);
        let lines: Vec<&str> = listed.stdout.lines().collect();
        assert_eq!(lines.len(), 4, "{}", listed.stdout);
        assert!(lines[0].starts_with("ID"), "{}", lines[0]);
        assert!(lines[1..].iter().all(|line| line.contains("cli:tester")));
        assert!(
            lines[1..]
                .iter()
                .all(|line| line.contains("2023-11-14T22:13:20Z"))
        );
        assert!(lines[1..].iter().all(|line| line.ends_with("lost laptop")));

        let (revoked_node, user_revocation) = runtime().block_on(async {
            let store = open(fixture.dir.path()).await;
            (
                store.nodes().get("node-1").await.unwrap().unwrap(),
                store
                    .revocations()
                    .find(RevocationKind::User, &fixture.user_id)
                    .await
                    .unwrap()
                    .unwrap(),
            )
        });
        assert_eq!(revoked_node.state, NodeState::Removed);
        assert_eq!(user_revocation.created_by, "cli:tester");
        let removed = run(
            &fixture,
            RevokeAction::Remove {
                id: user_revocation.id.clone(),
            },
        );
        assert_eq!(removed.code, 0, "{}", removed.stderr);
        assert!(
            removed.stdout.starts_with(&format!(
                "removed revocation {} of user {}",
                user_revocation.id, fixture.user_id
            )),
            "{}",
            removed.stdout
        );
        let missing = run(
            &fixture,
            RevokeAction::Remove {
                id: user_revocation.id,
            },
        );
        assert_eq!(missing.code, 1);
        assert_eq!(missing.stderr, "no revocation has this id\n");
        assert_eq!(run(&fixture, RevokeAction::List).stdout.lines().count(), 3);
        assert!(
            removed
                .stdout
                .contains("if a jauntd that uses this database is running")
        );
        assert!(
            removed.stdout.ends_with(
                "the web sessions and API tokens of the user were deleted: the user signs in again to get new ones\n"
            ),
            "{}",
            removed.stdout
        );

        let node_revocation = runtime().block_on(async {
            open(fixture.dir.path())
                .await
                .revocations()
                .find(RevocationKind::Node, "node-1")
                .await
                .unwrap()
                .unwrap()
        });
        let lifted = run(
            &fixture,
            RevokeAction::Remove {
                id: node_revocation.id,
            },
        );
        assert_eq!(lifted.code, 0, "{}", lifted.stderr);
        assert!(
            lifted
                .stdout
                .contains("the node stays removed: its agent must enrol again"),
            "{}",
            lifted.stdout
        );
    }

    #[test]
    fn bad_and_unknown_subjects_and_a_missing_database_are_refused() {
        let fixture = fixture();
        for (action, code, message) in [
            (
                revoke(RevocationKind::Serial, "abc"),
                2,
                "the subject is not a valid certificate serial\n",
            ),
            (
                RevokeAction::Revoke {
                    kind: RevocationKind::User,
                    subject: fixture.user_id.clone(),
                    reason: " ".to_owned(),
                },
                2,
                "the reason must be 1 to 256 characters without control characters\n",
            ),
            (
                revoke(RevocationKind::User, "nobody"),
                1,
                "no user id matches this subject\n",
            ),
            (
                revoke(RevocationKind::Node, "web-99"),
                1,
                "no node id matches this subject\n",
            ),
        ] {
            let outcome = run(&fixture, action);
            assert_eq!((outcome.code, outcome.stderr.as_str()), (code, message));
            assert!(outcome.stdout.is_empty());
        }
        std::fs::remove_file(fixture.dir.path().join("jaunt.db")).unwrap();
        let outcome = run(&fixture, RevokeAction::List);
        assert_eq!(outcome.code, 1);
        assert!(
            outcome.stderr.contains("does not exist"),
            "{}",
            outcome.stderr
        );
    }
}
