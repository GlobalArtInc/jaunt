use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use jaunt_audit::{AuditTap, system_clock as audit_clock};
use jaunt_control::{
    ApproveError, Clock, LabelError, Labels, ListError, NodeAdmin, NodeListing, PendingEnrollment,
    system_clock,
};
use jaunt_store::{NodeState, Store, StoreError};

use crate::audit::{self, AuditStartError, Surface};
use crate::config::{self, EnvLookup};
use crate::logging;

const DATABASE_FILE: &str = "jaunt.db";
const USER_VAR: &str = "USER";
const UNKNOWN_USER: &str = "unknown";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeAction {
    Approve {
        code: String,
        labels: Option<String>,
        yes: bool,
    },
    Reject {
        code: String,
    },
    Rm {
        name: String,
        yes: bool,
    },
    List,
}

pub struct Terminal<'a> {
    pub input: &'a mut dyn BufRead,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

#[derive(Debug, thiserror::Error)]
enum NodeCommandError {
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
    #[error("cannot start the audit pipeline: {0}")]
    Audit(#[from] AuditStartError),
    #[error("cannot read the answer: {0}")]
    Input(#[source] io::Error),
    #[error("cannot write the output: {0}")]
    Output(#[source] io::Error),
    #[error(transparent)]
    Approve(#[from] ApproveError),
    #[error(transparent)]
    Remove(#[from] jaunt_control::RemoveError),
    #[error(transparent)]
    List(#[from] ListError),
    #[error("no active node is named {0:?}")]
    NoSuchNode(String),
    #[error("not confirmed, nothing was changed")]
    Declined,
    #[error("invalid --labels: {0}")]
    Labels(#[source] LabelError),
}

impl NodeCommandError {
    fn exit_code(&self) -> u8 {
        match self {
            NodeCommandError::Labels(_) => EXIT_USAGE,
            _ => EXIT_FAILED,
        }
    }
}

pub fn run(config_path: &Path, action: NodeAction) -> ExitCode {
    let env = |name: &str| std::env::var_os(name);
    let tap = AuditTap::new(audit_clock());
    if let Err(err) = logging::init(&env, &tap) {
        eprintln!("{err}");
        return ExitCode::from(EXIT_FAILED);
    }
    let approver = approver_from_env(&env);
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
        &approver,
        system_clock(),
        &mut terminal,
        &tap,
    ))
}

pub fn approver_from_env(env: EnvLookup<'_>) -> String {
    let user = env(USER_VAR)
        .and_then(|value| value.into_string().ok())
        .map(|value| {
            value
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                        ch
                    } else {
                        '_'
                    }
                })
                .take(64)
                .collect::<String>()
        })
        .filter(|value| !value.is_empty());
    format!("cli:{}", user.as_deref().unwrap_or(UNKNOWN_USER))
}

pub fn execute(
    config_path: &Path,
    action: NodeAction,
    approver: &str,
    clock: Clock,
    terminal: &mut Terminal<'_>,
    tap: &AuditTap,
) -> u8 {
    match attempt(config_path, action, approver, clock, terminal, tap) {
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
    action: NodeAction,
    approver: &str,
    clock: Clock,
    terminal: &mut Terminal<'_>,
    tap: &AuditTap,
) -> Result<(), NodeCommandError> {
    let labels = match &action {
        NodeAction::Approve {
            labels: Some(text), ..
        } => Some(Labels::parse_assignments(text).map_err(NodeCommandError::Labels)?),
        _ => None,
    };
    let config = config::load(config_path).map_err(NodeCommandError::Config)?;
    let database = config.data_dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Err(NodeCommandError::NoDatabase(database));
    }
    let read_only = matches!(action, NodeAction::List);
    let audit_settings = if read_only {
        None
    } else {
        Some(
            config
                .audit
                .into_settings()
                .map_err(|err| NodeCommandError::Config(err.to_string()))?,
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(NodeCommandError::Runtime)?;
    let outcome = runtime.block_on(async {
        let store = Store::open(&database)
            .await
            .map_err(|source| NodeCommandError::Open {
                path: database.clone(),
                source,
            })?;
        store.migrate().await.map_err(NodeCommandError::Migrate)?;
        let audit = audit_settings
            .map(|settings| audit::start(&settings, Surface::Cli, &store, tap, audit_clock()))
            .transpose()?;
        let admin = NodeAdmin::new(store, clock);
        let outcome = dispatch(&admin, action, labels, approver, terminal).await;
        if let Some(audit) = audit {
            audit.shutdown(audit::FLUSH_DEADLINE).await;
        }
        outcome
    });
    audit::finish_runtime(runtime, audit::RUNTIME_GRACE);
    outcome
}

async fn dispatch(
    admin: &NodeAdmin,
    action: NodeAction,
    labels: Option<Labels>,
    approver: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), NodeCommandError> {
    match action {
        NodeAction::Approve { code, yes, .. } => {
            approve(admin, &code, labels, yes, approver, terminal).await
        }
        NodeAction::Reject { code } => {
            let rejected = admin.reject(&code, approver).await?;
            say(
                terminal,
                &format!("rejected the enrollment of {}\n", printable(&rejected.name)),
            )
        }
        NodeAction::Rm { name, yes } => remove(admin, &name, yes, approver, terminal).await,
        NodeAction::List => list(admin, terminal).await,
    }
}

async fn approve(
    admin: &NodeAdmin,
    code: &str,
    labels: Option<Labels>,
    yes: bool,
    approver: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), NodeCommandError> {
    let pending = admin.pending(code).await?;
    say(terminal, &render_pending(&pending, labels.as_ref()))?;
    if !yes && !confirm(terminal, "Approve? [y/N] ")? {
        return Err(NodeCommandError::Declined);
    }
    let approved = admin.approve(code, approver, labels).await?;
    say(
        terminal,
        &format!(
            "approved node {} (id {})\n",
            printable(&approved.node.name),
            printable(&approved.node.id)
        ),
    )?;
    if let Some(old) = approved.replaced {
        say(
            terminal,
            &format!("removed the replaced node {}\n", printable(&old.id)),
        )?;
    }
    Ok(())
}

async fn remove(
    admin: &NodeAdmin,
    name: &str,
    yes: bool,
    approver: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), NodeCommandError> {
    let nodes = admin.list_nodes().await?;
    let node = nodes
        .iter()
        .map(|listing| &listing.node)
        .find(|node| node.name == name && node.state == NodeState::Active)
        .ok_or_else(|| NodeCommandError::NoSuchNode(name.to_owned()))?;
    let question = format!(
        "Remove node {} (id {})? [y/N] ",
        printable(&node.name),
        printable(&node.id)
    );
    if !yes && !confirm(terminal, &question)? {
        return Err(NodeCommandError::Declined);
    }
    let removed = admin.remove_node(name, approver).await?;
    say(
        terminal,
        &format!("removed node {}\n", printable(&removed.name)),
    )
}

async fn list(admin: &NodeAdmin, terminal: &mut Terminal<'_>) -> Result<(), NodeCommandError> {
    let nodes = admin.list_nodes().await?;
    say(terminal, &render_nodes(&nodes))
}

fn say(terminal: &mut Terminal<'_>, text: &str) -> Result<(), NodeCommandError> {
    terminal
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| terminal.stdout.flush())
        .map_err(NodeCommandError::Output)
}

fn confirm(terminal: &mut Terminal<'_>, question: &str) -> Result<bool, NodeCommandError> {
    say(terminal, question)?;
    let mut answer = String::new();
    terminal
        .input
        .read_line(&mut answer)
        .map_err(NodeCommandError::Input)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn render_pending(pending: &PendingEnrollment, label_override: Option<&Labels>) -> String {
    let mut text = format!(
        "name:         {}\nlabels:       {}\nhostname:     {}\nsource:       {}\n\
         requested at: {}\nagent:        {}\ntls key:      sha256:{}\nssh host key: {}\n",
        printable(&pending.name),
        or_dash(&pending.labels.to_string()),
        printable(&pending.hostname),
        printable(&pending.peer_addr),
        format_utc(pending.requested_at),
        printable(&pending.agent_version),
        printable(&pending.tls_key_sha256),
        printable(&pending.ssh_host_key_fingerprint),
    );
    if pending.source_network != pending.peer_addr {
        text.push_str(&format!(
            "network:      {}\n",
            printable(&pending.source_network)
        ));
    }
    if let Some(labels) = label_override {
        text.push_str(&format!("new labels:   {}\n", or_dash(&labels.to_string())));
    }
    if pending.replace_existing {
        text.push_str("replace:      yes, the active node with this name will be removed\n");
    }
    text
}

fn render_nodes(nodes: &[NodeListing]) -> String {
    let mut rows = vec![[
        "NAME".to_owned(),
        "STATE".to_owned(),
        "CERT".to_owned(),
        "LABELS".to_owned(),
        "APPROVED BY".to_owned(),
        "CREATED".to_owned(),
    ]];
    for listing in nodes {
        let node = &listing.node;
        rows.push([
            printable(&node.name),
            node.state.as_str().to_owned(),
            listing.certificates.as_str().to_owned(),
            or_dash(&printable(&node.labels.to_string())),
            printable(&node.approved_by),
            format_utc(node.created_at),
        ]);
    }
    let mut widths = [0_usize; 6];
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
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

pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if (' '..='~').contains(&ch) {
                ch.to_string()
            } else {
                ch.escape_default().to_string()
            }
        })
        .collect()
}

fn or_dash(text: &str) -> String {
    if text.is_empty() {
        "-".to_owned()
    } else {
        text.to_owned()
    }
}

pub fn format_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs_of_day = unix_secs.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_audit::{
        AuditTap, keep_callsites_enabled_for_scoped_capture, system_clock as audit_clock,
    };
    use jaunt_ca::ssh_key::rand_core::OsRng;
    use jaunt_ca::ssh_key::sha2::{Digest, Sha256};
    use jaunt_ca::ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
    use jaunt_control::Clock;
    use jaunt_store::{
        AuditQuery, CreateOutcome, EnrollmentLimits, NewEnrollment, NewNodeCertificate, Node,
        NodeCertificateKind, NodeState, Store,
    };
    use tempfile::TempDir;
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{NodeAction, Terminal, approver_from_env, execute, format_utc};

    const NOW: i64 = 1_700_000_000;
    const CODE: &str = "ABCD-2345";
    const OTHER_CODE: &str = "WXYZ-6789";
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    struct Fixture {
        _dir: TempDir,
        config: PathBuf,
        tls_der: Vec<u8>,
        ssh_fingerprint: String,
    }

    struct Outcome {
        code: u8,
        stdout: String,
        stderr: String,
    }

    fn clock_at(now_secs: i64) -> Clock {
        Arc::new(move || UNIX_EPOCH + Duration::from_secs(now_secs.unsigned_abs()))
    }

    fn hex(data: &[u8]) -> String {
        Sha256::digest(data)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn fixture(with_database: bool) -> Fixture {
        fixture_with(with_database, "example.com", "0.1.0")
    }

    fn fixture_with(with_database: bool, hostname_suffix: &str, agent_version: &str) -> Fixture {
        fixture_from(
            with_database,
            hostname_suffix,
            agent_version,
            ("203.0.113.5", "203.0.113.5"),
        )
    }

    fn fixture_from(
        with_database: bool,
        hostname_suffix: &str,
        agent_version: &str,
        (network, peer): (&str, &str),
    ) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("jauntd.yaml");
        std::fs::write(&config, format!("data_dir: {}\n", dir.path().display())).unwrap();
        let tls_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let raw = tls_private.public_key().key_data().ed25519().unwrap().0;
        let tls_der = [SPKI_PREFIX.as_slice(), raw.as_slice()].concat();
        let ssh_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let ssh_public = PublicKey::from(ssh_private.public_key().key_data().clone());
        let fixture = Fixture {
            _dir: dir,
            config,
            tls_der,
            ssh_fingerprint: ssh_public.fingerprint(HashAlg::Sha256).to_string(),
        };
        if with_database {
            let tls = STANDARD.encode(&fixture.tls_der);
            let ssh = ssh_public.to_openssh().unwrap();
            runtime().block_on(async {
                let store = open(&fixture.config).await;
                for (name, code) in [("web-01", CODE), ("db-01", OTHER_CODE)] {
                    let created = store
                        .enrollments()
                        .create(
                            &NewEnrollment {
                                handle_hash: hex(name.as_bytes()),
                                code_hash: hex(code.replace('-', "").as_bytes()),
                                name: name.to_owned(),
                                labels: [("env".to_owned(), "prod".to_owned())].into(),
                                hostname: format!("{name}.{hostname_suffix}"),
                                source_ip: network.to_owned(),
                                peer_addr: peer.to_owned(),
                                tls_public_key: tls.clone(),
                                ssh_host_public_key: ssh.clone(),
                                replace_existing: false,
                                agent_version: agent_version.to_owned(),
                                ttl_secs: 900,
                            },
                            EnrollmentLimits {
                                max_pending: 10,
                                max_pending_per_ip: 10,
                            },
                            NOW,
                        )
                        .await
                        .unwrap();
                    assert!(matches!(created, CreateOutcome::Created(_)));
                }
            });
        }
        fixture
    }

    async fn open(config: &Path) -> Store {
        let database = config.parent().unwrap().join("jaunt.db");
        let store = Store::open(&database).await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    fn nodes(fixture: &Fixture) -> Vec<Node> {
        runtime().block_on(async { open(&fixture.config).await.nodes().list().await.unwrap() })
    }

    fn run(fixture: &Fixture, action: NodeAction, answer: &str) -> Outcome {
        run_at(&fixture.config, action, answer)
    }

    fn run_at(config: &Path, action: NodeAction, answer: &str) -> Outcome {
        run_at_time(config, action, answer, NOW)
    }

    fn run_at_time(config: &Path, action: NodeAction, answer: &str, now_secs: i64) -> Outcome {
        run_with_tap(
            config,
            action,
            answer,
            now_secs,
            &AuditTap::new(audit_clock()),
        )
    }

    fn run_with_tap(
        config: &Path,
        action: NodeAction,
        answer: &str,
        now_secs: i64,
        tap: &AuditTap,
    ) -> Outcome {
        let mut input = answer.as_bytes();
        let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
        let code = execute(
            config,
            action,
            "cli:tester",
            clock_at(now_secs),
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

    fn approve(code: &str, labels: Option<&str>, yes: bool) -> NodeAction {
        NodeAction::Approve {
            code: code.to_owned(),
            labels: labels.map(str::to_owned),
            yes,
        }
    }

    #[test]
    fn approve_with_yes_shows_what_is_being_approved_and_creates_the_node() {
        let fixture = fixture(true);

        let outcome = run(&fixture, approve(CODE, Some("role=db"), true), "");

        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        for expected in [
            "web-01",
            "env=prod",
            "web-01.example.com",
            "203.0.113.5",
            "2023-11-14T22:13:20Z",
            &format!("sha256:{}", hex(&fixture.tls_der)),
            &fixture.ssh_fingerprint,
            "role=db",
            "approved node web-01",
        ] {
            assert!(
                outcome.stdout.contains(expected),
                "{expected}: {}",
                outcome.stdout
            );
        }
        assert!(!outcome.stdout.contains("Approve?"));
        let created = nodes(&fixture);
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].name, "web-01");
        assert_eq!(created[0].approved_by, "cli:tester");
        assert_eq!(created[0].labels["role"], "db");
        assert!(!created[0].labels.contains_key("env"));
    }

    fn run_audited(fixture: &Fixture, action: NodeAction) -> Outcome {
        keep_callsites_enabled_for_scoped_capture();
        let tap = AuditTap::new(audit_clock());
        let _guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));
        run_with_tap(&fixture.config, action, "", NOW, &tap)
    }

    #[test]
    fn cli_decisions_are_written_to_the_audit_table_with_the_operator_before_the_command_returns() {
        let fixture = fixture(true);

        let approved = run_audited(&fixture, approve(CODE, None, true));
        let rejected = run_audited(
            &fixture,
            NodeAction::Reject {
                code: OTHER_CODE.to_owned(),
            },
        );
        let removed = run_audited(
            &fixture,
            NodeAction::Rm {
                name: "web-01".to_owned(),
                yes: true,
            },
        );

        for outcome in [&approved, &rejected, &removed] {
            assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        }
        let rows = runtime().block_on(async {
            open(&fixture.config)
                .await
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
                ("node.removed", "cli:tester"),
                ("node.enroll.rejected", "cli:tester"),
                ("node.enroll.approved", "cli:tester")
            ]
        );
        assert!(rows.iter().all(|row| row.actor != "system"));
        assert!(rows[0].node.is_some());
    }

    #[test]
    fn read_only_commands_ignore_the_audit_section_while_changing_ones_refuse_to_run_without_it() {
        let fixture = fixture(true);
        let missing = fixture
            .config
            .parent()
            .unwrap()
            .join("missing")
            .join("audit.jsonl");
        let mut text = std::fs::read_to_string(&fixture.config).unwrap();
        text.push_str(&format!(
            "audit:\n  jsonl:\n    file: {}\n",
            missing.display()
        ));
        std::fs::write(&fixture.config, text).unwrap();

        let listed = run(&fixture, NodeAction::List, "");
        let approved = run(&fixture, approve(CODE, None, true), "");

        assert_eq!(listed.code, 0, "{}", listed.stderr);
        assert_eq!(approved.code, 1);
        assert!(approved.stderr.contains("audit"), "{}", approved.stderr);
        assert!(nodes(&fixture).is_empty());
    }

    #[test]
    fn a_changing_command_refuses_to_run_when_the_audit_config_leaves_no_sink() {
        let fixture = fixture(true);
        let mut text = std::fs::read_to_string(&fixture.config).unwrap();
        text.push_str("audit:\n  database: false\n");
        std::fs::write(&fixture.config, text).unwrap();

        let approved = run(&fixture, approve(CODE, None, true), "");
        let listed = run(&fixture, NodeAction::List, "");

        assert_eq!(approved.code, 1);
        assert!(
            approved.stderr.contains("no audit sink"),
            "{}",
            approved.stderr
        );
        assert!(nodes(&fixture).is_empty());
        assert_eq!(listed.code, 0, "{}", listed.stderr);
    }

    #[test]
    fn the_confirmation_prompt_approves_only_on_yes() {
        let fixture = fixture(true);

        for answer in ["n\n", "\n", "maybe\n", ""] {
            let outcome = run(&fixture, approve(CODE, None, false), answer);
            assert_eq!(outcome.code, 1, "{answer:?}");
            assert!(outcome.stdout.contains("Approve? [y/N]"));
            assert!(
                outcome.stderr.contains("nothing was changed"),
                "{}",
                outcome.stderr
            );
            assert!(nodes(&fixture).is_empty(), "{answer:?}");
        }
        let accepted = run(&fixture, approve(CODE, None, false), "Y\n");
        assert_eq!(accepted.code, 0, "{}", accepted.stderr);
        assert_eq!(nodes(&fixture)[0].labels["env"], "prod");
    }

    #[test]
    fn unusable_codes_labels_and_environments_are_refused() {
        let fixture = fixture(true);
        let wrong = run(&fixture, approve("ZZZZ-ZZZZ", None, true), "");
        assert_eq!(wrong.code, 1);
        assert!(
            wrong
                .stderr
                .contains("no pending enrollment matches this code")
        );
        assert!(wrong.stdout.is_empty());

        let bad_labels = run(&fixture, approve(CODE, Some("Env=x"), true), "");
        assert_eq!(bad_labels.code, 2);
        assert!(bad_labels.stderr.contains("invalid --labels"));
        assert!(nodes(&fixture).is_empty());

        let used = run(&fixture, approve(CODE, None, true), "");
        assert_eq!(used.code, 0);
        let again = run(&fixture, approve(CODE, None, true), "");
        assert_eq!(again.code, 1);
        assert!(again.stderr.contains("already approved"));

        let no_config = run_at(
            &fixture.config.with_file_name("absent.yaml"),
            NodeAction::List,
            "",
        );
        assert_eq!(no_config.code, 1);
        assert!(no_config.stderr.contains("absent.yaml"));

        let empty = self::fixture(false);
        let no_database = run(&empty, NodeAction::List, "");
        assert_eq!(no_database.code, 1);
        assert!(no_database.stderr.contains("does not exist"));
        assert!(!empty.config.with_file_name("jaunt.db").exists());
    }

    #[test]
    fn reject_closes_the_enrollment_and_rm_removes_a_node_after_confirmation() {
        let fixture = fixture(true);
        let rejected = run(
            &fixture,
            NodeAction::Reject {
                code: OTHER_CODE.to_owned(),
            },
            "",
        );
        assert_eq!(rejected.code, 0, "{}", rejected.stderr);
        assert!(rejected.stdout.contains("db-01"));
        let after = run(&fixture, approve(OTHER_CODE, None, true), "");
        assert_eq!(after.code, 1);
        assert!(after.stderr.contains("rejected"));

        assert_eq!(run(&fixture, approve(CODE, None, true), "").code, 0);
        let declined = run(
            &fixture,
            NodeAction::Rm {
                name: "web-01".to_owned(),
                yes: false,
            },
            "n\n",
        );
        assert_eq!(declined.code, 1);
        assert!(declined.stdout.contains("Remove node web-01"));
        assert_eq!(nodes(&fixture)[0].state, NodeState::Active);

        let removed = run(
            &fixture,
            NodeAction::Rm {
                name: "web-01".to_owned(),
                yes: false,
            },
            "y\n",
        );
        assert_eq!(removed.code, 0, "{}", removed.stderr);
        assert_eq!(nodes(&fixture)[0].state, NodeState::Removed);
        let twice = run(
            &fixture,
            NodeAction::Rm {
                name: "web-01".to_owned(),
                yes: true,
            },
            "",
        );
        assert_eq!(twice.code, 1);
        assert!(twice.stderr.contains("no active node"));
    }

    #[test]
    fn list_shows_name_state_labels_approver_and_creation_time() {
        let fixture = fixture(true);
        let empty = run(&fixture, NodeAction::List, "");
        assert_eq!(empty.code, 0);
        assert_eq!(empty.stdout.lines().count(), 1);

        run(&fixture, approve(CODE, None, true), "");
        run(&fixture, approve(OTHER_CODE, Some(""), true), "");
        run(
            &fixture,
            NodeAction::Rm {
                name: "db-01".to_owned(),
                yes: true,
            },
            "",
        );
        let listed = run(&fixture, NodeAction::List, "");

        assert_eq!(listed.code, 0, "{}", listed.stderr);
        let rows: Vec<Vec<&str>> = listed
            .stdout
            .lines()
            .map(|line| line.split_whitespace().collect())
            .collect();
        assert_eq!(
            rows[0],
            [
                "NAME", "STATE", "CERT", "LABELS", "APPROVED", "BY", "CREATED"
            ]
        );
        assert!(rows.contains(&vec![
            "web-01",
            "active",
            "pending",
            "env=prod",
            "cli:tester",
            "2023-11-14T22:13:20Z"
        ]));
        assert!(rows.contains(&vec![
            "db-01",
            "removed",
            "none",
            "-",
            "cli:tester",
            "2023-11-14T22:13:20Z"
        ]));
    }

    #[test]
    fn list_shows_whether_certificates_were_delivered_are_waiting_or_can_no_longer_be_collected() {
        let fixture = fixture(true);
        run(&fixture, approve(CODE, None, true), "");
        run(&fixture, approve(OTHER_CODE, None, true), "");
        runtime().block_on(async {
            let store = open(&fixture.config).await;
            let collected = store
                .enrollments()
                .get_by_handle_hash(&hex(b"web-01"))
                .await
                .unwrap()
                .unwrap();
            let node_id = collected.node_id.clone().unwrap();
            store
                .enrollments()
                .begin_delivery(&collected.id, NOW + 1)
                .await
                .unwrap()
                .unwrap();
            let records = [NewNodeCertificate {
                kind: NodeCertificateKind::X509,
                serial: "1".to_owned(),
                not_before: NOW,
                not_after: NOW + 100,
                issued_at: NOW,
                ca_fingerprint: None,
            }];
            assert!(
                store
                    .enrollments()
                    .complete_delivery(&collected.id, &node_id, &records)
                    .await
                    .unwrap()
            );
        });
        let certs = |outcome: &Outcome| -> Vec<(String, String)> {
            outcome
                .stdout
                .lines()
                .skip(1)
                .map(|line| {
                    let cells: Vec<&str> = line.split_whitespace().collect();
                    (cells[0].to_owned(), cells[2].to_owned())
                })
                .collect()
        };

        let soon = run_at_time(&fixture.config, NodeAction::List, "", NOW + 10);
        let after_expiry = run_at_time(&fixture.config, NodeAction::List, "", NOW + 900);

        let expected = |waiting: &str| {
            vec![
                ("web-01".to_owned(), "delivered".to_owned()),
                ("db-01".to_owned(), waiting.to_owned()),
            ]
        };
        let mut soon_rows = certs(&soon);
        let mut late_rows = certs(&after_expiry);
        soon_rows.sort_by_key(|row| std::cmp::Reverse(row.0.clone()));
        late_rows.sort_by_key(|row| std::cmp::Reverse(row.0.clone()));
        assert_eq!(soon_rows, expected("pending"));
        assert_eq!(late_rows, expected("none"));
    }

    #[test]
    fn the_exact_peer_address_is_shown_and_its_network_only_when_it_differs() {
        let v4 = fixture(true);
        let v6 = fixture_from(
            true,
            "example.com",
            "0.1.0",
            ("2001:db8:1:2::/64", "2001:db8:1:2::5"),
        );

        let plain = run(&v4, approve(CODE, None, true), "");
        let wide = run(&v6, approve(CODE, None, true), "");

        assert!(
            plain.stdout.contains("source:       203.0.113.5\n"),
            "{}",
            plain.stdout
        );
        assert!(!plain.stdout.contains("network:"));
        assert!(
            wide.stdout.contains("source:       2001:db8:1:2::5\n"),
            "{}",
            wide.stdout
        );
        assert!(
            wide.stdout.contains("network:      2001:db8:1:2::/64\n"),
            "{}",
            wide.stdout
        );
    }

    #[test]
    fn a_delivery_in_progress_is_listed_as_pending() {
        let fixture = fixture(true);
        run(&fixture, approve(CODE, None, true), "");
        runtime().block_on(async {
            let store = open(&fixture.config).await;
            let enrollment = store
                .enrollments()
                .get_by_handle_hash(&hex(b"web-01"))
                .await
                .unwrap()
                .unwrap();
            store
                .enrollments()
                .begin_delivery(&enrollment.id, NOW + 1)
                .await
                .unwrap()
                .unwrap();
        });

        let listed = run_at_time(&fixture.config, NodeAction::List, "", NOW + 10);

        let row: Vec<&str> = listed
            .stdout
            .lines()
            .nth(1)
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!((row[0], row[2]), ("web-01", "pending"), "{}", listed.stdout);
    }

    #[test]
    fn everything_printed_from_a_request_is_escaped() {
        let fixture = fixture_with(true, "example.com\u{1b}[31m\nforged: line", "9.9\u{7}");

        let outcome = run(&fixture, approve(CODE, None, true), "");

        assert_eq!(outcome.code, 0, "{}", outcome.stderr);
        assert!(!outcome.stdout.contains('\u{1b}') && !outcome.stdout.contains('\u{7}'));
        assert!(outcome.stdout.contains("\\u{1b}[31m\\nforged: line"));
        assert!(outcome.stdout.contains("9.9\\u{7}"));
        assert_eq!(
            outcome
                .stdout
                .lines()
                .filter(|line| line.starts_with("forged"))
                .count(),
            0
        );
    }

    #[test]
    fn the_approver_is_the_unix_user_with_unsafe_characters_replaced() {
        let env = |value: Option<&'static str>| {
            move |name: &str| {
                (name == "USER")
                    .then(|| value.map(OsString::from))
                    .flatten()
            }
        };
        assert_eq!(approver_from_env(&env(Some("roman"))), "cli:roman");
        assert_eq!(approver_from_env(&env(Some("a b:ü"))), "cli:a_b__");
        assert_eq!(approver_from_env(&env(Some(""))), "cli:unknown");
        assert_eq!(approver_from_env(&env(None)), "cli:unknown");
    }

    #[test]
    fn timestamps_are_rendered_as_utc() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(NOW), "2023-11-14T22:13:20Z");
        assert_eq!(format_utc(-1), "1969-12-31T23:59:59Z");
    }
}
