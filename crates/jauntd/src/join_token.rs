use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use jaunt_audit::{AuditTap, system_clock as audit_clock};
use jaunt_control::{
    Clock, CreatedJoinToken, JoinTokenAdmin, JoinTokenError, JoinTokenRequest, LabelError, Labels,
    MAX_JOIN_TOKEN_TTL, system_clock,
};
use jaunt_store::{JoinToken, NameScope, Store, StoreError};

use crate::audit::{self, AuditStartError, Surface};
use crate::config;
use crate::logging;
use crate::node::{Terminal, approver_from_env, format_utc, printable};

const DATABASE_FILE: &str = "jaunt.db";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const MAX_TTL_TEXT_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinTokenAction {
    Create(CreateOptions),
    List,
    Remove { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOptions {
    pub name: Option<String>,
    pub name_prefix: Option<String>,
    pub labels: Vec<String>,
    pub uses: u32,
    pub ttl: Duration,
    pub allow_replace: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TtlError {
    #[error("a duration is a whole number followed by s, m, h or d, for example 30m or 2d")]
    Malformed,
    #[error("a join token lives at least one second and at most seven days")]
    OutOfRange,
}

#[derive(Debug, thiserror::Error)]
enum JoinTokenCommandError {
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
    #[error(transparent)]
    Audit(#[from] AuditStartError),
    #[error("cannot write the output: {0}")]
    Output(#[source] io::Error),
    #[error("give exactly one of --name and --name-prefix")]
    Scope,
    #[error("invalid --label: {0}")]
    Labels(#[source] LabelError),
    #[error(transparent)]
    Token(#[from] JoinTokenError),
}

impl JoinTokenCommandError {
    fn exit_code(&self) -> u8 {
        match self {
            JoinTokenCommandError::Scope
            | JoinTokenCommandError::Labels(_)
            | JoinTokenCommandError::Token(
                JoinTokenError::InvalidName
                | JoinTokenError::InvalidPrefix
                | JoinTokenError::InvalidUses
                | JoinTokenError::InvalidTtl,
            ) => EXIT_USAGE,
            _ => EXIT_FAILED,
        }
    }
}

pub fn parse_ttl(text: &str) -> Result<Duration, TtlError> {
    if text.is_empty() || text.len() > MAX_TTL_TEXT_LEN {
        return Err(TtlError::Malformed);
    }
    let Some(unit) = text.chars().last() else {
        return Err(TtlError::Malformed);
    };
    let scale: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => return Err(TtlError::Malformed),
    };
    let digits = &text[..text.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(TtlError::Malformed);
    }
    let count: u64 = digits.parse().map_err(|_| TtlError::Malformed)?;
    let ttl = count
        .checked_mul(scale)
        .map(Duration::from_secs)
        .ok_or(TtlError::OutOfRange)?;
    if ttl.is_zero() || ttl > MAX_JOIN_TOKEN_TTL {
        return Err(TtlError::OutOfRange);
    }
    Ok(ttl)
}

pub fn run(config_path: &Path, action: JoinTokenAction) -> ExitCode {
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
    action: JoinTokenAction,
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

fn request_of(options: CreateOptions) -> Result<JoinTokenRequest, JoinTokenCommandError> {
    let scope = match (options.name, options.name_prefix) {
        (Some(name), None) => NameScope::Exact(name),
        (None, Some(prefix)) => NameScope::Prefix(prefix),
        _ => return Err(JoinTokenCommandError::Scope),
    };
    Ok(JoinTokenRequest {
        scope,
        labels: parse_labels(&options.labels).map_err(JoinTokenCommandError::Labels)?,
        uses: options.uses,
        ttl: options.ttl,
        allow_replace: options.allow_replace,
    })
}

fn parse_labels(assignments: &[String]) -> Result<Labels, LabelError> {
    if assignments
        .iter()
        .any(|assignment| assignment.is_empty() || assignment.contains(','))
    {
        return Err(LabelError::Malformed);
    }
    Labels::parse_assignments(&assignments.join(","))
}

enum Planned {
    Create(JoinTokenRequest),
    List,
    Remove(String),
}

fn attempt(
    config_path: &Path,
    action: JoinTokenAction,
    author: &str,
    clock: Clock,
    terminal: &mut Terminal<'_>,
    tap: &AuditTap,
) -> Result<(), JoinTokenCommandError> {
    let planned = match action {
        JoinTokenAction::Create(options) => Planned::Create(request_of(options)?),
        JoinTokenAction::List => Planned::List,
        JoinTokenAction::Remove { id } => Planned::Remove(id),
    };
    let config = config::load(config_path).map_err(JoinTokenCommandError::Config)?;
    let database = config.data_dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Err(JoinTokenCommandError::NoDatabase(database));
    }
    let audit_settings = if matches!(planned, Planned::List) {
        None
    } else {
        Some(
            config
                .audit
                .into_settings()
                .map_err(|err| JoinTokenCommandError::Config(err.to_string()))?,
        )
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(JoinTokenCommandError::Runtime)?;
    let outcome = runtime.block_on(async {
        let store = Store::open(&database)
            .await
            .map_err(|source| JoinTokenCommandError::Open {
                path: database.clone(),
                source,
            })?;
        store
            .migrate()
            .await
            .map_err(JoinTokenCommandError::Migrate)?;
        let audit = audit_settings
            .map(|settings| audit::start(&settings, Surface::Cli, &store, tap, audit_clock()))
            .transpose()?;
        let admin = JoinTokenAdmin::new(store, clock);
        let outcome = match planned {
            Planned::Create(request) => create(&admin, request, author, terminal).await,
            Planned::List => list(&admin, terminal).await,
            Planned::Remove(id) => remove(&admin, &id, author, terminal).await,
        };
        if let Some(audit) = audit {
            audit.shutdown(audit::FLUSH_DEADLINE).await;
        }
        outcome
    });
    audit::finish_runtime(runtime, audit::RUNTIME_GRACE);
    outcome
}

async fn create(
    admin: &JoinTokenAdmin,
    request: JoinTokenRequest,
    author: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), JoinTokenCommandError> {
    let CreatedJoinToken { secret, token } = admin.create(request, author).await?;
    let mut line = String::with_capacity(secret.expose().len() + 1);
    line.push_str(secret.expose());
    line.push('\n');
    terminal
        .stdout
        .write_all(line.as_bytes())
        .and_then(|()| terminal.stdout.flush())
        .map_err(JoinTokenCommandError::Output)?;
    let summary = format!(
        "created join token {} for {}; {} {}; labels {}; expires at {}{}\n\
         the token above is shown only this once: put it in a file with mode 0600 owned by the \
         agent's user and run `jaunt-agent enroll --token-file <file>`\n",
        printable(&token.id),
        describe_scope(&token.scope),
        token.max_uses,
        if token.max_uses == 1 { "use" } else { "uses" },
        or_dash(&labels_text(&token)),
        format_utc(token.expires_at),
        if token.allow_replace {
            "; may replace an active node with the same name"
        } else {
            ""
        },
    );
    terminal
        .stderr
        .write_all(summary.as_bytes())
        .and_then(|()| terminal.stderr.flush())
        .map_err(JoinTokenCommandError::Output)
}

async fn list(
    admin: &JoinTokenAdmin,
    terminal: &mut Terminal<'_>,
) -> Result<(), JoinTokenCommandError> {
    let tokens = admin.list().await?;
    say(terminal, &render(&tokens))
}

async fn remove(
    admin: &JoinTokenAdmin,
    id: &str,
    author: &str,
    terminal: &mut Terminal<'_>,
) -> Result<(), JoinTokenCommandError> {
    let revoked = admin.revoke(id, author).await?;
    say(
        terminal,
        &format!(
            "revoked join token {} ({} of {} uses were left)\n",
            printable(&revoked.id),
            revoked.uses_left,
            revoked.max_uses
        ),
    )
}

fn describe_scope(scope: &NameScope) -> String {
    match scope {
        NameScope::Exact(name) => format!("the node name {}", printable(name)),
        NameScope::Prefix(prefix) => format!("node names starting with {}", printable(prefix)),
    }
}

fn scope_cell(scope: &NameScope) -> String {
    match scope {
        NameScope::Exact(name) => printable(name),
        NameScope::Prefix(prefix) => format!("{}*", printable(prefix)),
    }
}

fn labels_text(token: &JoinToken) -> String {
    let pairs: Vec<String> = token
        .labels
        .iter()
        .map(|(key, value)| format!("{}={}", printable(key), printable(value)))
        .collect();
    pairs.join(",")
}

fn or_dash(text: &str) -> String {
    if text.is_empty() {
        "-".to_owned()
    } else {
        text.to_owned()
    }
}

fn render(tokens: &[JoinToken]) -> String {
    let mut rows = vec![[
        "ID".to_owned(),
        "NAME".to_owned(),
        "LABELS".to_owned(),
        "USES".to_owned(),
        "EXPIRES".to_owned(),
        "REVOKED".to_owned(),
        "REPLACE".to_owned(),
    ]];
    for token in tokens {
        rows.push([
            printable(&token.id),
            scope_cell(&token.scope),
            or_dash(&labels_text(token)),
            format!("{}/{}", token.uses_left, token.max_uses),
            format_utc(token.expires_at),
            token.revoked_at.map_or_else(|| "-".to_owned(), format_utc),
            if token.allow_replace { "yes" } else { "no" }.to_owned(),
        ]);
    }
    let mut widths = [0_usize; 7];
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

fn say(terminal: &mut Terminal<'_>, text: &str) -> Result<(), JoinTokenCommandError> {
    terminal
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| terminal.stdout.flush())
        .map_err(JoinTokenCommandError::Output)
}

#[cfg(test)]
mod tests;
