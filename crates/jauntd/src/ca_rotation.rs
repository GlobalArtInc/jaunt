use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::UNIX_EPOCH;

use jaunt_audit::{AuditTap, system_clock as audit_clock};
use jaunt_ca::ssh_key::{Fingerprint, HashAlg};
use jaunt_ca::{CaError, CaKind, CaLock, FileBackend, TrustSet, fingerprint_hex};
use jaunt_control::ca_rotation::{
    self, Counters, RotationKind, RotationStep, SlotReport, Summary, Unexpired, Verdict,
};
use jaunt_control::{Clock, system_clock};
use jaunt_store::{Store, StoreError};

use crate::audit::{self, AuditSettings, AuditStartError, Surface};
use crate::ca::{CA_DIR, resolve_identity};
use crate::config::{self, EnvLookup};
use crate::logging;
use crate::node::{approver_from_env, format_utc, printable};

const DATABASE_FILE: &str = "jaunt.db";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_BLOCKED: u8 = 3;
pub(crate) const LAST_LINE: &str = "applied within 10 s";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAction {
    Status { json: bool },
    Change { kind: CaKind, step: ChangeStep },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeStep {
    AddNext,
    Promote { force: bool },
    Retire { force: bool },
}

pub struct Streams<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

pub struct Context<'a> {
    pub operator: &'a str,
    pub clock: Clock,
    pub env: EnvLookup<'a>,
    pub tap: &'a AuditTap,
}

#[derive(Debug, thiserror::Error)]
enum RotationError {
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
    #[error("cannot read the rotation counters: {0}")]
    Counters(#[source] StoreError),
    #[error("cannot start the audit pipeline: {0}")]
    Audit(#[from] AuditStartError),
    #[error("cannot write the output: {0}")]
    Output(#[source] io::Error),
    #[error("{0}")]
    Identity(String),
    #[error("the clock is before 1970")]
    Clock,
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error("{0}; the key change took effect anyway, check `jauntd ca status`")]
    AppliedWithError(#[source] CaError),
    #[error("{error}; the keys could not be read back ({check}), check `jauntd ca status`")]
    Unverified {
        #[source]
        error: CaError,
        check: CaError,
    },
}

struct AfterFailure {
    trust: TrustSet,
    error: CaError,
}

pub fn run(config_path: &Path, action: RotationAction) -> ExitCode {
    let env = |name: &str| std::env::var_os(name);
    let tap = AuditTap::new(audit_clock());
    if let Err(err) = logging::init(&env, &tap) {
        eprintln!("{err}");
        return ExitCode::from(EXIT_FAILED);
    }
    let operator = approver_from_env(&env);
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = execute(
        config_path,
        action,
        &Context {
            operator: &operator,
            clock: system_clock(),
            env: &env,
            tap: &tap,
        },
        &mut Streams {
            stdout: &mut stdout,
            stderr: &mut stderr,
        },
    );
    ExitCode::from(code)
}

pub fn execute(
    config_path: &Path,
    action: RotationAction,
    context: &Context<'_>,
    streams: &mut Streams<'_>,
) -> u8 {
    match attempt(config_path, action, context, streams) {
        Ok(code) => code,
        Err(err) => {
            if writeln!(streams.stderr, "{err}").is_err() {
                return EXIT_FAILED;
            }
            EXIT_FAILED
        }
    }
}

fn attempt(
    config_path: &Path,
    action: RotationAction,
    context: &Context<'_>,
    streams: &mut Streams<'_>,
) -> Result<u8, RotationError> {
    let change = match action {
        RotationAction::Status { .. } => None,
        RotationAction::Change { kind, step } => Some((rotation_kind(kind)?, step)),
    };
    let config = config::load(config_path).map_err(RotationError::Config)?;
    let ca_dir = config.data_dir.join(CA_DIR);
    let database = config.data_dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Err(RotationError::NoDatabase(database));
    }
    let audit_settings = change
        .map(|_| config.audit.into_settings())
        .transpose()
        .map_err(|err| RotationError::Config(err.to_string()))?;
    let now = unix_now(&context.clock)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(RotationError::Runtime)?;
    let outcome = runtime.block_on(async {
        let store = Store::open(&database)
            .await
            .map_err(|source| RotationError::Open {
                path: database.clone(),
                source,
            })?;
        store.migrate().await.map_err(RotationError::Migrate)?;
        match change.zip(audit_settings) {
            Some(((kind, step), settings)) => {
                let target = Target {
                    store: &store,
                    ca_dir: &ca_dir,
                    kind,
                    now,
                };
                apply(&target, step, &settings, context, streams).await
            }
            None => {
                let json = matches!(action, RotationAction::Status { json: true });
                status(&store, &ca_dir, now, json, streams).await
            }
        }
    });
    audit::finish_runtime(runtime, audit::RUNTIME_GRACE);
    outcome
}

struct Target<'a> {
    store: &'a Store,
    ca_dir: &'a Path,
    kind: RotationKind,
    now: i64,
}

async fn apply(
    target: &Target<'_>,
    step: ChangeStep,
    settings: &AuditSettings,
    context: &Context<'_>,
    streams: &mut Streams<'_>,
) -> Result<u8, RotationError> {
    let ca_kind = target.kind.ca_kind();
    if !FileBackend::is_initialized(target.ca_dir, ca_kind)? {
        return Err(CaError::NotInitialized(ca_kind).into());
    }
    let lock = CaLock::acquire(target.ca_dir)?;
    let audit = audit::start(
        settings,
        Surface::Cli,
        target.store,
        context.tap,
        audit_clock(),
    )?;
    let change = Change {
        store: target.store,
        lock: &lock,
        kind: target.kind,
        context,
        now: target.now,
    };
    let outcome = match step {
        ChangeStep::AddNext => change.add_next(streams),
        ChangeStep::Promote { force } => change.promote(force, streams).await,
        ChangeStep::Retire { force } => change.retire(force, streams).await,
    };
    audit.shutdown(audit::FLUSH_DEADLINE).await;
    drop(lock);
    outcome
}

fn rotation_kind(kind: CaKind) -> Result<RotationKind, CaError> {
    match kind {
        CaKind::User => Ok(RotationKind::User),
        CaKind::Host => Ok(RotationKind::Host),
        CaKind::Internal => Err(CaError::RotationUnsupported(kind)),
    }
}

fn unix_now(clock: &Clock) -> Result<i64, RotationError> {
    let secs = clock()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RotationError::Clock)?
        .as_secs();
    i64::try_from(secs).map_err(|_| RotationError::Clock)
}

struct Change<'a> {
    store: &'a Store,
    lock: &'a CaLock,
    kind: RotationKind,
    context: &'a Context<'a>,
    now: i64,
}

impl Change<'_> {
    fn add_next(&self, streams: &mut Streams<'_>) -> Result<u8, RotationError> {
        let identity = resolve_identity(self.lock.root(), self.context.env)
            .map_err(RotationError::Identity)?;
        let had_next = self.read_back()?.next().is_some();
        let fp = match FileBackend::add_next(self.lock, self.kind.ca_kind(), &identity) {
            Ok(key) => fingerprint_hex(&key),
            Err(error) => {
                let after = self.read_back_after(error)?;
                return match after.trust.next().filter(|_| !had_next) {
                    Some(next) => {
                        self.audit_added(&fingerprint_hex(next));
                        Err(RotationError::AppliedWithError(after.error))
                    }
                    None => Err(after.error.into()),
                };
            }
        };
        self.audit_added(&fp);
        say(
            streams,
            &format!(
                "{} key {fp} added as next\n{LAST_LINE}\n",
                self.kind.as_str()
            ),
        )?;
        Ok(EXIT_OK)
    }

    async fn promote(&self, force: bool, streams: &mut Streams<'_>) -> Result<u8, RotationError> {
        let ca_kind = self.kind.ca_kind();
        let identity = resolve_identity(self.lock.root(), self.context.env)
            .map_err(RotationError::Identity)?;
        let (trust, _) = FileBackend::load_with_next(self.lock.root(), ca_kind, &identity)?;
        let next = trust.next().ok_or(CaError::NoNextKey(ca_kind))?;
        if trust.previous().next().is_some() {
            return Err(CaError::PreviousKeyPresent(ca_kind).into());
        }
        let counters = self.counters(&trust).await?;
        let verdict = ca_rotation::verdict(self.kind, RotationStep::Promote, &counters, self.now);
        let Some(blocked) = self.gate(&verdict, RotationStep::Promote, force, streams)? else {
            return Ok(EXIT_BLOCKED);
        };
        let summary = ca_rotation::summarize(self.kind, &counters, self.now);
        let (nodes_behind, old_unexpired) = match self.kind {
            RotationKind::User => (Some(count(summary.nodes_behind.len())), None),
            RotationKind::Host => (None, Some(summary.old_host_trust.count)),
        };
        let fp = fingerprint_hex(next);
        let audit = || {
            tracing::info!(
                target: "jaunt::audit",
                event = "ca.key.promoted",
                kind = self.kind.as_str(),
                fp = fp.as_str(),
                forced = force,
                blocked,
                nodes_behind,
                old_unexpired,
                changed_by = self.context.operator
            );
        };
        let fingerprint = next.fingerprint(HashAlg::Sha256);
        let promoted = match FileBackend::promote(self.lock, ca_kind, &identity, &fingerprint) {
            Ok(promoted) => promoted,
            Err(error) => {
                let after = self.read_back_after(error)?;
                if fingerprint_hex(after.trust.active()) == fp {
                    audit();
                    return Err(RotationError::AppliedWithError(after.error));
                }
                return Err(after.error.into());
            }
        };
        audit();
        say(
            streams,
            &format!(
                "{} key {fp} is active, {} is previous\n{LAST_LINE}\n",
                self.kind.as_str(),
                fingerprint_hex(&promoted.previous)
            ),
        )?;
        Ok(EXIT_OK)
    }

    async fn retire(&self, force: bool, streams: &mut Streams<'_>) -> Result<u8, RotationError> {
        let ca_kind = self.kind.ca_kind();
        let finished = FileBackend::finish_retired(self.lock, ca_kind)?;
        for fp in &finished {
            self.audit_retired(fp, false, false, &Summary::default());
            say(
                streams,
                &format!(
                    "{} key {fp} was already out of the trust set: removed the private key an interrupted retire left behind\n",
                    self.kind.as_str()
                ),
            )?;
        }
        let trust = self.read_back()?;
        let previous: Vec<Fingerprint> = trust
            .previous()
            .map(|key| key.fingerprint(HashAlg::Sha256))
            .collect();
        if previous.is_empty() {
            if finished.is_empty() {
                return Err(CaError::NoPreviousKey(ca_kind).into());
            }
            say(streams, &format!("{LAST_LINE}\n"))?;
            return Ok(EXIT_OK);
        }
        let counters = self.counters(&trust).await?;
        let verdict = ca_rotation::verdict(self.kind, RotationStep::Retire, &counters, self.now);
        let Some(blocked) = self.gate(&verdict, RotationStep::Retire, force, streams)? else {
            return Ok(EXIT_BLOCKED);
        };
        let summary = ca_rotation::summarize(self.kind, &counters, self.now);
        if let Err(error) = FileBackend::retire(self.lock, ca_kind, &previous) {
            let after = self.read_back_after(error)?;
            let gone: Vec<&Fingerprint> = previous
                .iter()
                .filter(|fingerprint| !after.trust.contains(fingerprint))
                .collect();
            for fingerprint in &gone {
                self.audit_retired(&hex(fingerprint), force, blocked, &summary);
            }
            return Err(if gone.is_empty() {
                after.error.into()
            } else {
                RotationError::AppliedWithError(after.error)
            });
        }
        for fingerprint in &previous {
            let fp = hex(fingerprint);
            self.audit_retired(&fp, force, blocked, &summary);
            say(
                streams,
                &format!("{} key {fp} retired\n", self.kind.as_str()),
            )?;
        }
        say(streams, &format!("{LAST_LINE}\n"))?;
        Ok(EXIT_OK)
    }

    fn read_back(&self) -> Result<TrustSet, RotationError> {
        Ok(FileBackend::read_slot(self.lock.root(), self.kind.ca_kind())?.trust)
    }

    fn read_back_after(&self, error: CaError) -> Result<AfterFailure, RotationError> {
        match FileBackend::read_slot(self.lock.root(), self.kind.ca_kind()) {
            Ok(listing) => Ok(AfterFailure {
                trust: listing.trust,
                error,
            }),
            Err(check) => Err(RotationError::Unverified { error, check }),
        }
    }

    fn audit_added(&self, fp: &str) {
        tracing::info!(
            target: "jaunt::audit",
            event = "ca.key.added",
            kind = self.kind.as_str(),
            fp,
            changed_by = self.context.operator
        );
    }

    fn audit_retired(&self, fp: &str, forced: bool, blocked: bool, summary: &Summary) {
        let (old_unexpired, nodes_old) = match self.kind {
            RotationKind::User => (Some(summary.old_certificates.count), None),
            RotationKind::Host => (None, Some(count(summary.nodes_on_old_host_key.len()))),
        };
        tracing::info!(
            target: "jaunt::audit",
            event = "ca.key.retired",
            kind = self.kind.as_str(),
            fp,
            forced,
            blocked,
            old_unexpired,
            nodes_old,
            changed_by = self.context.operator
        );
    }

    async fn counters(&self, trust: &TrustSet) -> Result<Counters, RotationError> {
        ca_rotation::gather(self.store, self.kind, trust, self.now)
            .await
            .map_err(RotationError::Counters)
    }

    fn gate(
        &self,
        verdict: &Verdict,
        step: RotationStep,
        force: bool,
        streams: &mut Streams<'_>,
    ) -> Result<Option<bool>, RotationError> {
        say(streams, &format!("{}\n", verdict.line(step)))?;
        if verdict.is_allowed() {
            return Ok(Some(false));
        }
        if !force {
            writeln!(
                streams.stderr,
                "the {} check blocks this step, so it was not applied; --force skips the check and is audited",
                step.as_str()
            )
            .map_err(RotationError::Output)?;
            return Ok(None);
        }
        say(streams, "forced past the check\n")?;
        Ok(Some(true))
    }
}

fn hex(fingerprint: &Fingerprint) -> String {
    fingerprint
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn count(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn say(streams: &mut Streams<'_>, text: &str) -> Result<(), RotationError> {
    streams
        .stdout
        .write_all(text.as_bytes())
        .and_then(|()| streams.stdout.flush())
        .map_err(RotationError::Output)
}

async fn status(
    store: &Store,
    ca_dir: &Path,
    now: i64,
    json: bool,
    streams: &mut Streams<'_>,
) -> Result<u8, RotationError> {
    let listings = ca_rotation::read_listings(ca_dir)?;
    let reports = ca_rotation::reports(store, listings, now)
        .await
        .map_err(RotationError::Counters)?;
    let text = if json {
        let mut text = ca_rotation::status_json(&reports).to_string();
        text.push('\n');
        text
    } else {
        render_text(&reports)
    };
    say(streams, &text)?;
    Ok(EXIT_OK)
}

fn render_text(reports: &[SlotReport]) -> String {
    let mut text = String::new();
    for report in reports {
        text.push_str(report.kind.as_str());
        text.push('\n');
        for (state, fp) in ca_rotation::ordered_keys(&report.listing) {
            text.push_str(&format!("  {state:<9} {fp}\n"));
        }
        text.push_str(&format!("  trust id  {}\n", report.listing.trust.set_id()));
        let summary = &report.summary;
        match report.kind {
            RotationKind::User => {
                text.push_str(&format!(
                    "  nodes     {} current, {} behind, {} offline\n",
                    summary.nodes_current,
                    summary.nodes_behind.len(),
                    summary.nodes_offline.len()
                ));
                if !summary.nodes_behind.is_empty() {
                    text.push_str(&format!("  behind    {}\n", listed(&summary.nodes_behind)));
                }
                if !summary.nodes_offline.is_empty() {
                    text.push_str(&format!("  offline   {}\n", listed(&summary.nodes_offline)));
                }
                text.push_str(&format!(
                    "  certificates on previous keys or untracked: {}\n",
                    unexpired_text(&summary.old_certificates)
                ));
            }
            RotationKind::Host => {
                text.push_str(&format!(
                    "  user certificates with an older host trust or untracked: {}\n",
                    unexpired_text(&summary.old_host_trust)
                ));
                text.push_str(&format!(
                    "  nodes on previous host keys or untracked: {}",
                    summary.nodes_on_old_host_key.len()
                ));
                if !summary.nodes_on_old_host_key.is_empty() {
                    text.push_str(&format!(" ({})", listed(&summary.nodes_on_old_host_key)));
                }
                text.push('\n');
            }
        }
        for step in &report.steps {
            text.push_str(&format!("  {}\n", step.line));
        }
    }
    text
}

fn unexpired_text(unexpired: &Unexpired) -> String {
    match (
        unexpired.nearest_valid_before,
        unexpired.farthest_valid_before,
    ) {
        (Some(nearest), Some(farthest)) if unexpired.count > 0 => format!(
            "{}, expiring {} to {}",
            unexpired.count,
            format_utc(nearest),
            format_utc(farthest)
        ),
        _ => unexpired.count.to_string(),
    }
}

fn listed(names: &[String]) -> String {
    let mut shown: Vec<String> = names
        .iter()
        .take(ca_rotation::MAX_LISTED_NODES)
        .map(|name| printable(name))
        .collect();
    if names.len() > ca_rotation::MAX_LISTED_NODES {
        shown.push("…".to_owned());
    }
    shown.join(", ")
}

#[cfg(test)]
mod tests;
