use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jaunt_proto::{FinishRequest, StartRequest};
use url::Url;

use crate::agent::{AgentError, SshAgent};
use crate::browser::BrowserOpener;
use crate::client::{ApiClient, ApiError, TOTAL_TIMEOUT};
use crate::consent::ConsentPrompt;
use crate::display::format_local;
use crate::issued::{VerifyError, verify};
use crate::key::{KeyError, SessionKey};
use crate::lock::{LockError, ProfileLock};
use crate::loopback::{Callback, FailureCode, LoopbackError, LoopbackListener};
use crate::pkce::{EntropyError, Pkce};
use crate::profile::ProfileName;
use crate::server_url::{ServerUrl, check_web_url};
use crate::ssh_config::{
    EnsureCommand, SshConfigError, check_ensure_command, check_profile_dir, render_known_hosts,
    render_ssh_config, validate,
};
use crate::ssh_include::{IncludeOutcome, IncludeTarget, ensure_include};
use crate::store::{LoginFiles, ProfileStore, SshFiles, StoreError, Transaction};

const CHALLENGE_METHOD: &str = "S256";
const MAX_LABEL_LEN: usize = 64;
const UNKNOWN_HOST: &str = "unknown";
const MIN_CALL_AFTER_APPROVAL: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    #[error(transparent)]
    Loopback(#[from] LoopbackError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("the server sent a sign-in address that cannot be used safely")]
    BadAuthorizeUrl,
    #[error("sign-in was denied")]
    Denied,
    #[error("sign-in failed")]
    Failed,
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(
        "cannot fetch the SSH settings from the server: {source}; sign in with --no-ssh-config to skip them"
    )]
    ClientConfig { source: ApiError },
    #[error(
        "the SSH settings from the server were refused: {0}; sign in with --no-ssh-config to skip them"
    )]
    SshSettings(#[from] SshConfigError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the system clock is set before 1970")]
    Clock,
    #[error("cannot write to the terminal: {0}")]
    Terminal(io::Error),
    #[error("cannot ask for confirmation: {0}")]
    Consent(io::Error),
    #[error(transparent)]
    Lock(#[from] LockError),
    #[error("the held lock belongs to another profile")]
    ForeignLock,
    #[error("{0}; sign in with --no-ssh-config to skip the SSH setup")]
    UnsafeCommand(SshConfigError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshSetup {
    pub include: IncludeTarget,
    pub program: PathBuf,
    pub ensure_home: Option<PathBuf>,
}

pub struct LoginOptions {
    pub server: ServerUrl,
    pub profile: ProfileName,
    pub home: PathBuf,
    pub no_browser: bool,
    pub timeout: Duration,
    pub ssh: Option<SshSetup>,
    pub accept_ssh_config: bool,
}

pub struct LoginPorts<'a> {
    pub browser: &'a dyn BrowserOpener,
    pub agent: &'a SshAgent,
    pub clock: &'a dyn Fn() -> SystemTime,
    pub notices: &'a mut dyn Write,
    pub consent: &'a dyn ConsentPrompt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPlacement {
    Agent,
    Disk { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginReport {
    pub email: String,
    pub serial: i64,
    pub valid_before: i64,
    pub placement: KeyPlacement,
    pub notes: Vec<String>,
}

impl LoginReport {
    pub fn summary(&self) -> String {
        format!(
            "Signed in as {}; certificate valid until {} (serial {}).",
            crate::display::printable(&self.email),
            format_local(self.valid_before),
            self.serial
        )
    }

    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if let KeyPlacement::Disk { path, reason } = &self.placement {
            warnings.push(format!(
                "warning: the private key is stored on disk at {} (mode 0600) because {reason}",
                path.display()
            ));
        }
        warnings.extend(self.notes.iter().cloned());
        warnings
    }
}

pub fn client_label() -> String {
    let host = hostname::get()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    label_for(&host)
}

fn label_for(host: &str) -> String {
    let suffix = format!(" (jaunt {})", env!("CARGO_PKG_VERSION"));
    let budget = MAX_LABEL_LEN.saturating_sub(suffix.len());
    let cleaned: String = host
        .chars()
        .map(|ch| if ch.is_ascii_graphic() { ch } else { '?' })
        .take(budget)
        .collect();
    if cleaned.is_empty() {
        format!("{UNKNOWN_HOST}{suffix}")
    } else {
        format!("{cleaned}{suffix}")
    }
}

fn unix_secs(now: SystemTime) -> Result<u64, LoginError> {
    now.duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| LoginError::Clock)
}

fn open_or_announce(
    no_browser: bool,
    url: &Url,
    ports: &mut LoginPorts<'_>,
) -> Result<(), LoginError> {
    let failure = if no_browser {
        None
    } else {
        match ports.browser.open(url) {
            Ok(()) => return Ok(()),
            Err(err) => Some(err),
        }
    };
    if let Some(err) = failure {
        writeln!(ports.notices, "jaunt: cannot open a browser: {err}")
            .map_err(LoginError::Terminal)?;
    }
    writeln!(
        ports.notices,
        "Open this address in your browser to sign in:\n{url}"
    )
    .map_err(LoginError::Terminal)
}

pub fn lock_profile(
    home: &Path,
    profile: &ProfileName,
    deadline: Instant,
    notices: &mut dyn Write,
) -> Result<ProfileLock, LoginError> {
    let store = ProfileStore::new(home, profile);
    let mut notice_error = None;
    let acquired = ProfileLock::acquire(home, &store.lock_path(), deadline, &mut || {
        if let Err(err) = writeln!(
            notices,
            "jaunt: another sign-in for profile `{profile}` is in progress; waiting for it to finish"
        ) {
            notice_error = Some(err);
        }
    });
    if let Some(err) = notice_error {
        return Err(LoginError::Terminal(err));
    }
    Ok(acquired?)
}

fn ensure_command<'a>(setup: &'a SshSetup, profile: &'a ProfileName) -> EnsureCommand<'a> {
    EnsureCommand {
        program: &setup.program,
        home: setup.ensure_home.as_deref(),
        profile,
    }
}

fn check_ssh_paths(options: &LoginOptions, store: &ProfileStore) -> Result<(), LoginError> {
    if let Some(setup) = &options.ssh {
        check_profile_dir(store.dir())?;
        check_ensure_command(&ensure_command(setup, &options.profile))
            .map_err(LoginError::UnsafeCommand)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallBudget {
    Standard,
    WithinDeadline,
}

impl CallBudget {
    fn before_approval(self, deadline: Instant) -> Result<Duration, LoginError> {
        match self {
            CallBudget::Standard => Ok(TOTAL_TIMEOUT),
            CallBudget::WithinDeadline => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(LoopbackError::TimedOut.into());
                }
                Ok(remaining.min(TOTAL_TIMEOUT))
            }
        }
    }

    fn after_approval(self, deadline: Instant) -> Duration {
        match self {
            CallBudget::Standard => TOTAL_TIMEOUT,
            CallBudget::WithinDeadline => deadline
                .saturating_duration_since(Instant::now())
                .max(MIN_CALL_AFTER_APPROVAL)
                .min(TOTAL_TIMEOUT),
        }
    }
}

pub fn login(
    options: &LoginOptions,
    ports: &mut LoginPorts<'_>,
) -> Result<LoginReport, LoginError> {
    let store = ProfileStore::new(&options.home, &options.profile);
    check_ssh_paths(options, &store)?;
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .ok_or(LoopbackError::InvalidTimeout)?;
    let lock = lock_profile(&options.home, &options.profile, deadline, ports.notices)?;
    let outcome = signed_in(options, deadline, CallBudget::Standard, ports, &store);
    drop(lock);
    outcome
}

pub fn login_with_lock(
    options: &LoginOptions,
    ports: &mut LoginPorts<'_>,
    lock: &ProfileLock,
) -> Result<LoginReport, LoginError> {
    let store = ProfileStore::new(&options.home, &options.profile);
    if lock.path() != store.lock_path() {
        return Err(LoginError::ForeignLock);
    }
    check_ssh_paths(options, &store)?;
    let deadline = Instant::now()
        .checked_add(options.timeout)
        .ok_or(LoopbackError::InvalidTimeout)?;
    signed_in(options, deadline, CallBudget::WithinDeadline, ports, &store)
}

fn signed_in(
    options: &LoginOptions,
    deadline: Instant,
    calls: CallBudget,
    ports: &mut LoginPorts<'_>,
    store: &ProfileStore,
) -> Result<LoginReport, LoginError> {
    let key = SessionKey::generate(&options.profile)?;
    let pkce = Pkce::generate()?;
    let listener = LoopbackListener::bind()?;
    let client = ApiClient::new(&options.server)?.with_deadline(calls.before_approval(deadline)?);

    let started = client.start(&StartRequest {
        code_challenge: pkce.challenge().to_owned(),
        code_challenge_method: CHALLENGE_METHOD.to_owned(),
        redirect_port: u32::from(listener.port()),
        client_label: Some(client_label()),
    })?;
    let authorize =
        check_web_url(&started.authorize_url).map_err(|_| LoginError::BadAuthorizeUrl)?;
    open_or_announce(options.no_browser, &authorize, ports)?;

    let wait = deadline.saturating_duration_since(Instant::now());
    if wait.is_zero() {
        return Err(LoopbackError::TimedOut.into());
    }
    let completion = match listener.wait_for_callback(&started.login_id, wait)? {
        Callback::Approved(code) => code,
        Callback::Failed(FailureCode::AccessDenied) => return Err(LoginError::Denied),
        Callback::Failed(FailureCode::Other) => return Err(LoginError::Failed),
    };
    let client = client.with_deadline(calls.after_approval(deadline));
    let response = client.finish(&FinishRequest {
        login_id: started.login_id,
        code_verifier: pkce.verifier().expose().to_owned(),
        completion_code: Some(completion.expose().to_owned()),
        public_key: key.public_line().to_owned(),
    })?;

    let clock_now = (ports.clock)();
    let now = unix_secs(clock_now)?;
    let verified = verify(response, &key, now)?;
    let lifetime = u64::try_from(verified.meta.valid_before)
        .ok()
        .and_then(|before| before.checked_sub(now))
        .filter(|secs| *secs > 0)
        .ok_or(VerifyError::Expired)?;

    let mut notes = Vec::new();
    let ssh = match &options.ssh {
        Some(setup) => prepare_ssh(
            &client.with_deadline(calls.after_approval(deadline)),
            store,
            &ensure_command(setup, &options.profile),
            ports.consent,
            options.accept_ssh_config,
            &mut notes,
        )?,
        None => None,
    };
    let had_ssh_files = store.has_any_ssh_file()?;
    let mut transaction = store.begin(
        &LoginFiles {
            server: &options.server,
            public_key_line: key.public_line(),
            certificate_line: &verified.certificate_line,
            token: &verified.token,
            meta: &verified.meta,
            ssh: ssh.as_ref(),
        },
        clock_now,
    )?;
    if let Some(err) = transaction.sweep_warning() {
        notes.push(format!(
            "warning: stale files of an earlier sign-in were not removed: {err}"
        ));
    }
    let staged = match place_key(&transaction, &key, ports.agent, lifetime) {
        Ok(staged) => staged,
        Err(failure) => {
            if failure.agent_may_hold_key {
                forget_new_key(&transaction, ports);
            }
            return Err(failure.error);
        }
    };
    let retired = match transaction.commit() {
        Ok(retired) => retired,
        Err(err) => {
            if staged.agent_may_hold_key() {
                forget_new_key(&transaction, ports);
            }
            return Err(err.into());
        }
    };

    if let Some(retired) = retired {
        let old_public_key = retired.public_key_path();
        if ports.agent.is_configured()
            && old_public_key.exists()
            && let Err(err) = ports.agent.remove(&old_public_key)
        {
            notes.push(format!(
                "warning: the previous key may still be loaded in ssh-agent: {err}"
            ));
        }
        if let Err(err) = retired.discard() {
            notes.push(format!(
                "warning: the previous profile files were not fully removed: {err}"
            ));
        }
    }
    if ssh.is_none() && had_ssh_files {
        notes.push("warning: the previous SSH setup of this profile was removed".to_owned());
    }
    if let Err(err) = store.clear_failure_marker() {
        notes.push(format!(
            "warning: the record of an earlier failed sign-in was not removed: {err}"
        ));
    }
    if let (Some(files), Some(setup)) = (&ssh, &options.ssh) {
        let scope = format!(
            "*.{} through {}:{}",
            files.client.ssh_suffix, files.client.gate.host, files.client.gate.port
        );
        notes.push(include_note(
            &scope,
            &setup.include,
            ensure_include(&setup.include),
        ));
    }
    let placement = match staged {
        StagedKey::Agent => KeyPlacement::Agent,
        StagedKey::Disk { reason, .. } => KeyPlacement::Disk {
            path: store.private_key_path(),
            reason,
        },
    };

    Ok(LoginReport {
        email: verified.meta.email,
        serial: verified.meta.serial,
        valid_before: verified.meta.valid_before,
        placement,
        notes,
    })
}

fn prepare_ssh(
    client: &ApiClient,
    store: &ProfileStore,
    command: &EnsureCommand<'_>,
    consent: &dyn ConsentPrompt,
    accept: bool,
    notes: &mut Vec<String>,
) -> Result<Option<SshFiles>, LoginError> {
    let fetched = match client.client_config() {
        Ok(fetched) => fetched,
        Err(ApiError::NotConfigured) => {
            notes.push(
                "warning: the server has no SSH gateway configured yet; the SSH setup was skipped"
                    .to_owned(),
            );
            return Ok(None);
        }
        Err(source) => return Err(LoginError::ClientConfig { source }),
    };
    let client_config = validate(fetched)?;
    let scope = format!(
        "*.{} through {}:{}",
        client_config.ssh_suffix, client_config.gate.host, client_config.gate.port
    );
    let known = store
        .read_client_config()
        .ok()
        .flatten()
        .is_some_and(|previous| {
            previous.ssh_suffix == client_config.ssh_suffix && previous.gate == client_config.gate
        });
    if !known && !accept {
        if !consent.interactive() {
            notes.push(format!(
                "warning: the server wants to manage ssh for {scope}; the SSH setup was skipped: run `jaunt login --accept-ssh-config` to enable it"
            ));
            return Ok(None);
        }
        let question = format!(
            "This server will manage ssh for *.{} through {}:{}. Configure ssh? [y/N]",
            client_config.ssh_suffix, client_config.gate.host, client_config.gate.port
        );
        if !consent.confirm(&question).map_err(LoginError::Consent)? {
            notes.push(format!(
                "warning: the SSH setup for {scope} was declined: run `jaunt login --accept-ssh-config` to enable it"
            ));
            return Ok(None);
        }
    }
    let ssh_config = render_ssh_config(&client_config, store.dir(), command)?;
    let known_hosts = render_known_hosts(&client_config);
    Ok(Some(SshFiles {
        client: client_config,
        ssh_config,
        known_hosts,
    }))
}

fn include_note(
    scope: &str,
    target: &IncludeTarget,
    outcome: Result<IncludeOutcome, crate::ssh_include::IncludeError>,
) -> String {
    match outcome {
        Ok(IncludeOutcome::Unchanged) => format!(
            "SSH setup is ready for {scope}: {} already includes the profile",
            target.config_path.display()
        ),
        Ok(IncludeOutcome::Created) => format!(
            "SSH setup is ready for {scope}: created {} with `{}`",
            target.config_path.display(),
            target.line
        ),
        Ok(IncludeOutcome::Added { backup }) => format!(
            "SSH setup is ready for {scope}: added `{}` to the top of {} (the previous file is saved as {})",
            target.line,
            target.config_path.display(),
            backup.display()
        ),
        Err(err) => format!(
            "warning: the SSH files are in place but {} was not updated: {err}",
            target.config_path.display()
        ),
    }
}

enum StagedKey {
    Agent,
    Disk {
        reason: String,
        agent_may_hold_key: bool,
    },
}

impl StagedKey {
    fn agent_may_hold_key(&self) -> bool {
        match self {
            StagedKey::Agent => true,
            StagedKey::Disk {
                agent_may_hold_key, ..
            } => *agent_may_hold_key,
        }
    }
}

struct PlacementFailure {
    error: LoginError,
    agent_may_hold_key: bool,
}

fn forget_new_key(transaction: &Transaction, ports: &mut LoginPorts<'_>) {
    if let Err(removal) = ports.agent.remove(&transaction.public_key_path()) {
        drop(writeln!(
            ports.notices,
            "jaunt: warning: the new key may still be loaded in ssh-agent: {removal}"
        ));
    }
}

fn place_key(
    transaction: &Transaction,
    key: &SessionKey,
    agent: &SshAgent,
    lifetime_secs: u64,
) -> Result<StagedKey, PlacementFailure> {
    let pem = key.private_openssh().map_err(|err| PlacementFailure {
        error: err.into(),
        agent_may_hold_key: false,
    })?;
    let (reason, agent_may_hold_key) = if agent.is_configured() {
        match agent.add(&pem, lifetime_secs) {
            Ok(()) => return Ok(StagedKey::Agent),
            Err(err) => {
                let ambiguous = matches!(err, AgentError::TimedOut | AgentError::Io(_));
                (err.to_string(), ambiguous)
            }
        }
    } else {
        (AgentError::NotRunning.to_string(), false)
    };
    transaction
        .write_private_key(&pem)
        .map_err(|err| PlacementFailure {
            error: err.into(),
            agent_may_hold_key,
        })?;
    Ok(StagedKey::Disk {
        reason,
        agent_may_hold_key,
    })
}

#[cfg(test)]
mod tests {
    use super::label_for;

    #[test]
    fn the_client_label_is_printable_ascii_within_sixty_four_characters() {
        let plain = label_for("laptop");
        assert_eq!(
            plain,
            format!("laptop (jaunt {})", env!("CARGO_PKG_VERSION"))
        );
        for host in ["", "é", "a b\n", &"h".repeat(200)] {
            let label = label_for(host);
            assert!((1..=64).contains(&label.len()), "{label}");
            assert!(
                label.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
                "{label}"
            );
            assert!(label.ends_with(&format!(" (jaunt {})", env!("CARGO_PKG_VERSION"))));
        }
        assert!(label_for("").starts_with("unknown "));
    }
}
