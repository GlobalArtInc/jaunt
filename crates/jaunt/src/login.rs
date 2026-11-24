use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_proto::{FinishRequest, StartRequest};
use url::Url;

use crate::agent::{AgentError, SshAgent};
use crate::browser::BrowserOpener;
use crate::client::{ApiClient, ApiError};
use crate::display::format_local;
use crate::issued::{VerifyError, verify};
use crate::key::{KeyError, SessionKey};
use crate::loopback::{Callback, FailureCode, LoopbackError, LoopbackListener};
use crate::pkce::{EntropyError, Pkce};
use crate::profile::ProfileName;
use crate::server_url::{ServerUrl, check_web_url};
use crate::store::{LoginFiles, ProfileStore, StoreError, Transaction};

const CHALLENGE_METHOD: &str = "S256";
const MAX_LABEL_LEN: usize = 64;
const UNKNOWN_HOST: &str = "unknown";

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
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the system clock is set before 1970")]
    Clock,
    #[error("cannot write to the terminal: {0}")]
    Terminal(io::Error),
}

pub struct LoginOptions {
    pub server: ServerUrl,
    pub profile: ProfileName,
    pub home: PathBuf,
    pub no_browser: bool,
    pub timeout: Duration,
}

pub struct LoginPorts<'a> {
    pub browser: &'a dyn BrowserOpener,
    pub agent: &'a SshAgent,
    pub clock: &'a dyn Fn() -> SystemTime,
    pub notices: &'a mut dyn Write,
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

pub fn login(
    options: &LoginOptions,
    ports: &mut LoginPorts<'_>,
) -> Result<LoginReport, LoginError> {
    let key = SessionKey::generate(&options.profile)?;
    let pkce = Pkce::generate()?;
    let listener = LoopbackListener::bind()?;
    let client = ApiClient::new(&options.server)?;

    let started = client.start(&StartRequest {
        code_challenge: pkce.challenge().to_owned(),
        code_challenge_method: CHALLENGE_METHOD.to_owned(),
        redirect_port: u32::from(listener.port()),
        client_label: Some(client_label()),
    })?;
    let authorize =
        check_web_url(&started.authorize_url).map_err(|_| LoginError::BadAuthorizeUrl)?;
    open_or_announce(options.no_browser, &authorize, ports)?;

    let completion = match listener.wait_for_callback(&started.login_id, options.timeout)? {
        Callback::Approved(code) => code,
        Callback::Failed(FailureCode::AccessDenied) => return Err(LoginError::Denied),
        Callback::Failed(FailureCode::Other) => return Err(LoginError::Failed),
    };
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

    let store = ProfileStore::new(&options.home, &options.profile);
    let mut transaction = store.begin(
        &LoginFiles {
            server: &options.server,
            public_key_line: key.public_line(),
            certificate_line: &verified.certificate_line,
            token: &verified.token,
            meta: &verified.meta,
        },
        clock_now,
    )?;
    let mut notes = Vec::new();
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
