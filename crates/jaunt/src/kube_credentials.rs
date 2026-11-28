use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::agent::SshAgent;
use crate::browser::BrowserOpener;
use crate::consent::ConsentPrompt;
use crate::ensure::{Freshness, check, login_hint};
use crate::kube::{ClusterName, KubeError, check_domain, cluster_host, stored_services};
use crate::kubeconfig::EXEC_API_VERSION;
use crate::lock::{LockError, ProfileLock};
use crate::login::{LoginError, LoginOptions, LoginPorts, SshSetup, lock_profile, login_with_lock};
use crate::loopback::LoopbackError;
use crate::profile::ProfileName;
use crate::status::Session;
use crate::store::{ProfileStore, StoreError};
use crate::user_x509::{UserIdentity, X509Error, ensure_x509, read_identity};

pub const EXPIRY_MARGIN_SECS: i64 = 30;
const EXEC_KIND: &str = "ExecCredential";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const JSON_SLACK: usize = 512;

pub struct CredentialsRequest {
    pub home: PathBuf,
    pub custom_home: bool,
    pub profile: ProfileName,
    pub cluster: Option<ClusterName>,
    pub ssh: Option<SshSetup>,
    pub deadline: Duration,
}

impl CredentialsRequest {
    fn hint(&self) -> String {
        login_hint(&self.home, self.custom_home, &self.profile)
    }
}

pub struct CredentialsIo<'a> {
    pub stdout: &'a mut dyn Write,
    pub stdout_terminal: bool,
    pub stderr: &'a mut dyn Write,
    pub terminal: bool,
    pub browser: &'a dyn BrowserOpener,
    pub agent: &'a SshAgent,
    pub consent: &'a dyn ConsentPrompt,
    pub clock: &'a dyn Fn() -> SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    #[error("not signed in (profile `{profile}`): run `{hint} --server URL` and retry")]
    NotSignedIn { profile: ProfileName, hint: String },
    #[error("the sign-in of profile `{profile}` has expired: run `{hint}` and retry")]
    SignInNeeded { profile: ProfileName, hint: String },
    #[error("cannot renew the SSH setup of profile `{profile}` here: run `{hint}` and retry")]
    NoSshSetup { profile: ProfileName, hint: String },
    #[error("the sign-in for profile `{profile}` did not finish in time: run `{hint}` and retry")]
    TimedOut { profile: ProfileName, hint: String },
    #[error(transparent)]
    Services(KubeError),
    #[error(transparent)]
    Login(LoginError),
    #[error(transparent)]
    Lock(LockError),
    #[error(transparent)]
    X509(#[from] X509Error),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the system clock is set before 1970")]
    Clock,
    #[error("the end of the certificate cannot be written as a time")]
    Expiry,
    #[error("cannot write to the terminal: {0}")]
    Terminal(io::Error),
    #[error("the credential cannot be encoded")]
    Encode,
}

impl CredentialsError {
    fn from_login(err: LoginError, request: &CredentialsRequest) -> CredentialsError {
        match err {
            LoginError::Loopback(LoopbackError::TimedOut)
            | LoginError::Lock(LockError::TimedOut) => CredentialsError::TimedOut {
                profile: request.profile.clone(),
                hint: request.hint(),
            },
            LoginError::Lock(err) => CredentialsError::Lock(err),
            LoginError::Terminal(err) => CredentialsError::Terminal(err),
            other => CredentialsError::Login(other),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecStatus<'a> {
    client_certificate_data: &'a str,
    client_key_data: &'a str,
    expiration_timestamp: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential<'a> {
    api_version: &'static str,
    kind: &'static str,
    status: ExecStatus<'a>,
}

fn unix_now(clock: &dyn Fn() -> SystemTime) -> Result<i64, CredentialsError> {
    clock()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or(CredentialsError::Clock)
}

pub fn expiration_timestamp(valid_before: i64) -> Option<String> {
    let at = valid_before.checked_sub(EXPIRY_MARGIN_SECS)?;
    DateTime::<Utc>::from_timestamp(at, 0).map(|at| at.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub fn exec_credential(identity: &UserIdentity) -> Result<Zeroizing<Vec<u8>>, CredentialsError> {
    let expires = expiration_timestamp(identity.valid_before).ok_or(CredentialsError::Expiry)?;
    let credential = ExecCredential {
        api_version: EXEC_API_VERSION,
        kind: EXEC_KIND,
        status: ExecStatus {
            client_certificate_data: identity.certificate_pem(),
            client_key_data: identity.key_pem(),
            expiration_timestamp: &expires,
        },
    };
    let capacity = 2 * (identity.certificate_pem().len() + identity.key_pem().len()) + JSON_SLACK;
    let mut buffer = Zeroizing::new(Vec::with_capacity(capacity));
    serde_json::to_writer(&mut *buffer, &credential).map_err(|_| CredentialsError::Encode)?;
    buffer.push(b'\n');
    Ok(buffer)
}

fn say(stderr: &mut dyn Write, line: impl std::fmt::Display) {
    drop(writeln!(stderr, "jaunt: {line}"));
}

pub fn run_credentials(request: &CredentialsRequest, mut io: CredentialsIo<'_>) -> u8 {
    if io.stdout_terminal {
        say(
            io.stderr,
            "this command is run by kubectl; it prints a private key, so it does not write to a terminal",
        );
        return EXIT_USAGE;
    }
    let identity = match identity(request, &mut io) {
        Ok(identity) => identity,
        Err(err) => {
            say(io.stderr, &err);
            return EXIT_FAILED;
        }
    };
    let json = match exec_credential(&identity) {
        Ok(json) => json,
        Err(err) => {
            say(io.stderr, &err);
            return EXIT_FAILED;
        }
    };
    drop(identity);
    match io.stdout.write_all(&json).and_then(|()| io.stdout.flush()) {
        Ok(()) => EXIT_OK,
        Err(err) => {
            say(io.stderr, CredentialsError::Terminal(err));
            EXIT_FAILED
        }
    }
}

fn identity(
    request: &CredentialsRequest,
    io: &mut CredentialsIo<'_>,
) -> Result<UserIdentity, CredentialsError> {
    let store = ProfileStore::new(&request.home, &request.profile);
    if Session::load(&store)?.is_none() {
        return Err(CredentialsError::NotSignedIn {
            profile: request.profile.clone(),
            hint: request.hint(),
        });
    }
    let deadline = Instant::now()
        .checked_add(request.deadline)
        .ok_or_else(|| CredentialsError::TimedOut {
            profile: request.profile.clone(),
            hint: request.hint(),
        })?;
    let lock = lock_profile(&request.home, &request.profile, deadline, io.stderr)
        .map_err(|err| CredentialsError::from_login(err, request))?;
    let identity = identity_locked(request, io, &store, &lock, deadline);
    drop(lock);
    identity
}

fn identity_locked(
    request: &CredentialsRequest,
    io: &mut CredentialsIo<'_>,
    store: &ProfileStore,
    lock: &ProfileLock,
    deadline: Instant,
) -> Result<UserIdentity, CredentialsError> {
    match check(store, unix_now(io.clock)?)? {
        Freshness::Fresh => {}
        Freshness::NotSignedIn => {
            return Err(CredentialsError::NotSignedIn {
                profile: request.profile.clone(),
                hint: request.hint(),
            });
        }
        Freshness::Stale if !io.terminal => {
            return Err(CredentialsError::SignInNeeded {
                profile: request.profile.clone(),
                hint: request.hint(),
            });
        }
        Freshness::Stale => sign_in(request, io, store, lock, deadline)?,
    }
    let services = stored_services(store, &request.profile).map_err(CredentialsError::Services)?;
    match &request.cluster {
        Some(cluster) => cluster_host(&services, cluster).map(drop),
        None => check_domain(&services),
    }
    .map_err(CredentialsError::Services)?;
    let issued = ensure_x509(store, lock, unix_now(io.clock)?)?;
    Ok(read_identity(&issued)?)
}

fn sign_in(
    request: &CredentialsRequest,
    io: &mut CredentialsIo<'_>,
    store: &ProfileStore,
    lock: &ProfileLock,
    deadline: Instant,
) -> Result<(), CredentialsError> {
    let session = Session::load(store)?.ok_or_else(|| CredentialsError::NotSignedIn {
        profile: request.profile.clone(),
        hint: request.hint(),
    })?;
    let ssh = if store.has_any_ssh_file()? {
        Some(
            request
                .ssh
                .clone()
                .ok_or_else(|| CredentialsError::NoSshSetup {
                    profile: request.profile.clone(),
                    hint: request.hint(),
                })?,
        )
    } else {
        None
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(CredentialsError::TimedOut {
            profile: request.profile.clone(),
            hint: request.hint(),
        });
    }
    writeln!(
        io.stderr,
        "jaunt: the certificate of profile `{}` needs renewal; signing in to {}",
        request.profile, session.server
    )
    .map_err(CredentialsError::Terminal)?;
    let options = LoginOptions {
        server: session.server,
        profile: request.profile.clone(),
        home: request.home.clone(),
        no_browser: false,
        timeout,
        ssh,
        accept_ssh_config: false,
    };
    let mut ports = LoginPorts {
        browser: io.browser,
        agent: io.agent,
        clock: io.clock,
        notices: &mut *io.stderr,
        consent: io.consent,
    };
    let report = login_with_lock(&options, &mut ports, lock)
        .map_err(|err| CredentialsError::from_login(err, request))?;
    for warning in report.warnings() {
        say(io.stderr, warning);
    }
    say(io.stderr, report.summary());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::expiration_timestamp;

    #[test]
    fn the_expiration_is_thirty_seconds_before_the_end_in_rfc3339_utc() {
        for (valid_before, expected) in [
            (1_800_000_030, Some("2027-01-15T08:00:00Z")),
            (1_800_000_000, Some("2027-01-15T07:59:30Z")),
            (30, Some("1970-01-01T00:00:00Z")),
            (i64::MIN, None),
        ] {
            assert_eq!(
                expiration_timestamp(valid_before).as_deref(),
                expected,
                "{valid_before}"
            );
        }
    }
}
