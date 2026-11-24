use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ssh_key::Certificate;

use crate::agent::SshAgent;
use crate::browser::BrowserOpener;
use crate::consent::ConsentPrompt;
use crate::lock::{LockError, ProfileLock};
use crate::login::{
    LoginError, LoginOptions, LoginPorts, LoginReport, SshSetup, lock_profile, login_with_lock,
};
use crate::loopback::LoopbackError;
use crate::profile::ProfileName;
use crate::ssh_config::SshConfigError;
use crate::status::Session;
use crate::store::{ProfileStore, StoreError};

pub const MIN_REMAINING_SECS: i64 = 60;
pub const FAILURE_PAUSE_SECS: i64 = 90;
pub const SIGN_IN_DEADLINE: Duration = Duration::from_secs(5 * 60);

pub const EXIT_OK: u8 = 0;
pub const EXIT_NEEDS_SIGN_IN: u8 = 1;
pub const EXIT_LOCAL: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
    NotSignedIn,
}

pub fn check(store: &ProfileStore, now_secs: i64) -> Result<Freshness, StoreError> {
    if Session::load(store)?.is_none() {
        return Ok(Freshness::NotSignedIn);
    }
    let line = match store.read_certificate_line() {
        Ok(Some(line)) => line,
        Ok(None) | Err(StoreError::Corrupt { .. } | StoreError::TooLarge { .. }) => {
            return Ok(Freshness::Stale);
        }
        Err(err) => return Err(err),
    };
    let Ok(certificate) = Certificate::from_openssh(&line) else {
        return Ok(Freshness::Stale);
    };
    let valid_before = i64::try_from(certificate.valid_before()).unwrap_or(i64::MAX);
    if valid_before.saturating_sub(now_secs) >= MIN_REMAINING_SECS {
        Ok(Freshness::Fresh)
    } else {
        Ok(Freshness::Stale)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnsureError {
    #[error("no sign-in for profile `{profile}` was found in {dir}: run `{hint} --server URL`")]
    NotSignedIn {
        profile: ProfileName,
        dir: PathBuf,
        hint: String,
    },
    #[error("the sign-in for profile `{profile}` did not finish in time: run `{hint}`")]
    TimedOut { profile: ProfileName, hint: String },
    #[error("cannot renew the SSH setup of profile `{profile}` here: run `{hint}`")]
    NoSshSetup { profile: ProfileName, hint: String },
    #[error("sign-in did not complete a moment ago: run `{hint}`")]
    RecentFailure { hint: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Lock(LockError),
    #[error(transparent)]
    Login(LoginError),
    #[error("the system clock is set before 1970")]
    Clock,
    #[error("cannot write to the terminal: {0}")]
    Terminal(io::Error),
}

fn login_is_local(err: &LoginError) -> bool {
    match err {
        LoginError::Store(_)
        | LoginError::Lock(_)
        | LoginError::Key(_)
        | LoginError::Entropy(_)
        | LoginError::Clock
        | LoginError::ForeignLock
        | LoginError::UnsafeCommand(_) => true,
        LoginError::SshSettings(settings) => matches!(
            settings,
            SshConfigError::UnsafePath { .. }
                | SshConfigError::UnsafeProgram { .. }
                | SshConfigError::UnsafeProfile { .. }
        ),
        _ => false,
    }
}

impl EnsureError {
    pub fn exit_code(&self) -> u8 {
        match self {
            EnsureError::Store(_)
            | EnsureError::Lock(_)
            | EnsureError::Clock
            | EnsureError::NoSshSetup { .. } => EXIT_LOCAL,
            EnsureError::Login(err) if login_is_local(err) => EXIT_LOCAL,
            EnsureError::NotSignedIn { .. }
            | EnsureError::RecentFailure { .. }
            | EnsureError::TimedOut { .. }
            | EnsureError::Login(_)
            | EnsureError::Terminal(_) => EXIT_NEEDS_SIGN_IN,
        }
    }

    fn from_login(err: LoginError, options: &RenewOptions) -> EnsureError {
        match err {
            LoginError::Loopback(LoopbackError::TimedOut)
            | LoginError::Lock(LockError::TimedOut) => EnsureError::TimedOut {
                profile: options.profile.clone(),
                hint: options.login_hint(),
            },
            LoginError::Lock(err) => EnsureError::Lock(err),
            LoginError::Terminal(err) => EnsureError::Terminal(err),
            other => EnsureError::Login(other),
        }
    }
}

pub struct RenewOptions {
    pub home: PathBuf,
    pub custom_home: bool,
    pub profile: ProfileName,
    pub deadline: Duration,
    pub ssh: Option<SshSetup>,
}

impl RenewOptions {
    pub fn login_hint(&self) -> String {
        login_hint(&self.home, self.custom_home, &self.profile)
    }

    fn not_signed_in(&self, store: &ProfileStore) -> EnsureError {
        EnsureError::NotSignedIn {
            profile: self.profile.clone(),
            dir: store.dir().to_owned(),
            hint: self.login_hint(),
        }
    }
}

pub fn login_hint(home: &Path, custom_home: bool, profile: &ProfileName) -> String {
    if custom_home {
        format!(
            "JAUNT_HOME='{}' jaunt login --profile {profile}",
            home.display()
        )
    } else {
        format!("jaunt login --profile {profile}")
    }
}

#[derive(Debug)]
pub enum Renewed {
    AlreadyFresh,
    SignedIn(LoginReport),
}

fn unix_now(clock: &dyn Fn() -> SystemTime) -> Result<i64, EnsureError> {
    clock()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or(EnsureError::Clock)
}

pub fn renew(options: &RenewOptions, ports: &mut LoginPorts<'_>) -> Result<Renewed, EnsureError> {
    let profile = &options.profile;
    let store = ProfileStore::new(&options.home, profile);
    let deadline = Instant::now()
        .checked_add(options.deadline)
        .ok_or_else(|| EnsureError::TimedOut {
            profile: profile.clone(),
            hint: options.login_hint(),
        })?;
    let lock = lock_profile(&options.home, profile, deadline, ports.notices)
        .map_err(|err| EnsureError::from_login(err, options))?;
    let outcome = renew_locked(options, ports, &store, deadline, &lock);
    if let Err(err) = &outcome
        && !matches!(err, EnsureError::RecentFailure { .. })
        && let Ok(failed_at) = unix_now(ports.clock)
        && let Err(marker) = store.write_failure_marker(failed_at)
    {
        drop(writeln!(
            ports.notices,
            "jaunt: warning: cannot record the failed sign-in: {marker}"
        ));
    }
    drop(lock);
    outcome
}

fn renew_locked(
    options: &RenewOptions,
    ports: &mut LoginPorts<'_>,
    store: &ProfileStore,
    deadline: Instant,
    lock: &ProfileLock,
) -> Result<Renewed, EnsureError> {
    let profile = &options.profile;
    let now = unix_now(ports.clock)?;
    match check(store, now)? {
        Freshness::Fresh => {
            if let Err(err) = store.clear_failure_marker() {
                drop(writeln!(
                    ports.notices,
                    "jaunt: warning: the record of an earlier failed sign-in was not removed: {err}"
                ));
            }
            return Ok(Renewed::AlreadyFresh);
        }
        Freshness::NotSignedIn => return Err(options.not_signed_in(store)),
        Freshness::Stale => {}
    }
    if recent_failure(store.read_failure_marker(), now) {
        return Err(EnsureError::RecentFailure {
            hint: options.login_hint(),
        });
    }
    let session = Session::load(store)?.ok_or_else(|| options.not_signed_in(store))?;
    let ssh = if store.has_any_ssh_file()? {
        Some(options.ssh.clone().ok_or_else(|| EnsureError::NoSshSetup {
            profile: profile.clone(),
            hint: options.login_hint(),
        })?)
    } else {
        None
    };
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(EnsureError::TimedOut {
            profile: profile.clone(),
            hint: options.login_hint(),
        });
    }
    writeln!(
        ports.notices,
        "jaunt: the certificate of profile `{profile}` needs renewal; signing in to {}",
        session.server
    )
    .map_err(EnsureError::Terminal)?;
    let login_options = LoginOptions {
        server: session.server,
        profile: profile.clone(),
        home: options.home.clone(),
        no_browser: false,
        timeout,
        ssh,
        accept_ssh_config: false,
    };
    let report = login_with_lock(&login_options, ports, lock)
        .map_err(|err| EnsureError::from_login(err, options))?;
    Ok(Renewed::SignedIn(report))
}

pub fn note_is_shown(note: &str, quiet: bool) -> bool {
    !quiet || note.starts_with("warning:")
}

pub fn recent_failure(failed_at: Option<i64>, now_secs: i64) -> bool {
    failed_at.is_some_and(|at| (0..FAILURE_PAUSE_SECS).contains(&now_secs.saturating_sub(at)))
}

pub struct EnsureRequest {
    pub renew: RenewOptions,
    pub quiet: bool,
}

pub struct EnsureIo<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub terminal: bool,
    pub browser: &'a dyn BrowserOpener,
    pub agent: &'a SshAgent,
    pub consent: &'a dyn ConsentPrompt,
    pub clock: &'a dyn Fn() -> SystemTime,
}

fn say(stderr: &mut dyn Write, line: impl std::fmt::Display) {
    drop(writeln!(stderr, "jaunt: {line}"));
}

pub fn run(request: &EnsureRequest, io: EnsureIo<'_>) -> u8 {
    let options = &request.renew;
    let store = ProfileStore::new(&options.home, &options.profile);
    let now = match unix_now(io.clock) {
        Ok(now) => now,
        Err(err) => {
            say(io.stderr, &err);
            return err.exit_code();
        }
    };
    match check(&store, now) {
        Ok(Freshness::Fresh) => return EXIT_OK,
        Ok(Freshness::NotSignedIn) => {
            say(io.stderr, options.not_signed_in(&store));
            return EXIT_NEEDS_SIGN_IN;
        }
        Ok(Freshness::Stale) => {}
        Err(err) => {
            say(io.stderr, err);
            return EXIT_LOCAL;
        }
    }
    if recent_failure(store.read_failure_marker(), now) {
        let err = EnsureError::RecentFailure {
            hint: options.login_hint(),
        };
        say(io.stderr, &err);
        return err.exit_code();
    }
    if !io.terminal {
        say(
            io.stderr,
            format_args!(
                "sign-in needed for profile `{}`: run `{}`",
                options.profile,
                options.login_hint()
            ),
        );
        return EXIT_NEEDS_SIGN_IN;
    }
    let mut ports = LoginPorts {
        browser: io.browser,
        agent: io.agent,
        clock: io.clock,
        notices: &mut *io.stderr,
        consent: io.consent,
    };
    match renew(options, &mut ports) {
        Ok(Renewed::AlreadyFresh) => EXIT_OK,
        Ok(Renewed::SignedIn(report)) => {
            for note in report.warnings() {
                if note_is_shown(&note, request.quiet) {
                    say(io.stderr, note);
                }
            }
            if !request.quiet {
                say(io.stderr, report.summary());
            }
            EXIT_OK
        }
        Err(err) => {
            say(io.stderr, &err);
            err.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::PathBuf;

    use super::{EXIT_LOCAL, EXIT_NEEDS_SIGN_IN, EnsureError, note_is_shown, recent_failure};
    use crate::key::KeyError;
    use crate::lock::LockError;
    use crate::login::LoginError;
    use crate::loopback::LoopbackError;
    use crate::pkce::EntropyError;
    use crate::profile::ProfileName;
    use crate::ssh_config::SshConfigError;
    use crate::store::StoreError;

    #[test]
    fn quiet_keeps_warnings_and_drops_informational_notes() {
        let cases = [
            (
                "warning: the previous SSH setup of this profile was removed",
                true,
                true,
            ),
            ("warning: the private key is stored on disk", true, true),
            ("SSH setup is ready for *.example.test", true, false),
            ("SSH setup is ready for *.example.test", false, true),
            ("a warning: inside the text", true, false),
            ("", true, false),
        ];
        for (note, quiet, shown) in cases {
            assert_eq!(note_is_shown(note, quiet), shown, "{note:?} quiet={quiet}");
        }
    }

    #[test]
    fn a_failure_pauses_renewal_for_ninety_seconds_only() {
        let cases = [
            (None, 1_000, false),
            (Some(1_000), 1_000, true),
            (Some(1_000), 1_089, true),
            (Some(1_000), 1_090, false),
            (Some(1_000), 1_091, false),
            (Some(1_100), 1_000, false),
            (Some(1_050), 1_000, false),
            (Some(1_001), 1_000, false),
        ];
        for (failed_at, now, recent) in cases {
            assert_eq!(
                recent_failure(failed_at, now),
                recent,
                "{failed_at:?} {now}"
            );
        }
    }

    #[test]
    fn local_failures_exit_two_and_unfinished_sign_ins_exit_one() {
        let profile = ProfileName::default_name();
        let path = PathBuf::from("/p");
        let login = EnsureError::Login;
        let cases: Vec<(EnsureError, u8)> = vec![
            (
                EnsureError::Store(StoreError::NotADirectory { path: path.clone() }),
                EXIT_LOCAL,
            ),
            (
                EnsureError::Lock(LockError::Unsafe { path: path.clone() }),
                EXIT_LOCAL,
            ),
            (EnsureError::Clock, EXIT_LOCAL),
            (
                EnsureError::NoSshSetup {
                    profile: profile.clone(),
                    hint: String::new(),
                },
                EXIT_LOCAL,
            ),
            (
                login(LoginError::Store(StoreError::TooLarge {
                    path: path.clone(),
                })),
                EXIT_LOCAL,
            ),
            (login(LoginError::Key(KeyError::Entropy)), EXIT_LOCAL),
            (login(LoginError::Entropy(EntropyError)), EXIT_LOCAL),
            (login(LoginError::Clock), EXIT_LOCAL),
            (login(LoginError::ForeignLock), EXIT_LOCAL),
            (
                login(LoginError::UnsafeCommand(SshConfigError::UnsafeProgram {
                    path: path.clone(),
                })),
                EXIT_LOCAL,
            ),
            (
                login(LoginError::SshSettings(SshConfigError::UnsafePath {
                    path: path.clone(),
                })),
                EXIT_LOCAL,
            ),
            (
                login(LoginError::SshSettings(SshConfigError::BadSuffix)),
                EXIT_NEEDS_SIGN_IN,
            ),
            (login(LoginError::Denied), EXIT_NEEDS_SIGN_IN),
            (login(LoginError::Failed), EXIT_NEEDS_SIGN_IN),
            (
                login(LoginError::Loopback(LoopbackError::TimedOut)),
                EXIT_NEEDS_SIGN_IN,
            ),
            (
                EnsureError::TimedOut {
                    profile: profile.clone(),
                    hint: String::new(),
                },
                EXIT_NEEDS_SIGN_IN,
            ),
            (
                EnsureError::NotSignedIn {
                    profile,
                    dir: path,
                    hint: String::new(),
                },
                EXIT_NEEDS_SIGN_IN,
            ),
            (
                EnsureError::Terminal(io::Error::other("closed")),
                EXIT_NEEDS_SIGN_IN,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.exit_code(), code, "{err:?}");
        }
    }
}
