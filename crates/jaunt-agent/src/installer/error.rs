use std::fmt;
use std::io;
use std::path::PathBuf;

use thiserror::Error;

use super::runner::RunnerError;

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("invalid {name}: {reason}")]
    InvalidArgument {
        name: &'static str,
        reason: &'static str,
    },
    #[error("this command must run as root, but `id -u` reported `{uid}`")]
    NotRoot { uid: String },
    #[error("unexpected output from `{command}`")]
    UnexpectedOutput { command: String },
    #[error(
        "sshd was not found at /usr/sbin/sshd or in PATH; install the OpenSSH server package first"
    )]
    SshdNotFound,
    #[error(
        "{config} has no `Include /etc/ssh/sshd_config.d/*.conf` before its first Match block; add that line near the top of the file and run install again (nothing was changed)"
    )]
    IncludeMissing { config: PathBuf },
    #[error(
        "sshd does not serve loopback (listenaddress: {listen}); add `ListenAddress 127.0.0.1` to the sshd configuration and run install again (jaunt-agent never changes ListenAddress; nothing was changed)"
    )]
    LoopbackNotServed { listen: String },
    #[error(
        "user {user} already exists but is not a Jaunt service account: {reason}; jaunt-agent only adopts an existing account that is absent or a nologin account whose home is the state directory (nothing was changed)"
    )]
    UserNotOurs { user: String, reason: String },
    #[error(
        "sshd already trusts a user CA ({paths}) for {scope}; Jaunt requires that sshd trusts no user CA for outside connections. Remove that TrustedUserCAKeys setting and run install again (nothing was changed)"
    )]
    UserCaAlreadyTrusted { scope: String, paths: String },
    #[error("refusing to use the state directory {path}: {reason} (nothing was changed)")]
    StateDirNotOurs { path: String, reason: &'static str },
    #[error(
        "{path} already exists and was not written by jaunt-agent (it does not start with the line `# Managed by jaunt-agent. Do not edit.`); move it away or remove it and run install again (nothing was changed)"
    )]
    ForeignDropin { path: String },
    #[error(
        "{file}:{line}: `TrustedUserCAKeys {value}` makes sshd trust a user CA; Jaunt requires that sshd trusts no user CA for outside connections. Remove or comment out that directive and run install again (nothing was changed)"
    )]
    UserCaDirective {
        file: String,
        line: usize,
        value: String,
    },
    #[error(
        "{step} failed ({detail}); {remains}; fix the problem and run that step by hand or run `jaunt-agent install` again, or run `jaunt-agent uninstall` to remove everything"
    )]
    AfterCommit {
        step: String,
        detail: String,
        remains: &'static str,
    },
    #[error("`{command}` failed ({status}): {stderr}")]
    CommandFailed {
        command: String,
        status: String,
        stderr: String,
    },
    #[error("sshd validation failed: {problem}; rollback: {rollback}")]
    Validation {
        problem: ValidationProblem,
        rollback: RollbackOutcome,
    },
    #[error(
        "sshd rejects the configuration after removing the drop-in: {stderr}; sshd was not reloaded"
    )]
    ConfigBrokenAfterRemoval { stderr: String },
    #[error("refusing to purge {path}: {reason}")]
    UnsafePurgeTarget { path: String, reason: &'static str },
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Runner(#[from] RunnerError),
}

impl InstallError {
    pub fn io(op: &'static str, path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |source| InstallError::Io { op, path, source }
    }
}

pub const DROPIN_REMAINS: &str = "the validated sshd drop-in stays in place";
pub const DROPIN_AND_UNIT_REMAIN: &str =
    "the validated sshd drop-in and the unit file stay in place";

#[derive(Debug, Error)]
pub enum ValidationProblem {
    #[error("`sshd -t` rejected the configuration: {stderr}")]
    ConfigTest { stderr: String },
    #[error("`sshd -T -C {spec}` failed: {stderr}")]
    ProbeCommand { spec: String, stderr: String },
    #[error("for {spec}: expected {expected}, sshd reports {observed}")]
    Mismatch {
        spec: String,
        expected: String,
        observed: String,
    },
    #[error(transparent)]
    Runner(#[from] RunnerError),
}

#[derive(Debug)]
pub enum ConfigTestOutcome {
    Passed,
    Failed(String),
}

#[derive(Debug)]
pub enum RollbackOutcome {
    Done {
        action: &'static str,
        config_test: ConfigTestOutcome,
    },
    Failed {
        reason: String,
    },
}

impl fmt::Display for RollbackOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RollbackOutcome::Done {
                action,
                config_test: ConfigTestOutcome::Passed,
            } => write!(f, "{action}; `sshd -t` passes, sshd was not reloaded"),
            RollbackOutcome::Done {
                action,
                config_test: ConfigTestOutcome::Failed(detail),
            } => write!(
                f,
                "{action}; `sshd -t` STILL FAILS after rollback ({detail}); fix the sshd configuration before reloading sshd"
            ),
            RollbackOutcome::Failed { reason } => write!(
                f,
                "ROLLBACK FAILED ({reason}); the drop-in may still be in place, so the account, the state directory and inner-ca.pub were left where it expects them; inspect /etc/ssh/sshd_config.d/50-jaunt.conf by hand before reloading sshd"
            ),
        }
    }
}
