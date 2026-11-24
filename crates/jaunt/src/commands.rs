use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Args;

use crate::agent::SshAgent;
use crate::browser::SystemBrowser;
use crate::login::{LoginOptions, LoginPorts, login};
use crate::logout::logout;
use crate::profile::{ProfileName, resolve_home};
use crate::server_url::ServerUrl;
use crate::status::{Session, agent_view, check_online, render};
use crate::store::ProfileStore;

const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;
const MAX_TIMEOUT_SECS: u64 = 900;
const DEFAULT_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub jaunt_home: Option<OsString>,
    pub user_home: Option<PathBuf>,
    pub ssh_auth_sock: Option<OsString>,
}

impl Environment {
    pub fn from_process() -> Environment {
        Environment {
            jaunt_home: env::var_os("JAUNT_HOME"),
            user_home: env::home_dir(),
            ssh_auth_sock: env::var_os("SSH_AUTH_SOCK"),
        }
    }
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long, value_name = "URL", env = "JAUNT_SERVER")]
    pub server: Option<ServerUrl>,
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(long, help = "Print the sign-in address instead of opening a browser")]
    pub no_browser: bool,
    #[arg(
        long,
        value_name = "SECS",
        default_value_t = DEFAULT_TIMEOUT_SECS,
        value_parser = clap::value_parser!(u64).range(1..=900),
        help = "How long to wait for the browser sign-in (at most 900)"
    )]
    pub timeout: u64,
    #[arg(
        long,
        help = "Sign in without a browser on this machine (not implemented yet)"
    )]
    pub device: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
    #[arg(
        long,
        help = "Also ask the server whether the sign-in is still accepted"
    )]
    pub online: bool,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    #[arg(
        long,
        value_name = "NAME",
        env = "JAUNT_PROFILE",
        default_value = "default"
    )]
    pub profile: ProfileName,
}

fn usage_error(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("jaunt: {message}");
    ExitCode::from(EXIT_USAGE)
}

fn failure(message: impl std::fmt::Display) -> ExitCode {
    eprintln!("jaunt: {message}");
    ExitCode::from(EXIT_FAILED)
}

fn home_for(environment: &Environment) -> Result<PathBuf, ExitCode> {
    resolve_home(
        environment.jaunt_home.clone(),
        environment.user_home.clone(),
    )
    .map_err(usage_error)
}

fn now_secs() -> Result<i64, ExitCode> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or_else(|| failure("the system clock is set before 1970"))
}

pub fn run_login(args: &LoginArgs, environment: &Environment) -> ExitCode {
    if args.device {
        return usage_error("not implemented: login --device");
    }
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let stored = match store.read_server() {
        Ok(stored) => stored,
        Err(err) => return failure(err),
    };
    let server = match (stored, args.server.clone()) {
        (Some(stored), None) => stored,
        (Some(stored), Some(requested)) if stored == requested => stored,
        (Some(stored), Some(_)) => {
            return usage_error(format!(
                "profile `{}` is already signed in to {stored}; run `jaunt logout --profile {}` first or choose another profile",
                args.profile, args.profile
            ));
        }
        (None, Some(requested)) => requested,
        (None, None) => {
            return usage_error("no server given: pass --server URL or set JAUNT_SERVER");
        }
    };
    let options = LoginOptions {
        server,
        profile: args.profile.clone(),
        home,
        no_browser: args.no_browser,
        timeout: Duration::from_secs(args.timeout.min(MAX_TIMEOUT_SECS)),
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let mut stderr = io::stderr();
    let mut ports = LoginPorts {
        browser: &SystemBrowser,
        agent: &agent,
        clock: &SystemTime::now,
        notices: &mut stderr,
    };
    match login(&options, &mut ports) {
        Ok(report) => {
            for warning in report.warnings() {
                eprintln!("jaunt: {warning}");
            }
            match writeln!(io::stdout().lock(), "{}", report.summary()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => failure(format!("cannot write to the terminal: {err}")),
            }
        }
        Err(err) => failure(err),
    }
}

pub fn run_status(args: &StatusArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let now = match now_secs() {
        Ok(now) => now,
        Err(code) => return code,
    };
    let session = match Session::load(&store) {
        Ok(Some(session)) => session,
        Ok(None) => {
            let mut text = format!(
                "Not signed in (profile `{}`). Run `jaunt login`.",
                args.profile
            );
            match store.stranded_dirs() {
                Ok(found) => {
                    for path in found {
                        text.push_str(&format!(
                            "\nA previous session was left in {}: move it back to {} or run `jaunt logout`.",
                            path.display(),
                            store.dir().display()
                        ));
                    }
                }
                Err(err) => return failure(err),
            }
            return report_lines(&text, ExitCode::from(EXIT_FAILED));
        }
        Err(err) => return failure(err),
    };
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    let view = agent_view(&store, &agent);
    let mut stdout = io::stdout().lock();
    if let Err(err) = render(&mut stdout, &session, now, &view) {
        return failure(format!("cannot write to the terminal: {err}"));
    }
    let mut valid = session.is_valid_at(now);
    if args.online
        && let Err(err) = check_online(&mut stdout, &store, &session.server)
    {
        if err.is_rejection() {
            eprintln!("jaunt: {err}");
            valid = false;
        } else {
            eprintln!("jaunt: warning: the server could not confirm this sign-in: {err}");
        }
    }
    if valid {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILED)
    }
}

fn report_lines(text: &str, code: ExitCode) -> ExitCode {
    match writeln!(io::stdout().lock(), "{text}") {
        Ok(()) => code,
        Err(err) => failure(format!("cannot write to the terminal: {err}")),
    }
}

pub fn run_logout(args: &LogoutArgs, environment: &Environment) -> ExitCode {
    let home = match home_for(environment) {
        Ok(home) => home,
        Err(code) => return code,
    };
    let store = ProfileStore::new(&home, &args.profile);
    let agent = SshAgent::new(environment.ssh_auth_sock.clone());
    match logout(&store, &agent) {
        Ok(report) => {
            if let Some(warning) = &report.agent_warning {
                eprintln!("jaunt: warning: the key may still be loaded in ssh-agent: {warning}");
            }
            if report.directory_kept {
                eprintln!(
                    "jaunt: warning: {} still contains other files and was kept",
                    store.dir().display()
                );
            }
            let text = if report.was_signed_in {
                "Signed out."
            } else {
                "Already signed out."
            };
            report_lines(text, ExitCode::SUCCESS)
        }
        Err(err) => failure(err),
    }
}
