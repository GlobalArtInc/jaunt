mod accounts;
mod clock;
mod db;
mod endpoint;
mod enroll;
mod fsio;
mod installer;
mod keys;
mod kube;
mod kube_state;
mod paths;
mod pin;
mod recording;
mod run;
mod runtime;
mod ssh;
mod state;
#[cfg(test)]
mod testkit;
mod trust;
mod verify;

use std::fmt::Display;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use enroll::EnrollArgs;
use installer::{InstallArgs, UninstallArgs};
use run::RunArgs;

pub const AGENT_VERSION: &str = concat!("jaunt-agent/", env!("CARGO_PKG_VERSION"));

#[derive(Parser)]
#[command(version, about = "Jaunt node agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Enroll this host with a Jaunt server")]
    Enroll(EnrollArgs),
    #[command(about = "Install the agent service and the sshd drop-in")]
    Install(InstallArgs),
    #[command(about = "Remove the agent service and the sshd drop-in")]
    Uninstall(UninstallArgs),
    #[command(about = "Run the agent")]
    Run(RunArgs),
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Install(args) => installer::run_install(&args),
        Command::Uninstall(args) => installer::run_uninstall(&args),
        Command::Enroll(args) => enroll::command(&args),
        Command::Run(args) => run::command(&args),
    }
}

pub fn finish<E: Display>(result: Result<(), E>, err: &mut dyn Write) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            drop(writeln!(err, "error: {error}"));
            ExitCode::FAILURE
        }
    }
}

pub fn finish_on_stderr<E: Display>(result: Result<(), E>) -> ExitCode {
    finish(result, &mut io::stderr())
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    use clap::{CommandFactory, Parser};

    use super::{Cli, finish};

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn failures_exit_with_one_and_say_why() {
        let mut err = Vec::new();
        assert_eq!(finish::<String>(Ok(()), &mut err), ExitCode::SUCCESS);
        assert!(err.is_empty());
        let failure = finish(Err("the enrollment was rejected"), &mut err);
        assert_eq!(failure, ExitCode::FAILURE);
        assert_eq!(err, b"error: the enrollment was rejected\n");

        struct Closed;
        impl std::io::Write for Closed {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(finish(Err("lost"), &mut Closed), ExitCode::FAILURE);
        assert_eq!(finish::<String>(Ok(()), &mut Closed), ExitCode::SUCCESS);
    }

    #[test]
    fn invalid_arguments_are_usage_errors_with_exit_code_two() {
        let base = ["jaunt-agent", "enroll", "--name", "web-01"];
        for extra in [
            &["--server", "http://jaunt.example.com"][..],
            &[
                "--server",
                "https://jaunt.example.com",
                "--ca-pin",
                "sha256:abc",
            ],
            &[
                "--server",
                "https://jaunt.example.com",
                "--labels",
                "Env=prod",
            ],
            &[
                "--server",
                "https://jaunt.example.com",
                "--state-dir",
                "relative",
            ],
            &[
                "--server",
                "https://jaunt.example.com",
                "--timeout-secs",
                "0",
            ],
            &[
                "--server",
                "https://jaunt.example.com",
                "--hostname",
                "bad host",
            ],
        ] {
            let args: Vec<&str> = base.iter().chain(extra).copied().collect();
            let error = Cli::try_parse_from(&args).err().unwrap();
            assert_eq!(error.exit_code(), 2, "{args:?}");
        }
        assert!(
            Cli::try_parse_from([
                "jaunt-agent",
                "run",
                "--config",
                "/etc/jaunt/agent.yaml",
                "--state-dir",
                "/var/lib/jaunt",
            ])
            .is_ok()
        );
    }
}
