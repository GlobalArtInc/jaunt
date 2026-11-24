mod installer;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use installer::{InstallArgs, UninstallArgs};

#[derive(Parser)]
#[command(version, about = "Jaunt node agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Enroll this host with a Jaunt server")]
    Enroll {
        #[arg(long, value_name = "URL")]
        server: String,
        #[arg(long, value_name = "NAME")]
        name: String,
        #[arg(long, value_name = "K=V,...")]
        labels: Option<String>,
        #[arg(long)]
        replace: bool,
        #[arg(long, value_name = "sha256:HEX")]
        ca_pin: Option<String>,
    },
    #[command(about = "Install the agent service and the sshd drop-in")]
    Install(InstallArgs),
    #[command(about = "Remove the agent service and the sshd drop-in")]
    Uninstall(UninstallArgs),
    #[command(about = "Run the agent")]
    Run,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Install(args) => installer::run_install(&args),
        Command::Uninstall(args) => installer::run_uninstall(&args),
        Command::Enroll { .. } => not_implemented("enroll"),
        Command::Run => not_implemented("run"),
    }
}

fn not_implemented(command: &str) -> ExitCode {
    eprintln!("not implemented: {command}");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::Cli;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
