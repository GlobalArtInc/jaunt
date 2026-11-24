mod policy;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::policy::PolicyCommand;

#[derive(Parser)]
#[command(version, about = "Jaunt command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Sign in through single sign-on")]
    Login {
        #[arg(long)]
        device: bool,
        #[arg(long, value_name = "NAME")]
        profile: Option<String>,
    },
    #[command(about = "Sign out")]
    Logout,
    #[command(about = "Show session status")]
    Status,
    #[command(about = "List available hosts")]
    Ls,
    #[command(about = "Policy commands")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(about = "Ensure a valid session and certificate")]
    Ensure,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = match cli.command {
        Command::Policy { command } => return policy::run(&command),
        Command::Login { .. } => "login",
        Command::Logout => "logout",
        Command::Status => "status",
        Command::Ls => "ls",
        Command::Ensure => "ensure",
    };
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
