mod policy;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jaunt::commands::{
    Environment, LoginArgs, LogoutArgs, StatusArgs, run_login, run_logout, run_status,
};

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
    Login(LoginArgs),
    #[command(about = "Sign out")]
    Logout(LogoutArgs),
    #[command(about = "Show session status")]
    Status(StatusArgs),
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
        Command::Login(args) => return run_login(&args, &Environment::from_process()),
        Command::Logout(args) => return run_logout(&args, &Environment::from_process()),
        Command::Status(args) => return run_status(&args, &Environment::from_process()),
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
