mod policy;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jaunt::commands::{
    AdminArgs, EnsureArgs, Environment, LoginArgs, LogoutArgs, LsArgs, ProxyCommand, StatusArgs,
    run_admin, run_ensure, run_login, run_logout, run_ls, run_proxy, run_status,
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
    #[command(about = "List available hosts and services")]
    Ls(LsArgs),
    #[command(about = "Policy commands")]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    #[command(about = "Make sure a valid certificate is in place, signing in again if needed")]
    Ensure(EnsureArgs),
    #[command(about = "Administrator commands, sent as requests signed by the session key")]
    Admin(AdminArgs),
    #[command(about = "Connect through the gateway over TLS (used by ssh)")]
    Proxy {
        #[command(subcommand)]
        command: ProxyCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Policy { command } => policy::run(&command),
        Command::Login(args) => run_login(&args, &Environment::from_process()),
        Command::Logout(args) => run_logout(&args, &Environment::from_process()),
        Command::Status(args) => run_status(&args, &Environment::from_process()),
        Command::Ls(args) => run_ls(&args, &Environment::from_process()),
        Command::Ensure(args) => run_ensure(&args, &Environment::from_process()),
        Command::Admin(args) => run_admin(&args, &Environment::from_process()),
        Command::Proxy { command } => run_proxy(&command, &Environment::from_process()),
    }
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
