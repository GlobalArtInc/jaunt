mod ca;
mod config;
mod logging;
mod serve;
mod storage;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Jaunt control daemon")]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "JAUNT_CONFIG",
        default_value = "/etc/jaunt/jauntd.yaml",
        value_name = "PATH"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Run the daemon")]
    Run,
    #[command(about = "Certificate authority commands")]
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    #[command(about = "Node management commands")]
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    #[command(about = "Database commands")]
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    #[command(about = "Initialize the certificate authority")]
    Init {
        #[arg(
            long,
            help = "Create a new age identity in <data_dir>/ca instead of reading one from the environment"
        )]
        generate_identity: bool,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    #[command(about = "Approve a pending node by its code")]
    Approve { code: String },
    #[command(about = "Remove a node")]
    Rm { name: String },
}

#[derive(Subcommand)]
enum DbCommand {
    #[command(about = "Copy the database")]
    Copy,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Run => run(&cli.config),
        Command::Ca {
            command: CaCommand::Init { generate_identity },
        } => ca::init(&cli.config, generate_identity),
        Command::Node {
            command: NodeCommand::Approve { .. },
        } => not_implemented("node approve"),
        Command::Node {
            command: NodeCommand::Rm { .. },
        } => not_implemented("node rm"),
        Command::Db {
            command: DbCommand::Copy,
        } => not_implemented("db copy"),
    }
}

fn run(path: &Path) -> ExitCode {
    match serve::run(path, &|name| std::env::var_os(name)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
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
