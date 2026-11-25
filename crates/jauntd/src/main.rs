mod policy;
mod serve;
mod storage;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use jaunt_ca::CaKind;
use jauntd::{ca, ca_rotation, node};

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
    #[command(about = "Show the user and host keys and whether the next rotation step is safe")]
    Status {
        #[arg(long, help = "Print JSON instead of text")]
        json: bool,
    },
    #[command(about = "Create the next key of an authority and add it to the trust set")]
    AddNext { authority: Authority },
    #[command(about = "Make the next key the signing key and keep the old one as previous")]
    Promote {
        authority: Authority,
        #[arg(long, help = "Skip the safety check; the override is audited")]
        force: bool,
    },
    #[command(about = "Remove the previous key from the trust set and delete its private key")]
    Retire {
        authority: Authority,
        #[arg(long, help = "Skip the safety check; the override is audited")]
        force: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Authority {
    User,
    Host,
    Internal,
}

impl From<Authority> for CaKind {
    fn from(authority: Authority) -> CaKind {
        match authority {
            Authority::User => CaKind::User,
            Authority::Host => CaKind::Host,
            Authority::Internal => CaKind::Internal,
        }
    }
}

#[derive(Subcommand)]
enum NodeCommand {
    #[command(about = "Approve a pending node by the code shown on the node")]
    Approve {
        code: String,
        #[arg(
            long,
            value_name = "K=V,K=V",
            help = "Replace the proposed labels with these"
        )]
        labels: Option<String>,
        #[arg(long, help = "Do not ask for confirmation")]
        yes: bool,
    },
    #[command(about = "Reject a pending node by its code")]
    Reject { code: String },
    #[command(about = "Remove a node")]
    Rm {
        name: String,
        #[arg(long, help = "Do not ask for confirmation")]
        yes: bool,
    },
    #[command(about = "List nodes")]
    List,
}

impl From<NodeCommand> for node::NodeAction {
    fn from(command: NodeCommand) -> node::NodeAction {
        match command {
            NodeCommand::Approve { code, labels, yes } => {
                node::NodeAction::Approve { code, labels, yes }
            }
            NodeCommand::Reject { code } => node::NodeAction::Reject { code },
            NodeCommand::Rm { name, yes } => node::NodeAction::Rm { name, yes },
            NodeCommand::List => node::NodeAction::List,
        }
    }
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
        Command::Ca { command } => ca_command(&cli.config, command),
        Command::Node { command } => node::run(&cli.config, command.into()),
        Command::Db {
            command: DbCommand::Copy,
        } => not_implemented("db copy"),
    }
}

fn ca_command(config: &Path, command: CaCommand) -> ExitCode {
    use ca_rotation::{ChangeStep, RotationAction};
    let change = |authority: Authority, step| RotationAction::Change {
        kind: authority.into(),
        step,
    };
    let action = match command {
        CaCommand::Init { generate_identity } => return ca::init(config, generate_identity),
        CaCommand::Status { json } => RotationAction::Status { json },
        CaCommand::AddNext { authority } => change(authority, ChangeStep::AddNext),
        CaCommand::Promote { authority, force } => change(authority, ChangeStep::Promote { force }),
        CaCommand::Retire { authority, force } => change(authority, ChangeStep::Retire { force }),
    };
    ca_rotation::run(config, action)
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
