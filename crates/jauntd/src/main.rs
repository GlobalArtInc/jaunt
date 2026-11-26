mod policy;
mod serve;
mod storage;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use jaunt_ca::CaKind;
use jaunt_store::RevocationKind;
use jauntd::{ca, ca_rotation, join_token, node, recordings, revoke};

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
    #[command(about = "Join tokens that let agents enrol without an approval code")]
    JoinToken {
        #[command(subcommand)]
        command: JoinTokenCommand,
    },
    #[command(about = "Database commands")]
    Db {
        #[command(subcommand)]
        command: DbCommand,
    },
    #[command(about = "Revoke a user, one certificate or a node")]
    Revoke {
        #[command(subcommand)]
        command: RevokeCommand,
    },
    #[command(about = "List and remove revocations")]
    Revocations {
        #[command(subcommand)]
        command: RevocationsCommand,
    },
    #[command(about = "Session recording commands")]
    Recordings {
        #[command(subcommand)]
        command: RecordingsCommand,
    },
}

#[derive(Subcommand)]
enum RevokeCommand {
    #[command(about = "Revoke every certificate of a user, by user id")]
    User {
        #[arg(
            value_name = "SUBJECT",
            help = "The user id, as shown in the audit log and the admin API"
        )]
        subject: String,
        #[arg(long, help = "Why the access is revoked")]
        reason: String,
    },
    #[command(about = "Revoke one certificate, by serial")]
    Serial {
        #[arg(value_name = "SUBJECT", help = "The serial number of the certificate")]
        subject: String,
        #[arg(long, help = "Why the access is revoked")]
        reason: String,
    },
    #[command(about = "Revoke a node, by id or by the name of an active node")]
    Node {
        #[arg(
            value_name = "SUBJECT",
            help = "The node id, or the name of an active node"
        )]
        subject: String,
        #[arg(long, help = "Why the access is revoked")]
        reason: String,
    },
}

impl From<RevokeCommand> for revoke::RevokeAction {
    fn from(command: RevokeCommand) -> revoke::RevokeAction {
        let (kind, subject, reason) = match command {
            RevokeCommand::User { subject, reason } => (RevocationKind::User, subject, reason),
            RevokeCommand::Serial { subject, reason } => (RevocationKind::Serial, subject, reason),
            RevokeCommand::Node { subject, reason } => (RevocationKind::Node, subject, reason),
        };
        revoke::RevokeAction::Revoke {
            kind,
            subject,
            reason,
        }
    }
}

#[derive(Subcommand)]
enum RevocationsCommand {
    #[command(about = "List revocations, newest first")]
    List,
    #[command(
        about = "Remove a revocation by its id",
        long_about = "Remove a revocation by its id. Removing a user revocation also deletes the \
                      web sessions and API tokens of that user: the user signs in again to get \
                      new ones. Removing a node revocation leaves the node removed: its agent \
                      must enrol again."
    )]
    Rm {
        #[arg(
            value_name = "ID",
            help = "The revocation id, as shown by `jauntd revocations list`"
        )]
        id: String,
    },
}

impl From<RevocationsCommand> for revoke::RevokeAction {
    fn from(command: RevocationsCommand) -> revoke::RevokeAction {
        match command {
            RevocationsCommand::List => revoke::RevokeAction::List,
            RevocationsCommand::Rm { id } => revoke::RevokeAction::Remove { id },
        }
    }
}

#[derive(Subcommand)]
enum RecordingsCommand {
    #[command(about = "Check a stored recording against the digests taken when it was accepted")]
    Verify { session_id: String },
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
enum JoinTokenCommand {
    #[command(
        about = "Create a join token and print it once",
        long_about = "Create a join token that lets agents enrol without an approval code. The \
                      token is printed once on stdout and only its SHA-256 hash is stored; its id \
                      and expiry go to stderr. An agent enrols with it by reading it from a file: \
                      `jaunt-agent enroll --token-file <file>`. The node name must equal --name or \
                      start with --name-prefix, and the node gets exactly the labels given here. \
                      Each accepted enrolment uses one use at the moment the enrolment is \
                      created; a use is not given back if the agent never finishes enrolling."
    )]
    Create {
        #[arg(
            long,
            value_name = "NAME",
            conflicts_with = "name_prefix",
            required_unless_present = "name_prefix",
            help = "The only node name the token accepts"
        )]
        name: Option<String>,
        #[arg(
            long,
            value_name = "PREFIX",
            help = "Accept node names that start with this prefix"
        )]
        name_prefix: Option<String>,
        #[arg(
            long = "label",
            value_name = "K=V",
            help = "A label every node enrolled with the token gets; repeat for more"
        )]
        labels: Vec<String>,
        #[arg(
            long,
            value_name = "N",
            default_value_t = 1,
            help = "How many enrolments the token allows"
        )]
        uses: u32,
        #[arg(
            long,
            value_name = "DURATION",
            default_value = "1h",
            value_parser = join_token::parse_ttl,
            help = "How long the token is valid, at most 7d (s, m, h or d)"
        )]
        ttl: Duration,
        #[arg(
            long,
            help = "Let an agent that enrols with --replace replace the active node with its name"
        )]
        allow_replace: bool,
    },
    #[command(about = "List join tokens without the tokens themselves")]
    List,
    #[command(
        about = "Revoke a join token by its id",
        long_about = "Revoke a join token by its id: no new enrolment is accepted with it. \
                      Revoking does not remove the nodes already enrolled with the token, nor \
                      their enrolments whose certificates were not collected yet; those nodes \
                      show `join-token:<id>` as APPROVED BY in `jauntd node list`, remove them \
                      with `jauntd node rm` if needed."
    )]
    Rm {
        #[arg(
            value_name = "ID",
            help = "The join token id, as shown by `jauntd join-token list`"
        )]
        id: String,
    },
}

impl From<JoinTokenCommand> for join_token::JoinTokenAction {
    fn from(command: JoinTokenCommand) -> join_token::JoinTokenAction {
        match command {
            JoinTokenCommand::Create {
                name,
                name_prefix,
                labels,
                uses,
                ttl,
                allow_replace,
            } => join_token::JoinTokenAction::Create(join_token::CreateOptions {
                name,
                name_prefix,
                labels,
                uses,
                ttl,
                allow_replace,
            }),
            JoinTokenCommand::List => join_token::JoinTokenAction::List,
            JoinTokenCommand::Rm { id } => join_token::JoinTokenAction::Remove { id },
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
        Command::JoinToken { command } => join_token::run(&cli.config, command.into()),
        Command::Db {
            command: DbCommand::Copy,
        } => not_implemented("db copy"),
        Command::Revoke { command } => revoke::run(&cli.config, command.into()),
        Command::Revocations { command } => revoke::run(&cli.config, command.into()),
        Command::Recordings {
            command: RecordingsCommand::Verify { session_id },
        } => recordings::verify_command(&cli.config, &session_id),
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

fn process_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

fn run(path: &Path) -> ExitCode {
    match serve::run(path, &process_env) {
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

    #[test]
    fn join_token_create_says_that_unfinished_enrolments_keep_their_use_and_takes_no_token_input() {
        let mut command = Cli::command();
        let create = command
            .find_subcommand_mut("join-token")
            .unwrap()
            .find_subcommand_mut("create")
            .unwrap();
        let help = create.render_long_help().to_string();
        assert!(help.contains("a use is not given back"), "{help}");
        assert!(help.contains("--name-prefix") && help.contains("--allow-replace"));
        assert!(create.get_arguments().all(|arg| arg.get_env().is_none()));
    }

    #[test]
    fn join_token_rm_says_that_nodes_already_enrolled_stay() {
        let mut command = Cli::command();
        let rm = command
            .find_subcommand_mut("join-token")
            .unwrap()
            .find_subcommand_mut("rm")
            .unwrap();
        let help = rm.render_long_help().to_string();
        assert!(
            help.contains("does not remove the nodes already enrolled with the token"),
            "{help}"
        );
        assert!(help.contains("join-token:<id>") && help.contains("node list"));
    }

    #[test]
    fn join_token_create_needs_exactly_one_of_name_and_prefix_and_a_bounded_ttl() {
        use clap::Parser;
        let base = ["jauntd", "join-token", "create"];
        for extra in [
            &[][..],
            &["--name", "web-01", "--name-prefix", "web-"],
            &["--name", "web-01", "--ttl", "8d"],
            &["--name", "web-01", "--ttl", "0s"],
            &["--name", "web-01", "--ttl", "1w"],
            &["--name", "web-01", "--uses", "-1"],
            &["--name", "web-01", "--token", "x"],
        ] {
            let args: Vec<&str> = base.iter().chain(extra).copied().collect();
            let error = Cli::try_parse_from(&args).err().unwrap();
            assert_eq!(error.exit_code(), 2, "{args:?}");
        }
        assert!(
            Cli::try_parse_from([
                "jauntd",
                "join-token",
                "create",
                "--name-prefix",
                "web-",
                "--ttl",
                "7d"
            ])
            .is_ok()
        );
    }
}
