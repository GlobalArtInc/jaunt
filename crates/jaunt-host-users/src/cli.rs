use std::ffi::OsString;
use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::connection;
use crate::list;
use crate::names::Name;

const USAGE: &str = concat!(
    "usage: jaunt-host-users serve --config <path> --agent-user <name>\n",
    "       jaunt-host-users list [--json]",
);
const USAGE_EXIT: u8 = 2;
const CONFIG_FLAG: &str = "--config";
const AGENT_USER_FLAG: &str = "--agent-user";
const JSON_FLAG: &str = "--json";
const HELP_WORDS: [&str; 3] = ["--help", "-h", "help"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Serve { config: PathBuf, agent_user: Name },
    List { json: bool },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UsageError {
    #[error("arguments must be valid UTF-8")]
    NotUtf8,
    #[error("a subcommand is required")]
    NoCommand,
    #[error("unknown subcommand {0:?}")]
    UnknownCommand(String),
    #[error("unexpected argument {0:?}")]
    Unexpected(String),
    #[error("{0} is given more than once")]
    Repeated(&'static str),
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    #[error("{0} is required")]
    Required(&'static str),
    #[error("--config must be an absolute path")]
    RelativeConfig,
    #[error("--agent-user must be a portable user name")]
    AgentUser,
}

pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, UsageError> {
    let args = args
        .into_iter()
        .map(|arg| arg.into_string().map_err(|_| UsageError::NotUtf8))
        .collect::<Result<Vec<String>, UsageError>>()?;
    let (command, rest) = args.split_first().ok_or(UsageError::NoCommand)?;
    match command.as_str() {
        "serve" => parse_serve(rest),
        "list" => parse_list(rest),
        help if HELP_WORDS.contains(&help) => Ok(Command::Help),
        other => Err(UsageError::UnknownCommand(other.to_owned())),
    }
}

fn parse_serve(args: &[String]) -> Result<Command, UsageError> {
    let mut config = None;
    let mut agent_user = None;
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let (slot, name) = match flag.as_str() {
            CONFIG_FLAG => (&mut config, CONFIG_FLAG),
            AGENT_USER_FLAG => (&mut agent_user, AGENT_USER_FLAG),
            other => return Err(UsageError::Unexpected(other.to_owned())),
        };
        let value = args.next().ok_or(UsageError::MissingValue(name))?;
        if slot.replace(value.clone()).is_some() {
            return Err(UsageError::Repeated(name));
        }
    }
    let config = PathBuf::from(config.ok_or(UsageError::Required(CONFIG_FLAG))?);
    if !config.is_absolute() {
        return Err(UsageError::RelativeConfig);
    }
    let agent_user = agent_user.ok_or(UsageError::Required(AGENT_USER_FLAG))?;
    let agent_user = Name::parse(&agent_user).map_err(|_| UsageError::AgentUser)?;
    Ok(Command::Serve { config, agent_user })
}

fn parse_list(args: &[String]) -> Result<Command, UsageError> {
    match args {
        [] => Ok(Command::List { json: false }),
        [flag] if flag == JSON_FLAG => Ok(Command::List { json: true }),
        [other, ..] => Err(UsageError::Unexpected(other.clone())),
    }
}

pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    match parse(args) {
        Ok(Command::Serve { config, agent_user }) => connection::serve(&config, &agent_user),
        Ok(Command::List { json }) => list::run(json),
        Ok(Command::Help) => match writeln!(io::stdout().lock(), "{USAGE}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Err(error) => complain(&format!("{error}\n{USAGE}"), ExitCode::from(USAGE_EXIT)),
    }
}

pub(crate) fn complain(message: &dyn fmt::Display, code: ExitCode) -> ExitCode {
    match writeln!(io::stderr().lock(), "jaunt-host-users: {message}") {
        Ok(()) => code,
        Err(_) => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{Command, UsageError, parse};
    use crate::testing::name;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn help_as_the_first_argument_asks_for_the_usage() {
        for word in ["--help", "-h", "help"] {
            assert_eq!(parse(args(&[word])), Ok(Command::Help), "{word}");
        }
        assert_eq!(
            parse(args(&["--version"])),
            Err(UsageError::UnknownCommand("--version".to_owned()))
        );
    }

    #[test]
    fn serve_needs_an_absolute_config_and_a_portable_agent_user_and_list_takes_json() {
        let serve = Command::Serve {
            config: PathBuf::from("/etc/jaunt/agent.yaml"),
            agent_user: name("jaunt"),
        };
        for order in [
            [
                "serve",
                "--config",
                "/etc/jaunt/agent.yaml",
                "--agent-user",
                "jaunt",
            ],
            [
                "serve",
                "--agent-user",
                "jaunt",
                "--config",
                "/etc/jaunt/agent.yaml",
            ],
        ] {
            assert_eq!(parse(args(&order)), Ok(serve.clone()));
        }
        assert_eq!(parse(args(&["list"])), Ok(Command::List { json: false }));
        assert_eq!(
            parse(args(&["list", "--json"])),
            Ok(Command::List { json: true })
        );

        for (values, error) in [
            (vec![], UsageError::NoCommand),
            (
                vec!["prune"],
                UsageError::UnknownCommand("prune".to_owned()),
            ),
            (
                vec!["serve", "--config", "/c"],
                UsageError::Required("--agent-user"),
            ),
            (
                vec!["serve", "--agent-user", "jaunt"],
                UsageError::Required("--config"),
            ),
            (
                vec!["serve", "--config"],
                UsageError::MissingValue("--config"),
            ),
            (
                vec![
                    "serve",
                    "--config",
                    "/a",
                    "--config",
                    "/b",
                    "--agent-user",
                    "j",
                ],
                UsageError::Repeated("--config"),
            ),
            (
                vec!["serve", "--config", "agent.yaml", "--agent-user", "jaunt"],
                UsageError::RelativeConfig,
            ),
            (
                vec!["serve", "--config", "/c", "--agent-user", "Jaunt"],
                UsageError::AgentUser,
            ),
            (
                vec!["serve", "--config", "/c", "--agent-user", "j", "--x"],
                UsageError::Unexpected("--x".to_owned()),
            ),
            (
                vec!["list", "--yaml"],
                UsageError::Unexpected("--yaml".to_owned()),
            ),
        ] {
            assert_eq!(parse(args(&values)), Err(error), "{values:?}");
        }
    }
}
