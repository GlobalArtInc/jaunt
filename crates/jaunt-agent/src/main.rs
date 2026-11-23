use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
    #[command(about = "Install the agent service")]
    Install,
    #[command(about = "Uninstall the agent service")]
    Uninstall,
    #[command(about = "Run the agent")]
    Run,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let command = match cli.command {
        Command::Enroll { .. } => "enroll",
        Command::Install => "install",
        Command::Uninstall => "uninstall",
        Command::Run => "run",
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
