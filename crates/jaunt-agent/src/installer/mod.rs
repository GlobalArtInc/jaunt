mod account;
mod args;
mod env;
mod error;
mod files;
mod install;
mod layout;
mod render;
mod report;
mod runner;
mod scan;
mod service;
mod sshd;
#[cfg(test)]
mod testing;
mod uninstall;

use std::io::{self, Write};
use std::process::ExitCode;

pub use args::{InstallArgs, UninstallArgs};

use args::InstallOptions;
use env::Env;
use error::InstallError;
use layout::Layout;
use report::Report;
use runner::{Runner, SystemRunner};

pub fn run_install(args: &InstallArgs) -> ExitCode {
    let mut report = Report::new();
    let result = (|| {
        let options = InstallOptions::from_args(args)?;
        let layout = args.layout()?;
        let mut runner = SystemRunner;
        let mut env = environment(&layout, &mut runner, &mut report, args.dry_run);
        install::install(&mut env, &options)
    })();
    finish(&report, result)
}

pub fn run_uninstall(args: &UninstallArgs) -> ExitCode {
    let mut report = Report::new();
    let result = (|| {
        let options = args.options()?;
        let layout = args.layout()?;
        let mut runner = SystemRunner;
        let mut env = environment(&layout, &mut runner, &mut report, args.dry_run);
        uninstall::uninstall(&mut env, &options)
    })();
    finish(&report, result)
}

fn environment<'a>(
    layout: &'a Layout,
    runner: &'a mut dyn Runner,
    report: &'a mut Report,
    dry_run: bool,
) -> Env<'a> {
    Env {
        layout,
        runner,
        report,
        dry_run,
        live: layout.is_live(),
        path_env: std::env::var("PATH").unwrap_or_default(),
    }
}

fn finish(report: &Report, result: Result<(), InstallError>) -> ExitCode {
    if report
        .write_to(&mut io::stdout().lock(), &mut io::stderr().lock())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}
