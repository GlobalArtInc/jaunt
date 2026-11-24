use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use jaunt_policy::{AccessTestResult, PolicySet, load_dir, policy_schema_pretty, run_access_tests};
use serde_json::{Value, json};

#[derive(Subcommand)]
pub(crate) enum PolicyCommand {
    #[command(about = "Check policy files in a directory and run its access tests")]
    Check {
        dir: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    #[command(about = "Print the JSON Schema of policy documents")]
    Schema,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    Text,
    Json,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PolicyCliError {
    #[error("cannot read policy directory {path}: {source}")]
    Directory { path: PathBuf, source: io::Error },
    #[error("{path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("cannot write output: {0}")]
    Output(#[from] io::Error),
}

const NO_DOCUMENTS: &str = "no policy documents found";
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_ERROR: u8 = 2;

pub(crate) fn run(command: &PolicyCommand) -> ExitCode {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let result = match command {
        PolicyCommand::Check { dir, format } => check(dir, *format, &mut out),
        PolicyCommand::Schema => schema(&mut out),
    };
    match result {
        Ok(code) => code,
        Err(err) => {
            eprintln!("jaunt: {err}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn schema(out: &mut impl Write) -> Result<ExitCode, PolicyCliError> {
    writeln!(out, "{}", policy_schema_pretty())?;
    Ok(ExitCode::from(EXIT_OK))
}

fn ensure_directory(dir: &Path) -> Result<(), PolicyCliError> {
    let metadata = fs::metadata(dir).map_err(|source| PolicyCliError::Directory {
        path: dir.to_path_buf(),
        source,
    })?;
    if metadata.is_dir() {
        Ok(())
    } else {
        Err(PolicyCliError::NotADirectory {
            path: dir.to_path_buf(),
        })
    }
}

struct CaseReport {
    index: usize,
    source: String,
    passed: bool,
    detail: String,
}

fn case_reports(set: &PolicySet) -> Vec<CaseReport> {
    let results: Vec<AccessTestResult> = run_access_tests(set);
    results
        .into_iter()
        .zip(set.tests())
        .map(|(result, case)| {
            let described = result
                .description
                .split_once(": ")
                .map_or(result.description.as_str(), |(_, rest)| rest);
            let detail = described
                .strip_prefix(case.source.as_str())
                .map_or(described, str::trim_start);
            CaseReport {
                index: result.index,
                source: case.source.clone(),
                passed: result.passed,
                detail: detail.to_owned(),
            }
        })
        .collect()
}

fn report_invalid(
    messages: &[String],
    format: Format,
    out: &mut impl Write,
) -> Result<ExitCode, PolicyCliError> {
    match format {
        Format::Text => {
            for message in messages {
                writeln!(out, "ERROR {message}")?;
            }
            writeln!(out, "policy invalid: {} errors", messages.len())?;
        }
        Format::Json => write_json(out, false, None, &[], messages)?,
    }
    Ok(ExitCode::from(EXIT_FAILED))
}

fn check(dir: &Path, format: Format, out: &mut impl Write) -> Result<ExitCode, PolicyCliError> {
    ensure_directory(dir)?;
    let set = match load_dir(dir) {
        Ok(set) => set,
        Err(errors) => return report_invalid(&errors.messages(), format, out),
    };
    if set.is_empty() {
        return report_invalid(&[NO_DOCUMENTS.to_owned()], format, out);
    }
    let reports = case_reports(&set);
    let failed = reports.iter().filter(|report| !report.passed).count();
    match format {
        Format::Text => {
            for report in &reports {
                let verdict = if report.passed { "PASS" } else { "FAIL" };
                writeln!(out, "{verdict} {}: {}", report.source, report.detail)?;
            }
            writeln!(
                out,
                "policy loaded (hash {}): {} tests, {} passed, {} failed",
                set.hash(),
                reports.len(),
                reports.len() - failed,
                failed
            )?;
        }
        Format::Json => write_json(out, true, Some(set.hash()), &reports, &[])?,
    }
    Ok(ExitCode::from(if failed == 0 {
        EXIT_OK
    } else {
        EXIT_FAILED
    }))
}

fn write_json(
    out: &mut impl Write,
    loaded: bool,
    hash: Option<&str>,
    reports: &[CaseReport],
    errors: &[String],
) -> io::Result<()> {
    let tests: Vec<Value> = reports
        .iter()
        .map(|report| {
            json!({
                "index": report.index,
                "source": report.source,
                "passed": report.passed,
                "detail": report.detail,
            })
        })
        .collect();
    let document = json!({
        "loaded": loaded,
        "hash": hash,
        "tests": tests,
        "errors": errors,
    });
    writeln!(out, "{document:#}")
}
