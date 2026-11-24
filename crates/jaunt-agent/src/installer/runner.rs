use std::io;
use std::process::Command;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn success_empty() -> Self {
        Self {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    pub fn status_text(&self) -> String {
        match self.code {
            Some(code) => format!("exit code {code}"),
            None => "terminated by a signal".to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("command not found: {program}")]
    NotFound { program: String },
    #[error("cannot run {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: io::Error,
    },
}

pub trait Runner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, RunnerError>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output, RunnerError> {
        let output = Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .map_err(|source| {
                if source.kind() == io::ErrorKind::NotFound {
                    RunnerError::NotFound {
                        program: program.to_string(),
                    }
                } else {
                    RunnerError::Spawn {
                        program: program.to_string(),
                        source,
                    }
                }
            })?;
        Ok(Output {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

pub fn command_line(program: &str, args: &[&str]) -> String {
    let mut line = program.to_string();
    for arg in args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

pub fn excerpt(text: &str) -> String {
    const LIMIT: usize = 1000;
    let trimmed = text.trim();
    if trimmed.chars().count() <= LIMIT {
        return trimmed.to_string();
    }
    let mut cut: String = trimmed.chars().take(LIMIT).collect();
    cut.push_str("...");
    cut
}

#[cfg(test)]
mod tests {
    use super::{Runner, RunnerError, SystemRunner, command_line, excerpt};

    #[test]
    fn missing_program_is_reported_as_not_found() {
        let error = SystemRunner
            .run("/nonexistent/jaunt-test-program", &[])
            .unwrap_err();
        assert!(matches!(error, RunnerError::NotFound { .. }));
    }

    #[test]
    fn exit_code_and_output_are_captured() {
        let output = SystemRunner
            .run("sh", &["-c", "echo out; echo err >&2; exit 3"])
            .unwrap();
        assert_eq!(output.code, Some(3));
        assert_eq!(output.stdout, "out\n");
        assert_eq!(output.stderr, "err\n");
    }

    #[test]
    fn command_line_joins_arguments() {
        assert_eq!(command_line("sshd", &["-T", "-C", "a=b"]), "sshd -T -C a=b");
    }

    #[test]
    fn excerpt_caps_long_output() {
        assert_eq!(excerpt("  short \n"), "short");
        assert_eq!(excerpt(&"x".repeat(2000)).chars().count(), 1003);
    }
}
