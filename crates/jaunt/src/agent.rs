use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::secret::Secret;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

const DEFAULT_PROGRAM: &str = "ssh-add";
const EXIT_UNREACHABLE: i32 = 2;
const MAX_DETAIL_LEN: usize = 160;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("no ssh-agent is running (SSH_AUTH_SOCK is not set)")]
    NotRunning,
    #[error("ssh-add cannot be started: {0}")]
    Launch(io::Error),
    #[error("cannot talk to ssh-add: {0}")]
    Io(io::Error),
    #[error("the ssh-agent cannot be reached")]
    Unreachable,
    #[error("ssh-add timed out (the ssh-agent may be stopped)")]
    TimedOut,
    #[error("ssh-add failed{}", detail_suffix(.0))]
    Failed(String),
}

fn detail_suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    Removed,
    NotLoaded,
}

#[derive(Debug, Clone)]
pub struct SshAgent {
    socket: Option<OsString>,
    program: OsString,
    timeout: Duration,
}

impl SshAgent {
    pub fn new(socket: Option<OsString>) -> SshAgent {
        SshAgent {
            socket: socket.filter(|socket| !socket.is_empty()),
            program: OsString::from(DEFAULT_PROGRAM),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_program(mut self, program: impl Into<OsString>) -> SshAgent {
        self.program = program.into();
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> SshAgent {
        self.timeout = timeout;
        self
    }

    pub fn is_configured(&self) -> bool {
        self.socket.is_some()
    }

    pub fn add(&self, private_key: &Secret, lifetime_secs: u64) -> Result<(), AgentError> {
        let mut command = self.command()?;
        command.arg("-t").arg(lifetime_secs.to_string()).arg("-");
        let output = self.run(&mut command, Some(private_key.expose().as_bytes()))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(failure(&output))
        }
    }

    pub fn remove(&self, public_key_file: &Path) -> Result<RemoveOutcome, AgentError> {
        let mut command = self.command()?;
        command.arg("-d").arg(public_key_file);
        let output = self.run(&mut command, None)?;
        match output.status.code() {
            Some(0) => Ok(RemoveOutcome::Removed),
            Some(1) => Ok(RemoveOutcome::NotLoaded),
            _ => Err(failure(&output)),
        }
    }

    pub fn holds(&self, public_key_line: &str) -> Result<bool, AgentError> {
        let mut command = self.command()?;
        command.arg("-L");
        let output = self.run(&mut command, None)?;
        match output.status.code() {
            Some(0) => {}
            Some(1) => return Ok(false),
            _ => return Err(failure(&output)),
        }
        let wanted = key_fields(public_key_line);
        let listing = String::from_utf8_lossy(&output.stdout);
        Ok(wanted.is_some() && listing.lines().any(|line| key_fields(line) == wanted))
    }

    fn command(&self) -> Result<Command, AgentError> {
        let socket = self.socket.as_ref().ok_or(AgentError::NotRunning)?;
        let mut command = Command::new(&self.program);
        command.env("SSH_AUTH_SOCK", socket);
        Ok(command)
    }

    fn run(&self, command: &mut Command, input: Option<&[u8]>) -> Result<Output, AgentError> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(AgentError::TimedOut)?;
        command
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(AgentError::Launch)?;
        let readers = match (
            child.stdout.take().map(drain_in_background),
            child.stderr.take().map(drain_in_background),
        ) {
            (Some(Ok(stdout)), Some(Ok(stderr))) => (stdout, stderr),
            (stdout, stderr) => {
                abandon(&mut child);
                let cause = [stdout, stderr]
                    .into_iter()
                    .flatten()
                    .find_map(Result::err)
                    .unwrap_or_else(|| io::Error::other("ssh-add output is unavailable"));
                return Err(AgentError::Io(cause));
            }
        };
        let delivered = match (input, child.stdin.take()) {
            (Some(bytes), Some(mut stdin)) => stdin.write_all(bytes),
            _ => Ok(()),
        };
        let status = wait_until(&mut child, deadline)?;
        let output = Output {
            status,
            stdout: collect(&readers.0, deadline)?,
            stderr: collect(&readers.1, deadline)?,
        };
        if output.status.success() {
            delivered.map_err(AgentError::Io)?;
        }
        Ok(output)
    }
}

fn drain_in_background<R>(mut pipe: R) -> io::Result<mpsc::Receiver<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("jaunt-ssh-add-output".to_owned())
        .spawn(move || {
            let mut collected = Vec::new();
            drop(
                (&mut pipe)
                    .take(MAX_OUTPUT_BYTES)
                    .read_to_end(&mut collected),
            );
            drop(sender.send(collected));
        })?;
    Ok(receiver)
}

fn collect(output: &mpsc::Receiver<Vec<u8>>, deadline: Instant) -> Result<Vec<u8>, AgentError> {
    output
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| AgentError::TimedOut)
}

fn wait_until(child: &mut Child, deadline: Instant) -> Result<ExitStatus, AgentError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(err) => {
                abandon(child);
                return Err(AgentError::Io(err));
            }
        }
        if Instant::now() >= deadline {
            abandon(child);
            return Err(AgentError::TimedOut);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn abandon(child: &mut Child) {
    drop(child.kill());
    drop(child.wait());
}

fn key_fields(line: &str) -> Option<(&str, &str)> {
    let mut fields = line.split_whitespace();
    Some((fields.next()?, fields.next()?))
}

fn failure(output: &Output) -> AgentError {
    if output.status.code() == Some(EXIT_UNREACHABLE) {
        return AgentError::Unreachable;
    }
    AgentError::Failed(first_line(&output.stderr))
}

fn first_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.chars()
                .map(|ch| {
                    if ch.is_ascii() && !ch.is_ascii_control() {
                        ch
                    } else {
                        '?'
                    }
                })
                .take(MAX_DETAIL_LEN)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::{AgentError, SshAgent, first_line, key_fields};
    use crate::secret::Secret;

    #[test]
    fn without_a_socket_every_operation_reports_that_no_agent_is_running() {
        let agent = SshAgent::new(None);
        assert!(!agent.is_configured());
        assert!(!SshAgent::new(Some(OsString::new())).is_configured());
        let key = Secret::new("key".to_owned());
        assert!(matches!(agent.add(&key, 60), Err(AgentError::NotRunning)));
        assert!(matches!(
            agent.remove(Path::new("/tmp/x.pub")),
            Err(AgentError::NotRunning)
        ));
        assert!(matches!(
            agent.holds("ssh-ed25519 AAAA"),
            Err(AgentError::NotRunning)
        ));
    }

    #[test]
    fn a_missing_ssh_add_is_a_launch_error() {
        let agent = SshAgent::new(Some(OsString::from("/nonexistent/socket")))
            .with_program("/nonexistent/ssh-add");
        let key = Secret::new("key".to_owned());
        assert!(matches!(agent.add(&key, 60), Err(AgentError::Launch(_))));
    }

    #[test]
    fn listing_lines_match_on_type_and_key_ignoring_the_comment() {
        assert_eq!(
            key_fields("ssh-ed25519 AAAA jaunt:default"),
            Some(("ssh-ed25519", "AAAA"))
        );
        assert_eq!(key_fields("ssh-ed25519"), None);
        assert_eq!(key_fields(""), None);
    }

    #[test]
    fn failure_detail_is_one_short_ascii_line() {
        assert_eq!(
            first_line(b"\n  Could not add\x1b[31m identity\nsecond"),
            "Could not add?[31m identity"
        );
        assert_eq!(first_line(b""), "");
        assert_eq!(first_line("é".repeat(400).as_bytes()).len(), 160);
    }
}
