use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustix::io::Errno;
use rustix::process::{Pid, Signal, kill_process_group};

use crate::system::{Runner, RunnerError, ToolExit};

pub(crate) const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
pub(crate) const MAX_TOOL_STDERR: usize = 4096;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const READ_CHUNK: usize = 8192;
const CHUNKS_PER_ROUND: usize = 16;
const FINAL_ROUNDS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stdout {
    Discard,
    Capture { limit: usize },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Captured {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Finished {
    pub(crate) code: Option<i32>,
    pub(crate) timed_out: bool,
    pub(crate) stdout: Captured,
    pub(crate) stderr: Captured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    Idle,
    Busy,
}

struct Sink<R> {
    source: Option<R>,
    limit: usize,
    captured: Captured,
}

impl<R: Read + AsFd> Sink<R> {
    fn new(source: Option<R>, limit: usize) -> io::Result<Self> {
        if let Some(source) = &source {
            rustix::io::ioctl_fionbio(source, true)?;
        }
        Ok(Self {
            source,
            limit,
            captured: Captured::default(),
        })
    }

    fn drain(&mut self) -> io::Result<Round> {
        let mut chunk = [0_u8; READ_CHUNK];
        for _ in 0..CHUNKS_PER_ROUND {
            let Some(source) = self.source.as_mut() else {
                return Ok(Round::Idle);
            };
            match source.read(&mut chunk) {
                Ok(0) => self.source = None,
                Ok(read) => self.keep(chunk.get(..read).unwrap_or_default()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(Round::Idle),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Round::Busy)
    }

    fn finish(mut self) -> io::Result<Captured> {
        for _ in 0..FINAL_ROUNDS {
            if self.drain()? == Round::Idle {
                break;
            }
        }
        Ok(self.captured)
    }

    fn keep(&mut self, piece: &[u8]) {
        let room = self.limit.saturating_sub(self.captured.bytes.len());
        let (kept, dropped) = piece.split_at(piece.len().min(room));
        self.captured.bytes.extend_from_slice(kept);
        self.captured.truncated |= !dropped.is_empty();
    }
}

pub(crate) fn run(
    program: &Path,
    args: &[String],
    timeout: Duration,
    stdout: Stdout,
) -> io::Result<Finished> {
    let (stdout_pipe, stdout_limit) = match stdout {
        Stdout::Discard => (Stdio::null(), 0),
        Stdout::Capture { limit } => (Stdio::piped(), limit),
    };
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", CHILD_PATH)
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(stdout_pipe)
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;
    match supervise(&mut child, timeout, stdout_limit) {
        Ok(finished) => Ok(finished),
        Err(error) => {
            stop(&mut child)?;
            Err(error)
        }
    }
}

fn supervise(child: &mut Child, timeout: Duration, stdout_limit: usize) -> io::Result<Finished> {
    let mut stdout = Sink::new(child.stdout.take(), stdout_limit)?;
    let mut stderr = Sink::new(child.stderr.take(), MAX_TOOL_STDERR)?;
    let deadline = Instant::now().checked_add(timeout);
    let (status, timed_out) = loop {
        stdout.drain()?;
        stderr.drain()?;
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            kill_tree(child)?;
            break (child.wait()?, true);
        }
        thread::sleep(POLL_INTERVAL);
    };
    Ok(Finished {
        code: status.code(),
        timed_out,
        stdout: stdout.finish()?,
        stderr: stderr.finish()?,
    })
}

fn kill_tree(child: &mut Child) -> io::Result<()> {
    match kill_process_group(Pid::from_child(child), Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(_) => child.kill(),
    }
}

fn stop(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        kill_tree(child)?;
    }
    child.wait().map(drop)
}

pub(crate) struct SystemRunner;

impl Runner for SystemRunner {
    fn run(
        &mut self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> Result<ToolExit, RunnerError> {
        let finished =
            run(program, args, timeout, Stdout::Discard).map_err(|source| RunnerError {
                program: program.to_path_buf(),
                source,
            })?;
        Ok(ToolExit {
            code: finished.code,
            timed_out: finished.timed_out,
            stderr: finished.stderr.bytes,
        })
    }
}

#[cfg(test)]
mod tests;
