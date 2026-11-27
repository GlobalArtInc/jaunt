use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use jaunt_host_users::Name;
use jaunt_tunnel::BoxFuture;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

pub const GETENT_PROGRAMS: [&str; 2] = ["/usr/bin/getent", "/bin/getent"];

const MAX_GETENT_OUTPUT: u64 = 4096;
const GETENT_NOT_FOUND: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Present,
    Absent,
}

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("getent is not installed")]
    NotInstalled,
    #[error("getent could not run: {0}")]
    Run(#[source] io::Error),
    #[error("getent did not answer within {0:?}")]
    TimedOut(Duration),
    #[error("getent ended with exit code {0:?}")]
    Exit(Option<i32>),
    #[error("getent answered with an entry for another name")]
    Mismatch,
}

pub trait PasswdLookup: Send + Sync {
    fn passwd<'a>(&'a self, login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>>;
}

pub struct Getent {
    programs: Vec<PathBuf>,
    timeout: Duration,
}

impl Getent {
    pub fn system(timeout: Duration) -> Self {
        Self {
            programs: GETENT_PROGRAMS.iter().map(PathBuf::from).collect(),
            timeout,
        }
    }

    #[cfg(test)]
    pub fn with_program(program: PathBuf, timeout: Duration) -> Self {
        Self {
            programs: vec![program],
            timeout,
        }
    }

    fn program(&self) -> Option<&Path> {
        self.programs
            .iter()
            .map(PathBuf::as_path)
            .find(|program| program.is_file())
    }

    async fn look_up(&self, login: &Name) -> Result<Presence, LookupError> {
        let program = self.program().ok_or(LookupError::NotInstalled)?;
        let mut child = Command::new(program)
            .arg("passwd")
            .arg(login.as_str())
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(LookupError::Run)?;
        let stdout = child.stdout.take();
        let finished = async {
            let mut output = Vec::new();
            if let Some(stdout) = stdout {
                stdout
                    .take(MAX_GETENT_OUTPUT)
                    .read_to_end(&mut output)
                    .await
                    .map_err(LookupError::Run)?;
            }
            let status = child.wait().await.map_err(LookupError::Run)?;
            Ok::<_, LookupError>((status, output))
        };
        let (status, output) = tokio::time::timeout(self.timeout, finished)
            .await
            .map_err(|_| LookupError::TimedOut(self.timeout))??;
        match status.code() {
            Some(0) if names_login(&output, login) => Ok(Presence::Present),
            Some(0) => Err(LookupError::Mismatch),
            Some(GETENT_NOT_FOUND) => Ok(Presence::Absent),
            code => Err(LookupError::Exit(code)),
        }
    }
}

fn names_login(output: &[u8], login: &Name) -> bool {
    output
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| line.split(|byte| *byte == b':').next())
        .is_some_and(|name| name == login.as_str().as_bytes())
}

impl PasswdLookup for Getent {
    fn passwd<'a>(&'a self, login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>> {
        Box::pin(self.look_up(login))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use jaunt_host_users::Name;

    use super::{Getent, LookupError, Presence};
    use crate::testkit::eventually;

    type Expected = fn(&Result<Presence, LookupError>) -> bool;

    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("getent");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn alice() -> Name {
        Name::parse("alice").unwrap()
    }

    #[tokio::test]
    async fn getent_answers_map_to_presence_or_an_error() {
        let found = "test \"$1\" = passwd && test \"$2\" = alice && test -z \"$HOME$USER\" \
                     && echo 'alice:x:30001:30001::/home/alice:/bin/bash'";
        let cases: [(&str, Expected); 5] = [
            (found, |answer| matches!(answer, Ok(Presence::Present))),
            ("exit 2", |answer| matches!(answer, Ok(Presence::Absent))),
            ("exit 1", |answer| {
                matches!(answer, Err(LookupError::Exit(Some(1))))
            }),
            ("echo 'alicex:x:1:1::/:/bin/sh'", |answer| {
                matches!(answer, Err(LookupError::Mismatch))
            }),
            ("exit 0", |answer| {
                matches!(answer, Err(LookupError::Mismatch))
            }),
        ];
        for (body, expected) in cases {
            let dir = tempfile::tempdir().unwrap();
            let getent = Getent::with_program(script(dir.path(), body), Duration::from_secs(10));
            let answer = getent.look_up(&alice()).await;
            assert!(expected(&answer), "{body}: {answer:?}");
        }
    }

    fn running(pid: &str) -> bool {
        let shown = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&shown.stdout);
        let state = state.trim();
        !state.is_empty() && !state.starts_with('Z')
    }

    #[tokio::test]
    async fn a_hanging_or_missing_getent_is_an_error_and_a_hanging_one_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let getent = Getent::with_program(
            script(
                dir.path(),
                &format!("echo $$ > '{}'\nexec /bin/sleep 30", pid_file.display()),
            ),
            Duration::from_millis(500),
        );
        let started = Instant::now();
        assert!(matches!(
            getent.look_up(&alice()).await,
            Err(LookupError::TimedOut(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        eventually("the timed out getent to be killed", || !running(pid.trim())).await;
        let absent = Getent::with_program(dir.path().join("nothing"), Duration::from_secs(1));
        assert!(matches!(
            absent.look_up(&alice()).await,
            Err(LookupError::NotInstalled)
        ));
    }
}
