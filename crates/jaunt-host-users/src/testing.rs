use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::panic::resume_unwind;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::clock::Clock;
use crate::config::{HostUsersConfig, Settings, parse_agent_file};
use crate::names::Name;
use crate::rules::Candidate;
use crate::state::State;
use crate::system::{
    FileFacts, FileKind, Files, FilesError, GroupEntry, LookupError, PasswdEntry, Runner,
    RunnerError, ToolExit, Users,
};
use crate::verify::{Verified, verify_created};

pub const NOW: u64 = 1_764_000_000;
pub const BLOCKING_LIMIT: Duration = Duration::from_secs(10);

pub fn name(value: &str) -> Name {
    Name::parse(value).unwrap()
}

pub fn within<T, F>(what: &str, work: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    let worker = thread::spawn(move || sender.send(work()).is_ok());
    match receiver.recv_timeout(BLOCKING_LIMIT) {
        Ok(value) => value,
        Err(RecvTimeoutError::Timeout) => {
            panic!("{what} still blocks after {BLOCKING_LIMIT:?}")
        }
        Err(RecvTimeoutError::Disconnected) => match worker.join() {
            Err(payload) => resume_unwind(payload),
            Ok(_) => panic!("{what} ended without a result"),
        },
    }
}

pub fn enabled_config(extra: &str) -> HostUsersConfig {
    let text = format!("host_users:\n  enabled: true\n{extra}");
    match parse_agent_file(&text).unwrap().settings().unwrap() {
        Settings::Enabled(config) => config,
        Settings::Disabled => panic!("expected an enabled section"),
    }
}

pub fn candidate(config: &HostUsersConfig, login: &str) -> Candidate {
    let login = name(login);
    let home = config.home_of(&login);
    Candidate::new(login, home)
}

pub fn created_entries(
    config: &HostUsersConfig,
    candidate: &Candidate,
    uid: u32,
) -> (PasswdEntry, GroupEntry, FileFacts) {
    let passwd = PasswdEntry {
        name: candidate.login().clone(),
        uid,
        gid: uid,
        home: candidate.home().to_owned(),
        shell: config.shell().to_owned(),
    };
    let group = GroupEntry {
        name: candidate.login().clone(),
        gid: uid,
    };
    let home = FileFacts {
        kind: FileKind::Directory,
        uid,
        mode: 0o750,
    };
    (passwd, group, home)
}

pub fn verified(config: &HostUsersConfig, candidate: &Candidate, uid: u32) -> Verified {
    let (passwd, group, home) = created_entries(config, candidate, uid);
    verify_created(config, candidate, Some(&passwd), Some(&group), Some(&home)).unwrap()
}

pub fn record(login: &str, uid: Option<u32>, state: &str) -> Value {
    let mut record = json!({
        "login": login,
        "home": format!("/home/{login}"),
        "created_at": NOW,
        "ref": "H-0000000A",
        "session": "s-1",
        "state": state,
    });
    if let Some(uid) = uid {
        record["uid"] = json!(uid);
        record["gid"] = json!(uid);
    }
    record
}

pub fn state_of(records: Vec<Value>, attempts: &[u64]) -> State {
    let file = json!({"v": 1, "accounts": records, "attempts": attempts});
    State::from_json(file.to_string().as_bytes()).unwrap()
}

#[derive(Default)]
pub struct FakeUsers {
    passwd: BTreeMap<String, PasswdEntry>,
    groups: BTreeMap<String, GroupEntry>,
    broken: bool,
    lookups: Cell<usize>,
    batches: Cell<usize>,
}

impl FakeUsers {
    pub fn with_account(mut self, login: &str, uid: u32) -> Self {
        self.passwd.insert(
            login.to_owned(),
            PasswdEntry {
                name: name(login),
                uid,
                gid: uid,
                home: format!("/home/{login}"),
                shell: "/bin/bash".to_owned(),
            },
        );
        self
    }

    pub fn with_group(mut self, group: &str, gid: u32) -> Self {
        self.groups.insert(
            group.to_owned(),
            GroupEntry {
                name: name(group),
                gid,
            },
        );
        self
    }

    pub fn broken() -> Self {
        Self {
            broken: true,
            ..Self::default()
        }
    }

    pub fn lookups(&self) -> usize {
        self.lookups.get()
    }

    pub fn batches(&self) -> usize {
        self.batches.get()
    }

    fn check(&self, database: &'static str) -> Result<(), LookupError> {
        if self.broken {
            Err(LookupError::Exit {
                database,
                exit_code: Some(1),
            })
        } else {
            Ok(())
        }
    }
}

impl Users for FakeUsers {
    fn passwd(&self, login: &Name) -> Result<Option<PasswdEntry>, LookupError> {
        self.lookups.set(self.lookups.get() + 1);
        self.check("passwd")?;
        Ok(self.passwd.get(login.as_str()).cloned())
    }

    fn passwd_many(&self, logins: &[Name]) -> Result<Vec<Option<PasswdEntry>>, LookupError> {
        self.batches.set(self.batches.get() + 1);
        self.check("passwd")?;
        Ok(logins
            .iter()
            .map(|login| self.passwd.get(login.as_str()).cloned())
            .collect())
    }

    fn group(&self, group: &Name) -> Result<Option<GroupEntry>, LookupError> {
        self.lookups.set(self.lookups.get() + 1);
        self.check("group")?;
        Ok(self.groups.get(group.as_str()).cloned())
    }
}

#[derive(Default)]
pub struct FakeFiles {
    entries: RefCell<BTreeMap<PathBuf, FileFacts>>,
}

impl FakeFiles {
    pub fn with(self, path: &str, kind: FileKind, uid: u32, mode: u32) -> Self {
        self.entries
            .borrow_mut()
            .insert(PathBuf::from(path), FileFacts { kind, uid, mode });
        self
    }

    pub fn root_dirs(self, paths: &[&str]) -> Self {
        paths.iter().fold(self, |files, path| {
            files.with(path, FileKind::Directory, 0, 0o755)
        })
    }

    pub fn without(self, path: &str) -> Self {
        self.entries.borrow_mut().remove(Path::new(path));
        self
    }
}

impl Files for FakeFiles {
    fn lstat(&self, path: &Path) -> Result<Option<FileFacts>, FilesError> {
        Ok(self.entries.borrow().get(path).copied())
    }

    fn chmod_directory_nofollow(
        &self,
        path: &Path,
        owner: u32,
        mode: u32,
    ) -> Result<(), FilesError> {
        match self.entries.borrow_mut().get_mut(path) {
            Some(facts) if facts.kind == FileKind::Directory && facts.uid == owner => {
                facts.mode = mode;
                Ok(())
            }
            _ => Err(FilesError {
                op: "chmod",
                path: path.to_path_buf(),
                source: io::Error::from(io::ErrorKind::NotFound),
            }),
        }
    }
}

pub struct FakeClock {
    start: Instant,
    elapsed: Cell<Duration>,
    sleeps: Cell<usize>,
}

impl FakeClock {
    pub fn started() -> Self {
        Self {
            start: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
            sleeps: Cell::new(0),
        }
    }

    pub fn advance(&self, by: Duration) {
        self.elapsed.set(self.elapsed.get() + by);
    }

    pub fn elapsed(&self) -> Duration {
        self.elapsed.get()
    }

    pub fn sleeps(&self) -> usize {
        self.sleeps.get()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.start + self.elapsed.get()
    }

    fn sleep(&self, duration: Duration) {
        self.sleeps.set(self.sleeps.get() + 1);
        self.advance(duration);
    }
}

pub struct FakeRunner {
    pub exit: ToolExit,
    pub calls: Vec<(PathBuf, Vec<String>, Duration)>,
}

impl FakeRunner {
    pub fn exiting(code: Option<i32>) -> Self {
        Self {
            exit: ToolExit {
                code,
                timed_out: false,
                stderr: Vec::new(),
            },
            calls: Vec::new(),
        }
    }
}

impl Runner for FakeRunner {
    fn run(
        &mut self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> Result<ToolExit, RunnerError> {
        self.calls
            .push((program.to_path_buf(), args.to_vec(), timeout));
        Ok(self.exit.clone())
    }
}
