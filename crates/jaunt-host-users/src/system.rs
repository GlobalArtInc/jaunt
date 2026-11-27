use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::names::Name;

const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const OTHER_EXECUTE: u32 = 0o001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub kind: FileKind,
    pub uid: u32,
    pub mode: u32,
}

impl FileFacts {
    pub fn writable_by_group_or_others(&self) -> bool {
        self.mode & GROUP_OR_OTHER_WRITE != 0
    }

    pub fn executable_by_others(&self) -> bool {
        self.mode & OTHER_EXECUTE != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: Name,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: Name,
    pub gid: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    #[error("the {database} lookup could not run: {source}")]
    Run {
        database: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("the {database} lookup ended with {}", exit_text(*.exit_code))]
    Exit {
        database: &'static str,
        exit_code: Option<i32>,
    },
    #[error("the {database} lookup returned an unexpected entry")]
    Malformed { database: &'static str },
}

fn exit_text(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("exit code {code}"),
        None => "a signal or a timeout".to_owned(),
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{op} {path}: {source}")]
pub struct FilesError {
    pub op: &'static str,
    pub path: PathBuf,
    #[source]
    pub source: io::Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExit {
    pub code: Option<i32>,
    pub timed_out: bool,
    pub stderr: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
#[error("cannot run {program}: {source}")]
pub struct RunnerError {
    pub program: PathBuf,
    #[source]
    pub source: io::Error,
}

pub trait Users {
    fn passwd(&self, login: &Name) -> Result<Option<PasswdEntry>, LookupError>;
    fn passwd_many(&self, logins: &[Name]) -> Result<Vec<Option<PasswdEntry>>, LookupError>;
    fn group(&self, name: &Name) -> Result<Option<GroupEntry>, LookupError>;
}

pub(crate) fn lookup_many(
    users: &dyn Users,
    logins: &[Name],
) -> Result<Vec<Option<PasswdEntry>>, LookupError> {
    let entries = users.passwd_many(logins)?;
    let aligned = entries.len() == logins.len()
        && entries
            .iter()
            .zip(logins)
            .all(|(entry, login)| entry.as_ref().is_none_or(|entry| entry.name == *login));
    if aligned {
        Ok(entries)
    } else {
        Err(LookupError::Malformed { database: "passwd" })
    }
}

pub trait Files {
    fn lstat(&self, path: &Path) -> Result<Option<FileFacts>, FilesError>;
    fn chmod_directory_nofollow(
        &self,
        path: &Path,
        owner: u32,
        mode: u32,
    ) -> Result<(), FilesError>;
}

pub trait Runner {
    fn run(
        &mut self,
        program: &Path,
        args: &[String],
        timeout: Duration,
    ) -> Result<ToolExit, RunnerError>;
}
