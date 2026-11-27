use std::fs::{self, File, Metadata, Permissions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::ROOT_UID;
use super::tools::{Tool, ToolError, locate};
use crate::config::{
    ConfigError, MAX_CONFIG_BYTES, Settings, SyntaxLocation, TrustProblem, check_config_trust,
    parse_agent_file, trust_problem,
};
use crate::directory::{DirectoryUse, detect_directory};
use crate::serve::Node;
use crate::system::{FileFacts, FileKind, Files, FilesError};

const SHELLS_FILE: &str = "/etc/shells";
const NSSWITCH_FILE: &str = "/etc/nsswitch.conf";
const SSSD_CONFIG: &str = "/etc/sssd/sssd.conf";
const MAX_SYSTEM_FILE_BYTES: usize = 64 * 1024;
const PERMISSION_BITS: u32 = 0o7777;

#[derive(Debug, thiserror::Error)]
#[error("the directory belongs to uid {actual} instead of uid {expected}")]
struct OwnerMismatch {
    expected: u32,
    actual: u32,
}

pub(crate) fn facts_of(meta: &Metadata) -> FileFacts {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        FileKind::Symlink
    } else if file_type.is_dir() {
        FileKind::Directory
    } else if file_type.is_file() {
        FileKind::Regular
    } else {
        FileKind::Other
    };
    FileFacts {
        kind,
        uid: meta.uid(),
        mode: meta.mode() & PERMISSION_BITS,
    }
}

fn files_error(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> FilesError {
    let path = path.to_path_buf();
    move |source| FilesError { op, path, source }
}

fn read_limited(reader: impl Read, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader.take(cap).read_to_end(&mut bytes)?;
    Ok((bytes.len() <= limit).then_some(bytes))
}

pub(crate) struct SystemFiles;

impl Files for SystemFiles {
    fn lstat(&self, path: &Path) -> Result<Option<FileFacts>, FilesError> {
        match fs::symlink_metadata(path) {
            Ok(meta) => Ok(Some(facts_of(&meta))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(files_error("lstat", path)(source)),
        }
    }

    fn chmod_directory_nofollow(
        &self,
        path: &Path,
        owner: u32,
        mode: u32,
    ) -> Result<(), FilesError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let directory = rustix::fs::open(path, flags, Mode::empty())
            .map(File::from)
            .map_err(|errno| files_error("open", path)(errno.into()))?;
        let meta = directory.metadata().map_err(files_error("fstat", path))?;
        if !meta.is_dir() {
            return Err(files_error("fstat", path)(io::Error::from(
                io::ErrorKind::NotADirectory,
            )));
        }
        if meta.uid() != owner {
            return Err(files_error("check the owner of", path)(io::Error::other(
                OwnerMismatch {
                    expected: owner,
                    actual: meta.uid(),
                },
            )));
        }
        directory
            .set_permissions(Permissions::from_mode(mode))
            .map_err(files_error("fchmod", path))
    }
}

fn open_trusted_config(path: &Path) -> Result<File, ConfigError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(|errno| match errno {
        Errno::LOOP => ConfigError::Untrusted {
            path: path.to_path_buf(),
            problem: TrustProblem::Symlink,
        },
        Errno::NOENT => ConfigError::Missing {
            path: path.to_path_buf(),
        },
        errno => ConfigError::Files(files_error("open", path)(errno.into())),
    })?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(files_error("fstat", path))?;
    match trust_problem(&facts_of(&meta), FileKind::Regular) {
        None => Ok(file),
        Some(problem) => Err(ConfigError::Untrusted {
            path: path.to_path_buf(),
            problem,
        }),
    }
}

pub(crate) fn read_agent_config(path: &Path) -> Result<String, ConfigError> {
    check_config_trust(path, &SystemFiles)?;
    let file = open_trusted_config(path)?;
    let bytes = read_limited(&file, MAX_CONFIG_BYTES)
        .map_err(files_error("read", path))?
        .ok_or(ConfigError::TooLarge)?;
    String::from_utf8(bytes).map_err(|_| ConfigError::Syntax {
        at: SyntaxLocation {
            line: None,
            column: None,
        },
    })
}

fn read_system_file(path: &Path) -> Result<Option<String>, FilesError> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(files_error("open", path)(errno.into())),
    };
    let file = File::from(fd);
    let meta = file.metadata().map_err(files_error("fstat", path))?;
    if !meta.is_file() {
        return Err(files_error("read", path)(io::Error::from(
            io::ErrorKind::InvalidInput,
        )));
    }
    let bytes = read_limited(&file, MAX_SYSTEM_FILE_BYTES)
        .map_err(files_error("read", path))?
        .ok_or_else(|| files_error("read", path)(io::Error::from(io::ErrorKind::FileTooLarge)))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| files_error("read", path)(io::Error::from(io::ErrorKind::InvalidData)))
}

pub(crate) struct SystemNode {
    config: PathBuf,
}

impl SystemNode {
    pub(crate) fn new(config: &Path) -> Self {
        Self {
            config: config.to_path_buf(),
        }
    }
}

impl Node for SystemNode {
    fn settings(&self) -> Result<Settings, ConfigError> {
        let text = read_agent_config(&self.config)?;
        parse_agent_file(&text)?.settings()
    }

    fn shells(&self) -> Result<String, FilesError> {
        Ok(read_system_file(Path::new(SHELLS_FILE))?.unwrap_or_default())
    }

    fn directory(&self) -> Result<DirectoryUse, FilesError> {
        let nsswitch = read_system_file(Path::new(NSSWITCH_FILE))?;
        let sssd_configured = SystemFiles.lstat(Path::new(SSSD_CONFIG))?.is_some();
        Ok(detect_directory(nsswitch.as_deref(), sssd_configured))
    }

    fn tool(&self, tool: &Tool) -> Result<PathBuf, ToolError> {
        locate(tool, ROOT_UID)
    }
}

#[cfg(test)]
mod tests;
