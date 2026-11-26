use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use crate::clock::Clock;
use crate::state::{MAX_STATE_BYTES, State, StateError};

pub const STATE_FILE: &str = "accounts.json";
pub const LOCK_WAIT: Duration = Duration::from_secs(5);

const TEMP_FILE: &str = ".accounts.json.tmp";
const LOCK_FILE: &str = "lock";
const LOCK_POLL: Duration = Duration::from_millis(25);
const GROUP_AND_OTHER_BITS: u32 = 0o077;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{op} {path}: {source}")]
    Io {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{path} is not a directory or is a symbolic link")]
    NotDirectory { path: PathBuf },
    #[error("{path} must belong to uid {owner} and be closed to group and others")]
    Untrusted { path: PathBuf, owner: u32 },
    #[error("{path} is not a regular file with a single link")]
    NotRegular { path: PathBuf },
    #[error("{path} is larger than allowed")]
    TooLarge { path: PathBuf },
    #[error("another request holds the state lock")]
    Busy,
    #[error("{path}: {source}")]
    State {
        path: PathBuf,
        #[source]
        source: StateError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WriteStep {
    TempCreated,
    TempWritten,
    TempSynced,
    Renamed,
    DirectorySynced,
}

#[derive(Debug)]
pub struct StateDir {
    dir: File,
    path: PathBuf,
}

#[derive(Debug)]
pub struct StateLock<'a> {
    dir: &'a StateDir,
    _lock: File,
}

fn io_error(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> StoreError {
    let path = path.to_path_buf();
    move |source| StoreError::Io { op, path, source }
}

fn errno_error(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> StoreError {
    let path = path.to_path_buf();
    move |errno| StoreError::Io {
        op,
        path,
        source: io::Error::from(errno),
    }
}

fn require_single_regular(file: &File, path: &Path) -> Result<(), StoreError> {
    let meta = file.metadata().map_err(io_error("stat", path))?;
    if meta.is_file() && meta.nlink() == 1 {
        Ok(())
    } else {
        Err(StoreError::NotRegular {
            path: path.to_path_buf(),
        })
    }
}

impl StateDir {
    pub fn open(path: &Path, owner: u32) -> Result<Self, StoreError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = rustix::fs::open(path, flags, Mode::empty()).map_err(|errno| match errno {
            Errno::LOOP | Errno::NOTDIR | Errno::MLINK => StoreError::NotDirectory {
                path: path.to_path_buf(),
            },
            errno => errno_error("open", path)(errno),
        })?;
        let dir = File::from(fd);
        let meta = dir.metadata().map_err(io_error("stat", path))?;
        if !meta.is_dir() {
            return Err(StoreError::NotDirectory {
                path: path.to_path_buf(),
            });
        }
        if meta.uid() != owner || meta.mode() & GROUP_AND_OTHER_BITS != 0 {
            return Err(StoreError::Untrusted {
                path: path.to_path_buf(),
                owner,
            });
        }
        Ok(Self {
            dir,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn lock<C: Clock + ?Sized>(
        &self,
        clock: &C,
        wait: Duration,
    ) -> Result<StateLock<'_>, StoreError> {
        let path = self.path.join(LOCK_FILE);
        let fd = rustix::fs::openat(
            &self.dir,
            LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_error("open", &path))?;
        let file = File::from(fd);
        require_single_regular(&file, &path)?;
        let started = clock.now();
        loop {
            match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    return Ok(StateLock {
                        dir: self,
                        _lock: file,
                    });
                }
                Err(Errno::WOULDBLOCK | Errno::INTR) => {}
                Err(errno) => return Err(errno_error("lock", &path)(errno)),
            }
            let waited = clock.now().saturating_duration_since(started);
            if waited >= wait {
                return Err(StoreError::Busy);
            }
            clock.sleep(LOCK_POLL.min(wait.saturating_sub(waited)));
        }
    }
}

impl StateLock<'_> {
    pub fn load(&self) -> Result<State, StoreError> {
        let path = self.dir.path.join(STATE_FILE);
        let fd = match rustix::fs::openat(
            &self.dir.dir,
            STATE_FILE,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(State::default()),
            Err(errno) => return Err(errno_error("open", &path)(errno)),
        };
        let file = File::from(fd);
        require_single_regular(&file, &path)?;
        let limit = u64::try_from(MAX_STATE_BYTES).unwrap_or(u64::MAX);
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_error("read", &path))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StoreError::TooLarge { path });
        }
        State::from_json(&bytes).map_err(|source| StoreError::State { path, source })
    }

    pub fn save(&self, state: &State) -> Result<(), StoreError> {
        self.save_observed(state, &mut |_| {})
    }

    pub(crate) fn save_observed(
        &self,
        state: &State,
        observe: &mut dyn FnMut(WriteStep),
    ) -> Result<(), StoreError> {
        let target = self.dir.path.join(STATE_FILE);
        let temp = self.dir.path.join(TEMP_FILE);
        let bytes = state.to_json().map_err(|source| StoreError::State {
            path: target.clone(),
            source,
        })?;
        match rustix::fs::unlinkat(&self.dir.dir, TEMP_FILE, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(errno) => return Err(errno_error("remove", &temp)(errno)),
        }
        let fd = rustix::fs::openat(
            &self.dir.dir,
            TEMP_FILE,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_error("create", &temp))?;
        let mut file = File::from(fd);
        observe(WriteStep::TempCreated);
        file.write_all(&bytes).map_err(io_error("write", &temp))?;
        observe(WriteStep::TempWritten);
        file.sync_all().map_err(io_error("fsync", &temp))?;
        observe(WriteStep::TempSynced);
        drop(file);
        rustix::fs::renameat(&self.dir.dir, TEMP_FILE, &self.dir.dir, STATE_FILE)
            .map_err(errno_error("rename", &target))?;
        observe(WriteStep::Renamed);
        self.dir
            .dir
            .sync_all()
            .map_err(io_error("fsync", &self.dir.path))?;
        observe(WriteStep::DirectorySynced);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
