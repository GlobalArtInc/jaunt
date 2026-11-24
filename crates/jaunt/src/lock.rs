use std::fs::{self, DirBuilder, File};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::Errno;
use rustix::process::geteuid;

const DIR_MODE: u32 = 0o700;
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is not a regular file owned by you; remove it and try again")]
    Unsafe { path: PathBuf },
    #[error("{path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("another sign-in of this profile is still running; try again later")]
    TimedOut,
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> LockError {
    LockError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug)]
pub struct ProfileLock {
    _held: File,
    path: PathBuf,
}

impl ProfileLock {
    pub fn acquire(
        home: &Path,
        path: &Path,
        deadline: Instant,
        on_wait: &mut dyn FnMut(),
    ) -> Result<ProfileLock, LockError> {
        prepare_home(home)?;
        let file = open_lock_file(path)?;
        let mut announced = false;
        loop {
            match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => {
                    return Ok(ProfileLock {
                        _held: file,
                        path: path.to_owned(),
                    });
                }
                Err(Errno::WOULDBLOCK) => {}
                Err(errno) => return Err(io_error("lock", path, errno.into())),
            }
            if !announced {
                announced = true;
                on_wait();
            }
            if Instant::now() >= deadline {
                return Err(LockError::TimedOut);
            }
            thread::sleep(POLL);
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn prepare_home(home: &Path) -> Result<(), LockError> {
    match fs::metadata(home) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(LockError::NotADirectory {
            path: home.to_owned(),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(home)
            .map_err(|err| io_error("create", home, err)),
        Err(err) => Err(io_error("inspect", home, err)),
    }
}

fn open_lock_file(path: &Path) -> Result<File, LockError> {
    let flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match open(path, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => File::from(fd),
        Err(Errno::LOOP | Errno::MLINK | Errno::ISDIR) => {
            return Err(LockError::Unsafe {
                path: path.to_owned(),
            });
        }
        Err(errno) => return Err(io_error("open", path, errno.into())),
    };
    let meta = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    if !meta.is_file() || meta.uid() != geteuid().as_raw() {
        return Err(LockError::Unsafe {
            path: path.to_owned(),
        });
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{Duration, Instant};

    use super::{LockError, ProfileLock};

    fn soon() -> Instant {
        Instant::now() + Duration::from_millis(250)
    }

    #[test]
    fn a_second_holder_waits_once_then_times_out_and_the_file_stays() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("state");
        let path = home.join(".default.lock");

        let first = ProfileLock::acquire(&home, &path, soon(), &mut || {}).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut waits = 0;
        let second = ProfileLock::acquire(&home, &path, soon(), &mut || waits += 1);

        assert!(matches!(second, Err(LockError::TimedOut)), "{second:?}");
        assert_eq!(waits, 1);
        drop(first);
        assert!(path.is_file());
        let mut waits = 0;
        ProfileLock::acquire(&home, &path, soon(), &mut || waits += 1).unwrap();
        assert_eq!(waits, 0);
    }

    #[test]
    fn a_symlink_or_a_directory_in_place_of_the_lock_is_refused_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("elsewhere");
        let linked = root.path().join(".default.lock");
        symlink(&target, &linked).unwrap();
        let directory = root.path().join(".work.lock");
        fs::create_dir(&directory).unwrap();

        for path in [&linked, &directory] {
            let refused = ProfileLock::acquire(root.path(), path, soon(), &mut || {});
            assert!(
                matches!(refused, Err(LockError::Unsafe { .. })),
                "{refused:?}"
            );
        }
        assert!(!target.exists());
    }

    #[test]
    fn a_fifo_in_place_of_the_lock_is_refused_without_hanging() {
        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join(".default.lock");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            eprintln!("skipped: mkfifo is not available");
            return;
        }

        let started = Instant::now();
        let refused = ProfileLock::acquire(root.path(), &fifo, soon(), &mut || {});

        assert!(
            matches!(refused, Err(LockError::Unsafe { .. })),
            "{refused:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
