use std::ffi::{OsStr, OsString};
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, NaiveDateTime};
use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::Errno;
use rustix::process::geteuid;

pub const LOCK_WAIT: Duration = Duration::from_secs(60);
pub const KEPT_BACKUPS: usize = 5;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const NEW_FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;
const PERMISSION_BITS: u32 = 0o777;
const KEPT_MODE_LIMIT: u32 = 0o644;
const OWNER_WRITE: u32 = 0o200;
const BACKUP_INFIX: &str = ".jaunt-backup-";
const BACKUP_STAMP: &str = "%Y%m%dT%H%M%SZ";
const BACKUP_STAMP_LEN: usize = 16;
const BACKUP_ATTEMPTS: i64 = 60;
const LOCK_SUFFIX: &str = ".jaunt-lock";
const LOCK_OPEN_ATTEMPTS: usize = 100;
const POLL: Duration = Duration::from_millis(50);

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is not a regular file")]
    NotARegularFile { path: PathBuf },
    #[error("{path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("{path} is a link to {target}, which is not a regular file")]
    LinkTarget { path: PathBuf, target: PathBuf },
    #[error("{path} is a link to a file that does not exist")]
    DanglingLink { path: PathBuf },
    #[error("{path} belongs to another user")]
    ForeignOwner { path: PathBuf },
    #[error("{path} is read-only, so it was left unchanged")]
    ReadOnly { path: PathBuf },
    #[error("{path} is larger than 8 MiB, so it was left unchanged")]
    TooLarge { path: PathBuf },
    #[error("the new content of {path} would be larger than 8 MiB, so the file was left unchanged")]
    ResultTooLarge { path: PathBuf },
    #[error(
        "{path} has other hard links; jaunt replaces the file by renaming a new one over it, which would cut those links, so it was left unchanged; make it a single file or a symbolic link first"
    )]
    HardLinked { path: PathBuf },
    #[error("the directory {path} does not exist")]
    MissingDirectory { path: PathBuf },
    #[error("{path} changed while jaunt waited to edit it; run the command again")]
    Changed { path: PathBuf },
    #[error("another jaunt command is still editing {path}; try again later")]
    LockTimedOut { path: PathBuf },
    #[error("{path} is not a regular file owned by you; remove it and try again")]
    UnsafeLock { path: PathBuf },
    #[error("no free backup name is left next to {path}")]
    BackupNames { path: PathBuf },
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> FileError {
    FileError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub requested: PathBuf,
    pub real: PathBuf,
    pub via_link: bool,
}

pub type Rename = dyn Fn(&Path, &Path) -> io::Result<()>;

pub struct FilePorts<'a> {
    pub clock: &'a dyn Fn() -> SystemTime,
    pub rename: &'a Rename,
    pub lock_wait: Duration,
    pub on_wait: &'a mut dyn FnMut(&Path),
}

pub type Change<'a, T, E> = dyn FnMut(Option<&[u8]>) -> Result<Planned<T>, E> + 'a;

pub struct Planned<T> {
    pub contents: Option<Vec<u8>>,
    pub report: T,
}

#[derive(Debug)]
pub struct Edited<T> {
    pub report: T,
    pub located: Located,
    pub written: bool,
    pub created: bool,
    pub backup: Option<PathBuf>,
    pub warnings: Vec<String>,
}

fn owned_by_me(meta: &Metadata) -> bool {
    meta.uid() == geteuid().as_raw()
}

pub fn locate(path: &Path) -> Result<Located, FileError> {
    let requested = std::path::absolute(path).map_err(|err| io_error("resolve", path, err))?;
    let meta = match fs::symlink_metadata(&requested) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(Located {
                real: requested.clone(),
                requested,
                via_link: false,
            });
        }
        Err(err) => return Err(io_error("inspect", &requested, err)),
    };
    if meta.file_type().is_symlink() {
        let target = match fs::canonicalize(&requested) {
            Ok(target) => target,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(FileError::DanglingLink { path: requested });
            }
            Err(err) => return Err(io_error("resolve", &requested, err)),
        };
        let target_meta =
            fs::symlink_metadata(&target).map_err(|err| io_error("inspect", &target, err))?;
        if !target_meta.is_file() {
            return Err(FileError::LinkTarget {
                path: requested,
                target,
            });
        }
        if !owned_by_me(&target_meta) {
            return Err(FileError::ForeignOwner { path: target });
        }
        return Ok(Located {
            requested,
            real: target,
            via_link: true,
        });
    }
    if !meta.is_file() {
        return Err(FileError::NotARegularFile { path: requested });
    }
    if !owned_by_me(&meta) {
        return Err(FileError::ForeignOwner { path: requested });
    }
    Ok(Located {
        real: requested.clone(),
        requested,
        via_link: false,
    })
}

fn split(real: &Path) -> Result<(&Path, &OsStr), FileError> {
    match (real.parent(), real.file_name()) {
        (Some(directory), Some(name)) => Ok((directory, name)),
        _ => Err(FileError::NotARegularFile {
            path: real.to_owned(),
        }),
    }
}

fn directory_exists(directory: &Path) -> Result<bool, FileError> {
    match fs::metadata(directory) {
        Ok(meta) if meta.is_dir() => Ok(true),
        Ok(_) => Err(FileError::NotADirectory {
            path: directory.to_owned(),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("inspect", directory, err)),
    }
}

fn create_directory(directory: &Path) -> Result<(), FileError> {
    match DirBuilder::new().mode(DIR_MODE).create(directory) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Err(FileError::MissingDirectory {
            path: directory.parent().unwrap_or(directory).to_owned(),
        }),
        Err(err) => Err(io_error("create", directory, err)),
    }
}

struct Current {
    bytes: Vec<u8>,
    mode: u32,
    links: u64,
}

fn read_current(path: &Path) -> Result<Option<Current>, FileError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP | Errno::MLINK) => {
            return Err(FileError::NotARegularFile {
                path: path.to_owned(),
            });
        }
        Err(errno) => return Err(io_error("open", path, errno.into())),
    };
    let meta = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    if !meta.is_file() {
        return Err(FileError::NotARegularFile {
            path: path.to_owned(),
        });
    }
    if !owned_by_me(&meta) {
        return Err(FileError::ForeignOwner {
            path: path.to_owned(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("read", path, err))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(FileError::TooLarge {
            path: path.to_owned(),
        });
    }
    Ok(Some(Current {
        bytes,
        mode: meta.mode(),
        links: meta.nlink(),
    }))
}

pub fn peek(path: &Path) -> Result<Option<Vec<u8>>, FileError> {
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(io_error("open", path, errno.into())),
    };
    let meta = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    if !meta.is_file() {
        return Err(FileError::NotARegularFile {
            path: path.to_owned(),
        });
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| io_error("read", path, err))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(FileError::TooLarge {
            path: path.to_owned(),
        });
    }
    Ok(Some(bytes))
}

pub fn kept_mode(original: u32) -> u32 {
    let bits = original & PERMISSION_BITS;
    if bits & !KEPT_MODE_LIMIT == 0 {
        bits
    } else {
        NEW_FILE_MODE
    }
}

fn sibling(name: &OsStr, prefix: &str, suffix: &str) -> OsString {
    let mut joined = OsString::from(prefix);
    joined.push(name);
    joined.push(suffix);
    joined
}

pub fn backup_name(name: &OsStr, at_secs: i64) -> Option<OsString> {
    let stamp = DateTime::from_timestamp(at_secs, 0)?
        .format(BACKUP_STAMP)
        .to_string();
    (stamp.len() == BACKUP_STAMP_LEN).then(|| sibling(name, "", &format!("{BACKUP_INFIX}{stamp}")))
}

fn backup_stamp<'a>(name: &OsStr, candidate: &'a OsStr) -> Option<&'a [u8]> {
    candidate
        .as_bytes()
        .strip_prefix(name.as_bytes())
        .and_then(|rest| rest.strip_prefix(BACKUP_INFIX.as_bytes()))
}

fn backup_secs(name: &OsStr, candidate: &OsStr) -> Option<i64> {
    let text = std::str::from_utf8(backup_stamp(name, candidate)?).ok()?;
    NaiveDateTime::parse_from_str(text, BACKUP_STAMP)
        .ok()
        .map(|at| at.and_utc().timestamp())
}

fn unix_secs(at: SystemTime) -> i64 {
    DateTime::<chrono::Utc>::from(at).timestamp()
}

fn own_backups(directory: &Path, name: &OsStr) -> Result<Vec<OsString>, FileError> {
    let entries = fs::read_dir(directory).map_err(|err| io_error("list", directory, err))?;
    Ok(entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|candidate| is_backup_name(name, candidate))
        .filter(|candidate| {
            fs::symlink_metadata(directory.join(candidate))
                .is_ok_and(|meta| meta.is_file() && owned_by_me(&meta))
        })
        .collect())
}

pub fn is_backup_name(name: &OsStr, candidate: &OsStr) -> bool {
    let stamp = backup_stamp(name, candidate);
    stamp.is_some_and(|stamp| {
        stamp.len() == BACKUP_STAMP_LEN
            && stamp.iter().enumerate().all(|(index, byte)| match index {
                8 => *byte == b'T',
                15 => *byte == b'Z',
                _ => byte.is_ascii_digit(),
            })
    })
}

fn write_backup(
    directory: &Path,
    name: &OsStr,
    original: &[u8],
    now: SystemTime,
) -> Result<PathBuf, FileError> {
    let newest = own_backups(directory, name)?
        .iter()
        .filter_map(|candidate| backup_secs(name, candidate))
        .max();
    let now = unix_secs(now);
    let first = newest.map_or(now, |newest| now.max(newest.saturating_add(1)));
    for offset in 0..BACKUP_ATTEMPTS {
        let Some(backup) = first
            .checked_add(offset)
            .and_then(|at| backup_name(name, at))
        else {
            break;
        };
        let path = directory.join(backup);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(NEW_FILE_MODE)
            .open(&path)
        {
            Ok(mut file) => {
                if let Err(err) = file.write_all(original).and_then(|()| file.sync_all()) {
                    drop(fs::remove_file(&path));
                    return Err(io_error("write", &path, err));
                }
                return Ok(path);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(io_error("create", &path, err)),
        }
    }
    Err(FileError::BackupNames {
        path: directory.join(name),
    })
}

fn prune_backups(directory: &Path, name: &OsStr, written: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut backups = match own_backups(directory, name) {
        Ok(backups) => backups,
        Err(err) => {
            warnings.push(format!("warning: old backups were not checked: {err}"));
            return warnings;
        }
    };
    backups.retain(|candidate| Some(candidate.as_os_str()) != written.file_name());
    backups.sort_unstable_by(|left, right| right.cmp(left));
    for old in backups.into_iter().skip(KEPT_BACKUPS.saturating_sub(1)) {
        let path = directory.join(old);
        if let Err(err) = fs::remove_file(&path) {
            warnings.push(format!(
                "warning: the old backup {} was not removed: {err}",
                path.display()
            ));
        }
    }
    warnings
}

fn write_temporary(
    directory: &Path,
    name: &OsStr,
    contents: &[u8],
    mode: u32,
) -> Result<PathBuf, FileError> {
    let serial = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = directory.join(sibling(
        name,
        ".",
        &format!(".jaunt-tmp.{}.{serial}", std::process::id()),
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(NEW_FILE_MODE)
        .open(&path)
        .map_err(|err| io_error("create", &path, err))?;
    let written = file
        .write_all(contents)
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all());
    if let Err(err) = written {
        drop(fs::remove_file(&path));
        return Err(io_error("write", &path, err));
    }
    Ok(path)
}

fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory).and_then(|handle| handle.sync_all())
}

pub struct SiblingLock {
    file: File,
    path: PathBuf,
    created: bool,
}

fn open_lock(path: &Path) -> Result<(File, bool), FileError> {
    let unsafe_lock = || FileError::UnsafeLock {
        path: path.to_owned(),
    };
    for _ in 0..LOCK_OPEN_ATTEMPTS {
        let base = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (opened, created) = match open(
            path,
            base | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => (fd, true),
            Err(Errno::EXIST) => match open(path, base, Mode::empty()) {
                Ok(fd) => (fd, false),
                Err(Errno::NOENT) => continue,
                Err(Errno::LOOP | Errno::MLINK | Errno::ISDIR) => return Err(unsafe_lock()),
                Err(errno) => return Err(io_error("open", path, errno.into())),
            },
            Err(errno) => return Err(io_error("create", path, errno.into())),
        };
        let file = File::from(opened);
        let meta = file
            .metadata()
            .map_err(|err| io_error("inspect", path, err))?;
        if !meta.is_file() || !owned_by_me(&meta) {
            return Err(unsafe_lock());
        }
        return Ok((file, created));
    }
    Err(unsafe_lock())
}

fn still_at(path: &Path, file: &File) -> Result<bool, FileError> {
    let held = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.dev() == held.dev() && meta.ino() == held.ino()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("inspect", path, err)),
    }
}

impl SiblingLock {
    pub fn lock_path(directory: &Path, name: &OsStr) -> PathBuf {
        directory.join(sibling(name, ".", LOCK_SUFFIX))
    }

    pub fn acquire(
        directory: &Path,
        name: &OsStr,
        wait: Duration,
        on_wait: &mut dyn FnMut(&Path),
    ) -> Result<SiblingLock, FileError> {
        let path = SiblingLock::lock_path(directory, name);
        let target = directory.join(name);
        let deadline = Instant::now()
            .checked_add(wait)
            .unwrap_or_else(Instant::now);
        let mut announced = false;
        loop {
            let (file, created) = open_lock(&path)?;
            loop {
                match flock(&file, FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => break,
                    Err(Errno::WOULDBLOCK) => {}
                    Err(errno) => return Err(io_error("lock", &path, errno.into())),
                }
                if !announced {
                    announced = true;
                    on_wait(&target);
                }
                if Instant::now() >= deadline {
                    return Err(FileError::LockTimedOut { path: target });
                }
                thread::sleep(POLL);
            }
            if still_at(&path, &file)? {
                return Ok(SiblingLock {
                    file,
                    path,
                    created,
                });
            }
        }
    }

    fn remove_if_created(&mut self) -> Result<(), FileError> {
        if !self.created {
            return Ok(());
        }
        self.created = false;
        if still_at(&self.path, &self.file)? {
            fs::remove_file(&self.path).map_err(|err| io_error("remove", &self.path, err))?;
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<(), FileError> {
        self.remove_if_created()
    }
}

impl Drop for SiblingLock {
    fn drop(&mut self) {
        drop(self.remove_if_created());
    }
}

pub fn edit<T, E: From<FileError>>(
    path: &Path,
    ports: &mut FilePorts<'_>,
    change: &mut Change<'_, T, E>,
) -> Result<Edited<T>, E> {
    let located = locate(path)?;
    let (directory, name) = split(&located.real)?;
    let unchanged = |report: T, located: Located, warnings: Vec<String>| Edited {
        report,
        located,
        written: false,
        created: false,
        backup: None,
        warnings,
    };
    let directory_present = directory_exists(directory)?;
    let unlocked = if directory_present {
        read_current(&located.real)?
    } else {
        None
    };
    let preview = change(unlocked.as_ref().map(|current| current.bytes.as_slice()))?;
    if preview.contents.is_none() {
        return Ok(unchanged(preview.report, located, Vec::new()));
    }
    if !directory_present {
        create_directory(directory)?;
    }
    let lock = SiblingLock::acquire(directory, name, ports.lock_wait, ports.on_wait)?;
    if locate(path)? != located {
        return Err(FileError::Changed {
            path: located.requested,
        }
        .into());
    }
    let current = read_current(&located.real)?;
    let planned = change(current.as_ref().map(|current| current.bytes.as_slice()))?;
    let Some(contents) = planned.contents else {
        let warnings = lock
            .release()
            .err()
            .map(|err| format!("warning: {err}"))
            .into_iter()
            .collect();
        return Ok(unchanged(planned.report, located, warnings));
    };
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_BYTES {
        return Err(FileError::ResultTooLarge { path: located.real }.into());
    }
    let (mode, backup) = match &current {
        Some(current) => {
            if current.mode & OWNER_WRITE == 0 {
                return Err(FileError::ReadOnly { path: located.real }.into());
            }
            if current.links > 1 {
                return Err(FileError::HardLinked { path: located.real }.into());
            }
            let backup = write_backup(directory, name, &current.bytes, (ports.clock)())?;
            (kept_mode(current.mode), Some(backup))
        }
        None => (NEW_FILE_MODE, None),
    };
    let temporary = write_temporary(directory, name, &contents, mode)?;
    if let Err(err) = (ports.rename)(&temporary, &located.real) {
        drop(fs::remove_file(&temporary));
        return Err(io_error("replace", &located.real, err).into());
    }
    let mut warnings = Vec::new();
    if let Err(err) = sync_directory(directory) {
        warnings.push(format!(
            "warning: {} was written but its directory could not be flushed: {err}",
            located.real.display()
        ));
    }
    if let Some(written) = &backup {
        warnings.extend(prune_backups(directory, name, written));
    }
    if let Err(err) = lock.release() {
        warnings.push(format!("warning: {err}"));
    }
    Ok(Edited {
        report: planned.report,
        located,
        written: true,
        created: current.is_none(),
        backup,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{
        Edited, FileError, FilePorts, MAX_BYTES, Planned, Rename, SiblingLock, backup_name, edit,
        is_backup_name, kept_mode, read_current,
    };

    const AT: u64 = 1_800_000_000;
    const STAMP: &str = "config.jaunt-backup-20270115T080000Z";

    fn real_rename(from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn failing_rename(_: &Path, _: &Path) -> io::Result<()> {
        Err(io::Error::other("injected rename failure"))
    }

    fn clock() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(AT)
    }

    type Plan<'a> = dyn FnMut(Option<&[u8]>) -> Option<Vec<u8>> + 'a;

    fn change(
        path: &Path,
        rename: &Rename,
        wait: Duration,
        planned: &mut Plan<'_>,
    ) -> Result<Edited<()>, FileError> {
        let mut on_wait = |_: &Path| {};
        let mut ports = FilePorts {
            clock: &clock,
            rename,
            lock_wait: wait,
            on_wait: &mut on_wait,
        };
        edit(path, &mut ports, &mut |current| {
            Ok::<_, FileError>(Planned {
                contents: planned(current),
                report: (),
            })
        })
    }

    fn append(path: &Path, line: &str) -> Result<Edited<()>, FileError> {
        change(
            path,
            &real_rename,
            Duration::from_secs(60),
            &mut |current| {
                let mut contents = current.map(<[u8]>::to_vec).unwrap_or_default();
                contents.extend_from_slice(line.as_bytes());
                Some(contents)
            },
        )
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn existing(dir: &Path, content: &str, file_mode: u32) -> std::path::PathBuf {
        let path = dir.join("config");
        fs::write(&path, content).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(file_mode)).unwrap();
        path
    }

    #[test]
    fn a_new_file_and_its_missing_directory_are_created_private_with_nothing_left_behind() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join(".kube");
        let path = dir.join("config");

        let edited = append(&path, "a\n").unwrap();

        assert!(edited.written && edited.created && edited.backup.is_none());
        assert_eq!(fs::read_to_string(&path).unwrap(), "a\n");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(names(&dir), ["config"]);

        let untouched = root.path().join("missing");
        let nothing = change(
            &untouched.join("config"),
            &real_rename,
            Duration::from_secs(5),
            &mut |_| None,
        )
        .unwrap();
        assert!(!nothing.written);
        assert!(!untouched.exists());
        let deep = append(&root.path().join("x/y/config"), "a\n");
        assert!(
            matches!(deep, Err(FileError::MissingDirectory { .. })),
            "{deep:?}"
        );
    }

    #[test]
    fn the_original_is_backed_up_first_and_only_the_five_newest_backups_are_kept() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        let path = existing(dir, "original\n", 0o640);
        for second in 0..6 {
            fs::write(
                dir.join(format!("config.jaunt-backup-20200101T00000{second}Z")),
                "old",
            )
            .unwrap();
        }
        let strangers = [
            "config.jaunt-backup-2020",
            "config.jaunt-backup-20200101T000000Z.old",
            "other.jaunt-backup-20200101T000000Z",
            "xconfig.jaunt-backup-20200101T000000Z",
        ];
        for name in strangers {
            fs::write(dir.join(name), "keep").unwrap();
        }
        fs::create_dir(dir.join("config.jaunt-backup-19990101T000000Z")).unwrap();

        let edited = append(&path, "new\n").unwrap();

        let backup = edited.backup.unwrap();
        assert_eq!(backup, dir.join(STAMP));
        assert_eq!(
            backup_name(OsStr::new("config"), i64::try_from(AT).unwrap()),
            Some(STAMP.into())
        );
        assert_eq!(fs::read_to_string(&backup).unwrap(), "original\n");
        assert_eq!(mode(&backup), 0o600);
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\nnew\n");
        assert_eq!(mode(&path), 0o640);
        let kept: Vec<String> = names(dir)
            .into_iter()
            .filter(|name| is_backup_name(OsStr::new("config"), OsStr::new(name)))
            .collect();
        assert_eq!(
            kept,
            [
                "config.jaunt-backup-19990101T000000Z",
                "config.jaunt-backup-20200101T000002Z",
                "config.jaunt-backup-20200101T000003Z",
                "config.jaunt-backup-20200101T000004Z",
                "config.jaunt-backup-20200101T000005Z",
                STAMP,
            ]
        );
        assert!(dir.join("config.jaunt-backup-19990101T000000Z").is_dir());
        for name in strangers {
            assert_eq!(
                fs::read_to_string(dir.join(name)).unwrap(),
                "keep",
                "{name}"
            );
        }
    }

    #[test]
    fn backups_stamped_after_the_clock_never_push_out_the_one_just_written() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        let path = existing(dir, "0\n", 0o600);
        let at = i64::try_from(AT).unwrap();
        for ahead in 100..105 {
            let name = backup_name(OsStr::new("config"), at + ahead).unwrap();
            fs::write(dir.join(name), "later").unwrap();
        }

        for round in 1..=12 {
            let before = fs::read_to_string(&path).unwrap();
            let edited = append(&path, &format!("{round}\n")).unwrap();

            let backup = edited.backup.unwrap();
            assert_eq!(fs::read_to_string(&backup).unwrap(), before, "{round}");
            let expected = backup_name(OsStr::new("config"), at + 104 + round).unwrap();
            assert_eq!(backup.file_name(), Some(expected.as_os_str()), "{round}");
            let kept = names(dir)
                .into_iter()
                .filter(|name| is_backup_name(OsStr::new("config"), OsStr::new(name)))
                .count();
            assert_eq!(kept, 5, "{round}");
        }
    }

    #[test]
    fn an_input_or_a_result_over_the_size_limit_leaves_the_file_untouched() {
        let root = tempfile::tempdir().unwrap();
        let limit = usize::try_from(MAX_BYTES).unwrap();
        let path = root.path().join("config");
        let oversized = vec![b'#'; limit + 1];
        fs::write(&path, &oversized).unwrap();

        let input = append(&path, "x");

        assert!(
            matches!(input, Err(FileError::TooLarge { .. })),
            "{input:?}"
        );
        assert_eq!(fs::read(&path).unwrap(), oversized);
        fs::write(&path, "small\n").unwrap();
        let result = change(&path, &real_rename, Duration::from_secs(5), &mut |_| {
            Some(vec![b'#'; limit + 1])
        });
        assert!(
            matches!(result, Err(FileError::ResultTooLarge { .. })),
            "{result:?}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "small\n");
        assert_eq!(names(root.path()), ["config"]);
    }

    #[test]
    fn a_hard_linked_file_is_never_replaced_and_a_link_is_never_read_as_the_file() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "original\n", 0o600);
        let other_name = root.path().join("other-name");
        fs::hard_link(&path, &other_name).unwrap();

        let refused = append(&path, "new\n");
        let unchanged = change(&path, &real_rename, Duration::from_secs(5), &mut |_| None);

        assert!(
            matches!(refused, Err(FileError::HardLinked { .. })),
            "{refused:?}"
        );
        assert!(refused.unwrap_err().to_string().contains("hard links"));
        assert!(!unchanged.unwrap().written);
        assert_eq!(fs::read_to_string(&other_name).unwrap(), "original\n");
        assert_eq!(names(root.path()), ["config", "other-name"]);
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(matches!(
            read_current(&link),
            Err(FileError::NotARegularFile { .. })
        ));
    }

    #[test]
    fn a_waiter_on_a_lock_file_removed_by_its_creator_takes_a_fresh_one() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path();
        let name = OsStr::new("config");
        let first = SiblingLock::acquire(dir, name, Duration::from_secs(5), &mut |_| {}).unwrap();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (held_tx, held_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel::<()>();

        thread::scope(|scope| {
            scope.spawn(move || {
                let waiter = SiblingLock::acquire(dir, name, Duration::from_secs(30), &mut |_| {
                    waiting_tx.send(()).ok();
                })
                .unwrap();
                held_tx.send(()).unwrap();
                done_rx.recv_timeout(Duration::from_secs(30)).unwrap();
                waiter.release().unwrap();
            });
            waiting_rx.recv_timeout(Duration::from_secs(30)).unwrap();
            first.release().unwrap();
            held_rx.recv_timeout(Duration::from_secs(30)).unwrap();

            let started = Instant::now();
            let third = SiblingLock::acquire(dir, name, Duration::from_millis(300), &mut |_| {});

            assert!(
                matches!(third, Err(FileError::LockTimedOut { .. })),
                "a third holder got in while the waiter held the lock"
            );
            assert!(started.elapsed() < Duration::from_secs(20));
            done_tx.send(()).unwrap();
        });
        assert!(!SiblingLock::lock_path(dir, name).exists());
    }

    #[test]
    fn an_existing_backup_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "original\n", 0o600);
        fs::write(root.path().join(STAMP), "precious").unwrap();

        let edited = append(&path, "new\n").unwrap();

        assert_eq!(
            edited.backup.unwrap(),
            root.path().join("config.jaunt-backup-20270115T080001Z")
        );
        assert_eq!(
            fs::read_to_string(root.path().join(STAMP)).unwrap(),
            "precious"
        );
    }

    #[test]
    fn a_failing_rename_leaves_the_original_intact_after_the_backup() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "original\n", 0o640);

        let outcome = change(&path, &failing_rename, Duration::from_secs(5), &mut |_| {
            Some(b"replacement\n".to_vec())
        });

        assert!(
            matches!(
                &outcome,
                Err(FileError::Io {
                    action: "replace",
                    ..
                })
            ),
            "{outcome:?}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
        assert_eq!(mode(&path), 0o640);
        assert_eq!(names(root.path()), ["config", STAMP]);
        assert_eq!(
            fs::read_to_string(root.path().join(STAMP)).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn nothing_is_written_or_backed_up_when_the_change_is_empty() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "same\n", 0o644);

        let edited = change(&path, &failing_rename, Duration::from_secs(5), &mut |_| {
            None
        })
        .unwrap();

        assert!(!edited.written && edited.backup.is_none());
        assert_eq!(names(root.path()), ["config"]);
    }

    #[test]
    fn a_mode_up_to_0644_is_kept_a_wider_one_becomes_0600_and_read_only_is_refused() {
        for (before, after) in [
            (0o600, 0o600),
            (0o640, 0o640),
            (0o644, 0o644),
            (0o604, 0o604),
            (0o664, 0o600),
            (0o666, 0o600),
            (0o755, 0o600),
            (0o4644, 0o644),
        ] {
            assert_eq!(kept_mode(before), after, "{before:o}");
        }
        for read_only in [0o400, 0o444] {
            let root = tempfile::tempdir().unwrap();
            let path = existing(root.path(), "original\n", read_only);

            let outcome = append(&path, "new\n");

            assert!(
                matches!(outcome, Err(FileError::ReadOnly { .. })),
                "{outcome:?}"
            );
            assert_eq!(names(root.path()), ["config"]);
            assert_eq!(mode(&path), read_only);
        }
    }

    #[test]
    fn a_link_to_an_own_file_is_written_through_and_other_links_or_types_are_refused() {
        let root = tempfile::tempdir().unwrap();
        let dotfiles = root.path().join("dotfiles");
        let kube = root.path().join("kube");
        fs::create_dir(&dotfiles).unwrap();
        fs::create_dir(&kube).unwrap();
        let real = existing(&dotfiles, "original\n", 0o640);
        let link = kube.join("config");
        symlink(&real, &link).unwrap();

        let edited = append(&link, "new\n").unwrap();

        assert!(edited.located.via_link);
        assert_eq!(edited.located.real, fs::canonicalize(&real).unwrap());
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&real).unwrap(), "original\nnew\n");
        assert_eq!(mode(&real), 0o640);
        assert_eq!(names(&kube), ["config"]);
        assert_eq!(names(&dotfiles), ["config", STAMP]);

        let dangling = kube.join("dangling");
        symlink(root.path().join("nowhere"), &dangling).unwrap();
        let to_directory = kube.join("directory");
        symlink(&dotfiles, &to_directory).unwrap();
        let directory = kube.join("plain-directory");
        fs::create_dir(&directory).unwrap();
        let refused = [
            (append(&dangling, "x"), "dangling"),
            (append(&to_directory, "x"), "directory"),
            (append(&directory, "x"), "plain"),
        ];
        for (outcome, case) in refused {
            let fitting = matches!(
                (&outcome, case),
                (Err(FileError::DanglingLink { .. }), "dangling")
                    | (Err(FileError::LinkTarget { .. }), "directory")
                    | (Err(FileError::NotARegularFile { .. }), "plain")
            );
            assert!(fitting, "{case}: {outcome:?}");
        }
        assert!(!root.path().join("nowhere").exists());
        assert_eq!(names(&dotfiles), ["config", STAMP]);
    }

    #[test]
    fn concurrent_edits_lose_nothing_and_the_lock_file_is_removed_unless_it_was_there() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config");
        let writers = 8;

        thread::scope(|scope| {
            for writer in 0..writers {
                let path = &path;
                scope.spawn(move || append(path, &format!("{writer}\n")).unwrap());
            }
        });

        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        lines.sort();
        let expected: Vec<String> = (0..writers).map(|writer| writer.to_string()).collect();
        assert_eq!(lines, expected);
        let lock = SiblingLock::lock_path(root.path(), OsStr::new("config"));
        assert!(!lock.exists());
        fs::write(&lock, "").unwrap();
        append(&path, "more\n").unwrap();
        assert!(lock.exists());
    }

    #[test]
    fn a_held_lock_makes_the_edit_wait_and_give_up_at_its_deadline() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "original\n", 0o600);
        let held = SiblingLock::acquire(
            root.path(),
            OsStr::new("config"),
            Duration::from_secs(5),
            &mut |_| {},
        )
        .unwrap();
        let waits = AtomicUsize::new(0);
        let mut on_wait = |_: &Path| {
            waits.fetch_add(1, Ordering::SeqCst);
        };
        let mut ports = FilePorts {
            clock: &clock,
            rename: &real_rename,
            lock_wait: Duration::from_millis(300),
            on_wait: &mut on_wait,
        };

        let outcome = edit(&path, &mut ports, &mut |_| {
            Ok::<_, FileError>(Planned {
                contents: Some(b"changed\n".to_vec()),
                report: (),
            })
        });

        assert!(
            matches!(outcome, Err(FileError::LockTimedOut { .. })),
            "{outcome:?}"
        );
        assert_eq!(waits.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
        held.release().unwrap();
        assert_eq!(names(root.path()), ["config"]);
    }

    #[test]
    fn a_lock_path_that_is_a_link_or_a_directory_is_refused_without_following_it() {
        let root = tempfile::tempdir().unwrap();
        let path = existing(root.path(), "original\n", 0o600);
        let lock = SiblingLock::lock_path(root.path(), OsStr::new("config"));
        let target = root.path().join("elsewhere");
        symlink(&target, &lock).unwrap();

        let linked = append(&path, "x");

        assert!(
            matches!(linked, Err(FileError::UnsafeLock { .. })),
            "{linked:?}"
        );
        assert!(!target.exists());
        fs::remove_file(&lock).unwrap();
        fs::create_dir(&lock).unwrap();
        assert!(matches!(
            append(&path, "x"),
            Err(FileError::UnsafeLock { .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    }

    #[test]
    fn only_names_that_match_the_backup_pattern_exactly_count_as_backups() {
        let name = OsStr::new("config");
        for (candidate, matches) in [
            ("config.jaunt-backup-20270115T080000Z", true),
            ("config.jaunt-backup-00000000T000000Z", true),
            ("config.jaunt-backup-20270115T080000", false),
            ("config.jaunt-backup-20270115T0800000Z", false),
            ("config.jaunt-backup-20270115t080000Z", false),
            ("config.jaunt-backup-2027011aT080000Z", false),
            ("config.jaunt-backup-20270115T080000Z~", false),
            ("config.jaunt-backup-", false),
            ("config", false),
            ("other.jaunt-backup-20270115T080000Z", false),
        ] {
            assert_eq!(
                is_backup_name(name, OsStr::new(candidate)),
                matches,
                "{candidate}"
            );
        }
    }
}
