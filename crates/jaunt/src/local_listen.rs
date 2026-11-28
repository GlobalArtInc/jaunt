use std::fs::{self, DirBuilder, File, Permissions};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr as UnixAddr, UnixListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rustix::fs::{FlockOperation, Mode, OFlags, flock, open};
use rustix::io::Errno;
use rustix::process::geteuid;
use ssh_key::rand_core::{OsRng, RngCore};

use crate::service_dial::ServiceName;
use crate::store::{
    DB_DIR, DB_LOCK_FILE, DB_SOCKET_FILE, RUN_DIR_PREFIX, RUN_DIR_RANDOM_HEX, is_run_dir_name,
};

pub const PG_SOCKET_PORT: u16 = 5432;
pub const DEFAULT_LOOPBACK: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
const DIR_MODE: u32 = 0o700;
const SOCKET_MODE: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o777;
const GROUP_OR_OTHER: u32 = 0o077;
const NEW_LOCK_FILE: &str = ".lock.new";
const RUN_DIR_ATTEMPTS: usize = 8;
const LOCK_ATTEMPTS: usize = 4;
const UNFINISHED_AGE: Duration = Duration::from_secs(60);
const PAIR_ATTEMPTS: usize = 8;
const NOT_LOOPBACK: &str = "give a port, 127.0.0.1 or ::1 (with or without a port): any other address or a host name would let other machines connect as you";

#[derive(Debug, thiserror::Error)]
pub enum ListenError {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is a symbolic link; remove it and try again")]
    Symlink { path: PathBuf },
    #[error("{path} is not a directory; remove it and try again")]
    NotADirectory { path: PathBuf },
    #[error("{path} belongs to another user; remove it and try again")]
    ForeignOwner { path: PathBuf },
    #[error("{path} can be used by other users; restrict it with `chmod 700 {path}`")]
    Exposed { path: PathBuf },
    #[error("{path} is not a socket; remove it and try again")]
    NotASocket { path: PathBuf },
    #[error("{path} is not a lock file of yours; remove it and try again")]
    NotALockFile { path: PathBuf },
    #[error("a proxy is already running in {path}")]
    AlreadyRunning { path: PathBuf },
    #[error(
        "cannot lock {path}: {source}; the file system may not support locks, so jaunt cannot tell whether another proxy uses this directory"
    )]
    LockUnsupported { path: PathBuf, source: io::Error },
    #[error("{path} kept changing while jaunt tried to lock it; try again")]
    LockMoved { path: PathBuf },
    #[error("{path} holds files that jaunt did not make; remove it by hand")]
    Foreign { path: PathBuf },
    #[error(
        "{path} is too long for a socket on this system: set JAUNT_HOME to a shorter directory"
    )]
    PathTooLong { path: PathBuf },
    #[error("the socket {path} did not get mode 0600")]
    SocketMode { path: PathBuf },
    #[error("cannot make a private directory in {path}: the system entropy source failed")]
    Entropy { path: PathBuf },
    #[error("cannot make a private directory in {path}: every name tried was taken")]
    NoFreeName { path: PathBuf },
    #[error("cannot listen on {address}: {source}")]
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
    #[error("cannot find a port that is free on both 127.0.0.1 and ::1")]
    NoFreePair,
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> ListenError {
    ListenError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirFacts {
    pub symlink: bool,
    pub directory: bool,
    pub owner: u32,
    pub mode: u32,
}

pub fn check_dir(path: &Path, facts: DirFacts, euid: u32) -> Result<(), ListenError> {
    let path = path.to_owned();
    if facts.symlink {
        return Err(ListenError::Symlink { path });
    }
    if !facts.directory {
        return Err(ListenError::NotADirectory { path });
    }
    if facts.owner != euid {
        return Err(ListenError::ForeignOwner { path });
    }
    if facts.mode & GROUP_OR_OTHER != 0 {
        return Err(ListenError::Exposed { path });
    }
    Ok(())
}

fn inspect_dir(path: &Path) -> Result<(), ListenError> {
    let meta = fs::symlink_metadata(path).map_err(|err| io_error("inspect", path, err))?;
    check_dir(
        path,
        DirFacts {
            symlink: meta.file_type().is_symlink(),
            directory: meta.is_dir(),
            owner: meta.uid(),
            mode: meta.mode(),
        },
        geteuid().as_raw(),
    )
}

fn private_dir(path: &Path) -> Result<(), ListenError> {
    match DirBuilder::new().mode(DIR_MODE).create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_error("create", path, err)),
    }
    inspect_dir(path)
}

fn db_root(profile_dir: &Path) -> Result<PathBuf, ListenError> {
    inspect_dir(profile_dir)?;
    let db = profile_dir.join(DB_DIR);
    private_dir(&db)?;
    Ok(db)
}

fn lock_unsupported(errno: Errno) -> bool {
    errno == Errno::NOLCK
        || errno == Errno::NOTSUP
        || errno == Errno::OPNOTSUPP
        || errno == Errno::NOSYS
        || errno == Errno::INVAL
}

pub fn flock_failure(errno: Errno, path: &Path) -> ListenError {
    if lock_unsupported(errno) {
        ListenError::LockUnsupported {
            path: path.to_owned(),
            source: errno.into(),
        }
    } else {
        io_error("lock", path, errno.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFailure {
    Retry,
    NotALockFile,
    Fail,
}

pub fn classify_open(errno: Errno) -> OpenFailure {
    if errno == Errno::NOENT || errno == Errno::INVAL {
        OpenFailure::Retry
    } else if errno == Errno::LOOP || errno == Errno::MLINK || errno == Errno::ISDIR {
        OpenFailure::NotALockFile
    } else {
        OpenFailure::Fail
    }
}

#[derive(Debug)]
pub enum LockOpenError {
    Gone(io::Error),
    Refused(ListenError),
}

fn checked_lock_file(file: File, path: &Path) -> Result<File, ListenError> {
    let meta = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    if !meta.is_file() || meta.uid() != geteuid().as_raw() {
        return Err(ListenError::NotALockFile {
            path: path.to_owned(),
        });
    }
    Ok(file)
}

pub fn open_lock(path: &Path, flags: OFlags) -> Result<File, LockOpenError> {
    let flags = flags | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    match open(path, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => checked_lock_file(File::from(fd), path).map_err(LockOpenError::Refused),
        Err(errno) => Err(match classify_open(errno) {
            OpenFailure::Retry => LockOpenError::Gone(errno.into()),
            OpenFailure::NotALockFile => LockOpenError::Refused(ListenError::NotALockFile {
                path: path.to_owned(),
            }),
            OpenFailure::Fail => LockOpenError::Refused(io_error("open", path, errno.into())),
        }),
    }
}

fn try_lock(file: &File, path: &Path) -> Result<bool, ListenError> {
    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(Errno::WOULDBLOCK) => Ok(false),
        Err(errno) => Err(flock_failure(errno, path)),
    }
}

fn same_file(file: &File, path: &Path) -> Result<bool, ListenError> {
    let held = file
        .metadata()
        .map_err(|err| io_error("inspect", path, err))?;
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(meta.dev() == held.dev() && meta.ino() == held.ino()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("inspect", path, err)),
    }
}

#[derive(Debug)]
struct HeldLock {
    file: File,
    path: PathBuf,
}

impl HeldLock {
    fn remove(&self) {
        if same_file(&self.file, &self.path).unwrap_or(false) {
            warn_unless_gone(fs::remove_file(&self.path), &self.path);
        }
    }
}

fn warn_unless_gone(outcome: io::Result<()>, path: &Path) {
    if let Err(err) = outcome
        && err.kind() != io::ErrorKind::NotFound
    {
        eprintln!("jaunt: warning: cannot remove {}: {err}", path.display());
    }
}

fn remove_dir_if_empty(path: &Path) {
    match fs::remove_dir(path) {
        Ok(()) => {}
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(err) => eprintln!("jaunt: warning: cannot remove {}: {err}", path.display()),
    }
}

fn remove_socket_file(dir: &Path) {
    let socket = dir.join(DB_SOCKET_FILE);
    if fs::symlink_metadata(&socket).is_ok_and(|meta| meta.file_type().is_socket()) {
        warn_unless_gone(fs::remove_file(&socket), &socket);
    }
}

#[derive(Debug)]
pub struct DatabaseDir {
    path: PathBuf,
    lock: HeldLock,
}

impl DatabaseDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bind(&self) -> Result<(UnixListener, SocketFile), ListenError> {
        bind_locked(&self.path, &self.lock)
    }
}

impl Drop for DatabaseDir {
    fn drop(&mut self) {
        self.lock.remove();
        remove_dir_if_empty(&self.path);
    }
}

pub fn lock_database_dir(
    profile_dir: &Path,
    name: &ServiceName,
) -> Result<DatabaseDir, ListenError> {
    lock_database_dir_with(profile_dir, name, &mut |path| {
        open_lock(path, OFlags::CREATE)
    })
}

fn vanished(err: &ListenError) -> bool {
    matches!(err, ListenError::Io { source, .. } if source.kind() == io::ErrorKind::NotFound)
}

pub fn lock_database_dir_with(
    profile_dir: &Path,
    name: &ServiceName,
    opener: &mut dyn FnMut(&Path) -> Result<File, LockOpenError>,
) -> Result<DatabaseDir, ListenError> {
    let dir = profile_dir.join(DB_DIR).join(name.as_str());
    let lock_path = dir.join(DB_LOCK_FILE);
    let mut last_gone = None;
    for _ in 0..LOCK_ATTEMPTS {
        db_root(profile_dir)?;
        match private_dir(&dir) {
            Ok(()) => {}
            Err(err) if vanished(&err) => continue,
            Err(err) => return Err(err),
        }
        let file = match opener(&lock_path) {
            Ok(file) => file,
            Err(LockOpenError::Gone(err)) => {
                last_gone = Some(err);
                continue;
            }
            Err(LockOpenError::Refused(err)) => return Err(err),
        };
        if !try_lock(&file, &lock_path)? {
            return Err(ListenError::AlreadyRunning { path: dir });
        }
        if same_file(&file, &lock_path)? {
            return Ok(DatabaseDir {
                path: dir,
                lock: HeldLock {
                    file,
                    path: lock_path,
                },
            });
        }
    }
    Err(match last_gone {
        Some(source) => io_error("open", &lock_path, source),
        None => ListenError::LockMoved { path: dir },
    })
}

#[derive(Debug)]
pub struct RunDir {
    path: PathBuf,
    lock: Option<HeldLock>,
}

impl RunDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bind(&self) -> Result<(UnixListener, SocketFile), ListenError> {
        match &self.lock {
            Some(lock) => bind_locked(&self.path, lock),
            None => Err(ListenError::NotALockFile {
                path: self.path.join(DB_LOCK_FILE),
            }),
        }
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        remove_socket_file(&self.path);
        if let Some(lock) = &self.lock {
            lock.remove();
        }
        warn_unless_gone(
            fs::remove_file(self.path.join(NEW_LOCK_FILE)),
            &self.path.join(NEW_LOCK_FILE),
        );
        if let Err(err) = fs::remove_dir(&self.path)
            && err.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "jaunt: warning: cannot remove {}: {err}",
                self.path.display()
            );
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

pub fn run_dir(profile_dir: &Path, now: SystemTime) -> Result<RunDir, ListenError> {
    let db = db_root(profile_dir)?;
    sweep_run_dirs(&db, now);
    for _ in 0..RUN_DIR_ATTEMPTS {
        let mut random = [0_u8; RUN_DIR_RANDOM_HEX / 2];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| ListenError::Entropy { path: db.clone() })?;
        let path = db.join(format!("{RUN_DIR_PREFIX}{}", hex(&random)));
        match DirBuilder::new().mode(DIR_MODE).create(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(io_error("create", &path, err)),
        }
        let mut dir = RunDir { path, lock: None };
        inspect_dir(&dir.path)?;
        let fresh = dir.path.join(NEW_LOCK_FILE);
        let file = match open_lock(&fresh, OFlags::CREATE | OFlags::EXCL) {
            Ok(file) => file,
            Err(LockOpenError::Gone(err)) => return Err(io_error("open", &fresh, err)),
            Err(LockOpenError::Refused(err)) => return Err(err),
        };
        if !try_lock(&file, &fresh)? {
            return Err(ListenError::AlreadyRunning {
                path: dir.path.clone(),
            });
        }
        let lock_path = dir.path.join(DB_LOCK_FILE);
        fs::rename(&fresh, &lock_path).map_err(|err| io_error("rename", &fresh, err))?;
        dir.lock = Some(HeldLock {
            file,
            path: lock_path,
        });
        return Ok(dir);
    }
    Err(ListenError::NoFreeName { path: db })
}

fn sweep_run_dirs(db: &Path, now: SystemTime) {
    let mut failed = 0_usize;
    let mut first: Option<String> = None;
    let mut fail = |what: String| {
        failed += 1;
        first.get_or_insert(what);
    };
    match fs::read_dir(db) {
        Ok(entries) => {
            let euid = geteuid().as_raw();
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        fail(format!("cannot list {}: {err}", db.display()));
                        continue;
                    }
                };
                let matches_pattern = entry.file_name().to_str().is_some_and(is_run_dir_name);
                let path = entry.path();
                let ours = fs::symlink_metadata(&path)
                    .is_ok_and(|meta| meta.is_dir() && meta.uid() == euid);
                if matches_pattern
                    && ours
                    && let Err(err) = clear_stale_run_dir(&path, now)
                {
                    fail(err.to_string());
                }
            }
        }
        Err(err) => fail(format!("cannot list {}: {err}", db.display())),
    }
    if let Some(first) = first {
        eprintln!(
            "jaunt: warning: {failed} stale run directories under {} were left in place; the first: {first}",
            db.display()
        );
    }
}

fn holds_only(path: &Path, allowed: &[&str]) -> Result<bool, ListenError> {
    let entries = fs::read_dir(path).map_err(|err| io_error("list", path, err))?;
    for entry in entries {
        let entry = entry.map_err(|err| io_error("list", path, err))?;
        let known = entry
            .file_name()
            .to_str()
            .is_some_and(|name| allowed.contains(&name));
        if !known {
            return Ok(false);
        }
    }
    Ok(true)
}

fn clear_stale_run_dir(path: &Path, now: SystemTime) -> Result<(), ListenError> {
    let lock_path = path.join(DB_LOCK_FILE);
    let file = match open_lock(&lock_path, OFlags::empty()) {
        Ok(file) => file,
        Err(LockOpenError::Gone(_)) => return clear_unfinished_run_dir(path, now),
        Err(LockOpenError::Refused(err)) => return Err(err),
    };
    if !try_lock(&file, &lock_path)? || !same_file(&file, &lock_path)? {
        return Ok(());
    }
    if !holds_only(path, &[DB_LOCK_FILE, DB_SOCKET_FILE])? {
        return Err(ListenError::Foreign {
            path: path.to_owned(),
        });
    }
    remove_socket_file(path);
    fs::remove_file(&lock_path).map_err(|err| io_error("remove", &lock_path, err))?;
    fs::remove_dir(path).map_err(|err| io_error("remove", path, err))
}

fn clear_unfinished_run_dir(path: &Path, now: SystemTime) -> Result<(), ListenError> {
    let fresh = path.join(NEW_LOCK_FILE);
    let file = match open_lock(&fresh, OFlags::empty()) {
        Ok(file) => file,
        Err(LockOpenError::Gone(_)) => return Ok(()),
        Err(LockOpenError::Refused(err)) => return Err(err),
    };
    let modified = file
        .metadata()
        .and_then(|meta| meta.modified())
        .map_err(|err| io_error("inspect", &fresh, err))?;
    let settled = now
        .duration_since(modified)
        .is_ok_and(|age| age >= UNFINISHED_AGE);
    if !settled || !try_lock(&file, &fresh)? || !same_file(&file, &fresh)? {
        return Ok(());
    }
    if !holds_only(path, &[NEW_LOCK_FILE])? {
        return Err(ListenError::Foreign {
            path: path.to_owned(),
        });
    }
    fs::remove_file(&fresh).map_err(|err| io_error("remove", &fresh, err))?;
    fs::remove_dir(path).map_err(|err| io_error("remove", path, err))
}

#[derive(Debug)]
pub struct SocketFile {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketFile {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        let ours = fs::symlink_metadata(&self.path)
            .is_ok_and(|meta| meta.dev() == self.device && meta.ino() == self.inode);
        if ours && let Err(err) = fs::remove_file(&self.path) {
            eprintln!(
                "jaunt: warning: cannot remove {}: {err}",
                self.path.display()
            );
        }
    }
}

fn bind_locked(dir: &Path, _lock: &HeldLock) -> Result<(UnixListener, SocketFile), ListenError> {
    let path = dir.join(DB_SOCKET_FILE);
    if UnixAddr::from_pathname(&path).is_err() {
        return Err(ListenError::PathTooLong { path });
    }
    remove_stale_socket(&path)?;
    let listener = UnixListener::bind(&path).map_err(|err| io_error("listen on", &path, err))?;
    let meta = fs::symlink_metadata(&path).map_err(|err| io_error("inspect", &path, err))?;
    let file = SocketFile {
        path,
        device: meta.dev(),
        inode: meta.ino(),
    };
    fs::set_permissions(&file.path, Permissions::from_mode(SOCKET_MODE))
        .map_err(|err| io_error("restrict", &file.path, err))?;
    let meta =
        fs::symlink_metadata(&file.path).map_err(|err| io_error("inspect", &file.path, err))?;
    let private = meta.file_type().is_socket()
        && meta.dev() == file.device
        && meta.ino() == file.inode
        && meta.uid() == geteuid().as_raw()
        && meta.mode() & PERMISSION_BITS == SOCKET_MODE;
    if !private {
        return Err(ListenError::SocketMode {
            path: file.path.clone(),
        });
    }
    listener
        .set_nonblocking(true)
        .map_err(|err| io_error("listen on", &file.path, err))?;
    Ok((listener, file))
}

fn remove_stale_socket(path: &Path) -> Result<(), ListenError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(io_error("remove the stale socket", path, err)),
        },
        Ok(_) => Err(ListenError::NotASocket {
            path: path.to_owned(),
        }),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(io_error("inspect", path, err)),
    }
}

pub fn is_allowed_loopback(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

pub fn parse_loopback(text: &str) -> Result<SocketAddr, String> {
    let address = if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        let port = text
            .parse::<u16>()
            .map_err(|_| format!("{text} is not a port from 0 to 65535"))?;
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    } else if let Ok(address) = text.parse::<SocketAddr>() {
        address
    } else if let Ok(ip) = text.parse::<IpAddr>() {
        SocketAddr::new(ip, 0)
    } else {
        return Err(NOT_LOOPBACK.to_owned());
    };
    if is_allowed_loopback(address.ip()) {
        Ok(address)
    } else {
        Err(NOT_LOOPBACK.to_owned())
    }
}

pub fn bind_loopback(address: SocketAddr) -> Result<TcpListener, ListenError> {
    if !is_allowed_loopback(address.ip()) {
        return Err(ListenError::Bind {
            address,
            source: io::Error::from(io::ErrorKind::PermissionDenied),
        });
    }
    let listener =
        TcpListener::bind(address).map_err(|source| ListenError::Bind { address, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenError::Bind { address, source })?;
    Ok(listener)
}

pub fn bind_loopback_pair(port: u16) -> Result<Vec<TcpListener>, ListenError> {
    for _ in 0..PAIR_ATTEMPTS {
        let v4 = bind_loopback(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))?;
        let chosen = v4
            .local_addr()
            .map_err(|source| ListenError::Bind {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                source,
            })?
            .port();
        let v6_address = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), chosen);
        match bind_loopback(v6_address) {
            Ok(v6) => return Ok(vec![v4, v6]),
            Err(ListenError::Bind { source, .. })
                if source.kind() == io::ErrorKind::AddrInUse && port == 0 => {}
            Err(ListenError::Bind { source, .. }) if source.kind() == io::ErrorKind::AddrInUse => {
                return Err(ListenError::Bind {
                    address: v6_address,
                    source,
                });
            }
            Err(_) => return Ok(vec![v4]),
        }
    }
    Err(ListenError::NoFreePair)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::SocketAddr;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use rustix::fs::OFlags;
    use rustix::io::Errno;

    use super::{
        DirFacts, ListenError, LockOpenError, OpenFailure, bind_loopback, check_dir, classify_open,
        flock_failure, lock_database_dir, lock_database_dir_with, open_lock, parse_loopback,
    };
    use crate::service_dial::ServiceName;

    fn private_profile() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("default");
        fs::create_dir(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        (root, profile)
    }

    #[test]
    fn a_lock_file_that_vanishes_while_its_directory_is_made_again_is_tried_again() {
        let cases = [
            (Errno::NOENT, OpenFailure::Retry),
            (Errno::INVAL, OpenFailure::Retry),
            (Errno::LOOP, OpenFailure::NotALockFile),
            (Errno::ISDIR, OpenFailure::NotALockFile),
            (Errno::ACCESS, OpenFailure::Fail),
        ];
        for (errno, expected) in cases {
            assert_eq!(classify_open(errno), expected, "{errno:?}");
        }
        let name = ServiceName::parse("orders").unwrap();
        for errno in [Errno::NOENT, Errno::INVAL] {
            let (_root, profile) = private_profile();
            let mut calls = 0;

            let locked = lock_database_dir_with(&profile, &name, &mut |path| {
                calls += 1;
                if calls == 1 {
                    Err(LockOpenError::Gone(errno.into()))
                } else {
                    open_lock(path, OFlags::CREATE)
                }
            })
            .unwrap();

            assert_eq!(calls, 2, "{errno:?}");
            drop(locked);
            let mut tries = 0;
            let persistent = lock_database_dir_with(&profile, &name, &mut |_| {
                tries += 1;
                Err(LockOpenError::Gone(errno.into()))
            })
            .unwrap_err();
            assert_eq!(tries, 4, "{errno:?}");
            let text = persistent.to_string();
            assert!(
                text.starts_with("cannot open ")
                    && text.contains("/db/orders/.lock")
                    && text.ends_with(&std::io::Error::from(errno).to_string()),
                "{text}"
            );
        }
    }

    #[test]
    fn a_file_system_without_locks_is_named_as_such() {
        let path = Path::new("/home/a/.jaunt/default/db/orders/.lock");
        for errno in [
            Errno::NOLCK,
            Errno::NOTSUP,
            Errno::OPNOTSUPP,
            Errno::NOSYS,
            Errno::INVAL,
        ] {
            let text = flock_failure(errno, path).to_string();
            assert!(text.contains("may not support locks"), "{errno:?}: {text}");
            assert!(
                text.starts_with("cannot lock /home/a/"),
                "{errno:?}: {text}"
            );
        }
        let other = flock_failure(Errno::IO, path).to_string();
        assert!(!other.contains("may not support locks"), "{other}");
    }

    #[test]
    fn a_lock_file_that_was_replaced_is_left_to_its_new_owner() {
        let (_root, profile) = private_profile();
        let name = ServiceName::parse("orders").unwrap();
        let locked = lock_database_dir(&profile, &name).unwrap();
        let lock = locked.path().join(".lock");
        let replacement = locked.path().join("replacement");
        fs::write(&replacement, "theirs").unwrap();
        fs::rename(&replacement, &lock).unwrap();

        drop(locked);

        assert_eq!(fs::read_to_string(&lock).unwrap(), "theirs");
    }

    const ME: u32 = 501;

    #[test]
    fn a_socket_directory_must_be_a_plain_private_directory_of_this_user() {
        let good = DirFacts {
            symlink: false,
            directory: true,
            owner: ME,
            mode: 0o40700,
        };
        let path = Path::new("/home/a/.jaunt/default/db/orders");
        assert!(check_dir(path, good, ME).is_ok());
        type Expected = fn(&ListenError) -> bool;
        let cases: Vec<(DirFacts, Expected)> = vec![
            (
                DirFacts {
                    symlink: true,
                    ..good
                },
                |err| matches!(err, ListenError::Symlink { .. }),
            ),
            (
                DirFacts {
                    directory: false,
                    ..good
                },
                |err| matches!(err, ListenError::NotADirectory { .. }),
            ),
            (DirFacts { owner: 0, ..good }, |err| {
                matches!(err, ListenError::ForeignOwner { .. })
            }),
            (
                DirFacts {
                    mode: 0o40750,
                    ..good
                },
                |err| matches!(err, ListenError::Exposed { .. }),
            ),
            (
                DirFacts {
                    mode: 0o40701,
                    ..good
                },
                |err| matches!(err, ListenError::Exposed { .. }),
            ),
            (
                DirFacts {
                    mode: 0o40770,
                    ..good
                },
                |err| matches!(err, ListenError::Exposed { .. }),
            ),
        ];
        for (facts, expected) in cases {
            let err = check_dir(path, facts, ME).unwrap_err();
            assert!(expected(&err), "{facts:?}: {err}");
        }
    }

    #[test]
    fn only_one_proxy_holds_a_socket_directory_and_the_last_one_out_removes_it() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("default");
        fs::create_dir(&profile).unwrap();
        fs::set_permissions(&profile, fs::Permissions::from_mode(0o700)).unwrap();
        let name = ServiceName::parse("orders").unwrap();

        let first = lock_database_dir(&profile, &name).unwrap();
        let second = lock_database_dir(&profile, &name).unwrap_err();

        assert!(
            matches!(&second, ListenError::AlreadyRunning { path } if path == first.path()),
            "{second}"
        );
        assert!(second.to_string().contains("/db/orders"), "{second}");
        let dir = first.path().to_owned();
        drop(first);
        assert!(!dir.exists());
        let again = lock_database_dir(&profile, &name).unwrap();
        assert_eq!(again.path(), dir);

        fs::set_permissions(&profile, fs::Permissions::from_mode(0o755)).unwrap();
        drop(again);
        let exposed = lock_database_dir(&profile, &name).unwrap_err();
        assert!(
            matches!(&exposed, ListenError::Exposed { path } if path == &profile),
            "{exposed}"
        );
    }

    #[test]
    fn only_the_two_loopback_addresses_are_accepted_for_a_local_tcp_listener() {
        let accepted = [
            ("5433", "127.0.0.1:5433"),
            ("0", "127.0.0.1:0"),
            ("127.0.0.1", "127.0.0.1:0"),
            ("127.0.0.1:6543", "127.0.0.1:6543"),
            ("::1", "[::1]:0"),
            ("[::1]:6543", "[::1]:6543"),
        ];
        for (given, expected) in accepted {
            assert_eq!(
                parse_loopback(given),
                Ok(expected.parse::<SocketAddr>().unwrap()),
                "{given}"
            );
        }
        for refused in [
            "",
            "65536",
            "0.0.0.0",
            "0.0.0.0:5432",
            "10.0.0.1:5432",
            "127.0.0.2",
            "127.1",
            "[::]:5432",
            "::",
            "[::ffff:127.0.0.1]:5432",
            "localhost",
            "localhost:5432",
            "example.com:5432",
            "5432x",
            "-1",
        ] {
            assert!(parse_loopback(refused).is_err(), "{refused:?}");
        }
        for refused in ["0.0.0.0:0", "[::]:0", "127.0.0.2:0"] {
            let address: SocketAddr = refused.parse().unwrap();
            assert!(
                matches!(bind_loopback(address), Err(ListenError::Bind { .. })),
                "{refused}"
            );
        }
    }
}
