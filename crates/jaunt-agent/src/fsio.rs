use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use zeroize::Zeroizing;

pub const PRIVATE_DIR_MODE: u32 = 0o700;
pub const PRIVATE_FILE_MODE: u32 = 0o600;
const PARENT_DIR_MODE: u32 = 0o755;
const GROUP_AND_OTHER_BITS: u32 = 0o077;

#[derive(Debug, thiserror::Error)]
#[error("{op} {path}: {source}")]
pub struct FsError {
    pub op: &'static str,
    pub path: PathBuf,
    #[source]
    pub source: io::Error,
}

impl FsError {
    pub fn is_not_found(&self) -> bool {
        self.source.kind() == io::ErrorKind::NotFound
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("{path} is a symbolic link; pass the real directory")]
    Symlink { path: PathBuf },
    #[error("{path} exists and is not a directory")]
    NotDirectory { path: PathBuf },
    #[error("{path} does not exist")]
    Missing { path: PathBuf },
    #[error(transparent)]
    Fs(#[from] FsError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owner {
    pub uid: u32,
    pub gid: u32,
}

fn fs_error(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> FsError {
    let path = path.to_path_buf();
    move |source| FsError { op, path, source }
}

fn errno_error(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> FsError {
    let path = path.to_path_buf();
    move |errno| FsError {
        op,
        path,
        source: io::Error::from(errno),
    }
}

fn refused(op: &'static str, path: &Path, reason: &'static str) -> FsError {
    FsError {
        op,
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, reason),
    }
}

fn require_regular(file: &File, path: &Path, single_link: bool) -> Result<(), FsError> {
    let meta = file.metadata().map_err(fs_error("stat", path))?;
    if !meta.is_file() {
        return Err(refused("open", path, "is not a regular file"));
    }
    if single_link && meta.nlink() != 1 {
        return Err(refused("open", path, "has more than one hard link"));
    }
    Ok(())
}

pub fn running_as_root() -> bool {
    rustix::process::geteuid().is_root()
}

pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub fn normalize(path: &Path) -> PathBuf {
    path.components().collect()
}

pub fn temp_name(name: &str) -> String {
    format!(".{name}.{}.tmp", std::process::id())
}

#[derive(Debug)]
pub struct DirHandle {
    dir: File,
    path: PathBuf,
}

impl DirHandle {
    pub fn open(path: &Path) -> Result<Self, DirError> {
        let path = normalize(path);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(DirError::Symlink { path }),
            Ok(meta) if !meta.is_dir() => Err(DirError::NotDirectory { path }),
            Ok(_) => Self::open_nofollow(path),
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                Err(DirError::Missing { path })
            }
            Err(source) => Err(fs_error("stat", &path)(source).into()),
        }
    }

    pub fn create_or_open(path: &Path) -> Result<(Self, bool), DirError> {
        let path = normalize(path);
        match Self::open(&path) {
            Ok(handle) => return Ok((handle, false)),
            Err(DirError::Missing { .. }) => {}
            Err(error) => return Err(error),
        }
        if let Some(parent) = path.parent() {
            DirBuilder::new()
                .recursive(true)
                .mode(PARENT_DIR_MODE)
                .create(parent)
                .map_err(fs_error("mkdir", parent))?;
        }
        let created = match DirBuilder::new().mode(PRIVATE_DIR_MODE).create(&path) {
            Ok(()) => true,
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => false,
            Err(source) => return Err(fs_error("mkdir", &path)(source).into()),
        };
        let handle = Self::open_nofollow(path)?;
        if created {
            handle.set_mode(PRIVATE_DIR_MODE)?;
        }
        Ok((handle, created))
    }

    fn open_nofollow(path: PathBuf) -> Result<Self, DirError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match rustix::fs::open(&path, flags, Mode::empty()) {
            Ok(fd) => Ok(Self {
                dir: File::from(fd),
                path,
            }),
            Err(Errno::LOOP | Errno::MLINK) => Err(DirError::Symlink { path }),
            Err(Errno::NOTDIR) => {
                let is_link =
                    fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink());
                if is_link {
                    Err(DirError::Symlink { path })
                } else {
                    Err(DirError::NotDirectory { path })
                }
            }
            Err(errno) => Err(errno_error("open", &path)(errno).into()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn checked(&self, name: &str) -> Result<PathBuf, FsError> {
        let plain = !name.is_empty()
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\0');
        if plain {
            Ok(self.path.join(name))
        } else {
            Err(FsError {
                op: "name",
                path: self.path.clone(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "not a plain file name"),
            })
        }
    }

    pub fn owner(&self) -> Result<Owner, FsError> {
        let meta = self.dir.metadata().map_err(fs_error("stat", &self.path))?;
        Ok(Owner {
            uid: meta.uid(),
            gid: meta.gid(),
        })
    }

    pub fn mode(&self) -> Result<u32, FsError> {
        let meta = self.dir.metadata().map_err(fs_error("stat", &self.path))?;
        Ok(meta.mode() & 0o7777)
    }

    fn set_mode(&self, mode: u32) -> Result<(), FsError> {
        self.dir
            .set_permissions(Permissions::from_mode(mode))
            .map_err(fs_error("chmod", &self.path))
    }

    pub fn remove_group_and_other_access(&self) -> Result<(), FsError> {
        let mode = self.mode()?;
        if mode & GROUP_AND_OTHER_BITS == 0 {
            return Ok(());
        }
        self.set_mode(mode & !GROUP_AND_OTHER_BITS & 0o7777)
    }

    pub fn entries(&self) -> Result<Vec<OsString>, FsError> {
        let reader =
            rustix::fs::Dir::read_from(&self.dir).map_err(errno_error("read", &self.path))?;
        let mut names = Vec::new();
        for entry in reader {
            let entry = entry.map_err(errno_error("read", &self.path))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(OsString::from_vec(name.to_vec()));
            }
        }
        Ok(names)
    }

    pub fn exists(&self, name: &str) -> Result<bool, FsError> {
        let path = self.checked(name)?;
        match rustix::fs::statat(&self.dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(errno) => Err(errno_error("stat", &path)(errno)),
        }
    }

    pub fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, FsError> {
        let path = self.checked(name)?;
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno_error("open", &path))?;
        let mut file = File::from(fd);
        require_regular(&file, &path, false)?;
        let mut content = Zeroizing::new(Vec::new());
        file.read_to_end(&mut content)
            .map_err(fs_error("read", &path))?;
        Ok(content)
    }

    fn create_exclusive(&self, name: &str) -> Result<File, FsError> {
        let path = self.checked(name)?;
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_error("create", &path))?;
        Ok(File::from(fd))
    }

    fn remove_if_present(&self, name: &str) -> Result<(), FsError> {
        let path = self.checked(name)?;
        match rustix::fs::unlinkat(&self.dir, name, AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(errno) => Err(errno_error("remove", &path)(errno)),
        }
    }

    pub fn sync(&self) -> Result<(), FsError> {
        self.dir.sync_all().map_err(fs_error("fsync", &self.path))
    }

    pub fn probe_writable(&self) -> Result<(), FsError> {
        let probe = temp_name("write-check");
        self.remove_if_present(&probe)?;
        drop(self.create_exclusive(&probe)?);
        self.remove_if_present(&probe)
    }

    pub fn lock(&self, name: &str, owner: Option<Owner>) -> Result<Option<File>, FsError> {
        let path = self.checked(name)?;
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_error("open", &path))?;
        let file = File::from(fd);
        require_regular(&file, &path, true)?;
        match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => {}
            Err(Errno::WOULDBLOCK) => return Ok(None),
            Err(errno) => return Err(errno_error("lock", &path)(errno)),
        }
        if let Some(owner) = owner {
            fchown(&file, Some(owner.uid), Some(owner.gid)).map_err(fs_error("chown", &path))?;
        }
        file.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(fs_error("chmod", &path))?;
        Ok(Some(file))
    }

    pub fn write_private(
        &self,
        name: &str,
        content: &[u8],
        owner: Option<Owner>,
    ) -> Result<(), FsError> {
        self.checked(name)?;
        let temp = temp_name(name);
        if let Err(error) = self.write_temp_and_rename(&temp, name, content, owner) {
            if let Err(cleanup) = self.remove_if_present(&temp) {
                tracing::warn!(
                    target: "jaunt::agent",
                    error = %cleanup,
                    "removing a temporary file after a failed write failed"
                );
            }
            return Err(error);
        }
        self.sync()
    }

    fn write_temp_and_rename(
        &self,
        temp: &str,
        name: &str,
        content: &[u8],
        owner: Option<Owner>,
    ) -> Result<(), FsError> {
        let temp_path = self.checked(temp)?;
        let target = self.checked(name)?;
        self.remove_if_present(temp)?;
        let mut file = self.create_exclusive(temp)?;
        file.write_all(content)
            .map_err(fs_error("write", &temp_path))?;
        if let Some(owner) = owner {
            fchown(&file, Some(owner.uid), Some(owner.gid))
                .map_err(fs_error("chown", &temp_path))?;
        }
        file.set_permissions(Permissions::from_mode(PRIVATE_FILE_MODE))
            .map_err(fs_error("chmod", &temp_path))?;
        file.sync_all().map_err(fs_error("fsync", &temp_path))?;
        drop(file);
        rustix::fs::renameat(&self.dir, temp, &self.dir, name)
            .map_err(errno_error("rename", &target))
    }

    pub fn create_private_dir(
        &self,
        name: &str,
        owner: Option<Owner>,
    ) -> Result<Option<DirHandle>, FsError> {
        let path = self.checked(name)?;
        match rustix::fs::mkdirat(&self.dir, name, Mode::RWXU) {
            Ok(()) => {}
            Err(Errno::EXIST) => return Ok(None),
            Err(errno) => return Err(errno_error("mkdir", &path)(errno)),
        }
        let fd = rustix::fs::openat(
            &self.dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno_error("open", &path))?;
        let handle = DirHandle {
            dir: File::from(fd),
            path,
        };
        if let Err(error) = handle.take_ownership(owner) {
            if let Err(cleanup) = rustix::fs::unlinkat(&self.dir, name, AtFlags::REMOVEDIR) {
                tracing::warn!(
                    target: "jaunt::agent",
                    error = %io::Error::from(cleanup),
                    "removing a directory after a failed chown failed"
                );
            }
            return Err(error);
        }
        Ok(Some(handle))
    }

    fn take_ownership(&self, owner: Option<Owner>) -> Result<(), FsError> {
        self.set_mode(PRIVATE_DIR_MODE)?;
        if let Some(owner) = owner {
            fchown(&self.dir, Some(owner.uid), Some(owner.gid))
                .map_err(fs_error("chown", &self.path))?;
        }
        Ok(())
    }

    pub fn move_into(&self, name: &str, target: &DirHandle) -> Result<(), FsError> {
        let path = self.checked(name)?;
        target.checked(name)?;
        rustix::fs::renameat(&self.dir, name, &target.dir, name)
            .map_err(errno_error("rename", &path))
    }
}

#[cfg(test)]
mod tests;
