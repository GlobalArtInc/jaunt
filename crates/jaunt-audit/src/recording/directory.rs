use std::fs::{self, DirBuilder, File};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use jaunt_record::{Limits, SessionManifest};
use jaunt_store::is_session_id;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

use super::{
    CAST_SUFFIX, Committed, MANIFEST_SUFFIX, MAX_MANIFEST_BYTES, PART_SUFFIX, PENDING_SUFFIX,
    RecordingKey, RecordingSink, RecordingStoreError, StagedRecording, StoredRecording, hex,
    manifest_bytes, sha256_hex,
};

pub const ROOT_MODE: u32 = 0o750;
pub const FILE_MODE: u32 = 0o640;
pub const DEFAULT_MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryLimits {
    pub min_free_bytes: u64,
    pub max_total_raw: u64,
}

impl Default for DirectoryLimits {
    fn default() -> DirectoryLimits {
        DirectoryLimits {
            min_free_bytes: DEFAULT_MIN_FREE_BYTES,
            max_total_raw: Limits::default().max_total_raw,
        }
    }
}

pub struct PendingManifest {
    pub key: RecordingKey,
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for PendingManifest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingManifest")
            .field("key", &self.key)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Leftovers {
    pub parts: u64,
    pub orphan_casts: u64,
}

pub type FreeSpace = Arc<dyn Fn(BorrowedFd<'_>) -> io::Result<u64> + Send + Sync>;

pub const QUARANTINE_DIR: &str = "quarantine";
const RENAME_PROBE: &str = ".rename-probe";
const RENAME_PROBE_DONE: &str = ".rename-probe-done";

pub struct DirectorySink {
    root: PathBuf,
    root_fd: Arc<OwnedFd>,
    limits: DirectoryLimits,
    free_space: FreeSpace,
}

impl std::fmt::Debug for DirectorySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectorySink")
            .field("root", &self.root)
            .field("limits", &self.limits)
            .finish()
    }
}

fn dir_mode() -> Mode {
    Mode::RWXU | Mode::RGRP | Mode::XGRP
}

fn file_mode() -> Mode {
    Mode::RUSR | Mode::WUSR | Mode::RGRP
}

fn errno(operation: &'static str) -> impl FnOnce(Errno) -> RecordingStoreError {
    move |errno| match errno {
        Errno::EXIST => RecordingStoreError::Exists,
        Errno::LOOP | Errno::NOTDIR => RecordingStoreError::UnsafePath,
        other => RecordingStoreError::Io {
            operation,
            source: io::Error::from(other),
        },
    }
}

fn part_name(name: &str) -> String {
    format!("{name}{PART_SUFFIX}")
}

fn statvfs_free_space() -> FreeSpace {
    Arc::new(|fd| {
        let stats = rustix::fs::fstatvfs(fd)?;
        Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
    })
}

fn free_bytes(free_space: &FreeSpace, fd: BorrowedFd<'_>) -> Result<u64, RecordingStoreError> {
    free_space(fd).map_err(RecordingStoreError::io("measure the free space"))
}

fn probe_rename_without_replace(root: impl AsFd) -> Result<(), RecordingStoreError> {
    for name in [RENAME_PROBE, RENAME_PROBE_DONE] {
        unlink(&root, name)?;
    }
    drop(create_file(&root, RENAME_PROBE)?);
    let renamed = rustix::fs::renameat_with(
        &root,
        RENAME_PROBE,
        &root,
        RENAME_PROBE_DONE,
        RenameFlags::NOREPLACE,
    );
    let removed = [RENAME_PROBE, RENAME_PROBE_DONE].map(|name| unlink(&root, name));
    match renamed {
        Ok(()) => {}
        Err(code)
            if [Errno::INVAL, Errno::NOSYS, Errno::NOTSUP, Errno::OPNOTSUPP].contains(&code) =>
        {
            return Err(RecordingStoreError::NoReplaceUnsupported);
        }
        Err(other) => return Err(errno("probe renaming in the recording directory")(other)),
    }
    removed.into_iter().collect()
}

fn ensure_dir(parent: impl AsFd, name: &str) -> Result<OwnedFd, RecordingStoreError> {
    let created = match rustix::fs::mkdirat(&parent, name, dir_mode()) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(other) => return Err(errno("create a recording directory")(other)),
    };
    let fd = rustix::fs::openat(
        &parent,
        name,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno("open a recording directory"))?;
    if created {
        rustix::fs::fchmod(&fd, dir_mode()).map_err(errno("set a directory mode"))?;
        rustix::fs::fsync(&parent).map_err(errno("flush a recording directory"))?;
    }
    Ok(fd)
}

fn open_dir(parent: impl AsFd, name: &str) -> Result<Option<OwnedFd>, RecordingStoreError> {
    match rustix::fs::openat(
        parent,
        name,
        OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(other) => Err(errno("open a recording directory")(other)),
    }
}

fn open_file(dir: impl AsFd, name: &str) -> Result<Option<File>, RecordingStoreError> {
    let fd = match rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(other) => return Err(errno("open a stored recording")(other)),
    };
    let stat = rustix::fs::fstat(&fd).map_err(errno("inspect a stored recording"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(RecordingStoreError::UnsafePath);
    }
    Ok(Some(File::from(fd)))
}

fn create_file(dir: impl AsFd, name: &str) -> Result<File, RecordingStoreError> {
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        file_mode(),
    )
    .map_err(errno("create a recording file"))?;
    rustix::fs::fchmod(&fd, file_mode()).map_err(errno("set a file mode"))?;
    Ok(File::from(fd))
}

fn refuse_stored(month: impl AsFd, key: &RecordingKey) -> Result<(), RecordingStoreError> {
    for name in [key.manifest_name(), key.cast_name()] {
        match rustix::fs::statat(&month, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(RecordingStoreError::Exists),
            Err(Errno::NOENT) => {}
            Err(other) => return Err(errno("inspect a recording file")(other)),
        }
    }
    Ok(())
}

fn store_name(dir: impl AsFd, from: &str, to: &str) -> Result<(), RecordingStoreError> {
    rustix::fs::renameat_with(&dir, from, &dir, to, RenameFlags::NOREPLACE)
        .map_err(errno("store a recording file"))
}

fn unlink(dir: impl AsFd, name: &str) -> Result<(), RecordingStoreError> {
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(other) => Err(errno("remove a recording file")(other)),
    }
}

impl DirectorySink {
    pub fn create(
        root: &Path,
        limits: DirectoryLimits,
    ) -> Result<DirectorySink, RecordingStoreError> {
        let created = match DirBuilder::new().mode(ROOT_MODE).create(root) {
            Ok(()) => true,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => false,
            Err(source) => {
                return Err(RecordingStoreError::Io {
                    operation: "create the recording directory",
                    source,
                });
            }
        };
        let sink = DirectorySink::open_existing(root, limits)?;
        if created {
            rustix::fs::fchmod(&*sink.root_fd, dir_mode())
                .map_err(errno("set the recording directory mode"))?;
        }
        probe_rename_without_replace(&*sink.root_fd)?;
        Ok(sink)
    }

    pub fn with_free_space(mut self, free_space: FreeSpace) -> DirectorySink {
        self.free_space = free_space;
        self
    }

    pub fn open_existing(
        root: &Path,
        limits: DirectoryLimits,
    ) -> Result<DirectorySink, RecordingStoreError> {
        let root_fd = rustix::fs::open(
            root,
            OFlags::DIRECTORY | OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(errno("open the recording directory"))?;
        Ok(DirectorySink {
            root: root.to_path_buf(),
            root_fd: Arc::new(root_fd),
            limits,
            free_space: statvfs_free_space(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn remove_leftovers(&self) -> Result<Leftovers, RecordingStoreError> {
        self.remove_leftovers_except(&[])
    }

    pub fn remove_leftovers_except(
        &self,
        keep: &[String],
    ) -> Result<Leftovers, RecordingStoreError> {
        let mut leftovers = Leftovers::default();
        for year in subdirectories(&self.root, 4)? {
            for month in subdirectories(&year, 2)? {
                remove_leftovers_in(&month, keep, &mut leftovers)?;
            }
        }
        Ok(leftovers)
    }
}

fn listing(dir: &Path) -> Result<fs::ReadDir, RecordingStoreError> {
    fs::read_dir(dir).map_err(RecordingStoreError::io("list a recording directory"))
}

fn subdirectories(dir: &Path, digits: usize) -> Result<Vec<PathBuf>, RecordingStoreError> {
    let mut found = Vec::new();
    for entry in listing(dir)? {
        let entry = entry.map_err(RecordingStoreError::io("list a recording directory"))?;
        let kind = entry
            .file_type()
            .map_err(RecordingStoreError::io("inspect a recording directory"))?;
        let name = entry.file_name();
        let numeric = name
            .to_str()
            .is_some_and(|text| text.len() == digits && text.bytes().all(|b| b.is_ascii_digit()));
        if numeric && kind.is_dir() {
            found.push(entry.path());
        }
    }
    Ok(found)
}

enum Leftover {
    Part(String),
    Cast(String),
}

fn leftover_kind(name: &str) -> Option<Leftover> {
    if let Some(stem) = name.strip_suffix(PART_SUFFIX) {
        let id = stem
            .strip_suffix(CAST_SUFFIX)
            .or_else(|| stem.strip_suffix(MANIFEST_SUFFIX))?;
        return is_session_id(id).then(|| Leftover::Part(id.to_owned()));
    }
    let id = name.strip_suffix(CAST_SUFFIX)?;
    is_session_id(id).then(|| Leftover::Cast(id.to_owned()))
}

fn remove_leftovers_in(
    dir: &Path,
    keep: &[String],
    leftovers: &mut Leftovers,
) -> Result<(), RecordingStoreError> {
    for entry in listing(dir)? {
        let entry = entry.map_err(RecordingStoreError::io("list a recording directory"))?;
        let kind = entry
            .file_type()
            .map_err(RecordingStoreError::io("inspect a recording file"))?;
        if kind.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let remove =
            || fs::remove_file(entry.path()).map_err(RecordingStoreError::io("remove a leftover"));
        match leftover_kind(&name) {
            Some(Leftover::Part(id)) => {
                if keep.contains(&id) {
                    continue;
                }
                let pending = name
                    .strip_suffix(&format!("{CAST_SUFFIX}{PART_SUFFIX}"))
                    .map(|id| dir.join(format!("{id}{PENDING_SUFFIX}")));
                if pending.is_some_and(|path| path.symlink_metadata().is_ok()) {
                    continue;
                }
                remove()?;
                leftovers.parts += 1;
            }
            Some(Leftover::Cast(id)) => {
                if keep.contains(&id) {
                    continue;
                }
                let manifest = dir.join(format!("{id}{MANIFEST_SUFFIX}"));
                match fs::symlink_metadata(&manifest) {
                    Ok(_) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => {
                        remove()?;
                        leftovers.orphan_casts += 1;
                    }
                    Err(source) => {
                        return Err(RecordingStoreError::Io {
                            operation: "inspect a stored manifest",
                            source,
                        });
                    }
                }
            }
            None => {}
        }
    }
    Ok(())
}

impl DirectorySink {
    pub fn begin_staged(&self, key: &RecordingKey) -> Result<DirectoryStaged, RecordingStoreError> {
        if free_bytes(&self.free_space, self.root_fd.as_fd())? < self.limits.min_free_bytes {
            return Err(RecordingStoreError::DiskFull);
        }
        let year = ensure_dir(&*self.root_fd, &key.year_dir())?;
        let month = ensure_dir(&year, &key.month_dir())?;
        refuse_stored(&month, key)?;
        Ok(DirectoryStaged {
            dir: month,
            key: key.clone(),
            limits: self.limits,
            free_space: self.free_space.clone(),
            cast: None,
            hasher: Sha256::new(),
            written: 0,
            last_seq: None,
            files: Files::default(),
            finished: false,
        })
    }

    pub fn resume_staged(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<DirectoryStaged>, RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(None);
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(None);
        };
        refuse_stored(&month, key)?;
        let fd = match rustix::fs::openat(
            &month,
            part_name(&key.cast_name()),
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(other) => return Err(errno("open a staged recording")(other)),
        };
        let stat = rustix::fs::fstat(&fd).map_err(errno("inspect a staged recording"))?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(RecordingStoreError::UnsafePath);
        }
        if u64::try_from(stat.st_size).map_or(true, |size| size < raw_bytes) {
            return Ok(None);
        }
        let mut file = File::from(fd);
        file.set_len(raw_bytes)
            .map_err(RecordingStoreError::io("cut a staged recording"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(RecordingStoreError::io("rewind a staged recording"))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut remaining = raw_bytes;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(64 * 1024)).unwrap_or(64 * 1024);
            let read = file
                .read(&mut buffer[..want])
                .map_err(RecordingStoreError::io("read a staged recording"))?;
            if read == 0 {
                return Ok(None);
            }
            hasher.update(&buffer[..read]);
            remaining -= u64::try_from(read).unwrap_or(remaining);
        }
        if hex(&hasher.clone().finalize()) != prefix_sha256 {
            drop(file);
            unlink(&month, &part_name(&key.cast_name()))?;
            return Err(RecordingStoreError::PrefixMismatch);
        }
        Ok(Some(DirectoryStaged {
            dir: month,
            key: key.clone(),
            limits: self.limits,
            free_space: self.free_space.clone(),
            cast: Some(file),
            hasher,
            written: raw_bytes,
            last_seq: Some(u64::MAX),
            files: Files {
                cast_part: true,
                ..Files::default()
            },
            finished: false,
        }))
    }

    pub fn pending_manifests(&self) -> Result<Vec<PendingManifest>, RecordingStoreError> {
        let mut found = Vec::new();
        let years = match subdirectories(&self.root, 4) {
            Ok(years) => years,
            Err(err) => {
                tracing::warn!(target: "jaunt::recordings", error = %err, "the staging directory cannot be listed for pending manifests");
                return Ok(found);
            }
        };
        for year in years {
            let Some(year_name) = year.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let year_fd = match open_dir(&*self.root_fd, year_name) {
                Ok(Some(fd)) => fd,
                Ok(None) => continue,
                Err(err) => {
                    tracing::warn!(target: "jaunt::recordings", directory = year_name, error = %err, "a staging directory is skipped");
                    continue;
                }
            };
            let months = match subdirectories(&year, 2) {
                Ok(months) => months,
                Err(err) => {
                    tracing::warn!(target: "jaunt::recordings", directory = year_name, error = %err, "a staging directory is skipped");
                    continue;
                }
            };
            for month in months {
                let Some(month_name) = month.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let month_fd = match open_dir(&year_fd, month_name) {
                    Ok(Some(fd)) => fd,
                    Ok(None) => continue,
                    Err(err) => {
                        tracing::warn!(target: "jaunt::recordings", directory = month_name, error = %err, "a staging directory is skipped");
                        continue;
                    }
                };
                let entries = match listing(&month) {
                    Ok(entries) => entries,
                    Err(err) => {
                        tracing::warn!(target: "jaunt::recordings", directory = month_name, error = %err, "a staging directory is skipped");
                        continue;
                    }
                };
                for entry in entries {
                    let Ok(entry) = entry else {
                        continue;
                    };
                    let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    let Some(id) = name.strip_suffix(PENDING_SUFFIX) else {
                        continue;
                    };
                    let Ok(key) = RecordingKey::from_directories(id, year_name, month_name) else {
                        continue;
                    };
                    let read = open_file(&month_fd, &name).and_then(|opened| match opened {
                        Some(file) => read_bounded(file).map(Some),
                        None => Ok(None),
                    });
                    match read {
                        Ok(Some(bytes)) => found.push(PendingManifest { key, bytes }),
                        Ok(None) => {}
                        Err(err) => {
                            tracing::warn!(target: "jaunt::recordings", session_id = key.session_id(), error = %err, "a pending manifest cannot be read and is skipped");
                        }
                    }
                }
            }
        }
        Ok(found)
    }

    pub fn open_staged_cast(
        &self,
        key: &RecordingKey,
    ) -> Result<Option<File>, RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(None);
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(None);
        };
        open_file(&month, &part_name(&key.cast_name()))
    }

    pub fn quarantine_staged(&self, key: &RecordingKey) -> Result<(), RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(());
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(());
        };
        let quarantine = ensure_dir(&*self.root_fd, QUARANTINE_DIR)?;
        let target = ensure_dir(&quarantine, key.session_id())?;
        let manifest_name = key.manifest_name();
        for name in [
            pending_name(key),
            part_name(&manifest_name),
            part_name(&key.cast_name()),
        ] {
            match rustix::fs::renameat_with(
                &month,
                name.as_str(),
                &target,
                name.as_str(),
                RenameFlags::NOREPLACE,
            ) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(other) => return Err(errno("quarantine a staged file")(other)),
            }
        }
        rustix::fs::fsync(&target).map_err(errno("flush the quarantine directory"))
    }

    pub fn pending_exists(&self, key: &RecordingKey) -> Result<bool, RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(false);
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(false);
        };
        match rustix::fs::statat(
            &month,
            pending_name(key).as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(other) => Err(errno("inspect a pending manifest")(other)),
        }
    }

    pub fn remove_staged(&self, key: &RecordingKey) -> Result<(), RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(());
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(());
        };
        let manifest_name = key.manifest_name();
        for name in [
            pending_name(key),
            part_name(&manifest_name),
            part_name(&key.cast_name()),
        ] {
            unlink(&month, &name)?;
        }
        Ok(())
    }
}

impl RecordingSink for DirectorySink {
    fn begin(&self, key: &RecordingKey) -> Result<Box<dyn StagedRecording>, RecordingStoreError> {
        Ok(Box::new(self.begin_staged(key)?))
    }

    fn holds_staged_manifest(&self, key: &RecordingKey) -> bool {
        self.pending_exists(key).unwrap_or(true)
    }

    fn holds_staged_part(&self, key: &RecordingKey) -> bool {
        self.open_staged_cast(key)
            .map_or(true, |opened| opened.is_some())
    }

    fn resume(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn StagedRecording>>, RecordingStoreError> {
        Ok(self
            .resume_staged(key, raw_bytes, prefix_sha256)?
            .map(|staged| Box::new(staged) as Box<dyn StagedRecording>))
    }

    fn open(&self, key: &RecordingKey) -> Result<Option<StoredRecording>, RecordingStoreError> {
        let Some(year) = open_dir(&*self.root_fd, &key.year_dir())? else {
            return Ok(None);
        };
        let Some(month) = open_dir(&year, &key.month_dir())? else {
            return Ok(None);
        };
        let Some(manifest_file) = open_file(&month, &key.manifest_name())? else {
            return Ok(None);
        };
        let bytes = read_bounded(manifest_file)?;
        let manifest: SessionManifest =
            serde_json::from_slice(&bytes).map_err(|_| RecordingStoreError::InvalidManifest)?;
        if manifest.session_id != key.session_id() {
            return Err(RecordingStoreError::InvalidManifest);
        }
        let cast =
            open_file(&month, &key.cast_name())?.map(|file| Box::new(file) as Box<dyn Read + Send>);
        Ok(Some(StoredRecording {
            manifest,
            manifest_sha256: sha256_hex(&bytes),
            cast,
        }))
    }
}

fn read_bounded(file: File) -> Result<Vec<u8>, RecordingStoreError> {
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(RecordingStoreError::io("read a stored manifest"))?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(RecordingStoreError::InvalidManifest);
    }
    Ok(bytes)
}

fn pending_name(key: &RecordingKey) -> String {
    format!("{}{PENDING_SUFFIX}", key.session_id())
}

#[derive(Debug, Default, Clone, Copy)]
struct Files {
    cast_part: bool,
    cast: bool,
    manifest_part: bool,
    manifest: bool,
    pending: bool,
}

pub struct DirectoryStaged {
    dir: OwnedFd,
    key: RecordingKey,
    limits: DirectoryLimits,
    free_space: FreeSpace,
    cast: Option<File>,
    hasher: Sha256,
    written: u64,
    last_seq: Option<u64>,
    files: Files,
    finished: bool,
}

impl DirectoryStaged {
    fn commit_files(
        &mut self,
        manifest: &SessionManifest,
    ) -> Result<Committed, RecordingStoreError> {
        let bytes = manifest_bytes(manifest)?;
        let cast_name = self.key.cast_name();
        let cast_sha256 = match self.cast.as_ref() {
            Some(file) => {
                file.sync_all()
                    .map_err(RecordingStoreError::io("flush the recording"))?;
                store_name(&self.dir, &part_name(&cast_name), &cast_name)?;
                self.files.cast_part = false;
                self.files.cast = true;
                Some(hex(&self.hasher.clone().finalize()))
            }
            None => None,
        };
        let manifest_name = self.key.manifest_name();
        let manifest_part = part_name(&manifest_name);
        let mut file = create_file(&self.dir, &manifest_part)?;
        self.files.manifest_part = true;
        file.write_all(&bytes)
            .map_err(RecordingStoreError::io("write the manifest"))?;
        file.sync_all()
            .map_err(RecordingStoreError::io("flush the manifest"))?;
        drop(file);
        store_name(&self.dir, &manifest_part, &manifest_name)?;
        self.files.manifest_part = false;
        self.files.manifest = true;
        rustix::fs::fsync(&self.dir).map_err(errno("flush the recording directory"))?;
        Ok(Committed {
            location: self.key.location(),
            cast_sha256,
            cast_bytes: self.written,
            manifest_sha256: sha256_hex(&bytes),
        })
    }

    pub fn cast_for_upload(&mut self) -> Result<Option<File>, RecordingStoreError> {
        if self.finished {
            return Err(RecordingStoreError::Finished);
        }
        let Some(writer) = self.cast.as_ref() else {
            return Ok(None);
        };
        writer
            .sync_all()
            .map_err(RecordingStoreError::io("flush the recording"))?;
        match open_file(&self.dir, &part_name(&self.key.cast_name()))? {
            Some(file) => Ok(Some(file)),
            None => Err(RecordingStoreError::Io {
                operation: "open the staged recording",
                source: io::Error::new(
                    ErrorKind::NotFound,
                    "the staged recording was removed while it was being stored",
                ),
            }),
        }
    }

    pub fn stash_manifest(&mut self, bytes: &[u8]) -> Result<(), RecordingStoreError> {
        if self.finished {
            return Err(RecordingStoreError::Finished);
        }
        let temporary = part_name(&self.key.manifest_name());
        unlink(&self.dir, &temporary)?;
        let mut file = create_file(&self.dir, &temporary)?;
        self.files.manifest_part = true;
        file.write_all(bytes)
            .map_err(RecordingStoreError::io("write the pending manifest"))?;
        file.sync_all()
            .map_err(RecordingStoreError::io("flush the pending manifest"))?;
        drop(file);
        rustix::fs::renameat(
            &self.dir,
            temporary.as_str(),
            &self.dir,
            pending_name(&self.key),
        )
        .map_err(errno("store the pending manifest"))?;
        self.files.manifest_part = false;
        self.files.pending = true;
        rustix::fs::fsync(&self.dir).map_err(errno("flush the recording directory"))
    }

    fn restore_after_exists(&mut self) -> Result<(), RecordingStoreError> {
        let manifest_name = self.key.manifest_name();
        let cast_name = self.key.cast_name();
        if self.files.manifest_part {
            unlink(&self.dir, &part_name(&manifest_name))?;
            self.files.manifest_part = false;
        }
        if self.files.cast {
            store_name(&self.dir, &cast_name, &part_name(&cast_name))?;
            self.files.cast = false;
            self.files.cast_part = true;
        }
        Ok(())
    }

    pub fn release(&mut self) {
        self.cast = None;
        self.files = Files::default();
        self.finished = true;
    }

    pub fn discard(&mut self) -> Result<(), RecordingStoreError> {
        self.finished = true;
        self.cast = None;
        let files = std::mem::take(&mut self.files);
        let manifest_name = self.key.manifest_name();
        let cast_name = self.key.cast_name();
        let mut first_error = None;
        for (present, name) in [
            (files.manifest, manifest_name.clone()),
            (files.pending, pending_name(&self.key)),
            (files.manifest_part, part_name(&manifest_name)),
            (files.cast, cast_name.clone()),
            (files.cast_part, part_name(&cast_name)),
        ] {
            if present && let Err(err) = unlink(&self.dir, &name) {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl StagedRecording for DirectoryStaged {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), RecordingStoreError> {
        if self.finished {
            return Err(RecordingStoreError::Finished);
        }
        if self.last_seq.is_some_and(|last| seq <= last) {
            return Err(RecordingStoreError::OutOfOrder { seq });
        }
        let len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if self.written.saturating_add(len) > self.limits.max_total_raw {
            return Err(RecordingStoreError::TooLarge);
        }
        if free_bytes(&self.free_space, self.dir.as_fd())?
            < self.limits.min_free_bytes.saturating_add(len)
        {
            return Err(RecordingStoreError::DiskFull);
        }
        let file = match &mut self.cast {
            Some(file) => file,
            None => {
                let created = create_file(&self.dir, &part_name(&self.key.cast_name()))?;
                self.files.cast_part = true;
                self.cast.insert(created)
            }
        };
        file.write_all(raw)
            .map_err(RecordingStoreError::io("write the recording"))?;
        self.hasher.update(raw);
        self.written += len;
        self.last_seq = Some(seq);
        Ok(())
    }

    fn written(&self) -> u64 {
        self.written
    }

    fn prefix_sha256(&self) -> String {
        hex(&self.hasher.clone().finalize())
    }

    fn commit(&mut self, manifest: &SessionManifest) -> Result<Committed, RecordingStoreError> {
        if self.finished {
            return Err(RecordingStoreError::Finished);
        }
        let committed = self.commit_files(manifest);
        match &committed {
            Ok(_) => self.finished = true,
            Err(RecordingStoreError::Exists) => {
                if let Err(err) = self.restore_after_exists() {
                    tracing::warn!(target: "jaunt::recordings", error = %err, "restoring a recording after a name collision failed: its files are removed");
                    let _ = self.discard();
                    self.finished = true;
                }
            }
            Err(_) => {
                if let Err(err) = self.discard() {
                    tracing::warn!(target: "jaunt::recordings", error = %err, "removing a failed recording left files behind");
                }
                self.finished = true;
            }
        }
        committed
    }

    fn keep_files(&mut self) {
        self.release();
    }

    fn abort(mut self: Box<Self>) -> Result<(), RecordingStoreError> {
        self.finished = true;
        self.discard()
    }
}

impl Drop for DirectoryStaged {
    fn drop(&mut self) {
        if !self.finished
            && let Err(err) = self.discard()
        {
            tracing::warn!(target: "jaunt::recordings", error = %err, "removing an abandoned recording left files behind");
        }
    }
}
