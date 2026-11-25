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
    CAST_SUFFIX, Committed, MANIFEST_SUFFIX, MAX_MANIFEST_BYTES, PART_SUFFIX, RecordingKey,
    RecordingSink, RecordingStoreError, StagedRecording, StoredRecording, hex, manifest_bytes,
    sha256_hex,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Leftovers {
    pub parts: u64,
    pub orphan_casts: u64,
}

pub type FreeSpace = Arc<dyn Fn(BorrowedFd<'_>) -> io::Result<u64> + Send + Sync>;

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
        let mut leftovers = Leftovers::default();
        for year in subdirectories(&self.root, 4)? {
            for month in subdirectories(&year, 2)? {
                remove_leftovers_in(&month, &mut leftovers)?;
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
    Part,
    Cast(String),
}

fn leftover_kind(name: &str) -> Option<Leftover> {
    if let Some(stem) = name.strip_suffix(PART_SUFFIX) {
        let id = stem
            .strip_suffix(CAST_SUFFIX)
            .or_else(|| stem.strip_suffix(MANIFEST_SUFFIX))?;
        return is_session_id(id).then_some(Leftover::Part);
    }
    let id = name.strip_suffix(CAST_SUFFIX)?;
    is_session_id(id).then(|| Leftover::Cast(id.to_owned()))
}

fn remove_leftovers_in(dir: &Path, leftovers: &mut Leftovers) -> Result<(), RecordingStoreError> {
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
            Some(Leftover::Part) => {
                remove()?;
                leftovers.parts += 1;
            }
            Some(Leftover::Cast(id)) => {
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

impl RecordingSink for DirectorySink {
    fn begin(&self, key: &RecordingKey) -> Result<Box<dyn StagedRecording>, RecordingStoreError> {
        if free_bytes(&self.free_space, self.root_fd.as_fd())? < self.limits.min_free_bytes {
            return Err(RecordingStoreError::DiskFull);
        }
        let year = ensure_dir(&*self.root_fd, &key.year_dir())?;
        let month = ensure_dir(&year, &key.month_dir())?;
        refuse_stored(&month, key)?;
        Ok(Box::new(DirectoryStaged {
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
        }))
    }

    fn resume(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn StagedRecording>>, RecordingStoreError> {
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
        Ok(Some(Box::new(DirectoryStaged {
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
        })))
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
        let mut bytes = Vec::new();
        let limit = u64::try_from(MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
        manifest_file
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(RecordingStoreError::io("read a stored manifest"))?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RecordingStoreError::InvalidManifest);
        }
        let manifest: SessionManifest =
            serde_json::from_slice(&bytes).map_err(|_| RecordingStoreError::InvalidManifest)?;
        if manifest.session_id != key.session_id() {
            return Err(RecordingStoreError::InvalidManifest);
        }
        let cast = open_file(&month, &key.cast_name())?;
        Ok(Some(StoredRecording {
            manifest,
            manifest_sha256: sha256_hex(&bytes),
            cast,
        }))
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Files {
    cast_part: bool,
    cast: bool,
    manifest_part: bool,
    manifest: bool,
}

struct DirectoryStaged {
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
        let cast_sha256 = match self.cast.take() {
            Some(file) => {
                file.sync_all()
                    .map_err(RecordingStoreError::io("flush the recording"))?;
                drop(file);
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

    fn discard(&mut self) -> Result<(), RecordingStoreError> {
        self.cast = None;
        let files = std::mem::take(&mut self.files);
        let manifest_name = self.key.manifest_name();
        let cast_name = self.key.cast_name();
        let mut first_error = None;
        for (present, name) in [
            (files.manifest, manifest_name.clone()),
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

    fn commit(
        mut self: Box<Self>,
        manifest: &SessionManifest,
    ) -> Result<Committed, RecordingStoreError> {
        if self.finished {
            return Err(RecordingStoreError::Finished);
        }
        let committed = self.commit_files(manifest);
        if committed.is_err()
            && let Err(err) = self.discard()
        {
            tracing::warn!(target: "jaunt::recordings", error = %err, "removing a failed recording left files behind");
        }
        self.finished = true;
        committed
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
