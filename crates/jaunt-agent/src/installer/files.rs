use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::error::InstallError;

pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, InstallError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstallError::io("read", path)(source)),
    }
}

pub const MAX_MANAGED_FILE: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct RegularFile {
    pub content: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Existing {
    Absent,
    NotRegular,
    Oversized,
    Regular(RegularFile),
}

pub fn read_regular_no_follow(path: &Path) -> Result<Existing, InstallError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(Existing::Absent),
        Err(Errno::LOOP) => return Ok(Existing::NotRegular),
        Err(errno) => return Err(InstallError::io("open", path)(io::Error::from(errno))),
    };
    let file = File::from(fd);
    let metadata = file.metadata().map_err(InstallError::io("stat", path))?;
    if !metadata.is_file() {
        return Ok(Existing::NotRegular);
    }
    let mut content = Vec::new();
    file.take(MAX_MANAGED_FILE + 1)
        .read_to_end(&mut content)
        .map_err(InstallError::io("read", path))?;
    if content.len() as u64 > MAX_MANAGED_FILE {
        return Ok(Existing::Oversized);
    }
    Ok(Existing::Regular(RegularFile {
        content,
        mode: metadata.permissions().mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    }))
}

pub fn exists(path: &Path) -> Result<bool, InstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallError::io("stat", path)(source)),
    }
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), InstallError> {
    fs::set_permissions(path, Permissions::from_mode(mode)).map_err(InstallError::io("chmod", path))
}

pub fn ensure_dir(
    path: &Path,
    mode: u32,
    enforce_mode: bool,
    created: &mut Vec<PathBuf>,
) -> Result<(), InstallError> {
    match fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            if enforce_mode {
                set_mode(path, mode)?;
            }
            Ok(())
        }
        Ok(_) => Err(InstallError::Io {
            op: "mkdir",
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "exists and is not a directory",
            ),
        }),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let mut missing: Vec<PathBuf> = path
                .ancestors()
                .take_while(|ancestor| !ancestor.exists())
                .map(Path::to_path_buf)
                .collect();
            missing.reverse();
            for dir in missing {
                let dir_mode = if dir == path { mode } else { 0o755 };
                DirBuilder::new()
                    .mode(dir_mode)
                    .create(&dir)
                    .map_err(InstallError::io("mkdir", &dir))?;
                created.push(dir.clone());
                set_mode(&dir, dir_mode)?;
            }
            Ok(())
        }
        Err(source) => Err(InstallError::io("stat", path)(source)),
    }
}

pub struct FileFacts {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

pub fn file_facts(path: &Path) -> Result<Option<FileFacts>, InstallError> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(FileFacts {
            mode: meta.permissions().mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
        })),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(InstallError::io("stat", path)(source)),
    }
}

pub fn is_empty_dir(path: &Path) -> Result<bool, InstallError> {
    let mut entries = fs::read_dir(path).map_err(InstallError::io("read", path))?;
    match entries.next() {
        None => Ok(true),
        Some(Ok(_)) => Ok(false),
        Some(Err(source)) => Err(InstallError::io("read", path)(source)),
    }
}

pub fn remove_dir(path: &Path) -> Result<bool, InstallError> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallError::io("remove", path)(source)),
    }
}

pub fn create_empty_if_absent(path: &Path, mode: u32) -> Result<bool, InstallError> {
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
    {
        Ok(file) => {
            file.sync_all().map_err(InstallError::io("fsync", path))?;
            set_mode(path, mode)?;
            Ok(true)
        }
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(InstallError::io("create", path)(source)),
    }
}

pub fn write_atomic(
    path: &Path,
    content: &[u8],
    mode: u32,
) -> Result<Option<InstallError>, InstallError> {
    let parent = path.parent().ok_or_else(|| InstallError::Io {
        op: "write",
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory"),
    })?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| InstallError::Io {
            op: "write",
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"),
        })?;
    let temp = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    match write_temp_and_rename(&temp, path, content, mode) {
        Ok(()) => Ok(sync_directory(parent).err()),
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error)
        }
    }
}

fn write_temp_and_rename(
    temp: &Path,
    target: &Path,
    content: &[u8],
    mode: u32,
) -> Result<(), InstallError> {
    match fs::remove_file(temp) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(InstallError::io("remove", temp)(source)),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)
        .map_err(InstallError::io("create", temp))?;
    file.write_all(content)
        .map_err(InstallError::io("write", temp))?;
    file.sync_all().map_err(InstallError::io("fsync", temp))?;
    drop(file);
    set_mode(temp, mode)?;
    fs::rename(temp, target).map_err(InstallError::io("rename", target))
}

fn sync_directory(dir: &Path) -> Result<(), InstallError> {
    let handle: File = File::open(dir).map_err(InstallError::io("open", dir))?;
    handle.sync_all().map_err(InstallError::io("fsync", dir))
}

pub fn remove_file(path: &Path) -> Result<bool, InstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InstallError::io("remove", path)(source)),
    }
}

pub fn remove_dir_all(path: &Path) -> Result<(), InstallError> {
    fs::remove_dir_all(path).map_err(InstallError::io("remove", path))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::super::testing::TempRoot;
    use super::{
        Existing, MAX_MANAGED_FILE, RegularFile, create_empty_if_absent, ensure_dir, read_optional,
        read_regular_no_follow, remove_file, write_atomic,
    };

    fn mode_of(path: &std::path::Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn atomic_write_sets_mode_replaces_content_and_leaves_no_temp_file() {
        let root = TempRoot::new();
        let path = root.path().join("dir/file.conf");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert!(write_atomic(&path, b"first", 0o644).unwrap().is_none());
        assert!(write_atomic(&path, b"second", 0o640).unwrap().is_none());
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(mode_of(&path), 0o640);
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1);
    }

    #[test]
    fn empty_file_is_created_once_and_never_truncated() {
        let root = TempRoot::new();
        let path = root.path().join("inner-ca.pub");
        assert!(create_empty_if_absent(&path, 0o644).unwrap());
        assert_eq!(mode_of(&path), 0o644);
        fs::write(&path, b"ssh-ed25519 AAAA").unwrap();
        assert!(!create_empty_if_absent(&path, 0o644).unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"ssh-ed25519 AAAA");
    }

    #[test]
    fn ensure_dir_reports_what_it_created_and_enforces_only_when_asked() {
        let root = TempRoot::new();
        let path = root.path().join("a/b/state");
        let mut created = Vec::new();
        ensure_dir(&path, 0o700, false, &mut created).unwrap();
        assert_eq!(
            created,
            vec![root.path().join("a"), root.path().join("a/b"), path.clone()]
        );
        assert_eq!(mode_of(&path), 0o700);
        assert_eq!(mode_of(&root.path().join("a")), 0o755);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let mut again = Vec::new();
        ensure_dir(&path, 0o700, false, &mut again).unwrap();
        assert!(again.is_empty());
        assert_eq!(mode_of(&path), 0o755);
        ensure_dir(&path, 0o700, true, &mut again).unwrap();
        assert!(again.is_empty());
        assert_eq!(mode_of(&path), 0o700);
    }

    #[test]
    fn ensure_dir_refuses_a_regular_file() {
        let root = TempRoot::new();
        let path = root.path().join("file");
        fs::write(&path, b"x").unwrap();
        assert!(ensure_dir(&path, 0o700, true, &mut Vec::new()).is_err());
    }

    #[test]
    fn ensure_dir_that_fails_halfway_still_reports_the_ancestors_it_created() {
        let root = TempRoot::new();
        let path = root.path().join("a").join("x".repeat(300)).join("state");
        let mut created = Vec::new();
        assert!(ensure_dir(&path, 0o700, true, &mut created).is_err());
        assert_eq!(created, vec![root.path().join("a")]);
    }

    #[test]
    fn reading_without_following_sees_only_small_regular_files() {
        let root = TempRoot::new();
        let file = root.path().join("file");
        fs::write(&file, b"content").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        let limit = usize::try_from(MAX_MANAGED_FILE).unwrap();
        let largest = root.path().join("largest");
        fs::write(&largest, vec![b'#'; limit]).unwrap();
        let oversized = root.path().join("oversized");
        fs::write(&oversized, vec![b'#'; limit + 1]).unwrap();
        let fifo = root.path().join("fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());

        let meta = fs::metadata(&file).unwrap();
        let expected_file = Existing::Regular(RegularFile {
            content: b"content".to_vec(),
            mode: 0o640,
            uid: meta.uid(),
            gid: meta.gid(),
        });
        for (path, expected) in [
            (root.path().join("missing"), "absent"),
            (file.clone(), "regular"),
            (link, "not regular"),
            (root.path().to_path_buf(), "not regular"),
            (fifo, "not regular"),
            (largest.clone(), "regular"),
            (oversized, "oversized"),
        ] {
            let found = read_regular_no_follow(&path).unwrap();
            assert_eq!(expected_file_kind(&found), expected, "{path:?}");
        }
        assert_eq!(read_regular_no_follow(&file).unwrap(), expected_file);
    }

    fn expected_file_kind(existing: &Existing) -> &'static str {
        match existing {
            Existing::Absent => "absent",
            Existing::NotRegular => "not regular",
            Existing::Oversized => "oversized",
            Existing::Regular(_) => "regular",
        }
    }

    #[test]
    fn missing_files_read_as_none_and_remove_as_false() {
        let root = TempRoot::new();
        let path = root.path().join("missing");
        assert_eq!(read_optional(&path).unwrap(), None);
        assert!(!remove_file(&path).unwrap());
    }
}
