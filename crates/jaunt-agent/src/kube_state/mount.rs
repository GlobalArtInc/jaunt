use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use zeroize::Zeroizing;

const GROUP_OR_OTHER_WRITE: u32 = 0o022;

#[derive(Debug, thiserror::Error)]
pub enum MountError {
    #[error("{} does not exist", path.display())]
    Missing { path: PathBuf },
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{} leads outside its own directory", path.display())]
    Escapes { path: PathBuf },
    #[error("{} is not a regular file", path.display())]
    NotRegular { path: PathBuf },
    #[error("{} can be written by its group or by others", path.display())]
    Writable { path: PathBuf },
    #[error("{} belongs to uid {uid}, which is neither root nor the agent's user", path.display())]
    Owner { path: PathBuf, uid: u32 },
    #[error("{} is larger than {limit} bytes", path.display())]
    TooLarge { path: PathBuf, limit: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
}

fn read_error(path: &Path) -> impl FnOnce(io::Error) -> MountError {
    let path = path.to_path_buf();
    move |source| {
        if source.kind() == io::ErrorKind::NotFound {
            MountError::Missing { path }
        } else {
            MountError::Read { path, source }
        }
    }
}

fn contained(path: &Path) -> Result<PathBuf, MountError> {
    let parent = path
        .parent()
        .ok_or_else(|| MountError::Escapes {
            path: path.to_path_buf(),
        })?
        .canonicalize()
        .map_err(read_error(path))?;
    let real = path.canonicalize().map_err(read_error(path))?;
    if real.starts_with(&parent) {
        Ok(real)
    } else {
        Err(MountError::Escapes {
            path: path.to_path_buf(),
        })
    }
}

pub fn stamp(path: &Path) -> Result<FileStamp, MountError> {
    let real = contained(path)?;
    let meta = std::fs::symlink_metadata(&real).map_err(read_error(path))?;
    Ok(FileStamp {
        device: meta.dev(),
        inode: meta.ino(),
        length: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
    })
}

pub fn read_mounted(
    path: &Path,
    limit: u64,
    agent_uid: u32,
) -> Result<(Zeroizing<Vec<u8>>, FileStamp), MountError> {
    let owned = || path.to_path_buf();
    let real = contained(path)?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = rustix::fs::open(&real, flags, Mode::empty())
        .map_err(|errno| read_error(path)(io::Error::from(errno)))?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(read_error(path))?;
    if !meta.is_file() {
        return Err(MountError::NotRegular { path: owned() });
    }
    if meta.uid() != 0 && meta.uid() != agent_uid {
        return Err(MountError::Owner {
            path: owned(),
            uid: meta.uid(),
        });
    }
    if meta.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return Err(MountError::Writable { path: owned() });
    }
    let mut content = Zeroizing::new(Vec::new());
    file.take(limit.saturating_add(1))
        .read_to_end(&mut content)
        .map_err(read_error(path))?;
    if u64::try_from(content.len()).unwrap_or(u64::MAX) > limit {
        return Err(MountError::TooLarge {
            path: owned(),
            limit,
        });
    }
    let stamp = FileStamp {
        device: meta.dev(),
        inode: meta.ino(),
        length: meta.len(),
        modified: (meta.mtime(), meta.mtime_nsec()),
    };
    Ok((content, stamp))
}

pub fn is_dns_label(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
}

pub fn is_dns_subdomain(text: &str) -> bool {
    text.len() <= 253 && text.split('.').all(is_dns_label)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{MountError, is_dns_label, is_dns_subdomain, read_mounted, stamp};
    use crate::fsio::effective_uid;

    #[test]
    fn a_kubelet_style_link_inside_the_directory_is_followed_and_anything_else_refused() {
        let root = tempfile::tempdir().unwrap();
        let mount = root.path().join("mount");
        let data = mount.join("..2026_11_28_10_00_00.000000001");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("token"), b"abc\n").unwrap();
        fs::set_permissions(data.join("token"), fs::Permissions::from_mode(0o644)).unwrap();
        symlink("..2026_11_28_10_00_00.000000001", mount.join("..data")).unwrap();
        symlink("..data/token", mount.join("token")).unwrap();
        let uid = effective_uid();

        let (content, first) = read_mounted(&mount.join("token"), 16, uid).unwrap();
        assert_eq!(content.as_slice(), b"abc\n");
        assert_eq!(stamp(&mount.join("token")).unwrap(), first);

        fs::write(root.path().join("outside"), b"x").unwrap();
        symlink("../outside", mount.join("escape")).unwrap();
        fs::write(mount.join("loose"), b"x").unwrap();
        fs::set_permissions(mount.join("loose"), fs::Permissions::from_mode(0o664)).unwrap();
        fs::write(mount.join("big"), vec![b'x'; 17]).unwrap();
        fs::set_permissions(mount.join("big"), fs::Permissions::from_mode(0o600)).unwrap();
        type Check = fn(&MountError) -> bool;
        let cases: [(&str, Check); 5] = [
            ("escape", |e| matches!(e, MountError::Escapes { .. })),
            ("loose", |e| matches!(e, MountError::Writable { .. })),
            ("big", |e| {
                matches!(e, MountError::TooLarge { limit: 16, .. })
            }),
            ("absent", |e| matches!(e, MountError::Missing { .. })),
            ("..data", |e| matches!(e, MountError::NotRegular { .. })),
        ];
        for (name, expected) in cases {
            let error = read_mounted(&mount.join(name), 16, uid).unwrap_err();
            assert!(expected(&error), "{name}: {error}");
        }
        if uid != 0 {
            let foreign = read_mounted(&mount.join("token"), 16, uid.wrapping_add(1)).unwrap_err();
            assert!(matches!(foreign, MountError::Owner { .. }), "{foreign}");
        }
    }

    #[test]
    fn names_that_reach_the_api_path_are_dns_labels_or_subdomains() {
        for good in ["jaunt", "jaunt-agent-state", "a", "0a"] {
            assert!(is_dns_label(good) && is_dns_subdomain(good), "{good}");
        }
        assert!(is_dns_subdomain("jaunt.agent-state"));
        assert!(!is_dns_label("jaunt.agent"));
        for bad in [
            "",
            "-a",
            "a-",
            "A",
            "a_b",
            "..",
            "a/b",
            "a%2Fb",
            "a..b",
            &"a".repeat(64),
        ] {
            assert!(!is_dns_label(bad) && !is_dns_subdomain(bad), "{bad}");
        }
        let long = vec!["a".repeat(63); 4].join(".");
        assert!(!is_dns_subdomain(&long));
    }
}
