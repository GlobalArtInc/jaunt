use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::CaError;
use crate::fsutil::{create_new_private_dir, ensure_private_dir, random_hex, sync_dir};

pub(crate) const SUFFIX_BYTES: usize = 8;

#[derive(Debug)]
pub struct Committed {
    pub sync_failure: Option<CaError>,
}

#[derive(Debug)]
pub struct StagingDir {
    path: PathBuf,
    pending: bool,
}

impl StagingDir {
    pub fn create(parent: &Path, prefix: &str) -> Result<Self, CaError> {
        let valid_prefix = !prefix.is_empty()
            && prefix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid_prefix {
            return Err(CaError::io("create staging directory", parent)(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid staging prefix"),
            ));
        }
        ensure_private_dir(parent, false).map_err(CaError::io("create directory", parent))?;
        let suffix =
            random_hex(SUFFIX_BYTES).map_err(CaError::io("create staging directory", parent))?;
        let path = parent.join(format!("{prefix}-{suffix}"));
        create_new_private_dir(&path).map_err(CaError::io("create staging directory", &path))?;
        Ok(Self {
            path,
            pending: true,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn commit(&mut self, target: &Path) -> Result<Committed, CaError> {
        self.commit_with(target, &sync_dir)
    }

    pub(crate) fn commit_with(
        &mut self,
        target: &Path,
        sync_parent: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<Committed, CaError> {
        fs::rename(&self.path, target).map_err(CaError::io("rename into place", target))?;
        self.pending = false;
        let sync_failure = target
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .and_then(|parent| {
                sync_parent(parent)
                    .err()
                    .map(CaError::io("sync directory", parent))
            });
        Ok(Committed { sync_failure })
    }

    pub fn discard(mut self) -> Result<(), CaError> {
        self.pending = false;
        match fs::remove_dir_all(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(CaError::io("remove staging directory", &self.path)(err)),
        }
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if self.pending {
            drop(fs::remove_dir_all(&self.path));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::StagingDir;
    use crate::error::CaError;

    #[test]
    fn staging_directories_are_private_and_uniquely_named() {
        let parent = tempfile::tempdir().unwrap();
        let first = StagingDir::create(parent.path(), "ca.staging").unwrap();
        let second = StagingDir::create(parent.path(), "ca.staging").unwrap();
        assert_ne!(first.path(), second.path());
        let name = first.path().file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("ca.staging-"));
        assert_eq!(name.len(), "ca.staging-".len() + 16);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(first.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        assert!(StagingDir::create(parent.path(), "../escape").is_err());
        assert!(StagingDir::create(parent.path(), "").is_err());
    }

    #[test]
    fn commit_moves_the_directory_and_drop_cleans_up_otherwise() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("ca");

        let mut committed = StagingDir::create(parent.path(), "stage").unwrap();
        fs::write(committed.path().join("file"), b"data").unwrap();
        let committed_path = committed.path().to_path_buf();
        assert!(committed.commit(&target).unwrap().sync_failure.is_none());
        drop(committed);
        assert_eq!(fs::read(target.join("file")).unwrap(), b"data");
        assert!(!committed_path.exists());

        let abandoned = StagingDir::create(parent.path(), "stage").unwrap();
        let abandoned_path = abandoned.path().to_path_buf();
        drop(abandoned);
        assert!(!abandoned_path.exists());

        let discarded = StagingDir::create(parent.path(), "stage").unwrap();
        let discarded_path = discarded.path().to_path_buf();
        fs::write(discarded_path.join("file"), b"data").unwrap();
        discarded.discard().unwrap();
        assert!(!discarded_path.exists());
    }

    #[test]
    fn failed_directory_sync_after_rename_is_reported_but_not_fatal() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("ca");
        let mut staging = StagingDir::create(parent.path(), "stage").unwrap();
        fs::write(staging.path().join("file"), b"data").unwrap();
        let staging_path = staging.path().to_path_buf();

        let committed = staging
            .commit_with(&target, &|_| Err(std::io::Error::other("injected")))
            .unwrap();
        assert!(matches!(
            committed.sync_failure,
            Some(CaError::Io {
                op: "sync directory",
                ..
            })
        ));
        assert_eq!(fs::read(target.join("file")).unwrap(), b"data");
        drop(staging);
        assert!(!staging_path.exists());
        assert!(target.join("file").exists());
    }

    #[test]
    fn commit_does_not_replace_a_non_empty_target() {
        let parent = tempfile::tempdir().unwrap();
        let target = parent.path().join("ca");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("existing"), b"keep").unwrap();

        let mut staging = StagingDir::create(parent.path(), "stage").unwrap();
        fs::write(staging.path().join("new"), b"new").unwrap();
        assert!(staging.commit(&target).is_err());
        assert_eq!(fs::read(target.join("existing")).unwrap(), b"keep");
        assert!(!target.join("new").exists());
        assert!(staging.path().exists());
    }
}
