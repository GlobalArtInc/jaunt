use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const DATABASE_FILE: &str = "jaunt.db";
const DATABASE_MODE: u32 = 0o600;
const PERMISSION_BITS: u32 = 0o777;
const OTHERS: u32 = 0o007;
const GROUP_AND_OTHERS: u32 = 0o077;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exposure {
    DataDirAccessibleByOthers { mode: u32 },
    DatabaseAccessibleByGroupOrOthers { mode: u32 },
}

#[derive(Debug)]
pub struct Prepared {
    pub database: PathBuf,
    pub exposures: Vec<Exposure>,
}

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("cannot inspect the data directory {}: {source}", path.display())]
    DataDir {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot prepare the database file {}: {source}", path.display())]
    Database {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub fn prepare(data_dir: &Path) -> Result<Prepared, StorageError> {
    let mut exposures = Vec::new();

    let dir_mode = fs::metadata(data_dir)
        .map_err(|source| StorageError::DataDir {
            path: data_dir.to_path_buf(),
            source,
        })?
        .permissions()
        .mode()
        & PERMISSION_BITS;
    if dir_mode & OTHERS != 0 {
        exposures.push(Exposure::DataDirAccessibleByOthers { mode: dir_mode });
    }

    let database = data_dir.join(DATABASE_FILE);
    let database_error = |source| StorageError::Database {
        path: database.clone(),
        source,
    };
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(DATABASE_MODE)
        .open(&database)
        .map_err(database_error)?;
    let file_mode = file
        .metadata()
        .map_err(database_error)?
        .permissions()
        .mode()
        & PERMISSION_BITS;
    if file_mode & GROUP_AND_OTHERS != 0 {
        exposures.push(Exposure::DatabaseAccessibleByGroupOrOthers { mode: file_mode });
    }

    Ok(Prepared {
        database,
        exposures,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use jaunt_store::Store;

    use super::{Exposure, StorageError, prepare};

    const CHILD_DIR_VAR: &str = "JAUNTD_STORAGE_TEST_DATA_DIR";
    const CHILD_TEST: &str = "storage::tests::database_files_are_private_under_a_permissive_umask";

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o700);
        dir
    }

    fn assert_private_while_open(data_dir: &Path) {
        let prepared = prepare(data_dir).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = Store::open(&prepared.database).await.unwrap();
            store.migrate().await.unwrap();
            store
                .users()
                .upsert(
                    &jaunt_store::NewUser {
                        issuer: "https://idp.example".to_owned(),
                        subject: "subject".to_owned(),
                        email: "ada@example.com".to_owned(),
                        username: "ada".to_owned(),
                        display_name: None,
                        groups: Vec::new(),
                    },
                    1,
                )
                .await
                .unwrap();
            for name in ["jaunt.db", "jaunt.db-wal", "jaunt.db-shm"] {
                let path = data_dir.join(name);
                assert!(path.exists(), "{name} was not created");
                assert_eq!(mode_of(&path), 0o600, "{name}");
            }
        });
    }

    #[test]
    fn database_files_are_private_under_a_permissive_umask() {
        if let Some(dir) = std::env::var_os(CHILD_DIR_VAR) {
            assert_private_while_open(Path::new(&dir));
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let status = Command::new("sh")
            .args([
                "-c",
                "umask 022 && exec \"$0\" --exact \"$1\" --test-threads=1",
            ])
            .arg(std::env::current_exe().unwrap())
            .arg(CHILD_TEST)
            .env(CHILD_DIR_VAR, dir.path())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn a_fresh_database_is_created_private_and_reports_nothing() {
        let dir = private_dir();
        let prepared = prepare(dir.path()).unwrap();
        assert_eq!(prepared.database, dir.path().join("jaunt.db"));
        assert_eq!(mode_of(&prepared.database), 0o600);
        assert!(prepared.exposures.is_empty());
    }

    #[test]
    fn an_existing_database_keeps_its_mode_and_is_reported_when_exposed() {
        let dir = private_dir();
        let database = dir.path().join("jaunt.db");
        fs::write(&database, b"existing contents").unwrap();
        for (mode, exposed) in [(0o600, false), (0o640, true), (0o604, true), (0o644, true)] {
            set_mode(&database, mode);
            let prepared = prepare(dir.path()).unwrap();
            assert_eq!(mode_of(&database), mode);
            assert_eq!(fs::read(&database).unwrap(), b"existing contents");
            let expected: Vec<Exposure> = exposed
                .then_some(Exposure::DatabaseAccessibleByGroupOrOthers { mode })
                .into_iter()
                .collect();
            assert_eq!(prepared.exposures, expected, "{mode:o}");
        }
    }

    #[test]
    fn a_data_dir_open_to_others_is_reported_but_group_access_is_tolerated() {
        let dir = private_dir();
        for (mode, exposed) in [(0o700, false), (0o750, false), (0o705, true), (0o755, true)] {
            set_mode(dir.path(), mode);
            let prepared = prepare(dir.path()).unwrap();
            let reported = prepared
                .exposures
                .contains(&Exposure::DataDirAccessibleByOthers { mode });
            assert_eq!(reported, exposed, "{mode:o}");
        }
    }

    #[test]
    fn a_missing_data_dir_or_an_unusable_database_path_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = prepare(&dir.path().join("absent")).err().unwrap();
        assert!(matches!(missing, StorageError::DataDir { .. }));
        fs::create_dir(dir.path().join("jaunt.db")).unwrap();
        let blocked = prepare(dir.path()).err().unwrap();
        assert!(matches!(blocked, StorageError::Database { .. }));
    }
}
