use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use jaunt_proto::ClientConfig;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::gate_config::GateServices;
use crate::profile::{ProfileName, profile_dir};
use crate::secret::Secret;
use crate::server_url::ServerUrl;
use crate::ssh_config::{is_dns_label, validate};

const SERVER_FILE: &str = "server";
const PUBLIC_KEY_FILE: &str = "id_ed25519.pub";
const CERTIFICATE_FILE: &str = "id_ed25519-cert.pub";
const TOKEN_FILE: &str = "token";
const META_FILE: &str = "meta.json";
const PRIVATE_KEY_FILE: &str = "id_ed25519";
const CLIENT_FILE: &str = "client.json";
const SSH_CONFIG_FILE: &str = "ssh_config";
const KNOWN_HOSTS_FILE: &str = "known_hosts";
const SERVICES_FILE: &str = "services.json";
const OWNED_FILES: [&str; 10] = [
    PRIVATE_KEY_FILE,
    CERTIFICATE_FILE,
    PUBLIC_KEY_FILE,
    TOKEN_FILE,
    META_FILE,
    SERVER_FILE,
    CLIENT_FILE,
    SSH_CONFIG_FILE,
    KNOWN_HOSTS_FILE,
    SERVICES_FILE,
];
pub(crate) const X509_DIR: &str = "x509";
pub(crate) const X509_KEY_FILE: &str = "key.pem";
pub(crate) const X509_CERT_FILE: &str = "cert.pem";
const X509_OWNED_FILES: [&str; 2] = [X509_KEY_FILE, X509_CERT_FILE];
pub const DB_DIR: &str = "db";
pub const DB_SOCKET_FILE: &str = ".s.PGSQL.5432";
pub const DB_LOCK_FILE: &str = ".lock";
pub const RUN_DIR_PREFIX: &str = ".connect-";
pub const RUN_DIR_RANDOM_HEX: usize = 16;
const MAX_MARKER_BYTES: u64 = 64;
const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const PRIVATE_MODE_FORBIDDEN: u32 = 0o077;
const MAX_READ_BYTES: u64 = 1024 * 1024;
const STALE_AFTER: Duration = Duration::from_secs(15 * 60);

pub(crate) static SIBLING_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub user_id: String,
    pub email: String,
    pub serial: i64,
    pub key_id: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub token_expires_at: i64,
    pub host_ca_keys: Vec<String>,
}

pub struct LoginFiles<'a> {
    pub server: &'a ServerUrl,
    pub public_key_line: &'a str,
    pub certificate_line: &'a str,
    pub token: &'a Secret,
    pub meta: &'a ProfileMeta,
    pub ssh: Option<&'a SshFiles>,
    pub services: Option<ServicesFile<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicesFile<'a> {
    Checked(&'a GateServices),
    Kept(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshFiles {
    pub client: ClientConfig,
    pub ssh_config: String,
    pub known_hosts: String,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    #[error("{path} is not a plain directory")]
    NotADirectory { path: PathBuf },
    #[error("{path} is not a regular file")]
    NotARegularFile { path: PathBuf },
    #[error("{path} is too large")]
    TooLarge { path: PathBuf },
    #[error("{path} is damaged; run `jaunt logout` and sign in again")]
    Corrupt { path: PathBuf },
    #[error(
        "{path} can be read by other users; restrict it with `chmod 600` or run `jaunt login` again"
    )]
    Exposed { path: PathBuf },
    #[error("{path} still contains other files and was kept")]
    NotEmpty { path: PathBuf },
    #[error(
        "the previous profile was left in {path}: move it back to {profile} or run `jaunt logout`"
    )]
    Stranded { path: PathBuf, profile: PathBuf },
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cleared {
    pub removed_any: bool,
    pub directory_kept: bool,
}

#[derive(Debug, Clone)]
pub struct ProfileStore {
    home: PathBuf,
    name: String,
    dir: PathBuf,
}

impl ProfileStore {
    pub fn new(home: &Path, name: &ProfileName) -> ProfileStore {
        ProfileStore {
            home: home.to_owned(),
            name: name.as_str().to_owned(),
            dir: profile_dir(home, name),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn lock_path(&self) -> PathBuf {
        self.home.join(format!(".{}.lock", self.name))
    }

    pub fn failure_marker_path(&self) -> PathBuf {
        self.home.join(format!(".{}.ensure-failed", self.name))
    }

    pub fn read_failure_marker(&self) -> Option<i64> {
        let path = self.failure_marker_path();
        let meta = fs::symlink_metadata(&path).ok()?;
        if !meta.is_file() || meta.len() > MAX_MARKER_BYTES {
            return None;
        }
        fs::read_to_string(&path).ok()?.trim().parse::<i64>().ok()
    }

    pub fn write_failure_marker(&self, unix_secs: i64) -> Result<(), StoreError> {
        let path = self.failure_marker_path();
        let serial = SIBLING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = self.home.join(format!(
            ".{}.ensure-failed.tmp.{}.{serial}",
            self.name,
            std::process::id()
        ));
        if let Err(err) = write_new_file(&temporary, format!("{unix_secs}\n").as_bytes()) {
            drop(fs::remove_file(&temporary));
            return Err(io_error("write", &temporary, err));
        }
        fs::rename(&temporary, &path).map_err(|err| {
            drop(fs::remove_file(&temporary));
            io_error("replace", &path, err)
        })
    }

    pub fn clear_failure_marker(&self) -> Result<(), StoreError> {
        remove_if_present(&self.failure_marker_path()).map(drop)
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.dir.join(PUBLIC_KEY_FILE)
    }

    pub fn certificate_path(&self) -> PathBuf {
        self.dir.join(CERTIFICATE_FILE)
    }

    pub fn private_key_path(&self) -> PathBuf {
        self.dir.join(PRIVATE_KEY_FILE)
    }

    pub fn read_server(&self) -> Result<Option<ServerUrl>, StoreError> {
        let path = self.dir.join(SERVER_FILE);
        let Some(text) = self.read_text(&path)? else {
            return Ok(None);
        };
        ServerUrl::parse(text.trim())
            .map(Some)
            .map_err(|_| StoreError::Corrupt { path })
    }

    pub fn read_meta(&self) -> Result<Option<ProfileMeta>, StoreError> {
        let path = self.dir.join(META_FILE);
        let Some(bytes) = self.read_bytes(&path)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError::Corrupt { path })
    }

    pub fn ssh_config_path(&self) -> PathBuf {
        self.dir.join(SSH_CONFIG_FILE)
    }

    pub fn known_hosts_path(&self) -> PathBuf {
        self.dir.join(KNOWN_HOSTS_FILE)
    }

    pub fn read_client_config(&self) -> Result<Option<ClientConfig>, StoreError> {
        let path = self.dir.join(CLIENT_FILE);
        let Some(bytes) = self.read_bytes(&path)? else {
            return Ok(None);
        };
        let parsed: ClientConfig = serde_json::from_slice(&bytes)
            .map_err(|_| StoreError::Corrupt { path: path.clone() })?;
        validate(parsed)
            .map(Some)
            .map_err(|_| StoreError::Corrupt { path })
    }

    pub fn read_gate_services(&self) -> Result<Option<GateServices>, StoreError> {
        let path = self.dir.join(SERVICES_FILE);
        let Some(bytes) = self.read_bytes(&path)? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError::Corrupt { path })
    }

    pub fn read_gate_services_bytes(&self) -> Result<Option<Vec<u8>>, StoreError> {
        self.read_bytes(&self.dir.join(SERVICES_FILE))
    }

    pub fn x509_dir(&self) -> PathBuf {
        self.dir.join(X509_DIR)
    }

    pub fn forget_x509_certificate(&self) -> Result<bool, StoreError> {
        let dir = self.x509_dir();
        match fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => remove_if_present(&dir.join(X509_CERT_FILE)),
            Ok(_) => Err(StoreError::NotADirectory { path: dir }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(io_error("inspect", &dir, err)),
        }
    }

    pub fn read_certificate_line(&self) -> Result<Option<String>, StoreError> {
        let path = self.certificate_path();
        Ok(self.read_text(&path)?.map(|text| text.trim().to_owned()))
    }

    pub fn read_ssh_config(&self) -> Result<Option<String>, StoreError> {
        let path = self.ssh_config_path();
        self.read_text(&path)
    }

    pub fn ssh_files_present(&self) -> Result<bool, StoreError> {
        for path in [self.ssh_config_path(), self.known_hosts_path()] {
            if self.read_bytes(&path)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn shadowing_profiles(&self, suffix: &str) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.home) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name >= self.name {
                continue;
            }
            let Ok(profile) = ProfileName::parse(&name) else {
                continue;
            };
            let other = ProfileStore::new(&self.home, &profile);
            let same_suffix = matches!(
                other.read_client_config(),
                Ok(Some(config)) if config.ssh_suffix == suffix
            );
            if same_suffix && matches!(other.ssh_files_present(), Ok(true)) {
                found.push(name);
            }
        }
        found.sort();
        found
    }

    pub fn has_any_ssh_file(&self) -> Result<bool, StoreError> {
        if !self.dir_exists()? {
            return Ok(false);
        }
        for name in [CLIENT_FILE, SSH_CONFIG_FILE, KNOWN_HOSTS_FILE] {
            let path = self.dir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => return Ok(true),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(io_error("inspect", &path, err)),
            }
        }
        Ok(false)
    }

    pub fn read_token(&self) -> Result<Option<Secret>, StoreError> {
        let path = self.dir.join(TOKEN_FILE);
        let Some(mut text) = self.read_text(&path)? else {
            return Ok(None);
        };
        let trimmed = text.trim_end().len();
        text.truncate(trimmed);
        if text.is_empty() {
            return Err(StoreError::Corrupt { path });
        }
        Ok(Some(Secret::new(text)))
    }

    pub fn read_private_key(&self) -> Result<Option<Secret>, StoreError> {
        let path = self.private_key_path();
        if !self.dir_exists()? {
            return Ok(None);
        }
        match fs::symlink_metadata(&path) {
            Ok(meta) if !meta.is_file() => return Err(StoreError::NotARegularFile { path }),
            Ok(meta) if meta.permissions().mode() & PRIVATE_MODE_FORBIDDEN != 0 => {
                return Err(StoreError::Exposed { path });
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error("inspect", &path, err)),
        }
        let Some(bytes) = self.read_bytes(&path)?.map(Zeroizing::new) else {
            return Ok(None);
        };
        match std::str::from_utf8(&bytes) {
            Ok(text) => Ok(Some(Secret::new(text.to_owned()))),
            Err(_) => Err(StoreError::Corrupt { path }),
        }
    }

    pub fn read_public_key_line(&self) -> Result<Option<String>, StoreError> {
        let path = self.public_key_path();
        Ok(self.read_text(&path)?.map(|text| text.trim().to_owned()))
    }

    pub fn begin(
        &self,
        files: &LoginFiles<'_>,
        now: SystemTime,
    ) -> Result<Transaction, StoreError> {
        self.dir_exists()?;
        let meta = serde_json::to_vec_pretty(files.meta).map_err(|_| StoreError::Corrupt {
            path: self.dir.join(META_FILE),
        })?;
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&self.home)
            .map_err(|err| io_error("create", &self.home, err))?;
        let sweep_warning = match now.checked_sub(STALE_AFTER) {
            Some(limit) => self.sweep_siblings(Some(limit)).err(),
            None => None,
        };
        let staging = self.sibling("new");
        DirBuilder::new()
            .mode(DIR_MODE)
            .create(&staging)
            .map_err(|err| io_error("create", &staging, err))?;
        let transaction = Transaction {
            home: self.home.clone(),
            profile: self.dir.clone(),
            name: self.name.clone(),
            staging,
            server_line: line_bytes(files.server.as_str()),
            now,
            sweep_warning,
            committed: false,
        };
        transaction.write(PUBLIC_KEY_FILE, &line_bytes(files.public_key_line))?;
        transaction.write(CERTIFICATE_FILE, &line_bytes(files.certificate_line))?;
        transaction.write(TOKEN_FILE, files.token.expose().as_bytes())?;
        transaction.write(META_FILE, &meta)?;
        if let Some(ssh) = files.ssh {
            let client =
                serde_json::to_vec_pretty(&ssh.client).map_err(|_| StoreError::Corrupt {
                    path: self.dir.join(CLIENT_FILE),
                })?;
            transaction.write(CLIENT_FILE, &client)?;
            transaction.write(SSH_CONFIG_FILE, ssh.ssh_config.as_bytes())?;
            transaction.write(KNOWN_HOSTS_FILE, ssh.known_hosts.as_bytes())?;
        }
        match files.services {
            Some(ServicesFile::Checked(services)) => {
                let services =
                    serde_json::to_vec_pretty(services).map_err(|_| StoreError::Corrupt {
                        path: self.dir.join(SERVICES_FILE),
                    })?;
                transaction.write(SERVICES_FILE, &services)?;
            }
            Some(ServicesFile::Kept(bytes)) => transaction.write(SERVICES_FILE, bytes)?,
            None => {}
        }
        Ok(transaction)
    }

    pub fn clear(&self) -> Result<Cleared, StoreError> {
        let mut removed_any = false;
        let mut directory_kept = false;
        let mut failure: Option<StoreError> = None;
        match self.sweep_siblings(None) {
            Ok(swept) => removed_any |= swept,
            Err(err) => {
                failure.get_or_insert(err);
            }
        }
        match self.dir_exists() {
            Ok(false) => {}
            Ok(true) => {
                let (removed, first_error) = remove_owned(&self.dir);
                removed_any |= removed;
                let first_error = match remove_x509(&self.dir.join(X509_DIR)) {
                    Ok(removed) => {
                        removed_any |= removed;
                        first_error
                    }
                    Err(err) => first_error.or(Some(err)),
                };
                let first_error = match remove_db(&self.dir.join(DB_DIR)) {
                    Ok(removed) => {
                        removed_any |= removed;
                        first_error
                    }
                    Err(err) => first_error.or(Some(err)),
                };
                match (first_error, fs::remove_dir(&self.dir)) {
                    (Some(err), _) => {
                        failure.get_or_insert(err);
                    }
                    (None, Ok(())) => {}
                    (None, Err(err)) if err.kind() == io::ErrorKind::NotFound => {}
                    (None, Err(err)) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {
                        directory_kept = true;
                    }
                    (None, Err(err)) => {
                        failure.get_or_insert(io_error("remove", &self.dir, err));
                    }
                }
            }
            Err(err) => {
                failure.get_or_insert(err);
            }
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(Cleared {
                removed_any,
                directory_kept,
            }),
        }
    }

    fn sibling(&self, kind: &str) -> PathBuf {
        let serial = SIBLING_COUNTER.fetch_add(1, Ordering::Relaxed);
        self.home.join(format!(
            ".{}.{kind}.{}.{serial}",
            self.name,
            std::process::id()
        ))
    }

    fn sweep_siblings(&self, older_than: Option<SystemTime>) -> Result<bool, StoreError> {
        let entries = match fs::read_dir(&self.home) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(io_error("list", &self.home, err)),
        };
        let new_prefix = format!(".{}.new.", self.name);
        let old_prefix = format!(".{}.old.", self.name);
        let mut swept = false;
        let mut failure: Option<StoreError> = None;
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    failure.get_or_insert(io_error("list", &self.home, err));
                    continue;
                }
            };
            let file_name = entry.file_name();
            let Some(text) = file_name.to_str() else {
                continue;
            };
            if !(text.starts_with(&new_prefix) || text.starts_with(&old_prefix)) {
                continue;
            }
            let path = entry.path();
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() => {
                    if let Some(limit) = older_than {
                        match meta.modified() {
                            Ok(modified) if modified < limit => {}
                            Ok(_) => continue,
                            Err(err) => {
                                failure.get_or_insert(io_error("inspect", &path, err));
                                continue;
                            }
                        }
                    }
                    let (_, first_error) = remove_owned(&path);
                    let first_error = match remove_x509(&path.join(X509_DIR)) {
                        Ok(_) => first_error,
                        Err(err) => first_error.or(Some(err)),
                    };
                    let removed = fs::remove_dir_all(&path);
                    match (first_error, removed) {
                        (Some(err), _) => {
                            failure.get_or_insert(err);
                        }
                        (None, Ok(())) => swept = true,
                        (None, Err(err)) => {
                            failure.get_or_insert(io_error("remove", &path, err));
                        }
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    failure.get_or_insert(io_error("inspect", &path, err));
                }
            }
        }
        match failure {
            Some(err) => Err(err),
            None => Ok(swept),
        }
    }

    pub fn stranded_dirs(&self) -> Result<Vec<PathBuf>, StoreError> {
        let entries = match fs::read_dir(&self.home) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(io_error("list", &self.home, err)),
        };
        let prefix = format!(".{}.old.", self.name);
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|err| io_error("list", &self.home, err))?;
            let matches_prefix = entry
                .file_name()
                .to_str()
                .is_some_and(|text| text.starts_with(&prefix));
            if matches_prefix && fs::symlink_metadata(entry.path()).is_ok_and(|meta| meta.is_dir())
            {
                found.push(entry.path());
            }
        }
        found.sort();
        Ok(found)
    }

    fn dir_exists(&self) -> Result<bool, StoreError> {
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => Ok(true),
            Ok(_) => Err(StoreError::NotADirectory {
                path: self.dir.clone(),
            }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(io_error("inspect", &self.dir, err)),
        }
    }

    fn read_bytes(&self, path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
        if !self.dir_exists()? {
            return Ok(None);
        }
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io_error("inspect", path, err)),
        };
        if !meta.is_file() {
            return Err(StoreError::NotARegularFile {
                path: path.to_owned(),
            });
        }
        if meta.len() > MAX_READ_BYTES {
            return Err(StoreError::TooLarge {
                path: path.to_owned(),
            });
        }
        fs::read(path)
            .map(Some)
            .map_err(|err| io_error("read", path, err))
    }

    fn read_text(&self, path: &Path) -> Result<Option<String>, StoreError> {
        match self.read_bytes(path)? {
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| StoreError::Corrupt {
                    path: path.to_owned(),
                }),
            None => Ok(None),
        }
    }
}

#[derive(Debug)]
pub struct Transaction {
    home: PathBuf,
    profile: PathBuf,
    name: String,
    staging: PathBuf,
    server_line: Vec<u8>,
    now: SystemTime,
    sweep_warning: Option<StoreError>,
    committed: bool,
}

impl Transaction {
    pub fn staging_dir(&self) -> &Path {
        &self.staging
    }

    pub fn sweep_warning(&self) -> Option<&StoreError> {
        self.sweep_warning.as_ref()
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.staging.join(PUBLIC_KEY_FILE)
    }

    pub fn write_private_key(&self, pem: &Secret) -> Result<(), StoreError> {
        self.write(PRIVATE_KEY_FILE, pem.expose().as_bytes())
    }

    pub fn commit(&mut self) -> Result<Option<Retired>, StoreError> {
        self.commit_with(&|from, to| fs::rename(from, to))
    }

    fn commit_with(
        &mut self,
        rename: &dyn Fn(&Path, &Path) -> io::Result<()>,
    ) -> Result<Option<Retired>, StoreError> {
        self.write(SERVER_FILE, &self.server_line)?;
        sync_dir(&self.staging)?;
        let retired = match fs::symlink_metadata(&self.profile) {
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                rename(&self.staging, &self.profile)
                    .map_err(|err| io_error("install", &self.profile, err))?;
                None
            }
            Ok(meta) if meta.is_dir() => Some(self.replace_profile(rename)?),
            Ok(_) => {
                return Err(StoreError::NotADirectory {
                    path: self.profile.clone(),
                });
            }
            Err(err) => return Err(io_error("inspect", &self.profile, err)),
        };
        self.committed = true;
        drop(sync_dir(&self.home));
        Ok(retired)
    }

    fn replace_profile(
        &self,
        rename: &dyn Fn(&Path, &Path) -> io::Result<()>,
    ) -> Result<Retired, StoreError> {
        let serial = SIBLING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let retired = self.home.join(format!(
            ".{}.old.{}.{serial}",
            self.name,
            std::process::id()
        ));
        File::open(&self.profile)
            .and_then(|dir| dir.set_modified(self.now))
            .map_err(|err| io_error("mark", &self.profile, err))?;
        rename(&self.profile, &retired).map_err(|err| io_error("retire", &self.profile, err))?;
        if let Err(err) = rename(&self.staging, &self.profile) {
            return Err(match rename(&retired, &self.profile) {
                Ok(()) => io_error("install", &self.profile, err),
                Err(_) => StoreError::Stranded {
                    path: retired,
                    profile: self.profile.clone(),
                },
            });
        }
        let carry_error = carry_foreign_entries(&retired, &self.profile);
        Ok(Retired {
            dir: retired,
            carry_error,
        })
    }

    fn write(&self, name: &str, contents: &[u8]) -> Result<(), StoreError> {
        let path = self.staging.join(name);
        write_new_file(&path, contents).map_err(|err| io_error("write", &path, err))
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            drop(shred(&self.staging.join(PRIVATE_KEY_FILE)));
            drop(fs::remove_dir_all(&self.staging));
        }
    }
}

#[derive(Debug)]
pub struct Retired {
    dir: PathBuf,
    carry_error: Option<StoreError>,
}

impl Retired {
    pub fn public_key_path(&self) -> PathBuf {
        self.dir.join(PUBLIC_KEY_FILE)
    }

    pub fn discard(self) -> Result<(), StoreError> {
        let (_, first_error) = remove_owned(&self.dir);
        let removal = fs::remove_dir(&self.dir);
        if let Some(err) = self.carry_error.or(first_error) {
            return Err(err);
        }
        match removal {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {
                Err(StoreError::NotEmpty { path: self.dir })
            }
            Err(err) => Err(io_error("remove", &self.dir, err)),
        }
    }
}

fn is_owned_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|text| {
        OWNED_FILES.contains(&text)
            || (text.starts_with('.')
                && text.ends_with(".tmp")
                && OWNED_FILES
                    .iter()
                    .any(|owned| text.starts_with(&format!(".{owned}."))))
    })
}

fn carry_foreign_entries(from: &Path, to: &Path) -> Option<StoreError> {
    let entries = match fs::read_dir(from) {
        Ok(entries) => entries,
        Err(err) => return Some(io_error("list", from, err)),
    };
    let mut failure: Option<StoreError> = None;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                failure.get_or_insert(io_error("list", from, err));
                continue;
            }
        };
        let name = entry.file_name();
        if is_owned_name(&name) {
            continue;
        }
        if let Err(err) = fs::rename(entry.path(), to.join(&name)) {
            failure.get_or_insert(io_error("keep", &entry.path(), err));
        }
    }
    failure
}

fn remove_owned(dir: &Path) -> (bool, Option<StoreError>) {
    let mut removed = false;
    let mut failure: Option<StoreError> = None;
    let mut record = |result: Result<bool, StoreError>| match result {
        Ok(did_remove) => removed |= did_remove,
        Err(err) => {
            failure.get_or_insert(err);
        }
    };
    record(shred(&dir.join(PRIVATE_KEY_FILE)));
    for name in OWNED_FILES {
        if name != PRIVATE_KEY_FILE {
            record(remove_if_present(&dir.join(name)));
        }
    }
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) if is_owned_name(&entry.file_name()) => {
                        record(shred(&entry.path()));
                    }
                    Ok(_) => {}
                    Err(err) => record(Err(io_error("list", dir, err))),
                }
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => record(Err(io_error("list", dir, err))),
    }
    (removed, failure)
}

fn is_x509_owned_name(name: &OsStr) -> bool {
    name.to_str().is_some_and(|text| {
        X509_OWNED_FILES.contains(&text)
            || (text.starts_with('.')
                && text.ends_with(".tmp")
                && X509_OWNED_FILES
                    .iter()
                    .any(|owned| text.starts_with(&format!(".{owned}."))))
    })
}

fn remove_x509(dir: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return remove_if_present(dir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(io_error("inspect", dir, err)),
    }
    let mut removed = false;
    let mut failure: Option<StoreError> = None;
    let mut record = |result: Result<bool, StoreError>| match result {
        Ok(did_remove) => removed |= did_remove,
        Err(err) => {
            failure.get_or_insert(err);
        }
    };
    record(shred(&dir.join(X509_KEY_FILE)));
    match fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) if is_x509_owned_name(&entry.file_name()) => {
                        record(shred(&entry.path()));
                    }
                    Ok(_) => {}
                    Err(err) => record(Err(io_error("list", dir, err))),
                }
            }
        }
        Err(err) => record(Err(io_error("list", dir, err))),
    }
    if let Some(err) = failure {
        return Err(err);
    }
    match fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(removed),
        Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(removed),
        Err(err) => Err(io_error("remove", dir, err)),
    }
}

pub fn is_run_dir_name(name: &str) -> bool {
    name.strip_prefix(RUN_DIR_PREFIX).is_some_and(|random| {
        random.len() == RUN_DIR_RANDOM_HEX
            && random
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_db_owned_dir(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|text| is_run_dir_name(text) || is_dns_label(text))
}

fn remove_socket_dir(dir: &Path) -> Result<bool, StoreError> {
    let mut removed = false;
    let socket = dir.join(DB_SOCKET_FILE);
    match fs::symlink_metadata(&socket) {
        Ok(meta) if meta.file_type().is_socket() => removed |= remove_if_present(&socket)?,
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error("inspect", &socket, err)),
    }
    let lock = dir.join(DB_LOCK_FILE);
    match fs::symlink_metadata(&lock) {
        Ok(meta) if meta.is_file() => removed |= remove_if_present(&lock)?,
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(io_error("inspect", &lock, err)),
    }
    match fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(removed),
        Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(removed),
        Err(err) => Err(io_error("remove", dir, err)),
    }
}

fn remove_db(dir: &Path) -> Result<bool, StoreError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return remove_if_present(dir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(io_error("inspect", dir, err)),
    }
    let mut removed = false;
    let entries = fs::read_dir(dir).map_err(|err| io_error("list", dir, err))?;
    for entry in entries {
        let entry = entry.map_err(|err| io_error("list", dir, err))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|err| io_error("inspect", &path, err))?;
        if meta.is_dir() && is_db_owned_dir(&entry.file_name()) {
            removed |= remove_socket_dir(&path)?;
        }
    }
    match fs::remove_dir(dir) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(removed),
        Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => Ok(removed),
        Err(err) => Err(io_error("remove", dir, err)),
    }
}

fn line_bytes(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(b'\n');
    bytes
}

pub(crate) fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    File::open(dir)
        .and_then(|handle| handle.sync_all())
        .map_err(|err| io_error("flush", dir, err))
}

fn remove_if_present(path: &Path) -> Result<bool, StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error("remove", path, err)),
    }
}

pub(crate) fn shred(path: &Path) -> Result<bool, StoreError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(io_error("inspect", path, err)),
    };
    let overwritten = if meta.is_file() {
        overwrite_with_zeros(path, meta.len()).map_err(|err| io_error("overwrite", path, err))
    } else {
        Ok(())
    };
    let removed = remove_if_present(path);
    overwritten?;
    removed
}

fn overwrite_with_zeros(path: &Path, length: u64) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    io::copy(&mut io::repeat(0).take(length), &mut file)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::{self, File};
    use std::io;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    use tempfile::TempDir;

    use super::{
        Cleared, LoginFiles, ProfileMeta, ProfileStore, Retired, SIBLING_COUNTER, SshFiles,
        StoreError, Transaction,
    };
    use crate::profile::ProfileName;
    use crate::secret::Secret;
    use crate::server_url::ServerUrl;

    fn meta() -> ProfileMeta {
        ProfileMeta {
            user_id: "u-1".to_owned(),
            email: "a@example.com".to_owned(),
            serial: 7,
            key_id: "jaunt:a@example.com:7".to_owned(),
            valid_after: 100,
            valid_before: 900,
            token_expires_at: 900,
            host_ca_keys: vec!["ssh-ed25519 AAAA".to_owned()],
        }
    }

    fn store() -> (TempDir, ProfileStore) {
        let root = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(&root.path().join("state"), &ProfileName::default_name());
        (root, store)
    }

    fn try_begin(store: &ProfileStore, token: &str) -> Result<Transaction, StoreError> {
        let server = ServerUrl::parse("https://jaunt.example.com").unwrap();
        let token = Secret::new(token.to_owned());
        store.begin(
            &LoginFiles {
                server: &server,
                public_key_line: &format!("ssh-ed25519 PUB-{}", token.expose()),
                certificate_line: "ssh-ed25519-cert-v01@openssh.com CERT",
                token: &token,
                meta: &meta(),
                ssh: None,
                services: None,
            },
            SystemTime::now(),
        )
    }

    fn begin(store: &ProfileStore, token: &str) -> Transaction {
        try_begin(store, token).unwrap()
    }

    fn save(store: &ProfileStore, token: &str) -> Option<Retired> {
        begin(store, token).commit().unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn snapshot(dir: &Path) -> Vec<(String, u32, Vec<u8>)> {
        names(dir)
            .into_iter()
            .map(|name| {
                let path = dir.join(&name);
                (name, mode(&path), fs::read(&path).unwrap())
            })
            .collect()
    }

    fn running_as_root(dir: &Path) -> bool {
        fs::metadata(dir).unwrap().uid() == 0
    }

    fn age(dir: &Path, secs: u64) {
        File::open(dir)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(secs))
            .unwrap();
    }

    fn leftover_session(home: &Path, name: &str) -> PathBuf {
        let dir = home.join(name);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("token"), "jt_leftover").unwrap();
        fs::write(dir.join("id_ed25519"), "LEFTOVER-KEY\n").unwrap();
        dir
    }

    fn assert_zeroed(path: &Path, length: usize) {
        let content = fs::read(path).unwrap();
        assert_eq!(content.len(), length);
        assert!(content.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn a_transaction_stages_privately_writes_the_marker_last_and_installs_atomically() {
        let (root, store) = store();
        let mut transaction = begin(&store, "jt_first");
        assert!(!store.dir().exists());
        assert_eq!(mode(transaction.staging_dir()), 0o700);
        assert_eq!(
            names(transaction.staging_dir()),
            [
                "id_ed25519-cert.pub",
                "id_ed25519.pub",
                "meta.json",
                "token"
            ]
        );
        assert!(transaction.commit().unwrap().is_none());

        assert_eq!(mode(&root.path().join("state")), 0o700);
        assert_eq!(mode(store.dir()), 0o700);
        assert_eq!(
            names(store.dir()),
            [
                "id_ed25519-cert.pub",
                "id_ed25519.pub",
                "meta.json",
                "server",
                "token"
            ]
        );
        for name in names(store.dir()) {
            assert_eq!(mode(&store.dir().join(&name)), 0o600, "{name}");
        }
        assert_eq!(names(&root.path().join("state")), ["default"]);
        assert_eq!(store.read_token().unwrap().unwrap().expose(), "jt_first");
        assert_eq!(store.read_meta().unwrap(), Some(meta()));
        assert_eq!(
            store.read_server().unwrap().unwrap().as_str(),
            "https://jaunt.example.com"
        );
        assert_eq!(
            store.read_public_key_line().unwrap().as_deref(),
            Some("ssh-ed25519 PUB-jt_first")
        );
    }

    #[test]
    fn replacing_a_profile_retires_the_old_files_keeps_foreign_ones_and_tightens_the_mode() {
        let (root, store) = store();
        save(&store, "jt_first");
        fs::set_permissions(store.dir(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(store.dir().join("notes.txt"), "Host x\n").unwrap();
        fs::write(store.dir().join(".token.keep"), "keep-me\n").unwrap();
        fs::write(store.dir().join("id_ed25519"), "OLD-KEY\n").unwrap();
        for owned in ["ssh_config", "known_hosts", "client.json"] {
            fs::write(store.dir().join(owned), "old ssh setup\n").unwrap();
        }

        let retired = save(&store, "jt_second").unwrap();
        assert_eq!(
            fs::read_to_string(retired.public_key_path())
                .unwrap()
                .trim(),
            "ssh-ed25519 PUB-jt_first"
        );
        assert_eq!(mode(store.dir()), 0o700);
        assert_eq!(store.read_token().unwrap().unwrap().expose(), "jt_second");
        assert!(!store.private_key_path().exists());
        assert_eq!(
            fs::read_to_string(store.dir().join("notes.txt")).unwrap(),
            "Host x\n"
        );
        assert_eq!(
            fs::read_to_string(store.dir().join(".token.keep")).unwrap(),
            "keep-me\n"
        );
        for owned in ["ssh_config", "known_hosts", "client.json"] {
            assert!(!store.dir().join(owned).exists(), "{owned}");
        }
        assert!(!store.has_any_ssh_file().unwrap());

        retired.discard().unwrap();
        assert_eq!(names(&root.path().join("state")), ["default"]);
    }

    #[test]
    fn a_new_sign_in_keeps_the_x509_key_and_a_logout_keeps_only_foreign_x509_files() {
        let (_root, store) = store();
        save(&store, "jt_first");
        let x509 = store.x509_dir();
        fs::create_dir(&x509).unwrap();
        fs::write(x509.join("key.pem"), "KEY").unwrap();
        fs::write(x509.join("cert.pem"), "CERT").unwrap();
        fs::write(x509.join(".cert.pem.1.2.tmp"), "HALF").unwrap();

        save(&store, "jt_second").unwrap().discard().unwrap();

        assert_eq!(fs::read_to_string(x509.join("key.pem")).unwrap(), "KEY");
        fs::write(x509.join("notes.txt"), "mine").unwrap();
        let cleared = store.clear().unwrap();
        assert!(cleared.directory_kept);
        assert_eq!(names(&x509), ["notes.txt"]);
    }

    #[test]
    fn a_logout_removes_the_socket_directories_of_jaunt_and_keeps_anything_else_under_db() {
        let root = tempfile::Builder::new()
            .prefix("js")
            .tempdir_in("/tmp")
            .unwrap();
        let store = ProfileStore::new(&root.path().join("s"), &ProfileName::default_name());
        save(&store, "jt_first");
        let db = store.dir().join("db");
        let socket_dirs = [db.join("orders"), db.join(".connect-0123456789abcdef")];
        for dir in &socket_dirs {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(".lock"), "").unwrap();
            drop(std::os::unix::net::UnixListener::bind(dir.join(".s.PGSQL.5432")).unwrap());
        }

        let cleared = store.clear().unwrap();

        assert!(!cleared.directory_kept);
        assert!(!store.dir().exists());

        save(&store, "jt_second");
        for dir in &socket_dirs {
            fs::create_dir_all(dir).unwrap();
        }
        fs::write(db.join("orders").join("notes.txt"), "mine").unwrap();
        fs::create_dir(db.join(".connect-xyz")).unwrap();

        let cleared = store.clear().unwrap();

        assert!(cleared.directory_kept);
        assert_eq!(names(&db), [".connect-xyz", "orders"]);
        assert_eq!(names(&db.join("orders")), ["notes.txt"]);

        let foreign = root.path().join("foreign");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join(".lock"), "").unwrap();
        drop(std::os::unix::net::UnixListener::bind(foreign.join(".s.PGSQL.5432")).unwrap());
        fs::remove_file(db.join("orders").join("notes.txt")).unwrap();
        fs::write(db.join("orders").join(".s.PGSQL.5432"), "a file").unwrap();
        fs::remove_dir(db.join(".connect-xyz")).unwrap();
        std::os::unix::fs::symlink(&foreign, db.join("billing")).unwrap();

        let cleared = store.clear().unwrap();

        assert!(cleared.directory_kept);
        assert_eq!(names(&db), ["billing", "orders"]);
        assert_eq!(
            fs::read_to_string(db.join("orders").join(".s.PGSQL.5432")).unwrap(),
            "a file"
        );
        assert_eq!(names(&foreign), [".lock", ".s.PGSQL.5432"]);
    }

    #[test]
    fn a_failed_carry_leaves_the_x509_key_where_it_can_be_recovered() {
        let (root, _store) = store();
        let retired_dir = root.path().join(".default.old.1.2");
        fs::create_dir_all(retired_dir.join("x509")).unwrap();
        fs::write(retired_dir.join("x509/key.pem"), "KEY").unwrap();
        fs::write(retired_dir.join("token"), "jt_old").unwrap();
        let retired = Retired {
            dir: retired_dir.clone(),
            carry_error: Some(StoreError::NotEmpty {
                path: retired_dir.join("x509"),
            }),
        };

        let outcome = retired.discard();

        assert!(
            matches!(outcome, Err(StoreError::NotEmpty { .. })),
            "{outcome:?}"
        );
        assert_eq!(
            fs::read_to_string(retired_dir.join("x509/key.pem")).unwrap(),
            "KEY"
        );
        assert!(!retired_dir.join("token").exists());
    }

    #[test]
    fn an_abandoned_transaction_removes_its_staging_and_leaves_the_profile_untouched() {
        let (root, store) = store();
        save(&store, "jt_first");
        let before = snapshot(store.dir());

        let transaction = begin(&store, "jt_second");
        transaction
            .write_private_key(&Secret::new("NEW-KEY\n".to_owned()))
            .unwrap();
        let staging = transaction.staging_dir().to_owned();
        assert!(staging.exists());
        drop(transaction);

        assert!(!staging.exists());
        assert_eq!(snapshot(store.dir()), before);
        assert_eq!(names(&root.path().join("state")), ["default"]);
    }

    #[test]
    fn an_abandoned_transaction_wipes_a_staged_private_key_before_unlinking_it() {
        let (root, store) = store();
        let transaction = begin(&store, "jt_first");
        transaction
            .write_private_key(&Secret::new("STAGED-KEY\n".to_owned()))
            .unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(transaction.staging_dir().join("id_ed25519"), &alias).unwrap();
        drop(transaction);
        assert_zeroed(&alias, "STAGED-KEY\n".len());
    }

    #[test]
    fn a_symlinked_profile_directory_is_refused_and_its_target_untouched() {
        let (root, store) = store();
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("token"), "victim").unwrap();
        fs::create_dir_all(root.path().join("state")).unwrap();
        symlink(target.path(), store.dir()).unwrap();

        assert!(matches!(
            try_begin(&store, "jt_token"),
            Err(StoreError::NotADirectory { .. })
        ));
        assert!(matches!(
            store.clear(),
            Err(StoreError::NotADirectory { .. })
        ));
        assert!(matches!(
            store.read_token(),
            Err(StoreError::NotADirectory { .. })
        ));
        assert_eq!(names(target.path()), ["token"]);
        assert_eq!(
            fs::read_to_string(target.path().join("token")).unwrap(),
            "victim"
        );
        assert_eq!(names(&root.path().join("state")), ["default"]);
    }

    #[test]
    fn a_symlink_in_place_of_a_profile_file_is_refused_on_read_and_never_written_through() {
        let (_root, store) = store();
        save(&store, "jt_first");
        let foreign = tempfile::tempdir().unwrap();
        let victim = foreign.path().join("victim");
        fs::write(&victim, "foreign-content").unwrap();
        fs::remove_file(store.dir().join("token")).unwrap();
        symlink(&victim, store.dir().join("token")).unwrap();

        assert!(matches!(
            store.read_token(),
            Err(StoreError::NotARegularFile { .. })
        ));

        let retired = save(&store, "jt_second").unwrap();
        retired.discard().unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "foreign-content");
        assert!(
            fs::symlink_metadata(store.dir().join("token"))
                .unwrap()
                .is_file()
        );
        assert_eq!(store.read_token().unwrap().unwrap().expose(), "jt_second");
    }

    #[test]
    fn clear_shreds_the_key_removes_leftovers_and_stale_staging_keeps_foreign_files() {
        let (root, store) = store();
        assert_eq!(
            store.clear().unwrap(),
            Cleared {
                removed_any: false,
                directory_kept: false
            }
        );
        save(&store, "jt_token");
        fs::write(store.dir().join("id_ed25519"), "KEY-MATERIAL\n").unwrap();
        fs::write(store.dir().join(".id_ed25519.1.2.tmp"), "LEFTOVER-KEY\n").unwrap();
        fs::write(store.dir().join("notes.txt"), "Host x\n").unwrap();
        for owned in ["ssh_config", "known_hosts", "client.json"] {
            fs::write(store.dir().join(owned), "ssh setup\n").unwrap();
        }
        fs::write(store.dir().join(".token.keep"), "keep-me\n").unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(store.private_key_path(), &alias).unwrap();
        let home = root.path().join("state");
        let stale_new = leftover_session(&home, ".default.new.1.1");
        let stale_old = leftover_session(&home, ".default.old.1.2");
        let other_profile = leftover_session(&home, ".other.new.1.1");
        let lookalike = leftover_session(&home, ".default.keep");

        let cleared = store.clear().unwrap();
        assert_eq!(
            cleared,
            Cleared {
                removed_any: true,
                directory_kept: true
            }
        );
        assert_eq!(names(store.dir()), [".token.keep", "notes.txt"]);
        assert!(!stale_new.exists() && !stale_old.exists());
        assert_zeroed(&alias, "KEY-MATERIAL\n".len());
        for untouched in [&other_profile, &lookalike] {
            assert_eq!(names(untouched), ["id_ed25519", "token"]);
            assert_eq!(
                fs::read_to_string(untouched.join("id_ed25519")).unwrap(),
                "LEFTOVER-KEY\n"
            );
        }

        fs::remove_file(store.dir().join("notes.txt")).unwrap();
        fs::remove_file(store.dir().join(".token.keep")).unwrap();
        assert_eq!(
            store.clear().unwrap(),
            Cleared {
                removed_any: false,
                directory_kept: false
            }
        );
        assert!(!store.dir().exists());
    }

    #[test]
    fn a_key_that_cannot_be_overwritten_is_still_unlinked_and_the_failure_is_reported() {
        let (root, store) = store();
        save(&store, "jt_token");
        fs::write(store.dir().join("id_ed25519"), "KEY\n").unwrap();
        fs::set_permissions(store.private_key_path(), fs::Permissions::from_mode(0o400)).unwrap();

        let outcome = store.clear();
        assert!(!store.private_key_path().exists());
        assert!(!store.dir().exists());
        if running_as_root(root.path()) {
            assert!(outcome.is_ok());
        } else {
            assert!(
                matches!(
                    outcome,
                    Err(StoreError::Io {
                        action: "overwrite",
                        ..
                    })
                ),
                "{outcome:?}"
            );
        }
    }

    #[test]
    fn damaged_files_are_reported_instead_of_ignored() {
        let (_root, store) = store();
        save(&store, "jt_token");
        fs::write(store.dir().join("meta.json"), "{not json").unwrap();
        fs::write(store.dir().join("server"), "http://evil.example.com\n").unwrap();
        assert!(matches!(store.read_meta(), Err(StoreError::Corrupt { .. })));
        assert!(matches!(
            store.read_server(),
            Err(StoreError::Corrupt { .. })
        ));
    }

    #[test]
    fn a_key_file_readable_by_others_is_refused_like_ssh_does() {
        let (_root, store) = store();
        assert!(matches!(store.read_private_key(), Ok(None)));
        save(&store, "jt_token");
        let path = store.private_key_path();
        assert!(matches!(store.read_private_key(), Ok(None)));
        fs::write(&path, "key text").unwrap();
        for (mode, readable) in [(0o600, true), (0o400, true), (0o640, false), (0o604, false)] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            match store.read_private_key() {
                Ok(Some(key)) if readable => assert_eq!(key.expose(), "key text"),
                Err(StoreError::Exposed { path: reported }) if !readable => {
                    assert_eq!(reported, path);
                    assert!(
                        StoreError::Exposed { path: reported }
                            .to_string()
                            .contains("chmod 600")
                    );
                }
                other => panic!("{mode:o}: {other:?}"),
            }
        }
    }

    #[test]
    fn begin_sweeps_only_stale_staging_and_retired_directories_of_its_own_profile() {
        let (root, store) = store();
        let home = root.path().join("state");
        fs::create_dir_all(&home).unwrap();
        let stale_new = leftover_session(&home, ".default.new.1.1");
        let stale_old = leftover_session(&home, ".default.old.1.2");
        let recent = leftover_session(&home, ".default.new.2.1");
        let fresh = leftover_session(&home, ".default.new.3.1");
        let other_profile = leftover_session(&home, ".other.new.1.1");
        let lookalike = leftover_session(&home, ".default.keep");
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("token"), "outside").unwrap();
        symlink(outside.path(), home.join(".default.new.4.1")).unwrap();
        let alias = root.path().join("alias");
        fs::hard_link(stale_new.join("id_ed25519"), &alias).unwrap();
        fs::create_dir(stale_old.join("x509")).unwrap();
        fs::write(stale_old.join("x509/key.pem"), "OLD-X509-KEY\n").unwrap();
        let x509_alias = root.path().join("x509-alias");
        fs::hard_link(stale_old.join("x509/key.pem"), &x509_alias).unwrap();
        let live = store.dir().to_owned();
        fs::create_dir_all(live.join("x509")).unwrap();
        fs::write(live.join("x509/key.pem"), "LIVE-X509-KEY\n").unwrap();
        fs::write(live.join("services.json"), "{}").unwrap();
        for dir in [&stale_new, &stale_old, &other_profile, &lookalike] {
            age(dir, 16 * 60);
        }
        age(&recent, 14 * 60);

        let transaction = begin(&store, "jt_token");
        assert!(transaction.sweep_warning().is_none());
        assert!(!stale_new.exists() && !stale_old.exists());
        assert_zeroed(&alias, "LEFTOVER-KEY\n".len());
        assert_zeroed(&x509_alias, "OLD-X509-KEY\n".len());
        assert_eq!(
            fs::read_to_string(live.join("x509/key.pem")).unwrap(),
            "LIVE-X509-KEY\n"
        );
        assert_eq!(
            fs::read_to_string(live.join("services.json")).unwrap(),
            "{}"
        );
        for kept in [&recent, &fresh, &other_profile, &lookalike] {
            assert_eq!(names(kept), ["id_ed25519", "token"], "{}", kept.display());
        }
        assert_eq!(names(outside.path()), ["token"]);
        assert!(
            fs::symlink_metadata(home.join(".default.new.4.1"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn a_failed_second_rename_restores_the_previous_profile_byte_for_byte() {
        let (root, store) = store();
        save(&store, "jt_first");
        fs::write(store.dir().join("ssh_config"), "Host x\n").unwrap();
        let before = snapshot(store.dir());

        let calls = Cell::new(0_usize);
        let second_fails = |from: &Path, to: &Path| -> io::Result<()> {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(io::Error::other("injected"))
            } else {
                fs::rename(from, to)
            }
        };
        let mut transaction = begin(&store, "jt_second");
        let outcome = transaction.commit_with(&second_fails);
        assert!(
            matches!(
                outcome,
                Err(StoreError::Io {
                    action: "install",
                    ..
                })
            ),
            "{outcome:?}"
        );
        assert_eq!(calls.get(), 3);
        drop(transaction);

        assert_eq!(snapshot(store.dir()), before);
        assert_eq!(names(&root.path().join("state")), ["default"]);
        assert!(store.stranded_dirs().unwrap().is_empty());
    }

    #[test]
    fn when_the_rollback_fails_too_the_error_says_where_the_old_session_is() {
        let (root, store) = store();
        save(&store, "jt_first");

        let calls = Cell::new(0_usize);
        let from_second_on = |from: &Path, to: &Path| -> io::Result<()> {
            calls.set(calls.get() + 1);
            if calls.get() >= 2 {
                Err(io::Error::other("injected"))
            } else {
                fs::rename(from, to)
            }
        };
        let mut transaction = begin(&store, "jt_second");
        let Err(StoreError::Stranded { path, profile }) = transaction.commit_with(&from_second_on)
        else {
            panic!("expected a stranded profile");
        };
        drop(transaction);

        assert_eq!(profile, store.dir());
        assert!(!store.dir().exists());
        assert_eq!(store.stranded_dirs().unwrap(), std::slice::from_ref(&path));
        assert_eq!(fs::read_to_string(path.join("token")).unwrap(), "jt_first");
        let message = StoreError::Stranded {
            path: path.clone(),
            profile: profile.clone(),
        }
        .to_string();
        assert!(message.contains(&path.display().to_string()), "{message}");
        assert!(
            message.contains(&profile.display().to_string()),
            "{message}"
        );
        assert!(message.contains("`jaunt logout`"), "{message}");
        assert_eq!(names(&root.path().join("state")).len(), 1);
    }

    #[test]
    fn stranded_directories_are_only_retired_sessions_of_this_profile() {
        let (root, store) = store();
        assert!(store.stranded_dirs().unwrap().is_empty());
        let home = root.path().join("state");
        fs::create_dir_all(&home).unwrap();
        let retired = leftover_session(&home, ".default.old.5.5");
        leftover_session(&home, ".default.new.5.6");
        leftover_session(&home, ".other.old.5.7");
        fs::write(home.join(".default.old.5.8"), "not a directory").unwrap();
        assert_eq!(store.stranded_dirs().unwrap(), [retired]);
    }

    #[test]
    fn staging_creation_does_not_tolerate_an_existing_directory() {
        let (root, store) = store();
        let home = root.path().join("state");
        fs::create_dir_all(&home).unwrap();
        let next = SIBLING_COUNTER.load(Ordering::Relaxed);
        for serial in next..next + 512 {
            fs::create_dir(home.join(format!(".default.new.{}.{serial}", std::process::id())))
                .unwrap();
        }
        assert!(matches!(
            try_begin(&store, "jt_token"),
            Err(StoreError::Io {
                action: "create",
                ..
            })
        ));
    }

    fn ssh_files() -> SshFiles {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey, PublicKey};

        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = PublicKey::from(key.public_key().key_data().clone())
            .to_openssh()
            .unwrap();
        SshFiles {
            client: jaunt_proto::ClientConfig {
                ssh_suffix: "example.test".to_owned(),
                gate: jaunt_proto::GateEndpoint {
                    host: "gate.example.org".to_owned(),
                    port: 22,
                },
                host_ca_keys: vec![line],
            },
            ssh_config: "Host x\n".to_owned(),
            known_hosts: "@cert-authority x y\n".to_owned(),
        }
    }

    fn begin_with_ssh(store: &ProfileStore, ssh: &SshFiles) -> Transaction {
        let server = ServerUrl::parse("https://jaunt.example.com").unwrap();
        let token = Secret::new("jt_token".to_owned());
        store
            .begin(
                &LoginFiles {
                    server: &server,
                    public_key_line: "ssh-ed25519 PUB",
                    certificate_line: "ssh-ed25519-cert-v01@openssh.com CERT",
                    token: &token,
                    meta: &meta(),
                    ssh: Some(ssh),
                    services: None,
                },
                SystemTime::now(),
            )
            .unwrap()
    }

    #[test]
    fn the_ssh_files_are_staged_with_the_profile_read_back_and_validated() {
        let (_root, store) = store();
        save(&store, "jt_first");
        assert!(!store.has_any_ssh_file().unwrap());
        assert!(!store.ssh_files_present().unwrap());
        assert_eq!(store.read_client_config().unwrap(), None);

        let ssh = ssh_files();
        let mut transaction = begin_with_ssh(&store, &ssh);
        assert_eq!(
            names(transaction.staging_dir()),
            [
                "client.json",
                "id_ed25519-cert.pub",
                "id_ed25519.pub",
                "known_hosts",
                "meta.json",
                "ssh_config",
                "token"
            ]
        );
        transaction.commit().unwrap().unwrap().discard().unwrap();

        for name in ["client.json", "ssh_config", "known_hosts"] {
            assert_eq!(mode(&store.dir().join(name)), 0o600, "{name}");
        }
        assert_eq!(store.read_client_config().unwrap().unwrap(), ssh.client);
        assert_eq!(
            fs::read_to_string(store.ssh_config_path()).unwrap(),
            ssh.ssh_config
        );
        assert_eq!(
            fs::read_to_string(store.known_hosts_path()).unwrap(),
            ssh.known_hosts
        );
        assert!(store.ssh_files_present().unwrap() && store.has_any_ssh_file().unwrap());

        fs::remove_file(store.known_hosts_path()).unwrap();
        assert!(!store.ssh_files_present().unwrap());
        fs::write(store.dir().join("client.json"), r#"{"ssh_suffix":"A b"}"#).unwrap();
        assert!(matches!(
            store.read_client_config(),
            Err(StoreError::Corrupt { .. })
        ));
        for suffix in ["Bad Suffix", "com", "exa\nmple.test"] {
            let mut tampered = ssh.client.clone();
            tampered.ssh_suffix = suffix.to_owned();
            fs::write(
                store.dir().join("client.json"),
                serde_json::to_vec(&tampered).unwrap(),
            )
            .unwrap();
            assert!(
                matches!(store.read_client_config(), Err(StoreError::Corrupt { .. })),
                "{suffix:?}"
            );
        }
    }
}
