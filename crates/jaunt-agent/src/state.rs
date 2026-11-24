use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::clock::compact_utc;
use crate::fsio::{DirError, DirHandle, FsError, Owner, effective_uid, normalize};
use crate::keys::{HostKey, KeyError, TlsKey};
use crate::paths::check_state_dir;

pub const DEFAULT_STATE_DIR: &str = "/var/lib/jaunt";
pub const STATE_FILE: &str = "state.json";
pub const TLS_KEY_FILE: &str = "tls.key";
pub const SSH_HOST_KEY_FILE: &str = "ssh_host_ed25519";
pub const X509_FILE: &str = "x509.der";
pub const SSH_CERTIFICATE_FILE: &str = "ssh_host_ed25519-cert.pub";
pub const CA_ROOT_FILE: &str = "ca-root.der";
pub const LOCK_FILE: &str = ".enroll.lock";
const PROBE_NAME: &str = "write-check";
const INSTALLER_FILES: [&str; 1] = ["inner-ca.pub"];
const PREVIOUS_PREFIX: &str = "previous-";
const MANAGED_FILES: [&str; 6] = [
    STATE_FILE,
    TLS_KEY_FILE,
    SSH_HOST_KEY_FILE,
    X509_FILE,
    SSH_CERTIFICATE_FILE,
    CA_ROOT_FILE,
];
const MAX_PREVIOUS_ATTEMPTS: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentRecord {
    pub node_id: String,
    pub name: String,
    pub server_url: String,
    pub agent_endpoint: String,
    pub x509_not_after: i64,
    pub ssh_not_after: i64,
    pub enrolled_at: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("{dir} holds no enrollment (no {STATE_FILE}); run `jaunt-agent enroll` first")]
    NotEnrolled { dir: String },
    #[error("{dir} already holds an enrollment")]
    AlreadyEnrolled { dir: String },
    #[error(
        "refusing to use {dir}: it holds files that jaunt-agent did not write; pass an empty or dedicated directory (nothing was changed)"
    )]
    Foreign { dir: String },
    #[error("refusing to use {dir} as root: the state directory {reason} (nothing was changed)")]
    Unsafe { dir: String, reason: &'static str },
    #[error(
        "cannot write to {dir} ({source}); run enroll as the owner of the directory or fix its permissions (nothing was sent to the server)"
    )]
    NotWritable {
        dir: String,
        #[source]
        source: FsError,
    },
    #[error("another `jaunt-agent enroll` is already running for {dir}")]
    Busy { dir: String },
    #[error(
        "refusing to use {dir} as root: it is owned by uid {uid} instead of root and was not prepared by `jaunt-agent install`, so the node's private keys would belong to that user; remove it or run `jaunt-agent install` first (nothing was changed)"
    )]
    UntrustedOwner { dir: String, uid: u32 },
    #[error(transparent)]
    Dir(#[from] DirError),
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error("{path} is not a valid enrollment record: {reason}")]
    Record { path: String, reason: String },
    #[error("{path}: {source}")]
    Key { path: String, source: KeyError },
    #[error("{path} is not valid UTF-8")]
    Utf8 { path: String },
    #[error("cannot encode the enrollment record")]
    Encode,
    #[error("cannot find a free name for the previous enrollment under {dir}")]
    NoPreviousName { dir: String },
}

#[derive(Debug, thiserror::Error)]
pub struct StoreFailure {
    pub previous: Option<PathBuf>,
    #[source]
    pub error: StateError,
}

impl fmt::Display for StoreFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.previous {
            Some(previous) => write!(
                f,
                "{}; the previous enrollment files are in {}",
                self.error,
                previous.display()
            ),
            None => write!(f, "{}", self.error),
        }
    }
}

fn before_move(error: impl Into<StateError>) -> StoreFailure {
    StoreFailure {
        previous: None,
        error: error.into(),
    }
}

pub struct EnrollmentFiles<'a> {
    pub record: &'a EnrollmentRecord,
    pub tls_key: &'a TlsKey,
    pub host_key: &'a HostKey,
    pub x509_der: &'a [u8],
    pub ssh_certificate: &'a str,
    pub ca_root_der: &'a [u8],
}

pub struct Loaded {
    pub record: EnrollmentRecord,
    pub tls_key: TlsKey,
    pub host_key: HostKey,
    pub x509_der: Vec<u8>,
    pub ca_root_der: Vec<u8>,
}

pub struct EnrollLock {
    _file: File,
}

pub fn trusted_existing_dir(owner_uid: u32, installer_layout: bool) -> bool {
    owner_uid == 0 || installer_layout
}

pub fn is_state_entry(name: &str) -> bool {
    MANAGED_FILES.contains(&name)
        || INSTALLER_FILES.contains(&name)
        || name == LOCK_FILE
        || is_previous_name(name)
        || is_temp_name(name)
}

fn is_digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_temp_name(name: &str) -> bool {
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((base, pid)) = inner.rsplit_once('.') else {
        return false;
    };
    is_digits(pid) && (MANAGED_FILES.contains(&base) || base == PROBE_NAME)
}

fn is_previous_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(PREVIOUS_PREFIX) else {
        return false;
    };
    let (stamp, attempt) = match rest.split_once('-') {
        Some((stamp, attempt)) => (stamp, Some(attempt)),
        None => (rest, None),
    };
    let bytes = stamp.as_bytes();
    let stamp_ok = bytes.len() == 16
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 => *byte == b'T',
            15 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    stamp_ok && attempt.is_none_or(is_digits)
}

pub struct StateDir {
    dir: DirHandle,
    owner: Option<Owner>,
}

impl StateDir {
    pub fn open(path: &Path, privileged: bool) -> Result<Self, StateError> {
        let dir = match DirHandle::open(path) {
            Ok(dir) => dir,
            Err(DirError::Missing { path }) => {
                return Err(StateError::NotEnrolled {
                    dir: path.display().to_string(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        let owner = if privileged { Some(dir.owner()?) } else { None };
        Ok(Self { dir, owner })
    }

    pub fn prepare_enrollment(
        path: &Path,
        privileged: bool,
    ) -> Result<(Self, EnrollLock), StateError> {
        let path = normalize(path);
        let shown = path.display().to_string();
        if privileged {
            let text = path.to_str().ok_or(StateError::Unsafe {
                dir: shown.clone(),
                reason: "must be valid UTF-8",
            })?;
            check_state_dir(text).map_err(|reason| StateError::Unsafe {
                dir: shown.clone(),
                reason,
            })?;
        }
        let (dir, created) = DirHandle::create_or_open(&path)?;
        if !created {
            let entries = dir.entries()?;
            let ours = entries
                .iter()
                .all(|name| name.to_str().is_some_and(is_state_entry));
            if !ours {
                return Err(StateError::Foreign { dir: shown });
            }
            let owner = dir.owner()?;
            let installer_layout = entries
                .iter()
                .any(|name| INSTALLER_FILES.iter().any(|file| name == file));
            if privileged && !trusted_existing_dir(owner.uid, installer_layout) {
                return Err(StateError::UntrustedOwner {
                    dir: shown,
                    uid: owner.uid,
                });
            }
            if privileged || owner.uid == effective_uid() {
                dir.remove_group_and_other_access()?;
            }
        }
        dir.probe_writable()
            .map_err(|source| StateError::NotWritable {
                dir: shown.clone(),
                source,
            })?;
        let owner = if privileged { Some(dir.owner()?) } else { None };
        let lock = dir
            .lock(LOCK_FILE, owner)?
            .ok_or(StateError::Busy { dir: shown })?;
        Ok((Self { dir, owner }, EnrollLock { _file: lock }))
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    fn shown(&self) -> String {
        self.dir.path().display().to_string()
    }

    fn display(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    pub fn holds_enrollment(&self) -> Result<bool, StateError> {
        Ok(self.dir.exists(STATE_FILE)?)
    }

    pub fn store_enrollment(
        &self,
        files: &EnrollmentFiles<'_>,
        now_secs: i64,
        replace: bool,
    ) -> Result<Option<PathBuf>, StoreFailure> {
        let host_private = files
            .host_key
            .private_openssh()
            .map_err(|source| StateError::Key {
                path: self.display(SSH_HOST_KEY_FILE),
                source,
            })
            .map_err(before_move)?;
        let record = encode_record(files.record).map_err(before_move)?;
        if !replace && self.holds_enrollment().map_err(before_move)? {
            return Err(before_move(StateError::AlreadyEnrolled {
                dir: self.shown(),
            }));
        }
        let previous = self.move_aside(now_secs)?;
        let fail = |error: FsError| StoreFailure {
            previous: previous.clone(),
            error: error.into(),
        };
        let write = |name: &str, content: &[u8]| self.dir.write_private(name, content, self.owner);
        write(TLS_KEY_FILE, files.tls_key.pkcs8_der()).map_err(fail)?;
        write(SSH_HOST_KEY_FILE, host_private.as_bytes()).map_err(fail)?;
        write(X509_FILE, files.x509_der).map_err(fail)?;
        write(
            SSH_CERTIFICATE_FILE,
            certificate_line(files.ssh_certificate).as_bytes(),
        )
        .map_err(fail)?;
        write(CA_ROOT_FILE, files.ca_root_der).map_err(fail)?;
        write(STATE_FILE, &record).map_err(fail)?;
        Ok(previous)
    }

    pub fn store_renewal(
        &self,
        record: &EnrollmentRecord,
        x509_der: &[u8],
        ssh_certificate: &str,
    ) -> Result<(), StateError> {
        let encoded = encode_record(record)?;
        self.dir.write_private(X509_FILE, x509_der, self.owner)?;
        self.dir.write_private(
            SSH_CERTIFICATE_FILE,
            certificate_line(ssh_certificate).as_bytes(),
            self.owner,
        )?;
        self.dir.write_private(STATE_FILE, &encoded, self.owner)?;
        Ok(())
    }

    pub fn load(&self) -> Result<Loaded, StateError> {
        let state = match self.dir.read(STATE_FILE) {
            Ok(bytes) => bytes,
            Err(error) if error.is_not_found() => {
                return Err(StateError::NotEnrolled { dir: self.shown() });
            }
            Err(error) => return Err(error.into()),
        };
        let record: EnrollmentRecord =
            serde_json::from_slice(&state).map_err(|error| StateError::Record {
                path: self.display(STATE_FILE),
                reason: error.to_string(),
            })?;
        let tls_bytes = self.dir.read(TLS_KEY_FILE)?;
        let tls_key = TlsKey::from_pkcs8(&tls_bytes).map_err(|source| StateError::Key {
            path: self.display(TLS_KEY_FILE),
            source,
        })?;
        let host_bytes = self.dir.read(SSH_HOST_KEY_FILE)?;
        let host_text = std::str::from_utf8(&host_bytes).map_err(|_| StateError::Utf8 {
            path: self.display(SSH_HOST_KEY_FILE),
        })?;
        let host_key = HostKey::from_openssh(host_text).map_err(|source| StateError::Key {
            path: self.display(SSH_HOST_KEY_FILE),
            source,
        })?;
        let x509_der = self.dir.read(X509_FILE)?.to_vec();
        let ca_root_der = self.dir.read(CA_ROOT_FILE)?.to_vec();
        Ok(Loaded {
            record,
            tls_key,
            host_key,
            x509_der,
            ca_root_der,
        })
    }

    fn move_aside(&self, now_secs: i64) -> Result<Option<PathBuf>, StoreFailure> {
        let mut present = Vec::new();
        for name in MANAGED_FILES {
            if self.dir.exists(name).map_err(before_move)? {
                present.push(name);
            }
        }
        if present.is_empty() {
            return Ok(None);
        }
        let previous = self.fresh_previous_dir(now_secs).map_err(before_move)?;
        let moved = |error: FsError| StoreFailure {
            previous: Some(previous.path().to_path_buf()),
            error: error.into(),
        };
        for name in present {
            self.dir.move_into(name, &previous).map_err(moved)?;
        }
        previous.sync().map_err(moved)?;
        self.dir.sync().map_err(moved)?;
        Ok(Some(previous.path().to_path_buf()))
    }

    fn fresh_previous_dir(&self, now_secs: i64) -> Result<DirHandle, StateError> {
        let base = format!("{PREVIOUS_PREFIX}{}", compact_utc(now_secs));
        for attempt in 0..MAX_PREVIOUS_ATTEMPTS {
            let name = if attempt == 0 {
                base.clone()
            } else {
                format!("{base}-{attempt}")
            };
            if let Some(handle) = self.dir.create_private_dir(&name, self.owner)? {
                return Ok(handle);
            }
        }
        Err(StateError::NoPreviousName { dir: self.shown() })
    }
}

#[cfg(test)]
pub fn previous_dirs(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.starts_with(PREVIOUS_PREFIX))
        .collect();
    names.sort();
    names
}

fn encode_record(record: &EnrollmentRecord) -> Result<Vec<u8>, StateError> {
    let mut encoded = serde_json::to_vec_pretty(record).map_err(|_| StateError::Encode)?;
    encoded.push(b'\n');
    Ok(encoded)
}

fn certificate_line(line: &str) -> String {
    format!("{}\n", line.trim_end_matches('\n'))
}

#[cfg(test)]
mod tests;
