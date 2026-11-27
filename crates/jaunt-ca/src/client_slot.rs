use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use ssh_key::PublicKey;
use ssh_key::sha2::{Digest, Sha256};

use crate::error::CaError;
use crate::file::{
    ACTIVE_FILE, FileBackend, MAX_ROOT_LEN, ROOT_SUFFIX, corrupt, kind_dir, read_trust, write_slot,
};
use crate::fsutil::{digest_hex, exists, fingerprint_hex, read_limited, sync_dir};
use crate::identity::{AgeIdentity, AgeRecipient, encrypt};
use crate::kind::CaKind;
use crate::rotation::CaLock;
use crate::staging::{SUFFIX_BYTES, StagingDir};
use crate::trust::{KeyRole, TrustSet};
use crate::x509::{ClientCa, IssuedCertificate, SubjectPublicKey, validate_root};

pub struct TrustedRoot {
    pub role: KeyRole,
    pub fingerprint: String,
    pub certificate_der: Vec<u8>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

impl fmt::Debug for TrustedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedRoot")
            .field("role", &self.role)
            .field("fingerprint", &self.fingerprint)
            .field(
                "sha256",
                &format_args!("{}", digest_hex(&Sha256::digest(&self.certificate_der))),
            )
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish()
    }
}

#[derive(Debug)]
pub struct ClientSlot {
    pub trust: TrustSet,
    pub roots: Vec<TrustedRoot>,
    pub ca: ClientCa,
}

#[derive(Debug)]
pub struct ClientKeyAdded {
    pub public_key: PublicKey,
    pub root: IssuedCertificate,
}

#[derive(Debug)]
pub struct ClientInitialized {
    pub public_key: PublicKey,
    pub root: IssuedCertificate,
    pub sync_failure: Option<CaError>,
}

impl ClientCa {
    pub fn init(
        ca_root: &Path,
        kind: CaKind,
        recipient: &AgeRecipient,
        now: SystemTime,
    ) -> Result<ClientInitialized, CaError> {
        Self::init_with(ca_root, kind, recipient, now, &|_| Ok(()))
    }

    pub(crate) fn init_with(
        ca_root: &Path,
        kind: CaKind,
        recipient: &AgeRecipient,
        now: SystemTime,
        after_link: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<ClientInitialized, CaError> {
        if !kind.is_x509_client() {
            return Err(CaError::NotAClientAuthority(kind));
        }
        let dir = kind_dir(ca_root, kind);
        if exists(&dir.join(ACTIVE_FILE))? {
            return Err(CaError::AlreadyInitialized(kind));
        }
        let mut staging = StagingDir::create(ca_root, &format!(".{kind}.staging"))?;
        let (public_key, root) =
            write_slot(staging.path(), kind, recipient, Some(now), after_link)?;
        let root = root.ok_or(CaError::RootRequired(kind))?;
        let committed = staging.commit(&dir)?;
        Ok(ClientInitialized {
            public_key,
            root,
            sync_failure: committed.sync_failure,
        })
    }

    pub fn add_next(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        now: SystemTime,
    ) -> Result<ClientKeyAdded, CaError> {
        Self::add_next_with(lock, kind, identity, now, &|_| Ok(()))
    }

    pub(crate) fn add_next_with(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        now: SystemTime,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<ClientKeyAdded, CaError> {
        Self::read_roots(lock.root(), kind)?;
        let (public_key, root) =
            FileBackend::add_next_rooted(lock, kind, identity, &encrypt, Some(now), after_step)?;
        let root = root.ok_or(CaError::RootRequired(kind))?;
        Ok(ClientKeyAdded { public_key, root })
    }

    pub fn remove_stale_staging(lock: &CaLock, kind: CaKind) -> Result<Vec<PathBuf>, CaError> {
        if !kind.is_x509_client() {
            return Err(CaError::NotAClientAuthority(kind));
        }
        let ca_root = lock.root();
        let prefix = format!(".{kind}.staging-");
        let entries = fs::read_dir(ca_root).map_err(CaError::io("read directory", ca_root))?;
        let mut removed = Vec::new();
        for entry in entries {
            let entry = entry.map_err(CaError::io("read directory", ca_root))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let ours = name.strip_prefix(&prefix).is_some_and(|suffix| {
                suffix.len() == 2 * SUFFIX_BYTES
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
            if !ours {
                continue;
            }
            let path = entry.path();
            let is_dir = fs::symlink_metadata(&path)
                .map_err(CaError::io("inspect", &path))?
                .file_type()
                .is_dir();
            if is_dir {
                fs::remove_dir_all(&path).map_err(CaError::io("remove", &path))?;
                removed.push(path);
            }
        }
        if !removed.is_empty() {
            sync_dir(ca_root).map_err(CaError::io("sync directory", ca_root))?;
        }
        removed.sort();
        Ok(removed)
    }

    pub fn read_roots(
        ca_root: &Path,
        kind: CaKind,
    ) -> Result<(TrustSet, Vec<TrustedRoot>), CaError> {
        if !kind.is_x509_client() {
            return Err(CaError::NotAClientAuthority(kind));
        }
        let dir = kind_dir(ca_root, kind);
        let (_, trust) = read_trust(&dir, kind)?;
        let mut roots = Vec::with_capacity(trust.keys().len());
        for role in [KeyRole::Active, KeyRole::Next, KeyRole::Previous] {
            for (_, key) in trust.roles().filter(|(found, _)| *found == role) {
                let (certificate_der, (not_before, not_after)) = read_root(&dir, key)?;
                roots.push(TrustedRoot {
                    role,
                    fingerprint: fingerprint_hex(key),
                    certificate_der,
                    not_before,
                    not_after,
                });
            }
        }
        Ok((trust, roots))
    }

    pub fn load(
        ca_root: &Path,
        kind: CaKind,
        identity: &AgeIdentity,
    ) -> Result<ClientSlot, CaError> {
        let (trust, roots) = Self::read_roots(ca_root, kind)?;
        let (loaded, backend) = FileBackend::load(ca_root, kind, identity)?;
        if loaded.set_id() != trust.set_id()
            || fingerprint_hex(loaded.active()) != fingerprint_hex(trust.active())
        {
            return Err(CaError::SlotChanged(kind));
        }
        let active = roots
            .iter()
            .find(|root| root.role == KeyRole::Active)
            .map(|root| root.certificate_der.clone())
            .ok_or(CaError::ActiveKeyNotTrusted)?;
        let ca = ClientCa::new(Arc::new(backend), active)?;
        Ok(ClientSlot { trust, roots, ca })
    }
}

fn read_root(dir: &Path, key: &PublicKey) -> Result<(Vec<u8>, (SystemTime, SystemTime)), CaError> {
    let path = dir.join(format!("{}{ROOT_SUFFIX}", fingerprint_hex(key)));
    if !exists(&path)? {
        return Err(corrupt(&path, "the key has no root certificate"));
    }
    let der = read_limited(&path, MAX_ROOT_LEN)?.to_vec();
    let subject = SubjectPublicKey::from_ssh_key(key)
        .map_err(|_| corrupt(&path, "the key is not an Ed25519 key"))?;
    let validity = validate_root(&der, &subject).map_err(|err| match err {
        CaError::InvalidRootCertificate { reason } => corrupt(&path, reason),
        other => other,
    })?;
    Ok((der, validity))
}

#[cfg(test)]
mod tests;
