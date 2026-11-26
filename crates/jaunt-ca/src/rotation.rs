use std::fs::{self, File, TryLockError};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rustix::fs::{Mode, OFlags, open};
use rustix::io::Errno;
use rustix::process::geteuid;
use ssh_key::{Algorithm, Fingerprint, HashAlg, PrivateKey, PublicKey};

use crate::error::CaError;
use crate::file::{
    ACTIVE_FILE, ENCRYPTED_SUFFIX, FileBackend, KeyFiles, MAX_PRIVATE_LEN, NEXT_FILE,
    PUBLIC_SUFFIX, RETIRED_DIR, ROOT_SUFFIX, kind_dir, list_fingerprints, read_trust,
    write_key_files,
};
use crate::fsutil::{
    create_private_dir_with, exists, fingerprint_hex, move_with, remove_with, replace_with,
};
use crate::identity::{AgeIdentity, AgeRecipient, encrypt};
use crate::kind::CaKind;
use crate::x509::{ClientCa, IssuedCertificate};

const LOCK_FILE: &str = ".lock";

type Seal<'a> = dyn Fn(&AgeRecipient, &[u8]) -> Result<Vec<u8>, CaError> + 'a;

#[derive(Debug)]
pub struct CaLock {
    root: PathBuf,
    _file: File,
}

impl CaLock {
    pub fn acquire(root: &Path) -> Result<CaLock, CaError> {
        let owner = fs::metadata(root)
            .map_err(CaError::io("inspect", root))?
            .uid();
        ensure_owner(root, owner, geteuid().as_raw())?;
        let path = root.join(LOCK_FILE);
        let file = open_lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(CaLock {
                root: root.to_path_buf(),
                _file: file,
            }),
            Err(TryLockError::WouldBlock) => Err(CaError::LockBusy),
            Err(TryLockError::Error(err)) => Err(CaError::io("lock", &path)(err)),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn ensure_owner(dir: &Path, owner: u32, euid: u32) -> Result<(), CaError> {
    if owner == euid {
        Ok(())
    } else {
        Err(CaError::NotOwner {
            path: dir.to_path_buf(),
            owner,
            euid,
        })
    }
}

fn open_lock_file(path: &Path) -> Result<File, CaError> {
    let flags =
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match open(path, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => File::from(fd),
        Err(Errno::LOOP | Errno::MLINK | Errno::ISDIR) => {
            return Err(CaError::UnsafeLock(path.to_path_buf()));
        }
        Err(errno) => return Err(CaError::io("open", path)(errno.into())),
    };
    let meta = file.metadata().map_err(CaError::io("inspect", path))?;
    if !meta.is_file() || meta.uid() != geteuid().as_raw() {
        return Err(CaError::UnsafeLock(path.to_path_buf()));
    }
    Ok(file)
}

#[derive(Clone, Debug)]
pub struct Promoted {
    pub active: PublicKey,
    pub previous: PublicKey,
}

impl FileBackend {
    pub fn add_next(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
    ) -> Result<PublicKey, CaError> {
        if kind.is_x509_client() {
            return Err(CaError::RootRequired(kind));
        }
        Self::add_next_with(lock, kind, identity, &|_| Ok(()))
    }

    pub(crate) fn add_next_with(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<PublicKey, CaError> {
        Self::add_next_sealed(lock, kind, identity, &encrypt, after_step)
    }

    pub(crate) fn add_next_sealed(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        seal: &Seal<'_>,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<PublicKey, CaError> {
        Self::add_next_rooted(lock, kind, identity, seal, None, after_step).map(|(key, _)| key)
    }

    pub(crate) fn add_next_rooted(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        seal: &Seal<'_>,
        root_at: Option<SystemTime>,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<(PublicKey, Option<IssuedCertificate>), CaError> {
        ensure_rotatable(kind)?;
        let root = lock.root();
        let (trust, _) = Self::load(root, kind, identity)?;
        if trust.next().is_some() {
            return Err(CaError::NextKeyExists(kind));
        }
        let dir = kind_dir(root, kind);
        let stale_next = dir.join(NEXT_FILE);
        if exists(&stale_next)? {
            remove_with(&stale_next, after_step).map_err(CaError::io("remove", &stale_next))?;
        }

        let backend = FileBackend::generate(kind)?;
        let root = backend.root_certificate(root_at)?;
        let public_key = crate::signer::Signer::public_key(&backend).clone();
        let hex = fingerprint_hex(&public_key);
        let pem = backend.private_pem()?;
        let encrypted = seal(&identity.recipient(), pem.as_bytes())?;
        verify_round_trip(&encrypted, identity, &hex)?;
        let public_line = format!("{}\n", public_key.to_openssh().map_err(CaError::SshKey)?);

        let mut created: Vec<PathBuf> = Vec::new();
        let outcome = write_key_files(
            &dir,
            KeyFiles {
                hex: &hex,
                encrypted: &encrypted,
                root: root.as_ref().map(|root| root.certificate_der.as_slice()),
                public_line: public_line.as_bytes(),
                pointer: NEXT_FILE,
                pointer_taken: CaError::NextKeyExists(kind),
            },
            after_step,
            &mut created,
        );
        if let Err(err) = outcome {
            let published = exists(&dir.join(NEXT_FILE)).unwrap_or(true);
            if !published {
                for path in created.iter().rev() {
                    drop(fs::remove_file(path));
                }
            }
            return Err(err);
        }
        Ok((public_key, root))
    }

    pub fn promote(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        expected_next: &Fingerprint,
    ) -> Result<Promoted, CaError> {
        Self::promote_with(lock, kind, identity, expected_next, &|_| Ok(()))
    }

    pub(crate) fn promote_with(
        lock: &CaLock,
        kind: CaKind,
        identity: &AgeIdentity,
        expected_next: &Fingerprint,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<Promoted, CaError> {
        ensure_rotatable(kind)?;
        let root = lock.root();
        let (trust, _) = Self::load_with_next(root, kind, identity)?;
        let next = trust.next().ok_or(CaError::NoNextKey(kind))?;
        if trust.previous().next().is_some() {
            return Err(CaError::PreviousKeyPresent(kind));
        }
        if next.fingerprint(HashAlg::Sha256) != *expected_next {
            return Err(CaError::SlotChanged(kind));
        }
        let dir = kind_dir(root, kind);
        if kind.is_x509_client() {
            ClientCa::read_roots(root, kind)?;
        }
        let active_path = dir.join(ACTIVE_FILE);
        replace_with(
            &active_path,
            format!("{}\n", fingerprint_hex(next)).as_bytes(),
            after_step,
        )
        .map_err(CaError::io("replace", &active_path))?;
        let next_path = dir.join(NEXT_FILE);
        remove_with(&next_path, after_step).map_err(CaError::io("remove", &next_path))?;
        Ok(Promoted {
            active: next.clone(),
            previous: trust.active().clone(),
        })
    }

    pub fn retire(
        lock: &CaLock,
        kind: CaKind,
        expected_previous: &[Fingerprint],
    ) -> Result<Vec<PublicKey>, CaError> {
        Self::retire_with(lock, kind, expected_previous, &|_| Ok(()))
    }

    pub(crate) fn retire_with(
        lock: &CaLock,
        kind: CaKind,
        expected_previous: &[Fingerprint],
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<Vec<PublicKey>, CaError> {
        ensure_rotatable(kind)?;
        let dir = kind_dir(lock.root(), kind);
        let (_, trust) = read_trust(&dir, kind)?;
        let previous: Vec<PublicKey> = trust.previous().cloned().collect();
        if previous.is_empty() {
            return Err(CaError::NoPreviousKey(kind));
        }
        let mut found: Vec<Fingerprint> = previous
            .iter()
            .map(|key| key.fingerprint(HashAlg::Sha256))
            .collect();
        let mut expected = expected_previous.to_vec();
        found.sort();
        expected.sort();
        if found != expected {
            return Err(CaError::SlotChanged(kind));
        }

        let retired_dir = dir.join(RETIRED_DIR);
        create_private_dir_with(&retired_dir, after_step)
            .map_err(CaError::io("create directory", &retired_dir))?;
        for key in &previous {
            let hex = fingerprint_hex(key);
            let public_path = dir.join(format!("{hex}{PUBLIC_SUFFIX}"));
            let retired_path = retired_dir.join(format!("{hex}{PUBLIC_SUFFIX}"));
            move_with(&public_path, &retired_path, after_step)
                .map_err(CaError::io("move", &public_path))?;
            retire_root(&dir, &hex, after_step)?;
            remove_private_key(&dir, &hex, after_step)?;
        }
        Ok(previous)
    }

    pub fn finish_retired(lock: &CaLock, kind: CaKind) -> Result<Vec<String>, CaError> {
        Self::finish_retired_with(lock, kind, &|_| Ok(()))
    }

    pub(crate) fn finish_retired_with(
        lock: &CaLock,
        kind: CaKind,
        after_step: &dyn Fn(&Path) -> io::Result<()>,
    ) -> Result<Vec<String>, CaError> {
        ensure_rotatable(kind)?;
        let listing = Self::read_slot(lock.root(), kind)?;
        let dir = kind_dir(lock.root(), kind);
        for hex in list_fingerprints(&dir, ROOT_SUFFIX)?
            .iter()
            .filter(|hex| listing.retired.contains(hex))
        {
            retire_root(&dir, hex, after_step)?;
        }
        let mut finished = Vec::new();
        for hex in listing
            .stray
            .iter()
            .filter(|hex| listing.retired.contains(hex))
        {
            remove_private_key(&dir, hex, after_step)?;
            finished.push(hex.clone());
        }
        Ok(finished)
    }
}

fn ensure_rotatable(kind: CaKind) -> Result<(), CaError> {
    match kind {
        CaKind::User | CaKind::Host | CaKind::UserX509 | CaKind::DbClient => Ok(()),
        CaKind::Internal => Err(CaError::RotationUnsupported(kind)),
    }
}

fn retire_root(
    dir: &Path,
    hex: &str,
    after_step: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<(), CaError> {
    let root_path = dir.join(format!("{hex}{ROOT_SUFFIX}"));
    if !exists(&root_path)? {
        return Ok(());
    }
    let retired_path = dir.join(RETIRED_DIR).join(format!("{hex}{ROOT_SUFFIX}"));
    move_with(&root_path, &retired_path, after_step).map_err(CaError::io("move", &root_path))
}

fn verify_round_trip(
    encrypted: &[u8],
    identity: &AgeIdentity,
    expected_hex: &str,
) -> Result<(), CaError> {
    let plaintext = identity
        .decrypt(encrypted, MAX_PRIVATE_LEN)
        .map_err(|_| CaError::KeyRoundTrip)?;
    let key = PrivateKey::from_openssh(&*plaintext).map_err(|_| CaError::KeyRoundTrip)?;
    let intact = !key.is_encrypted()
        && key.algorithm() == Algorithm::Ed25519
        && fingerprint_hex(key.public_key()) == expected_hex;
    if intact {
        Ok(())
    } else {
        Err(CaError::KeyRoundTrip)
    }
}

fn remove_private_key(
    dir: &Path,
    hex: &str,
    after_step: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<(), CaError> {
    let path = dir.join(format!("{hex}{ENCRYPTED_SUFFIX}"));
    match remove_with(&path, after_step) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CaError::io("remove", &path)(err)),
    }
}

#[cfg(test)]
mod tests;
