use std::sync::Arc;

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tempfile::TempDir;

use crate::{AgeIdentity, CaKind, FileBackend, Signer, TrustSet};

pub(crate) struct Authority {
    pub(crate) dir: TempDir,
    pub(crate) identity: AgeIdentity,
    pub(crate) trust: TrustSet,
    pub(crate) backend: FileBackend,
}

impl Authority {
    pub(crate) fn shared_signer(&self) -> Arc<dyn Signer> {
        let (_, backend) =
            FileBackend::load(self.dir.path(), self.backend.kind(), &self.identity).unwrap();
        Arc::new(backend)
    }
}

pub(crate) fn authority(kind: CaKind) -> Authority {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    FileBackend::init(dir.path(), kind, &identity.recipient()).unwrap();
    let (trust, backend) = FileBackend::load(dir.path(), kind, &identity).unwrap();
    Authority {
        dir,
        identity,
        trust,
        backend,
    }
}

pub(crate) fn subject_key() -> PublicKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}
