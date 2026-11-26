use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey, PublicKey};
use tempfile::TempDir;

use crate::{
    AgeIdentity, CaError, CaKind, CaLock, ClientCa, ClientSlot, FileBackend, Signer, TrustSet,
};

const LOCK_DEADLINE: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(2);

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

pub(crate) struct ClientAuthority {
    pub(crate) dir: TempDir,
    pub(crate) identity: AgeIdentity,
    pub(crate) slot: ClientSlot,
}

pub(crate) fn client_authority(kind: CaKind, now: SystemTime) -> ClientAuthority {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    ClientCa::init(dir.path(), kind, &identity.recipient(), now).unwrap();
    let slot = ClientCa::load(dir.path(), kind, &identity).unwrap();
    ClientAuthority {
        dir,
        identity,
        slot,
    }
}

pub(crate) fn subject_key() -> PublicKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone()
}

pub(crate) fn acquire_lock(root: &Path) -> Result<CaLock, CaError> {
    let deadline = Instant::now() + LOCK_DEADLINE;
    loop {
        match CaLock::acquire(root) {
            Err(CaError::LockBusy) if Instant::now() < deadline => thread::sleep(LOCK_POLL),
            other => return other,
        }
    }
}

pub(crate) fn verify_client(
    root_der: &[u8],
    cert_der: &[u8],
    seconds: u64,
) -> Result<(), rustls::Error> {
    use rustls::RootCertStore;
    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::WebPkiClientVerifier;

    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(root_der.to_vec()))?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(store), Arc::new(default_provider()))
            .build()
            .map_err(|err| rustls::Error::General(err.to_string()))?;
    verifier
        .verify_client_cert(
            &CertificateDer::from(cert_der),
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(seconds)),
        )
        .map(drop)
}
