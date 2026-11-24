use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};

use crate::host::{HostIdentity, HostKey};

pub(crate) const NOW: u64 = 1_700_000_000;
pub(crate) const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

pub(crate) fn rng() -> impl russh::keys::ssh_key::rand_core::CryptoRng {
    safe_rng()
}

pub(crate) fn key(algorithm: Algorithm) -> PrivateKey {
    PrivateKey::random(&mut rng(), algorithm).unwrap()
}

pub(crate) fn host_certificate(
    ca: &PrivateKey,
    subject: &PublicKey,
    cert_type: CertType,
    valid_after: u64,
    valid_before: u64,
) -> Certificate {
    let mut builder = Builder::new_with_random_nonce(
        &mut rng(),
        subject.key_data().clone(),
        valid_after,
        valid_before,
    )
    .unwrap();
    builder.serial(7).unwrap();
    builder.cert_type(cert_type).unwrap();
    builder.key_id("jaunt-host:node1.example.com:7").unwrap();
    builder.valid_principal("node1.example.com").unwrap();
    builder.valid_principal("node1").unwrap();
    builder.sign(ca).unwrap()
}

pub(crate) fn host_identity(ca: &PrivateKey) -> (HostIdentity, PublicKey) {
    let host = HostKey::generate().unwrap();
    let public = PublicKey::from_openssh(&host.public_openssh().unwrap()).unwrap();
    let cert = host_certificate(ca, &public, CertType::Host, NOW - 120, NOW + 3600);
    let identity = host
        .with_certificate(&cert.to_openssh().unwrap(), NOW)
        .unwrap();
    (identity, public)
}
