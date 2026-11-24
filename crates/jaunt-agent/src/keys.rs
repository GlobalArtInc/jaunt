use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::KeyData;
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

const SEED_LEN: usize = 32;
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("cannot generate a key: the system entropy source failed")]
    Entropy,
    #[error("cannot encode the generated key")]
    Encode,
    #[error("the TLS key is not an Ed25519 PKCS#8 key written by jaunt-agent")]
    TlsKeyFormat,
    #[error("the SSH host key is not an unencrypted Ed25519 OpenSSH private key")]
    HostKeyFormat,
}

fn random_seed() -> Result<Zeroizing<[u8; SEED_LEN]>, KeyError> {
    let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
    OsRng
        .try_fill_bytes(seed.as_mut())
        .map_err(|_| KeyError::Entropy)?;
    Ok(seed)
}

pub fn sha256_hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

pub struct TlsKey {
    pkcs8: Zeroizing<Vec<u8>>,
    spki: Vec<u8>,
}

impl TlsKey {
    pub fn generate() -> Result<Self, KeyError> {
        let seed = random_seed()?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_pkcs8(der: &[u8]) -> Result<Self, KeyError> {
        let seed = der
            .strip_prefix(ED25519_PKCS8_PREFIX.as_slice())
            .and_then(|rest| <[u8; SEED_LEN]>::try_from(rest).ok())
            .map(Zeroizing::new)
            .ok_or(KeyError::TlsKeyFormat)?;
        Ok(Self::from_seed(&seed))
    }

    fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let keypair = Ed25519Keypair::from_seed(seed);
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + SEED_LEN));
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(seed);
        let spki = [ED25519_SPKI_PREFIX.as_slice(), keypair.public.0.as_slice()].concat();
        Self { pkcs8, spki }
    }

    pub fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    pub fn spki_base64(&self) -> String {
        STANDARD.encode(&self.spki)
    }

    pub fn fingerprint(&self) -> String {
        format!("sha256:{}", sha256_hex(&self.spki))
    }

    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8
    }

    pub fn rustls_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.pkcs8.to_vec()))
    }
}

impl fmt::Debug for TlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsKey")
            .field("fingerprint", &self.fingerprint())
            .field("private", &"[redacted]")
            .finish()
    }
}

pub struct HostKey {
    private: PrivateKey,
    public: PublicKey,
}

impl HostKey {
    pub fn generate() -> Result<Self, KeyError> {
        let seed = random_seed()?;
        let keypair = Ed25519Keypair::from_seed(&seed);
        let private =
            PrivateKey::new(KeypairData::Ed25519(keypair), "").map_err(|_| KeyError::Encode)?;
        Ok(Self::from_private(private))
    }

    pub fn from_openssh(text: &str) -> Result<Self, KeyError> {
        let private = PrivateKey::from_openssh(text).map_err(|_| KeyError::HostKeyFormat)?;
        if private.algorithm() != Algorithm::Ed25519 || private.is_encrypted() {
            return Err(KeyError::HostKeyFormat);
        }
        Ok(Self::from_private(private))
    }

    fn from_private(private: PrivateKey) -> Self {
        let public = PublicKey::from(private.public_key().key_data().clone());
        Self { private, public }
    }

    pub fn key_data(&self) -> &KeyData {
        self.public.key_data()
    }

    pub fn public_line(&self) -> Result<String, KeyError> {
        self.public.to_openssh().map_err(|_| KeyError::Encode)
    }

    pub fn fingerprint(&self) -> String {
        self.public.fingerprint(HashAlg::Sha256).to_string()
    }

    pub fn private_openssh(&self) -> Result<Zeroizing<String>, KeyError> {
        self.private
            .to_openssh(LineEnding::LF)
            .map_err(|_| KeyError::Encode)
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKey")
            .field("fingerprint", &self.fingerprint())
            .field("private", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rustls::pki_types::CertificateDer;
    use rustls::sign::CertifiedKey;

    use super::{HostKey, KeyError, TlsKey, sha256_hex};

    #[test]
    fn the_tls_key_is_a_pkcs8_ed25519_key_that_rustls_and_rcgen_accept() {
        let key = TlsKey::generate().unwrap();
        let parsed = rcgen::KeyPair::try_from(key.pkcs8_der()).unwrap();
        assert_eq!(
            rcgen::PublicKeyData::subject_public_key_info(&parsed),
            key.spki_der()
        );
        let cert = rcgen::CertificateParams::new(vec!["n.test".to_owned()])
            .unwrap()
            .self_signed(&parsed)
            .unwrap();
        let provider = rustls::crypto::ring::default_provider();
        CertifiedKey::from_der(
            vec![CertificateDer::from(cert.der().to_vec())],
            key.rustls_key(),
            &provider,
        )
        .unwrap()
        .keys_match()
        .unwrap();

        let reloaded = TlsKey::from_pkcs8(key.pkcs8_der()).unwrap();
        assert_eq!(reloaded.spki_der(), key.spki_der());
        assert_eq!(
            key.fingerprint(),
            format!(
                "sha256:{}",
                sha256_hex(&STANDARD.decode(key.spki_base64()).unwrap())
            )
        );
    }

    #[test]
    fn the_fingerprint_digest_matches_the_published_sha256_test_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_tls_key_file_of_another_shape_is_refused() {
        let key = TlsKey::generate().unwrap();
        let mut longer = key.pkcs8_der().to_vec();
        longer.push(0);
        let mut other_oid = key.pkcs8_der().to_vec();
        other_oid[10] = 0x71;
        for bad in [Vec::new(), longer, other_oid, key.spki_der().to_vec()] {
            assert_eq!(
                TlsKey::from_pkcs8(&bad).unwrap_err(),
                KeyError::TlsKeyFormat
            );
        }
    }

    #[test]
    fn the_host_key_round_trips_through_openssh_and_debug_hides_private_material() {
        let key = HostKey::generate().unwrap();
        let private = key.private_openssh().unwrap();
        let reloaded = HostKey::from_openssh(&private).unwrap();
        assert_eq!(reloaded.key_data(), key.key_data());
        assert!(key.public_line().unwrap().starts_with("ssh-ed25519 "));
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert!(HostKey::from_openssh("garbage").is_err());

        let tls = TlsKey::generate().unwrap();
        let shown = format!("{key:?} {tls:?}");
        let body: String = private
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!shown.contains(&body[..40]));
        assert!(!shown.contains(&STANDARD.encode(tls.pkcs8_der())));
        assert!(shown.contains("[redacted]"));
    }
}
