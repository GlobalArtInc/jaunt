use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jaunt_proto::{
    ADMIN_SIGNATURE_LABEL, ADMIN_SIGNATURE_NAMESPACE, admin_signature_base, admin_signature_params,
    is_admin_nonce,
};
use sha2::{Digest, Sha256};
use ssh_encoding::Encode;
use ssh_key::public::KeyData;
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Certificate, HashAlg, PrivateKey, PublicKey, SshSig};

use crate::agent_protocol::{AgentClient, AgentProtocolError};
use crate::secret::Secret;

const NONCE_BYTES: usize = 16;
const SIGNATURE_HASH: HashAlg = HashAlg::Sha512;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("the certificate of this profile cannot be read; run `jaunt login`")]
    Certificate,
    #[error("the key file of this profile cannot be read; run `jaunt login`")]
    KeyFile,
    #[error("the key file of this profile does not match its certificate; run `jaunt login`")]
    KeyMismatch,
    #[error("ssh-agent did not sign the request: {0}")]
    Agent(#[from] AgentProtocolError),
    #[error("the signature does not match the certificate of this profile")]
    BadSignature,
    #[error("cannot sign the request")]
    Signing,
    #[error("cannot generate a nonce: the system entropy source failed")]
    Entropy,
    #[error("the nonce is not valid")]
    Nonce,
}

pub trait SshSigner {
    fn sign(&self, key: &KeyData, message: &[u8]) -> Result<SshSig, SignError>;
}

pub struct KeyFileSigner {
    key: PrivateKey,
}

impl KeyFileSigner {
    pub fn from_openssh(pem: &Secret) -> Result<KeyFileSigner, SignError> {
        let key = PrivateKey::from_openssh(pem.expose()).map_err(|_| SignError::KeyFile)?;
        if key.is_encrypted() {
            return Err(SignError::KeyFile);
        }
        Ok(KeyFileSigner { key })
    }

    pub fn key_data(&self) -> &KeyData {
        self.key.public_key().key_data()
    }
}

impl fmt::Debug for KeyFileSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyFileSigner")
            .field("key", &"[redacted]")
            .finish()
    }
}

impl SshSigner for KeyFileSigner {
    fn sign(&self, key: &KeyData, message: &[u8]) -> Result<SshSig, SignError> {
        if self.key_data() != key {
            return Err(SignError::KeyMismatch);
        }
        self.key
            .sign(ADMIN_SIGNATURE_NAMESPACE, SIGNATURE_HASH, message)
            .map_err(|_| SignError::Signing)
    }
}

#[derive(Debug, Clone)]
pub struct AgentSigner {
    agent: AgentClient,
}

impl AgentSigner {
    pub fn new(socket: PathBuf, timeout: Duration) -> AgentSigner {
        AgentSigner {
            agent: AgentClient::new(socket, timeout),
        }
    }
}

impl SshSigner for AgentSigner {
    fn sign(&self, key: &KeyData, message: &[u8]) -> Result<SshSig, SignError> {
        let data = SshSig::signed_data(ADMIN_SIGNATURE_NAMESPACE, SIGNATURE_HASH, message)
            .map_err(|_| SignError::Signing)?;
        let signature = self.agent.sign(key, &data)?;
        SshSig::new(
            key.clone(),
            ADMIN_SIGNATURE_NAMESPACE,
            SIGNATURE_HASH,
            signature,
        )
        .map_err(|_| SignError::Signing)
    }
}

#[derive(Clone, Copy)]
pub struct RequestToSign<'a> {
    pub method: &'a str,
    pub target_uri: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub certificate: String,
    pub content_digest: String,
    pub signature_input: String,
    pub signature: String,
}

impl fmt::Debug for SignedHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedHeaders")
            .field("signature_input", &self.signature_input)
            .finish_non_exhaustive()
    }
}

pub fn certificate_header(line: &str) -> Option<String> {
    let mut fields = line.split_ascii_whitespace();
    let (algorithm, encoded) = (fields.next()?, fields.next()?);
    let header = format!("{algorithm} {encoded}");
    header
        .bytes()
        .all(|byte| (0x21..=0x7e).contains(&byte) || byte == b' ')
        .then_some(header)
}

pub fn sign_request(
    signer: &dyn SshSigner,
    certificate_line: &str,
    request: RequestToSign<'_>,
    created: i64,
    nonce: &str,
) -> Result<SignedHeaders, SignError> {
    let certificate_text = certificate_header(certificate_line).ok_or(SignError::Certificate)?;
    let certificate =
        Certificate::from_openssh(&certificate_text).map_err(|_| SignError::Certificate)?;
    if !is_admin_nonce(nonce) {
        return Err(SignError::Nonce);
    }
    let content_digest = content_digest(request.body);
    let params = admin_signature_params(created, nonce, certificate.serial());
    let base = admin_signature_base(
        [
            request.method,
            request.target_uri,
            &content_digest,
            &certificate_text,
        ],
        &params,
    );
    let signature = signer.sign(certificate.public_key(), base.as_bytes())?;
    PublicKey::from(certificate.public_key().clone())
        .verify(ADMIN_SIGNATURE_NAMESPACE, base.as_bytes(), &signature)
        .map_err(|_| SignError::BadSignature)?;
    let mut encoded = Vec::new();
    signature
        .encode(&mut encoded)
        .map_err(|_| SignError::Signing)?;
    Ok(SignedHeaders {
        certificate: certificate_text,
        content_digest,
        signature_input: format!("{ADMIN_SIGNATURE_LABEL}={params}"),
        signature: format!("{ADMIN_SIGNATURE_LABEL}=:{}:", STANDARD.encode(encoded)),
    })
}

pub fn new_nonce() -> Result<String, SignError> {
    let mut bytes = [0_u8; NONCE_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| SignError::Entropy)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

#[cfg(test)]
mod tests {
    use jaunt_proto::{admin_signature_base, admin_signature_params};
    use ssh_key::certificate::{Builder, CertType};
    use ssh_key::public::KeyData;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey, SshSig};

    use super::{
        KeyFileSigner, RequestToSign, SignError, SshSigner, certificate_header, content_digest,
        new_nonce, sign_request,
    };
    use crate::secret::Secret;

    struct Impostor(PrivateKey);

    impl SshSigner for Impostor {
        fn sign(&self, _key: &KeyData, message: &[u8]) -> Result<SshSig, SignError> {
            Ok(self
                .0
                .sign("jaunt-admin@1", HashAlg::Sha512, message)
                .unwrap())
        }
    }

    const NONCE: &str = "bm9uY2Utbm9uY2Utbm9uY2U";

    fn certificate_for(subject: &PrivateKey, serial: u64) -> String {
        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            subject.public_key().key_data().clone(),
            1,
            4_000_000_000,
        )
        .unwrap();
        builder.serial(serial).unwrap();
        builder.cert_type(CertType::User).unwrap();
        builder
            .key_id(format!("jaunt:a@example.com:{serial}"))
            .unwrap();
        builder.valid_principal("p").unwrap();
        builder.sign(&ca).unwrap().to_openssh().unwrap()
    }

    fn key_file(key: &PrivateKey) -> KeyFileSigner {
        let pem = key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        KeyFileSigner::from_openssh(&Secret::new(pem.to_string())).unwrap()
    }

    #[test]
    fn the_content_digest_is_sha256_of_the_body() {
        assert_eq!(
            content_digest(b""),
            "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    #[test]
    fn a_signer_that_returns_another_keys_signature_is_caught_before_sending() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = certificate_for(&key, 7);
        let request = RequestToSign {
            method: "GET",
            target_uri: "https://jaunt.example/v1/admin/whoami",
            body: b"",
        };
        assert!(matches!(
            sign_request(&Impostor(other), &line, request, 1, NONCE),
            Err(SignError::BadSignature)
        ));
        assert!(sign_request(&Impostor(key), &line, request, 1, NONCE).is_ok());
    }

    #[test]
    fn a_key_file_signs_a_request_whose_sshsig_verifies_over_the_base() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = format!("{} comment", certificate_for(&key, 42));
        let request = RequestToSign {
            method: "POST",
            target_uri: "https://jaunt.example/v1/admin/revocations",
            body: b"{}",
        };

        let signed = sign_request(&key_file(&key), &line, request, 1_700_000_000, NONCE).unwrap();

        let certificate_text = certificate_header(&line).unwrap();
        assert_eq!(signed.certificate, certificate_text);
        assert!(!signed.certificate.ends_with("comment"));
        assert_eq!(signed.content_digest, content_digest(b"{}"));
        let params = admin_signature_params(1_700_000_000, NONCE, 42);
        assert_eq!(signed.signature_input, format!("jaunt={params}"));
        let encoded = signed
            .signature
            .strip_prefix("jaunt=:")
            .and_then(|rest| rest.strip_suffix(':'))
            .unwrap();
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap();
        let mut reader = bytes.as_slice();
        let sshsig = <SshSig as ssh_encoding::Decode>::decode(&mut reader).unwrap();
        assert!(reader.is_empty());
        let base = admin_signature_base(
            [
                request.method,
                request.target_uri,
                &signed.content_digest,
                &certificate_text,
            ],
            &params,
        );
        let certificate = Certificate::from_openssh(&certificate_text).unwrap();
        PublicKey::from(certificate.public_key().clone())
            .verify("jaunt-admin@1", base.as_bytes(), &sshsig)
            .unwrap();
        assert!(!format!("{signed:?}").contains(&certificate_text));
    }

    #[test]
    fn a_key_file_for_another_key_and_a_bad_nonce_are_refused_before_signing() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = certificate_for(&key, 7);
        let request = RequestToSign {
            method: "GET",
            target_uri: "https://jaunt.example/v1/admin/whoami",
            body: b"",
        };
        assert!(matches!(
            sign_request(&key_file(&other), &line, request, 1, NONCE),
            Err(SignError::KeyMismatch)
        ));
        assert!(matches!(
            sign_request(&key_file(&key), &line, request, 1, "short"),
            Err(SignError::Nonce)
        ));
        assert!(matches!(
            sign_request(&key_file(&key), "garbage", request, 1, NONCE),
            Err(SignError::Certificate)
        ));
        assert!(!format!("{:?}", key_file(&key)).contains("PRIVATE"));
    }

    #[test]
    fn nonces_are_fresh_base64url_values_of_128_bits() {
        let first = new_nonce().unwrap();
        let second = new_nonce().unwrap();
        assert_eq!(first.len(), 22);
        assert!(jaunt_proto::is_admin_nonce(&first));
        assert_ne!(first, second);
    }
}
