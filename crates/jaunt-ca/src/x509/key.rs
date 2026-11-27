use std::cell::RefCell;
use std::fmt;

use ed25519_dalek::{Signature as RawSignature, VerifyingKey};
use rcgen::{PKCS_ED25519, PublicKeyData, SignatureAlgorithm, SigningKey, SubjectPublicKeyInfo};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, PublicKey, Signature};

use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;

pub(super) const ED25519_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectPublicKey {
    raw: [u8; ED25519_KEY_LEN],
}

impl SubjectPublicKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CaError> {
        let spki = SubjectPublicKeyInfo::from_der(der).map_err(|_| CaError::InvalidSubjectKey)?;
        if spki.algorithm() != &PKCS_ED25519 {
            return Err(CaError::InvalidSubjectKey);
        }
        let raw: [u8; ED25519_KEY_LEN] = spki
            .der_bytes()
            .try_into()
            .map_err(|_| CaError::InvalidSubjectKey)?;
        Self::from_raw(raw)
    }

    pub fn from_ssh_key(key: &PublicKey) -> Result<Self, CaError> {
        let ed25519 = key.key_data().ed25519().ok_or(CaError::InvalidSubjectKey)?;
        Self::from_raw(ed25519.0)
    }

    pub fn to_ssh_key(&self) -> PublicKey {
        PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(self.raw)))
    }

    pub(super) fn raw(&self) -> &[u8; ED25519_KEY_LEN] {
        &self.raw
    }

    fn from_raw(raw: [u8; ED25519_KEY_LEN]) -> Result<Self, CaError> {
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| CaError::InvalidSubjectKey)?;
        if key.is_weak() {
            return Err(CaError::InvalidSubjectKey);
        }
        Ok(Self { raw })
    }
}

impl TryFrom<&PublicKey> for SubjectPublicKey {
    type Error = CaError;

    fn try_from(key: &PublicKey) -> Result<Self, CaError> {
        Self::from_ssh_key(key)
    }
}

impl PublicKeyData for SubjectPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

pub(super) struct SignerKey<'a> {
    signer: &'a dyn Signer,
    verifying: VerifyingKey,
    raw: [u8; ED25519_KEY_LEN],
    failure: RefCell<Option<CaError>>,
}

impl<'a> SignerKey<'a> {
    pub(super) fn new(signer: &'a dyn Signer, expected: CaKind) -> Result<Self, CaError> {
        if signer.kind() != expected {
            return Err(CaError::WrongAuthorityKind { expected });
        }
        let raw = signer
            .public_key()
            .key_data()
            .ed25519()
            .ok_or(CaError::UnsupportedKeyAlgorithm)?
            .0;
        let verifying =
            VerifyingKey::from_bytes(&raw).map_err(|_| CaError::UnsupportedKeyAlgorithm)?;
        Ok(Self {
            signer,
            verifying,
            raw,
            failure: RefCell::new(None),
        })
    }

    pub(super) fn raw(&self) -> &[u8; ED25519_KEY_LEN] {
        &self.raw
    }

    pub(super) fn take_failure(&self) -> Option<CaError> {
        self.failure.borrow_mut().take()
    }

    fn fail(&self, err: CaError) -> rcgen::Error {
        *self.failure.borrow_mut() = Some(err);
        rcgen::Error::RemoteKeyError
    }

    fn checked_signature(&self, msg: &[u8], signature: &Signature) -> Result<Vec<u8>, CaError> {
        if signature.algorithm() != Algorithm::Ed25519
            || signature.as_bytes().len() != ED25519_SIGNATURE_LEN
        {
            return Err(CaError::Sign);
        }
        let raw = RawSignature::from_slice(signature.as_bytes()).map_err(|_| CaError::Sign)?;
        self.verifying
            .verify_strict(msg, &raw)
            .map_err(|_| CaError::Sign)?;
        Ok(signature.as_bytes().to_vec())
    }
}

impl PublicKeyData for SignerKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl SigningKey for SignerKey<'_> {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature = self.signer.try_sign(msg).map_err(|err| self.fail(err))?;
        self.checked_signature(msg, &signature)
            .map_err(|err| self.fail(err))
    }
}

impl fmt::Debug for SignerKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerKey")
            .field("kind", &self.signer.kind())
            .finish_non_exhaustive()
    }
}
