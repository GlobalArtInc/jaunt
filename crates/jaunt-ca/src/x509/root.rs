use std::time::{Duration, SystemTime};

use ed25519_dalek::{Signature as RawSignature, VerifyingKey};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyUsagePurpose};
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::parse_x509_certificate;

use super::key::{ED25519_KEY_LEN, SignerKey};
use super::{
    IssuedCertificate, common_name, key_identifier, random_serial, serial_number, set_window,
};
use crate::cert::window;
use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;

pub(super) struct RootProfile {
    pub(super) kind: CaKind,
    pub(super) common_name: &'static str,
    pub(super) validity: Duration,
}

pub(super) fn create(
    signer: &dyn Signer,
    now: SystemTime,
    profile: &RootProfile,
) -> Result<IssuedCertificate, CaError> {
    let key = SignerKey::new(signer, profile.kind)?;
    let window = window(now, profile.validity, profile.validity)?;
    let serial = random_serial()?;

    let mut params = CertificateParams::default();
    let (not_before, not_after) = set_window(&mut params, &window)?;
    params.serial_number = Some(serial_number(serial));
    params.distinguished_name = common_name(profile.common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.key_identifier_method = key_identifier(key.raw());

    let certificate = params
        .self_signed(&key)
        .map_err(|err| key.take_failure().unwrap_or(CaError::X509(err)))?;
    let certificate_der = certificate.der().to_vec();
    validate(&certificate_der, key.raw())?;
    Ok(IssuedCertificate {
        certificate_der,
        serial,
        not_before,
        not_after,
    })
}

#[derive(Clone, Copy, Debug)]
pub(super) struct RootValidity {
    not_before: u64,
    not_after: u64,
}

impl RootValidity {
    pub(super) fn check(self, now: u64, leaf_not_after: u64) -> Result<(), CaError> {
        if now < self.not_before || now > self.not_after {
            return Err(CaError::RootNotValid);
        }
        if leaf_not_after > self.not_after {
            return Err(CaError::ExceedsRootValidity);
        }
        Ok(())
    }
}

pub(super) fn validate(
    root_der: &[u8],
    expected_key: &[u8; ED25519_KEY_LEN],
) -> Result<RootValidity, CaError> {
    let (rest, root) =
        parse_x509_certificate(root_der).map_err(|_| invalid("it cannot be parsed"))?;
    if !rest.is_empty() {
        return Err(invalid("it has trailing data"));
    }

    let public_key = root.public_key();
    if public_key.algorithm.algorithm != OID_SIG_ED25519
        || public_key.subject_public_key.data.as_ref() != expected_key.as_slice()
    {
        return Err(invalid("it is not issued for the authority key"));
    }
    if root.subject().as_raw() != root.issuer().as_raw() {
        return Err(invalid("it is not self-signed"));
    }

    let constraints = root
        .basic_constraints()
        .map_err(|_| invalid("its basic constraints are malformed"))?
        .ok_or_else(|| invalid("it has no basic constraints"))?;
    if !constraints.value.ca || constraints.value.path_len_constraint != Some(0) {
        return Err(invalid(
            "it is not a certificate authority with path length 0",
        ));
    }
    let usage = root
        .key_usage()
        .map_err(|_| invalid("its key usage is malformed"))?
        .ok_or_else(|| invalid("it has no key usage"))?;
    if !usage.value.key_cert_sign() {
        return Err(invalid("it may not sign certificates"));
    }

    if root.signature_algorithm.algorithm != OID_SIG_ED25519 {
        return Err(invalid("it is not signed with Ed25519"));
    }
    let verifying =
        VerifyingKey::from_bytes(expected_key).map_err(|_| CaError::UnsupportedKeyAlgorithm)?;
    let signature = RawSignature::from_slice(root.signature_value.data.as_ref())
        .map_err(|_| invalid("its signature is malformed"))?;
    verifying
        .verify_strict(root.tbs_certificate.as_ref(), &signature)
        .map_err(|_| invalid("its signature does not verify"))?;

    let validity = root.validity();
    let seconds = |timestamp: i64| {
        u64::try_from(timestamp).map_err(|_| invalid("its validity starts before 1970"))
    };
    Ok(RootValidity {
        not_before: seconds(validity.not_before.timestamp())?,
        not_after: seconds(validity.not_after.timestamp())?,
    })
}

fn invalid(reason: &'static str) -> CaError {
    CaError::InvalidRootCertificate { reason }
}
