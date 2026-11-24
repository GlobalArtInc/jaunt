mod identity;
mod key;
mod root;

#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::string::Ia5String;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyIdMethod, KeyUsagePurpose, SanType, SerialNumber,
};
use rustls_pki_types::{CertificateDer, DnsName};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

pub use identity::{NodeIdentity, parse_node_identity};
pub use key::SubjectPublicKey;

use crate::cert::{Window, validate_hostnames, window};
use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;
use key::SignerKey;
use root::RootValidity;

pub const DEFAULT_NODE_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_NODE_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_SERVER_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const MAX_SERVER_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);
pub const ROOT_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

const ROOT_COMMON_NAME: &str = "Jaunt Internal CA";
const MAX_SERVER_NAMES: usize = 8;
const MAX_COMMON_NAME_LEN: usize = 64;
const KEY_IDENTIFIER_LEN: usize = 20;

#[derive(Clone, Debug)]
pub struct NodeCertParams {
    pub subject_public_key: SubjectPublicKey,
    pub node_id: Uuid,
    pub validity: Duration,
}

#[derive(Clone, Debug)]
pub struct ServerCertParams {
    pub subject_public_key: SubjectPublicKey,
    pub dns_names: Vec<String>,
    pub validity: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub certificate_der: Vec<u8>,
    pub serial: u128,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

pub struct InternalCa<'a> {
    signer: &'a dyn Signer,
    root_der: Vec<u8>,
    root_validity: RootValidity,
}

impl<'a> InternalCa<'a> {
    pub fn new(signer: &'a dyn Signer, root_der: Vec<u8>) -> Result<Self, CaError> {
        let key = SignerKey::new(signer, CaKind::Internal)?;
        let root_validity = root::validate(&root_der, key.raw())?;
        Ok(Self {
            signer,
            root_der,
            root_validity,
        })
    }

    pub fn create_root(signer: &dyn Signer, now: SystemTime) -> Result<IssuedCertificate, CaError> {
        root::create(signer, now)
    }

    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    pub fn root_sha256_hex(&self) -> String {
        sha256_hex(&self.root_der)
    }

    pub fn issue_node_certificate(
        &self,
        params: NodeCertParams,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        if params.node_id.is_nil() {
            return Err(CaError::InvalidNodeId);
        }
        let window = window(now, params.validity, MAX_NODE_VALIDITY)?;
        self.check_window(now, &window)?;
        let node_id = params.node_id.hyphenated().to_string();
        let uri = Ia5String::try_from(identity::node_urn(params.node_id)).map_err(CaError::X509)?;
        self.issue_leaf(
            &params.subject_public_key,
            &window,
            &node_id,
            ExtendedKeyUsagePurpose::ClientAuth,
            vec![SanType::URI(uri)],
        )
    }

    pub fn issue_server_certificate(
        &self,
        params: ServerCertParams,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        let dns_names: Vec<String> = params
            .dns_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        validate_server_names(&dns_names)?;
        let first_name = dns_names.first().ok_or(CaError::InvalidHostnames)?;
        let window = window(now, params.validity, MAX_SERVER_VALIDITY)?;
        self.check_window(now, &window)?;
        let names = dns_names
            .iter()
            .map(|name| Ia5String::try_from(name.as_str()).map(SanType::DnsName))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CaError::X509)?;
        self.issue_leaf(
            &params.subject_public_key,
            &window,
            first_name,
            ExtendedKeyUsagePurpose::ServerAuth,
            names,
        )
    }

    fn check_window(&self, now: SystemTime, window: &Window) -> Result<(), CaError> {
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CaError::InvalidTime)?
            .as_secs();
        self.root_validity.check(now_seconds, window.valid_before)
    }

    fn issue_leaf(
        &self,
        subject: &SubjectPublicKey,
        window: &Window,
        subject_name: &str,
        usage: ExtendedKeyUsagePurpose,
        names: Vec<SanType>,
    ) -> Result<IssuedCertificate, CaError> {
        let serial = random_serial()?;
        let mut params = CertificateParams::default();
        let (not_before, not_after) = set_window(&mut params, window)?;
        params.serial_number = Some(serial_number(serial));
        params.distinguished_name = common_name(subject_name);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        params.subject_alt_names = names;
        params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = key_identifier(subject.raw());
        let certificate_der = self.sign(&params, subject)?;
        Ok(IssuedCertificate {
            certificate_der,
            serial,
            not_before,
            not_after,
        })
    }

    fn sign(
        &self,
        params: &CertificateParams,
        subject: &SubjectPublicKey,
    ) -> Result<Vec<u8>, CaError> {
        let key = SignerKey::new(self.signer, CaKind::Internal)?;
        if subject.raw() == key.raw() {
            return Err(CaError::InvalidSubjectKey);
        }
        let root = CertificateDer::from(self.root_der.as_slice());
        let issuer = Issuer::from_ca_cert_der(&root, &key).map_err(CaError::X509)?;
        let certificate = params
            .signed_by(subject, &issuer)
            .map_err(|err| key.take_failure().unwrap_or(CaError::X509(err)))?;
        Ok(certificate.der().to_vec())
    }
}

impl fmt::Debug for InternalCa<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalCa")
            .field("kind", &self.signer.kind())
            .field("root_sha256", &format_args!("{}", self.root_sha256_hex()))
            .finish_non_exhaustive()
    }
}

fn validate_server_names(names: &[String]) -> Result<(), CaError> {
    validate_hostnames(names)?;
    let acceptable = names.len() <= MAX_SERVER_NAMES
        && names
            .first()
            .is_some_and(|name| name.len() <= MAX_COMMON_NAME_LEN)
        && names.iter().all(|name| is_dns_name(name));
    if acceptable {
        Ok(())
    } else {
        Err(CaError::InvalidHostnames)
    }
}

fn is_dns_name(name: &str) -> bool {
    let label = |label: &str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    };
    name.parse::<IpAddr>().is_err() && name.split('.').all(label) && DnsName::try_from(name).is_ok()
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn random_serial() -> Result<u128, CaError> {
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CaError::Random)?;
    bytes[0] &= 0x7f;
    match u128::from_be_bytes(bytes) {
        0 => Err(CaError::Random),
        serial => Ok(serial),
    }
}

fn serial_number(serial: u128) -> SerialNumber {
    SerialNumber::from_slice(&serial.to_be_bytes())
}

fn key_identifier(raw_public_key: &[u8; key::ED25519_KEY_LEN]) -> KeyIdMethod {
    let digest = Sha256::digest(raw_public_key);
    KeyIdMethod::PreSpecified(digest.iter().copied().take(KEY_IDENTIFIER_LEN).collect())
}

fn common_name(name: &str) -> DistinguishedName {
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    subject
}

fn set_window(
    params: &mut CertificateParams,
    window: &Window,
) -> Result<(SystemTime, SystemTime), CaError> {
    params.not_before = date_time(window.valid_after)?;
    params.not_after = date_time(window.valid_before)?;
    Ok((
        UNIX_EPOCH + Duration::from_secs(window.valid_after),
        UNIX_EPOCH + Duration::from_secs(window.valid_before),
    ))
}

fn date_time(unix_seconds: u64) -> Result<OffsetDateTime, CaError> {
    let seconds = i64::try_from(unix_seconds).map_err(|_| CaError::InvalidTime)?;
    OffsetDateTime::from_unix_timestamp(seconds).map_err(|_| CaError::InvalidTime)
}
