mod client;
mod identity;
mod key;
mod root;

#[cfg(test)]
mod tests;

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
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

pub use client::{
    CLIENT_ROOT_VALIDITY, ClientCa, DB_CLIENT_BACKDATE, DB_CLIENT_VALIDITY, DbClientParams,
    MAX_USER_X509_VALIDITY, UserX509Params,
};
pub use identity::{NodeIdentity, parse_node_identity};
pub use key::SubjectPublicKey;

use crate::cert::{Window, validate_hostnames, window};
use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;
use key::SignerKey;
use root::{RootProfile, RootValidity};

pub const DEFAULT_NODE_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_NODE_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const DEFAULT_SERVER_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const MAX_SERVER_VALIDITY: Duration = Duration::from_secs(90 * 24 * 60 * 60);
pub const DEFAULT_SERVICE_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const ROOT_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

const ROOT_COMMON_NAME: &str = "Jaunt Internal CA";
const INTERNAL_ROOT: RootProfile = RootProfile {
    kind: CaKind::Internal,
    common_name: ROOT_COMMON_NAME,
    validity: ROOT_VALIDITY,
};
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

#[derive(Clone, Debug)]
pub struct ServiceCertParams {
    pub subject_public_key: SubjectPublicKey,
    pub dns_names: Vec<String>,
    pub serial: u64,
    pub validity: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub certificate_der: Vec<u8>,
    pub serial: u128,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

impl IssuedCertificate {
    pub fn sha256_hex(&self) -> String {
        sha256_hex(&self.certificate_der)
    }
}

pub struct InternalCa {
    issuer: LeafIssuer,
}

impl InternalCa {
    pub fn new(signer: Arc<dyn Signer>, root_der: Vec<u8>) -> Result<Self, CaError> {
        Ok(Self {
            issuer: LeafIssuer::new(signer, root_der, CaKind::Internal)?,
        })
    }

    pub fn create_root(signer: &dyn Signer, now: SystemTime) -> Result<IssuedCertificate, CaError> {
        root::create(signer, now, &INTERNAL_ROOT)
    }

    pub fn root_der(&self) -> &[u8] {
        self.issuer.root_der()
    }

    pub fn root_sha256_hex(&self) -> String {
        self.issuer.root_sha256_hex()
    }

    pub fn root_not_before(&self) -> SystemTime {
        self.issuer.root_not_before()
    }

    pub fn root_not_after(&self) -> SystemTime {
        self.issuer.root_not_after()
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
        self.issuer.check_window(now, &window)?;
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
        self.issuer.check_window(now, &window)?;
        let names = dns_sans(&dns_names)?;
        self.issue_leaf(
            &params.subject_public_key,
            &window,
            first_name,
            ExtendedKeyUsagePurpose::ServerAuth,
            names,
        )
    }

    pub fn issue_service_certificate(
        &self,
        params: ServiceCertParams,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        let dns_names: Vec<String> = params
            .dns_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect();
        validate_dns_names(&dns_names)?;
        let window = window(now, params.validity, MAX_SERVER_VALIDITY)?;
        self.issuer.check_window(now, &window)?;
        self.issuer.issue(Leaf {
            subject: &params.subject_public_key,
            window: &window,
            common_name: None,
            usage: ExtendedKeyUsagePurpose::ServerAuth,
            names: dns_sans(&dns_names)?,
            serial: u128::from(params.serial),
        })
    }

    fn issue_leaf(
        &self,
        subject: &SubjectPublicKey,
        window: &Window,
        subject_name: &str,
        usage: ExtendedKeyUsagePurpose,
        names: Vec<SanType>,
    ) -> Result<IssuedCertificate, CaError> {
        self.issuer.issue(Leaf {
            subject,
            window,
            common_name: Some(subject_name),
            usage,
            names,
            serial: random_serial()?,
        })
    }
}

impl fmt::Debug for InternalCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalCa")
            .field("kind", &self.issuer.kind())
            .field("root_sha256", &format_args!("{}", self.root_sha256_hex()))
            .finish_non_exhaustive()
    }
}

struct LeafIssuer {
    kind: CaKind,
    signer: Arc<dyn Signer>,
    root_der: Vec<u8>,
    root_validity: RootValidity,
}

struct Leaf<'a> {
    subject: &'a SubjectPublicKey,
    window: &'a Window,
    common_name: Option<&'a str>,
    usage: ExtendedKeyUsagePurpose,
    names: Vec<SanType>,
    serial: u128,
}

impl LeafIssuer {
    fn new(signer: Arc<dyn Signer>, root_der: Vec<u8>, kind: CaKind) -> Result<Self, CaError> {
        let key = SignerKey::new(signer.as_ref(), kind)?;
        let root_validity = root::validate(&root_der, key.raw())?;
        Ok(Self {
            kind,
            signer,
            root_der,
            root_validity,
        })
    }

    fn kind(&self) -> CaKind {
        self.kind
    }

    fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    fn root_sha256_hex(&self) -> String {
        sha256_hex(&self.root_der)
    }

    fn root_not_before(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.root_validity.not_before())
    }

    fn root_not_after(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.root_validity.not_after())
    }

    fn check_window(&self, now: SystemTime, window: &Window) -> Result<(), CaError> {
        let now_seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CaError::InvalidTime)?
            .as_secs();
        self.root_validity.check(now_seconds, window.valid_before)
    }

    fn issue(&self, leaf: Leaf<'_>) -> Result<IssuedCertificate, CaError> {
        if leaf.serial == 0 {
            return Err(CaError::InvalidSerial);
        }
        let mut params = CertificateParams::default();
        let (not_before, not_after) = set_window(&mut params, leaf.window)?;
        params.serial_number = Some(serial_number(leaf.serial));
        params.distinguished_name = leaf
            .common_name
            .map_or_else(DistinguishedName::new, common_name);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![leaf.usage];
        params.subject_alt_names = leaf.names;
        params.use_authority_key_identifier_extension = true;
        params.key_identifier_method = key_identifier(leaf.subject.raw());
        let certificate_der = self.sign(&params, leaf.subject)?;
        Ok(IssuedCertificate {
            certificate_der,
            serial: leaf.serial,
            not_before,
            not_after,
        })
    }

    fn sign(
        &self,
        params: &CertificateParams,
        subject: &SubjectPublicKey,
    ) -> Result<Vec<u8>, CaError> {
        let key = SignerKey::new(self.signer.as_ref(), self.kind)?;
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

pub(crate) fn validate_root(
    root_der: &[u8],
    key: &SubjectPublicKey,
) -> Result<(SystemTime, SystemTime), CaError> {
    let validity = root::validate(root_der, key.raw())?;
    Ok((
        UNIX_EPOCH + Duration::from_secs(validity.not_before()),
        UNIX_EPOCH + Duration::from_secs(validity.not_after()),
    ))
}

fn validate_server_names(names: &[String]) -> Result<(), CaError> {
    validate_dns_names(names)?;
    if names
        .first()
        .is_some_and(|name| name.len() <= MAX_COMMON_NAME_LEN)
    {
        Ok(())
    } else {
        Err(CaError::InvalidHostnames)
    }
}

fn validate_dns_names(names: &[String]) -> Result<(), CaError> {
    validate_hostnames(names)?;
    if names.len() <= MAX_SERVER_NAMES && names.iter().all(|name| is_dns_name(name)) {
        Ok(())
    } else {
        Err(CaError::InvalidHostnames)
    }
}

fn dns_sans(names: &[String]) -> Result<Vec<SanType>, CaError> {
    names
        .iter()
        .map(|name| Ia5String::try_from(name.as_str()).map(SanType::DnsName))
        .collect::<Result<Vec<_>, _>>()
        .map_err(CaError::X509)
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
