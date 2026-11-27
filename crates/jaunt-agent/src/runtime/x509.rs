use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use jaunt_limits::LogThrottle;
use jaunt_proto::{TrustRole, TrustedX509Root};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, PeerIncompatible, RootCertStore,
    SignatureScheme,
};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{HashAlg, PublicKey};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::parse_x509_certificate;

use crate::clock::{Clock, unix_secs};
use crate::verify::{decode_der, is_node_id};

pub const VALID_AFTER_LEEWAY_SECS: i64 = 60;
pub const MAX_USER_X509_ROOTS: usize = 8;
pub const EMPTY_TRUST_NOTICE_EVERY: Duration = Duration::from_secs(60);

const USER_URN_PREFIX: &str = "urn:jaunt:user:";
const ED25519_KEY_LEN: usize = 32;
const MAX_SERIAL_BYTES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RootError {
    #[error("the control plane sent more than {MAX_USER_X509_ROOTS} user X.509 roots")]
    TooMany,
    #[error("a user X.509 root is not valid base64 or is too large")]
    Encoding,
    #[error("a user X.509 root cannot be parsed")]
    Malformed,
    #[error("a user X.509 root is not a self-issued CA certificate")]
    NotCa,
    #[error("a user X.509 root does not hold an Ed25519 key")]
    KeyType,
    #[error("a user X.509 root does not match the fingerprint sent with it")]
    Fingerprint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertRefusal {
    NoTrust,
    Malformed,
    Expired,
    NotYetValid,
    Untrusted,
    NotClientAuth,
    KeyType,
    UserUri,
    Serial,
}

impl CertRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoTrust => "no_trust",
            Self::Malformed => "malformed",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Untrusted => "untrusted",
            Self::NotClientAuth => "not_client_auth",
            Self::KeyType => "key_type",
            Self::UserUri => "user_uri",
            Self::Serial => "serial",
        }
    }

    fn certificate_error(self) -> CertificateError {
        match self {
            Self::Expired => CertificateError::Expired,
            Self::NotYetValid => CertificateError::NotValidYet,
            Self::NoTrust | Self::Untrusted => CertificateError::UnknownIssuer,
            Self::Malformed => CertificateError::BadEncoding,
            Self::NotClientAuth | Self::KeyType | Self::UserUri | Self::Serial => {
                CertificateError::ApplicationVerificationFailure
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedUser {
    pub user_id: String,
    pub serial: u64,
    pub subject_fingerprint: String,
    pub issuer_fingerprint: String,
}

struct Root {
    verifier: Arc<dyn ClientCertVerifier>,
    fingerprint: String,
    role: TrustRole,
    not_before: i64,
    not_after: i64,
}

#[derive(Default)]
pub struct UserRoots(Vec<Root>);

impl fmt::Debug for UserRoots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .iter()
                    .map(|root| (root.role, root.fingerprint.as_str())),
            )
            .finish()
    }
}

impl UserRoots {
    pub fn from_trust(entries: &[TrustedX509Root], now: i64) -> Result<Self, RootError> {
        if entries.len() > MAX_USER_X509_ROOTS {
            return Err(RootError::TooMany);
        }
        let roots = entries.iter().map(root).collect::<Result<Vec<_>, _>>()?;
        Ok(Self(
            roots
                .into_iter()
                .filter(|root| now < root.not_after)
                .collect(),
        ))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn issuer_of(&self, der: &[u8], at: i64, now: i64) -> Option<&Root> {
        let at = u64::try_from(at).ok()?;
        let time = UnixTime::since_unix_epoch(Duration::from_secs(at));
        let certificate = CertificateDer::from(der);
        self.0
            .iter()
            .filter(|root| {
                root.not_before <= now.saturating_add(VALID_AFTER_LEEWAY_SECS)
                    && now < root.not_after
            })
            .find(|root| {
                root.verifier
                    .verify_client_cert(&certificate, &[], time)
                    .is_ok()
            })
    }
}

fn root(entry: &TrustedX509Root) -> Result<Root, RootError> {
    let der = decode_der(&entry.certificate_der).ok_or(RootError::Encoding)?;
    let (rest, certificate) = parse_x509_certificate(&der).map_err(|_| RootError::Malformed)?;
    if !rest.is_empty() {
        return Err(RootError::Malformed);
    }
    if !certificate.is_ca() || certificate.subject().as_raw() != certificate.issuer().as_raw() {
        return Err(RootError::NotCa);
    }
    let key = ed25519_key(&certificate).ok_or(RootError::KeyType)?;
    if fingerprint_hex(&key) != entry.fingerprint {
        return Err(RootError::Fingerprint);
    }
    let validity = certificate.validity();
    let (not_before, not_after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    let mut store = RootCertStore::empty();
    store
        .add(CertificateDer::from(der.clone()))
        .map_err(|_| RootError::Malformed)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(store),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .map_err(|_| RootError::Malformed)?;
    Ok(Root {
        verifier,
        fingerprint: entry.fingerprint.clone(),
        role: entry.role,
        not_before,
        not_after,
    })
}

fn ed25519_key(certificate: &X509Certificate<'_>) -> Option<[u8; ED25519_KEY_LEN]> {
    let spki = certificate.public_key();
    if spki.algorithm.algorithm != OID_SIG_ED25519 || spki.algorithm.parameters.is_some() {
        return None;
    }
    <[u8; ED25519_KEY_LEN]>::try_from(spki.subject_public_key.data.as_ref()).ok()
}

pub fn fingerprint_hex(raw: &[u8; ED25519_KEY_LEN]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let key = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(*raw)));
    let fingerprint = key.fingerprint(HashAlg::Sha256);
    let mut out = String::with_capacity(fingerprint.as_bytes().len() * 2);
    for byte in fingerprint.as_bytes() {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn user_of(certificate: &X509Certificate<'_>) -> Option<String> {
    let san = certificate.subject_alternative_name().ok()??;
    match san.value.general_names.as_slice() {
        [GeneralName::URI(uri)] => uri
            .strip_prefix(USER_URN_PREFIX)
            .filter(|id| is_node_id(id))
            .map(str::to_owned),
        _ => None,
    }
}

pub fn serial_of(raw: &[u8]) -> Option<u64> {
    if raw.first().is_some_and(|first| *first & 0x80 != 0) {
        return None;
    }
    let significant = raw
        .iter()
        .position(|byte| *byte != 0)
        .map_or(&[][..], |start| &raw[start..]);
    if significant.len() > MAX_SERIAL_BYTES {
        return None;
    }
    let serial = significant
        .iter()
        .fold(0_u64, |serial, byte| (serial << 8) | u64::from(*byte));
    (serial != 0).then_some(serial)
}

pub fn verify_user(der: &[u8], roots: &UserRoots, now: i64) -> Result<VerifiedUser, CertRefusal> {
    if roots.is_empty() {
        return Err(CertRefusal::NoTrust);
    }
    let (rest, certificate) = parse_x509_certificate(der).map_err(|_| CertRefusal::Malformed)?;
    if !rest.is_empty() {
        return Err(CertRefusal::Malformed);
    }
    let validity = certificate.validity();
    let (not_before, not_after) = (
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    );
    if now >= not_after {
        return Err(CertRefusal::Expired);
    }
    if not_before > now.saturating_add(VALID_AFTER_LEEWAY_SECS) {
        return Err(CertRefusal::NotYetValid);
    }
    let issuer = roots
        .issuer_of(der, not_before.max(now), now)
        .ok_or(CertRefusal::Untrusted)?;
    let client_auth = certificate
        .extended_key_usage()
        .map_err(|_| CertRefusal::Malformed)?
        .is_some_and(|usage| usage.value.client_auth);
    if !client_auth {
        return Err(CertRefusal::NotClientAuth);
    }
    let key = ed25519_key(&certificate).ok_or(CertRefusal::KeyType)?;
    let user_id = user_of(&certificate).ok_or(CertRefusal::UserUri)?;
    let serial = serial_of(certificate.raw_serial()).ok_or(CertRefusal::Serial)?;
    Ok(VerifiedUser {
        user_id,
        serial,
        subject_fingerprint: fingerprint_hex(&key),
        issuer_fingerprint: issuer.fingerprint.clone(),
    })
}

pub struct UserX509Trust {
    roots: RwLock<Arc<UserRoots>>,
    empty_notice: LogThrottle,
}

impl Default for UserX509Trust {
    fn default() -> Self {
        Self {
            roots: RwLock::new(Arc::new(UserRoots::default())),
            empty_notice: LogThrottle::new(EMPTY_TRUST_NOTICE_EVERY),
        }
    }
}

impl UserX509Trust {
    pub fn install(&self, roots: UserRoots) {
        *self.roots.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(roots);
    }

    pub fn snapshot(&self) -> Arc<UserRoots> {
        Arc::clone(&self.roots.read().unwrap_or_else(PoisonError::into_inner))
    }

    pub fn notice_empty(&self, now: Duration) {
        if let Some(suppressed) = self.empty_notice.admit(now) {
            tracing::warn!(
                target: "jaunt::agent",
                suppressed,
                "no user X.509 roots are loaded: every Kubernetes, database and TCP client certificate is refused until the control plane serves them"
            );
        }
    }
}

pub struct UserVerifier {
    roots: Arc<UserRoots>,
    clock: Arc<dyn Clock>,
    algorithms: WebPkiSupportedAlgorithms,
    outcome: Mutex<Option<Result<VerifiedUser, CertRefusal>>>,
}

impl fmt::Debug for UserVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserVerifier")
            .field("roots", &self.roots)
            .finish_non_exhaustive()
    }
}

impl UserVerifier {
    pub fn new(roots: Arc<UserRoots>, clock: Arc<dyn Clock>) -> Self {
        Self {
            roots,
            clock,
            algorithms: rustls::crypto::ring::default_provider().signature_verification_algorithms,
            outcome: Mutex::new(None),
        }
    }

    pub fn take_outcome(&self) -> Option<Result<VerifiedUser, CertRefusal>> {
        self.outcome
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

impl ClientCertVerifier for UserVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let outcome = verify_user(
            end_entity.as_ref(),
            &self.roots,
            unix_secs(self.clock.now()),
        );
        let answer = match &outcome {
            Ok(_) => Ok(ClientCertVerified::assertion()),
            Err(refusal) => Err(rustls::Error::InvalidCertificate(
                refusal.certificate_error(),
            )),
        };
        *self.outcome.lock().unwrap_or_else(PoisonError::into_inner) = Some(outcome);
        answer
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
