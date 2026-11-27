use std::fmt;
use std::sync::Arc;

use jaunt_proto::ServiceIdentity;
use rustls::RootCertStore;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_SIG_ED25519;
use x509_parser::parse_x509_certificate;
use x509_parser::x509::SubjectPublicKeyInfo;

pub const MAX_USER_X509_ROOTS: usize = 16;
const USER_URN_PREFIX: &str = "urn:jaunt:user:";
const SSH_ED25519: &[u8] = b"ssh-ed25519";
const ED25519_KEY_LEN: usize = 32;
const MAX_SERIAL_BYTES: usize = 8;
const UUID_LEN: usize = 36;
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];

pub trait UserX509Source: Send + Sync {
    fn current(&self) -> Option<Arc<UserX509Roots>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UserX509RootsError {
    #[error("no user-x509 root is configured")]
    Empty,
    #[error("more than {MAX_USER_X509_ROOTS} user-x509 roots are configured")]
    TooMany,
    #[error("user-x509 root {0} is not an Ed25519 certificate the gate can trust")]
    Root(usize),
    #[error("the user-x509 roots cannot verify client certificates")]
    Verifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClientIdentityError {
    #[error("no client certificate was presented")]
    Missing,
    #[error("the client presented more than its own certificate")]
    Chain,
    #[error("the client certificate does not chain to a user-x509 root")]
    Untrusted,
    #[error("the client certificate cannot be parsed")]
    Malformed,
    #[error("the client certificate names no single jaunt user")]
    NoUser,
    #[error("the client certificate serial is not usable")]
    Serial,
    #[error("the client certificate key is not Ed25519")]
    Key,
    #[error("the client certificate is not marked for client authentication")]
    Usage,
}

struct TrustedRoot {
    verifier: Arc<dyn ClientCertVerifier>,
    fingerprint: String,
}

pub struct UserX509Roots {
    all: Arc<dyn ClientCertVerifier>,
    each: Vec<TrustedRoot>,
}

impl fmt::Debug for UserX509Roots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserX509Roots")
            .field("fingerprints", &self.fingerprints())
            .finish()
    }
}

impl UserX509Roots {
    pub fn from_der(roots: impl IntoIterator<Item = Vec<u8>>) -> Result<Self, UserX509RootsError> {
        let provider = Arc::new(default_provider());
        let mut all = RootCertStore::empty();
        let mut each = Vec::new();
        for (index, der) in roots.into_iter().enumerate() {
            if index >= MAX_USER_X509_ROOTS {
                return Err(UserX509RootsError::TooMany);
            }
            let fingerprint =
                certificate_key_fingerprint(&der).ok_or(UserX509RootsError::Root(index))?;
            let certificate = CertificateDer::from(der);
            let mut single = RootCertStore::empty();
            single
                .add(certificate.clone())
                .map_err(|_| UserX509RootsError::Root(index))?;
            all.add(certificate)
                .map_err(|_| UserX509RootsError::Root(index))?;
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(single),
                Arc::clone(&provider),
            )
            .build()
            .map_err(|_| UserX509RootsError::Verifier)?;
            each.push(TrustedRoot {
                verifier,
                fingerprint,
            });
        }
        if each.is_empty() {
            return Err(UserX509RootsError::Empty);
        }
        let all = WebPkiClientVerifier::builder_with_provider(Arc::new(all), provider)
            .build()
            .map_err(|_| UserX509RootsError::Verifier)?;
        Ok(Self { all, each })
    }

    pub fn fingerprints(&self) -> Vec<&str> {
        self.each
            .iter()
            .map(|root| root.fingerprint.as_str())
            .collect()
    }

    pub(crate) fn verifier(&self) -> Arc<dyn ClientCertVerifier> {
        Arc::clone(&self.all)
    }

    pub fn identify(
        &self,
        chain: Option<&[CertificateDer<'_>]>,
        now: UnixTime,
    ) -> Result<ServiceIdentity, ClientIdentityError> {
        let leaf = match chain.unwrap_or_default() {
            [] => return Err(ClientIdentityError::Missing),
            [leaf] => leaf,
            _ => return Err(ClientIdentityError::Chain),
        };
        let issuer = self
            .each
            .iter()
            .find(|root| root.verifier.verify_client_cert(leaf, &[], now).is_ok())
            .ok_or(ClientIdentityError::Untrusted)?;
        let holder = holder_of(leaf)?;
        Ok(ServiceIdentity {
            user_id: holder.user_id,
            serial: holder.serial,
            subject_fingerprint: holder.fingerprint,
            issuer_fingerprint: issuer.fingerprint.clone(),
        })
    }
}

struct Holder {
    user_id: String,
    serial: u64,
    fingerprint: String,
}

fn holder_of(der: &[u8]) -> Result<Holder, ClientIdentityError> {
    let (rest, certificate) =
        parse_x509_certificate(der).map_err(|_| ClientIdentityError::Malformed)?;
    if !rest.is_empty() {
        return Err(ClientIdentityError::Malformed);
    }
    let client_auth = certificate
        .extended_key_usage()
        .map_err(|_| ClientIdentityError::Malformed)?
        .is_some_and(|usage| usage.value.client_auth);
    if !client_auth {
        return Err(ClientIdentityError::Usage);
    }
    let names = certificate
        .subject_alternative_name()
        .map_err(|_| ClientIdentityError::Malformed)?
        .ok_or(ClientIdentityError::NoUser)?;
    let [GeneralName::URI(uri)] = names.value.general_names.as_slice() else {
        return Err(ClientIdentityError::NoUser);
    };
    let user_id = uri
        .strip_prefix(USER_URN_PREFIX)
        .filter(|user| is_canonical_uuid(user))
        .ok_or(ClientIdentityError::NoUser)?;
    let serial = serial_of(certificate.raw_serial()).ok_or(ClientIdentityError::Serial)?;
    let fingerprint =
        ed25519_fingerprint(certificate.public_key()).ok_or(ClientIdentityError::Key)?;
    Ok(Holder {
        user_id: user_id.to_owned(),
        serial,
        fingerprint,
    })
}

fn certificate_key_fingerprint(der: &[u8]) -> Option<String> {
    let (rest, certificate) = parse_x509_certificate(der).ok()?;
    if !rest.is_empty() {
        return None;
    }
    ed25519_fingerprint(certificate.public_key())
}

fn ed25519_fingerprint(key: &SubjectPublicKeyInfo<'_>) -> Option<String> {
    if key.algorithm.algorithm != OID_SIG_ED25519 {
        return None;
    }
    let raw = key.subject_public_key.data.as_ref();
    if raw.len() != ED25519_KEY_LEN {
        return None;
    }
    Some(ssh_ed25519_fingerprint(raw))
}

fn ssh_ed25519_fingerprint(raw: &[u8]) -> String {
    let mut blob = Vec::with_capacity(8 + SSH_ED25519.len() + raw.len());
    blob.extend(wire_len(SSH_ED25519.len()));
    blob.extend(SSH_ED25519);
    blob.extend(wire_len(raw.len()));
    blob.extend(raw);
    hex(&Sha256::digest(&blob))
}

fn wire_len(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

fn serial_of(raw: &[u8]) -> Option<u64> {
    let start = raw.iter().position(|byte| *byte != 0)?;
    let significant = raw.get(start..)?;
    if significant.len() > MAX_SERIAL_BYTES {
        return None;
    }
    let mut bytes = [0_u8; MAX_SERIAL_BYTES];
    let offset = MAX_SERIAL_BYTES - significant.len();
    bytes.get_mut(offset..)?.copy_from_slice(significant);
    Some(u64::from_be_bytes(bytes))
}

fn is_canonical_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == UUID_LEN
        && bytes.iter().enumerate().all(|(at, byte)| {
            if UUID_HYPHENS.contains(&at) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
        && bytes.iter().any(|byte| !matches!(byte, b'0' | b'-'))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519, PublicKeyData, SanType, SerialNumber,
    };
    use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData};
    use russh::keys::{HashAlg, PublicKey};
    use rustls::pki_types::{CertificateDer, UnixTime};

    use super::{
        ClientIdentityError, UserX509Roots, UserX509RootsError, is_canonical_uuid, serial_of,
        ssh_ed25519_fingerprint,
    };

    const USER: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn root(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        CertifiedIssuer::self_signed(params, key).unwrap()
    }

    fn leaf(
        issuer: &CertifiedIssuer<'static, KeyPair>,
        uris: &[String],
        serial: &[u8],
        key: &KeyPair,
    ) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI(Ia5String::try_from(uri.as_str()).unwrap()))
            .collect();
        params.serial_number = Some(SerialNumber::from_slice(serial));
        params.signed_by(key, &**issuer).unwrap().der().clone()
    }

    fn raw_key(key: &KeyPair) -> [u8; 32] {
        key.der_bytes().try_into().unwrap()
    }

    fn ssh_fingerprint(raw: [u8; 32]) -> String {
        let key = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(raw)));
        key.fingerprint(HashAlg::Sha256)
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn the_fingerprint_is_the_sha256_of_the_ssh_form_of_the_ed25519_key() {
        for _ in 0..4 {
            let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
            let raw = raw_key(&key);
            assert_eq!(ssh_ed25519_fingerprint(&raw), ssh_fingerprint(raw));
        }
    }

    #[test]
    fn the_identity_names_the_user_serial_subject_key_and_the_signing_root() {
        let active = root("Jaunt User X.509 CA");
        let next = root("Jaunt User X.509 CA");
        let roots = UserX509Roots::from_der([active.der().to_vec(), next.der().to_vec()]).unwrap();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let certificate = leaf(&next, &[format!("urn:jaunt:user:{USER}")], &[0, 7, 1], &key);
        let identity = roots
            .identify(Some(std::slice::from_ref(&certificate)), UnixTime::now())
            .unwrap();
        assert_eq!(identity.user_id, USER);
        assert_eq!(identity.serial, 0x0701);
        assert_eq!(identity.subject_fingerprint, ssh_fingerprint(raw_key(&key)));
        let next_key: [u8; 32] = next.key().der_bytes().try_into().unwrap();
        assert_eq!(identity.issuer_fingerprint, ssh_fingerprint(next_key));
        assert_eq!(roots.fingerprints()[1], identity.issuer_fingerprint);
        assert_ne!(roots.fingerprints()[0], identity.issuer_fingerprint);
    }

    #[test]
    fn certificates_without_exactly_one_canonical_user_or_from_another_root_are_refused() {
        let trusted = root("trusted");
        let foreign = root("foreign");
        let roots = UserX509Roots::from_der([trusted.der().to_vec()]).unwrap();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let user = format!("urn:jaunt:user:{USER}");
        let cases: Vec<(CertificateDer<'static>, ClientIdentityError)> = vec![
            (
                leaf(&foreign, std::slice::from_ref(&user), &[7], &key),
                ClientIdentityError::Untrusted,
            ),
            (leaf(&trusted, &[], &[7], &key), ClientIdentityError::NoUser),
            (
                leaf(
                    &trusted,
                    &[
                        user.clone(),
                        format!("urn:jaunt:user:{}", USER.replace('6', "7")),
                    ],
                    &[7],
                    &key,
                ),
                ClientIdentityError::NoUser,
            ),
            (
                leaf(&trusted, &[format!("urn:jaunt:node:{USER}")], &[7], &key),
                ClientIdentityError::NoUser,
            ),
            (
                leaf(&trusted, &[user.to_uppercase()], &[7], &key),
                ClientIdentityError::NoUser,
            ),
            (
                leaf(
                    &trusted,
                    std::slice::from_ref(&user),
                    &[1, 2, 3, 4, 5, 6, 7, 8, 9],
                    &key,
                ),
                ClientIdentityError::Serial,
            ),
        ];
        for (certificate, expected) in cases {
            assert_eq!(
                roots
                    .identify(Some(std::slice::from_ref(&certificate)), UnixTime::now())
                    .err(),
                Some(expected)
            );
        }
        assert_eq!(
            roots.identify(None, UnixTime::now()).err(),
            Some(ClientIdentityError::Missing)
        );
        assert_eq!(
            roots.identify(Some(&[]), UnixTime::now()).err(),
            Some(ClientIdentityError::Missing)
        );
    }

    #[test]
    fn only_a_lone_client_certificate_with_one_user_name_and_client_usage_is_accepted() {
        let trusted = root("trusted");
        let roots = UserX509Roots::from_der([trusted.der().to_vec()]).unwrap();
        let user = format!("urn:jaunt:user:{USER}");
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let build = |names: Vec<SanType>, usages: Vec<ExtendedKeyUsagePurpose>| {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.extended_key_usages = usages;
            params.subject_alt_names = names;
            params.serial_number = Some(SerialNumber::from(7_u64));
            params.not_after = rcgen::date_time_ymd(2099, 1, 1);
            params.signed_by(&key, &*trusted).unwrap().der().clone()
        };
        let uri = || SanType::URI(Ia5String::try_from(user.as_str()).unwrap());
        let client = || vec![ExtendedKeyUsagePurpose::ClientAuth];
        let accepted = build(vec![uri()], client());
        let now = UnixTime::now();
        assert!(
            roots
                .identify(Some(std::slice::from_ref(&accepted)), now)
                .is_ok()
        );
        let cases = [
            (
                build(
                    vec![uri(), SanType::DnsName("x.example".try_into().unwrap())],
                    client(),
                ),
                ClientIdentityError::NoUser,
            ),
            (build(vec![uri()], Vec::new()), ClientIdentityError::Usage),
        ];
        for (certificate, expected) in cases {
            assert_eq!(
                roots
                    .identify(Some(std::slice::from_ref(&certificate)), now)
                    .err(),
                Some(expected)
            );
        }
        assert_eq!(
            roots
                .identify(Some(&[accepted.clone(), trusted.der().clone()]), now)
                .err(),
            Some(ClientIdentityError::Chain)
        );

        let mut middle = CertificateParams::new(Vec::<String>::new()).unwrap();
        middle.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        middle.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        middle.distinguished_name.push(DnType::CommonName, "middle");
        let middle = CertifiedIssuer::signed_by(
            middle,
            KeyPair::generate_for(&PKCS_ED25519).unwrap(),
            &trusted,
        )
        .unwrap();
        let below = leaf(&middle, std::slice::from_ref(&user), &[7], &key);
        assert_eq!(
            roots
                .identify(Some(&[below.clone(), middle.der().clone()]), now)
                .err(),
            Some(ClientIdentityError::Chain)
        );
        assert_eq!(
            roots
                .identify(Some(std::slice::from_ref(&below)), now)
                .err(),
            Some(ClientIdentityError::Untrusted)
        );
        let later = UnixTime::since_unix_epoch(std::time::Duration::from_secs(4_200_000_000));
        assert_eq!(
            roots
                .identify(Some(std::slice::from_ref(&accepted)), later)
                .err(),
            Some(ClientIdentityError::Untrusted)
        );
    }

    #[test]
    fn roots_must_be_present_bounded_and_ed25519() {
        assert_eq!(
            UserX509Roots::from_der(Vec::<Vec<u8>>::new()).err(),
            Some(UserX509RootsError::Empty)
        );
        let many: Vec<Vec<u8>> = (0..17).map(|_| root("r").der().to_vec()).collect();
        assert_eq!(
            UserX509Roots::from_der(many).err(),
            Some(UserX509RootsError::TooMany)
        );
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ecdsa = KeyPair::generate().unwrap();
        let ecdsa_root = params.self_signed(&ecdsa).unwrap().der().to_vec();
        assert_eq!(
            UserX509Roots::from_der([root("ok").der().to_vec(), ecdsa_root]).err(),
            Some(UserX509RootsError::Root(1))
        );
        assert_eq!(
            UserX509Roots::from_der([b"not a certificate".to_vec()]).err(),
            Some(UserX509RootsError::Root(0))
        );
    }

    #[test]
    fn serials_and_user_ids_have_one_accepted_form() {
        assert_eq!(serial_of(&[0, 0, 42]), Some(42));
        assert_eq!(serial_of(&[0xff; 8]), Some(u64::MAX));
        assert_eq!(serial_of(&[0, 1, 0, 0, 0, 0, 0, 0, 0]), Some(1 << 56));
        assert_eq!(serial_of(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(serial_of(&[0, 0]), None);
        assert_eq!(serial_of(&[]), None);
        assert!(is_canonical_uuid(USER));
        for bad in [
            "",
            "67e55044-10b1-426f-9247-bb680e5fe0c",
            "67e55044-10b1-426f-9247-bb680e5fe0c80",
            "67E55044-10B1-426F-9247-BB680E5FE0C8",
            "67e55044x10b1-426f-9247-bb680e5fe0c8",
            "67e5504410b1426f9247bb680e5fe0c8abcd",
            "00000000-0000-0000-0000-000000000000",
            "g7e55044-10b1-426f-9247-bb680e5fe0c8",
        ] {
            assert!(!is_canonical_uuid(bad), "{bad}");
        }
    }
}
