use std::sync::Arc;

use arc_swap::ArcSwap;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, HashAlg, PublicKey};

use crate::error::SshError;

const KEY_ID_PREFIX: &str = "jaunt:";
const MAX_EMAIL_LEN: usize = 254;
const UUID_LEN: usize = 36;
const UUID_HYPHENS: [usize; 4] = [8, 13, 18, 23];
const NIL_UUID: &str = "00000000-0000-0000-0000-000000000000";
const MAX_VALIDITY_SECS: u64 = 25 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserCaKeys {
    keys: Vec<KeyData>,
}

impl UserCaKeys {
    pub fn from_openssh_lines<I, S>(lines: I) -> Result<Self, SshError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut keys: Vec<KeyData> = Vec::new();
        for (index, line) in lines.into_iter().enumerate() {
            let key = PublicKey::from_openssh(line.as_ref().trim())
                .map_err(|source| SshError::InvalidCaKey { index, source })?;
            if key.algorithm() != Algorithm::Ed25519 {
                return Err(SshError::CaKeyAlgorithm { index });
            }
            let data = key.key_data().clone();
            if keys.contains(&data) {
                return Err(SshError::DuplicateCaKey { index });
            }
            keys.push(data);
        }
        if keys.is_empty() {
            return Err(SshError::EmptyTrustSet);
        }
        Ok(Self { keys })
    }

    fn trusts(&self, signer: &KeyData) -> bool {
        self.keys.iter().any(|key| key == signer)
    }
}

pub struct UserCaSource(ArcSwap<UserCaKeys>);

impl UserCaSource {
    pub fn new(keys: UserCaKeys) -> Self {
        Self(ArcSwap::from_pointee(keys))
    }

    pub fn current(&self) -> Arc<UserCaKeys> {
        self.0.load_full()
    }

    pub fn replace(&self, keys: UserCaKeys) {
        self.0.store(Arc::new(keys));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserIdentity {
    pub user_id: String,
    pub serial: u64,
    pub key_id: String,
    pub email: String,
    pub valid_before: u64,
    pub subject_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CertRejection {
    #[error("the certificate is not signed by a trusted user CA")]
    UntrustedCa,
    #[error("the certificate is not valid yet")]
    NotYetValid,
    #[error("the certificate has expired")]
    Expired,
    #[error("the certificate validity window is longer than a user certificate may be")]
    Window,
    #[error("the certificate is not a user certificate")]
    NotUserCertificate,
    #[error("the certified key is not an Ed25519 key")]
    KeyAlgorithm,
    #[error("the certificate carries critical options")]
    CriticalOptions,
    #[error("the certificate principal is not a single user id")]
    Principal,
    #[error("the certificate key id does not match the serial")]
    KeyId,
}

impl CertRejection {
    pub fn reason(self) -> &'static str {
        match self {
            Self::UntrustedCa => "untrusted_ca",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::Window => "window",
            Self::NotUserCertificate => "not_user_certificate",
            Self::KeyAlgorithm => "key_algorithm",
            Self::CriticalOptions => "critical_options",
            Self::Principal => "principal",
            Self::KeyId => "key_id",
        }
    }
}

pub fn verify_user_certificate(
    cert: &Certificate,
    cas: &UserCaKeys,
    now_unix: u64,
) -> Result<UserIdentity, CertRejection> {
    if !cas.trusts(cert.signature_key()) || cert.verify_signature().is_err() {
        return Err(CertRejection::UntrustedCa);
    }
    if now_unix < cert.valid_after() {
        return Err(CertRejection::NotYetValid);
    }
    if now_unix >= cert.valid_before() {
        return Err(CertRejection::Expired);
    }
    if cert.valid_before().saturating_sub(cert.valid_after()) > MAX_VALIDITY_SECS {
        return Err(CertRejection::Window);
    }
    if cert.cert_type() != CertType::User {
        return Err(CertRejection::NotUserCertificate);
    }
    if cert.public_key().algorithm() != Algorithm::Ed25519 {
        return Err(CertRejection::KeyAlgorithm);
    }
    if !cert.critical_options().is_empty() {
        return Err(CertRejection::CriticalOptions);
    }
    let user_id = match cert.valid_principals() {
        [principal] if is_user_id(principal) => principal.clone(),
        _ => return Err(CertRejection::Principal),
    };
    let email = email_from_key_id(cert.key_id(), cert.serial()).ok_or(CertRejection::KeyId)?;
    Ok(UserIdentity {
        user_id,
        serial: cert.serial(),
        key_id: cert.key_id().to_owned(),
        email: email.to_owned(),
        valid_before: cert.valid_before(),
        subject_fingerprint: sha256_hex(cert.public_key()),
    })
}

fn sha256_hex(key: &KeyData) -> String {
    key.fingerprint(HashAlg::Sha256)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_user_id(text: &str) -> bool {
    text.len() == UUID_LEN
        && text != NIL_UUID
        && text.bytes().enumerate().all(|(index, byte)| {
            if UUID_HYPHENS.contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn email_from_key_id(key_id: &str, serial: u64) -> Option<&str> {
    let (email, serial_text) = key_id.strip_prefix(KEY_ID_PREFIX)?.rsplit_once(':')?;
    (serial_text == serial.to_string() && is_key_id_email(email)).then_some(email)
}

pub(crate) fn is_key_id_email(email: &str) -> bool {
    !email.is_empty()
        && email.len() <= MAX_EMAIL_LEN
        && email
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b':' && byte != b'"')
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use russh::keys::ssh_key::certificate::{Builder, CertType};
    use russh::keys::{Algorithm, Certificate, EcdsaCurve, HashAlg, PrivateKey, PublicKey};

    use super::{
        CertRejection, UserCaKeys, UserCaSource, is_key_id_email, verify_user_certificate,
    };
    use crate::error::SshError;
    use crate::test_support::{NOW, USER_ID, key, rng};

    const ISSUED: u64 = NOW;
    const VALID_AFTER: u64 = ISSUED - 120;
    const VALID_BEFORE: u64 = ISSUED + 8 * 3600;

    struct Profile {
        subject: PrivateKey,
        cert_type: CertType,
        serial: u64,
        key_id: String,
        principals: Vec<String>,
        critical: Vec<(&'static str, &'static str)>,
        extensions: Vec<(&'static str, &'static str)>,
        valid_after: u64,
        valid_before: u64,
    }

    impl Profile {
        fn jaunt() -> Self {
            Self {
                subject: key(Algorithm::Ed25519),
                cert_type: CertType::User,
                serial: 42,
                key_id: "jaunt:alice@example.com:42".to_owned(),
                principals: vec![USER_ID.to_owned()],
                critical: Vec::new(),
                extensions: vec![("permit-port-forwarding", ""), ("permit-pty", "")],
                valid_after: VALID_AFTER,
                valid_before: VALID_BEFORE,
            }
        }

        fn sign(self, ca: &PrivateKey) -> Certificate {
            let mut builder = Builder::new_with_random_nonce(
                &mut rng(),
                self.subject.public_key().key_data().clone(),
                self.valid_after,
                self.valid_before,
            )
            .unwrap();
            builder.serial(self.serial).unwrap();
            builder.cert_type(self.cert_type).unwrap();
            builder.key_id(self.key_id).unwrap();
            if self.principals.is_empty() {
                builder.all_principals_valid().unwrap();
            }
            for principal in self.principals {
                builder.valid_principal(principal).unwrap();
            }
            for (name, value) in self.critical {
                builder.critical_option(name, value).unwrap();
            }
            for (name, value) in self.extensions {
                builder.extension(name, value).unwrap();
            }
            builder.sign(ca).unwrap()
        }
    }

    fn trust(ca: &PrivateKey) -> UserCaKeys {
        UserCaKeys::from_openssh_lines([ca.public_key().to_openssh().unwrap()]).unwrap()
    }

    #[test]
    fn the_identity_carries_the_certified_key_fingerprint_as_lowercase_sha256_hex() {
        let ca = key(Algorithm::Ed25519);
        let profile = Profile::jaunt();
        let subject = profile.subject.public_key().clone();
        let identity = verify_user_certificate(&profile.sign(&ca), &trust(&ca), ISSUED).unwrap();
        let hex = |key: &PublicKey| -> String {
            key.fingerprint(HashAlg::Sha256)
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        };
        assert_eq!(identity.subject_fingerprint, hex(&subject));
        assert_ne!(identity.subject_fingerprint, hex(ca.public_key()));
        assert_eq!(identity.subject_fingerprint.len(), 64);
        assert!(
            identity
                .subject_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn a_jaunt_user_certificate_yields_the_identity() {
        let ca = key(Algorithm::Ed25519);
        let identity =
            verify_user_certificate(&Profile::jaunt().sign(&ca), &trust(&ca), ISSUED).unwrap();
        assert_eq!(identity.user_id, USER_ID);
        assert_eq!(identity.serial, 42);
        assert_eq!(identity.key_id, "jaunt:alice@example.com:42");
        assert_eq!(identity.email, "alice@example.com");
        assert_eq!(identity.valid_before, VALID_BEFORE);
    }

    #[test]
    fn the_validity_window_is_checked_at_the_given_instant() {
        let ca = key(Algorithm::Ed25519);
        let cert = Profile::jaunt().sign(&ca);
        let cas = trust(&ca);
        for (now, expected) in [
            (VALID_AFTER - 1, Err(CertRejection::NotYetValid)),
            (VALID_AFTER, Ok(())),
            (ISSUED - 119, Ok(())),
            (VALID_BEFORE - 1, Ok(())),
            (VALID_BEFORE, Err(CertRejection::Expired)),
        ] {
            let outcome = verify_user_certificate(&cert, &cas, now).map(|_| ());
            assert_eq!(outcome, expected, "now = {now}");
        }
    }

    #[test]
    fn each_profile_rule_has_its_own_rejection() {
        let ca = key(Algorithm::Ed25519);
        let cas = trust(&ca);
        let other_ca = key(Algorithm::Ed25519);
        let ecdsa = || {
            key(Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            })
        };
        let cases: Vec<(&str, Certificate, CertRejection)> = vec![
            (
                "wrong CA",
                Profile::jaunt().sign(&other_ca),
                CertRejection::UntrustedCa,
            ),
            (
                "host certificate",
                Profile {
                    cert_type: CertType::Host,
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::NotUserCertificate,
            ),
            (
                "ECDSA subject",
                Profile {
                    subject: ecdsa(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyAlgorithm,
            ),
            (
                "known critical option",
                Profile {
                    critical: vec![("source-address", "10.0.0.0/8")],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::CriticalOptions,
            ),
            (
                "unknown critical option",
                Profile {
                    critical: vec![("verify-required@example.com", "")],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::CriticalOptions,
            ),
            (
                "no principal means any principal",
                Profile {
                    principals: Vec::new(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "two principals",
                Profile {
                    principals: vec![USER_ID.to_owned(), "root".to_owned()],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "uppercase UUID",
                Profile {
                    principals: vec![USER_ID.to_uppercase()],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "login instead of a user id",
                Profile {
                    principals: vec!["deploy".to_owned()],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "nil UUID",
                Profile {
                    principals: vec!["00000000-0000-0000-0000-000000000000".to_owned()],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "digit where a hyphen belongs",
                Profile {
                    principals: vec![USER_ID.replacen('-', "0", 1)],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "non-hex letter in the UUID",
                Profile {
                    principals: vec![USER_ID.replacen('e', "g", 1)],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "UUID with trailing bytes",
                Profile {
                    principals: vec![format!("{USER_ID}0")],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "one uppercase hex digit",
                Profile {
                    principals: vec![USER_ID.replacen('e', "E", 1)],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "uppercase login",
                Profile {
                    principals: vec!["Deploy".to_owned()],
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::Principal,
            ),
            (
                "key id serial differs from the serial",
                Profile {
                    key_id: "jaunt:alice@example.com:43".to_owned(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyId,
            ),
            (
                "key id serial is not canonical",
                Profile {
                    key_id: "jaunt:alice@example.com:042".to_owned(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyId,
            ),
            (
                "key id without prefix",
                Profile {
                    key_id: "alice@example.com:42".to_owned(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyId,
            ),
            (
                "key id with an empty email",
                Profile {
                    key_id: "jaunt::42".to_owned(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyId,
            ),
            (
                "key id email with a colon",
                Profile {
                    key_id: "jaunt:a:b@example.com:42".to_owned(),
                    ..Profile::jaunt()
                }
                .sign(&ca),
                CertRejection::KeyId,
            ),
        ];
        for (name, cert, expected) in cases {
            assert_eq!(
                verify_user_certificate(&cert, &cas, ISSUED),
                Err(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn the_validity_window_is_capped_at_a_user_certificate_lifetime() {
        let ca = key(Algorithm::Ed25519);
        let cas = trust(&ca);
        for (valid_before, expected) in [
            (VALID_AFTER + 24 * 3600 + 2 * 60, Ok(())),
            (VALID_AFTER + 25 * 3600, Ok(())),
            (VALID_AFTER + 25 * 3600 + 1, Err(CertRejection::Window)),
            (VALID_AFTER + 25 * 3600 + 60, Err(CertRejection::Window)),
            (u64::MAX, Err(CertRejection::Window)),
        ] {
            let cert = Profile {
                valid_before,
                ..Profile::jaunt()
            }
            .sign(&ca);
            let outcome = verify_user_certificate(&cert, &cas, ISSUED).map(|_| ());
            assert_eq!(outcome, expected, "valid_before = {valid_before}");
        }
    }

    #[test]
    fn key_id_emails_follow_the_issuance_rule() {
        let longest = format!("{}@example.com", "a".repeat(254 - 12));
        let too_long = format!("{}@example.com", "a".repeat(255 - 12));
        assert_eq!((longest.len(), too_long.len()), (254, 255));
        for (email, ok) in [
            ("alice@example.com", true),
            ("a+b!#$%&'*/=?^_`{|}~@example.com", true),
            (longest.as_str(), true),
            (too_long.as_str(), false),
            ("", false),
            ("a\"b@example.com", false),
            ("a b@example.com", false),
            ("a:b@example.com", false),
            ("a\tb@example.com", false),
            ("a\u{7f}b@example.com", false),
            ("bj\u{f6}rn@example.com", false),
        ] {
            assert_eq!(is_key_id_email(email), ok, "{email:?}");
        }
    }

    #[test]
    fn a_tampered_certificate_from_a_trusted_ca_is_untrusted() {
        let ca = key(Algorithm::Ed25519);
        let bytes = Profile::jaunt().sign(&ca).to_bytes().unwrap();
        let needle = b"alice@example.com";
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        let mut tampered = bytes.clone();
        tampered[at] = b'm';
        let tampered = Certificate::from_bytes(&tampered).unwrap();
        assert_eq!(tampered.key_id(), "jaunt:mlice@example.com:42");
        assert_eq!(
            verify_user_certificate(&tampered, &trust(&ca), ISSUED),
            Err(CertRejection::UntrustedCa)
        );
    }

    #[test]
    fn extensions_are_left_to_policy() {
        let ca = key(Algorithm::Ed25519);
        let cert = Profile {
            extensions: vec![
                ("permit-agent-forwarding", ""),
                ("permit-X11-forwarding", ""),
                ("permit-user-rc", ""),
                ("unknown@example.com", "value"),
            ],
            ..Profile::jaunt()
        }
        .sign(&ca);
        assert!(verify_user_certificate(&cert, &trust(&ca), ISSUED).is_ok());
    }

    #[test]
    fn every_key_of_the_trust_set_is_honoured_and_replacement_takes_effect() {
        let (old, new) = (key(Algorithm::Ed25519), key(Algorithm::Ed25519));
        let lines = [&new, &old].map(|ca| ca.public_key().to_openssh().unwrap());
        let source = UserCaSource::new(UserCaKeys::from_openssh_lines(lines).unwrap());
        let by_old = Profile::jaunt().sign(&old);
        assert!(verify_user_certificate(&by_old, &source.current(), ISSUED).is_ok());
        source.replace(trust(&new));
        assert_eq!(
            verify_user_certificate(&by_old, &source.current(), ISSUED),
            Err(CertRejection::UntrustedCa)
        );
    }

    #[test]
    fn the_trust_set_accepts_only_distinct_ed25519_keys() {
        let ed = key(Algorithm::Ed25519).public_key().to_openssh().unwrap();
        let ecdsa = key(Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        })
        .public_key()
        .to_openssh()
        .unwrap();
        let commented = format!("{ed} another-comment\n");
        type Expectation = fn(&SshError) -> bool;
        let cases: Vec<(Vec<&str>, Expectation)> = vec![
            (Vec::new(), |e| matches!(e, SshError::EmptyTrustSet)),
            (vec!["ssh-ed25519 AAAA"], |e| {
                matches!(e, SshError::InvalidCaKey { index: 0, .. })
            }),
            (vec![""], |e| {
                matches!(e, SshError::InvalidCaKey { index: 0, .. })
            }),
            (vec![ed.as_str(), ecdsa.as_str()], |e| {
                matches!(e, SshError::CaKeyAlgorithm { index: 1 })
            }),
            (vec![ed.as_str(), commented.as_str()], |e| {
                matches!(e, SshError::DuplicateCaKey { index: 1 })
            }),
        ];
        for (lines, expected) in cases {
            let error = UserCaKeys::from_openssh_lines(&lines).unwrap_err();
            assert!(expected(&error), "{lines:?}: {error:?}");
        }
    }

    #[test]
    fn a_certificate_signed_by_ssh_keygen_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("user_ca");
        let user_path = dir.path().join("user");
        for path in [&ca_path, &user_path] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        }
        let status = Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(&ca_path)
            .args([
                "-I",
                "jaunt:alice@example.com:42",
                "-n",
                USER_ID,
                "-z",
                "42",
                "-V",
                "-2m:+8h",
                "-O",
                "clear",
                "-O",
                "permit-pty",
                "-O",
                "permit-port-forwarding",
            ])
            .arg(user_path.with_extension("pub"))
            .status()
            .unwrap();
        assert!(status.success());
        let cert = Certificate::read_file(&dir.path().join("user-cert.pub")).unwrap();
        let ca_line = std::fs::read_to_string(ca_path.with_extension("pub")).unwrap();
        let cas = UserCaKeys::from_openssh_lines([ca_line]).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let identity = verify_user_certificate(&cert, &cas, now).unwrap();
        assert_eq!(
            (
                identity.user_id.as_str(),
                identity.serial,
                identity.email.as_str()
            ),
            (USER_ID, 42, "alice@example.com")
        );
    }
}
