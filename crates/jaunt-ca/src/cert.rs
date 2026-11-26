use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, Certificate, HashAlg, PublicKey};
use uuid::Uuid;

use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::{Signer, SignerAdapter};

pub const DEFAULT_USER_VALIDITY: Duration = Duration::from_secs(8 * 60 * 60);
pub const MAX_USER_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
pub const DEFAULT_HOST_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_HOST_VALIDITY: Duration = Duration::from_secs(30 * 24 * 60 * 60);
pub const BACKDATE: Duration = Duration::from_secs(2 * 60);
pub const ORIGIN_EXTENSION: &str = "jaunt-origin@globalart.dev";
pub const WEB_ORIGIN: &str = "web";

const MIN_VALIDITY: Duration = Duration::from_secs(1);
const MAX_EMAIL_LEN: usize = 254;
const MAX_HOSTNAME_LEN: usize = 253;
const MAX_HOSTNAMES: usize = 64;
const FORBIDDEN_HOSTNAME_CHARS: [char; 4] = ['*', '?', '!', ','];

#[derive(Clone, Debug)]
pub struct UserCertParams {
    pub subject_public_key: PublicKey,
    pub user_id: Uuid,
    pub email: String,
    pub serial: u64,
    pub validity: Duration,
}

#[derive(Clone, Debug)]
pub struct HostCertParams {
    pub subject_public_key: PublicKey,
    pub hostnames: Vec<String>,
    pub serial: u64,
    pub validity: Duration,
}

pub(crate) struct Window {
    pub(crate) valid_after: u64,
    pub(crate) valid_before: u64,
}

pub fn sign_user_certificate(
    signer: &dyn Signer,
    params: UserCertParams,
    now: SystemTime,
) -> Result<Certificate, CaError> {
    sign_user(signer, params, now, None)
}

pub fn sign_web_user_certificate(
    signer: &dyn Signer,
    params: UserCertParams,
    now: SystemTime,
) -> Result<Certificate, CaError> {
    sign_user(signer, params, now, Some(WEB_ORIGIN))
}

fn sign_user(
    signer: &dyn Signer,
    params: UserCertParams,
    now: SystemTime,
    origin: Option<&str>,
) -> Result<Certificate, CaError> {
    require_kind(signer, CaKind::User)?;
    require_ed25519(signer)?;
    validate_email(&params.email)?;
    if params.user_id.is_nil() {
        return Err(CaError::InvalidUserId);
    }
    let window = window(now, params.validity, MAX_USER_VALIDITY)?;

    let mut builder = new_builder(&params.subject_public_key, &window)?;
    builder.serial(params.serial).map_err(CaError::SshKey)?;
    builder.cert_type(CertType::User).map_err(CaError::SshKey)?;
    builder
        .key_id(format!("jaunt:{}:{}", params.email, params.serial))
        .map_err(CaError::SshKey)?;
    builder
        .valid_principal(params.user_id.to_string())
        .map_err(CaError::SshKey)?;
    builder
        .extension("permit-pty", "")
        .map_err(CaError::SshKey)?;
    builder
        .extension("permit-port-forwarding", "")
        .map_err(CaError::SshKey)?;
    if let Some(origin) = origin {
        builder
            .extension(ORIGIN_EXTENSION, origin)
            .map_err(CaError::SshKey)?;
    }

    finish(builder, signer, &window)
}

pub fn sign_host_certificate(
    signer: &dyn Signer,
    params: HostCertParams,
    now: SystemTime,
) -> Result<Certificate, CaError> {
    require_kind(signer, CaKind::Host)?;
    require_ed25519(signer)?;
    validate_hostnames(&params.hostnames)?;
    let window = window(now, params.validity, MAX_HOST_VALIDITY)?;

    let mut builder = new_builder(&params.subject_public_key, &window)?;
    builder.serial(params.serial).map_err(CaError::SshKey)?;
    builder.cert_type(CertType::Host).map_err(CaError::SshKey)?;
    builder
        .key_id(format!(
            "jaunt-host:{}:{}",
            params.hostnames[0], params.serial
        ))
        .map_err(CaError::SshKey)?;
    for hostname in &params.hostnames {
        builder
            .valid_principal(hostname.as_str())
            .map_err(CaError::SshKey)?;
    }

    finish(builder, signer, &window)
}

fn require_kind(signer: &dyn Signer, expected: CaKind) -> Result<(), CaError> {
    if signer.kind() == expected {
        Ok(())
    } else {
        Err(CaError::WrongAuthorityKind { expected })
    }
}

fn require_ed25519(signer: &dyn Signer) -> Result<(), CaError> {
    if signer.public_key().algorithm() == Algorithm::Ed25519 {
        Ok(())
    } else {
        Err(CaError::UnsupportedKeyAlgorithm)
    }
}

pub(crate) fn validate_email(email: &str) -> Result<(), CaError> {
    let acceptable = !email.is_empty()
        && email.len() <= MAX_EMAIL_LEN
        && email
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b':' && byte != b'"');
    if acceptable {
        Ok(())
    } else {
        Err(CaError::InvalidEmail)
    }
}

fn validate_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOSTNAME_LEN
        && !name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || FORBIDDEN_HOSTNAME_CHARS.contains(&c))
}

pub(crate) fn validate_hostnames(hostnames: &[String]) -> Result<(), CaError> {
    let distinct: HashSet<&str> = hostnames.iter().map(String::as_str).collect();
    let acceptable = !hostnames.is_empty()
        && hostnames.len() <= MAX_HOSTNAMES
        && distinct.len() == hostnames.len()
        && hostnames.iter().all(|name| validate_hostname(name));
    if acceptable {
        Ok(())
    } else {
        Err(CaError::InvalidHostnames)
    }
}

pub(crate) fn window(
    now: SystemTime,
    validity: Duration,
    max: Duration,
) -> Result<Window, CaError> {
    window_backdated(now, validity, max, BACKDATE)
}

pub(crate) fn window_backdated(
    now: SystemTime,
    validity: Duration,
    max: Duration,
    backdate: Duration,
) -> Result<Window, CaError> {
    if !(MIN_VALIDITY..=max).contains(&validity) {
        return Err(CaError::InvalidValidity { max });
    }
    let now_secs = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CaError::InvalidTime)?
        .as_secs();
    let valid_after = now_secs
        .checked_sub(backdate.as_secs())
        .ok_or(CaError::InvalidTime)?;
    let valid_before = now_secs
        .checked_add(validity.as_secs())
        .ok_or(CaError::InvalidTime)?;
    Ok(Window {
        valid_after,
        valid_before,
    })
}

fn new_builder(subject: &PublicKey, window: &Window) -> Result<Builder, CaError> {
    Builder::new_with_random_nonce(
        &mut OsRng,
        subject.key_data().clone(),
        window.valid_after,
        window.valid_before,
    )
    .map_err(CaError::SshKey)
}

fn finish(builder: Builder, signer: &dyn Signer, window: &Window) -> Result<Certificate, CaError> {
    let adapter = SignerAdapter::new(signer);
    let certificate = match builder.sign(&adapter) {
        Ok(certificate) => certificate,
        Err(err) => return Err(adapter.take_failure().unwrap_or(CaError::SshKey(err))),
    };
    let ca_fingerprint = signer.public_key().fingerprint(HashAlg::Sha256);
    certificate
        .validate_at(window.valid_after, [&ca_fingerprint])
        .map_err(CaError::SshKey)?;
    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ssh_key::certificate::CertType;
    use ssh_key::public::{KeyData, SkEd25519};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
    use uuid::Uuid;

    use super::{
        DEFAULT_HOST_VALIDITY, DEFAULT_USER_VALIDITY, HostCertParams, MAX_HOST_VALIDITY,
        MAX_USER_VALIDITY, ORIGIN_EXTENSION, UserCertParams, WEB_ORIGIN, sign_host_certificate,
        sign_user_certificate, sign_web_user_certificate,
    };
    use crate::error::CaError;
    use crate::kind::CaKind;
    use crate::signer::Signer;
    use crate::test_support::{authority, subject_key};

    const NOW_SECS: u64 = 1_700_000_000;
    const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
    const WEB_VALIDITY: Duration = Duration::from_secs(120);

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    fn user_params(validity: Duration) -> UserCertParams {
        UserCertParams {
            subject_public_key: subject_key(),
            user_id: Uuid::parse_str(USER_ID).unwrap(),
            email: "alice@example.com".to_owned(),
            serial: 42,
            validity,
        }
    }

    fn host_params(hostnames: &[&str], validity: Duration) -> HostCertParams {
        HostCertParams {
            subject_public_key: subject_key(),
            hostnames: hostnames.iter().map(|name| (*name).to_owned()).collect(),
            serial: 7,
            validity,
        }
    }

    fn keygen_listing(cert: &ssh_key::Certificate) -> Vec<String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user-cert.pub");
        std::fs::write(&path, cert.to_openssh().unwrap()).unwrap();
        let output = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&path)
            .env("TZ", "UTC")
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn indent(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    #[test]
    fn user_certificate_is_understood_by_ssh_keygen() {
        let authority = authority(CaKind::User);
        let cert = sign_user_certificate(
            &authority.backend,
            user_params(DEFAULT_USER_VALIDITY),
            now(),
        )
        .unwrap();
        let lines = keygen_listing(&cert);
        let has = |expected: &str| lines.iter().any(|line| line.trim() == expected);
        assert!(lines.iter().any(|line| line.ends_with("user certificate")));
        assert!(has("Key ID: \"jaunt:alice@example.com:42\""));
        assert!(has("Serial: 42"));
        assert!(has(
            "Valid: from 2023-11-14T22:11:20 to 2023-11-15T06:13:20"
        ));
        assert!(has("Critical Options: (none)"));
        let after = |header: &str| -> Vec<&str> {
            let start = lines.iter().position(|line| line.trim() == header).unwrap();
            let depth = indent(&lines[start]);
            lines[start + 1..]
                .iter()
                .take_while(|line| indent(line) > depth)
                .map(|line| line.trim())
                .collect()
        };
        assert_eq!(after("Principals:"), [USER_ID]);
        assert_eq!(
            after("Extensions:"),
            ["permit-port-forwarding", "permit-pty"]
        );
    }

    #[test]
    fn user_certificate_has_exact_profile_fields() {
        let authority = authority(CaKind::User);
        let cert = sign_user_certificate(
            &authority.backend,
            user_params(DEFAULT_USER_VALIDITY),
            now(),
        )
        .unwrap();
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.valid_principals(), [USER_ID]);
        assert_eq!(cert.key_id(), "jaunt:alice@example.com:42");
        assert_eq!(cert.valid_after(), NOW_SECS - 120);
        assert_eq!(cert.valid_before(), NOW_SECS + 8 * 3600);
        assert!(cert.critical_options().is_empty());
        let extensions: Vec<(&str, &str)> = cert
            .extensions()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            extensions,
            [("permit-port-forwarding", ""), ("permit-pty", "")]
        );
    }

    #[test]
    fn a_web_certificate_is_the_cli_profile_plus_one_origin_extension() {
        let authority = authority(CaKind::User);
        let cli =
            sign_user_certificate(&authority.backend, user_params(WEB_VALIDITY), now()).unwrap();
        let web = sign_web_user_certificate(&authority.backend, user_params(WEB_VALIDITY), now())
            .unwrap();
        assert_eq!(web.cert_type(), cli.cert_type());
        assert_eq!(web.valid_principals(), cli.valid_principals());
        assert_eq!(web.key_id(), cli.key_id());
        assert_eq!(web.serial(), cli.serial());
        assert_eq!(web.valid_after(), NOW_SECS - 120);
        assert_eq!(web.valid_before(), NOW_SECS + 120);
        assert!(web.critical_options().is_empty());
        let extensions = |cert: &ssh_key::Certificate| -> Vec<(String, String)> {
            cert.extensions()
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect()
        };
        let mut expected = extensions(&cli);
        assert!(!expected.iter().any(|(name, _)| name == ORIGIN_EXTENSION));
        expected.insert(0, (ORIGIN_EXTENSION.to_owned(), WEB_ORIGIN.to_owned()));
        assert_eq!(extensions(&web), expected);
        assert_eq!(ORIGIN_EXTENSION, "jaunt-origin@globalart.dev");
        assert_eq!(WEB_ORIGIN, "web");
    }

    #[test]
    fn ssh_keygen_shows_the_web_origin_of_a_web_certificate() {
        let authority = authority(CaKind::User);
        let web = sign_web_user_certificate(&authority.backend, user_params(WEB_VALIDITY), now())
            .unwrap();
        let cli =
            sign_user_certificate(&authority.backend, user_params(WEB_VALIDITY), now()).unwrap();
        let mentions_origin =
            |lines: &[String]| lines.iter().any(|line| line.contains(ORIGIN_EXTENSION));
        assert!(mentions_origin(&keygen_listing(&web)));
        assert!(!mentions_origin(&keygen_listing(&cli)));
    }

    #[test]
    fn validate_at_checks_authority_and_time_window() {
        let user_ca = authority(CaKind::User);
        let other_ca = authority(CaKind::User);
        let cert =
            sign_user_certificate(&user_ca.backend, user_params(DEFAULT_USER_VALIDITY), now())
                .unwrap();
        let trusted = user_ca.trust.active().fingerprint(HashAlg::Sha256);
        let stranger = other_ca.trust.active().fingerprint(HashAlg::Sha256);
        let (after, before) = (cert.valid_after(), cert.valid_before());

        assert!(cert.validate_at(NOW_SECS, [&trusted]).is_ok());
        assert!(cert.validate_at(after, [&trusted]).is_ok());
        assert!(cert.validate_at(before - 1, [&trusted]).is_ok());
        assert!(cert.validate_at(NOW_SECS, [&stranger]).is_err());
        assert!(cert.validate_at(after - 1, [&trusted]).is_err());
        assert!(cert.validate_at(before, [&trusted]).is_err());
    }

    #[test]
    fn user_validity_bounds_are_enforced() {
        let authority = authority(CaKind::User);
        let sign =
            |validity| sign_user_certificate(&authority.backend, user_params(validity), now());
        assert!(matches!(
            sign(Duration::ZERO),
            Err(CaError::InvalidValidity { .. })
        ));
        assert!(matches!(
            sign(Duration::from_millis(500)),
            Err(CaError::InvalidValidity { .. })
        ));
        assert!(matches!(
            sign(Duration::from_secs(24 * 3600) + Duration::from_nanos(1)),
            Err(CaError::InvalidValidity { .. })
        ));
        assert!(sign(Duration::from_secs(1)).is_ok());
        let cert = sign(Duration::from_secs(24 * 3600)).unwrap();
        assert_eq!(cert.valid_before() - NOW_SECS, 24 * 3600);
        assert_eq!(MAX_USER_VALIDITY, Duration::from_secs(24 * 3600));
        assert_eq!(DEFAULT_USER_VALIDITY, Duration::from_secs(8 * 3600));
    }

    #[test]
    fn user_id_must_not_be_nil() {
        let authority = authority(CaKind::User);
        let mut params = user_params(DEFAULT_USER_VALIDITY);
        params.user_id = Uuid::nil();
        assert!(matches!(
            sign_user_certificate(&authority.backend, params, now()),
            Err(CaError::InvalidUserId)
        ));
    }

    #[test]
    fn email_must_be_safe_for_a_key_id() {
        let authority = authority(CaKind::User);
        let sign = |email: &str| {
            let mut params = user_params(DEFAULT_USER_VALIDITY);
            params.email = email.to_owned();
            sign_user_certificate(&authority.backend, params, now())
        };
        let longest = format!("{}@example.com", "a".repeat(242));
        let too_long = format!("{}@example.com", "a".repeat(243));
        for bad in [
            "",
            "a:b@example.com",
            "a\nb@example.com",
            "a\0b@example.com",
            "a b@example.com",
            "a\tb@example.com",
            "a\u{7f}b@example.com",
            "a\u{202e}b@example.com",
            "a\u{200b}b@example.com",
            "a\"b@example.com",
            "\u{e9}lise@example.com",
            too_long.as_str(),
        ] {
            assert!(matches!(sign(bad), Err(CaError::InvalidEmail)), "{bad:?}");
        }
        assert!(sign("alice+ssh@example.com").is_ok());
        assert!(sign(&longest).is_ok());
    }

    #[test]
    fn host_certificate_has_exact_profile_fields() {
        let authority = authority(CaKind::Host);
        let params = host_params(&["web1.example.com", "10.0.0.5"], DEFAULT_HOST_VALIDITY);
        let cert = sign_host_certificate(&authority.backend, params, now()).unwrap();
        assert_eq!(cert.cert_type(), CertType::Host);
        assert_eq!(cert.valid_principals(), ["web1.example.com", "10.0.0.5"]);
        assert_eq!(cert.key_id(), "jaunt-host:web1.example.com:7");
        assert_eq!(cert.valid_after(), NOW_SECS - 120);
        assert_eq!(cert.valid_before(), NOW_SECS + 7 * 24 * 3600);
        assert!(cert.critical_options().is_empty());
        assert!(cert.extensions().is_empty());
        let trusted = authority.trust.active().fingerprint(HashAlg::Sha256);
        assert!(cert.validate_at(NOW_SECS, [&trusted]).is_ok());
    }

    #[test]
    fn host_names_and_validity_are_validated() {
        let authority = authority(CaKind::Host);
        let sign = |names: &[&str], validity| {
            sign_host_certificate(&authority.backend, host_params(names, validity), now())
        };
        assert!(matches!(
            sign(&[], DEFAULT_HOST_VALIDITY),
            Err(CaError::InvalidHostnames)
        ));
        for bad in [
            "",
            "web 1",
            "web\t1",
            "web\n1",
            "web\u{7f}1",
            "web\u{1b}1",
            "web\u{85}1",
            "web\u{a0}1",
        ] {
            assert!(
                matches!(
                    sign(&["ok.example.com", bad], DEFAULT_HOST_VALIDITY),
                    Err(CaError::InvalidHostnames)
                ),
                "{bad:?}"
            );
        }
        for pattern in ["*", "*.example.com", "web?", "!web1", "web1,web2", "a*b"] {
            assert!(
                matches!(
                    sign(&["ok.example.com", pattern], DEFAULT_HOST_VALIDITY),
                    Err(CaError::InvalidHostnames)
                ),
                "{pattern:?}"
            );
        }
        assert!(
            sign(
                &["web-1.example.com", "10.0.0.5", "fd00::1"],
                DEFAULT_HOST_VALIDITY
            )
            .is_ok()
        );
        assert!(matches!(
            sign(&["web1"], Duration::ZERO),
            Err(CaError::InvalidValidity { .. })
        ));
        let thirty_days = Duration::from_secs(30 * 24 * 3600);
        assert!(matches!(
            sign(&["web1"], thirty_days + Duration::from_secs(1)),
            Err(CaError::InvalidValidity { .. })
        ));
        let cert = sign(&["web1"], thirty_days).unwrap();
        assert_eq!(cert.valid_before() - NOW_SECS, 30 * 24 * 3600);
        assert_eq!(MAX_HOST_VALIDITY, thirty_days);
        assert_eq!(DEFAULT_HOST_VALIDITY, Duration::from_secs(7 * 24 * 3600));
    }

    #[test]
    fn host_name_count_length_and_duplicates_are_limited() {
        let authority = authority(CaKind::Host);
        let sign = |names: Vec<String>| {
            let mut params = host_params(&[], DEFAULT_HOST_VALIDITY);
            params.hostnames = names;
            sign_host_certificate(&authority.backend, params, now())
        };
        let numbered = |count: usize| -> Vec<String> {
            (0..count).map(|index| format!("web{index}")).collect()
        };
        assert!(sign(numbered(64)).is_ok());
        assert!(matches!(sign(numbered(65)), Err(CaError::InvalidHostnames)));
        assert!(sign(vec!["a".repeat(253)]).is_ok());
        assert!(matches!(
            sign(vec!["a".repeat(254)]),
            Err(CaError::InvalidHostnames)
        ));
        assert!(matches!(
            sign(vec![
                "web1".to_owned(),
                "web2".to_owned(),
                "web1".to_owned()
            ]),
            Err(CaError::InvalidHostnames)
        ));
    }

    struct FailingSigner(PublicKey, CaKind);

    impl Signer for FailingSigner {
        fn kind(&self) -> CaKind {
            self.1
        }

        fn public_key(&self) -> &PublicKey {
            &self.0
        }

        fn try_sign(&self, _msg: &[u8]) -> Result<Signature, CaError> {
            Err(CaError::Sign)
        }
    }

    struct ImpostorSigner {
        claimed: PublicKey,
        actual: PrivateKey,
    }

    impl Signer for ImpostorSigner {
        fn kind(&self) -> CaKind {
            CaKind::User
        }

        fn public_key(&self) -> &PublicKey {
            &self.claimed
        }

        fn try_sign(&self, msg: &[u8]) -> Result<Signature, CaError> {
            signature::Signer::try_sign(&self.actual, msg).map_err(|_| CaError::Sign)
        }
    }

    #[test]
    fn signer_failures_and_forged_signatures_are_rejected() {
        let failing = FailingSigner(subject_key(), CaKind::User);
        assert!(matches!(
            sign_user_certificate(&failing, user_params(DEFAULT_USER_VALIDITY), now()),
            Err(CaError::Sign)
        ));

        let impostor = ImpostorSigner {
            claimed: subject_key(),
            actual: PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
        };
        assert!(matches!(
            sign_user_certificate(&impostor, user_params(DEFAULT_USER_VALIDITY), now()),
            Err(CaError::SshKey(_))
        ));
    }

    #[test]
    fn signer_must_use_an_ed25519_key() {
        let ed25519 = *subject_key().key_data().ed25519().unwrap();
        let security_key = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")));
        assert!(matches!(
            sign_user_certificate(
                &FailingSigner(security_key.clone(), CaKind::User),
                user_params(DEFAULT_USER_VALIDITY),
                now()
            ),
            Err(CaError::UnsupportedKeyAlgorithm)
        ));
        assert!(matches!(
            sign_host_certificate(
                &FailingSigner(security_key, CaKind::Host),
                host_params(&["web1"], DEFAULT_HOST_VALIDITY),
                now()
            ),
            Err(CaError::UnsupportedKeyAlgorithm)
        ));
    }

    #[test]
    fn certificates_require_the_matching_authority_kind() {
        let user_ca = authority(CaKind::User);
        let host_ca = authority(CaKind::Host);
        assert!(matches!(
            sign_user_certificate(&host_ca.backend, user_params(DEFAULT_USER_VALIDITY), now()),
            Err(CaError::WrongAuthorityKind {
                expected: CaKind::User
            })
        ));
        assert!(matches!(
            sign_host_certificate(
                &user_ca.backend,
                host_params(&["web1"], DEFAULT_HOST_VALIDITY),
                now()
            ),
            Err(CaError::WrongAuthorityKind {
                expected: CaKind::Host
            })
        ));
    }
}
