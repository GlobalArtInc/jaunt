use std::fmt;

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey};

use crate::cert::is_key_id_email;
use crate::error::SshError;

const BACKDATE_SECS: u64 = 5;
const VALIDITY_SECS: u64 = 60;
const SOURCE_ADDRESS: &str = "127.0.0.1/32,::1/128";
const MAX_LOGIN_LEN: usize = 32;

pub struct InnerCa {
    key: PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InnerCertRequest {
    pub(crate) login: String,
    pub(crate) session_id: String,
    pub(crate) email: String,
    pub(crate) pty: bool,
    pub(crate) port_forwarding: bool,
}

impl InnerCa {
    pub fn generate() -> Result<Self, SshError> {
        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
            .map_err(SshError::KeyGeneration)?;
        Ok(Self { key })
    }

    pub fn public_openssh(&self) -> Result<String, SshError> {
        self.key
            .public_key()
            .to_openssh()
            .map_err(SshError::KeyEncoding)
    }

    pub(crate) fn issue(
        &self,
        request: &InnerCertRequest,
        now_unix: u64,
    ) -> Result<(PrivateKey, Certificate), SshError> {
        if !is_portable_login(&request.login) {
            return Err(SshError::InvalidLogin);
        }
        if !is_key_id_email(&request.session_id) || !is_key_id_email(&request.email) {
            return Err(SshError::InvalidKeyIdPart);
        }
        let valid_after = now_unix
            .checked_sub(BACKDATE_SECS)
            .ok_or(SshError::InvalidTime)?;
        let valid_before = now_unix
            .checked_add(VALIDITY_SECS)
            .ok_or(SshError::InvalidTime)?;
        let subject = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519)
            .map_err(SshError::KeyGeneration)?;
        let mut builder = Builder::new_with_random_nonce(
            &mut safe_rng(),
            subject.public_key().key_data().clone(),
            valid_after,
            valid_before,
        )
        .map_err(SshError::CertificateSigning)?;
        builder
            .serial(0)
            .and_then(|b| b.cert_type(CertType::User))
            .and_then(|b| b.key_id(format!("jaunt:{}:{}", request.session_id, request.email)))
            .and_then(|b| b.valid_principal(request.login.as_str()))
            .and_then(|b| b.critical_option("source-address", SOURCE_ADDRESS))
            .map_err(SshError::CertificateSigning)?;
        if request.pty {
            builder
                .extension("permit-pty", "")
                .map_err(SshError::CertificateSigning)?;
        }
        if request.port_forwarding {
            builder
                .extension("permit-port-forwarding", "")
                .map_err(SshError::CertificateSigning)?;
        }
        let certificate = builder
            .sign(&self.key)
            .map_err(SshError::CertificateSigning)?;
        Ok((subject, certificate))
    }
}

impl fmt::Debug for InnerCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerCa")
            .field("public_key", &self.key.fingerprint(HashAlg::Sha256))
            .field("private_key", &"<redacted>")
            .finish()
    }
}

pub(crate) fn is_portable_login(login: &str) -> bool {
    let bytes = login.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= MAX_LOGIN_LEN
        && (first.is_ascii_lowercase() || *first == b'_')
        && rest.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use russh::keys::ssh_key::certificate::CertType;
    use russh::keys::{Algorithm, HashAlg, PublicKey};

    use super::{InnerCa, InnerCertRequest};
    use crate::error::SshError;
    use crate::test_support::NOW;

    fn request(pty: bool, port_forwarding: bool) -> InnerCertRequest {
        InnerCertRequest {
            login: "deploy".to_owned(),
            session_id: "4f1c2a8e-5d3b-4c6a-9e7f-0a1b2c3d4e5f".to_owned(),
            email: "alice@example.com".to_owned(),
            pty,
            port_forwarding,
        }
    }

    #[test]
    fn the_inner_certificate_has_the_short_loopback_profile() {
        let ca = InnerCa::generate().unwrap();
        let ca_public = PublicKey::from_openssh(&ca.public_openssh().unwrap()).unwrap();
        let (subject, cert) = ca.issue(&request(true, true), NOW).unwrap();
        assert_eq!(cert.public_key(), subject.public_key().key_data());
        assert_eq!(subject.algorithm(), Algorithm::Ed25519);
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.serial(), 0);
        assert_eq!(
            cert.key_id(),
            "jaunt:4f1c2a8e-5d3b-4c6a-9e7f-0a1b2c3d4e5f:alice@example.com"
        );
        assert_eq!(cert.valid_principals(), ["deploy"]);
        assert_eq!(
            (cert.valid_after(), cert.valid_before()),
            (NOW - 5, NOW + 60)
        );
        let critical: Vec<(&str, &str)> = cert
            .critical_options()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(critical, [("source-address", "127.0.0.1/32,::1/128")]);
        let fingerprint = ca_public.fingerprint(HashAlg::Sha256);
        cert.validate_at(NOW, [&fingerprint]).unwrap();
        assert!(cert.validate_at(NOW + 60, [&fingerprint]).is_err());
    }

    #[test]
    fn extensions_follow_the_permissions() {
        let ca = InnerCa::generate().unwrap();
        for (pty, forwarding, expected) in [
            (false, false, Vec::<&str>::new()),
            (true, false, vec!["permit-pty"]),
            (false, true, vec!["permit-port-forwarding"]),
            (true, true, vec!["permit-port-forwarding", "permit-pty"]),
        ] {
            let (_, cert) = ca.issue(&request(pty, forwarding), NOW).unwrap();
            let names: Vec<&str> = cert.extensions().keys().map(String::as_str).collect();
            assert_eq!(names, expected, "pty={pty} forwarding={forwarding}");
        }
    }

    #[test]
    fn each_session_gets_a_fresh_subject_key() {
        let ca = InnerCa::generate().unwrap();
        let (first, _) = ca.issue(&request(false, false), NOW).unwrap();
        let (second, _) = ca.issue(&request(false, false), NOW).unwrap();
        assert_ne!(first.public_key(), second.public_key());
    }

    #[test]
    fn requests_that_cannot_be_certified_are_refused() {
        let ca = InnerCa::generate().unwrap();
        let long = "a".repeat(33);
        let longest = "a".repeat(32);
        for (login, ok) in [
            ("deploy", true),
            ("_svc", true),
            ("web.ops-1_x", true),
            (longest.as_str(), true),
            (long.as_str(), false),
            ("", false),
            ("Deploy", false),
            ("1deploy", false),
            ("-deploy", false),
            ("root,deploy", false),
            ("de ploy", false),
            ("dé", false),
        ] {
            let outcome = ca.issue(
                &InnerCertRequest {
                    login: login.to_owned(),
                    ..request(false, false)
                },
                NOW,
            );
            match ok {
                true => assert!(outcome.is_ok(), "{login:?}"),
                false => assert!(matches!(outcome, Err(SshError::InvalidLogin)), "{login:?}"),
            }
        }
        for (session_id, email) in [
            ("", "alice@example.com"),
            ("s:1", "alice@example.com"),
            ("s1", "a\nb"),
        ] {
            let outcome = ca.issue(
                &InnerCertRequest {
                    session_id: session_id.to_owned(),
                    email: email.to_owned(),
                    ..request(false, false)
                },
                NOW,
            );
            assert!(
                matches!(outcome, Err(SshError::InvalidKeyIdPart)),
                "{session_id:?} {email:?}"
            );
        }
        assert!(matches!(
            ca.issue(&request(false, false), 4),
            Err(SshError::InvalidTime)
        ));
    }

    #[test]
    fn debug_output_hides_the_private_key() {
        let ca = InnerCa::generate().unwrap();
        let fingerprint = ca.key.fingerprint(HashAlg::Sha256);
        assert_eq!(
            format!("{ca:?}"),
            format!("InnerCa {{ public_key: {fingerprint:?}, private_key: \"<redacted>\" }}")
        );
    }

    #[test]
    fn ssh_keygen_reads_the_inner_certificate() {
        let ca = InnerCa::generate().unwrap();
        let (_, cert) = ca.issue(&request(true, false), NOW).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inner-cert.pub");
        std::fs::write(&path, cert.to_openssh().unwrap()).unwrap();
        let output = Command::new("ssh-keygen")
            .args(["-L", "-f"])
            .arg(&path)
            .env("TZ", "UTC")
            .output()
            .unwrap();
        assert!(output.status.success());
        let listing = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = listing.lines().map(str::trim).collect();
        let has = |expected: &str| lines.contains(&expected);
        assert!(
            lines.iter().any(|line| line.ends_with("user certificate")),
            "{listing}"
        );
        assert!(
            has("Key ID: \"jaunt:4f1c2a8e-5d3b-4c6a-9e7f-0a1b2c3d4e5f:alice@example.com\""),
            "{listing}"
        );
        assert!(has("Serial: 0"), "{listing}");
        assert!(
            has("Valid: from 2023-11-14T22:13:15 to 2023-11-14T22:14:20"),
            "{listing}"
        );
        assert!(has("deploy"), "{listing}");
        assert!(has("source-address 127.0.0.1/32,::1/128"), "{listing}");
        assert!(has("permit-pty"), "{listing}");
        assert!(!has("permit-port-forwarding"), "{listing}");
        let signer = format!(
            "Signing CA: ED25519 {}",
            ca.key.fingerprint(HashAlg::Sha256)
        );
        assert!(
            lines.iter().any(|line| line.starts_with(&signer)),
            "{listing}"
        );
    }
}
