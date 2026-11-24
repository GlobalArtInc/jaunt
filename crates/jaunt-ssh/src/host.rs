use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::error::{HostCertProblem, SshError};

const MAX_FILE_LEN: usize = 64 * 1024;
const MAX_FILE_LEN_U64: u64 = 64 * 1024;
#[cfg(unix)]
const GROUP_OR_OTHER_ACCESS: u32 = 0o077;

pub struct HostKey {
    key: PrivateKey,
}

impl HostKey {
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

    pub fn with_certificate(
        self,
        certificate: &str,
        now_unix: u64,
    ) -> Result<HostIdentity, SshError> {
        let certificate = Certificate::from_openssh(certificate.trim())
            .map_err(|_| SshError::HostCertificate(HostCertProblem::Malformed))?;
        check_host_certificate(&self.key, &certificate, now_unix)?;
        Ok(HostIdentity {
            key: self.key,
            certificate,
        })
    }

    fn from_private(key: PrivateKey) -> Result<Self, SshError> {
        if key.is_encrypted() {
            return Err(SshError::InvalidHostKey);
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(SshError::HostKeyAlgorithm);
        }
        Ok(Self { key })
    }
}

impl fmt::Debug for HostKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostKey")
            .field("public_key", &self.key.fingerprint(HashAlg::Sha256))
            .field("private_key", &"<redacted>")
            .finish()
    }
}

pub struct HostIdentity {
    key: PrivateKey,
    certificate: Certificate,
}

impl HostIdentity {
    pub fn load(key_path: &Path, cert_path: &Path, now_unix: u64) -> Result<Self, SshError> {
        let key_bytes = read_limited(key_path, Access::OwnerOnly)?;
        let cert_bytes = read_limited(cert_path, Access::Any)?;
        Self::from_openssh(&key_bytes, &cert_bytes, now_unix)
    }

    pub fn from_openssh(
        private_key: &[u8],
        certificate: &[u8],
        now_unix: u64,
    ) -> Result<Self, SshError> {
        let key = PrivateKey::from_openssh(private_key).map_err(|_| SshError::InvalidHostKey)?;
        let certificate = std::str::from_utf8(certificate)
            .map_err(|_| SshError::HostCertificate(HostCertProblem::Malformed))?;
        HostKey::from_private(key)?.with_certificate(certificate, now_unix)
    }

    pub fn valid_after(&self) -> u64 {
        self.certificate.valid_after()
    }

    pub fn valid_before(&self) -> u64 {
        self.certificate.valid_before()
    }

    pub(crate) fn into_parts(self) -> (PrivateKey, Certificate) {
        (self.key, self.certificate)
    }
}

impl fmt::Debug for HostIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostIdentity")
            .field("public_key", &self.key.fingerprint(HashAlg::Sha256))
            .field("key_id", &self.certificate.key_id())
            .field("valid_before", &self.certificate.valid_before())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

pub fn read_pinned_host_key(path: &Path) -> Result<KeyData, SshError> {
    let bytes = read_limited(path, Access::Any)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SshError::PinnedHostKey)?;
    let key = PublicKey::from_openssh(text.trim()).map_err(|_| SshError::PinnedHostKey)?;
    if key.algorithm() != Algorithm::Ed25519 {
        return Err(SshError::PinnedHostKey);
    }
    Ok(key.key_data().clone())
}

#[derive(Clone, Copy)]
pub(crate) enum Access {
    OwnerOnly,
    Any,
}

pub(crate) fn read_limited(path: &Path, access: Access) -> Result<Zeroizing<Vec<u8>>, SshError> {
    let io_error = |source: std::io::Error| SshError::ReadFile {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io_error)?;
    if let Access::OwnerOnly = access {
        check_owner_only(path, &file.metadata().map_err(io_error)?)?;
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_FILE_LEN + 1));
    file.take(MAX_FILE_LEN_U64 + 1)
        .read_to_end(&mut buffer)
        .map_err(io_error)?;
    if buffer.len() > MAX_FILE_LEN {
        return Err(SshError::FileTooLarge {
            path: path.to_path_buf(),
            limit: MAX_FILE_LEN,
        });
    }
    Ok(buffer)
}

#[cfg(unix)]
fn check_owner_only(path: &Path, metadata: &std::fs::Metadata) -> Result<(), SshError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & GROUP_OR_OTHER_ACCESS != 0 {
        return Err(SshError::KeyFilePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_only(_path: &Path, _metadata: &std::fs::Metadata) -> Result<(), SshError> {
    Ok(())
}

fn check_host_certificate(
    key: &PrivateKey,
    certificate: &Certificate,
    now_unix: u64,
) -> Result<(), SshError> {
    let problem = if certificate.cert_type() != CertType::Host {
        Some(HostCertProblem::NotHostCertificate)
    } else if certificate.public_key() != key.public_key().key_data() {
        Some(HostCertProblem::KeyMismatch)
    } else if certificate.verify_signature().is_err() {
        Some(HostCertProblem::Signature)
    } else if now_unix < certificate.valid_after() {
        Some(HostCertProblem::NotYetValid)
    } else if now_unix >= certificate.valid_before() {
        Some(HostCertProblem::Expired)
    } else {
        None
    };
    match problem {
        Some(problem) => Err(SshError::HostCertificate(problem)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    use russh::keys::ssh_key::LineEnding;
    use russh::keys::ssh_key::certificate::CertType;
    use russh::keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

    use super::{HostIdentity, HostKey, read_pinned_host_key};
    use crate::error::{HostCertProblem, SshError};
    use crate::test_support::{NOW, host_certificate, key};

    const AFTER: u64 = NOW - 120;
    const BEFORE: u64 = NOW + 7 * 24 * 3600;

    #[test]
    fn a_pinned_sshd_host_key_must_be_a_bare_ed25519_public_key_of_bounded_size() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let ed = key(Algorithm::Ed25519);
        let good = dir.path().join("good.pub");
        std::fs::write(
            &good,
            format!("{} root@node\n", ed.public_key().to_openssh().unwrap()),
        )
        .unwrap();
        assert_eq!(
            read_pinned_host_key(&good).unwrap(),
            *ed.public_key().key_data()
        );

        let ecdsa = key(Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        });
        let certificate = host_certificate(&ca, ed.public_key(), CertType::Host, AFTER, BEFORE);
        let mut padded = ed.public_key().to_openssh().unwrap().into_bytes();
        padded.resize(64 * 1024 + 1, b' ');
        for (name, content, refused) in [
            (
                "ecdsa.pub",
                ecdsa.public_key().to_openssh().unwrap().into_bytes(),
                (|error| matches!(error, SshError::PinnedHostKey)) as fn(&SshError) -> bool,
            ),
            (
                "cert.pub",
                certificate.to_openssh().unwrap().into_bytes(),
                |error| matches!(error, SshError::PinnedHostKey),
            ),
            ("large.pub", padded, |error| {
                matches!(error, SshError::FileTooLarge { .. })
            }),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            let error = read_pinned_host_key(&path).unwrap_err();
            assert!(refused(&error), "{name}: {error}");
        }
        assert!(matches!(
            read_pinned_host_key(&dir.path().join("missing.pub")),
            Err(SshError::ReadFile { .. })
        ));
    }

    fn write_pair(
        dir: &std::path::Path,
        subject: &PrivateKey,
        cert_line: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let key_path = dir.join("ssh_host_ed25519");
        let cert_path = dir.join("ssh_host_ed25519-cert.pub");
        std::fs::write(&key_path, subject.to_openssh(LineEnding::LF).unwrap()).unwrap();
        chmod(&key_path, 0o600);
        std::fs::write(&cert_path, format!("{cert_line}\n")).unwrap();
        (key_path, cert_path)
    }

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn a_generated_key_takes_its_host_certificate() {
        let ca = key(Algorithm::Ed25519);
        let host = HostKey::generate().unwrap();
        let public = host.public_openssh().unwrap();
        assert_eq!(
            public,
            host.key.public_key().to_openssh().unwrap(),
            "the public line is the plain OpenSSH key"
        );
        assert!(public.starts_with("ssh-ed25519 "));
        let cert = host_certificate(&ca, host.key.public_key(), CertType::Host, AFTER, BEFORE);
        let identity = host
            .with_certificate(&cert.to_openssh().unwrap(), NOW)
            .unwrap();
        assert_eq!(
            (identity.valid_after(), identity.valid_before()),
            (AFTER, BEFORE)
        );
        let (_, certificate) = identity.into_parts();
        assert_eq!(certificate, cert);
    }

    #[test]
    fn the_host_certificate_must_fit_the_key_type_and_time() {
        let ca = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let stranger = key(Algorithm::Ed25519);
        let valid = host_certificate(&ca, subject.public_key(), CertType::Host, AFTER, BEFORE);
        let cases = [
            (
                host_certificate(&ca, stranger.public_key(), CertType::Host, AFTER, BEFORE),
                NOW,
                HostCertProblem::KeyMismatch,
            ),
            (
                host_certificate(&ca, subject.public_key(), CertType::User, AFTER, BEFORE),
                NOW,
                HostCertProblem::NotHostCertificate,
            ),
            (valid.clone(), AFTER - 1, HostCertProblem::NotYetValid),
            (tampered(&valid), NOW, HostCertProblem::Signature),
            (valid.clone(), BEFORE, HostCertProblem::Expired),
        ];
        for (cert, now, expected) in cases {
            let error = HostKey {
                key: subject.clone(),
            }
            .with_certificate(&cert.to_openssh().unwrap(), now)
            .unwrap_err();
            assert!(
                matches!(error, SshError::HostCertificate(problem) if problem == expected),
                "{expected:?}: {error:?}"
            );
        }
        for now in [AFTER, BEFORE - 1] {
            HostKey {
                key: subject.clone(),
            }
            .with_certificate(&valid.to_openssh().unwrap(), now)
            .unwrap();
        }
        let error = HostKey { key: subject }
            .with_certificate("ssh-ed25519-cert-v01@openssh.com AAAA", NOW)
            .unwrap_err();
        assert!(matches!(
            error,
            SshError::HostCertificate(HostCertProblem::Malformed)
        ));
    }

    #[test]
    fn identity_loads_from_files_and_rejects_other_key_types() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let cert = host_certificate(&ca, subject.public_key(), CertType::Host, AFTER, BEFORE);
        let (key_path, cert_path) = write_pair(dir.path(), &subject, &cert.to_openssh().unwrap());
        let identity = HostIdentity::load(&key_path, &cert_path, NOW).unwrap();
        assert_eq!(identity.certificate, cert);
        let from_text = HostIdentity::from_openssh(
            &std::fs::read(&key_path).unwrap(),
            cert.to_openssh().unwrap().as_bytes(),
            NOW,
        )
        .unwrap();
        assert_eq!(from_text.certificate, cert);
        assert!(matches!(
            HostIdentity::from_openssh(b"not a key", b"", NOW),
            Err(SshError::InvalidHostKey)
        ));

        let ecdsa = key(Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        });
        let ecdsa_cert = host_certificate(&ca, ecdsa.public_key(), CertType::Host, AFTER, BEFORE);
        let (key_path, cert_path) =
            write_pair(dir.path(), &ecdsa, &ecdsa_cert.to_openssh().unwrap());
        assert!(matches!(
            HostIdentity::load(&key_path, &cert_path, NOW),
            Err(SshError::HostKeyAlgorithm)
        ));

        std::fs::write(&key_path, "not a key").unwrap();
        assert!(matches!(
            HostIdentity::load(&key_path, &cert_path, NOW),
            Err(SshError::InvalidHostKey)
        ));
        assert!(matches!(
            HostIdentity::load(&dir.path().join("missing"), &cert_path, NOW),
            Err(SshError::ReadFile { .. })
        ));
    }

    fn tampered(cert: &Certificate) -> Certificate {
        let mut bytes = cert.to_bytes().unwrap();
        let needle = b"node1.example.com:7";
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .unwrap();
        bytes[at] = b'm';
        let tampered = Certificate::from_bytes(&bytes).unwrap();
        assert_eq!(tampered.key_id(), "jaunt-host:mode1.example.com:7");
        tampered
    }

    #[test]
    fn the_private_key_file_must_be_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let cert = host_certificate(&ca, subject.public_key(), CertType::Host, AFTER, BEFORE);
        let (key_path, cert_path) = write_pair(dir.path(), &subject, &cert.to_openssh().unwrap());
        for (mode, ok) in [
            (0o600, true),
            (0o400, true),
            (0o640, false),
            (0o604, false),
            (0o610, false),
            (0o601, false),
        ] {
            chmod(&key_path, mode);
            let outcome = HostIdentity::load(&key_path, &cert_path, NOW);
            if ok {
                assert!(outcome.is_ok(), "{mode:o}: {outcome:?}");
            } else {
                assert!(
                    matches!(outcome, Err(SshError::KeyFilePermissions { mode: seen, .. }) if seen == mode),
                    "{mode:o}: {outcome:?}"
                );
            }
        }
        chmod(&cert_path, 0o644);
        chmod(&key_path, 0o600);
        assert!(HostIdentity::load(&key_path, &cert_path, NOW).is_ok());
    }

    #[test]
    fn oversized_files_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ca = key(Algorithm::Ed25519);
        let subject = key(Algorithm::Ed25519);
        let cert = host_certificate(&ca, subject.public_key(), CertType::Host, AFTER, BEFORE);
        let line = cert.to_openssh().unwrap();
        let padded = format!("{line}{}", " ".repeat(64 * 1024 - line.len()));
        assert_eq!(padded.len(), 64 * 1024);
        let (key_path, cert_path) = write_pair(dir.path(), &subject, &padded[..padded.len() - 1]);
        assert!(HostIdentity::load(&key_path, &cert_path, NOW).is_ok());
        std::fs::write(&cert_path, format!("{padded} ")).unwrap();
        assert!(matches!(
            HostIdentity::load(&key_path, &cert_path, NOW),
            Err(SshError::FileTooLarge { limit: 65536, .. })
        ));
        std::fs::write(&cert_path, &line).unwrap();
        std::fs::write(&key_path, vec![b'A'; 64 * 1024 + 1]).unwrap();
        assert!(matches!(
            HostIdentity::load(&key_path, &cert_path, NOW),
            Err(SshError::FileTooLarge { .. })
        ));
    }

    #[test]
    fn an_encrypted_host_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("ssh_host_ed25519");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "pass", "-f"])
            .arg(&key_path)
            .status()
            .unwrap();
        assert!(status.success());
        let public = PublicKey::from_openssh(
            &std::fs::read_to_string(key_path.with_extension("pub")).unwrap(),
        )
        .unwrap();
        let ca = key(Algorithm::Ed25519);
        let cert = host_certificate(&ca, &public, CertType::Host, AFTER, BEFORE);
        let cert_path = dir.path().join("ssh_host_ed25519-cert.pub");
        std::fs::write(&cert_path, cert.to_openssh().unwrap()).unwrap();
        assert!(matches!(
            HostIdentity::load(&key_path, &cert_path, NOW),
            Err(SshError::InvalidHostKey)
        ));
    }

    #[test]
    fn debug_output_hides_the_private_key() {
        let ca = key(Algorithm::Ed25519);
        let host = HostKey::generate().unwrap();
        let fingerprint = host.key.fingerprint(HashAlg::Sha256);
        assert_eq!(
            format!("{host:?}"),
            format!("HostKey {{ public_key: {fingerprint:?}, private_key: \"<redacted>\" }}")
        );
        let cert = host_certificate(&ca, host.key.public_key(), CertType::Host, AFTER, BEFORE);
        let identity = host
            .with_certificate(&cert.to_openssh().unwrap(), NOW)
            .unwrap();
        assert_eq!(
            format!("{identity:?}"),
            format!(
                "HostIdentity {{ public_key: {fingerprint:?}, key_id: \"jaunt-host:node1.example.com:7\", valid_before: {BEFORE}, private_key: \"<redacted>\" }}"
            )
        );
    }
}
