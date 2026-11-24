use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::NodeCertificates;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use ssh_key::certificate::CertType;
use ssh_key::public::KeyData;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;

use crate::clock::unix_secs;

const NODE_URN_PREFIX: &str = "urn:jaunt:node:";
const MAX_DER_TEXT_LEN: usize = 16 * 1024;
const MAX_SSH_CERTIFICATE_LEN: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the node id is not a canonical UUID")]
    NodeId,
    #[error("the internal CA root is not valid base64 or is too large")]
    RootEncoding,
    #[error("the internal CA root is not a usable X.509 CA certificate")]
    Root,
    #[error("the node certificate is not valid base64 or is too large")]
    CertificateEncoding,
    #[error("the node certificate cannot be parsed")]
    Certificate,
    #[error("the node certificate is for another key than the one this agent generated")]
    CertificateKey,
    #[error("the node certificate does not name exactly the node urn:jaunt:node:<node id>")]
    CertificateNode,
    #[error("the node certificate is marked as a CA certificate")]
    CertificateIsCa,
    #[error("the node certificate does not allow client authentication (no clientAuth usage)")]
    CertificateNotClientAuth,
    #[error("the node certificate is not valid yet: check the system clock")]
    CertificateNotYetValid,
    #[error("the node certificate has expired")]
    CertificateTime,
    #[error("the node certificate is not a client certificate issued by the internal CA root")]
    CertificateChain,
    #[error("the SSH host certificate cannot be parsed")]
    HostCertificate,
    #[error("the SSH host certificate is not a host certificate")]
    HostCertificateType,
    #[error("the SSH host certificate is for another key than the one this agent generated")]
    HostCertificateKey,
    #[error("the SSH host certificate names no principal of the form <name>.<suffix>")]
    HostCertificatePrincipals,
    #[error("the SSH host certificate is not valid yet: check the system clock")]
    HostCertificateNotYetValid,
    #[error("the SSH host certificate has expired")]
    HostCertificateTime,
}

pub struct Expected<'a> {
    pub node_id: &'a str,
    pub name: &'a str,
    pub tls_spki: &'a [u8],
    pub ssh_key: &'a KeyData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Checked {
    pub x509_der: Vec<u8>,
    pub x509: Validity,
    pub ssh_certificate: String,
    pub ssh_not_after: i64,
}

pub fn is_node_id(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
        && bytes.iter().any(|byte| *byte != b'0' && *byte != b'-')
}

pub fn decode_der(text: &str) -> Option<Vec<u8>> {
    if text.len() > MAX_DER_TEXT_LEN {
        return None;
    }
    STANDARD.decode(text).ok().filter(|der| !der.is_empty())
}

pub fn root_store(root_der: &[u8]) -> Result<RootCertStore, VerifyError> {
    let (rest, root) = parse_x509_certificate(root_der).map_err(|_| VerifyError::Root)?;
    if !rest.is_empty() || !root.is_ca() {
        return Err(VerifyError::Root);
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root_der.to_vec()))
        .map_err(|_| VerifyError::Root)?;
    Ok(roots)
}

pub fn node_identity(
    x509_der: &[u8],
    node_id: &str,
    tls_spki: &[u8],
) -> Result<Validity, VerifyError> {
    let (rest, certificate) =
        parse_x509_certificate(x509_der).map_err(|_| VerifyError::Certificate)?;
    if !rest.is_empty() {
        return Err(VerifyError::Certificate);
    }
    if certificate.public_key().raw != tls_spki {
        return Err(VerifyError::CertificateKey);
    }
    if certificate.is_ca() {
        return Err(VerifyError::CertificateIsCa);
    }
    let client_auth = certificate
        .extended_key_usage()
        .map_err(|_| VerifyError::Certificate)?
        .is_some_and(|usage| usage.value.client_auth);
    if !client_auth {
        return Err(VerifyError::CertificateNotClientAuth);
    }
    let san = certificate
        .subject_alternative_name()
        .map_err(|_| VerifyError::Certificate)?
        .ok_or(VerifyError::CertificateNode)?;
    let expected = format!("{NODE_URN_PREFIX}{node_id}");
    match san.value.general_names.as_slice() {
        [GeneralName::URI(uri)] if *uri == expected => {}
        _ => return Err(VerifyError::CertificateNode),
    }
    let validity = certificate.validity();
    Ok(Validity {
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    })
}

pub fn check_certificates(
    certificates: &NodeCertificates,
    root_der: &[u8],
    expected: &Expected<'_>,
    now: SystemTime,
) -> Result<Checked, VerifyError> {
    if !is_node_id(expected.node_id) {
        return Err(VerifyError::NodeId);
    }
    let roots = root_store(root_der)?;
    let x509_der =
        decode_der(&certificates.x509_certificate_der).ok_or(VerifyError::CertificateEncoding)?;
    let x509 = node_identity(&x509_der, expected.node_id, expected.tls_spki)?;
    let now_secs = unix_secs(now);
    if now_secs < x509.not_before {
        return Err(VerifyError::CertificateNotYetValid);
    }
    if now_secs >= x509.not_after {
        return Err(VerifyError::CertificateTime);
    }
    check_chain(&x509_der, roots, now)?;
    let ssh_certificate = certificates.ssh_host_certificate.trim_end_matches('\n');
    let ssh_not_after = check_host_certificate(ssh_certificate, expected, now_secs)?;
    Ok(Checked {
        x509_der,
        x509,
        ssh_certificate: ssh_certificate.to_owned(),
        ssh_not_after,
    })
}

fn check_chain(x509_der: &[u8], roots: RootCertStore, now: SystemTime) -> Result<(), VerifyError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|_| VerifyError::CertificateChain)?;
    let elapsed = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| VerifyError::CertificateTime)?;
    verifier
        .verify_client_cert(
            &CertificateDer::from(x509_der),
            &[],
            UnixTime::since_unix_epoch(elapsed),
        )
        .map(drop)
        .map_err(|_| VerifyError::CertificateChain)
}

fn check_host_certificate(
    line: &str,
    expected: &Expected<'_>,
    now_secs: i64,
) -> Result<i64, VerifyError> {
    if line.len() > MAX_SSH_CERTIFICATE_LEN || line.chars().any(char::is_control) {
        return Err(VerifyError::HostCertificate);
    }
    let certificate =
        ssh_key::Certificate::from_openssh(line).map_err(|_| VerifyError::HostCertificate)?;
    if certificate.cert_type() != CertType::Host {
        return Err(VerifyError::HostCertificateType);
    }
    if certificate.public_key() != expected.ssh_key {
        return Err(VerifyError::HostCertificateKey);
    }
    let qualified = format!("{}.", expected.name);
    let principals = certificate.valid_principals();
    if !principals
        .iter()
        .any(|principal| principal.len() > qualified.len() && principal.starts_with(&qualified))
    {
        return Err(VerifyError::HostCertificatePrincipals);
    }
    let valid_after = i64::try_from(certificate.valid_after()).unwrap_or(i64::MAX);
    let valid_before = i64::try_from(certificate.valid_before()).unwrap_or(i64::MAX);
    if now_secs < valid_after {
        return Err(VerifyError::HostCertificateNotYetValid);
    }
    if now_secs >= valid_before {
        return Err(VerifyError::HostCertificateTime);
    }
    Ok(valid_before)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use jaunt_proto::NodeCertificates;
    use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, SanType};

    use super::{Expected, VerifyError, check_certificates, is_node_id, root_store};
    use crate::clock::at_unix_secs;
    use crate::keys::{HostKey, TlsKey};
    use crate::testkit::{NODE_ID, TestPki, unix_now};

    struct Fixture {
        pki: TestPki,
        tls: TlsKey,
        host: HostKey,
        now: SystemTime,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                pki: TestPki::new(),
                tls: TlsKey::generate().unwrap(),
                host: HostKey::generate().unwrap(),
                now: SystemTime::now(),
            }
        }

        fn expected(&self) -> Expected<'_> {
            Expected {
                node_id: NODE_ID,
                name: "web-01",
                tls_spki: self.tls.spki_der(),
                ssh_key: self.host.key_data(),
            }
        }

        fn valid(&self) -> NodeCertificates {
            self.pki
                .node_certificates(self.tls.spki_der(), self.host.key_data(), NODE_ID, "web-01")
        }

        fn check(&self, certificates: &NodeCertificates) -> Result<(), VerifyError> {
            check_certificates(
                certificates,
                self.pki.root_der(),
                &self.expected(),
                self.now,
            )
            .map(drop)
        }
    }

    #[test]
    fn a_matching_bundle_passes_and_reports_both_expiries() {
        let fixture = Fixture::new();
        let certificates = fixture.valid();
        let checked = check_certificates(
            &certificates,
            fixture.pki.root_der(),
            &fixture.expected(),
            fixture.now,
        )
        .unwrap();
        assert!(checked.x509.not_after > unix_now());
        assert!(checked.ssh_not_after > unix_now());
        assert_eq!(checked.ssh_certificate, certificates.ssh_host_certificate);
    }

    #[test]
    fn every_mismatch_is_refused_with_its_own_reason() {
        let fixture = Fixture::new();
        let other_tls = TlsKey::generate().unwrap();
        let other_host = HostKey::generate().unwrap();
        let other_pki = TestPki::new();
        let pki = &fixture.pki;
        let spki = fixture.tls.spki_der();
        let host = fixture.host.key_data();
        let now = unix_now();
        let with_ssh = |line: String| NodeCertificates {
            ssh_host_certificate: line,
            ..fixture.valid()
        };
        let valid_line = fixture.valid().ssh_host_certificate;
        let x509_with = |adjust: &dyn Fn(&mut CertificateParams)| NodeCertificates {
            x509_certificate_der: pki.node_x509_with(spki, NODE_ID, now - 60, now + 3600, adjust),
            ..fixture.valid()
        };
        let cases: Vec<(&str, NodeCertificates, VerifyError)> = vec![
            (
                "another tls key",
                pki.node_certificates(other_tls.spki_der(), host, NODE_ID, "web-01"),
                VerifyError::CertificateKey,
            ),
            (
                "another node id",
                pki.node_certificates(spki, host, "11111111-2222-4333-8444-555555555555", "web-01"),
                VerifyError::CertificateNode,
            ),
            (
                "expired",
                NodeCertificates {
                    x509_certificate_der: pki.node_x509(spki, NODE_ID, now - 7200, now - 60),
                    ..fixture.valid()
                },
                VerifyError::CertificateTime,
            ),
            (
                "foreign issuer",
                other_pki.node_certificates(spki, host, NODE_ID, "web-01"),
                VerifyError::CertificateChain,
            ),
            (
                "garbage x509",
                NodeCertificates {
                    x509_certificate_der: "not base64!".to_owned(),
                    ..fixture.valid()
                },
                VerifyError::CertificateEncoding,
            ),
            (
                "unparsable host certificate",
                with_ssh("ssh-ed25519-cert-v01@openssh.com AAAA".to_owned()),
                VerifyError::HostCertificate,
            ),
            (
                "host certificate for another key",
                with_ssh(pki.host_certificate(
                    other_host.key_data(),
                    &["web-01.jaunt.test"],
                    now - 60,
                    now + 3600,
                )),
                VerifyError::HostCertificateKey,
            ),
            (
                "user certificate",
                with_ssh(pki.user_certificate(host, now - 60, now + 3600)),
                VerifyError::HostCertificateType,
            ),
            (
                "no qualified principal",
                with_ssh(pki.host_certificate(
                    host,
                    &["web-01", "db-01.jaunt.test"],
                    now - 60,
                    now + 3600,
                )),
                VerifyError::HostCertificatePrincipals,
            ),
            (
                "expired host certificate",
                with_ssh(pki.host_certificate(host, &["web-01.jaunt.test"], now - 7200, now - 60)),
                VerifyError::HostCertificateTime,
            ),
            (
                "host certificate not valid yet",
                with_ssh(pki.host_certificate(host, &["web-01.jaunt.test"], now + 600, now + 7200)),
                VerifyError::HostCertificateNotYetValid,
            ),
            (
                "only the bare name as principal",
                with_ssh(pki.host_certificate(host, &["web-01"], now - 60, now + 3600)),
                VerifyError::HostCertificatePrincipals,
            ),
            (
                "the name and a dot without a suffix",
                with_ssh(pki.host_certificate(host, &["web-01."], now - 60, now + 3600)),
                VerifyError::HostCertificatePrincipals,
            ),
            (
                "carriage return after the line",
                with_ssh(format!("{valid_line}\r")),
                VerifyError::HostCertificate,
            ),
            (
                "escape inside the line",
                with_ssh(valid_line.replacen(' ', " \u{1b}[31m", 1)),
                VerifyError::HostCertificate,
            ),
            (
                "an extra subject alternative name",
                x509_with(&|params| {
                    params
                        .subject_alt_names
                        .push(SanType::DnsName("web-01.jaunt.test".try_into().unwrap()));
                }),
                VerifyError::CertificateNode,
            ),
            (
                "no extended key usage",
                x509_with(&|params| params.extended_key_usages.clear()),
                VerifyError::CertificateNotClientAuth,
            ),
            (
                "server authentication only",
                x509_with(&|params| {
                    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
                }),
                VerifyError::CertificateNotClientAuth,
            ),
            (
                "a CA certificate",
                x509_with(&|params| params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained)),
                VerifyError::CertificateIsCa,
            ),
            (
                "not valid yet",
                NodeCertificates {
                    x509_certificate_der: pki.node_x509(spki, NODE_ID, now + 600, now + 7200),
                    ..fixture.valid()
                },
                VerifyError::CertificateNotYetValid,
            ),
        ];
        for (name, certificates, expected) in cases {
            assert_eq!(fixture.check(&certificates), Err(expected), "{name}");
        }
        assert!(
            VerifyError::CertificateNotYetValid
                .to_string()
                .contains("check the system clock")
        );
    }

    #[test]
    fn validity_starts_inclusive_and_ends_exclusive() {
        let fixture = Fixture::new();
        let now = unix_now();
        let host = fixture.host.key_data();
        let spki = fixture.tls.spki_der();
        let x509_window =
            fixture
                .pki
                .node_certificates_for(spki, host, NODE_ID, "web-01", now - 100, now + 100);
        let ssh_window = NodeCertificates {
            ssh_host_certificate: fixture.pki.host_certificate(
                host,
                &["web-01.jaunt.test"],
                now - 100,
                now + 50,
            ),
            ..x509_window.clone()
        };
        let cases: [(&NodeCertificates, i64, Result<(), VerifyError>); 6] = [
            (
                &x509_window,
                now - 101,
                Err(VerifyError::CertificateNotYetValid),
            ),
            (&x509_window, now - 100, Ok(())),
            (&x509_window, now + 99, Ok(())),
            (&x509_window, now + 100, Err(VerifyError::CertificateTime)),
            (&ssh_window, now + 49, Ok(())),
            (&ssh_window, now + 50, Err(VerifyError::HostCertificateTime)),
        ];
        for (certificates, at, expected) in cases {
            let result = check_certificates(
                certificates,
                fixture.pki.root_der(),
                &fixture.expected(),
                at_unix_secs(at),
            )
            .map(drop);
            assert_eq!(result, expected, "at {}", at - now);
        }
    }

    #[test]
    fn the_root_must_be_a_ca_certificate_and_the_clock_matters() {
        let fixture = Fixture::new();
        assert!(root_store(fixture.pki.root_der()).is_ok());
        assert_eq!(root_store(b"junk").unwrap_err(), VerifyError::Root);
        assert_eq!(
            root_store(&fixture.pki.leaf_der("localhost")).unwrap_err(),
            VerifyError::Root
        );
        let late = Fixture {
            now: SystemTime::now() + Duration::from_secs(30 * 24 * 3600),
            ..Fixture::new()
        };
        assert_eq!(late.check(&late.valid()), Err(VerifyError::CertificateTime));
    }

    #[test]
    fn node_ids_must_be_canonical_uuids() {
        assert!(is_node_id(NODE_ID));
        for bad in [
            "",
            "00000000-0000-0000-0000-000000000000",
            "0f8fad5b-d9cb-469f-a165-70867728950E",
            "0f8fad5bd9cb469fa16570867728950e",
            "0f8fad5b-d9cb-469f-a165-70867728950e0",
            "../etc/passwd-0000-0000-0000-00000000",
        ] {
            assert!(!is_node_id(bad), "{bad}");
        }
    }
}
