use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    ClientConfig, ClientConfigV2, ClientTransport, GATE_ALPN_SSH, GATE_ALPN_SVC, PinnedRoot,
    ServicesClient,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::gate_tls::{GateRoute, ServiceGate};
use crate::ssh_config::{SshConfigError, is_dns_name};

pub const MAX_PINNED_ROOTS: usize = 8;
const MAX_ALPN_NAMES: usize = 8;
const MAX_ALPN_NAME_LEN: usize = 255;
const MAX_ROOT_DER_BYTES: usize = 16 * 1024;
const MAX_ROOT_TEXT_LEN: usize = MAX_ROOT_DER_BYTES.div_ceil(3) * 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateServices {
    pub client_transport: ClientTransport,
    pub services: ServicesClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitConfig {
    pub client: ClientConfig,
    pub transport: ClientTransport,
    pub services: Option<ServicesClient>,
}

pub fn split_v2(config: ClientConfigV2) -> SplitConfig {
    let ClientConfigV2 {
        ssh_suffix,
        gate,
        host_ca_keys,
        ssh_gate,
        services,
    } = config;
    SplitConfig {
        client: ClientConfig {
            ssh_suffix,
            gate,
            host_ca_keys,
        },
        transport: ssh_gate.client_transport,
        services,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedServices {
    pub services: Option<GateServices>,
    pub notes: Vec<String>,
}

impl AcceptedServices {
    pub fn transport(&self) -> ClientTransport {
        self.services
            .as_ref()
            .map_or(ClientTransport::Tcp, |services| services.client_transport)
    }
}

pub fn accept_services(
    transport: ClientTransport,
    offered: Option<ServicesClient>,
    now: i64,
) -> AcceptedServices {
    let mut notes = Vec::new();
    let Some(mut services) = offered else {
        return AcceptedServices {
            services: None,
            notes,
        };
    };
    if let Err(err) = check_endpoint(&services, transport) {
        notes.push(format!(
            "warning: the TLS settings of the gate were dropped: {err}"
        ));
        return AcceptedServices {
            services: None,
            notes,
        };
    }
    let mut kept = Vec::with_capacity(services.roots.len());
    for (index, root) in services.roots.into_iter().enumerate() {
        match check_root(&root, now) {
            Ok(_) => kept.push(root),
            Err(err) => notes.push(format!(
                "warning: pinned root {} of the gate was dropped: {err}",
                index + 1
            )),
        }
    }
    if kept.is_empty() {
        notes.push(
            "warning: no pinned root of the gate is usable, so its TLS settings were dropped"
                .to_owned(),
        );
        return AcceptedServices {
            services: None,
            notes,
        };
    }
    services.roots = kept;
    AcceptedServices {
        services: Some(GateServices {
            client_transport: transport,
            services,
        }),
        notes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StoredGateError {
    #[error("the stored TLS name, port or protocols of the gate are not usable")]
    Endpoint,
    #[error("the stored TLS settings of the gate do not offer SSH over TLS (jaunt-ssh/1)")]
    NoSsh,
    #[error(
        "the stored TLS settings of the gate do not offer database and TCP connections (jaunt-svc/1)"
    )]
    NoSvc,
    #[error("the stored TLS settings of the gate hold no pinned root, or more than 8")]
    RootCount,
    #[error("a stored pinned root is not base64 DER")]
    RootUnreadable,
    #[error("a stored pinned root does not match its SHA-256")]
    RootDigest,
    #[error("a stored pinned root is not a CA certificate")]
    RootNotCa,
    #[error("a stored pinned root is not self-signed")]
    RootNotSelfSigned,
    #[error("a stored pinned root is not valid at this time (check the system clock)")]
    RootOutsideValidity,
}

impl From<SshConfigError> for StoredGateError {
    fn from(err: SshConfigError) -> StoredGateError {
        match err {
            SshConfigError::MissingSshAlpn => StoredGateError::NoSsh,
            SshConfigError::RootCount => StoredGateError::RootCount,
            SshConfigError::RootUnreadable => StoredGateError::RootUnreadable,
            SshConfigError::RootDigest => StoredGateError::RootDigest,
            SshConfigError::RootNotCa => StoredGateError::RootNotCa,
            SshConfigError::RootNotSelfSigned => StoredGateError::RootNotSelfSigned,
            SshConfigError::RootOutsideValidity => StoredGateError::RootOutsideValidity,
            _ => StoredGateError::Endpoint,
        }
    }
}

pub fn ssh_route(stored: &GateServices, now: i64) -> Result<GateRoute, StoredGateError> {
    check_endpoint(&stored.services, ClientTransport::Tls)?;
    usable_route(&stored.services, now)
}

pub fn service_gate(stored: &GateServices, now: i64) -> Result<ServiceGate, StoredGateError> {
    check_endpoint(&stored.services, ClientTransport::Tcp)?;
    if !stored
        .services
        .alpn
        .iter()
        .any(|name| name == GATE_ALPN_SVC)
    {
        return Err(StoredGateError::NoSvc);
    }
    let route = usable_route(&stored.services, now)?;
    Ok(ServiceGate::new(route, stored.services.domain.clone()))
}

fn usable_route(services: &ServicesClient, now: i64) -> Result<GateRoute, StoredGateError> {
    let mut roots = Vec::with_capacity(services.roots.len());
    let mut first_error = None;
    for root in &services.roots {
        match check_root(root, now) {
            Ok(der) => roots.push(der),
            Err(err) => {
                first_error.get_or_insert(err);
            }
        }
    }
    if roots.is_empty() {
        return Err(first_error.map_or(StoredGateError::RootCount, StoredGateError::from));
    }
    Ok(GateRoute::new(
        services.gate_tls_name.clone(),
        services.port,
        roots,
    ))
}

fn check_endpoint(
    services: &ServicesClient,
    transport: ClientTransport,
) -> Result<(), SshConfigError> {
    if !is_dns_name(&services.domain) {
        return Err(SshConfigError::BadServicesDomain);
    }
    if !is_dns_name(&services.gate_tls_name) {
        return Err(SshConfigError::BadGateTlsName);
    }
    if services.port == 0 {
        return Err(SshConfigError::BadServicesPort);
    }
    let alpn_usable = services.alpn.len() <= MAX_ALPN_NAMES
        && services.alpn.iter().all(|name| {
            (1..=MAX_ALPN_NAME_LEN).contains(&name.len())
                && name.bytes().all(|byte| byte.is_ascii_graphic())
        });
    if !alpn_usable {
        return Err(SshConfigError::BadAlpn);
    }
    if transport == ClientTransport::Tls && !services.alpn.iter().any(|name| name == GATE_ALPN_SSH)
    {
        return Err(SshConfigError::MissingSshAlpn);
    }
    if services.roots.is_empty() || services.roots.len() > MAX_PINNED_ROOTS {
        return Err(SshConfigError::RootCount);
    }
    Ok(())
}

pub fn check_root(root: &PinnedRoot, now: i64) -> Result<Vec<u8>, SshConfigError> {
    if root.certificate_der.len() > MAX_ROOT_TEXT_LEN {
        return Err(SshConfigError::RootUnreadable);
    }
    let der = STANDARD
        .decode(&root.certificate_der)
        .ok()
        .filter(|der| !der.is_empty() && der.len() <= MAX_ROOT_DER_BYTES)
        .ok_or(SshConfigError::RootUnreadable)?;
    if sha256_hex(&der) != root.sha256 {
        return Err(SshConfigError::RootDigest);
    }
    let (rest, certificate) =
        X509Certificate::from_der(&der).map_err(|_| SshConfigError::RootUnreadable)?;
    if !rest.is_empty() {
        return Err(SshConfigError::RootUnreadable);
    }
    let is_ca = certificate
        .basic_constraints()
        .map_err(|_| SshConfigError::RootUnreadable)?
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(SshConfigError::RootNotCa);
    }
    if certificate.subject().as_raw() != certificate.issuer().as_raw()
        || certificate.verify_signature(None).is_err()
    {
        return Err(SshConfigError::RootNotSelfSigned);
    }
    let validity = certificate.validity();
    if now < validity.not_before.timestamp() || now > validity.not_after.timestamp() {
        return Err(SshConfigError::RootOutsideValidity);
    }
    Ok(der)
}

pub fn sha256_hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use jaunt_proto::{ClientTransport, GATE_ALPN_SSH, GATE_ALPN_SVC, PinnedRoot, ServicesClient};
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

    use super::{
        AcceptedServices, GateServices, StoredGateError, accept_services, check_root, service_gate,
        sha256_hex, ssh_route,
    };
    use crate::ssh_config::SshConfigError;

    const NOW: i64 = 1_800_000_000;

    fn params(name: &str, not_before: i64, not_after: i64, ca: bool) -> CertificateParams {
        let epoch = rcgen::date_time_ymd(1970, 1, 1);
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.not_before = epoch + Duration::from_secs(u64::try_from(not_before).unwrap());
        params.not_after = epoch + Duration::from_secs(u64::try_from(not_after).unwrap());
        params.is_ca = if ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params
    }

    fn self_signed(params: &CertificateParams) -> Vec<u8> {
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    fn signed_by_another(subject: &str, issuer_name: &str) -> Vec<u8> {
        let issuer = CertifiedIssuer::self_signed(
            params(issuer_name, NOW - 100, NOW + 100, true),
            KeyPair::generate().unwrap(),
        )
        .unwrap();
        params(subject, NOW - 100, NOW + 100, true)
            .signed_by(&KeyPair::generate().unwrap(), &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    fn pinned(der: &[u8]) -> PinnedRoot {
        PinnedRoot {
            certificate_der: STANDARD.encode(der),
            sha256: sha256_hex(der),
            not_before: 0,
            not_after: 0,
        }
    }

    fn root() -> PinnedRoot {
        pinned(&self_signed(&params("root", NOW - 100, NOW + 100, true)))
    }

    fn expired_root() -> PinnedRoot {
        pinned(&self_signed(&params("old", NOW - 100, NOW - 1, true)))
    }

    fn services(roots: Vec<PinnedRoot>) -> ServicesClient {
        ServicesClient {
            domain: "svc.example.test".to_owned(),
            gate_tls_name: "svc.example.test".to_owned(),
            port: 443,
            alpn: vec![GATE_ALPN_SSH.to_owned(), GATE_ALPN_SVC.to_owned()],
            roots,
        }
    }

    fn mentions_no_certificate(accepted: &AcceptedServices, roots: &[PinnedRoot]) -> bool {
        accepted.notes.iter().all(|note| {
            roots.iter().all(|root| {
                let head: String = root.certificate_der.chars().take(16).collect();
                !note.contains(&head) && !note.contains(&root.sha256)
            })
        })
    }

    #[test]
    fn a_valid_block_keeps_its_transport_and_a_missing_one_means_tcp() {
        let offered = services(vec![root()]);

        let tls = accept_services(ClientTransport::Tls, Some(offered.clone()), NOW);
        let bare = accept_services(ClientTransport::Tcp, None, NOW);
        let asked_without = accept_services(ClientTransport::Tls, None, NOW);
        let mut database_only = offered.clone();
        database_only.alpn = vec![GATE_ALPN_SVC.to_owned()];
        let tcp = accept_services(ClientTransport::Tcp, Some(database_only), NOW);

        assert_eq!(
            tls,
            AcceptedServices {
                services: Some(GateServices {
                    client_transport: ClientTransport::Tls,
                    services: offered,
                }),
                notes: Vec::new(),
            }
        );
        assert_eq!(bare, AcceptedServices::default());
        assert_eq!(asked_without.transport(), ClientTransport::Tcp);
        assert_eq!(asked_without.services, None);
        assert!(asked_without.notes.is_empty());
        assert_eq!(tcp.transport(), ClientTransport::Tcp);
        assert_eq!(
            ssh_route(&tcp.services.unwrap(), NOW).err(),
            Some(StoredGateError::NoSsh)
        );
    }

    #[test]
    fn a_defective_block_is_dropped_with_one_note_whatever_the_transport() {
        type Change = fn(&mut ServicesClient);
        let cases: Vec<(Change, SshConfigError)> = vec![
            (
                |block| block.domain = "svc.example.test\nx".to_owned(),
                SshConfigError::BadServicesDomain,
            ),
            (
                |block| block.gate_tls_name = "Svc.example.test".to_owned(),
                SshConfigError::BadGateTlsName,
            ),
            (
                |block| block.gate_tls_name = "svc.example.test.".to_owned(),
                SshConfigError::BadGateTlsName,
            ),
            (|block| block.port = 0, SshConfigError::BadServicesPort),
            (
                |block| block.alpn.push("two words".to_owned()),
                SshConfigError::BadAlpn,
            ),
            (
                |block| block.alpn.push(String::new()),
                SshConfigError::BadAlpn,
            ),
            (|block| block.roots.clear(), SshConfigError::RootCount),
            (
                |block| block.roots = vec![block.roots[0].clone(); 9],
                SshConfigError::RootCount,
            ),
        ];
        for transport in [ClientTransport::Tls, ClientTransport::Tcp] {
            for (change, expected) in &cases {
                let mut block = services(vec![root()]);
                change(&mut block);

                let accepted = accept_services(transport, Some(block), NOW);

                assert_eq!(accepted.services, None, "{transport:?} {expected:?}");
                assert_eq!(accepted.notes.len(), 1, "{transport:?} {expected:?}");
                assert!(accepted.notes[0].contains(&expected.to_string()));
            }
        }
        let mut without_ssh = services(vec![root()]);
        without_ssh.alpn = vec![GATE_ALPN_SVC.to_owned()];
        let accepted = accept_services(ClientTransport::Tls, Some(without_ssh), NOW);
        assert_eq!(accepted.services, None);
        assert!(accepted.notes[0].contains(&SshConfigError::MissingSshAlpn.to_string()));
        let eight = accept_services(ClientTransport::Tls, Some(services(vec![root(); 8])), NOW);
        assert_eq!(eight.services.unwrap().services.roots.len(), 8);
    }

    #[test]
    fn each_bad_root_is_dropped_on_its_own_with_a_note_and_the_others_are_kept() {
        let (first, third) = (root(), root());
        let mut wrong_digest = root();
        wrong_digest.sha256 = sha256_hex(b"something else");
        let offered = vec![first.clone(), expired_root(), third.clone(), wrong_digest];

        let accepted = accept_services(ClientTransport::Tls, Some(services(offered.clone())), NOW);

        assert_eq!(accepted.transport(), ClientTransport::Tls);
        assert_eq!(
            accepted.services.as_ref().unwrap().services.roots,
            [first, third]
        );
        assert_eq!(
            accepted.notes,
            [
                format!(
                    "warning: pinned root 2 of the gate was dropped: {}",
                    SshConfigError::RootOutsideValidity
                ),
                format!(
                    "warning: pinned root 4 of the gate was dropped: {}",
                    SshConfigError::RootDigest
                ),
            ]
        );
        assert!(mentions_no_certificate(&accepted, &offered));

        for transport in [ClientTransport::Tls, ClientTransport::Tcp] {
            let unusable = vec![expired_root(), pinned(b"junk")];
            let accepted = accept_services(transport, Some(services(unusable.clone())), NOW);
            assert_eq!(accepted.services, None, "{transport:?}");
            assert_eq!(accepted.transport(), ClientTransport::Tcp);
            assert_eq!(accepted.notes.len(), 3, "{transport:?}");
            assert!(mentions_no_certificate(&accepted, &unusable));
        }
    }

    #[test]
    fn the_route_rechecks_the_stored_roots_at_use() {
        let stored = |roots: Vec<PinnedRoot>| GateServices {
            client_transport: ClientTransport::Tls,
            services: services(roots),
        };
        let mut changed = root();
        changed.certificate_der = root().certificate_der;

        let mixed = ssh_route(&stored(vec![expired_root(), root()]), NOW).unwrap();

        assert_eq!(mixed.roots.len(), 1);
        assert_eq!(mixed.host, "svc.example.test");
        assert_eq!(mixed.port, 443);
        assert_eq!(
            ssh_route(&stored(vec![expired_root()]), NOW).err(),
            Some(StoredGateError::RootOutsideValidity)
        );
        assert_eq!(
            ssh_route(&stored(vec![changed]), NOW).err(),
            Some(StoredGateError::RootDigest)
        );
        assert_eq!(
            ssh_route(&stored(Vec::new()), NOW).err(),
            Some(StoredGateError::RootCount)
        );
        let mut broken = stored(vec![root()]);
        broken.services.port = 0;
        assert_eq!(
            ssh_route(&broken, NOW).err(),
            Some(StoredGateError::Endpoint)
        );
        for err in [
            StoredGateError::Endpoint,
            StoredGateError::NoSsh,
            StoredGateError::NoSvc,
            StoredGateError::RootCount,
            StoredGateError::RootUnreadable,
            StoredGateError::RootDigest,
            StoredGateError::RootNotCa,
            StoredGateError::RootNotSelfSigned,
            StoredGateError::RootOutsideValidity,
        ] {
            assert!(!err.to_string().contains("the server"), "{err}");
        }
    }

    #[test]
    fn the_service_route_needs_the_service_protocol_whatever_the_ssh_transport() {
        let stored = |transport: ClientTransport, alpn: &[&str], roots: Vec<PinnedRoot>| {
            let mut services = services(roots);
            services.alpn = alpn.iter().map(|name| (*name).to_owned()).collect();
            GateServices {
                client_transport: transport,
                services,
            }
        };
        for transport in [ClientTransport::Tls, ClientTransport::Tcp] {
            for alpn in [&[GATE_ALPN_SSH, GATE_ALPN_SVC][..], &[GATE_ALPN_SVC][..]] {
                let gate = service_gate(&stored(transport, alpn, vec![root()]), NOW).unwrap();
                assert_eq!(gate.domain, "svc.example.test");
                assert_eq!(gate.route.host, "svc.example.test");
                assert_eq!(gate.route.port, 443);
                assert_eq!(gate.route.roots.len(), 1);
            }
            assert_eq!(
                service_gate(&stored(transport, &[GATE_ALPN_SSH], vec![root()]), NOW).err(),
                Some(StoredGateError::NoSvc)
            );
            assert_eq!(
                service_gate(
                    &stored(transport, &[GATE_ALPN_SVC], vec![expired_root()]),
                    NOW
                )
                .err(),
                Some(StoredGateError::RootOutsideValidity)
            );
        }
    }

    #[test]
    fn a_pinned_root_must_match_its_digest_and_be_a_current_self_signed_ca() {
        let current = self_signed(&params("root", NOW - 100, NOW + 100, true));
        let mut wrong_digest = pinned(&current);
        wrong_digest.sha256 = sha256_hex(b"something else");
        let mut upper_digest = pinned(&current);
        upper_digest.sha256 = upper_digest.sha256.to_uppercase();
        let mut not_base64 = pinned(&current);
        not_base64.certificate_der = "not base64!".to_owned();
        let cases = [
            (wrong_digest, Err(SshConfigError::RootDigest)),
            (upper_digest, Err(SshConfigError::RootDigest)),
            (not_base64, Err(SshConfigError::RootUnreadable)),
            (pinned(b"junk"), Err(SshConfigError::RootUnreadable)),
            (
                pinned(&[current.as_slice(), &[0]].concat()),
                Err(SshConfigError::RootUnreadable),
            ),
            (
                pinned(&self_signed(&params("root", NOW - 100, NOW - 1, true))),
                Err(SshConfigError::RootOutsideValidity),
            ),
            (
                pinned(&self_signed(&params("root", NOW + 1, NOW + 100, true))),
                Err(SshConfigError::RootOutsideValidity),
            ),
            (
                pinned(&self_signed(&params("root", NOW, NOW, true))),
                Ok(()),
            ),
            (
                pinned(&signed_by_another("root", "other")),
                Err(SshConfigError::RootNotSelfSigned),
            ),
            (
                pinned(&signed_by_another("root", "root")),
                Err(SshConfigError::RootNotSelfSigned),
            ),
            (
                pinned(&self_signed(&params("leaf", NOW - 100, NOW + 100, false))),
                Err(SshConfigError::RootNotCa),
            ),
            (pinned(&current), Ok(())),
        ];
        for (index, (root, expected)) in cases.into_iter().enumerate() {
            assert_eq!(check_root(&root, NOW).map(drop), expected, "case {index}");
        }
        assert_eq!(check_root(&pinned(&current), NOW).unwrap(), current);
    }
}
