use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use rcgen::ExtendedKeyUsagePurpose;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error as TlsError, RootCertStore};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;

use super::{
    DAY, DEFAULT_NODE_VALIDITY, Fixture, NODE_ID, NOW_SECS, common_names, der_serial, dns,
    node_params, now, parsed, server_params, subject,
};
use crate::cert::window;
use crate::error::CaError;
use crate::test_support::verify_client;
use crate::x509::{
    DEFAULT_SERVER_VALIDITY, MAX_NODE_VALIDITY, MAX_SERVER_VALIDITY, ROOT_VALIDITY,
    parse_node_identity,
};

fn at(seconds: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(seconds))
}

fn roots(root_der: &[u8]) -> Arc<RootCertStore> {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(root_der.to_vec())).unwrap();
    Arc::new(store)
}

pub(super) fn verify_server(
    root_der: &[u8],
    cert_der: &[u8],
    name: &str,
    seconds: u64,
) -> Result<(), TlsError> {
    let verifier =
        WebPkiServerVerifier::builder_with_provider(roots(root_der), Arc::new(default_provider()))
            .build()
            .unwrap();
    let name = ServerName::try_from(name.to_owned()).unwrap();
    verifier
        .verify_server_cert(
            &CertificateDer::from(cert_der),
            &[],
            &name,
            &[],
            at(seconds),
        )
        .map(drop)
}

pub(super) fn is_expired(err: &TlsError) -> bool {
    matches!(
        err,
        TlsError::InvalidCertificate(
            CertificateError::Expired | CertificateError::ExpiredContext { .. }
        )
    )
}

pub(super) fn is_not_yet_valid(err: &TlsError) -> bool {
    matches!(
        err,
        TlsError::InvalidCertificate(
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. }
        )
    )
}

pub(super) fn is_wrong_name(err: &TlsError) -> bool {
    matches!(
        err,
        TlsError::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    )
}

pub(super) fn subject_key_id(certificate: &X509Certificate<'_>) -> Vec<u8> {
    certificate
        .iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
            _ => None,
        })
        .unwrap()
}

pub(super) fn authority_key_id(certificate: &X509Certificate<'_>) -> Vec<u8> {
    certificate
        .iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(id) => {
                id.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => None,
        })
        .unwrap()
}

pub(super) fn usages(certificate: &X509Certificate<'_>) -> (bool, bool, bool) {
    let usage = certificate.extended_key_usage().unwrap().unwrap().value;
    let others = usage.any
        || usage.code_signing
        || usage.email_protection
        || usage.time_stamping
        || usage.ocsp_signing
        || !usage.other.is_empty();
    (usage.client_auth, usage.server_auth, others)
}

pub(super) fn sans(certificate: &X509Certificate<'_>) -> Vec<String> {
    certificate
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(|name| format!("{name}"))
        .collect()
}

#[test]
fn node_certificate_verifies_against_the_root_and_names_the_node() {
    let fixture = Fixture::new();
    let issued = fixture
        .ca()
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();
    let root = &fixture.root.certificate_der;
    assert!(verify_client(root, &issued.certificate_der, NOW_SECS).is_ok());
    let identity = parse_node_identity(&issued.certificate_der).unwrap();
    assert_eq!(identity.node_id.to_string(), NODE_ID);
}

#[test]
fn certificate_from_another_authority_is_rejected() {
    let (ours, theirs) = (Fixture::new(), Fixture::new());
    let node = theirs
        .ca()
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();
    let server = theirs
        .ca()
        .issue_server_certificate(
            server_params(&["agents.example.com"], DEFAULT_SERVER_VALIDITY),
            now(),
        )
        .unwrap();
    let root = &ours.root.certificate_der;
    assert!(matches!(
        verify_client(root, &node.certificate_der, NOW_SECS),
        Err(TlsError::InvalidCertificate(_))
    ));
    assert!(matches!(
        verify_server(
            root,
            &server.certificate_der,
            "agents.example.com",
            NOW_SECS
        ),
        Err(TlsError::InvalidCertificate(_))
    ));
}

#[test]
fn validity_window_is_enforced_by_the_verifier() {
    let fixture = Fixture::new();
    let root = &fixture.root.certificate_der;
    let issued = fixture
        .ca()
        .issue_node_certificate(node_params(Duration::from_secs(3600)), now())
        .unwrap();
    let cert = &issued.certificate_der;
    let (first, last) = (NOW_SECS - 120, NOW_SECS + 3600);
    assert!(verify_client(root, cert, first).is_ok());
    assert!(verify_client(root, cert, last).is_ok());
    assert!(is_not_yet_valid(
        &verify_client(root, cert, first - 1).unwrap_err()
    ));
    assert!(is_expired(
        &verify_client(root, cert, last + 1).unwrap_err()
    ));
    assert_eq!(issued.not_before, UNIX_EPOCH + Duration::from_secs(first));
    assert_eq!(issued.not_after, UNIX_EPOCH + Duration::from_secs(last));
}

#[test]
fn server_certificate_verifies_for_its_names_only() {
    let fixture = Fixture::new();
    let root = &fixture.root.certificate_der;
    let names = ["agents.example.com", "agents.example.net"];
    let issued = fixture
        .ca()
        .issue_server_certificate(server_params(&names, DEFAULT_SERVER_VALIDITY), now())
        .unwrap();
    let cert = &issued.certificate_der;
    for name in names {
        assert!(verify_server(root, cert, name, NOW_SECS).is_ok(), "{name}");
    }
    for other in ["www.example.com", "example.com", "evil.agents.example.com"] {
        let err = verify_server(root, cert, other, NOW_SECS).unwrap_err();
        assert!(is_wrong_name(&err), "{other}");
    }
}

#[test]
fn extended_key_usage_keeps_node_and_server_certificates_apart() {
    let fixture = Fixture::new();
    let root = &fixture.root.certificate_der;
    let ca = fixture.ca();
    let node = ca
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();
    let server = ca
        .issue_server_certificate(
            server_params(&["agents.example.com"], DEFAULT_SERVER_VALIDITY),
            now(),
        )
        .unwrap();
    assert!(matches!(
        verify_server(root, &node.certificate_der, "agents.example.com", NOW_SECS),
        Err(TlsError::InvalidCertificate(_))
    ));
    assert!(matches!(
        verify_client(root, &server.certificate_der, NOW_SECS),
        Err(TlsError::InvalidCertificate(_))
    ));

    let window = window(now(), DEFAULT_NODE_VALIDITY, MAX_NODE_VALIDITY).unwrap();
    let named_client = ca
        .issue_leaf(
            &subject(),
            &window,
            "agents.example.com",
            ExtendedKeyUsagePurpose::ClientAuth,
            vec![dns("agents.example.com")],
        )
        .unwrap();
    let err = verify_server(
        root,
        &named_client.certificate_der,
        "agents.example.com",
        NOW_SECS,
    )
    .unwrap_err();
    assert!(!is_wrong_name(&err));
    assert!(matches!(err, TlsError::InvalidCertificate(_)));
}

#[test]
fn validity_bounds_are_enforced() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let node = |validity| ca.issue_node_certificate(node_params(validity), now());
    let server = |validity| {
        ca.issue_server_certificate(server_params(&["agents.example.com"], validity), now())
    };
    let nanosecond = Duration::from_nanos(1);
    for validity in [
        Duration::ZERO,
        Duration::from_millis(500),
        MAX_NODE_VALIDITY + nanosecond,
    ] {
        assert!(
            matches!(node(validity), Err(CaError::InvalidValidity { .. })),
            "node {validity:?}"
        );
    }
    for validity in [
        Duration::ZERO,
        Duration::from_millis(500),
        MAX_SERVER_VALIDITY + nanosecond,
    ] {
        assert!(
            matches!(server(validity), Err(CaError::InvalidValidity { .. })),
            "server {validity:?}"
        );
    }
    let longest_node = node(MAX_NODE_VALIDITY).unwrap();
    let longest_server = server(MAX_SERVER_VALIDITY).unwrap();
    assert_eq!(
        longest_node.not_after,
        now() + Duration::from_secs(30 * DAY)
    );
    assert_eq!(
        longest_server.not_after,
        now() + Duration::from_secs(90 * DAY)
    );
    assert!(node(Duration::from_secs(1)).is_ok());
    assert_eq!(DEFAULT_NODE_VALIDITY, Duration::from_secs(7 * DAY));
    assert_eq!(DEFAULT_SERVER_VALIDITY, Duration::from_secs(30 * DAY));
    assert_eq!(ROOT_VALIDITY, Duration::from_secs(3650 * DAY));
}

#[test]
fn issuance_stays_inside_the_root_validity() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let (root_start, root_end) = (fixture.root.not_before, fixture.root.not_after);
    let (second, hour) = (Duration::from_secs(1), Duration::from_secs(3600));
    let node = |validity, at| ca.issue_node_certificate(node_params(validity), at);
    let server = |validity, at| {
        ca.issue_server_certificate(server_params(&["agents.example.com"], validity), at)
    };

    assert!(node(hour, root_start).is_ok());
    assert!(server(hour, root_start).is_ok());
    assert!(matches!(
        node(hour, root_start - second),
        Err(CaError::RootNotValid)
    ));
    assert!(matches!(
        server(hour, root_start - second),
        Err(CaError::RootNotValid)
    ));
    assert!(matches!(
        node(hour, root_end + second),
        Err(CaError::RootNotValid)
    ));
    assert!(matches!(
        server(hour, root_end + second),
        Err(CaError::RootNotValid)
    ));

    let late = root_end - hour;
    assert!(node(hour, late).is_ok());
    assert!(server(hour, late).is_ok());
    assert!(matches!(
        node(hour + second, late),
        Err(CaError::ExceedsRootValidity)
    ));
    assert!(matches!(
        server(hour + second, late),
        Err(CaError::ExceedsRootValidity)
    ));
    assert!(matches!(
        node(hour, root_end),
        Err(CaError::ExceedsRootValidity)
    ));
}

#[test]
fn nil_node_id_is_refused() {
    let fixture = Fixture::new();
    let mut params = node_params(DEFAULT_NODE_VALIDITY);
    params.node_id = Uuid::nil();
    assert!(matches!(
        fixture.ca().issue_node_certificate(params, now()),
        Err(CaError::InvalidNodeId)
    ));
}

#[test]
fn issued_certificates_have_the_leaf_profiles() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let root_der = fixture.root.certificate_der.clone();
    let root = parsed(&root_der);
    let root_key_id = subject_key_id(&root);

    let node = ca
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();
    let server = ca
        .issue_server_certificate(
            server_params(
                &["agents.example.com", "agents.example.net"],
                DEFAULT_SERVER_VALIDITY,
            ),
            now(),
        )
        .unwrap();

    for (issued, window_days) in [(&node, 7), (&server, 30)] {
        let leaf = parsed(&issued.certificate_der);
        let constraints = leaf.basic_constraints().unwrap().unwrap();
        assert!(constraints.critical && !constraints.value.ca);
        assert_eq!(constraints.value.path_len_constraint, None);
        let usage = leaf.key_usage().unwrap().unwrap();
        assert!(usage.critical);
        assert_eq!(usage.value.flags, 1);
        assert_eq!(leaf.issuer().as_raw(), root.subject().as_raw());
        assert_eq!(authority_key_id(&leaf), root_key_id);
        let validity = leaf.validity();
        assert_eq!(
            validity.not_before.timestamp(),
            i64::try_from(NOW_SECS - 120).unwrap()
        );
        assert_eq!(
            validity.not_after.timestamp(),
            i64::try_from(NOW_SECS + window_days * DAY).unwrap()
        );
        assert_eq!(der_serial(&leaf), issued.serial);
    }

    let leaf = parsed(&node.certificate_der);
    assert_eq!(usages(&leaf), (true, false, false));
    assert_eq!(common_names(&leaf), [NODE_ID]);
    assert_eq!(sans(&leaf), [format!("URI(urn:jaunt:node:{NODE_ID})")]);

    let leaf = parsed(&server.certificate_der);
    assert_eq!(usages(&leaf), (false, true, false));
    assert_eq!(common_names(&leaf), ["agents.example.com"]);
    assert_eq!(
        sans(&leaf),
        ["DNSName(agents.example.com)", "DNSName(agents.example.net)"]
    );
}

#[test]
fn serials_are_random_positive_and_reported() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let serials: Vec<u128> = (0..8)
        .map(|_| {
            ca.issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
                .unwrap()
                .serial
        })
        .collect();
    for (index, serial) in serials.iter().enumerate() {
        assert!(*serial > 0 && *serial >> 127 == 0);
        assert!(!serials[..index].contains(serial));
    }
    assert!(serials.iter().any(|serial| *serial >> 100 != 0));
}

fn numbered(count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("agent{index}.example.com"))
        .collect()
}

#[test]
fn server_names_are_validated() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let sign = |names: &[&str]| {
        ca.issue_server_certificate(server_params(names, DEFAULT_SERVER_VALIDITY), now())
    };
    let nine = numbered(9);
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    let too_long = format!("{}.example.com", "a".repeat(250));
    let long_label = format!("{}.example.com", "a".repeat(64));
    let rejected: Vec<(&str, Vec<&str>)> = vec![
        ("no names", vec![]),
        ("nine names", nine),
        ("wildcard", vec!["*.example.com"]),
        ("ipv4", vec!["10.0.0.5"]),
        ("ipv6", vec!["fd00::1"]),
        ("bracketed ipv6", vec!["[::1]"]),
        ("empty label", vec!["agents..example.com"]),
        ("trailing dot", vec!["agents.example.com."]),
        ("leading dot", vec![".example.com"]),
        ("empty name", vec![""]),
        ("space", vec!["agents example.com"]),
        ("not ascii", vec!["agents.m\u{fc}nchen.example"]),
        ("duplicate", vec!["a.example.com", "a.example.com"]),
        (
            "duplicate ignoring case",
            vec!["A.example.com", "a.example.com"],
        ),
        ("too long", vec![too_long.as_str()]),
        ("good then bad", vec!["agents.example.com", "*.example.com"]),
        ("label of 64 characters", vec![long_label.as_str()]),
        ("label starting with a hyphen", vec!["-agents.example.com"]),
        ("label ending with a hyphen", vec!["agents-.example.com"]),
        ("numeric last label", vec!["foo.123"]),
        ("zero padded ipv4 lookalike", vec!["010.000.000.001"]),
    ];
    for (label, names) in rejected {
        assert!(
            matches!(sign(&names), Err(CaError::InvalidHostnames)),
            "{label}"
        );
    }
    let eight = numbered(8);
    let eight: Vec<&str> = eight.iter().map(String::as_str).collect();
    let longest_label = format!("{}.example.com", "a".repeat(63));
    assert!(sign(&eight).is_ok());
    assert!(sign(&["agents", "a_b-c.example.com", "AGENTS.Example.COM"]).is_ok());
    assert!(sign(&["agents.example.com", longest_label.as_str()]).is_ok());
}

#[test]
fn server_names_are_lowercased_in_the_subject_and_the_alternative_names() {
    let fixture = Fixture::new();
    let issued = fixture
        .ca()
        .issue_server_certificate(
            server_params(
                &["Agents.Example.COM", "OTHER.example.com"],
                DEFAULT_SERVER_VALIDITY,
            ),
            now(),
        )
        .unwrap();
    let leaf = parsed(&issued.certificate_der);
    assert_eq!(common_names(&leaf), ["agents.example.com"]);
    assert_eq!(
        sans(&leaf),
        ["DNSName(agents.example.com)", "DNSName(other.example.com)"]
    );
    let root = &fixture.root.certificate_der;
    let cert = &issued.certificate_der;
    assert!(verify_server(root, cert, "agents.example.com", NOW_SECS).is_ok());
    assert!(verify_server(root, cert, "other.example.com", NOW_SECS).is_ok());
}

#[test]
fn server_subject_respects_the_common_name_limit() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let sign = |names: &[&str]| {
        ca.issue_server_certificate(server_params(names, DEFAULT_SERVER_VALIDITY), now())
    };
    let longest = format!("{}.{}", "a".repeat(30), "b".repeat(33));
    let too_long = format!("{}.{}", "a".repeat(30), "b".repeat(34));
    assert_eq!(longest.len(), 64);
    assert!(sign(&[longest.as_str()]).is_ok());
    assert!(matches!(
        sign(&[too_long.as_str()]),
        Err(CaError::InvalidHostnames)
    ));
    assert!(sign(&["short.example.com", too_long.as_str()]).is_ok());
}
