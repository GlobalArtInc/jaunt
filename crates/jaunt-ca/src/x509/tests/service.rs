use std::time::Duration;

use rustls::Error as TlsError;

use super::issuance::{is_wrong_name, sans, usages, verify_server};
use super::{DAY, Fixture, NOW_SECS, now, openssl, openssl_verify_with, parsed, pem, subject};
use crate::error::CaError;
use crate::test_support::verify_client;
use crate::x509::{
    DEFAULT_SERVICE_VALIDITY, InternalCa, IssuedCertificate, MAX_SERVER_VALIDITY, ServerCertParams,
};

fn long_name() -> String {
    format!("{}.kube.svc.example.com", "a".repeat(63))
}

fn params(names: &[&str], validity: Duration) -> ServerCertParams {
    ServerCertParams {
        subject_public_key: subject(),
        dns_names: names.iter().map(|name| (*name).to_owned()).collect(),
        validity,
    }
}

fn service(
    ca: &InternalCa,
    names: &[&str],
    validity: Duration,
) -> Result<IssuedCertificate, CaError> {
    ca.issue_service_certificate(params(names, validity), now())
}

#[test]
fn service_certificate_names_the_service_only_in_a_critical_alternative_name() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let name = long_name();
    assert!(name.len() > 64);
    let issued = service(&ca, &[&name], DEFAULT_SERVICE_VALIDITY).unwrap();
    let leaf = parsed(&issued.certificate_der);

    assert_eq!(leaf.subject().iter_attributes().count(), 0);
    let san = leaf.subject_alternative_name().unwrap().unwrap();
    assert!(san.critical);
    assert_eq!(sans(&leaf), [format!("DNSName({name})")]);
    assert_eq!(usages(&leaf), (false, true, false));
    assert_eq!(issued.not_after, now() + Duration::from_secs(7 * DAY));
    assert_eq!(DEFAULT_SERVICE_VALIDITY, Duration::from_secs(7 * DAY));

    let root = &fixture.root.certificate_der;
    let cert = &issued.certificate_der;
    assert!(verify_server(root, cert, &name, NOW_SECS).is_ok());
    let other = format!("{}.kube.svc.example.com", "b".repeat(63));
    assert!(is_wrong_name(
        &verify_server(root, cert, &other, NOW_SECS).unwrap_err()
    ));
    assert!(matches!(
        verify_client(root, cert, NOW_SECS),
        Err(TlsError::InvalidCertificate(_))
    ));
    assert!(matches!(
        ca.issue_server_certificate(params(&[&name], DEFAULT_SERVICE_VALIDITY), now()),
        Err(CaError::InvalidHostnames)
    ));
}

#[test]
fn service_certificate_validity_and_names_are_bounded() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let name = "lk-ru-prod.db.svc.example.com";
    for validity in [
        Duration::ZERO,
        MAX_SERVER_VALIDITY + Duration::from_nanos(1),
    ] {
        assert!(
            matches!(
                service(&ca, &[name], validity),
                Err(CaError::InvalidValidity { .. })
            ),
            "{validity:?}"
        );
    }
    assert!(service(&ca, &[name], MAX_SERVER_VALIDITY).is_ok());

    let long_label = format!("{}.db.example.com", "a".repeat(64));
    let nine: Vec<String> = (0..9)
        .map(|index| format!("s{index}.db.example.com"))
        .collect();
    let nine: Vec<&str> = nine.iter().map(String::as_str).collect();
    let labels = |last: usize| {
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(last)
        )
    };
    let (longest, too_long) = (labels(61), labels(62));
    assert_eq!((longest.len(), too_long.len()), (253, 254));
    let rejected: Vec<(&str, Vec<&str>)> = vec![
        ("no names", vec![]),
        ("nine names", nine),
        ("wildcard", vec!["*.kube.svc.example.com"]),
        ("ip address", vec!["10.0.0.5"]),
        ("label of 64 characters", vec![long_label.as_str()]),
        ("name of 254 characters", vec![too_long.as_str()]),
        ("empty label", vec!["db..example.com"]),
    ];
    for (label, names) in rejected {
        assert!(
            matches!(
                service(&ca, &names, DEFAULT_SERVICE_VALIDITY),
                Err(CaError::InvalidHostnames)
            ),
            "{label}"
        );
    }
    let issued = service(
        &ca,
        &[longest.as_str(), "Grafana.TCP.svc.example.com"],
        DEFAULT_SERVICE_VALIDITY,
    )
    .unwrap();
    assert_eq!(
        sans(&parsed(&issued.certificate_der)),
        [
            format!("DNSName({longest})"),
            "DNSName(grafana.tcp.svc.example.com)".to_owned()
        ]
    );
}

#[test]
fn openssl_accepts_a_service_certificate_for_its_long_name_only() {
    let Some(openssl) = openssl() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let fixture = Fixture::new();
    let name = long_name();
    let issued = service(&fixture.ca(), &[&name], DEFAULT_SERVICE_VALIDITY).unwrap();
    let root = pem(openssl, dir.path(), "root", &fixture.root.certificate_der);
    let leaf = pem(openssl, dir.path(), "service", &issued.certificate_der);
    let other = format!("{}.kube.svc.example.com", "b".repeat(63));
    let verify = |purpose: &str, host: &str| {
        openssl_verify_with(
            openssl,
            &root,
            &leaf,
            purpose,
            NOW_SECS,
            &["-x509_strict", "-verify_hostname", host],
        )
    };

    assert!(verify("sslserver", &name));
    assert!(!verify("sslserver", &other));
    assert!(!verify("sslclient", &name));
}
