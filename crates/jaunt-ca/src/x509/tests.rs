mod identity;
mod issuance;
mod keys;
mod root;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, SanType};
use uuid::Uuid;
use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;

use super::{
    DEFAULT_NODE_VALIDITY, InternalCa, IssuedCertificate, MAX_NODE_VALIDITY, NodeCertParams,
    ServerCertParams, SubjectPublicKey, common_name, serial_number, set_window,
};
use crate::cert::window;
use crate::kind::CaKind;
use crate::test_support::{Authority, authority, subject_key};

const NOW_SECS: u64 = 1_700_000_000;
const NODE_ID: &str = "8d3b7c0e-5f0a-4c1b-9a64-2f7d9e1c4b10";
const DAY: u64 = 24 * 60 * 60;

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

struct Fixture {
    authority: Authority,
    root: IssuedCertificate,
}

impl Fixture {
    fn new() -> Self {
        let authority = authority(CaKind::Internal);
        let root = InternalCa::create_root(&authority.backend, now()).unwrap();
        Self { authority, root }
    }

    fn ca(&self) -> InternalCa<'_> {
        InternalCa::new(&self.authority.backend, self.root.certificate_der.clone()).unwrap()
    }
}

fn subject() -> SubjectPublicKey {
    SubjectPublicKey::from_ssh_key(&subject_key()).unwrap()
}

fn node_params(validity: Duration) -> NodeCertParams {
    NodeCertParams {
        subject_public_key: subject(),
        node_id: Uuid::parse_str(NODE_ID).unwrap(),
        validity,
    }
}

fn server_params(names: &[&str], validity: Duration) -> ServerCertParams {
    ServerCertParams {
        subject_public_key: subject(),
        dns_names: names.iter().map(|name| (*name).to_owned()).collect(),
        validity,
    }
}

fn parsed(der: &[u8]) -> X509Certificate<'_> {
    let (rest, certificate) = parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty());
    certificate
}

fn common_names(certificate: &X509Certificate<'_>) -> Vec<String> {
    certificate
        .subject()
        .iter_common_name()
        .map(|name| name.as_str().unwrap().to_owned())
        .collect()
}

fn der_serial(certificate: &X509Certificate<'_>) -> u128 {
    certificate
        .raw_serial()
        .iter()
        .fold(0u128, |value, byte| (value << 8) | u128::from(*byte))
}

fn crafted(san: Vec<SanType>) -> CertificateParams {
    let mut params = CertificateParams::default();
    let window = window(now(), DEFAULT_NODE_VALIDITY, MAX_NODE_VALIDITY).unwrap();
    set_window(&mut params, &window).unwrap();
    params.serial_number = Some(serial_number(7));
    params.distinguished_name = common_name("crafted");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = san;
    params
}

fn uri(text: &str) -> SanType {
    SanType::URI(text.to_owned().try_into().unwrap())
}

fn dns(text: &str) -> SanType {
    SanType::DnsName(text.to_owned().try_into().unwrap())
}
