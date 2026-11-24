use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyUsagePurpose};

use super::{
    DAY, DEFAULT_NODE_VALIDITY, Fixture, NOW_SECS, common_name, common_names, crafted, der_serial,
    node_params, now, parsed, subject,
};
use crate::error::CaError;
use crate::kind::CaKind;
use crate::test_support::authority;
use crate::x509::key::SignerKey;
use crate::x509::{InternalCa, ROOT_COMMON_NAME, SubjectPublicKey, key_identifier};

#[test]
fn root_certificate_has_the_authority_profile() {
    let fixture = Fixture::new();
    let der = &fixture.root.certificate_der;
    let root = parsed(der);

    let constraints = root.basic_constraints().unwrap().unwrap();
    assert!(constraints.critical);
    assert!(constraints.value.ca);
    assert_eq!(constraints.value.path_len_constraint, Some(0));
    let usage = root.key_usage().unwrap().unwrap();
    assert!(usage.critical);
    assert!(usage.value.key_cert_sign() && usage.value.crl_sign());
    assert_eq!(usage.value.flags, 0b110_0000);
    assert!(root.extended_key_usage().unwrap().is_none());
    assert_eq!(root.subject().as_raw(), root.issuer().as_raw());
    assert_eq!(common_names(&root), ["Jaunt Internal CA"]);
    assert_eq!(root.subject().iter_attributes().count(), 1);

    let validity = root.validity();
    let expected_after = i64::try_from(NOW_SECS + 3650 * DAY).unwrap();
    assert_eq!(
        validity.not_before.timestamp(),
        i64::try_from(NOW_SECS - 120).unwrap()
    );
    assert_eq!(validity.not_after.timestamp(), expected_after);
    assert_eq!(der_serial(&root), fixture.root.serial);
    assert!(fixture.root.serial > 0 && fixture.root.serial >> 127 == 0);
    let authority_key = fixture
        .authority
        .trust
        .active()
        .key_data()
        .ed25519()
        .unwrap();
    assert_eq!(
        root.public_key().subject_public_key.data.as_ref(),
        authority_key.0.as_slice()
    );
    assert_eq!(fixture.ca().root_der(), der.as_slice());
}

#[test]
fn internal_ca_accepts_only_its_own_root() {
    let fixture = Fixture::new();
    let der = fixture.root.certificate_der.clone();
    let other = Fixture::new();
    let node = fixture
        .ca()
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();

    let mut tampered = der.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let mut trailing = der.clone();
    trailing.push(0);
    for (label, root) in [
        ("another authority", other.root.certificate_der.clone()),
        ("not a certificate authority", node.certificate_der),
        ("tampered signature", tampered),
        ("trailing data", trailing),
        ("garbage", vec![0x30, 0x03, 0x02, 0x01, 0x00]),
        ("empty", Vec::new()),
    ] {
        assert!(
            matches!(
                InternalCa::new(fixture.authority.shared_signer(), root),
                Err(CaError::InvalidRootCertificate { .. })
            ),
            "{label}"
        );
    }

    let user = authority(CaKind::User);
    assert!(matches!(
        InternalCa::new(user.shared_signer(), der.clone()),
        Err(CaError::WrongAuthorityKind {
            expected: CaKind::Internal
        })
    ));
    assert!(matches!(
        InternalCa::create_root(&user.backend, now()),
        Err(CaError::WrongAuthorityKind {
            expected: CaKind::Internal
        })
    ));
    assert!(InternalCa::new(fixture.authority.shared_signer(), der).is_ok());
}

type Edit = fn(&mut CertificateParams);
type Case<'a> = (&'a str, &'a SubjectPublicKey, Edit, &'a str);

fn crafted_root(key: &SignerKey<'_>, subject: &SubjectPublicKey, edit: Edit) -> Vec<u8> {
    let mut params = crafted(Vec::new());
    params.distinguished_name = common_name(ROOT_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = Vec::new();
    params.key_identifier_method = key_identifier(key.raw());
    edit(&mut params);
    let mut issuer_params = params.clone();
    issuer_params.distinguished_name = common_name(ROOT_COMMON_NAME);
    let issuer = Issuer::from_params(&issuer_params, key);
    params.signed_by(subject, &issuer).unwrap().der().to_vec()
}

#[test]
fn each_root_check_rejects_an_otherwise_valid_root() {
    let fixture = Fixture::new();
    let backend = &fixture.authority.backend;
    let key = SignerKey::new(backend, CaKind::Internal).unwrap();
    let own = SubjectPublicKey::from_ssh_key(fixture.authority.trust.active()).unwrap();
    let foreign = subject();

    let control = crafted_root(&key, &own, |_| {});
    assert!(InternalCa::new(fixture.authority.shared_signer(), control).is_ok());

    let cases: [Case<'_>; 6] = [
        (
            "unconstrained path length",
            &own,
            |params| params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained),
            "path length 0",
        ),
        (
            "path length 1",
            &own,
            |params| params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1)),
            "path length 0",
        ),
        (
            "not a certificate authority",
            &own,
            |params| params.is_ca = IsCa::ExplicitNoCa,
            "path length 0",
        ),
        (
            "no certificate signing usage",
            &own,
            |params| params.key_usages = vec![KeyUsagePurpose::DigitalSignature],
            "may not sign",
        ),
        (
            "same key, different subject name",
            &own,
            |params| params.distinguished_name = common_name("Somebody Else"),
            "not self-signed",
        ),
        (
            "same name, different key",
            &foreign,
            |_| {},
            "not issued for the authority key",
        ),
    ];
    for (label, subject_key, edit, expected) in cases {
        let der = crafted_root(&key, subject_key, edit);
        match InternalCa::new(fixture.authority.shared_signer(), der) {
            Err(CaError::InvalidRootCertificate { reason }) => {
                assert!(reason.contains(expected), "{label}: {reason}");
            }
            other => panic!("{label}: {other:?}"),
        }
    }
}
