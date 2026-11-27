use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::TrustRole;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::SanType;
use rcgen::string::Ia5String;

use super::support::{DAY, USER_ID, UserCa, UserSpec, ssh_fingerprint, user_uri};
use crate::keys::TlsKey;
use crate::runtime::x509::{
    CertRefusal, RootError, UserRoots, VALID_AFTER_LEEWAY_SECS, serial_of, verify_user,
};
use crate::testkit::{NODE_ID, TestPki, unix_now};

#[test]
fn a_user_certificate_yields_the_identity_control_computes() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let user = ca.issue(&UserSpec::valid(now));
    let roots = UserCa::roots(&[(&ca, TrustRole::Active)]);

    let verified = verify_user(&user.der, &roots, now).unwrap();

    assert_eq!(verified.user_id, USER_ID);
    assert_eq!(verified.serial, 4242);
    assert_eq!(verified.subject_fingerprint, user.subject_fingerprint());
    assert_eq!(verified.issuer_fingerprint, ca.fingerprint());
    assert_eq!(verified.subject_fingerprint.len(), 64);
}

#[test]
fn every_certificate_outside_the_user_profile_is_refused() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let roots = UserCa::roots(&[(&ca, TrustRole::Active)]);
    let valid = UserSpec::valid(now);
    let with = |adjust: &dyn Fn(&mut UserSpec)| {
        let mut spec = valid.clone();
        adjust(&mut spec);
        ca.issue(&spec).der
    };
    let foreign = UserCa::new(now).issue(&valid).der;
    let node_key = TlsKey::generate().unwrap();
    let node = STANDARD
        .decode(TestPki::new().node_x509(node_key.spki_der(), NODE_ID, now - 60, now + DAY))
        .unwrap();
    let uri = |text: &str| SanType::URI(Ia5String::try_from(text.to_owned()).unwrap());
    let cases: Vec<(&str, Vec<u8>, CertRefusal)> = vec![
        ("another CA", foreign, CertRefusal::Untrusted),
        ("a node certificate", node, CertRefusal::Untrusted),
        (
            "expired",
            with(&|spec| spec.not_after = now - 1),
            CertRefusal::Expired,
        ),
        (
            "ends right now",
            with(&|spec| spec.not_after = now),
            CertRefusal::Expired,
        ),
        (
            "not yet valid beyond the leeway",
            with(&|spec| spec.not_before = now + VALID_AFTER_LEEWAY_SECS + 1),
            CertRefusal::NotYetValid,
        ),
        (
            "a DNS name instead of the user",
            with(&|spec| spec.sans = vec![SanType::DnsName("alice.test".try_into().unwrap())]),
            CertRefusal::UserUri,
        ),
        (
            "no subject alternative name",
            with(&|spec| spec.sans = Vec::new()),
            CertRefusal::UserUri,
        ),
        (
            "a node urn",
            with(&|spec| spec.sans = vec![uri(&format!("urn:jaunt:node:{USER_ID}"))]),
            CertRefusal::UserUri,
        ),
        (
            "an upper-case user id",
            with(&|spec| spec.sans = vec![user_uri(&USER_ID.to_uppercase())]),
            CertRefusal::UserUri,
        ),
        (
            "two users",
            with(&|spec| {
                spec.sans = vec![
                    user_uri(USER_ID),
                    user_uri("0f8fad5b-d9cb-469f-a165-70867728950e"),
                ]
            }),
            CertRefusal::UserUri,
        ),
        (
            "an ECDSA key",
            with(&|spec| spec.ed25519 = false),
            CertRefusal::KeyType,
        ),
        (
            "server authentication only",
            with(&|spec| spec.usages = vec![ExtendedKeyUsagePurpose::ServerAuth]),
            CertRefusal::Untrusted,
        ),
        (
            "no extended key usage",
            with(&|spec| spec.usages = Vec::new()),
            CertRefusal::NotClientAuth,
        ),
        (
            "a CA certificate",
            with(&|spec| spec.ca = true),
            CertRefusal::Untrusted,
        ),
        (
            "serial zero",
            with(&|spec| spec.serial = vec![0]),
            CertRefusal::Serial,
        ),
        (
            "serial wider than 64 bits",
            with(&|spec| spec.serial = vec![1; 9]),
            CertRefusal::Serial,
        ),
        (
            "garbage",
            b"not a certificate".to_vec(),
            CertRefusal::Malformed,
        ),
    ];
    for (name, der, expected) in cases {
        assert_eq!(verify_user(&der, &roots, now), Err(expected), "{name}");
    }
    let edge = with(&|spec| spec.not_before = now + VALID_AFTER_LEEWAY_SECS);
    assert!(verify_user(&edge, &roots, now).is_ok());
    let widest = with(&|spec| spec.serial = vec![0xff; 8]);
    assert_eq!(verify_user(&widest, &roots, now).unwrap().serial, u64::MAX);
}

#[test]
fn an_empty_trust_set_refuses_even_a_good_certificate() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let user = ca.issue(&UserSpec::valid(now));
    assert_eq!(
        verify_user(&user.der, &UserRoots::default(), now),
        Err(CertRefusal::NoTrust)
    );
}

#[test]
fn next_and_previous_roots_verify_and_name_their_own_fingerprint() {
    let now = unix_now();
    let (active, next, previous) = (UserCa::new(now), UserCa::new(now), UserCa::new(now));
    let roots = UserCa::roots(&[
        (&active, TrustRole::Active),
        (&next, TrustRole::Next),
        (&previous, TrustRole::Previous),
    ]);
    for ca in [&active, &next, &previous] {
        let user = ca.issue(&UserSpec::valid(now));
        let verified = verify_user(&user.der, &roots, now).unwrap();
        assert_eq!(verified.issuer_fingerprint, ca.fingerprint());
    }
    let late = now + 6 * 365 * DAY;
    let mut spec = UserSpec::valid(late);
    spec.not_before = late - 60;
    let after_the_root = active.issue(&spec);
    assert_eq!(
        verify_user(&after_the_root.der, &roots, late),
        Err(CertRefusal::Untrusted)
    );
}

#[test]
fn a_trust_set_is_refused_whole_when_one_root_is_wrong() {
    let now = unix_now();
    let ca = UserCa::new(now);
    let good = ca.root(TrustRole::Active);
    let mut wrong_fingerprint = good.clone();
    wrong_fingerprint.fingerprint = ssh_fingerprint(&[7; 32]);
    let mut not_a_ca = good.clone();
    not_a_ca.certificate_der = STANDARD.encode(ca.issue(&UserSpec::valid(now)).der);
    let mut not_base64 = good.clone();
    not_base64.certificate_der = "***".to_owned();
    let cases = [
        (wrong_fingerprint, RootError::Fingerprint),
        (not_a_ca, RootError::NotCa),
        (not_base64, RootError::Encoding),
    ];
    for (bad, expected) in cases {
        assert_eq!(
            UserRoots::from_trust(&[good.clone(), bad], now).err(),
            Some(expected)
        );
    }
    let many = vec![good.clone(); 9];
    assert_eq!(
        UserRoots::from_trust(&many, now).err(),
        Some(RootError::TooMany)
    );
    assert_eq!(UserRoots::from_trust(&[good], now).unwrap().len(), 1);
}

#[test]
fn a_serial_is_a_positive_integer_of_at_most_sixty_four_bits() {
    let cases: [(&[u8], Option<u64>); 8] = [
        (&[0x80, 0x01], None),
        (&[0xff], None),
        (&[0x00, 0x80, 0x01], Some(0x8001)),
        (&[0x01], Some(1)),
        (&[0x00], None),
        (&[], None),
        (&[0x01, 0, 0, 0, 0, 0, 0, 0, 0], None),
        (
            &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            Some(u64::MAX),
        ),
    ];
    for (raw, expected) in cases {
        assert_eq!(serial_of(raw), expected, "{raw:02x?}");
    }
}

#[test]
fn a_root_counts_only_from_sixty_seconds_before_it_starts_until_it_ends() {
    let now = unix_now();
    for (starts_in, accepted) in [
        (VALID_AFTER_LEEWAY_SECS, true),
        (VALID_AFTER_LEEWAY_SECS + 1, false),
    ] {
        let ca = UserCa::with_validity(now + starts_in, now + DAY);
        let roots = UserCa::roots(&[(&ca, TrustRole::Next)]);
        let user = ca.issue(&UserSpec::valid(now));
        assert_eq!(
            verify_user(&user.der, &roots, now).is_ok(),
            accepted,
            "{starts_in}"
        );
    }
    let ended = UserCa::with_validity(now - 2 * DAY, now - 1);
    let active = UserCa::new(now);
    let roots = UserRoots::from_trust(
        &[
            ended.root(TrustRole::Previous),
            active.root(TrustRole::Active),
        ],
        now,
    )
    .unwrap();
    assert_eq!(roots.len(), 1);
    let ending_now = UserCa::with_validity(now - DAY, now);
    assert!(
        UserRoots::from_trust(&[ending_now.root(TrustRole::Previous)], now)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_root_must_be_a_self_issued_certificate_authority() {
    let now = unix_now();
    let leaf = UserCa::self_signed_leaf(now);
    assert_eq!(
        UserRoots::from_trust(&[leaf.root(TrustRole::Active)], now).err(),
        Some(RootError::NotCa)
    );
    let intermediate = UserCa::new(now).intermediate(now);
    assert_eq!(
        UserRoots::from_trust(&[intermediate.root(TrustRole::Active)], now).err(),
        Some(RootError::NotCa)
    );
}
