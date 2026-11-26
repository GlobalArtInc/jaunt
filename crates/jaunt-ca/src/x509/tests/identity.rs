use rcgen::SanType;
use ssh_key::sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Fixture, NODE_ID, crafted, dns, node_params, now, server_params, subject, uri};
use crate::error::CaError;
use crate::x509::{DEFAULT_NODE_VALIDITY, DEFAULT_SERVER_VALIDITY, parse_node_identity};

const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[test]
fn node_identity_carries_the_sha256_of_the_certified_key() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let params = node_params(DEFAULT_NODE_VALIDITY);
    let spki = [
        ED25519_SPKI_PREFIX.as_slice(),
        params.subject_public_key.raw(),
    ]
    .concat();
    let expected: [u8; 32] = Sha256::digest(&spki).into();
    let issued = ca.issue_node_certificate(params, now()).unwrap();

    let identity = parse_node_identity(&issued.certificate_der).unwrap();

    assert_eq!(identity.subject_public_key_sha256, expected);
    let other = ca
        .issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
        .unwrap();
    let other_identity = parse_node_identity(&other.certificate_der).unwrap();
    assert_eq!(other_identity.node_id, identity.node_id);
    assert_ne!(other_identity.subject_public_key_sha256, expected);
}

#[test]
fn node_identity_requires_exactly_one_canonical_uri() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let key = subject();
    let good = format!("urn:jaunt:node:{NODE_ID}");
    let sign = |san: Vec<SanType>| ca.issuer.sign(&crafted(san), &key).unwrap();

    let accepted = parse_node_identity(&sign(vec![uri(&good)])).unwrap();
    assert_eq!(accepted.node_id.to_string(), NODE_ID);

    let upper = format!("urn:jaunt:node:{}", NODE_ID.to_uppercase());
    let simple = format!("urn:jaunt:node:{}", NODE_ID.replace('-', ""));
    let nil = format!("urn:jaunt:node:{}", Uuid::nil());
    let rejected = [
        ("two uris", vec![uri(&good), uri("urn:jaunt:node:other")]),
        ("same uri twice", vec![uri(&good), uri(&good)]),
        ("not a uuid", vec![uri("urn:jaunt:node:web-01")]),
        ("uppercase uuid", vec![uri(&upper)]),
        ("simple uuid", vec![uri(&simple)]),
        ("nil uuid", vec![uri(&nil)]),
        (
            "other scheme",
            vec![uri(&format!("urn:jaunt:user:{NODE_ID}"))],
        ),
        (
            "https",
            vec![uri(&format!("https://example.com/{NODE_ID}"))],
        ),
        ("uri and dns", vec![uri(&good), dns("agents.example.com")]),
        ("dns only", vec![dns("agents.example.com")]),
        ("no names", Vec::new()),
    ];
    for (label, san) in rejected {
        assert!(
            matches!(
                parse_node_identity(&sign(san)),
                Err(CaError::InvalidNodeIdentity)
            ),
            "{label}"
        );
    }

    let server = ca
        .issue_server_certificate(
            server_params(&["agents.example.com"], DEFAULT_SERVER_VALIDITY),
            now(),
        )
        .unwrap();
    assert!(matches!(
        parse_node_identity(&server.certificate_der),
        Err(CaError::InvalidNodeIdentity)
    ));
    let mut trailing = sign(vec![uri(&good)]);
    trailing.push(0);
    for garbage in [Vec::new(), vec![0x30, 0x00], trailing] {
        assert!(matches!(
            parse_node_identity(&garbage),
            Err(CaError::InvalidNodeIdentity)
        ));
    }
}
