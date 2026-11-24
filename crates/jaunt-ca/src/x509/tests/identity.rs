use rcgen::SanType;
use uuid::Uuid;

use super::{Fixture, NODE_ID, crafted, dns, now, server_params, subject, uri};
use crate::error::CaError;
use crate::x509::{DEFAULT_SERVER_VALIDITY, parse_node_identity};

#[test]
fn node_identity_requires_exactly_one_canonical_uri() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let key = subject();
    let good = format!("urn:jaunt:node:{NODE_ID}");
    let sign = |san: Vec<SanType>| ca.sign(&crafted(san), &key).unwrap();

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
