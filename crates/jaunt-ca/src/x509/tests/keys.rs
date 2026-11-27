use std::fs;
use std::sync::Arc;

use rcgen::{KeyPair, PublicKeyData};
use ssh_key::public::{KeyData, SkEd25519};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, Signature};

use super::{DEFAULT_NODE_VALIDITY, Fixture, node_params, now, server_params, subject_key};
use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;
use crate::x509::key::SignerKey;
use crate::x509::{DEFAULT_SERVER_VALIDITY, InternalCa, SubjectPublicKey};

#[test]
fn internal_ca_can_be_shared_between_threads() {
    fn assert_shareable<T: Send + Sync>() {}
    assert_shareable::<InternalCa>();
}

#[test]
fn subject_key_must_be_a_valid_ed25519_key() {
    let good = subject_key();
    let ed25519 = *good.key_data().ed25519().unwrap();
    let security_key = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")));
    assert!(matches!(
        SubjectPublicKey::from_ssh_key(&security_key),
        Err(CaError::InvalidSubjectKey)
    ));

    let spki = SubjectPublicKey::from_ssh_key(&good)
        .unwrap()
        .subject_public_key_info();
    assert_eq!(
        SubjectPublicKey::from_spki_der(&spki).unwrap(),
        SubjectPublicKey::from_ssh_key(&good).unwrap()
    );
    assert_eq!(
        SubjectPublicKey::from_spki_der(&spki)
            .unwrap()
            .to_ssh_key()
            .key_data(),
        good.key_data()
    );

    let p256 = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap()
        .subject_public_key_info();
    let mut trailing = spki.clone();
    trailing.push(0);
    let mut weak = spki.clone();
    let tail = weak.len() - 32;
    weak[tail..].fill(0);
    weak[tail] = 1;
    for (label, der) in [
        ("p-256", p256),
        ("trailing byte", trailing),
        ("truncated", spki[..spki.len() - 1].to_vec()),
        ("small order point", weak),
        ("empty", Vec::new()),
        ("garbage", vec![0xff; 44]),
    ] {
        assert!(
            matches!(
                SubjectPublicKey::from_spki_der(&der),
                Err(CaError::InvalidSubjectKey)
            ),
            "{label}"
        );
    }
}

#[test]
fn the_authority_key_is_refused_as_a_subject_key() {
    let fixture = Fixture::new();
    let ca = fixture.ca();
    let own = SubjectPublicKey::from_ssh_key(fixture.authority.trust.active()).unwrap();

    let mut node = node_params(DEFAULT_NODE_VALIDITY);
    node.subject_public_key = own.clone();
    assert!(matches!(
        ca.issue_node_certificate(node, now()),
        Err(CaError::InvalidSubjectKey)
    ));
    let mut server = server_params(&["agents.example.com"], DEFAULT_SERVER_VALIDITY);
    server.subject_public_key = own;
    assert!(matches!(
        ca.issue_server_certificate(server, now()),
        Err(CaError::InvalidSubjectKey)
    ));
    assert!(
        ca.issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now())
            .is_ok()
    );
}

struct BrokenSigner {
    public: PublicKey,
    kind: CaKind,
    actual: Option<PrivateKey>,
}

impl Signer for BrokenSigner {
    fn kind(&self) -> CaKind {
        self.kind
    }

    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn try_sign(&self, msg: &[u8]) -> Result<Signature, CaError> {
        let key = self.actual.as_ref().ok_or(CaError::Sign)?;
        signature::Signer::try_sign(key, msg).map_err(|_| CaError::Sign)
    }
}

#[test]
fn signer_failures_forged_signatures_and_wrong_algorithms_are_rejected() {
    let fixture = Fixture::new();
    let real = fixture.authority.trust.active().clone();
    let broken = |actual: Option<PrivateKey>| BrokenSigner {
        public: real.clone(),
        kind: CaKind::Internal,
        actual,
    };

    let failing: Arc<dyn Signer> = Arc::new(broken(None));
    assert!(matches!(
        InternalCa::create_root(failing.as_ref(), now()),
        Err(CaError::Sign)
    ));
    let ca = InternalCa::new(failing, fixture.root.certificate_der.clone()).unwrap();
    assert!(matches!(
        ca.issue_node_certificate(node_params(DEFAULT_NODE_VALIDITY), now()),
        Err(CaError::Sign)
    ));

    let impostor: Arc<dyn Signer> = Arc::new(broken(Some(
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
    )));
    assert!(matches!(
        InternalCa::create_root(impostor.as_ref(), now()),
        Err(CaError::Sign)
    ));
    let ca = InternalCa::new(impostor, fixture.root.certificate_der.clone()).unwrap();
    assert!(matches!(
        ca.issue_server_certificate(
            server_params(&["agents.example.com"], DEFAULT_SERVER_VALIDITY),
            now()
        ),
        Err(CaError::Sign)
    ));

    let ed25519 = *real.key_data().ed25519().unwrap();
    let security_key = PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")));
    let wrong_algorithm = BrokenSigner {
        public: security_key,
        kind: CaKind::Internal,
        actual: None,
    };
    assert!(matches!(
        InternalCa::create_root(&wrong_algorithm, now()),
        Err(CaError::UnsupportedKeyAlgorithm)
    ));
}

#[test]
fn debug_output_never_shows_key_material() {
    let fixture = Fixture::new();
    let dir = fixture.authority.dir.path().join("internal");
    let encrypted = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "age"))
        .unwrap();
    let plaintext = fixture
        .authority
        .identity
        .decrypt(&fs::read(encrypted).unwrap(), 8 * 1024)
        .unwrap();
    let private = PrivateKey::from_openssh(&*plaintext).unwrap();
    let secret = private.key_data().ed25519().unwrap().private.to_bytes();
    let pem = private.to_openssh(LineEnding::LF).unwrap();

    let ca = fixture.ca();
    let adapter = SignerKey::new(&fixture.authority.backend, CaKind::Internal).unwrap();
    let printed = format!(
        "{ca:?} {ca:#?} {adapter:?} {adapter:#?} {:?}",
        fixture.authority.backend
    );
    assert!(printed.contains("InternalCa") && printed.contains("SignerKey"));
    let lower: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    assert!(!printed.to_lowercase().contains(&lower));
    assert!(!printed.contains(&format!("{secret:?}")));
    assert!(!printed.contains("PRIVATE KEY"));
    for body_line in pem.lines().filter(|line| line.len() > 20) {
        assert!(!printed.contains(body_line));
    }
}
