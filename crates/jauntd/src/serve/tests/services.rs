use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use jaunt_ca::{
    AgeIdentity, CaKind, ClientCa, SubjectPublicKey, UserX509Params, Uuid, fingerprint_hex,
};
use jaunt_gate::{StreamRefusal, TlsRefusal, UserX509Source};
use jaunt_proto::{GateTlsIssueError, GateTlsIssuer};
use jauntd::gate_services::ControlUserX509;
use rcgen::{KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use super::started_with;

const DOMAIN: &str = "svc.example.com";
const USER: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

fn tls13(
    roots: RootCertStore,
) -> rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert> {
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
}

#[test]
fn the_gate_takes_its_certificate_from_control_and_reads_user_certificates_as_control_does() {
    let (dir, runtime, started) = started_with(&format!(
        "agents_listen: 127.0.0.1:0\nservices:\n  domain: {DOMAIN}\n"
    ));
    let ca_root = dir.path().join("x509");
    let identity = AgeIdentity::generate();
    let now = SystemTime::now();
    ClientCa::init(&ca_root, CaKind::UserX509, &identity.recipient(), now).unwrap();
    let slot = ClientCa::load(&ca_root, CaKind::UserX509, &identity).unwrap();
    let active = fingerprint_hex(slot.trust.active());
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let subject = SubjectPublicKey::from_spki_der(&key.subject_public_key_info()).unwrap();
    let issued = slot
        .ca
        .issue_user_certificate(
            UserX509Params {
                subject_public_key: subject.clone(),
                user_id: Uuid::parse_str(USER).unwrap(),
                email: "alice@example.com".to_owned(),
                serial: 77,
                valid_before: now + Duration::from_secs(3600),
            },
            now,
        )
        .unwrap();
    started.control.replace_user_x509(slot).unwrap();
    let certificate = CertificateDer::from(issued.certificate_der);

    runtime.block_on(async {
        let gate_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        assert_eq!(
            GateTlsIssuer::issue(
                &started.control,
                &gate_key.subject_public_key_info(),
                "other.example.com"
            )
            .await
            .err(),
            Some(GateTlsIssueError::NameRefused)
        );

        let roots = ControlUserX509::new(started.control.clone())
            .current()
            .unwrap();
        assert_eq!(roots.fingerprints(), [active.as_str()]);
        let seen = roots
            .identify(Some(std::slice::from_ref(&certificate)), UnixTime::now())
            .unwrap();
        assert_eq!(seen.user_id, USER);
        assert_eq!(seen.serial, 77);
        assert_eq!(
            seen.subject_fingerprint,
            fingerprint_hex(&subject.to_ssh_key())
        );
        assert_eq!(seen.issuer_fingerprint, active);

        let agents = super::super::start_agents(
            started.agents.clone(),
            started.entry.clone(),
            &started.control,
            started.store.clone(),
        )
        .await
        .unwrap()
        .unwrap();
        let services = super::super::start_services(
            Some(DOMAIN.to_owned()),
            Some(&agents),
            None,
            &started.control,
        )
        .await
        .unwrap()
        .unwrap();

        let mut internal = RootCertStore::empty();
        internal
            .add(CertificateDer::from(
                started.control.internal_root_der().to_vec(),
            ))
            .unwrap();
        let mut outer = tls13(internal)
            .with_client_auth_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        outer.alpn_protocols = vec![b"jaunt-svc/1".to_vec()];
        let tcp = tokio::net::TcpStream::connect(agents.local_addr())
            .await
            .unwrap();
        let outer = tokio::time::timeout(
            Duration::from_secs(10),
            TlsConnector::from(Arc::new(outer)).connect(ServerName::try_from(DOMAIN).unwrap(), tcp),
        )
        .await
        .unwrap()
        .unwrap();
        let inner = tls13(RootCertStore::empty()).with_no_client_auth();
        let refused = tokio::time::timeout(
            Duration::from_secs(10),
            TlsConnector::from(Arc::new(inner)).connect(
                ServerName::try_from(format!("lk.db.{DOMAIN}")).unwrap(),
                outer,
            ),
        )
        .await
        .unwrap();
        assert!(refused.is_err());
        let deadline = Instant::now() + Duration::from_secs(10);
        while services.gate().svc_refused(StreamRefusal::Denied) != 1 {
            assert!(
                Instant::now() < deadline,
                "control did not deny the unknown user"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(agents.tls_refused(TlsRefusal::ClientCertificate), 0);
        assert_eq!(agents.tls_refused(TlsRefusal::UnsupportedClass), 0);
        services.shutdown(Duration::from_secs(5)).await;
        agents.shutdown(Duration::from_secs(5)).await;
    });
    started.watcher.stop();
}
