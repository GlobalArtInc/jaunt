use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_audit::{AuditTap, system_clock};
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::sha2::{Digest, Sha256};
use jaunt_ca::ssh_key::{Algorithm, PrivateKey};
use jaunt_control::AuthenticatedNode;
use jaunt_store::{CreateOutcome, EnrollmentLimits, NewEnrollment, Store};
use tower::ServiceExt;

use super::{fake_discovery, secret_only, start, write_config};
use jauntd::{ca, config};

const CODE: &str = "ABCD-2345";
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn pending_enrollment(store: &Store, now: i64) {
    let tls_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let raw = tls_private.public_key().key_data().ed25519().unwrap().0;
    let tls_der = [SPKI_PREFIX.as_slice(), raw.as_slice()].concat();
    let ssh_private = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let created = store
        .enrollments()
        .create(
            &NewEnrollment {
                handle_hash: hex(b"web-01"),
                code_hash: hex(CODE.replace('-', "").as_bytes()),
                name: "web-01".to_owned(),
                labels: [("env".to_owned(), "prod".to_owned())].into(),
                hostname: "web-01.example.com".to_owned(),
                source_ip: "203.0.113.5".to_owned(),
                peer_addr: "203.0.113.5".to_owned(),
                tls_public_key: STANDARD.encode(&tls_der),
                ssh_host_public_key: ssh_private.public_key().to_openssh().unwrap(),
                replace_existing: false,
                agent_version: "0.1.0".to_owned(),
                ttl_secs: 900,
            },
            EnrollmentLimits {
                max_pending: 10,
                max_pending_per_ip: 10,
            },
            now,
        )
        .await
        .unwrap();
    assert!(matches!(created, CreateOutcome::Created(_)));
}

#[test]
fn the_agent_trust_route_serves_the_user_key_printed_by_ca_init() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("policy")).unwrap();
    let path = write_config(dir.path(), "");
    let mut settings = config::load(&path)
        .unwrap()
        .into_run_settings(&secret_only)
        .unwrap();
    settings.oidc.issuer_url = fake_discovery();
    let printed = ca::run(&settings.data_dir, true, &secret_only, SystemTime::now());
    assert_eq!(printed.code, 0);
    let user_ca = printed
        .stdout
        .lines()
        .find_map(|line| line.strip_prefix("user-ca "))
        .unwrap()
        .to_owned();
    let authorities = ca::load_authorities(&settings.data_dir, &secret_only).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let started = runtime
        .block_on(start(settings, authorities, &AuditTap::new(system_clock())))
        .unwrap();
    let (status, body) = runtime.block_on(async {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        pending_enrollment(&started.store, i64::try_from(now.as_secs()).unwrap()).await;
        let approved = started
            .control
            .node_admin()
            .approve(CODE, "cli:tester", None)
            .await
            .unwrap();
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/v1/agent/trust")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(AuthenticatedNode(approved.node.id));
        let response = started
            .control
            .agent_router()
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    });
    started.watcher.stop();

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, format!(r#"{{"user_ca_keys":["{user_ca}"]}}"#));
}
