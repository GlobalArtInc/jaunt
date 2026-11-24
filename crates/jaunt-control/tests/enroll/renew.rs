use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::parse_node_identity;
use serde_json::{Value, json};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use crate::support::{
    Agent, Harness, host_certificate_is_valid, new_agent, sha256_hex_of_bytes,
    verify_node_certificate,
};

const FAIL_RECORDING: &str = "CREATE TRIGGER fail_certificate_insert BEFORE INSERT ON \
    node_certificates BEGIN SELECT RAISE(ABORT, 'forced'); END";

fn node_id_of(body: &Value) -> String {
    body["node_id"].as_str().unwrap().to_owned()
}

fn x509_of(body: &Value) -> Vec<u8> {
    STANDARD
        .decode(body["x509_certificate_der"].as_str().unwrap())
        .unwrap()
}

fn embeds_key(certificate_der: &[u8], agent: &Agent) -> bool {
    let raw = &agent.tls_der[12..];
    certificate_der
        .windows(raw.len())
        .any(|window| window == raw)
}

#[tokio::test]
async fn renewing_without_keys_reissues_certificates_for_the_stored_keys() {
    let harness = Harness::new().await;
    let (enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    harness.clock.advance(3 * 86_400);
    let now = harness.clock.now_secs();

    let reply = harness.renew(Some(&node_id), &json!({})).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    let der = x509_of(&body);
    verify_node_certificate(&harness.root_der, &der, now).unwrap();
    assert_eq!(
        parse_node_identity(&der).unwrap().node_id.to_string(),
        node_id
    );
    assert!(embeds_key(&der, &enrolled.agent));
    assert_eq!(body["x509_not_after"], now + 7 * 86_400);
    let host = host_certificate_is_valid(
        body["ssh_host_certificate"].as_str().unwrap(),
        &harness.host_ca,
        now,
    );
    assert_eq!(host.valid_principals(), ["web-01.jaunt.test", "web-01"]);
    assert_eq!(host.public_key(), enrolled.agent.ssh_public_key.key_data());
    assert!(body.get("node_id").is_none());
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn supplied_keys_rotate_the_stored_ones_together_with_the_new_records() {
    let harness = Harness::new().await;
    let (_enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    let rotated = new_agent();

    let reply = harness
        .renew(
            Some(&node_id),
            &json!({"tls_public_key": rotated.tls_public_key, "ssh_host_public_key": rotated.ssh_line}),
        )
        .await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    let now = harness.clock.now_secs();
    let der = x509_of(&body);
    verify_node_certificate(&harness.root_der, &der, now).unwrap();
    assert!(embeds_key(&der, &rotated));
    let host = host_certificate_is_valid(
        body["ssh_host_certificate"].as_str().unwrap(),
        &harness.host_ca,
        now,
    );
    assert_eq!(host.public_key(), rotated.ssh_public_key.key_data());
    let node = harness
        .store
        .nodes()
        .get_active(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.tls_public_key, rotated.tls_public_key);
    assert_eq!(node.tls_spki_sha256, sha256_hex_of_bytes(&rotated.tls_der));
    assert!(rotated.ssh_line.starts_with(&node.ssh_host_public_key));
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        4
    );

    let reused = harness.renew(Some(&node_id), &json!({})).await;
    assert!(
        embeds_key(&x509_of(&reused.json()), &rotated),
        "the rotated keys are the stored keys now"
    );
}

#[tokio::test]
async fn invalid_supplied_keys_are_refused_and_change_nothing() {
    let harness = Harness::new().await;
    let (enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    let good = new_agent();

    for (body, code) in [
        (
            json!({"tls_public_key": "garbage"}),
            "invalid_tls_public_key",
        ),
        (
            json!({"ssh_host_public_key": "garbage"}),
            "invalid_ssh_host_public_key",
        ),
        (
            json!({"tls_public_key": good.tls_public_key, "ssh_host_public_key": ""}),
            "invalid_ssh_host_public_key",
        ),
    ] {
        let reply = harness.renew(Some(&node_id), &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.error_code(), code);
    }

    let node = harness
        .store
        .nodes()
        .get_active(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.tls_public_key, enrolled.agent.tls_public_key);
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn a_failed_record_rolls_the_rotation_back_and_returns_no_certificates() {
    let harness = Harness::new().await;
    let (enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    let rotated = new_agent();
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&harness.db_path))
        .await
        .unwrap();
    sqlx::query(FAIL_RECORDING).execute(&pool).await.unwrap();

    let reply = harness
        .renew(
            Some(&node_id),
            &json!({"tls_public_key": rotated.tls_public_key}),
        )
        .await;

    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(reply.json().get("x509_certificate_der").is_none());
    let node = harness
        .store
        .nodes()
        .get_active(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(node.tls_public_key, enrolled.agent.tls_public_key);
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn a_removed_or_unknown_node_is_refused() {
    let harness = Harness::new().await;
    let (_enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    harness.admin.remove_node("web-01").await.unwrap();

    for id in [node_id.as_str(), "00000000-0000-4000-8000-000000000000", ""] {
        let reply = harness.renew(Some(id), &json!({})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{id:?}");
        assert_eq!(reply.json(), json!({"error": "node_removed"}));
    }
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn a_node_can_only_renew_itself() {
    let harness = Harness::new().await;
    let (_first, first_body) = harness.enrolled_node("web-01").await;
    let (_second, second_body) = harness.enrolled_node("web-02").await;
    let (first_id, second_id) = (node_id_of(&first_body), node_id_of(&second_body));

    let asking = harness
        .renew(Some(&first_id), &json!({"node_id": second_id}))
        .await;
    assert_eq!(asking.status, StatusCode::BAD_REQUEST);

    let reply = harness.renew(Some(&first_id), &json!({})).await;
    let der = x509_of(&reply.json());
    assert_eq!(
        parse_node_identity(&der).unwrap().node_id.to_string(),
        first_id
    );
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&second_id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&first_id)
            .await
            .unwrap()
            .len(),
        4
    );
}

#[tokio::test]
async fn renewal_without_an_authenticated_node_is_unauthorized() {
    let harness = Harness::new().await;
    let (_enrolled, delivered) = harness.enrolled_node("web-01").await;

    let reply = harness.renew(None, &json!({})).await;

    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(reply.body.is_empty());
    let node_id = node_id_of(&delivered);
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&node_id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn every_issuance_draws_a_fresh_and_larger_host_certificate_serial() {
    let harness = Harness::new().await;
    let (_enrolled, delivered) = harness.enrolled_node("web-01").await;
    let node_id = node_id_of(&delivered);
    let serial_of = |body: &Value| {
        jaunt_ca::ssh_key::Certificate::from_openssh(body["ssh_host_certificate"].as_str().unwrap())
            .unwrap()
            .serial()
    };

    let first = harness.renew(Some(&node_id), &json!({})).await.json();
    let second = harness.renew(Some(&node_id), &json!({})).await.json();

    let serials = [serial_of(&delivered), serial_of(&first), serial_of(&second)];
    assert!(
        serials[0] < serials[1] && serials[1] < serials[2],
        "{serials:?}"
    );
    let recorded: Vec<String> = harness
        .store
        .nodes()
        .certificates(&node_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|record| record.kind == jaunt_store::NodeCertificateKind::SshHost)
        .map(|record| record.serial)
        .collect();
    for serial in serials {
        assert!(recorded.contains(&format!("{serial:x}")), "{serial}");
    }
}
