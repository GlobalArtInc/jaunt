use std::path::Path;

use jaunt_store::{NodeHostCertificate, NodeTrustServed, Store, UnexpiredGroup};
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 1_700_000_000;
const VERSION_BEFORE_CA_ROTATION: i64 = 8;

const RAW_USER: &str = "INSERT INTO users (id, issuer, subject, email, display_name, groups, \
    created_at, updated_at) VALUES ('u1', 'https://idp.example', 's1', 'ada@example.com', NULL, \
    '[]', 1, 1)";

const RAW_CERTIFICATE: &str = "INSERT INTO certificates (serial, user_id, kind, key_id, \
    valid_after, valid_before, issued_at) VALUES (?, 'u1', 'user', 'k', 1, ?, 1)";

const STAMP_CERTIFICATE: &str =
    "UPDATE certificates SET ca_fingerprint = ?, host_trust_id = ? WHERE serial = ?";

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', ?, 'cli:root', 1)";

const SERVE_NODE: &str = "UPDATE nodes SET trust_served_id = ?, trust_served_at = ? WHERE id = ?";

const RAW_NODE_CERTIFICATE: &str = "INSERT INTO node_certificates (id, node_id, kind, serial, \
    not_before, not_after, issued_at) VALUES (?, ?, ?, 'ab', 1, ?, ?)";

const STAMP_NODE_CERTIFICATE: &str = "UPDATE node_certificates SET ca_fingerprint = ? WHERE id = ?";

async fn raw_pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true),
    )
    .await
    .unwrap()
}

async fn open() -> (TempDir, Store, SqlitePool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let pool = raw_pool(&path).await;
    sqlx::query(RAW_USER).execute(&pool).await.unwrap();
    (dir, store, pool)
}

async fn certificate(
    pool: &SqlitePool,
    serial: i64,
    valid_before: i64,
    signer: Option<&str>,
    host_trust: Option<&str>,
) {
    sqlx::query(RAW_CERTIFICATE)
        .bind(serial)
        .bind(valid_before)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(STAMP_CERTIFICATE)
        .bind(signer)
        .bind(host_trust)
        .bind(serial)
        .execute(pool)
        .await
        .unwrap();
}

async fn node(pool: &SqlitePool, id: &str, name: &str, state: &str) {
    sqlx::query(RAW_NODE)
        .bind(id)
        .bind(name)
        .bind(state)
        .execute(pool)
        .await
        .unwrap();
}

async fn node_certificate(
    pool: &SqlitePool,
    id: &str,
    node_id: &str,
    kind: &str,
    (not_after, issued_at): (i64, i64),
    signer: Option<&str>,
) {
    sqlx::query(RAW_NODE_CERTIFICATE)
        .bind(id)
        .bind(node_id)
        .bind(kind)
        .bind(not_after)
        .bind(issued_at)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(STAMP_NODE_CERTIFICATE)
        .bind(signer)
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
}

fn group(id: Option<&str>, count: i64, nearest: i64, farthest: i64) -> UnexpiredGroup {
    UnexpiredGroup {
        id: id.map(str::to_owned),
        count,
        nearest_valid_before: nearest,
        farthest_valid_before: farthest,
    }
}

#[tokio::test]
async fn unexpired_certificates_are_grouped_by_signer_and_host_trust_and_expire_at_valid_before() {
    let (_dir, store, pool) = open().await;
    certificate(&pool, 1, NOW + 100, Some("aa"), Some("h1")).await;
    certificate(&pool, 2, NOW + 50, Some("aa"), Some("h1")).await;
    certificate(&pool, 3, NOW + 10, Some("bb"), Some("h2")).await;
    certificate(&pool, 4, NOW + 5, None, None).await;
    certificate(&pool, 5, NOW, Some("aa"), Some("h1")).await;
    certificate(&pool, 6, NOW - 1, Some("bb"), None).await;
    let counters = store.ca_counters();

    assert_eq!(
        counters.certificates_by_signer(NOW).await.unwrap(),
        [
            group(None, 1, NOW + 5, NOW + 5),
            group(Some("aa"), 2, NOW + 50, NOW + 100),
            group(Some("bb"), 1, NOW + 10, NOW + 10),
        ]
    );
    assert_eq!(
        counters.certificates_by_host_trust(NOW).await.unwrap(),
        [
            group(None, 1, NOW + 5, NOW + 5),
            group(Some("h1"), 2, NOW + 50, NOW + 100),
            group(Some("h2"), 1, NOW + 10, NOW + 10),
        ]
    );
    assert_eq!(
        counters.certificates_by_signer(NOW - 1).await.unwrap()[1],
        group(Some("aa"), 3, NOW, NOW + 100)
    );
    assert!(
        counters
            .certificates_by_signer(NOW + 100)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rows_written_before_the_migration_have_no_signer_and_no_trust_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let pool = raw_pool(&path).await;
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run_to(VERSION_BEFORE_CA_ROTATION, &pool)
        .await
        .unwrap();
    sqlx::query(RAW_USER).execute(&pool).await.unwrap();
    sqlx::query(RAW_CERTIFICATE)
        .bind(1_i64)
        .bind(NOW + 60)
        .execute(&pool)
        .await
        .unwrap();
    node(&pool, "n1", "web-01", "active").await;
    sqlx::query(RAW_NODE_CERTIFICATE)
        .bind("c1")
        .bind("n1")
        .bind("ssh-host")
        .bind(NOW + 60)
        .bind(NOW)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let counters = store.ca_counters();

    assert_eq!(
        counters.certificates_by_signer(NOW).await.unwrap(),
        [group(None, 1, NOW + 60, NOW + 60)]
    );
    assert_eq!(
        counters.certificates_by_host_trust(NOW).await.unwrap(),
        [group(None, 1, NOW + 60, NOW + 60)]
    );
    assert_eq!(
        counters.node_trust().await.unwrap(),
        [NodeTrustServed {
            node_id: "n1".to_owned(),
            name: "web-01".to_owned(),
            trust_id: None,
            served_at: None,
        }]
    );
    assert_eq!(
        counters.latest_node_host_certificates().await.unwrap(),
        [NodeHostCertificate {
            node_id: "n1".to_owned(),
            name: "web-01".to_owned(),
            ca_fingerprint: None,
            not_after: NOW + 60,
        }]
    );
}

#[tokio::test]
async fn node_trust_lists_only_active_nodes_with_what_they_were_served() {
    let (_dir, store, pool) = open().await;
    node(&pool, "n1", "web-01", "active").await;
    node(&pool, "n2", "db-01", "active").await;
    node(&pool, "n3", "gone", "removed").await;
    for (id, trust) in [("n1", "t1"), ("n3", "t0")] {
        sqlx::query(SERVE_NODE)
            .bind(trust)
            .bind(NOW)
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }

    let served = store.ca_counters().node_trust().await.unwrap();

    let shown: Vec<(&str, Option<&str>, Option<i64>)> = served
        .iter()
        .map(|node| (node.name.as_str(), node.trust_id.as_deref(), node.served_at))
        .collect();
    assert_eq!(
        shown,
        [("db-01", None, None), ("web-01", Some("t1"), Some(NOW))]
    );
}

#[tokio::test]
async fn only_the_latest_host_certificate_of_each_active_node_is_reported() {
    let (_dir, store, pool) = open().await;
    node(&pool, "n1", "web-01", "active").await;
    node(&pool, "n2", "db-01", "active").await;
    node(&pool, "n3", "gone", "removed").await;
    node(&pool, "n4", "fresh", "active").await;
    node_certificate(&pool, "c1", "n1", "ssh-host", (NOW + 100, 1), Some("aa")).await;
    node_certificate(&pool, "c2", "n1", "ssh-host", (NOW + 200, 2), Some("bb")).await;
    node_certificate(&pool, "c2x", "n1", "x509", (NOW + 400, 2), None).await;
    node_certificate(&pool, "c3", "n1", "x509", (NOW + 300, 3), Some("cc")).await;
    node_certificate(&pool, "c4", "n2", "ssh-host", (NOW + 50, 5), Some("aa")).await;
    node_certificate(&pool, "c5", "n2", "ssh-host", (NOW + 60, 5), None).await;
    node_certificate(&pool, "c5x", "n2", "x509", (NOW + 500, 5), Some("aa")).await;
    node_certificate(&pool, "c6", "n3", "ssh-host", (NOW + 70, 9), Some("aa")).await;
    node_certificate(&pool, "c7", "n4", "x509", (NOW + 80, 9), Some("aa")).await;

    let latest = store
        .ca_counters()
        .latest_node_host_certificates()
        .await
        .unwrap();

    let shown: Vec<(&str, Option<&str>, i64)> = latest
        .iter()
        .map(|cert| {
            (
                cert.name.as_str(),
                cert.ca_fingerprint.as_deref(),
                cert.not_after,
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            ("db-01", Some("aa"), NOW + 50),
            ("db-01", None, NOW + 60),
            ("web-01", Some("bb"), NOW + 200),
        ]
    );
}
