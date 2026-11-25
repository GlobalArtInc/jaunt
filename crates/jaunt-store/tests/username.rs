use std::path::Path;

use jaunt_store::{NewApiToken, NewCertificate, NewUser, Store};
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::SqliteConnectOptions;

const VERSION_BEFORE_USERNAME: i64 = 4;

fn new_user(username: &str) -> NewUser {
    NewUser {
        issuer: "https://idp.example".to_owned(),
        subject: "subject-1".to_owned(),
        email: "ada@example.com".to_owned(),
        username: username.to_owned(),
        display_name: None,
        groups: Vec::new(),
    }
}

#[tokio::test]
async fn upsert_stores_the_username_and_replaces_it_on_every_login() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
    store.migrate().await.unwrap();
    let users = store.users();

    let first = users.upsert(&new_user("ada"), 10).await.unwrap();
    assert_eq!(first.username, "ada");
    let renamed = users.upsert(&new_user("ada.l"), 20).await.unwrap();
    assert_eq!(renamed.id, first.id);
    assert_eq!(renamed.username, "ada.l");
    let cleared = users.upsert(&new_user(""), 30).await.unwrap();
    assert_eq!(cleared.username, "");
    let renamed_again = users.upsert(&new_user("ada"), 40).await.unwrap();
    assert_eq!(users.get(&first.id).await.unwrap().unwrap(), renamed_again);

    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: first.id.clone(),
            kind: "user".to_owned(),
            key_id: "key".to_owned(),
            valid_after: 40,
            valid_before: 100,
            issued_at: 40,
            ca_fingerprint: None,
            host_trust_id: None,
            subject_fingerprint: None,
        })
        .await
        .unwrap();
    store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: "hash".to_owned(),
            user_id: first.id.clone(),
            cert_serial: serial,
            created_at: 40,
            expires_at: 100,
        })
        .await
        .unwrap();
    let found = store
        .api_tokens()
        .find_valid("hash", 50)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.user.username, "ada");
}

#[tokio::test]
async fn users_stored_before_the_migration_get_an_empty_username() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true),
    )
    .await
    .unwrap();
    let migrations = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run_to(VERSION_BEFORE_USERNAME, &pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users (id, issuer, subject, email, display_name, groups, created_at, updated_at) \
         VALUES ('existing', 'https://idp.example', 'subject-1', 'ada@example.com', NULL, '[]', 1, 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();

    let existing = store.users().get("existing").await.unwrap().unwrap();
    assert_eq!(existing.username, "");
    assert_eq!(existing.email, "ada@example.com");
}
