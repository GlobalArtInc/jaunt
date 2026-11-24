use std::sync::Arc;

use jaunt_store::{NewUser, NewWebSession, Store, StoreError};
use sqlx::Connection;
use sqlx::sqlite::SqliteConnection;
use tempfile::TempDir;

const NOW: i64 = 10_000;
const TTL: i64 = 28_800;

async fn fixture() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
    store.migrate().await.unwrap();
    (dir, store)
}

async fn user(store: &Store, subject: &str) -> String {
    store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: subject.to_owned(),
                email: format!("{subject}@example.com"),
                username: subject.to_owned(),
                display_name: Some("Ada".to_owned()),
                groups: vec!["ops".to_owned()],
            },
            NOW,
        )
        .await
        .unwrap()
        .id
}

fn session(user_id: &str, id_hash: &str, created_at: i64) -> NewWebSession {
    NewWebSession {
        id_hash: id_hash.to_owned(),
        user_id: user_id.to_owned(),
        csrf_token_hash: format!("csrf-{id_hash}"),
        created_at,
        expires_at: created_at + TTL,
        source_ip: Some("203.0.113.9".to_owned()),
        user_agent: Some("agent".to_owned()),
    }
}

#[tokio::test]
async fn a_session_is_found_by_hash_with_its_user_until_the_exact_second_of_expiry() {
    let (_dir, store) = fixture().await;
    let user_id = user(&store, "ada").await;
    let sessions = store.web_sessions();
    sessions
        .create(&session(&user_id, "hash-1", NOW), 20)
        .await
        .unwrap();

    let found = sessions
        .find_valid("hash-1", NOW + TTL - 1)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(found.user.id, user_id);
    assert_eq!(found.user.email, "ada@example.com");
    assert_eq!(found.session.csrf_token_hash, "csrf-hash-1");
    assert_eq!(found.session.created_at, NOW);
    assert_eq!(found.session.expires_at, NOW + TTL);
    assert_eq!(found.session.last_seen_at, NOW);
    assert_eq!(found.session.source_ip.as_deref(), Some("203.0.113.9"));
    assert!(
        sessions
            .find_valid("hash-1", NOW + TTL)
            .await
            .unwrap()
            .is_none()
    );
    assert!(sessions.find_valid("hash-2", NOW).await.unwrap().is_none());
}

#[tokio::test]
async fn the_twenty_first_session_removes_the_oldest_and_never_itself_even_on_a_tie() {
    let (_dir, store) = fixture().await;
    let ada = user(&store, "ada").await;
    let bob = user(&store, "bob").await;
    let sessions = store.web_sessions();
    sessions
        .create(&session(&bob, "bob-1", NOW), 20)
        .await
        .unwrap();
    for n in 0..20 {
        let created = NOW + n;
        sessions
            .create(&session(&ada, &format!("ada-{n:02}"), created), 20)
            .await
            .unwrap();
    }
    assert_eq!(sessions.count_for_user(&ada).await.unwrap(), 20);

    sessions
        .create(&session(&ada, "ada-new", NOW + 20), 20)
        .await
        .unwrap();

    assert_eq!(sessions.count_for_user(&ada).await.unwrap(), 20);
    assert!(sessions.get("ada-00").await.unwrap().is_none());
    assert!(sessions.get("ada-01").await.unwrap().is_some());
    assert!(sessions.get("ada-new").await.unwrap().is_some());
    assert_eq!(sessions.count_for_user(&bob).await.unwrap(), 1);

    for tied in ["zzz-newest-hash", "aaa-lowest-hash"] {
        sessions
            .create(&session(&ada, tied, NOW + 100), 20)
            .await
            .unwrap();
        assert!(sessions.get(tied).await.unwrap().is_some(), "{tied}");
    }
    assert_eq!(sessions.count_for_user(&ada).await.unwrap(), 20);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creations_never_leave_more_than_the_cap() {
    let (_dir, store) = fixture().await;
    let ada = Arc::new(user(&store, "ada").await);
    let mut tasks = Vec::new();
    for n in 0..24_i64 {
        let sessions = store.web_sessions();
        let ada = Arc::clone(&ada);
        tasks.push(tokio::spawn(async move {
            sessions
                .create(&session(&ada, &format!("ada-{n:02}"), NOW + n), 5)
                .await
        }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(store.web_sessions().count_for_user(&ada).await.unwrap(), 5);
}

#[tokio::test]
async fn touching_updates_last_seen_at_most_once_per_interval() {
    let (_dir, store) = fixture().await;
    let ada = user(&store, "ada").await;
    let sessions = store.web_sessions();
    sessions
        .create(&session(&ada, "hash-1", NOW), 20)
        .await
        .unwrap();

    assert!(!sessions.touch("hash-1", NOW + 59, 60).await.unwrap());
    assert!(sessions.touch("hash-1", NOW + 60, 60).await.unwrap());
    assert!(!sessions.touch("hash-1", NOW + 119, 60).await.unwrap());
    assert!(sessions.touch("hash-1", NOW + 120, 60).await.unwrap());
    assert_eq!(
        sessions.get("hash-1").await.unwrap().unwrap().last_seen_at,
        NOW + 120
    );
    assert!(!sessions.touch("hash-1", NOW + TTL, 60).await.unwrap());
    assert!(!sessions.touch("missing", NOW + 500, 60).await.unwrap());
}

#[tokio::test]
async fn deleting_and_purging_report_whose_sessions_went_away() {
    let (_dir, store) = fixture().await;
    let ada = user(&store, "ada").await;
    let bob = user(&store, "bob").await;
    let sessions = store.web_sessions();
    sessions
        .create(&session(&ada, "ada-1", NOW), 20)
        .await
        .unwrap();
    sessions
        .create(&session(&ada, "ada-2", NOW + 10), 20)
        .await
        .unwrap();
    sessions
        .create(&session(&bob, "bob-1", NOW + 20), 20)
        .await
        .unwrap();

    assert_eq!(
        sessions.delete("ada-1").await.unwrap().as_deref(),
        Some(ada.as_str())
    );
    assert_eq!(sessions.delete("ada-1").await.unwrap(), None);
    assert_eq!(
        sessions.delete_expired("ada-2", NOW + TTL).await.unwrap(),
        None
    );
    assert_eq!(
        sessions
            .delete_expired("ada-2", NOW + 10 + TTL)
            .await
            .unwrap()
            .as_deref(),
        Some(ada.as_str())
    );

    assert!(
        sessions
            .purge_expired(NOW + 19 + TTL)
            .await
            .unwrap()
            .is_empty()
    );
    let purged = sessions.purge_expired(NOW + 20 + TTL).await.unwrap();
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0], bob);
    assert_eq!(sessions.count_for_user(&bob).await.unwrap(), 0);
}

#[tokio::test]
async fn a_session_whose_user_row_is_gone_is_not_valid() {
    let (dir, store) = fixture().await;
    let ada = user(&store, "ada").await;
    let sessions = store.web_sessions();
    sessions
        .create(&session(&ada, "hash-1", NOW), 20)
        .await
        .unwrap();
    let mut direct = SqliteConnection::connect(&format!(
        "sqlite://{}?mode=rw",
        dir.path().join("jaunt.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut direct)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&ada)
        .execute(&mut direct)
        .await
        .unwrap();

    assert!(sessions.find_valid("hash-1", NOW).await.unwrap().is_none());
    assert!(sessions.get("hash-1").await.unwrap().is_some());
}

#[tokio::test]
async fn invalid_sessions_and_unknown_users_are_refused() {
    let (_dir, store) = fixture().await;
    let ada = user(&store, "ada").await;
    let sessions = store.web_sessions();
    let mut backwards = session(&ada, "hash-1", NOW);
    backwards.expires_at = NOW;
    let mut no_csrf = session(&ada, "hash-2", NOW);
    no_csrf.csrf_token_hash.clear();

    for refused in [backwards, no_csrf, session(&ada, "", NOW)] {
        assert!(matches!(
            sessions.create(&refused, 20).await,
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert!(matches!(
        sessions.create(&session(&ada, "hash-3", NOW), 0).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        sessions
            .create(&session("no-such-user", "hash-4", NOW), 20)
            .await,
        Err(StoreError::Database(_))
    ));
    assert!(sessions.get("hash-4").await.unwrap().is_none());
}
