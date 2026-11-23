use std::collections::BTreeSet;

use jaunt_store::{LoginRequestState, NewCertificate, NewLoginRequest, NewUser, Store, StoreError};
use tempfile::TempDir;

const NOW: i64 = 1_000;

async fn open_store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("jaunt.db"))
        .await
        .expect("open");
    store.migrate().await.expect("migrate");
    (dir, store)
}

fn new_user(email: &str) -> NewUser {
    NewUser {
        issuer: "https://idp.example".to_string(),
        subject: "subject-1".to_string(),
        email: email.to_string(),
        display_name: Some("Ada".to_string()),
        groups: vec!["ops".to_string(), "dev".to_string()],
    }
}

fn new_request(ttl_secs: i64) -> NewLoginRequest {
    NewLoginRequest {
        kind: "web".to_string(),
        pkce_challenge: "challenge".to_string(),
        client_label: None,
        ttl_secs,
    }
}

async fn approved_request(store: &Store, ttl_secs: i64) -> String {
    let user = store
        .users()
        .upsert(&new_user("ada@example.com"), NOW)
        .await
        .expect("upsert");
    let requests = store.login_requests();
    let request = requests
        .create(&new_request(ttl_secs), NOW)
        .await
        .expect("create");
    assert!(
        requests
            .approve(&request.id, &user.id, NOW)
            .await
            .expect("approve")
    );
    request.id
}

#[tokio::test]
async fn migrate_twice_succeeds() {
    let (_dir, store) = open_store().await;
    store.migrate().await.expect("second migrate");
}

#[tokio::test]
async fn upsert_keeps_id_and_updates_email() {
    let (_dir, store) = open_store().await;
    let users = store.users();
    let first = users
        .upsert(&new_user("old@example.com"), 10)
        .await
        .unwrap();
    let second = users
        .upsert(&new_user("new@example.com"), 20)
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(second.email, "new@example.com");
    assert_eq!(second.created_at, 10);
    assert_eq!(second.updated_at, 20);
    assert_eq!(second.groups, vec!["ops".to_string(), "dev".to_string()]);
    let fetched = users.get(&first.id).await.unwrap().expect("user exists");
    assert_eq!(fetched, second);
    assert!(users.get("missing").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redeem_succeeds_for_exactly_one_of_sixteen_concurrent_calls() {
    let (_dir, store) = open_store().await;
    let id = approved_request(&store, 60).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let requests = store.login_requests();
        let id = id.clone();
        tasks.push(tokio::spawn(async move {
            requests.redeem(&id, NOW + 1).await.expect("redeem")
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(request) = task.await.expect("join") {
            winners.push(request);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].state, LoginRequestState::Redeemed);
    assert_eq!(winners[0].redeemed_at, Some(NOW + 1));
    let stored = store.login_requests().get(&id).await.unwrap().unwrap();
    assert_eq!(stored.state, LoginRequestState::Redeemed);
}

#[tokio::test]
async fn redeem_rejects_pending_and_expired_requests() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    let pending = requests.create(&new_request(60), NOW).await.unwrap();
    assert_eq!(pending.state, LoginRequestState::Pending);
    assert_eq!(pending.expires_at, NOW + 60);
    assert!(
        requests
            .redeem(&pending.id, NOW + 1)
            .await
            .unwrap()
            .is_none()
    );

    let approved = approved_request(&store, 60).await;
    assert!(
        requests
            .redeem(&approved, NOW + 60)
            .await
            .unwrap()
            .is_none()
    );
    let stored = requests.get(&approved).await.unwrap().unwrap();
    assert_eq!(stored.state, LoginRequestState::Approved);
}

#[tokio::test]
async fn approve_rejects_expired_request() {
    let (_dir, store) = open_store().await;
    let user = store
        .users()
        .upsert(&new_user("ada@example.com"), NOW)
        .await
        .unwrap();
    let requests = store.login_requests();
    let request = requests.create(&new_request(60), NOW).await.unwrap();
    assert!(
        !requests
            .approve(&request.id, &user.id, NOW + 60)
            .await
            .unwrap()
    );
    let stored = requests.get(&request.id).await.unwrap().unwrap();
    assert_eq!(stored.state, LoginRequestState::Pending);
    assert_eq!(stored.user_id, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixty_four_concurrent_serial_allocations_are_unique() {
    let (_dir, store) = open_store().await;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let certificates = store.certificates();
        tasks.push(tokio::spawn(async move {
            certificates.allocate_serial().await.expect("allocate")
        }));
    }
    let mut serials = BTreeSet::new();
    for task in tasks {
        assert!(serials.insert(task.await.expect("join")));
    }
    assert_eq!(serials, (1..=64).collect::<BTreeSet<i64>>());
}

#[tokio::test]
async fn record_rejects_unknown_user() {
    let (_dir, store) = open_store().await;
    let certificates = store.certificates();
    let serial = certificates.allocate_serial().await.unwrap();
    let certificate = NewCertificate {
        serial,
        user_id: "no-such-user".to_string(),
        kind: "user".to_string(),
        key_id: "key".to_string(),
        valid_after: NOW,
        valid_before: NOW + 60,
        issued_at: NOW,
    };
    let result = certificates.record(&certificate).await;
    assert!(matches!(result, Err(StoreError::Database(_))));
    assert!(certificates.get(serial).await.unwrap().is_none());
}

#[tokio::test]
async fn record_and_get_round_trip() {
    let (_dir, store) = open_store().await;
    let user = store
        .users()
        .upsert(&new_user("ada@example.com"), NOW)
        .await
        .unwrap();
    let certificates = store.certificates();
    let serial = certificates.allocate_serial().await.unwrap();
    let certificate = NewCertificate {
        serial,
        user_id: user.id,
        kind: "user".to_string(),
        key_id: "key".to_string(),
        valid_after: NOW,
        valid_before: NOW + 60,
        issued_at: NOW,
    };
    certificates.record(&certificate).await.unwrap();
    let stored = certificates.get(serial).await.unwrap().expect("exists");
    assert_eq!(stored.user_id, certificate.user_id);
    assert_eq!(stored.valid_before, NOW + 60);
}

#[tokio::test]
async fn approve_only_works_from_pending() {
    let (_dir, store) = open_store().await;
    let first_id = approved_request(&store, 60).await;
    let mut other = new_user("grace@example.com");
    other.subject = "subject-2".to_string();
    let other = store.users().upsert(&other, NOW).await.unwrap();
    let requests = store.login_requests();
    let before = requests.get(&first_id).await.unwrap().unwrap();
    assert_eq!(before.state, LoginRequestState::Approved);
    assert!(!requests.approve(&first_id, &other.id, NOW).await.unwrap());
    let after = requests.get(&first_id).await.unwrap().unwrap();
    assert_eq!(after.user_id, before.user_id);
    assert_eq!(after.state, LoginRequestState::Approved);

    assert!(requests.redeem(&first_id, NOW + 1).await.unwrap().is_some());
    assert!(
        !requests
            .approve(&first_id, &other.id, NOW + 1)
            .await
            .unwrap()
    );
    let redeemed = requests.get(&first_id).await.unwrap().unwrap();
    assert_eq!(redeemed.state, LoginRequestState::Redeemed);
    assert_eq!(redeemed.user_id, before.user_id);
}

#[tokio::test]
async fn create_rejects_zero_ttl() {
    let (_dir, store) = open_store().await;
    let result = store.login_requests().create(&new_request(0), NOW).await;
    assert!(matches!(result, Err(StoreError::InvalidInput(_))));
}

#[tokio::test]
async fn approve_unknown_request_returns_false() {
    let (_dir, store) = open_store().await;
    let user = store
        .users()
        .upsert(&new_user("ada@example.com"), NOW)
        .await
        .unwrap();
    let approved = store
        .login_requests()
        .approve("no-such-request", &user.id, NOW)
        .await
        .unwrap();
    assert!(!approved);
}
