use jaunt_store::{
    LoginRequestState, NewDeviceLoginRequest, NewLoginRequest, NewUser, Store, StoreError,
};
use tempfile::TempDir;

const NOW: i64 = 5_000;
const TTL: i64 = 300;
const HASH: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const OTHER_HASH: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

async fn open_store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
    store.migrate().await.unwrap();
    (dir, store)
}

fn device_request(hash: &str) -> NewDeviceLoginRequest {
    NewDeviceLoginRequest {
        pkce_challenge: "challenge".to_owned(),
        client_label: Some("build host".to_owned()),
        user_code_hash: hash.to_owned(),
        requester_ip: "203.0.113.9".to_owned(),
        ttl_secs: TTL,
    }
}

async fn user_id(store: &Store) -> String {
    store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "subject-1".to_owned(),
                email: "ada@example.com".to_owned(),
                username: "ada".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            NOW,
        )
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn a_device_request_keeps_its_code_hash_requester_and_label() {
    let (_dir, store) = open_store().await;

    let created = store
        .login_requests()
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(created.kind, "device");
    assert_eq!(created.state, LoginRequestState::Pending);
    assert_eq!(created.user_code_hash.as_deref(), Some(HASH));
    assert_eq!(created.requester_ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(created.client_label.as_deref(), Some("build host"));
    assert_eq!(created.created_at, NOW);
    assert_eq!(created.expires_at, NOW + TTL);
    assert_eq!(created.completion_hash, None);
    let stored = store
        .login_requests()
        .get(&created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, created);
}

#[tokio::test]
async fn a_code_hash_cannot_be_reused_while_another_request_with_it_is_pending() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    let first = requests
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();

    let clash = requests
        .create_device(&device_request(HASH), NOW + TTL - 1)
        .await
        .unwrap();
    assert!(clash.is_none());
    assert_eq!(requests.count_live_device(NOW).await.unwrap(), 1);
    let other = requests
        .create_device(&device_request(OTHER_HASH), NOW)
        .await
        .unwrap();
    assert!(other.is_some());

    let user = user_id(&store).await;
    assert!(
        requests
            .approve(&first.id, &user, None, NOW + 1)
            .await
            .unwrap()
    );
    let after_approval = requests
        .create_device(&device_request(HASH), NOW + 2)
        .await
        .unwrap();
    assert!(after_approval.is_some());
}

#[tokio::test]
async fn a_code_hash_is_free_again_once_its_request_expired() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    requests
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();

    let at_expiry = requests
        .create_device(&device_request(HASH), NOW + TTL)
        .await
        .unwrap();

    assert!(at_expiry.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_creates_with_one_code_hash_have_exactly_one_winner() {
    let (_dir, store) = open_store().await;

    let mut tasks = Vec::new();
    for _ in 0..16 {
        let requests = store.login_requests();
        tasks.push(tokio::spawn(async move {
            requests
                .create_device(&device_request(HASH), NOW)
                .await
                .unwrap()
                .is_some()
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }

    assert_eq!(winners, 1);
    assert_eq!(
        store.login_requests().count_live_device(NOW).await.unwrap(),
        1
    );
    let stored = store
        .login_requests()
        .find_pending_device(HASH, NOW)
        .await
        .unwrap();
    assert!(stored.is_some());
}

#[tokio::test]
async fn an_empty_code_hash_or_a_zero_ttl_is_refused() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    let empty = requests.create_device(&device_request(""), NOW).await;
    assert!(matches!(empty, Err(StoreError::InvalidInput(_))));
    let mut immediate = device_request(HASH);
    immediate.ttl_secs = 0;
    let zero = requests.create_device(&immediate, NOW).await;
    assert!(matches!(zero, Err(StoreError::InvalidInput(_))));
}

#[tokio::test]
async fn the_code_lookup_finds_only_unexpired_pending_device_requests() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    let created = requests
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();

    let found = requests
        .find_pending_device(HASH, NOW + TTL - 1)
        .await
        .unwrap();
    assert_eq!(found.map(|request| request.id), Some(created.id.clone()));
    assert!(
        requests
            .find_pending_device(HASH, NOW + TTL)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        requests
            .find_pending_device(OTHER_HASH, NOW)
            .await
            .unwrap()
            .is_none()
    );

    assert!(requests.deny(&created.id, NOW + 1).await.unwrap());
    assert!(
        requests
            .find_pending_device(HASH, NOW + 1)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn only_a_pending_unexpired_request_can_be_denied() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    let user = user_id(&store).await;
    let denied = requests
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();
    let approved = requests
        .create_device(&device_request(OTHER_HASH), NOW)
        .await
        .unwrap()
        .unwrap();
    assert!(
        requests
            .approve(&approved.id, &user, None, NOW + 1)
            .await
            .unwrap()
    );

    assert!(!requests.deny(&approved.id, NOW + 2).await.unwrap());
    let still_approved = requests.get(&approved.id).await.unwrap().unwrap();
    assert_eq!(still_approved.state, LoginRequestState::Approved);
    assert_eq!(still_approved.user_id.as_deref(), Some(user.as_str()));

    assert!(!requests.deny(&denied.id, NOW + TTL).await.unwrap());
    assert!(requests.deny(&denied.id, NOW + TTL - 1).await.unwrap());
    assert!(!requests.deny(&denied.id, NOW + TTL - 1).await.unwrap());
    assert!(
        !requests
            .approve(&denied.id, &user, None, NOW + 2)
            .await
            .unwrap()
    );
    let after = requests.get(&denied.id).await.unwrap().unwrap();
    assert_eq!(after.state, LoginRequestState::Denied);
    assert_eq!(after.user_id, None);
    assert!(
        requests
            .redeem(&denied.id, NOW + 2)
            .await
            .unwrap()
            .is_none()
    );
    assert!(!requests.deny("no-such-request", NOW).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn approve_and_deny_racing_on_one_request_have_exactly_one_winner() {
    let (_dir, store) = open_store().await;
    let user = user_id(&store).await;
    let id = store
        .login_requests()
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap()
        .id;

    let mut tasks = Vec::new();
    for turn in 0..16 {
        let requests = store.login_requests();
        let id = id.clone();
        let user = user.clone();
        tasks.push(tokio::spawn(async move {
            if turn % 2 == 0 {
                requests.approve(&id, &user, None, NOW + 1).await.unwrap()
            } else {
                requests.deny(&id, NOW + 1).await.unwrap()
            }
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap() {
            winners += 1;
        }
    }

    assert_eq!(winners, 1);
    let state = store
        .login_requests()
        .get(&id)
        .await
        .unwrap()
        .unwrap()
        .state;
    assert!(matches!(
        state,
        LoginRequestState::Approved | LoginRequestState::Denied
    ));
}

#[tokio::test]
async fn the_live_count_covers_unexpired_device_requests_only() {
    let (_dir, store) = open_store().await;
    let requests = store.login_requests();
    requests
        .create(
            &NewLoginRequest {
                kind: "loopback".to_owned(),
                pkce_challenge: "challenge".to_owned(),
                client_label: None,
                ttl_secs: TTL,
            },
            NOW,
        )
        .await
        .unwrap();
    let mut short = device_request(OTHER_HASH);
    short.ttl_secs = 10;
    requests.create_device(&short, NOW).await.unwrap().unwrap();
    requests
        .create_device(&device_request(HASH), NOW)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(requests.count_live_device(NOW).await.unwrap(), 2);
    assert_eq!(requests.count_live_device(NOW + 10).await.unwrap(), 1);
    assert_eq!(requests.count_live_device(NOW + TTL).await.unwrap(), 0);
}
