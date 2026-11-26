use std::path::Path;

use jaunt_store::{
    EnrollmentState, JoinEnrollment, JoinOutcome, JoinToken, Joined, Labels, NameScope,
    NewJoinToken, NodeState, Store, TokenFailure, TokenRevokeOutcome, Unusable,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 10_000;
const TTL: i64 = 3600;

async fn open_store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("jaunt.db"))
        .await
        .expect("open");
    store.migrate().await.expect("migrate");
    (dir, store)
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn new_token(hash: &str, scope: NameScope, max_uses: i64, allow_replace: bool) -> NewJoinToken {
    NewJoinToken {
        hash: hash.to_owned(),
        scope,
        labels: labels(&[("env", "prod")]),
        max_uses,
        allow_replace,
        created_by: "cli:root".to_owned(),
        ttl_secs: TTL,
    }
}

async fn create(store: &Store, hash: &str, max_uses: i64, allow_replace: bool) -> JoinToken {
    store
        .join_tokens()
        .create(
            &new_token(
                hash,
                NameScope::Prefix("web-".to_owned()),
                max_uses,
                allow_replace,
            ),
            NOW,
        )
        .await
        .expect("create")
}

fn pinned() -> Labels {
    labels(&[("env", "prod")])
}

async fn join(
    store: &Store,
    token: &JoinToken,
    hash: &str,
    name: &str,
    tag: &str,
    replace: bool,
    now: i64,
) -> JoinOutcome {
    let labels = pinned();
    let handle = format!("handle-{tag}");
    let approved_by = format!("join-token:{}", token.id);
    store
        .join_tokens()
        .enroll(JoinEnrollment {
            token_id: &token.id,
            token_hash: hash,
            handle_hash: &handle,
            name,
            labels: &labels,
            hostname: "host.example.com",
            source_ip: "203.0.113.5",
            peer_addr: "203.0.113.5",
            tls_public_key: "tls",
            ssh_host_public_key: "ssh",
            tls_spki_sha256: "aa",
            ssh_host_key_fingerprint: "SHA256:bb",
            replace_existing: replace,
            agent_version: "0.1.0",
            approved_by: &approved_by,
            ttl_secs: 900,
            now,
        })
        .await
        .expect("enroll")
}

fn joined(outcome: JoinOutcome) -> Joined {
    match outcome {
        JoinOutcome::Joined(joined) => *joined,
        other => panic!("unexpected {other:?}"),
    }
}

async fn uses_left(store: &Store, id: &str) -> i64 {
    store
        .join_tokens()
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|token| token.id == id)
        .unwrap()
        .uses_left
}

async fn raw_pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .expect("raw pool")
}

#[tokio::test]
async fn a_created_token_is_listed_with_its_limits_and_without_its_hash() {
    let (_dir, store) = open_store().await;
    let exact = store
        .join_tokens()
        .create(
            &new_token("hash-a", NameScope::Exact("db-01".to_owned()), 3, true),
            NOW,
        )
        .await
        .unwrap();

    assert_eq!(exact.scope, NameScope::Exact("db-01".to_owned()));
    assert_eq!((exact.max_uses, exact.uses_left), (3, 3));
    assert_eq!(exact.expires_at, NOW + TTL);
    assert!(exact.allow_replace);
    assert_eq!(exact.revoked_at, None);
    assert_eq!(store.join_tokens().list().await.unwrap(), vec![exact]);
    for (scope, max_uses, ttl) in [
        (NameScope::Exact(String::new()), 1, TTL),
        (NameScope::Prefix(String::new()), 1, TTL),
        (NameScope::Exact("db".to_owned()), 0, TTL),
        (NameScope::Exact("db".to_owned()), 1, 0),
    ] {
        let mut token = new_token("hash-b", scope, max_uses, false);
        token.ttl_secs = ttl;
        assert!(store.join_tokens().create(&token, NOW).await.is_err());
    }
}

#[tokio::test]
async fn the_schema_holds_exactly_one_of_a_name_and_a_prefix_and_never_more_uses_than_allowed() {
    let (dir, _store) = open_store().await;
    let pool = raw_pool(&dir.path().join("jaunt.db")).await;
    let insert = "INSERT INTO join_tokens (id, hash, name, name_prefix, labels, max_uses, \
        uses_left, expires_at, allow_replace, created_by, created_at) \
        VALUES (?, ?, ?, ?, '{}', ?, ?, 1, 0, 'cli:root', 1)";
    for (index, (name, prefix, max_uses, left, accepted)) in [
        (Some("web"), None, 1, 1, true),
        (None, Some("web-"), 1, 1, true),
        (Some("web"), Some("web-"), 1, 1, false),
        (None, None, 1, 1, false),
        (Some("web"), None, 1, 2, false),
        (Some("web"), None, 1, -1, false),
        (Some("web"), None, 0, 0, false),
        (Some(""), None, 1, 1, false),
        (None, Some(""), 1, 1, false),
    ]
    .into_iter()
    .enumerate()
    {
        let result = sqlx::query(insert)
            .bind(format!("id-{index}"))
            .bind(format!("hash-{index}"))
            .bind(name)
            .bind(prefix)
            .bind(max_uses)
            .bind(left)
            .execute(&pool)
            .await;
        assert_eq!(result.is_ok(), accepted, "{index}");
    }
}

#[tokio::test]
async fn every_use_creates_an_approved_enrollment_and_an_active_node_until_the_uses_run_out() {
    let (_dir, store) = open_store().await;
    let token = create(&store, "hash", 2, false).await;

    let first = joined(join(&store, &token, "hash", "web-01", "1", false, NOW + 1).await);
    let second = joined(join(&store, &token, "hash", "web-02", "2", false, NOW + 2).await);
    let third = join(&store, &token, "hash", "web-03", "3", false, NOW + 3).await;

    assert_eq!((first.uses_left, second.uses_left), (1, 0));
    for (joined, name) in [(&first, "web-01"), (&second, "web-02")] {
        assert_eq!(joined.enrollment.state, EnrollmentState::Approved);
        assert_eq!(
            joined.enrollment.node_id.as_deref(),
            Some(joined.node.id.as_str())
        );
        assert_eq!(joined.enrollment.code_hash, "");
        assert_eq!(
            joined.enrollment.expires_at,
            joined.enrollment.created_at + 900
        );
        assert_eq!(joined.node.name, name);
        assert_eq!(joined.node.state, NodeState::Active);
        assert_eq!(joined.node.labels, pinned());
        assert_eq!(joined.node.approved_by, format!("join-token:{}", token.id));
        assert_eq!(joined.replaced, None);
    }
    assert_eq!(
        third,
        JoinOutcome::Unusable(Unusable {
            failure: TokenFailure::UsedUp,
            token_id: Some(token.id.clone()),
        })
    );
    assert_eq!(store.nodes().list().await.unwrap().len(), 2);
    assert!(
        store
            .enrollments()
            .get_by_handle_hash("handle-3")
            .await
            .unwrap()
            .is_none()
    );
    let delivery = store
        .enrollments()
        .begin_delivery(&first.enrollment.id, NOW + 5)
        .await
        .unwrap();
    assert!(delivery.is_some());
}

#[tokio::test]
async fn a_name_held_by_an_active_node_rolls_the_use_back_unless_the_join_replaces_it() {
    let (_dir, store) = open_store().await;
    let token = create(&store, "hash", 3, true).await;
    let old = joined(join(&store, &token, "hash", "web-01", "1", false, NOW + 1).await);

    let refused = join(&store, &token, "hash", "web-01", "2", false, NOW + 2).await;
    assert_eq!(refused, JoinOutcome::NameTaken);
    assert_eq!(uses_left(&store, &token.id).await, 2);
    assert!(
        store
            .enrollments()
            .get_by_handle_hash("handle-2")
            .await
            .unwrap()
            .is_none()
    );

    let replacing = joined(join(&store, &token, "hash", "web-01", "3", true, NOW + 3).await);
    let replaced = replacing.replaced.clone().unwrap();
    assert_eq!(replaced.id, old.node.id);
    assert_eq!(replaced.state, NodeState::Removed);
    assert_eq!(uses_left(&store, &token.id).await, 1);
    let old_enrollment = store
        .enrollments()
        .get_by_handle_hash("handle-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old_enrollment.state, EnrollmentState::Rejected);
    assert!(replacing.enrollment.replace_existing);
    let active = store.nodes().get_active_by_name("web-01").await.unwrap();
    assert_eq!(active.map(|node| node.id), Some(replacing.node.id));
}

#[tokio::test]
async fn unusable_tokens_are_classified_by_what_happened_to_them() {
    let (_dir, store) = open_store().await;
    let tokens = store.join_tokens();
    let expiring = create(&store, "expiring", 1, false).await;
    let used = create(&store, "used", 1, false).await;
    let revoked = create(&store, "revoked", 1, false).await;
    joined(join(&store, &used, "used", "web-01", "1", false, NOW + 1).await);
    tokens.revoke(&revoked.id, NOW + 1).await.unwrap();
    let at_expiry = NOW + TTL;

    assert!(
        tokens
            .find_usable("expiring", at_expiry - 1)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        tokens.classify("expiring", at_expiry - 1).await.unwrap(),
        None
    );
    for (hash, now, failure, id) in [
        ("absent", NOW, TokenFailure::Unknown, None),
        (
            "expiring",
            at_expiry,
            TokenFailure::Expired,
            Some(&expiring.id),
        ),
        ("used", NOW + 2, TokenFailure::UsedUp, Some(&used.id)),
        ("revoked", NOW + 2, TokenFailure::Revoked, Some(&revoked.id)),
    ] {
        assert!(
            tokens.find_usable(hash, now).await.unwrap().is_none(),
            "{hash}"
        );
        assert_eq!(
            tokens.classify(hash, now).await.unwrap(),
            Some(Unusable {
                failure,
                token_id: id.cloned(),
            }),
            "{hash}"
        );
    }
    assert_eq!(
        join(
            &store, &expiring, "expiring", "web-02", "2", false, at_expiry
        )
        .await,
        JoinOutcome::Unusable(Unusable {
            failure: TokenFailure::Expired,
            token_id: Some(expiring.id.clone()),
        })
    );
    assert_eq!(
        join(&store, &revoked, "revoked", "web-03", "3", false, NOW + 2).await,
        JoinOutcome::Unusable(Unusable {
            failure: TokenFailure::Revoked,
            token_id: Some(revoked.id.clone()),
        })
    );
}

#[tokio::test]
async fn a_token_id_that_does_not_belong_to_the_hash_consumes_nothing() {
    let (_dir, store) = open_store().await;
    let mine = create(&store, "mine", 1, false).await;
    let other = create(&store, "other", 1, false).await;

    let crossed_error = store
        .join_tokens()
        .enroll(JoinEnrollment {
            token_id: &other.id,
            token_hash: "mine",
            handle_hash: "handle-2",
            name: "web-02",
            labels: &pinned(),
            hostname: "host.example.com",
            source_ip: "203.0.113.5",
            peer_addr: "203.0.113.5",
            tls_public_key: "tls",
            ssh_host_public_key: "ssh",
            tls_spki_sha256: "aa",
            ssh_host_key_fingerprint: "SHA256:bb",
            replace_existing: false,
            agent_version: "0.1.0",
            approved_by: "join-token:x",
            ttl_secs: 900,
            now: NOW + 1,
        })
        .await;

    assert!(crossed_error.is_err());
    assert_eq!(uses_left(&store, &mine.id).await, 1);
    assert_eq!(uses_left(&store, &other.id).await, 1);
    assert!(store.nodes().list().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn of_sixteen_concurrent_joins_on_a_two_use_token_exactly_two_succeed() {
    let (_dir, store) = open_store().await;
    let token = create(&store, "hash", 2, false).await;

    let mut tasks = Vec::new();
    for index in 0..16 {
        let store = store.clone();
        let token = token.clone();
        tasks.push(tokio::spawn(async move {
            let name = format!("web-{index:02}");
            let tag = index.to_string();
            join(&store, &token, "hash", &name, &tag, false, NOW + 1).await
        }));
    }
    let mut won = 0;
    for task in tasks {
        match task.await.unwrap() {
            JoinOutcome::Joined(_) => won += 1,
            JoinOutcome::Unusable(unusable) => {
                assert_eq!(unusable.failure, TokenFailure::UsedUp);
            }
            JoinOutcome::NameTaken => panic!("every join used its own name"),
        }
    }

    assert_eq!(won, 2);
    assert_eq!(uses_left(&store, &token.id).await, 0);
    assert_eq!(store.nodes().list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn revoking_is_recorded_once_and_unknown_ids_are_told_apart() {
    let (_dir, store) = open_store().await;
    let token = create(&store, "hash", 1, false).await;
    let tokens = store.join_tokens();

    let first = tokens.revoke(&token.id, NOW + 5).await.unwrap();
    let TokenRevokeOutcome::Revoked(revoked) = first else {
        panic!("unexpected {first:?}");
    };
    assert_eq!(revoked.revoked_at, Some(NOW + 5));
    assert_eq!(
        tokens.revoke(&token.id, NOW + 6).await.unwrap(),
        TokenRevokeOutcome::AlreadyRevoked
    );
    assert_eq!(
        tokens.revoke("absent", NOW + 6).await.unwrap(),
        TokenRevokeOutcome::Unknown
    );
    assert_eq!(tokens.list().await.unwrap()[0].revoked_at, Some(NOW + 5));
}

#[tokio::test]
async fn purging_deletes_only_tokens_that_expired_before_the_cutoff() {
    let (_dir, store) = open_store().await;
    let old = create(&store, "old", 1, false).await;
    let mut later = new_token("later", NameScope::Exact("db-01".to_owned()), 1, false);
    later.ttl_secs = TTL * 2;
    let later = store.join_tokens().create(&later, NOW).await.unwrap();
    joined(join(&store, &later, "later", "db-01", "1", false, NOW + 1).await);
    assert_eq!(uses_left(&store, &later.id).await, 0);

    assert_eq!(
        store
            .join_tokens()
            .purge_expired(old.expires_at)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .join_tokens()
            .purge_expired(old.expires_at + 1)
            .await
            .unwrap(),
        1
    );
    let left: Vec<String> = store
        .join_tokens()
        .list()
        .await
        .unwrap()
        .into_iter()
        .map(|token| token.id)
        .collect();
    assert_eq!(left, vec![later.id.clone()]);
    assert_eq!(uses_left(&store, &later.id).await, 0);
}

#[tokio::test]
async fn the_store_replaces_a_node_only_for_a_token_that_allows_it() {
    let (_dir, store) = open_store().await;
    let strict = create(&store, "strict", 3, false).await;
    let old = joined(join(&store, &strict, "strict", "web-01", "1", false, NOW + 1).await);

    let refused = join(&store, &strict, "strict", "web-01", "2", true, NOW + 2).await;

    assert_eq!(refused, JoinOutcome::NameTaken);
    assert_eq!(uses_left(&store, &strict.id).await, 2);
    let active = store.nodes().get_active_by_name("web-01").await.unwrap();
    assert_eq!(active.map(|node| node.id), Some(old.node.id.clone()));
    let free = joined(join(&store, &strict, "strict", "web-02", "3", true, NOW + 3).await);
    assert_eq!(free.replaced, None);
    assert!(!free.enrollment.replace_existing);
}
