use std::collections::HashSet;

use jaunt_store::{
    NewApiToken, NewCertificate, NewRevocation, NewUser, NewWebSession, NodeState, RevocationKind,
    RevokeOutcome, Store, StoreError, Subjects,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 1_000;

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)";

async fn open() -> (TempDir, Store, SqlitePool) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.expect("open");
    store.migrate().await.expect("migrate");
    let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .expect("raw pool");
    (dir, store, raw)
}

fn revocation(kind: RevocationKind, subject: &str, reason: &str) -> NewRevocation {
    NewRevocation {
        kind,
        subject: subject.to_owned(),
        reason: reason.to_owned(),
        created_by: "cli:root".to_owned(),
    }
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
                display_name: None,
                groups: Vec::new(),
            },
            NOW,
        )
        .await
        .unwrap()
        .id
}

async fn certificate(store: &Store, user_id: &str, valid_before: i64) -> i64 {
    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user_id.to_owned(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:x@example.com:{serial}"),
            valid_after: NOW - 60,
            valid_before,
            issued_at: NOW,
            ca_fingerprint: None,
            host_trust_id: None,
            subject_fingerprint: None,
        })
        .await
        .unwrap();
    serial
}

async fn count(raw: &SqlitePool, table: &str, user_id: &str) -> i64 {
    let query = match table {
        "web_sessions" => "SELECT COUNT(*) FROM web_sessions WHERE user_id = ?",
        _ => "SELECT COUNT(*) FROM api_tokens WHERE user_id = ?",
    };
    sqlx::query_scalar(query)
        .bind(user_id)
        .fetch_one(raw)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_subject_is_revoked_once_per_kind_and_a_repeat_returns_the_first_record() {
    let (_dir, store, _raw) = open().await;
    let revocations = store.revocations();

    let first = revocations
        .insert(
            &revocation(RevocationKind::User, "user-1", "lost laptop"),
            NOW,
        )
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.removed_node, None);
    let stored = first.revocation;
    assert_eq!(
        (stored.kind, stored.subject.as_str(), stored.reason.as_str()),
        (RevocationKind::User, "user-1", "lost laptop")
    );
    assert_eq!(
        (stored.created_at, stored.created_by.as_str()),
        (NOW, "cli:root")
    );

    let repeat = revocations
        .insert(
            &revocation(RevocationKind::User, "user-1", "again"),
            NOW + 5,
        )
        .await
        .unwrap();
    assert!(!repeat.created);
    assert_eq!(repeat.revocation, stored);

    let other_kind = revocations
        .insert(
            &revocation(RevocationKind::Serial, "user-1", "same text"),
            NOW,
        )
        .await
        .unwrap();
    assert!(other_kind.created);
    assert_eq!(
        revocations
            .find(RevocationKind::User, "user-1")
            .await
            .unwrap(),
        Some(stored.clone())
    );
    assert_eq!(revocations.get(&stored.id).await.unwrap(), Some(stored));
    assert!(matches!(
        revocations
            .insert(&revocation(RevocationKind::User, "", "empty"), NOW)
            .await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn one_lookup_matches_a_revoked_user_serial_or_node_and_nothing_else() {
    let (_dir, store, _raw) = open().await;
    let revocations = store.revocations();
    for (kind, subject) in [
        (RevocationKind::User, "user-1"),
        (RevocationKind::Serial, "42"),
        (RevocationKind::Node, "node-1"),
    ] {
        revocations
            .insert(&revocation(kind, subject, "r"), NOW)
            .await
            .unwrap();
    }
    let probe = |user_id, serial, node_id| Subjects {
        user_id,
        serial,
        node_id,
    };

    for (subjects, revoked) in [
        (probe("user-1", None, None), true),
        (probe("user-2", Some(42), None), true),
        (probe("user-2", Some(7), Some("node-1")), true),
        (probe("user-2", Some(7), Some("node-2")), false),
        (probe("user-2", None, None), false),
        (probe("42", None, Some("user-1")), false),
        (probe("node-1", Some(1), None), false),
    ] {
        assert_eq!(
            revocations.any_matches(subjects).await.unwrap(),
            revoked,
            "{subjects:?}"
        );
    }
}

#[tokio::test]
async fn revoking_a_user_ends_their_web_sessions_and_api_tokens_in_the_same_write() {
    let (_dir, store, raw) = open().await;
    let alice = user(&store, "alice").await;
    let bob = user(&store, "bob").await;
    for (owner, tag) in [(&alice, "a1"), (&alice, "a2"), (&bob, "b1")] {
        access(&store, owner, tag).await;
    }

    let revoked = store
        .revocations()
        .insert(&revocation(RevocationKind::User, &alice, "left"), NOW)
        .await
        .unwrap();

    assert_eq!(
        (revoked.ended_web_sessions, revoked.removed_api_tokens),
        (2, 2)
    );
    for table in ["web_sessions", "api_tokens"] {
        assert_eq!(count(&raw, table, &alice).await, 0, "{table}");
        assert_eq!(count(&raw, table, &bob).await, 1, "{table}");
    }
    let serial_only = store
        .revocations()
        .insert(&revocation(RevocationKind::Serial, "1", "r"), NOW)
        .await
        .unwrap();
    assert_eq!(
        (
            serial_only.ended_web_sessions,
            serial_only.removed_api_tokens
        ),
        (0, 0)
    );
    assert_eq!(count(&raw, "api_tokens", &bob).await, 1);

    access(&store, &alice, "a3").await;
    let repeated = store
        .revocations()
        .insert(&revocation(RevocationKind::User, &alice, "again"), NOW + 1)
        .await
        .unwrap();
    assert!(!repeated.created);
    assert_eq!(
        (repeated.ended_web_sessions, repeated.removed_api_tokens),
        (1, 1)
    );
    access(&store, &alice, "a4").await;
    store
        .revocations()
        .delete(&revoked.revocation.id)
        .await
        .unwrap()
        .unwrap();
    for table in ["web_sessions", "api_tokens"] {
        assert_eq!(count(&raw, table, &alice).await, 0, "{table}");
        assert_eq!(count(&raw, table, &bob).await, 1, "{table}");
    }
}

async fn access(store: &Store, owner: &str, tag: &str) {
    let serial = certificate(store, owner, NOW + 3600).await;
    store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: format!("token-{tag}"),
            user_id: owner.to_owned(),
            cert_serial: serial,
            created_at: NOW,
            expires_at: NOW + 3600,
        })
        .await
        .unwrap();
    store
        .web_sessions()
        .create(
            &NewWebSession {
                id_hash: format!("web-{tag}"),
                user_id: owner.to_owned(),
                csrf_token_hash: format!("csrf-{tag}"),
                created_at: NOW,
                expires_at: NOW + 3600,
                source_ip: None,
                user_agent: None,
            },
            20,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn revocations_since_a_time_come_oldest_first() {
    let (_dir, store, _raw) = open().await;
    let revocations = store.revocations();
    for (subject, at) in [("u-1", 10), ("u-2", 30), ("u-3", 20)] {
        revocations
            .insert(&revocation(RevocationKind::User, subject, "r"), at)
            .await
            .unwrap();
    }

    let since: Vec<String> = revocations
        .since(20)
        .await
        .unwrap()
        .into_iter()
        .map(|revocation| revocation.subject)
        .collect();

    assert_eq!(since, ["u-3", "u-2"]);
    assert_eq!(revocations.since(i64::MIN).await.unwrap().len(), 3);
}

#[tokio::test]
async fn a_deleted_revocation_is_returned_once_and_frees_its_subject() {
    let (_dir, store, _raw) = open().await;
    let revocations = store.revocations();
    let first = revocations
        .insert(&revocation(RevocationKind::Serial, "42", "leaked"), NOW)
        .await
        .unwrap()
        .revocation;

    assert_eq!(
        revocations.delete(&first.id).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(revocations.delete(&first.id).await.unwrap(), None);
    assert_eq!(revocations.get(&first.id).await.unwrap(), None);

    let again: RevokeOutcome = revocations
        .insert(
            &revocation(RevocationKind::Serial, "42", "leaked again"),
            NOW + 1,
        )
        .await
        .unwrap();
    assert!(again.created);
    assert_ne!(again.revocation.id, first.id);
}

#[tokio::test]
async fn pages_walk_newest_first_without_gaps_or_repeats() {
    let (_dir, store, _raw) = open().await;
    let revocations = store.revocations();
    for (index, at) in [10, 20, 20, 20, 30, 40, 50].into_iter().enumerate() {
        revocations
            .insert(
                &revocation(RevocationKind::User, &format!("user-{index}"), "r"),
                at,
            )
            .await
            .unwrap();
    }

    let mut seen = Vec::new();
    let mut cursor = None;
    let mut pages = 0;
    loop {
        let page = revocations.page(cursor.as_ref(), 2).await.unwrap();
        assert!(page.revocations.len() <= 2);
        pages += 1;
        seen.extend(page.revocations);
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(pages, 4);
    assert_eq!(seen.len(), 7);
    let ids: HashSet<&str> = seen.iter().map(|entry| entry.id.as_str()).collect();
    assert_eq!(ids.len(), 7);
    let order: Vec<(i64, &str)> = seen
        .iter()
        .map(|entry| (entry.created_at, entry.id.as_str()))
        .collect();
    let mut sorted = order.clone();
    sorted.sort_by(|left, right| right.cmp(left));
    assert_eq!(order, sorted);

    let exact = revocations.page(None, 7).await.unwrap();
    assert_eq!((exact.revocations.len(), exact.next), (7, None));
    for limit in [0, 501] {
        assert!(matches!(
            revocations.page(None, limit).await,
            Err(StoreError::InvalidInput(_))
        ));
    }
    assert_eq!(
        revocations.page(None, 500).await.unwrap().revocations.len(),
        7
    );
}

#[tokio::test]
async fn revoking_a_node_removes_it_from_the_active_registry() {
    let (_dir, store, raw) = open().await;
    sqlx::query(RAW_NODE)
        .bind("node-a")
        .bind("web-a")
        .execute(&raw)
        .await
        .unwrap();
    let revocations = store.revocations();

    let outcome = revocations
        .insert(
            &revocation(RevocationKind::Node, "node-a", "stolen disk"),
            NOW,
        )
        .await
        .unwrap();

    let removed = outcome.removed_node.expect("the node must be removed");
    assert_eq!(
        (removed.id.as_str(), removed.state),
        ("node-a", NodeState::Removed)
    );
    assert_eq!(removed.removed_at, Some(NOW));
    assert_eq!(store.nodes().get_active("node-a").await.unwrap(), None);

    revocations
        .delete(&outcome.revocation.id)
        .await
        .unwrap()
        .unwrap();
    let again = revocations
        .insert(
            &revocation(RevocationKind::Node, "node-a", "again"),
            NOW + 1,
        )
        .await
        .unwrap();
    assert!(again.created);
    assert_eq!(again.removed_node, None);
    assert_eq!(store.nodes().get_active("node-a").await.unwrap(), None);
}

#[tokio::test]
async fn serial_revocations_are_pruned_a_day_after_their_certificate_expired() {
    let (_dir, store, _raw) = open().await;
    let alice = user(&store, "alice").await;
    let expired = certificate(&store, &alice, NOW).await;
    let current = certificate(&store, &alice, NOW + 3600).await;
    let revocations = store.revocations();
    let lookalikes = [
        format!("0{expired}"),
        format!("{expired}x"),
        format!(" {expired}"),
    ];
    for subject in [expired.to_string(), current.to_string(), "999".to_owned()]
        .into_iter()
        .chain(lookalikes.iter().cloned())
    {
        revocations
            .insert(&revocation(RevocationKind::Serial, &subject, "r"), NOW)
            .await
            .unwrap();
    }
    revocations
        .insert(&revocation(RevocationKind::User, &alice, "r"), NOW)
        .await
        .unwrap();

    assert!(
        revocations
            .prune_expired_serials(NOW)
            .await
            .unwrap()
            .is_empty()
    );
    let pruned = revocations.prune_expired_serials(NOW + 1).await.unwrap();

    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].subject, expired.to_string());
    let left = revocations.page(None, 10).await.unwrap().revocations;
    assert_eq!(left.len(), 6);
    assert!(
        lookalikes
            .iter()
            .all(|subject| left.iter().any(|kept| kept.subject == *subject))
    );
    assert!(
        !revocations
            .any_matches(Subjects {
                user_id: "someone-else",
                serial: Some(expired),
                node_id: None,
            })
            .await
            .unwrap()
    );
}
