use jaunt_store::{
    AdminToken, AdminTokenCaps, AdminTokenCreated, AdminTokenRevoked, NewAdminToken, SecretHash,
    Store, StoredAdminToken,
};
use tempfile::TempDir;

const NOW: i64 = 1_000_000;
const TTL: i64 = 3_600;
const CAP: u32 = 20;
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const CAPS: AdminTokenCaps = AdminTokenCaps {
    max_live_per_creator: CAP,
    max_dead_per_creator: 100,
    max_created_per_window: 30,
    window_secs: HOUR,
};
const ALICE: &str = "3f2b1c9e-7a44-4d0e-9c58-0a6b8f1d2e77";
const BOB: &str = "9a1e6c2d-0b7f-4c3e-8d51-6f2a9b0c4e13";

async fn open_store() -> (TempDir, Store) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store::open(&dir.path().join("jaunt.db"))
        .await
        .expect("open");
    store.migrate().await.expect("migrate");
    (dir, store)
}

fn new_token(id: &str, name: &str, creator: &str) -> NewAdminToken {
    NewAdminToken {
        id: id.to_owned(),
        name: name.to_owned(),
        creator_user_id: creator.to_owned(),
        secret_hash: SecretHash::new(format!("hash-of-{id}")),
        scope: vec!["audit.read".to_owned()],
        cidrs: vec!["192.0.2.0/24".to_owned()],
        ttl_secs: TTL,
    }
}

async fn create(store: &Store, token: &NewAdminToken, now: i64) -> AdminTokenCreated {
    store
        .admin_tokens()
        .create(token, now, CAPS)
        .await
        .expect("create")
}

async fn listed(store: &Store, now: i64) -> Vec<AdminToken> {
    store
        .admin_tokens()
        .list(now, 0, 1_000)
        .await
        .expect("list")
        .tokens
}

#[tokio::test]
async fn a_created_token_is_found_by_id_with_its_hash_and_listed_without_it() {
    let (_dir, store) = open_store().await;
    let AdminTokenCreated::Created(created) =
        create(&store, &new_token("id-1", "ci-audit", ALICE), NOW).await
    else {
        panic!("the token was not created");
    };
    assert_eq!(created.expires_at, NOW + TTL);
    assert_eq!(created.scope, ["audit.read"]);
    assert_eq!(created.cidrs, ["192.0.2.0/24"]);
    assert_eq!((created.revoked_at, created.last_used_at), (None, None));

    let StoredAdminToken { token, secret_hash } = store
        .admin_tokens()
        .get_for_use("id-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(token, created);
    assert_eq!(secret_hash.expose(), "hash-of-id-1");
    assert!(!format!("{secret_hash:?}").contains("hash-of"));
    assert!(
        !format!("{:?}", new_token("id-1", "ci-audit", ALICE)).contains("hash-of"),
        "the new token Debug shows the hash"
    );
    assert_eq!(listed(&store, NOW).await, [created]);
    assert_eq!(
        store.admin_tokens().get_for_use("id-2").await.unwrap(),
        None
    );
}

#[tokio::test]
async fn a_creator_holds_at_most_twenty_live_tokens_and_dead_ones_do_not_count() {
    let (_dir, store) = open_store().await;
    for index in 0..CAP {
        let token = new_token(&format!("a-{index}"), &format!("t{index}"), ALICE);
        assert!(matches!(
            create(&store, &token, NOW).await,
            AdminTokenCreated::Created(_)
        ));
    }
    assert_eq!(
        create(&store, &new_token("a-extra", "extra", ALICE), NOW).await,
        AdminTokenCreated::TooMany
    );
    assert!(matches!(
        create(&store, &new_token("b-0", "extra", BOB), NOW).await,
        AdminTokenCreated::Created(_)
    ));

    store.admin_tokens().revoke("a-0", NOW, 100).await.unwrap();
    assert!(matches!(
        create(&store, &new_token("a-after-revoke", "extra", ALICE), NOW).await,
        AdminTokenCreated::Created(_)
    ));
    assert_eq!(
        create(&store, &new_token("a-full", "full", ALICE), NOW).await,
        AdminTokenCreated::TooMany
    );
    assert!(matches!(
        create(&store, &new_token("a-later", "later", ALICE), NOW + TTL).await,
        AdminTokenCreated::Created(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creations_never_exceed_the_cap() {
    let (_dir, store) = open_store().await;
    let attempts: Vec<_> = (0..CAP + 10)
        .map(|index| {
            let store = store.clone();
            tokio::spawn(async move {
                let token = new_token(&format!("c-{index}"), &format!("c{index}"), ALICE);
                create(&store, &token, NOW).await
            })
        })
        .collect();
    let mut created = 0;
    for attempt in attempts {
        if matches!(attempt.await.unwrap(), AdminTokenCreated::Created(_)) {
            created += 1;
        }
    }
    assert_eq!(created, CAP);
}

#[tokio::test]
async fn a_name_is_unique_among_the_live_tokens_of_one_creator() {
    let (_dir, store) = open_store().await;
    assert!(matches!(
        create(&store, &new_token("n-1", "ci", ALICE), NOW).await,
        AdminTokenCreated::Created(_)
    ));
    assert_eq!(
        create(&store, &new_token("n-2", "ci", ALICE), NOW).await,
        AdminTokenCreated::NameTaken
    );
    assert!(matches!(
        create(&store, &new_token("n-3", "ci", BOB), NOW).await,
        AdminTokenCreated::Created(_)
    ));
    assert!(matches!(
        create(&store, &new_token("n-4", "ci", ALICE), NOW + TTL).await,
        AdminTokenCreated::Created(_)
    ));
    store
        .admin_tokens()
        .revoke("n-4", NOW + TTL, 100)
        .await
        .unwrap();
    assert!(matches!(
        create(&store, &new_token("n-5", "ci", ALICE), NOW + TTL).await,
        AdminTokenCreated::Created(_)
    ));
}

#[tokio::test]
async fn revocation_marks_the_row_once_and_unknown_ids_are_reported() {
    let (_dir, store) = open_store().await;
    create(&store, &new_token("r-1", "ci", ALICE), NOW).await;
    let tokens = store.admin_tokens();
    let AdminTokenRevoked::Revoked(revoked) = tokens.revoke("r-1", NOW + 5, 100).await.unwrap()
    else {
        panic!("the token was not revoked");
    };
    assert_eq!(revoked.revoked_at, Some(NOW + 5));
    assert_eq!(
        tokens.revoke("r-1", NOW + 6, 100).await.unwrap(),
        AdminTokenRevoked::AlreadyRevoked
    );
    assert_eq!(
        tokens.revoke("r-2", NOW, 100).await.unwrap(),
        AdminTokenRevoked::Unknown
    );
    let stored = tokens.get_for_use("r-1").await.unwrap().unwrap();
    assert_eq!(stored.token.revoked_at, Some(NOW + 5));
}

#[tokio::test]
async fn last_use_is_recorded_at_most_once_per_interval() {
    let (_dir, store) = open_store().await;
    create(&store, &new_token("u-1", "ci", ALICE), NOW).await;
    let tokens = store.admin_tokens();
    assert!(tokens.touch("u-1", NOW + 10, 60).await.unwrap());
    assert!(!tokens.touch("u-1", NOW + 70, 60).await.unwrap());
    assert!(tokens.touch("u-1", NOW + 71, 60).await.unwrap());
    assert!(!tokens.touch("u-2", NOW + 71, 60).await.unwrap());
    let stored = tokens.get_for_use("u-1").await.unwrap().unwrap();
    assert_eq!(stored.token.last_used_at, Some(NOW + 71));
}

#[tokio::test]
async fn purging_removes_a_token_thirty_days_after_it_was_revoked_or_expired_whichever_came_first()
{
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    for (id, ttl) in [("expired", 60), ("revoked", 90 * DAY), ("live", 90 * DAY)] {
        let token = NewAdminToken {
            ttl_secs: ttl,
            ..new_token(id, id, ALICE)
        };
        create(&store, &token, NOW).await;
    }
    tokens.revoke("revoked", NOW + 100, 100).await.unwrap();
    let cutoff = |now: i64| now - 30 * DAY;
    assert_eq!(
        tokens
            .purge_dead(cutoff(NOW + 60 + 30 * DAY))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        tokens
            .purge_dead(cutoff(NOW + 61 + 30 * DAY))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        tokens
            .purge_dead(cutoff(NOW + 100 + 30 * DAY))
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        tokens
            .purge_dead(cutoff(NOW + 101 + 30 * DAY))
            .await
            .unwrap(),
        1
    );
    let left: Vec<String> = listed(&store, NOW)
        .await
        .into_iter()
        .map(|token| token.id)
        .collect();
    assert_eq!(left, ["live"]);
}

#[tokio::test]
async fn two_hundred_create_and_revoke_cycles_keep_at_most_the_live_and_dead_caps() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    let mut now = NOW;
    for cycle in 0..200 {
        now += 120;
        let token = new_token(&format!("y-{cycle}"), &format!("y{cycle}"), ALICE);
        assert!(
            matches!(
                create(&store, &token, now).await,
                AdminTokenCreated::Created(_)
            ),
            "{cycle}"
        );
        if cycle > 0 {
            tokens
                .revoke(&format!("y-{}", cycle - 1), now, 100)
                .await
                .unwrap();
        }
    }
    let rows = listed(&store, now).await;
    let live = rows
        .iter()
        .filter(|token| token.revoked_at.is_none())
        .count();
    let dead = rows.len() - live;
    assert_eq!((live, dead), (1, 100));
    assert!(rows.iter().any(|token| token.id == "y-198"));
    assert!(!rows.iter().any(|token| token.id == "y-98"));
}

#[tokio::test]
async fn a_creator_makes_at_most_thirty_tokens_an_hour() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    for index in 0..30 {
        let token = new_token(&format!("h-{index}"), &format!("h{index}"), ALICE);
        assert!(matches!(
            create(&store, &token, NOW + index).await,
            AdminTokenCreated::Created(_)
        ));
        tokens
            .revoke(&format!("h-{index}"), NOW + index, 100)
            .await
            .unwrap();
    }
    let next = new_token("h-next", "next", ALICE);
    assert_eq!(
        create(&store, &next, NOW + 40).await,
        AdminTokenCreated::TooFrequent {
            retry_after_secs: HOUR - 40
        }
    );
    assert!(matches!(
        create(&store, &new_token("b-1", "next", BOB), NOW + 40).await,
        AdminTokenCreated::Created(_)
    ));
    assert_eq!(
        create(&store, &next, NOW + HOUR - 1).await,
        AdminTokenCreated::TooFrequent {
            retry_after_secs: 1
        }
    );
    assert!(matches!(
        create(&store, &next, NOW + HOUR).await,
        AdminTokenCreated::Created(_)
    ));
}

#[tokio::test]
async fn the_list_shows_live_and_recently_dead_tokens_newest_first_up_to_its_bound() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    for (index, id) in ["old-dead", "recent-dead", "expired", "live-1", "live-2"]
        .into_iter()
        .enumerate()
    {
        let ttl = if id == "expired" { 60 } else { 90 * DAY };
        let token = NewAdminToken {
            ttl_secs: ttl,
            ..new_token(id, id, ALICE)
        };
        create(&store, &token, NOW + i64::try_from(index).unwrap()).await;
    }
    tokens.revoke("old-dead", NOW, 100).await.unwrap();
    tokens
        .revoke("recent-dead", NOW + 2 * DAY, 100)
        .await
        .unwrap();
    let now = NOW + 8 * DAY;
    let page = tokens.list(now, now - 7 * DAY, 10).await.unwrap();
    let ids: Vec<&str> = page.tokens.iter().map(|token| token.id.as_str()).collect();
    assert_eq!(ids, ["live-2", "live-1", "recent-dead"]);
    assert!(!page.truncated);
    let cut = tokens.list(now, now - 7 * DAY, 2).await.unwrap();
    assert_eq!(cut.tokens.len(), 2);
    assert!(cut.truncated);
    let exact = tokens.list(now, now - 7 * DAY, 3).await.unwrap();
    assert!(!exact.truncated);
}

#[tokio::test]
async fn creation_rejects_empty_fields_and_lifetimes() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    let valid = new_token("v-1", "ci", ALICE);
    for broken in [
        NewAdminToken {
            id: String::new(),
            ..valid.clone()
        },
        NewAdminToken {
            name: String::new(),
            ..valid.clone()
        },
        NewAdminToken {
            secret_hash: SecretHash::new(String::new()),
            ..valid.clone()
        },
        NewAdminToken {
            scope: Vec::new(),
            ..valid.clone()
        },
        NewAdminToken {
            ttl_secs: 0,
            ..valid.clone()
        },
    ] {
        assert!(tokens.create(&broken, NOW, CAPS).await.is_err());
    }
    let no_live = AdminTokenCaps {
        max_live_per_creator: 0,
        ..CAPS
    };
    assert!(tokens.create(&valid, NOW, no_live).await.is_err());
    assert!(listed(&store, NOW).await.is_empty());
}

fn dead_ids(rows: &[AdminToken], now: i64) -> Vec<String> {
    rows.iter()
        .filter(|token| token.revoked_at.is_some() || token.expires_at <= now)
        .map(|token| token.id.clone())
        .collect()
}

#[tokio::test]
async fn live_tokens_come_first_so_dead_rows_never_push_them_off_the_page() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    let busy = AdminTokenCaps {
        max_created_per_window: 1_000,
        ..CAPS
    };
    let old_live = NewAdminToken {
        ttl_secs: 90 * DAY,
        ..new_token("old-live", "old-live", ALICE)
    };
    create(&store, &old_live, NOW).await;
    let now = NOW + 10 * DAY;
    for creator in 0..5 {
        for index in 0..100 {
            let id = format!("d-{creator}-{index}");
            let token = new_token(&id, &id, &format!("creator-{creator}"));
            let created = tokens.create(&token, now, busy).await.unwrap();
            assert!(matches!(created, AdminTokenCreated::Created(_)), "{id}");
            tokens.revoke(&id, now, 100).await.unwrap();
        }
    }

    let page = tokens.list(now, now - 7 * DAY, 500).await.unwrap();

    assert!(page.truncated);
    assert_eq!(page.tokens.len(), 500);
    assert_eq!(page.tokens[0].id, "old-live");
}

#[tokio::test]
async fn creation_alone_keeps_at_most_the_dead_cap_of_a_creator() {
    let (_dir, store) = open_store().await;
    let mut now = NOW;
    for index in 0..150 {
        now += 125;
        let token = NewAdminToken {
            ttl_secs: 60,
            ..new_token(&format!("e-{index}"), &format!("e{index}"), ALICE)
        };
        assert!(
            matches!(
                create(&store, &token, now).await,
                AdminTokenCreated::Created(_)
            ),
            "{index}"
        );
        let dead = dead_ids(&listed(&store, now).await, now);
        assert!(dead.len() <= 100, "{index}: {}", dead.len());
    }
    let rows = listed(&store, now).await;
    assert_eq!(dead_ids(&rows, now).len(), 100);
    assert!(!rows.iter().any(|token| token.id == "e-48"));
    assert!(rows.iter().any(|token| token.id == "e-49"));
}

#[tokio::test]
async fn a_token_revoked_after_it_expired_counts_as_dead_since_its_expiry() {
    let (_dir, store) = open_store().await;
    let tokens = store.admin_tokens();
    let short = NewAdminToken {
        ttl_secs: 60,
        ..new_token("late-revoked", "late-revoked", ALICE)
    };
    let long = NewAdminToken {
        ttl_secs: 90 * DAY,
        ..new_token("revoked", "revoked", ALICE)
    };
    create(&store, &short, NOW).await;
    create(&store, &long, NOW).await;
    tokens
        .revoke("revoked", NOW + 7 * DAY + 100, 100)
        .await
        .unwrap();
    tokens
        .revoke("late-revoked", NOW + 7 * DAY + 150, 100)
        .await
        .unwrap();
    let now = NOW + 7 * DAY + 200;

    let page = tokens.list(now, now - 7 * DAY, 10).await.unwrap();
    let listed_ids: Vec<&str> = page.tokens.iter().map(|token| token.id.as_str()).collect();
    assert_eq!(listed_ids, ["revoked"]);

    let AdminTokenCreated::Created(_) =
        create(&store, &new_token("fresh", "fresh", ALICE), now).await
    else {
        panic!("the token was not created");
    };
    tokens.revoke("fresh", now, 2).await.unwrap();
    let left: Vec<String> = listed(&store, now)
        .await
        .into_iter()
        .map(|token| token.id)
        .collect();
    assert_eq!(left, ["fresh", "revoked"]);
}
