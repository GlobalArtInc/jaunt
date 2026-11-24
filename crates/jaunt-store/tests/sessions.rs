use jaunt_store::{
    ActivateSession, EndOutcome, EndRejection, EndSession, NewCertificate, NewSession, NewUser,
    Session, SessionState, Store, StoreError,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 1_000;
const TTL: i64 = 60;
const NODE: &str = "node-a";
const OTHER_NODE: &str = "node-b";

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)";

struct Fixture {
    _dir: TempDir,
    store: Store,
    raw: SqlitePool,
    user_id: String,
    serial: i64,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.expect("open");
    store.migrate().await.expect("migrate");
    let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .expect("raw pool");
    for (id, name) in [(NODE, "web-a"), (OTHER_NODE, "web-b")] {
        sqlx::query(RAW_NODE)
            .bind(id)
            .bind(name)
            .execute(&raw)
            .await
            .expect("node");
    }
    let user = store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            NOW,
        )
        .await
        .expect("user");
    let serial = store
        .certificates()
        .allocate_serial()
        .await
        .expect("serial");
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user.id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:alice@example.com:{serial}"),
            valid_after: NOW - 120,
            valid_before: NOW + 3600,
            issued_at: NOW,
        })
        .await
        .expect("certificate");
    Fixture {
        _dir: dir,
        store,
        raw,
        user_id: user.id,
        serial,
    }
}

impl Fixture {
    async fn routed(&self) -> Session {
        self.store
            .sessions()
            .create(
                &NewSession {
                    user_id: self.user_id.clone(),
                    serial: self.serial,
                    node_id: NODE.to_owned(),
                    ttl_secs: TTL,
                },
                NOW,
            )
            .await
            .expect("create")
    }

    fn activation<'a>(&'a self, session: &'a Session, now: i64) -> ActivateSession<'a> {
        ActivateSession {
            id: &session.id,
            node_id: NODE,
            user_id: &self.user_id,
            serial: self.serial,
            login: "deploy",
            now,
        }
    }

    async fn active(&self) -> Session {
        let session = self.routed().await;
        self.store
            .sessions()
            .activate(self.activation(&session, NOW + 1))
            .await
            .expect("activate")
            .expect("activated")
    }
}

fn end_of<'a>(session: &'a Session, node_id: &'a str, bytes_out: i64) -> EndSession<'a> {
    EndSession {
        id: &session.id,
        node_id,
        exit_status: Some(0),
        bytes_in: 10,
        bytes_out,
        recording_incomplete: false,
        now: NOW + 5,
    }
}

#[tokio::test]
async fn a_routed_session_is_bound_to_user_serial_and_node_with_a_short_expiry() {
    let fixture = fixture().await;
    let session = fixture.routed().await;
    let stored = fixture
        .store
        .sessions()
        .get(&session.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored, session);
    assert_eq!(stored.state, SessionState::Routed);
    assert_eq!(
        (
            stored.user_id.as_str(),
            stored.serial,
            stored.node_id.as_str()
        ),
        (fixture.user_id.as_str(), fixture.serial, NODE)
    );
    assert_eq!((stored.created_at, stored.expires_at), (NOW, NOW + TTL));
    assert_eq!((stored.authorized_at, stored.login), (None, None));

    let zero = NewSession {
        user_id: fixture.user_id.clone(),
        serial: fixture.serial,
        node_id: NODE.to_owned(),
        ttl_secs: 0,
    };
    let err = fixture.store.sessions().create(&zero, NOW).await;
    assert!(matches!(err, Err(StoreError::InvalidInput(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_one_of_sixteen_concurrent_activations_wins() {
    let fixture = fixture().await;
    let session = fixture.routed().await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let sessions = fixture.store.sessions();
        let (id, user_id, serial) = (session.id.clone(), fixture.user_id.clone(), fixture.serial);
        tasks.push(tokio::spawn(async move {
            sessions
                .activate(ActivateSession {
                    id: &id,
                    node_id: NODE,
                    user_id: &user_id,
                    serial,
                    login: "deploy",
                    now: NOW + 1,
                })
                .await
                .expect("activate")
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(session) = task.await.expect("join") {
            winners.push(session);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].state, SessionState::Active);
    assert_eq!(winners[0].authorized_at, Some(NOW + 1));
    assert_eq!(winners[0].login.as_deref(), Some("deploy"));
}

#[tokio::test]
async fn activation_requires_the_owning_node_the_bound_holder_and_an_unexpired_binding() {
    let fixture = fixture().await;
    let session = fixture.routed().await;
    let sessions = fixture.store.sessions();
    let base = fixture.activation(&session, NOW + 1);
    let refused = [
        ActivateSession {
            node_id: OTHER_NODE,
            ..base
        },
        ActivateSession {
            user_id: "someone-else",
            ..base
        },
        ActivateSession {
            serial: fixture.serial + 1,
            ..base
        },
        ActivateSession {
            now: NOW + TTL,
            ..base
        },
    ];
    for activation in refused {
        assert_eq!(sessions.activate(activation).await.unwrap(), None);
    }
    let last_second = ActivateSession {
        now: NOW + TTL - 1,
        ..base
    };
    assert!(sessions.activate(last_second).await.unwrap().is_some());
    assert_eq!(sessions.activate(last_second).await.unwrap(), None);
}

#[tokio::test]
async fn a_node_removed_just_before_activation_cannot_activate_its_session() {
    let fixture = fixture().await;
    let session = fixture.routed().await;
    sqlx::query("UPDATE nodes SET state = 'removed', removed_at = ? WHERE id = ?")
        .bind(NOW)
        .bind(NODE)
        .execute(&fixture.raw)
        .await
        .expect("remove the node");

    let sessions = fixture.store.sessions();
    let activation = fixture.activation(&session, NOW + 1);
    assert_eq!(sessions.activate(activation).await.unwrap(), None);
    let stored = sessions.get(&session.id).await.unwrap().unwrap();
    assert_eq!(stored.state, SessionState::Routed);
}

#[tokio::test]
async fn only_the_owner_ends_an_active_session_and_an_identical_repeat_is_idempotent() {
    let fixture = fixture().await;
    let sessions = fixture.store.sessions();

    let routed = fixture.routed().await;
    assert_eq!(
        sessions.end(end_of(&routed, NODE, 20)).await.unwrap(),
        EndOutcome::Rejected(EndRejection::NotActive)
    );
    let unknown = Session {
        id: "unknown".to_owned(),
        ..routed.clone()
    };
    assert_eq!(
        sessions.end(end_of(&unknown, NODE, 20)).await.unwrap(),
        EndOutcome::Rejected(EndRejection::UnknownSession)
    );

    let active = fixture.active().await;
    assert_eq!(
        sessions.end(end_of(&active, OTHER_NODE, 20)).await.unwrap(),
        EndOutcome::Rejected(EndRejection::WrongNode)
    );
    let EndOutcome::Ended(ended) = sessions.end(end_of(&active, NODE, 20)).await.unwrap() else {
        panic!("the owner must end the session");
    };
    assert_eq!(ended.state, SessionState::Ended);
    assert_eq!(
        (
            ended.ended_at,
            ended.exit_status,
            ended.bytes_in,
            ended.bytes_out,
            ended.recording_incomplete
        ),
        (Some(NOW + 5), Some(0), Some(10), Some(20), Some(false))
    );
    assert_eq!(
        sessions.end(end_of(&active, NODE, 20)).await.unwrap(),
        EndOutcome::Repeated
    );
    let identical = end_of(&active, NODE, 20);
    let conflicting = [
        EndSession {
            bytes_out: 21,
            ..identical
        },
        EndSession {
            bytes_in: 11,
            ..identical
        },
        EndSession {
            exit_status: None,
            ..identical
        },
        EndSession {
            exit_status: Some(1),
            ..identical
        },
        EndSession {
            recording_incomplete: true,
            ..identical
        },
    ];
    for end in conflicting {
        assert_eq!(
            sessions.end(end).await.unwrap(),
            EndOutcome::Rejected(EndRejection::ConflictingEnd),
            "{end:?}"
        );
    }
    assert_eq!(
        sessions.end(end_of(&active, OTHER_NODE, 20)).await.unwrap(),
        EndOutcome::Rejected(EndRejection::WrongNode)
    );
    let stored = sessions.get(&active.id).await.unwrap().unwrap();
    assert_eq!(stored, *ended);
}

#[tokio::test]
async fn purge_removes_only_routed_sessions_that_expired_before_the_cutoff() {
    let fixture = fixture().await;
    let sessions = fixture.store.sessions();
    let stale = fixture.routed().await;
    let active = fixture.active().await;
    let ended = fixture.active().await;
    assert!(matches!(
        sessions.end(end_of(&ended, NODE, 1)).await.unwrap(),
        EndOutcome::Ended(_)
    ));

    assert_eq!(sessions.purge_expired_routed(NOW + TTL).await.unwrap(), 0);
    assert_eq!(
        sessions.purge_expired_routed(NOW + TTL + 1).await.unwrap(),
        1
    );
    assert_eq!(sessions.get(&stale.id).await.unwrap(), None);
    assert!(sessions.get(&active.id).await.unwrap().is_some());
    assert!(sessions.get(&ended.id).await.unwrap().is_some());
}
