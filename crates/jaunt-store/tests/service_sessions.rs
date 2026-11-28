use std::path::Path;

use jaunt_store::{
    ActivateService, EndOutcome, EndRejection, EndService, KubeOpened, LiveEntry, NewCertificate,
    NewServiceRoute, NewSession, NewUser, OpenKubeSession, ServiceRouted, Session,
    SessionEndReason, SessionKind, SessionState, Store, StoreError,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 10_000;
const WINDOW: i64 = 30;
const NODE: &str = "node-a";
const OTHER_NODE: &str = "node-b";
const CAP: i64 = 3;

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)";

const RAW_SERVICE: &str = "INSERT INTO services (id, node_id, kind, name, labels, \
    announced_labels, settings, address_hint, state, revision, announced, approved_by, \
    approved_at, created_at, last_seen_at) \
    VALUES (?, ?, ?, ?, ?, ?, '{}', NULL, ?, ?, 1, 'cli:root', 1, 1, 1)";

fn name_of(service_id: &str) -> &'static str {
    match service_id {
        "svc-tcp-1" | "svc-tcp-2" | "svc-tcp-3" => "grafana",
        "svc-db" => "lk",
        "svc-kube" => "prod",
        _ => "metrics",
    }
}

fn readable<T: std::fmt::Debug>(entry: &LiveEntry<T>) -> &T {
    match entry {
        LiveEntry::Readable(live) => live,
        LiveEntry::Unreadable { .. } => panic!("unreadable: {entry:?}"),
    }
}

struct Fixture {
    _dir: TempDir,
    store: Store,
    raw: SqlitePool,
    users: Vec<String>,
    serial: i64,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    for (id, name) in [(NODE, "web-a"), (OTHER_NODE, "web-b")] {
        sqlx::query(RAW_NODE)
            .bind(id)
            .bind(name)
            .execute(&raw)
            .await
            .unwrap();
    }
    let mut users = Vec::new();
    for subject in ["alice", "bob"] {
        let user = store
            .users()
            .upsert(
                &NewUser {
                    issuer: "https://idp.example".to_owned(),
                    subject: subject.to_owned(),
                    email: format!("{subject}@example.com"),
                    username: subject.to_owned(),
                    display_name: None,
                    groups: vec!["ops".to_owned()],
                },
                NOW,
            )
            .await
            .unwrap();
        users.push(user.id);
    }
    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: users[0].clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:alice@example.com:{serial}"),
            valid_after: NOW - 120,
            valid_before: NOW + 3600,
            issued_at: NOW,
            ca_fingerprint: None,
            host_trust_id: None,
            subject_fingerprint: None,
        })
        .await
        .unwrap();
    for (id, node, kind, name, state, revision) in [
        ("svc-tcp-1", NODE, "tcp", "grafana", "removed", 1),
        ("svc-tcp-2", NODE, "tcp", "grafana", "approved", 2),
        ("svc-db", NODE, "postgres", "lk", "approved", 1),
        ("svc-kube", NODE, "kubernetes", "prod", "approved", 1),
        ("svc-metrics", NODE, "tcp", "metrics", "approved", 1),
        ("svc-other", OTHER_NODE, "tcp", "metrics", "approved", 1),
    ] {
        sqlx::query(RAW_SERVICE)
            .bind(id)
            .bind(node)
            .bind(kind)
            .bind(name)
            .bind(r#"{"team":"ops"}"#)
            .bind(r#"{"team":"ops"}"#)
            .bind(state)
            .bind(revision)
            .execute(&raw)
            .await
            .unwrap();
    }
    Fixture {
        _dir: dir,
        store,
        raw,
        users,
        serial,
    }
}

impl Fixture {
    fn alice(&self) -> &str {
        &self.users[0]
    }

    fn route_of<'a>(
        &'a self,
        user_id: &'a str,
        kind: SessionKind,
        service: &'a str,
    ) -> NewServiceRoute<'a> {
        NewServiceRoute {
            user_id,
            serial: self.serial,
            node_id: NODE,
            kind,
            service_id: service,
            service_name: name_of(service),
            ttl_secs: WINDOW,
            max_open: CAP,
            now: NOW,
        }
    }

    async fn routed(&self, kind: SessionKind, service: &str) -> Session {
        match self
            .store
            .service_sessions()
            .route(&self.route_of(self.alice(), kind, service))
            .await
            .unwrap()
        {
            ServiceRouted::Routed(session) => *session,
            ServiceRouted::TooMany => panic!("the cap was reached"),
        }
    }

    fn activation<'a>(&'a self, session: &'a Session, roles: &'a [String]) -> ActivateService<'a> {
        ActivateService {
            id: &session.id,
            node_id: NODE,
            user_id: self.alice(),
            serial: self.serial,
            kind: session.kind,
            service_id: session.service_id.as_deref().unwrap(),
            login: Some("app"),
            target: Some("main"),
            roles,
            max_duration_secs: 3600,
            db_client_serial: Some(77),
            now: NOW + 1,
        }
    }

    async fn active_db(&self) -> Session {
        let routed = self.routed(SessionKind::Db, "svc-db").await;
        let roles = vec!["dba".to_owned()];
        self.store
            .service_sessions()
            .activate(&self.activation(&routed, &roles))
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn a_routed_service_session_is_activated_once_and_records_what_was_decided() {
    let fixture = fixture().await;
    let routed = fixture.routed(SessionKind::Db, "svc-db").await;
    assert_eq!(
        (routed.kind, routed.state, routed.expires_at),
        (SessionKind::Db, SessionState::Routed, NOW + WINDOW)
    );
    assert_eq!(routed.service_id.as_deref(), Some("svc-db"));
    assert!(routed.roles.is_empty() && routed.grant_ids.is_empty());

    let roles = vec!["dba".to_owned(), "readers".to_owned()];
    let sessions = fixture.store.service_sessions();
    let base = fixture.activation(&routed, &roles);
    let refused = [
        ActivateService {
            node_id: OTHER_NODE,
            ..base
        },
        ActivateService {
            user_id: &fixture.users[1],
            ..base
        },
        ActivateService {
            serial: fixture.serial + 1,
            ..base
        },
        ActivateService {
            kind: SessionKind::Tcp,
            ..base
        },
        ActivateService {
            service_id: "svc-tcp-2",
            ..base
        },
        ActivateService {
            now: NOW + WINDOW,
            ..base
        },
    ];
    for (index, activation) in refused.iter().enumerate() {
        assert_eq!(
            sessions.activate(activation).await.unwrap(),
            None,
            "{index}"
        );
    }
    let active = sessions.activate(&base).await.unwrap().unwrap();
    assert_eq!(active.state, SessionState::Active);
    assert_eq!(active.login.as_deref(), Some("app"));
    assert_eq!(active.target.as_deref(), Some("main"));
    assert_eq!(active.roles, roles);
    assert_eq!(active.db_client_serial, Some(77));
    assert_eq!(active.max_duration_secs, Some(3600));
    assert_eq!(sessions.activate(&base).await.unwrap(), None);
    assert!(matches!(
        sessions
            .activate(&ActivateService {
                kind: SessionKind::Ssh,
                ..base
            })
            .await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn the_open_session_cap_counts_every_revision_of_the_service_and_only_live_rows() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let old_revision = fixture.routed(SessionKind::Tcp, "svc-tcp-1").await;
    for _ in 1..CAP {
        fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    }
    assert_eq!(
        sessions
            .route(&fixture.route_of(fixture.alice(), SessionKind::Tcp, "svc-tcp-2"))
            .await
            .unwrap(),
        ServiceRouted::TooMany
    );
    assert!(matches!(
        sessions
            .route(&fixture.route_of(&fixture.users[1], SessionKind::Tcp, "svc-tcp-2"))
            .await
            .unwrap(),
        ServiceRouted::Routed(_)
    ));
    assert!(matches!(
        sessions
            .route(&fixture.route_of(fixture.alice(), SessionKind::Db, "svc-db"))
            .await
            .unwrap(),
        ServiceRouted::Routed(_)
    ));

    sqlx::query("UPDATE sessions SET state = 'ended' WHERE id = ?")
        .bind(&old_revision.id)
        .execute(&fixture.raw)
        .await
        .unwrap();
    let ended_freed = NewServiceRoute {
        now: NOW + 1,
        ..fixture.route_of(fixture.alice(), SessionKind::Tcp, "svc-tcp-2")
    };
    assert!(matches!(
        sessions.route(&ended_freed).await.unwrap(),
        ServiceRouted::Routed(_)
    ));
    assert_eq!(
        sessions.route(&ended_freed).await.unwrap(),
        ServiceRouted::TooMany
    );
    let after_the_window = NewServiceRoute {
        now: NOW + WINDOW,
        ..fixture.route_of(fixture.alice(), SessionKind::Tcp, "svc-tcp-2")
    };
    assert!(matches!(
        sessions.route(&after_the_window).await.unwrap(),
        ServiceRouted::Routed(_)
    ));
    assert!(matches!(
        sessions
            .route(&fixture.route_of(fixture.alice(), SessionKind::Ssh, "svc-tcp-2"))
            .await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn a_kube_session_is_opened_with_the_given_id_once_and_only_on_an_active_node() {
    let fixture = fixture().await;
    let roles = vec!["platform".to_owned()];
    let open = OpenKubeSession {
        id: "k-0123456789abcdef0123456789abcdef",
        user_id: fixture.alice(),
        serial: fixture.serial,
        node_id: NODE,
        service_id: "svc-kube",
        roles: &roles,
        max_duration_secs: 3600,
        decision_hash: &"ab".repeat(32),
        service_name: "prod",
        max_per_user: 10,
        max_per_service: 10,
        now: NOW,
    };
    let sessions = fixture.store.service_sessions();
    for bad in [
        "".to_owned(),
        "AB".repeat(32),
        "ab".repeat(31),
        "zz".repeat(32),
    ] {
        assert!(matches!(
            sessions
                .open_kube(&OpenKubeSession {
                    decision_hash: &bad,
                    ..open
                })
                .await,
            Err(StoreError::InvalidInput(_))
        ));
    }
    let KubeOpened::Opened(opened) = sessions.open_kube(&open).await.unwrap() else {
        panic!("the session was not opened");
    };
    assert_eq!(
        (opened.kind, opened.state, opened.authorized_at),
        (SessionKind::Kube, SessionState::Active, Some(NOW))
    );
    assert_eq!(opened.roles, roles);
    assert_eq!(opened.decision_hash, Some("ab".repeat(32)));
    assert_eq!(
        sessions.open_kube(&open).await.unwrap(),
        KubeOpened::Repeated
    );
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = ?")
        .bind(OTHER_NODE)
        .execute(&fixture.raw)
        .await
        .unwrap();
    let elsewhere = OpenKubeSession {
        id: "k-ffffffffffffffffffffffffffffffff",
        node_id: OTHER_NODE,
        ..open
    };
    assert_eq!(
        sessions.open_kube(&elsewhere).await.unwrap(),
        KubeOpened::NodeInactive
    );
}

#[tokio::test]
async fn a_service_end_is_recorded_once_and_never_through_the_wrong_path() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let active = fixture.active_db().await;
    let end = EndService {
        id: &active.id,
        node_id: NODE,
        outcome: "closed",
        bytes_in: 10,
        bytes_out: 20,
        now: NOW + 5,
    };
    let EndOutcome::Ended(ended) = sessions.end(&end).await.unwrap() else {
        panic!("the session did not end");
    };
    assert_eq!(ended.outcome.as_deref(), Some("closed"));
    assert_eq!((ended.bytes_in, ended.bytes_out), (Some(10), Some(20)));
    assert_eq!(ended.end_reason, Some(SessionEndReason::Closed));
    assert_eq!(sessions.end(&end).await.unwrap(), EndOutcome::Repeated);
    for different in [
        EndService {
            outcome: "idle_timeout",
            ..end
        },
        EndService {
            bytes_out: 21,
            ..end
        },
    ] {
        assert_eq!(
            sessions.end(&different).await.unwrap(),
            EndOutcome::Rejected(EndRejection::ConflictingEnd)
        );
    }
    let other = fixture.active_db().await;
    assert_eq!(
        sessions
            .end(&EndService {
                id: &other.id,
                node_id: OTHER_NODE,
                ..end
            })
            .await
            .unwrap(),
        EndOutcome::Rejected(EndRejection::WrongNode)
    );

    let ssh = active_ssh(&fixture).await;
    assert_eq!(
        (ssh.kind, ssh.state),
        (SessionKind::Ssh, SessionState::Active)
    );
    assert_eq!(
        sessions
            .end(&EndService { id: &ssh.id, ..end })
            .await
            .unwrap(),
        EndOutcome::Rejected(EndRejection::UnknownSession)
    );
    let untouched = fixture
        .store
        .sessions()
        .get(&ssh.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (untouched.state, untouched.outcome, untouched.bytes_out),
        (SessionState::Active, None, None)
    );
    let routed = fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    assert_eq!(
        sessions
            .end(&EndService {
                id: &routed.id,
                ..end
            })
            .await
            .unwrap(),
        EndOutcome::Rejected(EndRejection::NotActive)
    );
}

#[tokio::test]
async fn a_service_closed_by_control_takes_its_counters_late_exactly_once() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let active = fixture.active_db().await;
    for wrong in [SessionKind::Ssh, SessionKind::Tcp] {
        assert_eq!(
            sessions
                .close_active(
                    &active.id,
                    wrong,
                    SessionEndReason::AccessWithdrawn,
                    NOW + 2
                )
                .await
                .unwrap(),
            None
        );
    }
    let closed = sessions
        .close_active(
            &active.id,
            SessionKind::Db,
            SessionEndReason::AccessWithdrawn,
            NOW + 3,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closed.end_reason, Some(SessionEndReason::AccessWithdrawn));
    assert_eq!(
        sessions
            .close_active(
                &active.id,
                SessionKind::Db,
                SessionEndReason::AccessWithdrawn,
                NOW + 4
            )
            .await
            .unwrap(),
        None
    );
    let end = EndService {
        id: &active.id,
        node_id: NODE,
        outcome: "upstream_error",
        bytes_in: 1,
        bytes_out: 2,
        now: NOW + 5,
    };
    let EndOutcome::Late(late) = sessions.end(&end).await.unwrap() else {
        panic!("the late counters were not taken");
    };
    assert_eq!(late.end_reason, Some(SessionEndReason::AccessWithdrawn));
    assert_eq!(late.outcome.as_deref(), Some("upstream_error"));
    assert_eq!(
        sessions.end(&end).await.unwrap(),
        EndOutcome::Rejected(EndRejection::ClosedByControl)
    );
}

#[tokio::test]
async fn the_ssh_paths_never_activate_or_end_a_service_session() {
    let fixture = fixture().await;
    let routed = fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    let activated = fixture
        .store
        .sessions()
        .activate(jaunt_store::ActivateSession {
            id: &routed.id,
            node_id: NODE,
            user_id: fixture.alice(),
            serial: fixture.serial,
            login: "deploy",
            max_duration_secs: 60,
            pty: true,
            record_input: false,
            now: NOW + 1,
        })
        .await
        .unwrap();
    assert_eq!(activated, None);
    let active = fixture.active_db().await;
    assert_eq!(
        fixture
            .store
            .sessions()
            .end(jaunt_store::EndSession {
                id: &active.id,
                node_id: NODE,
                exit_status: Some(0),
                bytes_in: 1,
                bytes_out: 1,
                recording_incomplete: false,
                now: NOW + 2,
            })
            .await
            .unwrap(),
        EndOutcome::Rejected(EndRejection::UnknownSession)
    );
}

#[tokio::test]
async fn live_service_sessions_carry_the_holder_and_the_current_approved_revision() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let tcp = fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    let roles = Vec::new();
    let mut activation = fixture.activation(&tcp, &roles);
    activation.login = None;
    activation.target = None;
    activation.db_client_serial = None;
    sessions.activate(&activation).await.unwrap().unwrap();
    let db = fixture.active_db().await;
    fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    for statement in [
        "UPDATE services SET state = 'removed' WHERE id IN ('svc-db', 'svc-tcp-2')",
        "INSERT INTO services (id, node_id, kind, name, labels, announced_labels, settings, \
         state, revision, announced, approved_by, approved_at, created_at, last_seen_at) \
         VALUES ('svc-tcp-3', 'node-a', 'tcp', 'grafana', '{\"team\":\"ops\",\"v\":\"3\"}', \
         '{}', '{}', 'approved', 3, 1, 'cli:root', 2, 2, 2)",
        "DELETE FROM services WHERE id IN ('svc-tcp-1', 'svc-tcp-2')",
    ] {
        sqlx::query(statement).execute(&fixture.raw).await.unwrap();
    }

    let entries = sessions.live().await.unwrap();
    let mut live: Vec<_> = entries.iter().map(readable).collect();
    live.sort_by_key(|entry| entry.service.is_none());
    let found: Vec<(String, Option<String>)> = live
        .iter()
        .map(|entry| {
            (
                entry.session.id.clone(),
                entry.service.as_ref().map(|service| service.id.clone()),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            (tcp.id.clone(), Some("svc-tcp-3".to_owned())),
            (db.id.clone(), None),
        ]
    );
    let first = live[0];
    assert_eq!(first.session.service_name.as_deref(), Some("grafana"));
    assert_eq!(first.email, "alice@example.com");
    assert_eq!(first.groups, ["ops"]);
    let service = first.service.as_ref().unwrap();
    assert_eq!(service.name, "grafana");
    assert_eq!(service.labels.get("v").map(String::as_str), Some("3"));
}

#[tokio::test]
async fn a_live_row_that_cannot_be_read_is_reported_alone_and_the_others_stay_readable() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let mine = fixture.active_db().await;
    let roles = Vec::new();
    let theirs = match sessions
        .route(&fixture.route_of(&fixture.users[1], SessionKind::Db, "svc-db"))
        .await
        .unwrap()
    {
        ServiceRouted::Routed(session) => *session,
        ServiceRouted::TooMany => panic!("the cap was reached"),
    };
    sessions
        .activate(&ActivateService {
            user_id: &fixture.users[1],
            ..fixture.activation(&theirs, &roles)
        })
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE users SET groups = 'not json' WHERE id = ?")
        .bind(&fixture.users[1])
        .execute(&fixture.raw)
        .await
        .unwrap();
    let live = sessions.live().await.unwrap();
    assert_eq!(live.len(), 2);
    for entry in &live {
        match entry {
            LiveEntry::Readable(live) => assert_eq!(live.session.id, mine.id),
            LiveEntry::Unreadable { id, kind, .. } => {
                assert_eq!((id.as_str(), *kind), (theirs.id.as_str(), SessionKind::Db));
            }
        }
    }
    sqlx::query("UPDATE services SET labels = '[' WHERE id = 'svc-db'")
        .execute(&fixture.raw)
        .await
        .unwrap();
    assert!(
        sessions
            .live()
            .await
            .unwrap()
            .iter()
            .all(|entry| matches!(entry, LiveEntry::Unreadable { .. }))
    );
}

async fn open_kube_as(fixture: &Fixture, index: usize, user_id: &str) -> KubeOpened {
    let id = format!("k-{index:032x}");
    let hash = "ab".repeat(32);
    fixture
        .store
        .service_sessions()
        .open_kube(&OpenKubeSession {
            id: &id,
            user_id,
            serial: fixture.serial,
            node_id: NODE,
            service_id: "svc-kube",
            service_name: "prod",
            roles: &[],
            max_duration_secs: 3600,
            decision_hash: &hash,
            max_per_user: 2,
            max_per_service: 3,
            now: NOW,
        })
        .await
        .unwrap()
}

#[tokio::test]
async fn kube_sessions_are_capped_per_user_and_per_cluster() {
    let fixture = fixture().await;
    let (alice, bob) = (fixture.users[0].clone(), fixture.users[1].clone());
    assert!(matches!(
        open_kube_as(&fixture, 0, &alice).await,
        KubeOpened::Opened(_)
    ));
    assert!(matches!(
        open_kube_as(&fixture, 1, &alice).await,
        KubeOpened::Opened(_)
    ));
    assert_eq!(open_kube_as(&fixture, 2, &alice).await, KubeOpened::TooMany);
    assert!(matches!(
        open_kube_as(&fixture, 3, &bob).await,
        KubeOpened::Opened(_)
    ));
    assert_eq!(open_kube_as(&fixture, 4, &bob).await, KubeOpened::TooMany);
    sqlx::query("UPDATE sessions SET state = 'ended' WHERE id = ?")
        .bind(format!("k-{:032x}", 0))
        .execute(&fixture.raw)
        .await
        .unwrap();
    assert!(matches!(
        open_kube_as(&fixture, 4, &bob).await,
        KubeOpened::Opened(_)
    ));
}

#[tokio::test]
async fn a_kube_session_needs_the_cluster_revision_to_still_be_approved() {
    let fixture = fixture().await;
    sqlx::query("UPDATE services SET state = 'removed' WHERE id = 'svc-kube'")
        .execute(&fixture.raw)
        .await
        .unwrap();
    let alice = fixture.users[0].clone();
    assert_eq!(
        open_kube_as(&fixture, 5, &alice).await,
        KubeOpened::ServiceGone
    );
    assert!(
        fixture
            .store
            .sessions()
            .get(&format!("k-{:032x}", 5))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn activation_needs_the_routed_revision_to_still_be_approved() {
    let fixture = fixture().await;
    let routed = fixture.routed(SessionKind::Db, "svc-db").await;
    sqlx::query("UPDATE services SET state = 'removed' WHERE id = 'svc-db'")
        .execute(&fixture.raw)
        .await
        .unwrap();
    let roles = Vec::new();
    assert_eq!(
        fixture
            .store
            .service_sessions()
            .activate(&fixture.activation(&routed, &roles))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn the_active_sessions_of_a_user_and_service_are_listed_and_nothing_else() {
    let fixture = fixture().await;
    let first = fixture.active_db().await;
    let second = fixture.active_db().await;
    fixture.routed(SessionKind::Db, "svc-db").await;
    let sessions = fixture.store.service_sessions();
    let mut found: Vec<String> = sessions
        .active_of_user(fixture.alice(), SessionKind::Db, "lk")
        .await
        .unwrap()
        .into_iter()
        .map(|session| session.id)
        .collect();
    found.sort();
    let mut expected = vec![first.id, second.id];
    expected.sort();
    assert_eq!(found, expected);
    for (user, kind, name) in [
        (fixture.users[1].as_str(), SessionKind::Db, "lk"),
        (fixture.alice(), SessionKind::Tcp, "lk"),
        (fixture.alice(), SessionKind::Db, "grafana"),
    ] {
        assert!(
            sessions
                .active_of_user(user, kind, name)
                .await
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn sessions_that_exist_before_the_migration_become_ssh_sessions() {
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
    let mut files: Vec<_> = std::fs::read_dir(&migrations)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let (before, after): (Vec<_>, Vec<_>) = files
        .into_iter()
        .partition(|file| file.file_name().unwrap().to_str().unwrap() < "0019");
    for file in &before {
        sqlx::raw_sql(sqlx::AssertSqlSafe(std::fs::read_to_string(file).unwrap()))
            .execute(&pool)
            .await
            .unwrap();
    }
    for statement in [
        "INSERT INTO users (id, issuer, subject, email, username, display_name, groups, \
         created_at, updated_at) VALUES ('u', 'i', 's', 'a@b', 'a', NULL, '[]', 1, 1)",
        RAW_NODE,
        "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, valid_before, \
         issued_at) VALUES (5, 'u', 'user', 'k', 1, 2, 1)",
        "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at) \
         VALUES ('old', 'u', 5, 'n', 'ended', 1, 2)",
    ] {
        let query = sqlx::query(statement);
        let query = if statement == RAW_NODE {
            query.bind("n").bind("web")
        } else {
            query
        };
        query.execute(&pool).await.unwrap();
    }
    for file in &after {
        sqlx::raw_sql(sqlx::AssertSqlSafe(std::fs::read_to_string(file).unwrap()))
            .execute(&pool)
            .await
            .unwrap();
    }
    let row: (String, String, String, Option<String>) =
        sqlx::query_as("SELECT kind, roles, grant_ids, service_id FROM sessions WHERE id = 'old'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        row,
        ("ssh".to_owned(), "[]".to_owned(), "[]".to_owned(), None)
    );
    for bad in [
        "UPDATE sessions SET kind = 'observe' WHERE id = 'old'",
        "UPDATE sessions SET target = printf('%.321c', 'x') WHERE id = 'old'",
    ] {
        assert!(sqlx::query(bad).execute(&pool).await.is_err(), "{bad}");
    }
}

async fn active_ssh(fixture: &Fixture) -> Session {
    let created = fixture
        .store
        .sessions()
        .create(
            &NewSession {
                user_id: fixture.alice().to_owned(),
                serial: fixture.serial,
                node_id: NODE.to_owned(),
                ttl_secs: 60,
            },
            NOW,
        )
        .await
        .unwrap();
    fixture
        .store
        .sessions()
        .activate(jaunt_store::ActivateSession {
            id: &created.id,
            node_id: NODE,
            user_id: fixture.alice(),
            serial: fixture.serial,
            login: "deploy",
            max_duration_secs: 60,
            pty: true,
            record_input: false,
            now: NOW + 1,
        })
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn only_active_service_sessions_closed_without_a_report_are_marked_abandoned() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let gone = fixture.active_db().await;
    let reported = fixture.active_db().await;
    let routed = fixture.routed(SessionKind::Tcp, "svc-tcp-2").await;
    let ssh = active_ssh(&fixture).await;
    assert_eq!(sessions.mark_abandoned(&gone.id).await.unwrap(), None);
    sessions
        .end(&EndService {
            id: &reported.id,
            node_id: NODE,
            outcome: "closed",
            bytes_in: 1,
            bytes_out: 1,
            now: NOW + 2,
        })
        .await
        .unwrap();
    fixture
        .store
        .sessions()
        .close(
            jaunt_store::OpenSessions::OfNode(NODE),
            SessionEndReason::AgentGone,
            NOW + 3,
        )
        .await
        .unwrap();
    let marked = sessions.mark_abandoned(&gone.id).await.unwrap().unwrap();
    assert_eq!(
        (marked.outcome.as_deref(), marked.end_reason),
        (
            Some(jaunt_store::ABANDONED_OUTCOME),
            Some(SessionEndReason::AgentGone)
        )
    );
    for untouched in [&reported.id, &routed.id, &ssh.id, &gone.id] {
        assert_eq!(sessions.mark_abandoned(untouched).await.unwrap(), None);
    }
    let late = EndService {
        id: &gone.id,
        node_id: NODE,
        outcome: "upstream_error",
        bytes_in: 3,
        bytes_out: 4,
        now: NOW + 4,
    };
    let EndOutcome::Late(filled) = sessions.end(&late).await.unwrap() else {
        panic!("a late report must replace the abandoned outcome");
    };
    assert_eq!(filled.outcome.as_deref(), Some("upstream_error"));
}

#[tokio::test]
async fn live_ssh_sessions_carry_the_holder_and_the_current_node_labels() {
    let fixture = fixture().await;
    let active = active_ssh(&fixture).await;
    fixture.active_db().await;
    sqlx::query("UPDATE nodes SET labels = '{\"env\":\"stage\"}' WHERE id = ?")
        .bind(NODE)
        .execute(&fixture.raw)
        .await
        .unwrap();
    let entries = fixture.store.service_sessions().live_ssh().await.unwrap();
    let live: Vec<_> = entries.iter().map(readable).collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].session.id, active.id);
    assert_eq!(live[0].session.login.as_deref(), Some("deploy"));
    assert_eq!(live[0].node_name, "web-a");
    assert_eq!(
        live[0].node_labels.get("env").map(String::as_str),
        Some("stage")
    );
    assert_eq!(live[0].groups, ["ops"]);
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = ?")
        .bind(NODE)
        .execute(&fixture.raw)
        .await
        .unwrap();
    assert!(
        fixture
            .store
            .service_sessions()
            .live_ssh()
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn the_audit_flag_is_set_once_by_the_owner_and_never_on_an_ssh_session() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let db = fixture.active_db().await;
    let ssh = active_ssh(&fixture).await;
    assert!(!db.audit_incomplete && !ssh.audit_incomplete);

    assert!(
        !sessions
            .mark_audit_incomplete(&db.id, OTHER_NODE)
            .await
            .unwrap()
    );
    assert!(!sessions.mark_audit_incomplete(&ssh.id, NODE).await.unwrap());
    assert!(
        !sessions
            .mark_audit_incomplete("unknown", NODE)
            .await
            .unwrap()
    );
    assert!(sessions.mark_audit_incomplete(&db.id, NODE).await.unwrap());
    assert!(!sessions.mark_audit_incomplete(&db.id, NODE).await.unwrap());

    let read = sessions
        .for_audit(&[&db.id, &ssh.id, "unknown"])
        .await
        .unwrap();
    let flags: Vec<(String, bool)> = read
        .iter()
        .map(|session| (session.id.clone(), session.audit_incomplete))
        .collect();
    assert_eq!(flags.len(), 2);
    assert!(flags.contains(&(db.id.clone(), true)));
    assert!(flags.contains(&(ssh.id.clone(), false)));
    let listed = fixture
        .store
        .sessions()
        .listing(&db.id)
        .await
        .unwrap()
        .unwrap();
    assert!(listed.session.audit_incomplete);
}

#[tokio::test]
async fn the_audit_lookup_is_bounded_and_an_empty_lookup_reads_nothing() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    assert!(sessions.for_audit(&[]).await.unwrap().is_empty());
    let ids: Vec<String> = (0..=jaunt_store::MAX_AUDIT_LOOKUP)
        .map(|index| format!("s-{index}"))
        .collect();
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert!(matches!(
        sessions.for_audit(&refs).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(
        sessions
            .for_audit(&refs[..jaunt_store::MAX_AUDIT_LOOKUP])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn sessions_that_exist_before_the_audit_flag_migration_are_complete() {
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
    let mut files: Vec<_> = std::fs::read_dir(&migrations)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    files.sort();
    let (before, after): (Vec<_>, Vec<_>) = files
        .into_iter()
        .partition(|file| file.file_name().unwrap().to_str().unwrap() < "0020");
    assert!(!after.is_empty());
    for file in &before {
        sqlx::raw_sql(sqlx::AssertSqlSafe(std::fs::read_to_string(file).unwrap()))
            .execute(&pool)
            .await
            .unwrap();
    }
    for statement in [
        "INSERT INTO users (id, issuer, subject, email, username, display_name, groups, \
         created_at, updated_at) VALUES ('u', 'i', 's', 'a@b', 'a', NULL, '[]', 1, 1)",
        "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, valid_before, \
         issued_at) VALUES (5, 'u', 'user', 'k', 1, 2, 1)",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    sqlx::query(RAW_NODE)
        .bind("n")
        .bind("web")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, \
         kind) VALUES ('old', 'u', 5, 'n', 'ended', 1, 2, 'db')",
    )
    .execute(&pool)
    .await
    .unwrap();
    for file in &after {
        sqlx::raw_sql(sqlx::AssertSqlSafe(std::fs::read_to_string(file).unwrap()))
            .execute(&pool)
            .await
            .unwrap();
    }
    let (flag,): (i64,) = sqlx::query_as("SELECT audit_incomplete FROM sessions WHERE id = 'old'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(flag, 0);
    assert!(
        sqlx::query("UPDATE sessions SET audit_incomplete = 2 WHERE id = 'old'")
            .execute(&pool)
            .await
            .is_err()
    );
}
