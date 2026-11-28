use std::path::Path;

use jaunt_store::{
    ActivateService, ChildOpened, EndOutcome, EndRejection, EndService, KubeOpened, LiveEntry,
    NewCertificate, NewServiceRoute, NewSession, NewUser, OpenChildSession, OpenKubeSession,
    OpenSessions, ServiceRouted, Session, SessionEndReason, SessionKind, SessionState, Store,
    StoreError,
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
        record_exec: true,
        record_input: false,
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
    let EndOutcome::Ended(ended) = sessions.end(&end).await.unwrap().outcome else {
        panic!("the session did not end");
    };
    assert_eq!(ended.outcome.as_deref(), Some("closed"));
    assert_eq!((ended.bytes_in, ended.bytes_out), (Some(10), Some(20)));
    assert_eq!(ended.end_reason, Some(SessionEndReason::Closed));
    assert_eq!(
        sessions.end(&end).await.unwrap().outcome,
        EndOutcome::Repeated
    );
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
            sessions.end(&different).await.unwrap().outcome,
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
            .unwrap()
            .outcome,
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
            .unwrap()
            .outcome,
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
            .unwrap()
            .outcome,
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
            Vec::new()
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
        .unwrap();
    assert_eq!(closed.len(), 1);
    assert_eq!(
        closed[0].end_reason,
        Some(SessionEndReason::AccessWithdrawn)
    );
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
        Vec::new()
    );
    let end = EndService {
        id: &active.id,
        node_id: NODE,
        outcome: "upstream_error",
        bytes_in: 1,
        bytes_out: 2,
        now: NOW + 5,
    };
    let EndOutcome::Late(late) = sessions.end(&end).await.unwrap().outcome else {
        panic!("the late counters were not taken");
    };
    assert_eq!(late.end_reason, Some(SessionEndReason::AccessWithdrawn));
    assert_eq!(late.outcome.as_deref(), Some("upstream_error"));
    assert_eq!(
        sessions.end(&end).await.unwrap().outcome,
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
            record_exec: true,
            record_input: false,
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
    let EndOutcome::Late(filled) = sessions.end(&late).await.unwrap().outcome else {
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

async fn parent_on(
    fixture: &Fixture,
    index: usize,
    node: &str,
    record_exec: bool,
    record_input: bool,
) -> Session {
    let id = format!("k-{index:032x}");
    let hash = "cd".repeat(32);
    let roles = vec!["platform".to_owned()];
    let opened = fixture
        .store
        .service_sessions()
        .open_kube(&OpenKubeSession {
            id: &id,
            user_id: fixture.alice(),
            serial: fixture.serial,
            node_id: node,
            service_id: "svc-kube",
            service_name: "prod",
            roles: &roles,
            max_duration_secs: 3600,
            decision_hash: &hash,
            record_exec,
            record_input,
            max_per_user: 100,
            max_per_service: 100,
            now: NOW,
        })
        .await
        .unwrap();
    match opened {
        KubeOpened::Opened(session) => *session,
        other => panic!("the parent was not opened: {other:?}"),
    }
}

fn child_id(index: usize) -> String {
    format!("kx-{index:032x}")
}

fn child_of<'a>(id: &'a str, parent: &'a str, node: &'a str) -> OpenChildSession<'a> {
    OpenChildSession {
        id,
        parent_id: parent,
        node_id: node,
        target: "default/web-0/app",
        tty: true,
        max_per_parent: 64,
        max_per_node: 512,
        now: NOW + 1,
    }
}

async fn opened_child(fixture: &Fixture, open: &OpenChildSession<'_>) -> Session {
    match fixture
        .store
        .service_sessions()
        .open_child(open)
        .await
        .unwrap()
    {
        ChildOpened::Opened(child) => *child,
        other => panic!("the child was not opened: {other:?}"),
    }
}

async fn raw(fixture: &Fixture, statement: &'static str, id: &str) {
    sqlx::query(statement)
        .bind(id)
        .execute(&fixture.raw)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_child_inherits_its_parent_and_lives_only_under_a_live_kube_parent_of_its_node() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let parent = parent_on(&fixture, 1, NODE, true, true).await;
    let first = child_id(1);
    let child = opened_child(&fixture, &child_of(&first, &parent.id, NODE)).await;
    assert_eq!(
        (
            child.kind,
            child.state,
            child.authorized_at,
            child.login.as_deref()
        ),
        (SessionKind::Kube, SessionState::Active, Some(NOW + 1), None)
    );
    assert_eq!(
        (&child.user_id, child.serial, &child.node_id, child.origin),
        (
            &parent.user_id,
            parent.serial,
            &parent.node_id,
            parent.origin
        )
    );
    assert_eq!(
        (&child.roles, &child.decision_hash, child.max_duration_secs),
        (
            &parent.roles,
            &parent.decision_hash,
            parent.max_duration_secs
        )
    );
    assert_eq!(
        (&child.service_id, &child.service_name),
        (&parent.service_id, &parent.service_name)
    );
    assert_eq!(child.target.as_deref(), Some("default/web-0/app"));
    assert_eq!(child.parent_session_id.as_deref(), Some(parent.id.as_str()));
    assert_eq!((child.record, child.record_input), (Some(true), Some(true)));
    assert_eq!(parent.parent_session_id, None);

    let elsewhere = parent_on(&fixture, 2, OTHER_NODE, true, true).await;
    let db = fixture.active_db().await;
    let ended = parent_on(&fixture, 3, NODE, true, true).await;
    raw(
        &fixture,
        "UPDATE sessions SET state = 'ended' WHERE id = ?",
        &ended.id,
    )
    .await;
    let missing = format!("k-{:032x}", 99);
    for (index, parent_id) in [
        (10, elsewhere.id.as_str()),
        (11, db.id.as_str()),
        (12, first.as_str()),
        (13, ended.id.as_str()),
        (14, missing.as_str()),
    ] {
        let id = child_id(index);
        assert_eq!(
            sessions
                .open_child(&child_of(&id, parent_id, NODE))
                .await
                .unwrap(),
            ChildOpened::ParentNotLive,
            "{parent_id}"
        );
        assert!(fixture.store.sessions().get(&id).await.unwrap().is_none());
    }
    let (before, after) = (child_id(15), child_id(16));
    opened_child(&fixture, &child_of(&before, &elsewhere.id, OTHER_NODE)).await;
    raw(
        &fixture,
        "UPDATE nodes SET state = 'removed' WHERE id = ?",
        OTHER_NODE,
    )
    .await;
    assert_eq!(
        sessions
            .open_child(&child_of(&after, &elsewhere.id, OTHER_NODE))
            .await
            .unwrap(),
        ChildOpened::ParentNotLive
    );
    let long = "x".repeat(321);
    let gate_id = format!("k-{:032x}", 20);
    let fresh = child_id(21);
    for bad in [
        OpenChildSession {
            id: &gate_id,
            ..child_of(&fresh, &parent.id, NODE)
        },
        OpenChildSession {
            target: "",
            ..child_of(&fresh, &parent.id, NODE)
        },
        OpenChildSession {
            target: &long,
            ..child_of(&fresh, &parent.id, NODE)
        },
        OpenChildSession {
            max_per_parent: 0,
            ..child_of(&fresh, &parent.id, NODE)
        },
        OpenChildSession {
            max_per_node: 0,
            ..child_of(&fresh, &parent.id, NODE)
        },
    ] {
        assert!(matches!(
            sessions.open_child(&bad).await,
            Err(StoreError::InvalidInput(_))
        ));
    }
}

#[tokio::test]
async fn the_record_flags_of_a_child_follow_the_grant_of_its_parent() {
    let fixture = fixture().await;
    for (index, grant, expected) in [
        (1, Some((true, true)), (true, true)),
        (2, Some((true, false)), (true, false)),
        (3, Some((false, true)), (false, false)),
        (4, None, (true, false)),
    ] {
        let (record_exec, record_input) = grant.unwrap_or((false, true));
        let parent = parent_on(&fixture, index, NODE, record_exec, record_input).await;
        assert_eq!(parent.record, Some(record_exec));
        if grant.is_none() {
            raw(
                &fixture,
                "UPDATE sessions SET record = NULL, record_input = NULL WHERE id = ?",
                &parent.id,
            )
            .await;
        }
        let id = child_id(index);
        let child = opened_child(&fixture, &child_of(&id, &parent.id, NODE)).await;
        assert_eq!(
            (child.record, child.record_input),
            (Some(expected.0), Some(expected.1)),
            "{grant:?}"
        );
    }
}

#[tokio::test]
async fn children_are_capped_per_parent_and_per_node_and_only_live_children_count() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let first = parent_on(&fixture, 1, NODE, true, false).await;
    let second = parent_on(&fixture, 2, NODE, true, false).await;
    let elsewhere = parent_on(&fixture, 3, OTHER_NODE, true, false).await;
    let ids: Vec<String> = (0..10).map(child_id).collect();
    let capped = |id: usize, parent: &Session| {
        let node = if parent.id == elsewhere.id {
            OTHER_NODE
        } else {
            NODE
        };
        (ids[id].clone(), parent.id.clone(), node)
    };
    let outcome = |opened: ChildOpened| match opened {
        ChildOpened::Opened(_) => "opened",
        ChildOpened::ParentNotLive => "parent_not_live",
        ChildOpened::TooManyForParent => "parent_cap",
        ChildOpened::TooManyForNode => "node_cap",
    };
    let mut seen = Vec::new();
    for (id, parent) in [
        (0, &first),
        (1, &first),
        (2, &first),
        (3, &elsewhere),
        (4, &second),
        (5, &second),
    ] {
        let (id, parent_id, node) = capped(id, parent);
        seen.push(outcome(
            sessions
                .open_child(&small_caps(&child_of(&id, &parent_id, node)))
                .await
                .unwrap(),
        ));
    }
    assert_eq!(
        seen,
        [
            "opened",
            "opened",
            "parent_cap",
            "opened",
            "opened",
            "node_cap"
        ]
    );
    raw(
        &fixture,
        "UPDATE sessions SET state = 'ended' WHERE id = ?",
        &ids[0],
    )
    .await;
    for (id, parent, expected) in [(6, &first, "opened"), (7, &second, "node_cap")] {
        let (id, parent_id, node) = capped(id, parent);
        let opened = sessions
            .open_child(&small_caps(&child_of(&id, &parent_id, node)))
            .await
            .unwrap();
        assert_eq!(outcome(opened), expected);
    }
}

fn small_caps<'a>(open: &OpenChildSession<'a>) -> OpenChildSession<'a> {
    OpenChildSession {
        max_per_parent: 2,
        max_per_node: 3,
        ..*open
    }
}

#[tokio::test]
async fn children_stay_out_of_the_kube_caps_the_access_review_and_the_user_list() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let alice = fixture.alice().to_owned();
    let KubeOpened::Opened(parent) = open_kube_as(&fixture, 0, &alice).await else {
        panic!("the parent was not opened");
    };
    let ids: Vec<String> = (0..3).map(child_id).collect();
    for id in &ids {
        opened_child(&fixture, &child_of(id, &parent.id, NODE)).await;
    }
    assert!(matches!(
        open_kube_as(&fixture, 1, &alice).await,
        KubeOpened::Opened(_)
    ));
    let live: Vec<String> = sessions
        .live()
        .await
        .unwrap()
        .iter()
        .map(|entry| readable(entry).session.id.clone())
        .collect();
    assert_eq!(live.len(), 2);
    assert!(ids.iter().all(|id| !live.contains(id)));
    let listed: Vec<String> = sessions
        .active_of_user(&alice, SessionKind::Kube, "prod")
        .await
        .unwrap()
        .into_iter()
        .map(|session| session.id)
        .collect();
    assert_eq!(listed.len(), 2);
    assert!(ids.iter().all(|id| !listed.contains(id)));
    let counts = fixture.store.sessions().node_counts(NODE, 0).await.unwrap();
    assert_eq!((counts.open, counts.since), (2, 2));
}

fn ids_of(sessions: &[Session]) -> Vec<String> {
    let mut ids: Vec<String> = sessions.iter().map(|session| session.id.clone()).collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn ending_a_parent_ends_its_live_children_in_the_same_step_with_its_reason() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let terminated = parent_on(&fixture, 1, NODE, true, false).await;
    let changed = parent_on(&fixture, 2, NODE, true, false).await;
    let reported = parent_on(&fixture, 3, NODE, true, false).await;
    let ids: Vec<String> = (0..6).map(child_id).collect();
    for (id, parent) in [
        (0, &terminated.id),
        (1, &terminated.id),
        (2, &terminated.id),
        (3, &changed.id),
        (4, &reported.id),
    ] {
        opened_child(&fixture, &child_of(&ids[id], parent, NODE)).await;
    }
    let own_end = EndService {
        id: &ids[2],
        node_id: NODE,
        outcome: "closed",
        bytes_in: 1,
        bytes_out: 2,
        now: NOW + 2,
    };
    let ending = sessions.end(&own_end).await.unwrap();
    assert!(matches!(ending.outcome, EndOutcome::Ended(_)));
    assert!(ending.children.is_empty());

    let closed = fixture
        .store
        .sessions()
        .close(
            OpenSessions::OfId(&terminated.id),
            SessionEndReason::Terminated,
            NOW + 5,
        )
        .await
        .unwrap();
    assert_eq!(closed[0].id, terminated.id);
    let mut expected = vec![terminated.id.clone(), ids[0].clone(), ids[1].clone()];
    expected.sort();
    assert_eq!(ids_of(&closed), expected);
    for id in &ids[..2] {
        let row = fixture.store.sessions().get(id).await.unwrap().unwrap();
        assert_eq!(
            (row.state, row.end_reason, row.ended_at),
            (
                SessionState::Ended,
                Some(SessionEndReason::Terminated),
                Some(NOW + 5)
            )
        );
    }
    let own = fixture
        .store
        .sessions()
        .get(&ids[2])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (own.end_reason, own.outcome.as_deref()),
        (Some(SessionEndReason::Closed), Some("closed"))
    );

    let cut = sessions
        .close_active(
            &changed.id,
            SessionKind::Kube,
            SessionEndReason::AccessChanged,
            NOW + 6,
        )
        .await
        .unwrap();
    assert_eq!(cut[0].id, changed.id);
    assert_eq!(ids_of(&cut[1..]), [ids[3].clone()]);
    assert_eq!(cut[1].end_reason, Some(SessionEndReason::AccessChanged));

    let parent_end = EndService {
        id: &reported.id,
        node_id: NODE,
        outcome: "closed",
        bytes_in: 10,
        bytes_out: 20,
        now: NOW + 7,
    };
    let ending = sessions.end(&parent_end).await.unwrap();
    assert!(matches!(ending.outcome, EndOutcome::Ended(_)));
    assert_eq!(ids_of(&ending.children), [ids[4].clone()]);
    assert_eq!(
        ending.children[0].end_reason,
        Some(SessionEndReason::ParentEnded)
    );
    let late = EndService {
        id: &ids[4],
        node_id: NODE,
        outcome: "closed",
        bytes_in: 3,
        bytes_out: 4,
        now: NOW + 8,
    };
    let EndOutcome::Late(filled) = sessions.end(&late).await.unwrap().outcome else {
        panic!("the late report of a child was not taken");
    };
    assert_eq!(
        (
            filled.outcome.as_deref(),
            filled.bytes_out,
            filled.end_reason
        ),
        (Some("closed"), Some(4), Some(SessionEndReason::ParentEnded))
    );
    assert_eq!(
        sessions.end(&late).await.unwrap().outcome,
        EndOutcome::Repeated
    );
    assert_eq!(
        sessions
            .end(&EndService {
                bytes_out: 5,
                ..late
            })
            .await
            .unwrap()
            .outcome,
        EndOutcome::Rejected(EndRejection::ClosedByControl)
    );
    assert_eq!(
        sessions
            .end(&EndService {
                node_id: OTHER_NODE,
                ..late
            })
            .await
            .unwrap()
            .outcome,
        EndOutcome::Rejected(EndRejection::WrongNode)
    );
}

#[tokio::test]
async fn live_children_of_a_parent_that_is_no_longer_live_are_closed_with_its_reason() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let revoked = parent_on(&fixture, 1, NODE, true, false).await;
    let reported = parent_on(&fixture, 2, NODE, true, false).await;
    let live = parent_on(&fixture, 3, NODE, true, false).await;
    let ids: Vec<String> = (0..3).map(child_id).collect();
    for (id, parent) in [(0, &revoked.id), (1, &reported.id), (2, &live.id)] {
        opened_child(&fixture, &child_of(&ids[id], parent, NODE)).await;
    }
    raw(
        &fixture,
        "UPDATE sessions SET state = 'ended', end_reason = 'revoked' WHERE id = ?",
        &revoked.id,
    )
    .await;
    raw(
        &fixture,
        "UPDATE sessions SET state = 'ended', end_reason = 'closed' WHERE id = ?",
        &reported.id,
    )
    .await;
    let mut orphans: Vec<(String, Option<SessionEndReason>)> = sessions
        .close_orphans(NOW + 9)
        .await
        .unwrap()
        .into_iter()
        .map(|child| (child.id, child.end_reason))
        .collect();
    orphans.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        orphans,
        [
            (ids[0].clone(), Some(SessionEndReason::Revoked)),
            (ids[1].clone(), Some(SessionEndReason::ParentEnded)),
        ]
    );
    assert!(sessions.close_orphans(NOW + 10).await.unwrap().is_empty());
    let kept = fixture
        .store
        .sessions()
        .get(&ids[2])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.state, SessionState::Active);
}

#[tokio::test]
async fn the_upload_target_of_a_child_names_the_node_of_its_parent_and_its_record_flag() {
    let fixture = fixture().await;
    let parent = parent_on(&fixture, 1, NODE, false, false).await;
    let id = child_id(1);
    opened_child(&fixture, &child_of(&id, &parent.id, NODE)).await;
    let recordings = fixture.store.recordings();
    let child = recordings.upload_target(&id).await.unwrap().unwrap();
    assert_eq!(
        (
            child.kind,
            child.parent_session_id.as_deref(),
            child.parent_node_id.as_deref(),
            child.record,
            child.pty
        ),
        (
            SessionKind::Kube,
            Some(parent.id.as_str()),
            Some(NODE),
            Some(false),
            Some(true)
        )
    );
    let of_parent = recordings.upload_target(&parent.id).await.unwrap().unwrap();
    assert_eq!(
        (of_parent.parent_session_id, of_parent.parent_node_id),
        (None, None)
    );
    for (value, accepted) in [
        ("67e55044-10b1-426f-9247-bb680e5fe0c8", true),
        (id.as_str(), true),
        (parent.id.as_str(), false),
        ("kx-0123", false),
        ("", false),
    ] {
        assert_eq!(jaunt_store::is_recording_id(value), accepted, "{value}");
    }
}

#[tokio::test]
async fn sessions_that_exist_before_the_child_migration_have_no_parent_and_no_record_flag() {
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
        .partition(|file| file.file_name().unwrap().to_str().unwrap() < "0021");
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
         kind) VALUES ('old', 'u', 5, 'n', 'active', 1, 2, 'kube')",
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
    let row: (Option<String>, Option<i64>) =
        sqlx::query_as("SELECT parent_session_id, record FROM sessions WHERE id = 'old'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (None, None));
    sqlx::query(
        "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, \
         kind, parent_session_id, record) VALUES ('child', 'u', 5, 'n', 'active', 1, 2, 'kube', \
         'old', 1)",
    )
    .execute(&pool)
    .await
    .unwrap();
    for bad in [
        "UPDATE sessions SET record = 2 WHERE id = 'child'",
        "UPDATE sessions SET parent_session_id = 'nowhere' WHERE id = 'child'",
    ] {
        assert!(sqlx::query(bad).execute(&pool).await.is_err(), "{bad}");
    }
}

const STUCK_CHILDREN: &str = "CREATE TRIGGER stuck_children BEFORE UPDATE OF state ON sessions \
    WHEN OLD.parent_session_id IS NOT NULL AND NEW.state = 'ended' \
    BEGIN SELECT RAISE(ABORT, 'children stay'); END";

#[tokio::test]
async fn a_parent_stays_live_when_its_children_cannot_be_closed_with_it() {
    let fixture = fixture().await;
    let sessions = fixture.store.service_sessions();
    let parent = parent_on(&fixture, 1, NODE, true, false).await;
    let id = child_id(1);
    opened_child(&fixture, &child_of(&id, &parent.id, NODE)).await;
    sqlx::query(STUCK_CHILDREN)
        .execute(&fixture.raw)
        .await
        .unwrap();
    assert!(
        sessions
            .close_active(
                &parent.id,
                SessionKind::Kube,
                SessionEndReason::AccessChanged,
                NOW + 2
            )
            .await
            .is_err()
    );
    let end = EndService {
        id: &parent.id,
        node_id: NODE,
        outcome: "closed",
        bytes_in: 1,
        bytes_out: 1,
        now: NOW + 3,
    };
    assert!(sessions.end(&end).await.is_err());
    assert!(
        fixture
            .store
            .sessions()
            .close(
                OpenSessions::OfId(&parent.id),
                SessionEndReason::Terminated,
                NOW + 4
            )
            .await
            .is_err()
    );
    for kept in [&parent.id, &id] {
        let row = fixture.store.sessions().get(kept).await.unwrap().unwrap();
        assert_eq!(
            (row.state, row.end_reason, row.outcome),
            (SessionState::Active, None, None),
            "{kept}"
        );
    }
}

async fn race(
    store: &Store,
    attempts: Vec<(String, String)>,
    max_per_parent: i64,
    max_per_node: i64,
) -> Vec<ChildOpened> {
    let start = std::sync::Arc::new(tokio::sync::Barrier::new(attempts.len()));
    let tasks: Vec<_> = attempts
        .into_iter()
        .map(|(id, parent_id)| {
            let store = store.clone();
            let start = std::sync::Arc::clone(&start);
            tokio::spawn(async move {
                start.wait().await;
                store
                    .service_sessions()
                    .open_child(&OpenChildSession {
                        max_per_parent,
                        max_per_node,
                        ..child_of(&id, &parent_id, NODE)
                    })
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.unwrap());
    }
    outcomes
}

fn opened(outcomes: &[ChildOpened]) -> usize {
    outcomes
        .iter()
        .filter(|outcome| matches!(outcome, ChildOpened::Opened(_)))
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_children_at_a_limit_get_exactly_the_room_that_is_left() {
    let fixture = fixture().await;
    let mut parents = Vec::new();
    for index in 0..4 {
        parents.push(parent_on(&fixture, index, NODE, true, false).await.id);
    }
    let first = child_id(0);
    opened_child(&fixture, &child_of(&first, &parents[0], NODE)).await;
    let under_one: Vec<(String, String)> = (1..4)
        .map(|index| (child_id(index), parents[0].clone()))
        .collect();
    let outcomes = race(&fixture.store, under_one, 3, 100).await;
    assert_eq!(opened(&outcomes), 2, "{outcomes:?}");
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        ChildOpened::Opened(_) | ChildOpened::TooManyForParent
    )));

    let across: Vec<(String, String)> = (1..4)
        .map(|index| (child_id(10 + index), parents[index].clone()))
        .collect();
    let outcomes = race(&fixture.store, across, 64, 5).await;
    assert_eq!(opened(&outcomes), 2, "{outcomes:?}");
    assert!(outcomes.iter().all(|outcome| matches!(
        outcome,
        ChildOpened::Opened(_) | ChildOpened::TooManyForNode
    )));
    let (live,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sessions WHERE parent_session_id IS NOT NULL AND state = 'active'",
    )
    .fetch_one(&fixture.raw)
    .await
    .unwrap();
    assert_eq!(live, 5);
}
