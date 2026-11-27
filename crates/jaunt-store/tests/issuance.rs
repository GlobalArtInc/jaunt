use jaunt_store::{
    NewCertificate, NewRevocation, NewServiceCertificate, NewSession, NewUser, OpenSessions,
    Parent, RevocationKind, ServiceKind, SessionEndReason, Store, StoreError, Subjects,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 10_000;
const PARENT_ENDS: i64 = NOW + 3600;
const NODE: &str = "node-a";
const OTHER_NODE: &str = "node-b";

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', ?, 'cli:root', 1)";

const RAW_SERVICE: &str = "INSERT INTO services (id, node_id, kind, name, labels, \
    announced_labels, settings, address_hint, state, revision, announced, approved_by, \
    approved_at, created_at, last_seen_at) \
    VALUES (?, ?, ?, ?, '{}', '{}', '{}', NULL, ?, 1, ?, ?, ?, 1, 1)";

struct Fixture {
    _dir: TempDir,
    store: Store,
    raw: SqlitePool,
    alice: String,
    bob: String,
    parent: i64,
}

async fn user(store: &Store, name: &str) -> String {
    store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: name.to_owned(),
                email: format!("{name}@example.com"),
                username: name.to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            NOW,
        )
        .await
        .unwrap()
        .id
}

fn row(serial: i64, user_id: &str, kind: &str, valid_before: i64) -> NewCertificate {
    NewCertificate {
        serial,
        user_id: user_id.to_owned(),
        kind: kind.to_owned(),
        key_id: format!("key-{serial}"),
        valid_after: NOW - 120,
        valid_before,
        issued_at: NOW,
        ca_fingerprint: Some("ca".to_owned()),
        host_trust_id: Some("trust".to_owned()),
        subject_fingerprint: Some(format!("subject-{serial}")),
    }
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    for (id, name, state) in [
        (NODE, "web-a", "active"),
        (OTHER_NODE, "web-b", "active"),
        ("node-gone", "web-c", "removed"),
    ] {
        sqlx::query(RAW_NODE)
            .bind(id)
            .bind(name)
            .bind(state)
            .execute(&raw)
            .await
            .unwrap();
    }
    let alice = user(&store, "alice").await;
    let bob = user(&store, "bob").await;
    let parent = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&row(parent, &alice, "user", PARENT_ENDS))
        .await
        .unwrap();
    Fixture {
        _dir: dir,
        store,
        raw,
        alice,
        bob,
        parent,
    }
}

impl Fixture {
    async fn child(&self, valid_before: i64) -> i64 {
        let serial = self.store.certificates().allocate_serial().await.unwrap();
        let recorded = self
            .store
            .certificates()
            .record_child(
                &row(serial, &self.alice, "x509", valid_before),
                Parent {
                    serial: self.parent,
                    kind: "user",
                },
            )
            .await
            .unwrap();
        assert!(recorded);
        serial
    }

    async fn revoke(&self, kind: RevocationKind, subject: String) {
        self.store
            .revocations()
            .insert(
                &NewRevocation {
                    kind,
                    subject,
                    reason: "lost laptop".to_owned(),
                    created_by: "cli:root".to_owned(),
                },
                NOW,
            )
            .await
            .unwrap();
    }

    async fn revoked(&self, serial: i64) -> bool {
        self.store
            .revocations()
            .any_matches(Subjects {
                user_id: &self.alice,
                serial: Some(serial),
                node_id: None,
            })
            .await
            .unwrap()
    }

    async fn session(&self, serial: i64) -> String {
        self.store
            .sessions()
            .create(
                &NewSession {
                    user_id: self.alice.clone(),
                    serial,
                    node_id: NODE.to_owned(),
                    ttl_secs: 60,
                },
                NOW,
            )
            .await
            .unwrap()
            .id
    }
}

#[tokio::test]
async fn a_child_is_recorded_only_under_a_live_parent_of_the_same_user_that_outlives_it() {
    let fixture = fixture().await;
    let certificates = fixture.store.certificates();
    let parent = Parent {
        serial: fixture.parent,
        kind: "user",
    };

    let at_the_edge = fixture.child(PARENT_ENDS).await;
    let stored = certificates.get(at_the_edge).await.unwrap().unwrap();
    assert_eq!(stored.parent_serial, Some(fixture.parent));
    assert_eq!(stored.kind, "x509");
    assert_eq!(stored.valid_before, PARENT_ENDS);
    assert_eq!(
        certificates
            .get(fixture.parent)
            .await
            .unwrap()
            .unwrap()
            .parent_serial,
        None
    );

    let refused = [
        (
            "outlives the parent",
            fixture.alice.clone(),
            PARENT_ENDS + 1,
            parent,
        ),
        ("another user", fixture.bob.clone(), PARENT_ENDS, parent),
        (
            "unknown parent",
            fixture.alice.clone(),
            PARENT_ENDS,
            Parent {
                serial: 999_999,
                kind: "user",
            },
        ),
        (
            "parent of another kind",
            fixture.alice.clone(),
            PARENT_ENDS,
            Parent {
                serial: fixture.parent,
                kind: "web",
            },
        ),
        (
            "a child as the parent",
            fixture.alice.clone(),
            PARENT_ENDS,
            Parent {
                serial: at_the_edge,
                kind: "x509",
            },
        ),
    ];
    for (label, user_id, valid_before, parent) in refused {
        let serial = certificates.allocate_serial().await.unwrap();
        let mut child = row(serial, &user_id, "x509", valid_before);
        if parent.kind == "x509" {
            child.kind = "x509-grandchild".to_owned();
        }
        assert!(
            !certificates.record_child(&child, parent).await.unwrap(),
            "{label}"
        );
        assert!(certificates.get(serial).await.unwrap().is_none(), "{label}");
    }

    let serial = certificates.allocate_serial().await.unwrap();
    let mut early = row(serial, &fixture.alice, "x509", PARENT_ENDS);
    early.issued_at = NOW - 121;
    assert!(!certificates.record_child(&early, parent).await.unwrap());

    let same_kind = row(serial, &fixture.alice, "user", PARENT_ENDS);
    assert!(matches!(
        certificates.record_child(&same_kind, parent).await,
        Err(StoreError::InvalidInput(_))
    ));
}

#[tokio::test]
async fn revoking_the_parent_revokes_the_child_in_every_lookup_but_not_the_reverse() {
    let fixture = fixture().await;
    let child = fixture.child(PARENT_ENDS).await;
    let sibling_parent = fixture
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    fixture
        .store
        .certificates()
        .record(&row(sibling_parent, &fixture.alice, "user", PARENT_ENDS))
        .await
        .unwrap();
    assert!(!fixture.revoked(child).await);

    fixture
        .revoke(RevocationKind::Serial, child.to_string())
        .await;
    assert!(fixture.revoked(child).await);
    assert!(!fixture.revoked(fixture.parent).await);

    let second = fixture.child(PARENT_ENDS).await;
    assert!(!fixture.revoked(second).await);
    fixture
        .revoke(RevocationKind::Serial, fixture.parent.to_string())
        .await;
    assert!(fixture.revoked(second).await);
    assert!(fixture.revoked(fixture.parent).await);
    assert!(!fixture.revoked(sibling_parent).await);
}

#[tokio::test]
async fn closing_the_sessions_of_a_serial_or_of_revoked_subjects_reaches_the_children() {
    let fixture = fixture().await;
    let child = fixture.child(PARENT_ENDS).await;
    let other_parent = fixture
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    fixture
        .store
        .certificates()
        .record(&row(other_parent, &fixture.alice, "user", PARENT_ENDS))
        .await
        .unwrap();
    let sessions = fixture.store.sessions();

    let on_parent = fixture.session(fixture.parent).await;
    let on_child = fixture.session(child).await;
    let unrelated = fixture.session(other_parent).await;
    let closed = sessions
        .close(
            OpenSessions::OfSerial(fixture.parent),
            SessionEndReason::Revoked,
            NOW + 1,
        )
        .await
        .unwrap();
    let mut ids: Vec<String> = closed.into_iter().map(|session| session.id).collect();
    ids.sort();
    let mut expected = vec![on_parent, on_child];
    expected.sort();
    assert_eq!(ids, expected);
    assert!(
        sessions
            .close(
                OpenSessions::OfSerial(child),
                SessionEndReason::Revoked,
                NOW + 1
            )
            .await
            .unwrap()
            .is_empty()
    );

    let on_child = fixture.session(child).await;
    assert!(!sessions.any_open_of_revoked_subjects().await.unwrap());
    fixture
        .revoke(RevocationKind::Serial, fixture.parent.to_string())
        .await;
    assert!(sessions.any_open_of_revoked_subjects().await.unwrap());
    let closed = sessions
        .close(
            OpenSessions::OfRevokedSubjects,
            SessionEndReason::Revoked,
            NOW + 2,
        )
        .await
        .unwrap();
    let ids: Vec<String> = closed.into_iter().map(|session| session.id).collect();
    assert_eq!(ids, [on_child]);
    assert!(
        sessions
            .get(&unrelated)
            .await
            .unwrap()
            .unwrap()
            .ended_at
            .is_none()
    );
}

#[tokio::test]
async fn the_unexpired_children_of_a_parent_are_listed_for_the_kill_orders() {
    let fixture = fixture().await;
    let short = fixture.child(NOW + 10).await;
    let long = fixture.child(PARENT_ENDS).await;
    let certificates = fixture.store.certificates();
    assert_eq!(
        certificates
            .unexpired_children(fixture.parent, NOW)
            .await
            .unwrap(),
        [short, long]
    );
    assert_eq!(
        certificates
            .unexpired_children(fixture.parent, NOW + 10)
            .await
            .unwrap(),
        [long]
    );
    assert!(
        certificates
            .unexpired_children(long, NOW)
            .await
            .unwrap()
            .is_empty()
    );
}

struct ServiceRow<'a> {
    id: &'a str,
    node_id: &'a str,
    kind: &'a str,
    name: &'a str,
    state: &'a str,
    announced: bool,
}

async fn service(raw: &SqlitePool, row: ServiceRow<'_>) {
    let approved = row.state == "approved";
    sqlx::query(RAW_SERVICE)
        .bind(row.id)
        .bind(row.node_id)
        .bind(row.kind)
        .bind(row.name)
        .bind(row.state)
        .bind(i64::from(row.announced))
        .bind(approved.then_some("cli:root"))
        .bind(approved.then_some(1_i64))
        .execute(raw)
        .await
        .unwrap();
}

fn issued(serial: i64, service_id: &str, node_id: &str, name: &str) -> NewServiceCertificate {
    NewServiceCertificate {
        serial,
        node_id: node_id.to_owned(),
        service_id: service_id.to_owned(),
        kind: ServiceKind::Tcp,
        name: name.to_owned(),
        domain: "svc.example.com".to_owned(),
        signed_dns_name: format!("{name}.tcp.svc.example.com"),
        valid_after: NOW - 120,
        valid_before: NOW + 7 * 86_400,
        issued_at: NOW,
        root_sha256: "root".to_owned(),
        subject_fingerprint: "subject".to_owned(),
    }
}

#[tokio::test]
async fn a_service_certificate_is_recorded_only_for_an_approved_announced_service_of_its_node() {
    let fixture = fixture().await;
    for row in [
        ServiceRow {
            id: "approved",
            node_id: NODE,
            kind: "tcp",
            name: "grafana",
            state: "approved",
            announced: true,
        },
        ServiceRow {
            id: "pending",
            node_id: NODE,
            kind: "tcp",
            name: "pending",
            state: "pending",
            announced: true,
        },
        ServiceRow {
            id: "withdrawn",
            node_id: NODE,
            kind: "tcp",
            name: "withdrawn",
            state: "approved",
            announced: false,
        },
        ServiceRow {
            id: "removed",
            node_id: NODE,
            kind: "tcp",
            name: "removed",
            state: "removed",
            announced: true,
        },
        ServiceRow {
            id: "on-gone-node",
            node_id: "node-gone",
            kind: "tcp",
            name: "orphan",
            state: "approved",
            announced: true,
        },
    ] {
        service(&fixture.raw, row).await;
    }
    let certificates = fixture.store.service_certificates();
    let mut serial = 100;
    let mut refused = |label: &'static str, request: NewServiceCertificate| {
        serial += 1;
        (label, NewServiceCertificate { serial, ..request })
    };
    let cases = [
        refused("pending", issued(0, "pending", NODE, "pending")),
        refused("withdrawn", issued(0, "withdrawn", NODE, "withdrawn")),
        refused("removed", issued(0, "removed", NODE, "removed")),
        refused(
            "node removed",
            issued(0, "on-gone-node", "node-gone", "orphan"),
        ),
        refused("another node", issued(0, "approved", OTHER_NODE, "grafana")),
        refused("another name", issued(0, "approved", NODE, "prometheus")),
        refused(
            "another kind",
            NewServiceCertificate {
                kind: ServiceKind::Postgres,
                ..issued(0, "approved", NODE, "grafana")
            },
        ),
        refused("unknown service", issued(0, "missing", NODE, "grafana")),
        refused(
            "signed for another name",
            NewServiceCertificate {
                signed_dns_name: "grafana.tcp.other.example.com".to_owned(),
                ..issued(0, "approved", NODE, "grafana")
            },
        ),
        refused(
            "signed for another kind label",
            NewServiceCertificate {
                signed_dns_name: "grafana.db.svc.example.com".to_owned(),
                ..issued(0, "approved", NODE, "grafana")
            },
        ),
    ];
    for (label, request) in cases {
        assert!(!certificates.record(&request).await.unwrap(), "{label}");
        assert!(
            certificates.get(request.serial).await.unwrap().is_none(),
            "{label}"
        );
    }

    let accepted = issued(7, "approved", NODE, "grafana");
    assert!(certificates.record(&accepted).await.unwrap());
    let stored = certificates.get(7).await.unwrap().unwrap();
    assert_eq!(
        (
            stored.node_id.as_str(),
            stored.service_id.as_str(),
            stored.kind,
            stored.name.as_str(),
            stored.dns_name.as_str(),
        ),
        (
            NODE,
            "approved",
            ServiceKind::Tcp,
            "grafana",
            "grafana.tcp.svc.example.com"
        )
    );
    assert!(certificates.record(&accepted).await.is_err());

    for (kind, name, label) in [("kubernetes", "prod-eu", "kube"), ("postgres", "lk", "db")] {
        service(
            &fixture.raw,
            ServiceRow {
                id: name,
                node_id: NODE,
                kind,
                name,
                state: "approved",
                announced: true,
            },
        )
        .await;
        serial += 1;
        let expected = format!("{name}.{label}.svc.example.com");
        let request = NewServiceCertificate {
            serial,
            kind: if kind == "kubernetes" {
                ServiceKind::Kubernetes
            } else {
                ServiceKind::Postgres
            },
            signed_dns_name: expected.clone(),
            ..issued(0, name, NODE, name)
        };
        assert!(certificates.record(&request).await.unwrap(), "{kind}");
        assert_eq!(
            certificates.get(serial).await.unwrap().unwrap().dns_name,
            expected
        );
    }
}

#[tokio::test]
async fn expired_service_certificates_are_purged_after_the_retention_point() {
    let fixture = fixture().await;
    service(
        &fixture.raw,
        ServiceRow {
            id: "approved",
            node_id: NODE,
            kind: "tcp",
            name: "grafana",
            state: "approved",
            announced: true,
        },
    )
    .await;
    let certificates = fixture.store.service_certificates();
    for (serial, valid_before) in [(1, NOW + 10), (2, NOW + 20), (3, NOW + 30)] {
        let request = NewServiceCertificate {
            serial,
            valid_before,
            ..issued(0, "approved", NODE, "grafana")
        };
        assert!(certificates.record(&request).await.unwrap());
    }

    assert_eq!(certificates.purge_expired(NOW + 20).await.unwrap(), 1);
    assert!(certificates.get(1).await.unwrap().is_none());
    assert!(certificates.get(2).await.unwrap().is_some());
    assert_eq!(certificates.purge_expired(NOW + 31).await.unwrap(), 2);
    assert!(certificates.get(3).await.unwrap().is_none());
}

#[tokio::test]
async fn a_child_is_not_recorded_under_a_revoked_parent_or_user() {
    for which in ["serial", "user", "other serial", "other user"] {
        let fixture = fixture().await;
        let other = fixture
            .store
            .certificates()
            .allocate_serial()
            .await
            .unwrap();
        fixture
            .store
            .certificates()
            .record(&row(other, &fixture.bob, "user", PARENT_ENDS))
            .await
            .unwrap();
        let (revocation, revoked_subject) = match which {
            "serial" => (RevocationKind::Serial, fixture.parent.to_string()),
            "user" => (RevocationKind::User, fixture.alice.clone()),
            "other serial" => (RevocationKind::Serial, other.to_string()),
            _ => (RevocationKind::User, fixture.bob.clone()),
        };
        fixture.revoke(revocation, revoked_subject).await;
        let serial = fixture
            .store
            .certificates()
            .allocate_serial()
            .await
            .unwrap();
        let recorded = fixture
            .store
            .certificates()
            .record_child(
                &row(serial, &fixture.alice, "x509", PARENT_ENDS),
                Parent {
                    serial: fixture.parent,
                    kind: "user",
                },
            )
            .await
            .unwrap();
        assert_eq!(recorded, which.starts_with("other"), "{which}");
    }
}

#[tokio::test]
async fn x509_children_do_not_count_toward_the_rotation_of_the_ssh_authorities() {
    let fixture = fixture().await;
    let counters = fixture.store.ca_counters();
    let signers = counters.certificates_by_signer(NOW).await.unwrap();
    let host_trusts = counters.certificates_by_host_trust(NOW).await.unwrap();
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].count, 1);

    for _ in 0..300 {
        fixture.child(PARENT_ENDS).await;
    }

    assert_eq!(counters.certificates_by_signer(NOW).await.unwrap(), signers);
    assert_eq!(
        counters.certificates_by_host_trust(NOW).await.unwrap(),
        host_trusts
    );
}
