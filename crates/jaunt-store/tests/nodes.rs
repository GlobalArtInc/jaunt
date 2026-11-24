use std::path::Path;

use jaunt_store::{
    ApproveEnrollment, ApproveOutcome, CertificateState, CodeFailure, CreateOutcome, Enrollment,
    EnrollmentLimits, EnrollmentState, Labels, NewEnrollment, NewNodeCertificate, Node,
    NodeCertificateKind, NodeKeys, NodeState, RejectOutcome, Store,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const NOW: i64 = 1_000;
const TTL: i64 = 900;
const LIMITS: EnrollmentLimits = EnrollmentLimits {
    max_pending: 1000,
    max_pending_per_ip: 20,
};

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

fn new_enrollment(name: &str, tag: &str, ip: &str, replace: bool) -> NewEnrollment {
    NewEnrollment {
        handle_hash: format!("handle-{tag}"),
        code_hash: format!("code-{tag}"),
        name: name.to_owned(),
        labels: labels(&[("env", "prod")]),
        hostname: format!("{name}.example.com"),
        source_ip: ip.to_owned(),
        peer_addr: ip.to_owned(),
        tls_public_key: format!("tls-{tag}"),
        ssh_host_public_key: format!("ssh-{tag}"),
        replace_existing: replace,
        agent_version: "0.1.0".to_owned(),
        ttl_secs: TTL,
    }
}

async fn enroll(store: &Store, name: &str, tag: &str, replace: bool) -> Enrollment {
    let outcome = store
        .enrollments()
        .create(
            &new_enrollment(name, tag, "203.0.113.5", replace),
            LIMITS,
            NOW,
        )
        .await
        .expect("create");
    match outcome {
        CreateOutcome::Created(enrollment) => *enrollment,
        other => panic!("unexpected {other:?}"),
    }
}

async fn approve_at(
    store: &Store,
    enrollment: &Enrollment,
    labels_override: Option<&Labels>,
    now: i64,
) -> ApproveOutcome {
    store
        .enrollments()
        .approve_enrollment(ApproveEnrollment {
            enrollment_id: &enrollment.id,
            code_hash: &enrollment.code_hash,
            approver: "cli:root",
            labels_override,
            tls_spki_sha256: "aa",
            ssh_host_key_fingerprint: "SHA256:bb",
            now,
        })
        .await
        .expect("approve")
}

async fn approve(store: &Store, enrollment: &Enrollment) -> Node {
    match approve_at(store, enrollment, None, NOW + 1).await {
        ApproveOutcome::Approved(approved) => approved.node,
        other => panic!("unexpected {other:?}"),
    }
}

async fn state_of(store: &Store, enrollment: &Enrollment) -> EnrollmentState {
    store
        .enrollments()
        .get_by_handle_hash(&enrollment.handle_hash)
        .await
        .unwrap()
        .unwrap()
        .state
}

fn certificate(kind: NodeCertificateKind, serial: &str) -> NewNodeCertificate {
    NewNodeCertificate {
        kind,
        serial: serial.to_owned(),
        not_before: NOW,
        not_after: NOW + 100,
        issued_at: NOW,
    }
}

async fn raw_pool(path: &Path) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(path))
        .await
        .expect("raw pool")
}

const FAIL_RECORDING: &str = "CREATE TRIGGER fail_certificate_insert BEFORE INSERT ON \
    node_certificates BEGIN SELECT RAISE(ABORT, 'forced'); END";

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, 'web', '{}', 'h', 't', 's', 'f', 'f', ?, 'cli:root', 1)";

#[tokio::test]
async fn only_one_active_node_may_hold_a_name_but_removed_ones_do_not_count() {
    let (dir, _store) = open_store().await;
    let pool = raw_pool(&dir.path().join("jaunt.db")).await;
    let insert = |id: &'static str, state: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query(RAW_NODE)
                .bind(id)
                .bind(state)
                .execute(&pool)
                .await
        }
    };
    insert("n1", "active").await.expect("first active");
    assert!(insert("n2", "active").await.is_err());
    insert("n3", "removed").await.expect("removed is free");
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = 'n1'")
        .execute(&pool)
        .await
        .expect("remove");
    insert("n4", "active").await.expect("name is free again");
}

#[tokio::test]
async fn approval_with_replace_removes_the_old_node_in_the_same_step() {
    let (_dir, store) = open_store().await;
    let first = enroll(&store, "web", "a", false).await;
    let old = approve(&store, &first).await;
    let second = enroll(&store, "web", "b", true).await;
    let override_labels = labels(&[("role", "db")]);

    let outcome = approve_at(&store, &second, Some(&override_labels), NOW + 2).await;

    let ApproveOutcome::Approved(approved) = outcome else {
        panic!("unexpected {outcome:?}");
    };
    assert_eq!(
        approved.replaced.as_ref().map(|node| &node.id),
        Some(&old.id)
    );
    assert_eq!(approved.node.labels, override_labels);
    assert_eq!(approved.node.approved_by, "cli:root");
    assert_eq!(approved.enrollment.state, EnrollmentState::Approved);
    assert_eq!(
        approved.enrollment.node_id.as_deref(),
        Some(approved.node.id.as_str())
    );
    let nodes = store.nodes();
    let removed = nodes.get(&old.id).await.unwrap().unwrap();
    assert_eq!(removed.state, NodeState::Removed);
    assert_eq!(removed.removed_at, Some(NOW + 2));
    let active = nodes.get_active_by_name("web").await.unwrap().unwrap();
    assert_eq!(active.id, approved.node.id);
    assert!(nodes.get_active(&old.id).await.unwrap().is_none());
    assert_eq!(nodes.list().await.unwrap().len(), 2);
}

#[tokio::test]
async fn a_name_conflict_rolls_the_whole_approval_back() {
    let (_dir, store) = open_store().await;
    let holder = approve(&store, &enroll(&store, "web", "a", false).await).await;
    let contender = enroll(&store, "web", "b", false).await;

    assert_eq!(
        approve_at(&store, &contender, None, NOW + 2).await,
        ApproveOutcome::NameTaken
    );

    let stored = store
        .enrollments()
        .get_by_handle_hash(&contender.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, EnrollmentState::Pending);
    assert_eq!((stored.node_id, stored.approved_by), (None, None));
    assert_eq!(store.nodes().list().await.unwrap().len(), 1);

    store.nodes().remove_by_name("web", NOW + 3).await.unwrap();
    let node = approve(&store, &contender).await;
    assert_ne!(node.id, holder.id);
}

#[tokio::test]
async fn refused_approvals_are_classified_by_what_happened_to_the_code() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let unknown = enroll(&store, "unknown", "u", false).await;
    let expired = enroll(&store, "expired", "e", false).await;
    let rejected = enroll(&store, "rejected", "r", false).await;
    let used = enroll(&store, "used", "d", false).await;
    approve(&store, &used).await;
    assert!(matches!(
        enrollments
            .reject_by_code(&rejected.code_hash, NOW)
            .await
            .unwrap(),
        RejectOutcome::Rejected(_)
    ));
    let stranger = Enrollment {
        code_hash: "code-nobody".to_owned(),
        ..unknown
    };

    let cases = [
        (&stranger, NOW + 1, CodeFailure::Unknown),
        (&expired, NOW + TTL, CodeFailure::Expired),
        (&rejected, NOW + 1, CodeFailure::Rejected),
        (&used, NOW + 1, CodeFailure::AlreadyApproved),
    ];
    for (enrollment, now, failure) in cases {
        assert_eq!(
            approve_at(&store, enrollment, None, now).await,
            ApproveOutcome::Refused(failure),
            "{}",
            enrollment.name
        );
    }
    assert_eq!(
        enrollments
            .reject_by_code("code-nobody", NOW)
            .await
            .unwrap(),
        RejectOutcome::Refused(CodeFailure::Unknown)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_one_of_sixteen_concurrent_approvals_of_one_code_wins() {
    let (_dir, store) = open_store().await;
    let enrollment = enroll(&store, "web", "a", false).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let store = store.clone();
        let enrollment = enrollment.clone();
        tasks.push(tokio::spawn(async move {
            approve_at(&store, &enrollment, None, NOW + 1).await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        match task.await.expect("join") {
            ApproveOutcome::Approved(_) => winners += 1,
            ApproveOutcome::Refused(CodeFailure::AlreadyApproved) => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(winners, 1);
    assert_eq!(store.nodes().list().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_one_of_sixteen_concurrent_deliveries_starts() {
    let (_dir, store) = open_store().await;
    let enrollment = enroll(&store, "web", "a", false).await;
    approve(&store, &enrollment).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let enrollments = store.enrollments();
        let id = enrollment.id.clone();
        tasks.push(tokio::spawn(async move {
            enrollments
                .begin_delivery(&id, NOW + 2)
                .await
                .expect("begin")
        }));
    }
    let mut winners = Vec::new();
    for task in tasks {
        if let Some(started) = task.await.expect("join") {
            winners.push(started);
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].state, EnrollmentState::Delivering);
    assert!(
        store
            .enrollments()
            .begin_delivery(&enrollment.id, NOW + 2)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn delivery_is_not_offered_after_expiry_and_a_failed_record_leaves_it_retryable() {
    let (dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let enrollment = enroll(&store, "web", "a", false).await;
    let node = approve(&store, &enrollment).await;
    assert!(
        enrollments
            .begin_delivery(&enrollment.id, enrollment.expires_at)
            .await
            .unwrap()
            .is_none()
    );

    let started = enrollments
        .begin_delivery(&enrollment.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(started.delivering_at, Some(NOW + 2));
    let records = [
        certificate(NodeCertificateKind::X509, "ab12"),
        certificate(NodeCertificateKind::SshHost, "7"),
    ];
    assert!(
        !enrollments
            .complete_delivery(&enrollment.id, "another-node", &records)
            .await
            .unwrap()
    );
    let pool = raw_pool(&dir.path().join("jaunt.db")).await;
    sqlx::query(FAIL_RECORDING).execute(&pool).await.unwrap();
    assert!(
        enrollments
            .complete_delivery(&enrollment.id, &node.id, &records)
            .await
            .is_err()
    );
    let stuck = enrollments
        .get_by_handle_hash(&enrollment.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stuck.state, EnrollmentState::Delivering);
    assert!(
        store
            .nodes()
            .certificates(&node.id)
            .await
            .unwrap()
            .is_empty()
    );
    sqlx::query("DROP TRIGGER fail_certificate_insert")
        .execute(&pool)
        .await
        .unwrap();

    assert!(enrollments.release_delivery(&enrollment.id).await.unwrap());
    let released = enrollments
        .get_by_handle_hash(&enrollment.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (released.state, released.delivering_at),
        (EnrollmentState::Approved, None)
    );
    assert!(
        enrollments
            .begin_delivery(&enrollment.id, NOW + 3)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        enrollments
            .complete_delivery(&enrollment.id, &node.id, &records)
            .await
            .unwrap()
    );
    assert!(
        !enrollments
            .complete_delivery(&enrollment.id, &node.id, &records)
            .await
            .unwrap()
    );
    let stored = store.nodes().certificates(&node.id).await.unwrap();
    assert_eq!(
        stored
            .iter()
            .map(|record| (record.kind, record.serial.as_str()))
            .collect::<Vec<_>>(),
        [
            (NodeCertificateKind::SshHost, "7"),
            (NodeCertificateKind::X509, "ab12")
        ]
    );
    let delivered = enrollments
        .get_by_handle_hash(&enrollment.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.state, EnrollmentState::Delivered);
}

#[tokio::test]
async fn certificates_come_back_in_one_deterministic_order_whatever_the_ids() {
    let (_dir, store) = open_store().await;
    let enrollment = enroll(&store, "web", "a", false).await;
    let node = approve(&store, &enrollment).await;
    let renewals = [
        certificate(NodeCertificateKind::X509, "f1"),
        certificate(NodeCertificateKind::SshHost, "9"),
        certificate(NodeCertificateKind::X509, "0a"),
        certificate(NodeCertificateKind::SshHost, "3"),
    ];
    let keys = NodeKeys {
        tls_public_key: "t".to_owned(),
        ssh_host_public_key: "s".to_owned(),
        tls_spki_sha256: "a".to_owned(),
        ssh_host_key_fingerprint: "b".to_owned(),
    };
    for pair in renewals.chunks(2) {
        assert!(
            store
                .nodes()
                .record_renewal(&node.id, &keys, pair)
                .await
                .unwrap()
        );
    }

    for _ in 0..10 {
        let order: Vec<_> = store
            .nodes()
            .certificates(&node.id)
            .await
            .unwrap()
            .into_iter()
            .map(|record| (record.kind, record.serial))
            .collect();
        assert_eq!(
            order,
            [
                (NodeCertificateKind::SshHost, "3".to_owned()),
                (NodeCertificateKind::SshHost, "9".to_owned()),
                (NodeCertificateKind::X509, "0a".to_owned()),
                (NodeCertificateKind::X509, "f1".to_owned()),
            ]
        );
    }
}

#[tokio::test]
async fn removing_a_node_during_delivery_stops_the_certificates_from_being_recorded() {
    let (dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let records = [certificate(NodeCertificateKind::X509, "1")];

    let removed_first = enroll(&store, "web", "a", false).await;
    let removed_node = approve(&store, &removed_first).await;
    assert!(
        enrollments
            .begin_delivery(&removed_first.id, NOW + 2)
            .await
            .unwrap()
            .is_some()
    );
    store.nodes().remove_by_name("web", NOW + 3).await.unwrap();
    assert!(
        !enrollments
            .complete_delivery(&removed_first.id, &removed_node.id, &records)
            .await
            .unwrap()
    );
    assert_eq!(
        state_of(&store, &removed_first).await,
        EnrollmentState::Rejected
    );
    assert!(
        store
            .nodes()
            .certificates(&removed_node.id)
            .await
            .unwrap()
            .is_empty()
    );

    let replaced_first = enroll(&store, "db", "b", false).await;
    let replaced_node = approve(&store, &replaced_first).await;
    assert!(
        enrollments
            .begin_delivery(&replaced_first.id, NOW + 2)
            .await
            .unwrap()
            .is_some()
    );
    let replacement = enroll(&store, "db", "c", true).await;
    approve_at(&store, &replacement, None, NOW + 4).await;
    assert!(
        !enrollments
            .complete_delivery(&replaced_first.id, &replaced_node.id, &records)
            .await
            .unwrap()
    );
    assert_eq!(
        state_of(&store, &replaced_first).await,
        EnrollmentState::Rejected
    );
    assert!(
        store
            .nodes()
            .certificates(&replaced_node.id)
            .await
            .unwrap()
            .is_empty()
    );

    let bypassed = enroll(&store, "cache", "d", false).await;
    let bypassed_node = approve(&store, &bypassed).await;
    assert!(
        enrollments
            .begin_delivery(&bypassed.id, NOW + 2)
            .await
            .unwrap()
            .is_some()
    );
    let pool = raw_pool(&dir.path().join("jaunt.db")).await;
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = ?")
        .bind(&bypassed_node.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !enrollments
            .complete_delivery(&bypassed.id, &bypassed_node.id, &records)
            .await
            .unwrap()
    );
    assert!(
        store
            .nodes()
            .certificates(&bypassed_node.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn stale_deliveries_return_to_approved_only_after_the_grace_period() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let stuck = enroll(&store, "web", "a", false).await;
    approve(&store, &stuck).await;
    assert!(
        enrollments
            .begin_delivery(&stuck.id, NOW + 10)
            .await
            .unwrap()
            .is_some()
    );

    assert!(
        enrollments
            .recover_stale_deliveries(NOW + 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(state_of(&store, &stuck).await, EnrollmentState::Delivering);
    let recovered = enrollments
        .recover_stale_deliveries(NOW + 11)
        .await
        .unwrap();

    assert_eq!(recovered.len(), 1);
    assert_eq!(
        (recovered[0].id.as_str(), recovered[0].name.as_str()),
        (stuck.id.as_str(), "web")
    );
    let after = enrollments
        .get_by_handle_hash(&stuck.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (after.state, after.delivering_at),
        (EnrollmentState::Approved, None)
    );
    assert!(
        enrollments
            .begin_delivery(&stuck.id, NOW + 12)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn replacing_rejects_the_old_nodes_unclaimed_enrollment_and_a_removed_holder_is_left_alone() {
    let (_dir, store) = open_store().await;
    let first = enroll(&store, "web", "a", false).await;
    let old = approve(&store, &first).await;
    let replacing = enroll(&store, "web", "b", true).await;
    approve_at(&store, &replacing, None, NOW + 2).await;
    assert_eq!(state_of(&store, &first).await, EnrollmentState::Rejected);
    assert_eq!(
        store
            .nodes()
            .get(&old.id)
            .await
            .unwrap()
            .unwrap()
            .removed_at,
        Some(NOW + 2)
    );

    store.nodes().remove_by_name("web", NOW + 5).await.unwrap();
    let again = enroll(&store, "web", "c", true).await;
    let ApproveOutcome::Approved(approved) = approve_at(&store, &again, None, NOW + 9).await else {
        panic!("the approval was refused");
    };

    assert!(approved.replaced.is_none());
    let untouched = store.nodes().get(&old.id).await.unwrap().unwrap();
    assert_eq!(
        (untouched.state, untouched.removed_at),
        (NodeState::Removed, Some(NOW + 2))
    );
}

#[tokio::test]
async fn an_enrollment_that_is_already_approved_cannot_be_rejected_by_its_code() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let approved = enroll(&store, "web-a", "a", false).await;
    approve(&store, &approved).await;
    let delivering = enroll(&store, "web-b", "b", false).await;
    approve(&store, &delivering).await;
    enrollments
        .begin_delivery(&delivering.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    let delivered = enroll(&store, "web-c", "c", false).await;
    let node = approve(&store, &delivered).await;
    enrollments
        .begin_delivery(&delivered.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    assert!(
        enrollments
            .complete_delivery(&delivered.id, &node.id, &[])
            .await
            .unwrap()
    );

    for (enrollment, state) in [
        (&approved, EnrollmentState::Approved),
        (&delivering, EnrollmentState::Delivering),
        (&delivered, EnrollmentState::Delivered),
    ] {
        assert_eq!(
            enrollments
                .reject_by_code(&enrollment.code_hash, NOW + 3)
                .await
                .unwrap(),
            RejectOutcome::Refused(CodeFailure::AlreadyApproved),
            "{state:?}"
        );
        assert_eq!(state_of(&store, enrollment).await, state);
    }
}

#[tokio::test]
async fn each_node_reports_whether_its_certificates_were_delivered_are_waiting_or_gone() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let waiting = approve(&store, &enroll(&store, "waiting", "a", false).await).await;
    let lapsed = approve(&store, &enroll(&store, "lapsed", "b", false).await).await;
    let collected_enrollment = enroll(&store, "collected", "c", false).await;
    let collected = approve(&store, &collected_enrollment).await;
    enrollments
        .begin_delivery(&collected_enrollment.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    let records = [certificate(NodeCertificateKind::X509, "1")];
    assert!(
        enrollments
            .complete_delivery(&collected_enrollment.id, &collected.id, &records)
            .await
            .unwrap()
    );

    let early = store.nodes().certificate_states(NOW + 5).await.unwrap();
    let late = store.nodes().certificate_states(NOW + TTL).await.unwrap();

    assert_eq!(early[&waiting.id], CertificateState::Pending);
    assert_eq!(early[&lapsed.id], CertificateState::Pending);
    assert_eq!(early[&collected.id], CertificateState::Delivered);
    assert_eq!(late[&waiting.id], CertificateState::None);
    assert_eq!(late[&collected.id], CertificateState::Delivered);
}

#[tokio::test]
async fn removing_a_node_rejects_its_unclaimed_enrollment_and_blocks_renewal() {
    let (_dir, store) = open_store().await;
    let enrollment = enroll(&store, "web", "a", false).await;
    let node = approve(&store, &enrollment).await;
    let keys = NodeKeys {
        tls_public_key: "tls-new".to_owned(),
        ssh_host_public_key: "ssh-new".to_owned(),
        tls_spki_sha256: "cc".to_owned(),
        ssh_host_key_fingerprint: "SHA256:dd".to_owned(),
    };
    let records = [certificate(NodeCertificateKind::X509, "1")];
    assert!(
        store
            .nodes()
            .record_renewal(&node.id, &keys, &records)
            .await
            .unwrap()
    );
    let renewed = store.nodes().get_active(&node.id).await.unwrap().unwrap();
    assert_eq!(renewed.tls_public_key, "tls-new");
    assert_eq!(renewed.ssh_host_key_fingerprint, "SHA256:dd");
    assert_eq!(store.nodes().certificates(&node.id).await.unwrap().len(), 1);

    let removed = store
        .nodes()
        .remove_by_name("web", NOW + 5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (removed.state, removed.removed_at),
        (NodeState::Removed, Some(NOW + 5))
    );
    assert!(
        store
            .nodes()
            .remove_by_name("web", NOW + 6)
            .await
            .unwrap()
            .is_none()
    );
    let stored = store
        .enrollments()
        .get_by_handle_hash(&enrollment.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, EnrollmentState::Rejected);
    assert!(
        !store
            .nodes()
            .record_renewal(&node.id, &keys, &records)
            .await
            .unwrap()
    );
    assert_eq!(store.nodes().certificates(&node.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn creation_enforces_the_global_and_per_address_caps_and_unique_pending_codes() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let limits = EnrollmentLimits {
        max_pending: 3,
        max_pending_per_ip: 2,
    };
    let create = |tag: &str, ip: &str, code: &str, now: i64| {
        let mut request = new_enrollment("web", tag, ip, false);
        request.code_hash = code.to_owned();
        let enrollments = enrollments.clone();
        async move { enrollments.create(&request, limits, now).await.unwrap() }
    };

    assert!(matches!(
        create("1", "10.0.0.1", "c1", NOW).await,
        CreateOutcome::Created(_)
    ));
    assert!(matches!(
        create("2", "10.0.0.1", "c2", NOW).await,
        CreateOutcome::Created(_)
    ));
    assert_eq!(
        create("3", "10.0.0.1", "c3", NOW).await,
        CreateOutcome::TooManyFromIp
    );
    assert_eq!(
        create("4", "10.0.0.2", "c1", NOW).await,
        CreateOutcome::CodeCollision
    );
    assert!(matches!(
        create("5", "10.0.0.2", "c5", NOW).await,
        CreateOutcome::Created(_)
    ));
    assert_eq!(
        create("6", "10.0.0.3", "c6", NOW).await,
        CreateOutcome::TooManyPending
    );
    assert!(matches!(
        create("7", "10.0.0.1", "c1", NOW + TTL).await,
        CreateOutcome::Created(_)
    ));
}

#[tokio::test]
async fn purging_removes_only_old_expired_rows_and_reports_them() {
    let (_dir, store) = open_store().await;
    let old = enroll(&store, "old", "o", false).await;
    let mut later = new_enrollment("later", "l", "203.0.113.5", false);
    later.ttl_secs = TTL * 10;
    store
        .enrollments()
        .create(&later, LIMITS, NOW)
        .await
        .unwrap();

    let purged = store
        .enrollments()
        .purge_expired(old.expires_at + 1)
        .await
        .unwrap();

    assert_eq!(purged.len(), 1);
    assert_eq!(
        (purged[0].id.as_str(), purged[0].state),
        (old.id.as_str(), EnrollmentState::Pending)
    );
    assert!(
        store
            .enrollments()
            .get_by_handle_hash("handle-o")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .enrollments()
            .get_by_handle_hash("handle-l")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn certificates_are_never_recorded_for_a_node_removed_behind_the_enrollments_back_or_for_another_node()
 {
    let (dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let records = [certificate(NodeCertificateKind::X509, "1")];
    let pool = raw_pool(&dir.path().join("jaunt.db")).await;

    let removed = enroll(&store, "removed", "a", false).await;
    let removed_node = approve(&store, &removed).await;
    enrollments
        .begin_delivery(&removed.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = ?")
        .bind(&removed_node.id)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !enrollments
            .complete_delivery(&removed.id, &removed_node.id, &records)
            .await
            .unwrap()
    );
    assert_eq!(
        state_of(&store, &removed).await,
        EnrollmentState::Delivering
    );
    assert!(
        store
            .nodes()
            .certificates(&removed_node.id)
            .await
            .unwrap()
            .is_empty()
    );

    let delivering = enroll(&store, "delivering", "b", false).await;
    let delivering_node = approve(&store, &delivering).await;
    let bystander = approve(&store, &enroll(&store, "bystander", "c", false).await).await;
    enrollments
        .begin_delivery(&delivering.id, NOW + 2)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !enrollments
            .complete_delivery(&delivering.id, &bystander.id, &records)
            .await
            .unwrap()
    );
    assert_eq!(
        state_of(&store, &delivering).await,
        EnrollmentState::Delivering
    );
    for node in [&delivering_node, &bystander] {
        assert!(
            store
                .nodes()
                .certificates(&node.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert!(
        enrollments
            .complete_delivery(&delivering.id, &delivering_node.id, &records)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_delivery_can_start_only_strictly_before_the_expiry_instant() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let last_second = enroll(&store, "last-second", "a", false).await;
    let at_expiry = enroll(&store, "at-expiry", "b", false).await;
    let after_expiry = enroll(&store, "after-expiry", "c", false).await;
    for enrollment in [&last_second, &at_expiry, &after_expiry] {
        approve(&store, enrollment).await;
    }
    let expiry = last_second.expires_at;

    assert!(
        enrollments
            .begin_delivery(&at_expiry.id, expiry)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        enrollments
            .begin_delivery(&after_expiry.id, expiry + 1)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        enrollments
            .begin_delivery(&last_second.id, expiry - 1)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        state_of(&store, &at_expiry).await,
        EnrollmentState::Approved
    );
}

#[tokio::test]
async fn an_expiry_is_marked_as_reported_once_and_only_after_it_happened() {
    let (_dir, store) = open_store().await;
    let enrollments = store.enrollments();
    let noticed = enroll(&store, "noticed", "a", false).await;
    let unnoticed = enroll(&store, "unnoticed", "b", false).await;
    let expiry = noticed.expires_at;

    assert!(
        !enrollments
            .mark_expiry_reported(&noticed.id, expiry - 1)
            .await
            .unwrap()
    );
    assert!(
        enrollments
            .mark_expiry_reported(&noticed.id, expiry)
            .await
            .unwrap()
    );
    assert!(
        !enrollments
            .mark_expiry_reported(&noticed.id, expiry + 5)
            .await
            .unwrap()
    );
    let stored = enrollments
        .get_by_handle_hash(&noticed.handle_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.expired_reported_at, Some(expiry));

    let mut purged = enrollments.purge_expired(expiry + 1).await.unwrap();
    purged.sort_by(|left, right| left.name.cmp(&right.name));
    let flags: Vec<_> = purged
        .iter()
        .map(|row| (row.name.as_str(), row.expiry_reported))
        .collect();
    assert_eq!(flags, [("noticed", true), ("unnoticed", false)]);
    assert_eq!(purged[1].id, unnoticed.id);
}
