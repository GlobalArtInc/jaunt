use jaunt_ca::ssh_key::HashAlg;
use jaunt_control::{ApproveError, Labels, RemoveError};
use jaunt_store::{CertificateState, NodeState};

use crate::support::{APPROVER, Harness, sha256_hex_of_bytes};

#[tokio::test]
async fn codes_that_are_wrong_expired_rejected_or_used_are_refused_with_typed_errors() {
    let harness = Harness::new().await;
    let expiring = harness.enroll("web-01").await;
    let rejected = harness.enroll("web-02").await;
    let used = harness.enroll("web-03").await;
    harness.approve(&used).await;
    harness.admin.reject(&rejected.code).await.unwrap();
    harness.clock.advance(900);
    let admin = &harness.admin;

    let unknown = admin
        .approve("ZZZZ-ZZZZ", APPROVER, None)
        .await
        .unwrap_err();
    let malformed = admin.approve("short", APPROVER, None).await.unwrap_err();
    let expired = admin
        .approve(&expiring.code, APPROVER, None)
        .await
        .unwrap_err();
    let again = admin.approve(&used.code, APPROVER, None).await.unwrap_err();
    let after_reject = admin
        .approve(&rejected.code, APPROVER, None)
        .await
        .unwrap_err();

    assert!(matches!(unknown, ApproveError::UnknownCode));
    assert!(matches!(malformed, ApproveError::UnknownCode));
    assert!(matches!(expired, ApproveError::Expired));
    assert!(matches!(again, ApproveError::AlreadyApproved));
    assert!(matches!(after_reject, ApproveError::Rejected));
    assert_eq!(unknown.to_string(), expired.to_string());
    assert!(matches!(
        admin.reject("ZZZZ-ZZZZ").await,
        Err(ApproveError::UnknownCode)
    ));
}

#[tokio::test]
async fn the_typed_code_is_normalized_and_the_label_override_replaces_the_proposal() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let typed = enrolled.code.replace('-', " ").to_lowercase();
    let labels = Labels::parse_assignments("role=db,tier=1").unwrap();

    let approved = harness
        .admin
        .approve(&typed, APPROVER, Some(labels.clone()))
        .await
        .unwrap();

    assert_eq!(approved.node.labels, labels);
    assert_eq!(approved.node.approved_by, APPROVER);
    assert_eq!(approved.node.name, "web-01");
    assert!(approved.replaced.is_none());
    let stored = harness
        .store
        .nodes()
        .get_active(&approved.node.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.labels["role"], "db");
    assert!(!stored.labels.contains_key("env"));
}

#[tokio::test]
async fn the_pending_view_shows_what_the_administrator_must_check() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;

    let view = harness.admin.pending(&enrolled.code).await.unwrap();

    assert_eq!(view.name, "web-01");
    assert_eq!(view.hostname, "web-01.internal.example.com");
    assert_eq!(view.peer_addr, "203.0.113.10");
    assert_eq!(view.source_network, "203.0.113.10");
    assert_eq!(view.labels.to_string(), "env=prod");
    assert_eq!(view.requested_at, harness.clock.now_secs());
    assert_eq!(view.expires_at, harness.clock.now_secs() + 900);
    assert!(!view.replace_existing);
    assert_eq!(view.agent_version, "0.1.0");
    assert_eq!(
        view.tls_key_sha256,
        sha256_hex_of_bytes(&enrolled.agent.tls_der)
    );
    assert_eq!(
        view.ssh_host_key_fingerprint,
        enrolled
            .agent
            .ssh_public_key
            .fingerprint(HashAlg::Sha256)
            .to_string()
    );
    harness.approve(&enrolled).await;
    assert!(matches!(
        harness.admin.pending(&enrolled.code).await,
        Err(ApproveError::AlreadyApproved)
    ));
}

#[tokio::test]
async fn approver_names_must_be_printable_ascii_without_spaces() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    for approver in ["", "cli root", "cli:\u{7}", "cli:é", &"a".repeat(129)] {
        let outcome = harness.admin.approve(&enrolled.code, approver, None).await;
        assert!(
            matches!(outcome, Err(ApproveError::InvalidApprover)),
            "{approver:?}"
        );
    }
    assert!(
        harness
            .admin
            .approve(&enrolled.code, &"a".repeat(128), None)
            .await
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_one_of_sixteen_concurrent_approvals_of_one_code_wins() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let admin = harness.admin.clone();
        let code = enrolled.code.clone();
        tasks.push(tokio::spawn(async move {
            admin.approve(&code, APPROVER, None).await
        }));
    }

    let mut winners = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => winners += 1,
            Err(ApproveError::AlreadyApproved) => {}
            Err(other) => panic!("unexpected {other}"),
        }
    }

    assert_eq!(winners, 1);
    assert_eq!(harness.admin.list_nodes().await.unwrap().len(), 1);
}

#[tokio::test]
async fn nodes_can_be_listed_and_removed_once() {
    let harness = Harness::new().await;
    harness.approve(&harness.enroll("web-01").await).await;
    harness.approve(&harness.enroll("web-02").await).await;

    let removed = harness.admin.remove_node("web-01").await.unwrap();

    assert_eq!(
        (removed.name.as_str(), removed.state),
        ("web-01", NodeState::Removed)
    );
    assert_eq!(removed.removed_at, Some(harness.clock.now_secs()));
    let listed = harness.admin.list_nodes().await.unwrap();
    let states: Vec<_> = listed
        .iter()
        .map(|listing| (listing.node.name.as_str(), listing.node.state))
        .collect();
    assert_eq!(states.len(), 2);
    assert!(states.contains(&("web-01", NodeState::Removed)));
    assert!(states.contains(&("web-02", NodeState::Active)));
    assert!(matches!(
        harness.admin.remove_node("web-01").await,
        Err(RemoveError::NoActiveNode)
    ));
    assert!(matches!(
        harness.admin.remove_node("nope").await,
        Err(RemoveError::NoActiveNode)
    ));
    harness.approve(&harness.enroll("web-01").await).await;
}

#[tokio::test]
async fn the_listing_tells_collected_waiting_and_lapsed_certificates_apart() {
    let harness = Harness::new().await;
    let collected = harness.enroll("collected").await;
    harness.approve(&collected).await;
    assert_eq!(harness.poll(&collected.handle).await.state(), "approved");
    let waiting = harness.enroll("waiting").await;
    harness.approve(&waiting).await;
    let states = |listed: Vec<jaunt_control::NodeListing>| {
        listed
            .into_iter()
            .map(|listing| (listing.node.name, listing.certificates))
            .collect::<std::collections::BTreeMap<_, _>>()
    };

    let now = states(harness.admin.list_nodes().await.unwrap());
    harness.clock.advance(900);
    let later = states(harness.admin.list_nodes().await.unwrap());

    assert_eq!(now["collected"], CertificateState::Delivered);
    assert_eq!(now["waiting"], CertificateState::Pending);
    assert_eq!(later["collected"], CertificateState::Delivered);
    assert_eq!(later["waiting"], CertificateState::None);
    assert_eq!(now.len(), 2);
}
