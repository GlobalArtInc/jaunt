use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::fingerprint_hex;
use jaunt_proto::{
    ControlError as PlaneError, DenyReason, LocateServiceRequest, NodeCaller, ServiceAccess,
    ServiceAuthorizeDecision, ServiceKind, ServiceLocation, ServiceOutcome, SessionEndOutcome,
};
use jaunt_store::{NewUser, SessionEndReason, SessionKind, SessionState};

use crate::audit::{start_recording, take_recording};
use crate::issuance_support::{P256_SPKI, client_verifies, parsed};
use crate::service_support::{
    DB, KUBE, KUBE_ID, METRICS, OPS_ROLE, SHARED, Stand, TCP, X509, active_issuer, announce,
    authorize_request, authorize_service, child_certificate, db_request, denied, end_service,
    kube_service, open, parent_certificate, person, route_denied, route_request, route_service,
    routed_id, row, stand, stand_with_policy, tcp_service,
};
use crate::session_support::{apply_policy, audit_events, plane, subject_fingerprint};

async fn locate(stand: &Stand, kind: ServiceKind, name: &str) -> Option<ServiceLocation> {
    plane(&stand.harness)
        .locate_service(LocateServiceRequest {
            kind,
            name: name.to_owned(),
        })
        .await
        .unwrap()
}

async fn session_count(stand: &Stand) -> i64 {
    let pool = crate::session_support::raw_pool(&stand.harness).await;
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    count
}

fn events_named(name: &str, recorded: &[crate::audit::Captured]) -> Vec<crate::audit::Captured> {
    recorded
        .iter()
        .filter(|event| event["target"] == "jaunt::audit" && event["event"] == name)
        .cloned()
        .collect()
}

#[tokio::test]
async fn locate_names_only_the_node_of_an_offered_service_on_a_connected_agent() {
    let stand = stand().await;
    let before = session_count(&stand).await;
    start_recording();
    assert_eq!(
        locate(&stand, ServiceKind::Kubernetes, KUBE).await,
        Some(ServiceLocation {
            node_id: stand.node_id.clone(),
            kind: ServiceKind::Kubernetes,
        })
    );
    assert!(audit_events(take_recording()).is_empty());
    assert_eq!(session_count(&stand).await, before);
    assert_eq!(
        locate(&stand, ServiceKind::Kubernetes, "absent").await,
        None
    );
    assert_eq!(locate(&stand, ServiceKind::Tcp, KUBE).await, None);

    announce(
        &stand.harness,
        &stand.other_node_id,
        &[kube_service("stage")],
    )
    .await;
    assert_eq!(locate(&stand, ServiceKind::Kubernetes, "stage").await, None);
    assert_eq!(
        plane(&stand.harness)
            .locate_service(LocateServiceRequest {
                kind: ServiceKind::Kubernetes,
                name: "Not A Label".to_owned(),
            })
            .await,
        Err(PlaneError::InvalidRequest)
    );

    stand.presence.disconnect(&stand.node_id);
    assert_eq!(locate(&stand, ServiceKind::Kubernetes, KUBE).await, None);
}

#[tokio::test]
async fn unannounced_services_and_removed_nodes_are_neither_located_nor_routed() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    announce(&stand.harness, &stand.node_id, &[tcp_service(TCP)]).await;
    assert_eq!(locate(&stand, ServiceKind::Kubernetes, KUBE).await, None);
    assert_eq!(
        route_denied(
            &route_service(
                &stand.harness,
                route_request(&alice, ServiceKind::Tcp, METRICS)
            )
            .await
        ),
        Some(DenyReason::ServiceUnknown)
    );
    assert_eq!(
        route_denied(
            &route_service(&stand.harness, route_request(&alice, ServiceKind::Tcp, TCP)).await
        ),
        None
    );
    stand
        .harness
        .admin
        .remove_node("svc-01", crate::support::APPROVER)
        .await
        .unwrap();
    assert_eq!(
        route_denied(
            &route_service(&stand.harness, route_request(&alice, ServiceKind::Tcp, TCP)).await
        ),
        Some(DenyReason::ServiceUnknown)
    );
    assert_eq!(
        plane(&stand.harness)
            .route_service(route_request(&alice, ServiceKind::Kubernetes, KUBE))
            .await,
        Err(PlaneError::InvalidRequest)
    );
}

#[tokio::test]
async fn a_tcp_session_is_routed_then_authorized_once_and_recorded_as_tcp() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    start_recording();
    let decision =
        route_service(&stand.harness, route_request(&alice, ServiceKind::Tcp, TCP)).await;
    let jaunt_proto::RouteDecision::Allow {
        session_id,
        node_id,
    } = decision
    else {
        panic!("{decision:?}");
    };
    assert_eq!(node_id, stand.node_id);
    let routed = row(&stand.harness, &session_id).await;
    assert_eq!(
        (routed.kind, routed.state, routed.expires_at),
        (
            SessionKind::Tcp,
            SessionState::Routed,
            stand.harness.clock.now_secs() + 30
        )
    );
    let granted = authorize_service(
        &stand.harness,
        &stand.node_id,
        authorize_request(&alice, &session_id, ServiceKind::Tcp, TCP),
    )
    .await;
    let ServiceAuthorizeDecision::Allow(grant) = &granted else {
        panic!("{granted:?}");
    };
    assert_eq!(grant.access, ServiceAccess::Tcp);
    assert_eq!(grant.roles, ["ops"]);
    assert_eq!(grant.max_duration_secs, 12 * 3600);
    assert_eq!(
        grant.policy_hash,
        stand.harness.control.policy().snapshot().hash()
    );
    let active = row(&stand.harness, &session_id).await;
    assert_eq!(active.state, SessionState::Active);
    assert_eq!(active.roles, ["ops"]);
    assert!(active.grant_ids.is_empty());
    assert_eq!(active.login, None);
    assert_eq!(active.max_duration_secs, Some(12 * 3600));
    let recorded = take_recording();
    let started = events_named("session.service.start", &recorded);
    assert_eq!(events_named("session.service.routed", &recorded).len(), 1);
    assert_eq!(started.len(), 1);
    assert_eq!(started[0]["kind"], "tcp");
    assert_eq!(started[0]["service"], TCP);
    assert_eq!(started[0]["session_id"], session_id);
    assert_eq!(started[0]["roles"], "ops");
}

#[tokio::test]
async fn the_second_hop_refuses_every_mismatch_and_only_the_routed_agent_consumes_the_id() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    let issuer = active_issuer(harness);
    let now = harness.clock.now_secs();
    let alice_second = child_certificate(
        harness,
        &alice.user_id,
        alice.parent,
        (now - 60, now + 3600),
        &issuer,
    )
    .await;
    let session_id = routed_id(harness, &alice, ServiceKind::Tcp, TCP).await;
    let late_id = routed_id(harness, &alice, ServiceKind::Tcp, TCP).await;
    let good = authorize_request(&alice, &session_id, ServiceKind::Tcp, TCP);

    let mut other_key = good.clone();
    other_key.identity.subject_fingerprint = subject_fingerprint();
    let mut other_issuer = good.clone();
    other_issuer.identity.issuer_fingerprint = "ab".repeat(32);
    let mut other_kind = authorize_request(&alice, &session_id, ServiceKind::Postgres, SHARED);
    other_kind.db = db_request("app", "main");
    let cases = [
        (
            "other node",
            stand.other_node_id.clone(),
            good.clone(),
            DenyReason::ServiceUnknown,
        ),
        (
            "other user",
            stand.node_id.clone(),
            authorize_request(&bob, &session_id, ServiceKind::Tcp, TCP),
            DenyReason::UserMismatch,
        ),
        (
            "other serial",
            stand.node_id.clone(),
            authorize_request(&alice_second, &session_id, ServiceKind::Tcp, TCP),
            DenyReason::SerialMismatch,
        ),
        (
            "other key",
            stand.node_id.clone(),
            other_key,
            DenyReason::SubjectKeyMismatch,
        ),
        (
            "other issuer",
            stand.node_id.clone(),
            other_issuer,
            DenyReason::IssuerMismatch,
        ),
        (
            "other kind",
            stand.node_id.clone(),
            other_kind,
            DenyReason::KindMismatch,
        ),
        (
            "other service",
            stand.node_id.clone(),
            authorize_request(&alice, &session_id, ServiceKind::Tcp, METRICS),
            DenyReason::ServiceMismatch,
        ),
        (
            "unknown id",
            stand.node_id.clone(),
            authorize_request(&alice, "no-such-session", ServiceKind::Tcp, TCP),
            DenyReason::SessionUnknown,
        ),
    ];
    start_recording();
    for (label, node_id, request, reason) in cases {
        let decision = authorize_service(harness, &node_id, request).await;
        assert_eq!(denied(&decision), Some(reason), "{label}");
    }
    let refusals = events_named("authz.service.deny", &take_recording());
    let reasons: Vec<&str> = refusals
        .iter()
        .map(|event| event["reason"].as_str())
        .collect();
    assert_eq!(refusals.len(), 8, "{reasons:?}");
    assert!(refusals.iter().all(|event| event["phase"] == "authorize"));
    assert_eq!(refusals[1]["reason"], "user_mismatch");
    assert_eq!(refusals[1]["user_id"], alice.user_id);
    assert_eq!(refusals[0]["user_id"], alice.user_id);

    let pool = crate::session_support::raw_pool(harness).await;
    sqlx::query(
        "INSERT INTO services (id, node_id, kind, name, labels, announced_labels, settings, \
         state, revision, announced, approved_by, approved_at, created_at, last_seen_at) \
         VALUES ('planted', ?, 'tcp', ?, '{\"team\":\"ops\"}', '{}', '{}', 'approved', 1, 1, \
         'cli:tester', 1, 1, 1)",
    )
    .bind(&stand.other_node_id)
    .bind(TCP)
    .execute(&pool)
    .await
    .unwrap();
    let wrong_node = authorize_service(harness, &stand.other_node_id, good.clone()).await;
    assert_eq!(denied(&wrong_node), Some(DenyReason::WrongNode));

    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, good.clone()).await),
        None
    );
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, good).await),
        Some(DenyReason::SessionUsed)
    );

    harness.clock.advance(30);
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                authorize_request(&alice, &late_id, ServiceKind::Tcp, TCP),
            )
            .await
        ),
        Some(DenyReason::SessionExpired)
    );
}

async fn bad_identities(stand: &Stand) -> Vec<(&'static str, X509, DenyReason)> {
    let harness = &stand.harness;
    let revocations = harness.control.revocations();
    let now = harness.clock.now_secs();
    let issuer = active_issuer(harness);
    let revoke = |kind, subject: String| {
        let revocations = revocations.clone();
        async move {
            revocations
                .revoke(
                    &jaunt_control::RevokeRequest {
                        kind,
                        subject,
                        reason: "test".to_owned(),
                    },
                    "cli:tester",
                )
                .await
                .unwrap();
        }
    };
    let mut cases = Vec::new();

    let mut unknown = person(harness, "u-unknown", &["ops"]).await;
    unknown.user_id = "00000000-0000-0000-0000-000000000000".to_owned();
    cases.push(("unknown user", unknown, DenyReason::UnknownUser));

    let owner = person(harness, "u-owner", &["ops"]).await;
    let mut foreign = person(harness, "u-foreign", &["ops"]).await;
    foreign.user_id = owner.user_id.clone();
    cases.push((
        "certificate of another user",
        foreign,
        DenyReason::CertificateNotIssued,
    ));

    let mut not_issued = person(harness, "u-missing", &["ops"]).await;
    not_issued.serial += 10_000;
    cases.push((
        "serial not issued",
        not_issued,
        DenyReason::CertificateNotIssued,
    ));

    let mut parent_as_child = person(harness, "u-parent", &["ops"]).await;
    parent_as_child.serial = parent_as_child.parent;
    cases.push((
        "ssh serial",
        parent_as_child,
        DenyReason::CertificateNotIssued,
    ));

    let other_kind_user = crate::session_support::user(harness, "u-kind", &["ops"]).await;
    let parent = parent_certificate(harness, &other_kind_user).await;
    let mut other_kind = child_certificate(
        harness,
        &other_kind_user,
        parent,
        (now - 60, now + 60),
        &issuer,
    )
    .await;
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    assert!(
        harness
            .store
            .certificates()
            .record_child(
                &jaunt_store::NewCertificate {
                    serial,
                    user_id: other_kind_user.clone(),
                    kind: "web".to_owned(),
                    key_id: format!("{serial:064x}"),
                    valid_after: now - 60,
                    valid_before: now + 60,
                    issued_at: now - 60,
                    ca_fingerprint: Some(issuer.clone()),
                    host_trust_id: None,
                    subject_fingerprint: Some(other_kind.subject.clone()),
                },
                jaunt_store::Parent {
                    serial: parent,
                    kind: "user",
                },
            )
            .await
            .unwrap()
    );
    other_kind.serial = serial;
    cases.push((
        "child of another kind",
        other_kind,
        DenyReason::CertificateNotIssued,
    ));

    let expired_user = crate::session_support::user(harness, "u-expired", &["ops"]).await;
    let parent = parent_certificate(harness, &expired_user).await;
    let expired = child_certificate(
        harness,
        &expired_user,
        parent,
        (now - 200, now - 1),
        &issuer,
    )
    .await;
    cases.push(("expired", expired, DenyReason::CertificateExpired));

    let disabled = person(harness, "u-disabled", &["ops"]).await;
    revoke(jaunt_store::RevocationKind::User, disabled.user_id.clone()).await;
    cases.push(("disabled user", disabled, DenyReason::Revoked));

    let serial_revoked = person(harness, "u-serial", &["ops"]).await;
    revoke(
        jaunt_store::RevocationKind::Serial,
        serial_revoked.serial.to_string(),
    )
    .await;
    cases.push(("revoked serial", serial_revoked, DenyReason::Revoked));

    let parent_revoked = person(harness, "u-cascade", &["ops"]).await;
    revoke(
        jaunt_store::RevocationKind::Serial,
        parent_revoked.parent.to_string(),
    )
    .await;
    cases.push(("revoked parent", parent_revoked, DenyReason::Revoked));

    let stranger = "cd".repeat(32);
    let untrusted_user = crate::session_support::user(harness, "u-untrusted", &["ops"]).await;
    let parent = parent_certificate(harness, &untrusted_user).await;
    let untrusted = child_certificate(
        harness,
        &untrusted_user,
        parent,
        (now - 60, now + 60),
        &stranger,
    )
    .await;
    cases.push(("untrusted issuer", untrusted, DenyReason::IssuerUntrusted));

    let mut other_key = person(harness, "u-key", &["ops"]).await;
    other_key.subject = subject_fingerprint();
    cases.push(("other key", other_key, DenyReason::SubjectKeyMismatch));

    let pool = crate::session_support::raw_pool(harness).await;
    let raw_child = |owner: String, parent: i64, serial: i64| {
        let pool = pool.clone();
        let issuer = issuer.clone();
        async move {
            let subject = subject_fingerprint();
            sqlx::query(
                "INSERT INTO certificates (serial, user_id, kind, key_id, valid_after, \
                 valid_before, issued_at, ca_fingerprint, subject_fingerprint, parent_serial) \
                 VALUES (?, ?, 'x509', ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(serial)
            .bind(owner)
            .bind(format!("{serial:064x}"))
            .bind(now - 60)
            .bind(now + 3600)
            .bind(now - 60)
            .bind(issuer)
            .bind(&subject)
            .bind(parent)
            .execute(&pool)
            .await
            .unwrap();
            subject
        }
    };
    let claimant = person(harness, "u-claimant", &["ops"]).await;
    let stranger_user = person(harness, "u-stranger", &["ops"]).await;
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let subject = raw_child(stranger_user.user_id.clone(), claimant.parent, serial).await;
    cases.push((
        "another owner under the claimed parent",
        X509 {
            user_id: claimant.user_id.clone(),
            parent: claimant.parent,
            serial,
            subject,
            issuer: issuer.clone(),
        },
        DenyReason::CertificateNotIssued,
    ));
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let subject = raw_child(claimant.user_id.clone(), stranger_user.parent, serial).await;
    cases.push((
        "parent of another user",
        X509 {
            user_id: claimant.user_id.clone(),
            parent: stranger_user.parent,
            serial,
            subject,
            issuer: issuer.clone(),
        },
        DenyReason::CertificateNotIssued,
    ));
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let subject = raw_child(claimant.user_id.clone(), claimant.serial, serial).await;
    cases.push((
        "parent of kind x509",
        X509 {
            user_id: claimant.user_id.clone(),
            parent: claimant.serial,
            serial,
            subject,
            issuer: issuer.clone(),
        },
        DenyReason::CertificateNotIssued,
    ));
    let lapsed = person(harness, "u-lapsed", &["ops"]).await;
    sqlx::query("UPDATE certificates SET valid_before = ? WHERE serial = ?")
        .bind(now - 1)
        .bind(lapsed.parent)
        .execute(&pool)
        .await
        .unwrap();
    cases.push(("parent expired", lapsed, DenyReason::CertificateExpired));

    let mut other_issuer = person(harness, "u-issuer", &["ops"]).await;
    other_issuer.issuer = stranger;
    cases.push(("other issuer", other_issuer, DenyReason::IssuerMismatch));
    cases
}

#[tokio::test]
async fn the_x509_identity_is_checked_on_the_gate_hop_and_on_the_agent_hop() {
    let stand = stand().await;
    let cases = bad_identities(&stand).await;
    for (label, holder, reason) in &cases {
        let routed =
            route_service(&stand.harness, route_request(holder, ServiceKind::Tcp, TCP)).await;
        assert_eq!(route_denied(&routed), Some(*reason), "route: {label}");
        let kube = authorize_service(
            &stand.harness,
            &stand.node_id,
            authorize_request(holder, KUBE_ID, ServiceKind::Kubernetes, KUBE),
        )
        .await;
        assert_eq!(denied(&kube), Some(*reason), "kube: {label}");
    }
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let session_id = routed_id(&stand.harness, &alice, ServiceKind::Tcp, TCP).await;
    stand
        .harness
        .store
        .revocations()
        .insert(
            &jaunt_store::NewRevocation {
                kind: jaunt_store::RevocationKind::Serial,
                subject: alice.parent.to_string(),
                reason: "lost laptop".to_owned(),
                created_by: "cli:tester".to_owned(),
            },
            stand.harness.clock.now_secs(),
        )
        .await
        .unwrap();
    let after = authorize_service(
        &stand.harness,
        &stand.node_id,
        authorize_request(&alice, &session_id, ServiceKind::Tcp, TCP),
    )
    .await;
    assert_eq!(denied(&after), Some(DenyReason::Revoked));
}

#[tokio::test]
async fn policy_decides_each_kind_again_on_the_agent_hop_and_deny_wins() {
    let deny_tcp = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: no-tcp }\nspec:\n  \
        members: { groups: [locked] }\n  deny: { tcp: { services: { team: [ops] } } }\n";
    let deny_app = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: no-app }\nspec:\n  \
        members: { groups: [narrow] }\n  deny: { databases: { servers: { env: [prod] }, users: [app] } }\n";
    let deny_cluster = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: no-cluster }\nspec:\n  \
        members: { groups: [locked] }\n  deny: { kubernetes: { clusters: { name: [prod-eu] } } }\n";
    let deny_view = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: no-view }\nspec:\n  \
        members: { groups: [narrow] }\n  deny: { kubernetes: { clusters: { env: [prod] }, groups: [view] } }\n";
    let trait_role = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: traits }\nspec:\n  \
        members: { groups: [traits] }\n  \
        kubernetes: { clusters: { env: [prod] }, users: ['{username}'], groups: [view] }\n  \
        databases: { servers: { env: [prod] }, users: ['{username}', reporting], names: ['*'] }\n";
    let stand = stand_with_policy(&[
        OPS_ROLE.to_owned(),
        deny_tcp.to_owned(),
        deny_app.to_owned(),
        deny_cluster.to_owned(),
        deny_view.to_owned(),
        trait_role.to_owned(),
    ])
    .await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let locked = person(harness, "locked", &["ops", "locked"]).await;
    let narrow = person(harness, "narrow", &["ops", "narrow"]).await;
    let outsider = person(harness, "outsider", &["dev"]).await;
    let traits = person(harness, "system:trait", &["traits"]).await;

    for (holder, kind, service, expected) in [
        (
            &locked,
            ServiceKind::Tcp,
            TCP,
            Some(DenyReason::DeniedByRule),
        ),
        (
            &outsider,
            ServiceKind::Tcp,
            TCP,
            Some(DenyReason::NoMatchingRole),
        ),
        (
            &outsider,
            ServiceKind::Postgres,
            DB,
            Some(DenyReason::PolicyDenied),
        ),
        (&narrow, ServiceKind::Postgres, DB, None),
    ] {
        let decision = route_service(harness, route_request(holder, kind, service)).await;
        assert_eq!(
            route_denied(&decision),
            expected,
            "{kind:?} {}",
            holder.user_id
        );
    }

    let kube =
        |holder: &X509, id: &str| authorize_request(holder, id, ServiceKind::Kubernetes, KUBE);
    let allowed = authorize_service(harness, &stand.node_id, kube(&alice, KUBE_ID)).await;
    let ServiceAuthorizeDecision::Allow(grant) = &allowed else {
        panic!("{allowed:?}");
    };
    assert_eq!(
        grant.access,
        ServiceAccess::Kube(jaunt_proto::KubeAccess {
            users: vec!["alice@example.com".to_owned()],
            groups: vec!["view".to_owned()],
            record_exec: true,
            record_input: true,
        })
    );
    for (holder, id, reason) in [
        (
            &locked,
            "k-11111111111111111111111111111111",
            DenyReason::DeniedByRule,
        ),
        (
            &narrow,
            "k-22222222222222222222222222222222",
            DenyReason::DeniedByRule,
        ),
        (
            &outsider,
            "k-33333333333333333333333333333333",
            DenyReason::NoMatchingRole,
        ),
        (
            &traits,
            "k-44444444444444444444444444444444",
            DenyReason::TraitNotValid,
        ),
    ] {
        let decision = authorize_service(harness, &stand.node_id, kube(holder, id)).await;
        assert_eq!(denied(&decision), Some(reason), "{id}");
    }
    let as_traits = routed_id(harness, &traits, ServiceKind::Postgres, DB).await;
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                authorize_request(&traits, &as_traits, ServiceKind::Postgres, DB),
            )
            .await
        ),
        Some(DenyReason::TraitNotValid)
    );
    let as_outsider = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;
    let mut unknown_role = authorize_request(&alice, &as_outsider, ServiceKind::Postgres, DB);
    unknown_role.db = db_request("reporting", "main");
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, unknown_role).await),
        Some(DenyReason::NoMatchingRole)
    );

    let as_narrow = routed_id(harness, &narrow, ServiceKind::Postgres, DB).await;
    let mut app = authorize_request(&narrow, &as_narrow, ServiceKind::Postgres, DB);
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, app.clone()).await),
        Some(DenyReason::DeniedByRule)
    );
    app.db = db_request("narrow", "main");
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, app).await),
        None
    );

    let tcp_id = routed_id(harness, &alice, ServiceKind::Tcp, TCP).await;
    apply_policy(
        harness,
        &[OPS_ROLE.replace(
            "tcp: { services: { team: [ops] } }",
            "tcp: { services: { team: [none] } }",
        )],
    );
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                authorize_request(&alice, &tcp_id, ServiceKind::Tcp, TCP),
            )
            .await
        ),
        Some(DenyReason::NoMatchingRole)
    );
}

#[tokio::test]
async fn a_db_client_certificate_is_issued_only_on_allow_for_the_chosen_role() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let session_id = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;
    let base = authorize_request(&alice, &session_id, ServiceKind::Postgres, DB);

    start_recording();
    let serial_before = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    for (label, user, key, reason) in [
        ("superuser", "postgres", None, DenyReason::NoMatchingRole),
        ("other role", "reporting", None, DenyReason::NoMatchingRole),
        (
            "p-256 key",
            "app",
            Some(P256_SPKI),
            DenyReason::InvalidAgentKey,
        ),
        (
            "garbage key",
            "app",
            Some("AAAA"),
            DenyReason::InvalidAgentKey,
        ),
    ] {
        let mut request = base.clone();
        request.db = db_request(user, "main");
        if let (Some(db), Some(key)) = (request.db.as_mut(), key) {
            db.agent_key = key.to_owned();
        }
        let decision = authorize_service(harness, &stand.node_id, request).await;
        assert_eq!(denied(&decision), Some(reason), "{label}");
    }
    let serial_after = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    assert_eq!(serial_after, serial_before + 1);
    assert!(events_named("cert.db_client.issued", &take_recording()).is_empty());
    assert_eq!(row(harness, &session_id).await.state, SessionState::Routed);

    start_recording();
    let now = harness.clock.now_secs();
    let mut named = base.clone();
    named.db = db_request("alice", "main");
    let decision = authorize_service(harness, &stand.node_id, named).await;
    let ServiceAuthorizeDecision::Allow(grant) = &decision else {
        panic!("{decision:?}");
    };
    let ServiceAccess::Db(access) = &grant.access else {
        panic!("{:?}", grant.access);
    };
    let der = STANDARD.decode(&access.certificate_der).unwrap();
    let leaf = parsed(&der);
    assert_eq!(leaf.common_names, ["alice"]);
    assert!(leaf.client_auth && !leaf.server_auth);
    assert_eq!((leaf.not_before, leaf.not_after), (now - 60, now + 300));
    assert_eq!(
        (access.valid_after, access.valid_before),
        (now - 60, now + 300)
    );
    assert_eq!(leaf.serial, u128::try_from(access.serial).unwrap());
    assert_eq!(access.serial, serial_after + 1);
    assert_eq!(
        (access.user.as_str(), access.name.as_str()),
        ("alice", "main")
    );
    let slot = harness.control.db_client().unwrap();
    assert!(client_verifies(&[slot.ca.root_der().to_vec()], &der, now));
    let user_roots: Vec<Vec<u8>> = harness
        .control
        .user_x509()
        .unwrap()
        .roots
        .iter()
        .map(|root| root.certificate_der.clone())
        .collect();
    assert!(!client_verifies(&user_roots, &der, now));
    let active = row(harness, &session_id).await;
    assert_eq!(active.db_client_serial, Some(access.serial));
    assert_eq!(
        (
            active.kind,
            active.login.as_deref(),
            active.target.as_deref()
        ),
        (SessionKind::Db, Some("alice"), Some("main"))
    );
    let issued = events_named("cert.db_client.issued", &take_recording());
    assert_eq!(issued.len(), 1);
    assert_eq!(issued[0]["db_user"], "alice");
    assert_eq!(issued[0]["serial"], access.serial.to_string());
    assert_eq!(issued[0]["session_id"], session_id);
    let probe = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let mut again = base.clone();
    again.db = db_request("alice", "main");
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, again).await),
        Some(DenyReason::SessionUsed)
    );
    assert_eq!(
        harness
            .store
            .certificates()
            .allocate_serial()
            .await
            .unwrap(),
        probe + 1
    );
    let shown = format!("{decision:?}");
    assert!(!shown.contains(&access.certificate_der), "{shown}");
}

async fn try_db(stand: &Stand, holder: &X509, close: bool) -> Option<DenyReason> {
    let session_id = routed_id(&stand.harness, holder, ServiceKind::Postgres, DB).await;
    let decision = authorize_service(
        &stand.harness,
        &stand.node_id,
        authorize_request(holder, &session_id, ServiceKind::Postgres, DB),
    )
    .await;
    let refused = denied(&decision);
    if refused.is_none() && close {
        end_service(
            &stand.harness,
            &stand.node_id,
            &session_id,
            ServiceOutcome::Closed,
            1,
        )
        .await;
    }
    refused
}

#[tokio::test]
async fn a_pool_of_sixteen_db_connections_fits_and_the_seventeenth_meets_the_cap() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    for connection in 0..16 {
        assert_eq!(try_db(&stand, &alice, false).await, None, "{connection}");
    }
    assert_eq!(
        route_denied(
            &route_service(harness, route_request(&alice, ServiceKind::Postgres, DB)).await
        ),
        Some(DenyReason::TooManySessions)
    );
}

#[tokio::test]
async fn db_client_issuance_is_limited_per_user_and_one_user_cannot_spend_another_ones_budget() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    for round in 0..16 {
        assert_eq!(try_db(&stand, &alice, true).await, None, "{round}");
    }
    assert_eq!(
        try_db(&stand, &alice, true).await,
        Some(DenyReason::IssuanceLimited)
    );
    assert_eq!(try_db(&stand, &bob, true).await, None);
    harness.clock.advance(3);
    assert_eq!(try_db(&stand, &alice, true).await, None);
    assert_eq!(
        try_db(&stand, &alice, true).await,
        Some(DenyReason::IssuanceLimited)
    );
}

fn claimed(holder: &X509, user_id: &str) -> jaunt_proto::ServiceAuthorizeRequest {
    let mut request = authorize_request(holder, "no-such-session", ServiceKind::Tcp, TCP);
    request.identity.user_id = user_id.to_owned();
    request
}

#[tokio::test]
async fn one_user_exhausting_the_authorizations_of_a_node_does_not_block_another_user() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    for round in 0..30 {
        let id = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
        assert_eq!(
            end_service(harness, &stand.node_id, &id, ServiceOutcome::Closed, 1).await,
            SessionEndOutcome::Recorded,
            "{round}"
        );
    }
    start_recording();
    let limited = authorize_service(
        harness,
        &stand.node_id,
        authorize_request(&alice, KUBE_ID, ServiceKind::Kubernetes, KUBE),
    )
    .await;
    assert_eq!(denied(&limited), Some(DenyReason::RateLimited));
    let refusals = events_named("authz.service.deny", &take_recording());
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0]["reason"], "rate_limited");
    assert_eq!(
        jaunt_audit::EventType::from_emitted("authz.service.deny")
            .unwrap()
            .class(),
        jaunt_audit::Class::Noisy
    );
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                authorize_request(&bob, KUBE_ID, ServiceKind::Kubernetes, KUBE),
            )
            .await
        ),
        None
    );
    let elsewhere =
        authorize_service(harness, &stand.other_node_id, claimed(&alice, "alice-x")).await;
    assert_eq!(denied(&elsewhere), Some(DenyReason::ServiceUnknown));
    for flood in 0..1000 {
        let refused =
            authorize_service(harness, &stand.node_id, claimed(&alice, &alice.user_id)).await;
        assert_eq!(denied(&refused), Some(DenyReason::RateLimited), "{flood}");
    }
    let carol = person(harness, "carol", &["ops"]).await;
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, claimed(&carol, &carol.user_id)).await),
        Some(DenyReason::SessionUnknown)
    );
    harness.clock.advance(1);
    for refill in 0..5 {
        let decision =
            authorize_service(harness, &stand.node_id, claimed(&alice, &alice.user_id)).await;
        assert_eq!(
            denied(&decision),
            Some(DenyReason::SessionUnknown),
            "{refill}"
        );
    }
    let sixth = authorize_service(harness, &stand.node_id, claimed(&alice, &alice.user_id)).await;
    assert_eq!(denied(&sixth), Some(DenyReason::RateLimited));
}

#[tokio::test]
async fn the_node_backstop_bounds_authorizations_across_claimed_users() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let mut first_limited = None;
    for attempt in 0..1020_usize {
        let user = format!("claimed-{}", attempt / 30);
        let decision = authorize_service(harness, &stand.node_id, claimed(&alice, &user)).await;
        match denied(&decision) {
            Some(DenyReason::RateLimited) => {
                first_limited.get_or_insert(attempt);
            }
            Some(DenyReason::SessionUnknown) => {
                assert!(first_limited.is_none(), "{attempt}");
            }
            other => panic!("{attempt}: {other:?}"),
        }
    }
    assert_eq!(first_limited, Some(1000));
    let fresh = authorize_service(harness, &stand.node_id, claimed(&alice, "never-seen")).await;
    assert_eq!(denied(&fresh), Some(DenyReason::RateLimited));
}

#[tokio::test]
async fn live_kube_sessions_are_capped_per_user_and_per_cluster() {
    let stand = stand().await;
    let harness = &stand.harness;
    let mut people = Vec::new();
    for index in 0..9 {
        people.push(person(harness, &format!("kube-{index}"), &["ops"]).await);
    }
    let mut opened = 0_u64;
    let mut attempt = |holder: &X509| {
        opened += 1;
        harness.clock.advance(1);
        let request = authorize_request(
            holder,
            &format!("k-{opened:032x}"),
            ServiceKind::Kubernetes,
            KUBE,
        );
        let node_id = stand.node_id.clone();
        async move { denied(&authorize_service(harness, &node_id, request).await) }
    };
    for holder in &people[..8] {
        for _ in 0..64 {
            assert_eq!(attempt(holder).await, None);
        }
        assert_eq!(attempt(holder).await, Some(DenyReason::TooManySessions));
    }
    assert_eq!(attempt(&people[8]).await, Some(DenyReason::TooManySessions));
}

#[tokio::test]
async fn at_the_cap_the_oldest_session_on_an_unreachable_node_is_closed_as_abandoned() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let mut tcp = Vec::new();
    for _ in 0..16 {
        harness.clock.advance(1);
        tcp.push(open(&stand, &alice, ServiceKind::Tcp, TCP).await);
    }
    let mut kube = Vec::new();
    for _ in 0..64 {
        harness.clock.advance(1);
        kube.push(open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await);
    }
    let kube_request = |id: &str| authorize_request(&alice, id, ServiceKind::Kubernetes, KUBE);
    assert_eq!(
        route_denied(&route_service(harness, route_request(&alice, ServiceKind::Tcp, TCP)).await),
        Some(DenyReason::TooManySessions)
    );
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                kube_request("k-ffffffffffffffffffffffffffffff01")
            )
            .await
        ),
        Some(DenyReason::TooManySessions)
    );
    assert!(stand.killer.orders().is_empty());

    stand.presence.disconnect(&stand.node_id);
    assert_eq!(
        route_denied(&route_service(harness, route_request(&alice, ServiceKind::Tcp, TCP)).await),
        None
    );
    assert_eq!(
        denied(
            &authorize_service(
                harness,
                &stand.node_id,
                kube_request("k-ffffffffffffffffffffffffffffff02")
            )
            .await
        ),
        None
    );
    for (oldest, rest) in [(&tcp[0], &tcp[1..]), (&kube[0], &kube[1..])] {
        let closed = row(harness, oldest).await;
        assert_eq!(
            (closed.end_reason, closed.outcome.as_deref()),
            (
                Some(SessionEndReason::AgentGone),
                Some(jaunt_store::ABANDONED_OUTCOME)
            )
        );
        for id in rest {
            assert_eq!(row(harness, id).await.state, SessionState::Active, "{id}");
        }
    }
    assert_eq!(killed(&stand).len(), 2);
}

#[tokio::test]
async fn a_promoted_db_client_key_stops_issuance_until_the_slot_is_reloaded() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let old = fingerprint_hex(harness.control.db_client().unwrap().trust.active());
    let next = {
        let lock = jaunt_ca::CaLock::acquire(&harness.ca_root).unwrap();
        let added = jaunt_ca::ClientCa::add_next(
            &lock,
            jaunt_ca::CaKind::DbClient,
            &harness.identity,
            std::time::SystemTime::now(),
        )
        .unwrap();
        jaunt_ca::FileBackend::promote(
            &lock,
            jaunt_ca::CaKind::DbClient,
            &harness.identity,
            &added
                .public_key
                .fingerprint(jaunt_ca::ssh_key::HashAlg::Sha256),
        )
        .unwrap();
        fingerprint_hex(&added.public_key)
    };
    assert_ne!(old, next);
    let attempt = || async {
        let session_id = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;
        authorize_service(
            harness,
            &stand.node_id,
            authorize_request(&alice, &session_id, ServiceKind::Postgres, DB),
        )
        .await
    };
    assert_eq!(
        denied(&attempt().await),
        Some(DenyReason::AuthorityUnavailable)
    );
    let reloaded = jaunt_ca::ClientCa::load(
        &harness.ca_root,
        jaunt_ca::CaKind::DbClient,
        &harness.identity,
    )
    .unwrap();
    harness.control.replace_db_client(reloaded).unwrap();
    let decision = attempt().await;
    let ServiceAuthorizeDecision::Allow(grant) = &decision else {
        panic!("{decision:?}");
    };
    let ServiceAccess::Db(access) = &grant.access else {
        panic!("not a db grant");
    };
    let der = STANDARD.decode(&access.certificate_der).unwrap();
    let slot = harness.control.db_client().unwrap();
    assert_eq!(fingerprint_hex(slot.trust.active()), next);
    assert!(client_verifies(
        &[slot.ca.root_der().to_vec()],
        &der,
        harness.clock.now_secs()
    ));
    let user_x509 = jaunt_ca::ClientCa::load(
        &harness.ca_root,
        jaunt_ca::CaKind::UserX509,
        &harness.identity,
    )
    .unwrap();
    assert!(harness.control.replace_db_client(user_x509).is_err());
}

#[tokio::test]
async fn a_kube_session_takes_the_gate_id_once_on_a_node_that_serves_the_cluster() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let request = authorize_request(&alice, KUBE_ID, ServiceKind::Kubernetes, KUBE);
    assert_eq!(
        denied(&authorize_service(harness, &stand.other_node_id, request.clone()).await),
        Some(DenyReason::ServiceUnknown)
    );
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, request.clone()).await),
        None
    );
    let opened = row(harness, KUBE_ID).await;
    assert_eq!(
        (opened.kind, opened.state, opened.node_id.as_str()),
        (
            SessionKind::Kube,
            SessionState::Active,
            stand.node_id.as_str()
        )
    );
    assert_eq!(opened.roles, ["ops"]);
    assert_eq!(opened.serial, alice.serial);
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, request).await),
        Some(DenyReason::SessionUsed)
    );
    for malformed in [
        "k-0123",
        "67e55044-10b1-426f-9247-bb680e5fe0c8",
        "k-0123456789ABCDEF0123456789ABCDEF",
    ] {
        let decision = authorize_service(
            harness,
            &stand.node_id,
            authorize_request(&alice, malformed, ServiceKind::Kubernetes, KUBE),
        )
        .await;
        assert_eq!(
            denied(&decision),
            Some(DenyReason::SessionUnknown),
            "{malformed}"
        );
    }
    let mut with_db = authorize_request(&alice, KUBE_ID, ServiceKind::Kubernetes, KUBE);
    with_db.db = db_request("app", "main");
    assert_eq!(
        plane(harness)
            .authorize_service(NodeCaller(stand.node_id.clone()), with_db)
            .await,
        Err(PlaneError::InvalidRequest)
    );
}

#[tokio::test]
async fn at_most_sixteen_sessions_per_user_and_service_are_open_at_once() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    for (kind, service) in [(ServiceKind::Tcp, TCP), (ServiceKind::Postgres, DB)] {
        let mut first = None;
        for _ in 0..16 {
            harness.clock.advance(6);
            let id = open(&stand, &alice, kind, service).await;
            first.get_or_insert(id);
        }
        let over = route_service(harness, route_request(&alice, kind, service)).await;
        assert_eq!(
            route_denied(&over),
            Some(DenyReason::TooManySessions),
            "{kind:?}"
        );
        assert_eq!(
            route_denied(&route_service(harness, route_request(&bob, kind, service)).await),
            None
        );
        let first = first.unwrap();
        end_service(harness, &stand.node_id, &first, ServiceOutcome::Closed, 1).await;
        assert_eq!(
            route_denied(&route_service(harness, route_request(&alice, kind, service)).await),
            None,
            "{kind:?}"
        );
    }
    assert_eq!(
        route_denied(
            &route_service(harness, route_request(&alice, ServiceKind::Tcp, METRICS)).await
        ),
        None
    );
}

#[tokio::test]
async fn a_service_end_is_recorded_once_and_only_by_the_node_of_the_session() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let session_id = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    start_recording();
    assert_eq!(
        end_service(
            harness,
            &stand.other_node_id,
            &session_id,
            ServiceOutcome::Closed,
            9
        )
        .await,
        SessionEndOutcome::Rejected
    );
    assert_eq!(
        end_service(
            harness,
            &stand.node_id,
            &session_id,
            ServiceOutcome::IdleTimeout,
            9
        )
        .await,
        SessionEndOutcome::Recorded
    );
    assert_eq!(
        end_service(
            harness,
            &stand.node_id,
            &session_id,
            ServiceOutcome::IdleTimeout,
            9
        )
        .await,
        SessionEndOutcome::Recorded
    );
    assert_eq!(
        end_service(
            harness,
            &stand.node_id,
            &session_id,
            ServiceOutcome::Closed,
            9
        )
        .await,
        SessionEndOutcome::Rejected
    );
    let ended = events_named("session.service.end", &take_recording());
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0]["outcome"], "idle_timeout");
    let stored = row(harness, &session_id).await;
    assert_eq!(stored.state, SessionState::Ended);
    assert_eq!(stored.outcome.as_deref(), Some("idle_timeout"));
    assert_eq!((stored.bytes_in, stored.bytes_out), (Some(5), Some(9)));

    let ssh = crate::session_support::holder(harness, "carol", &["ops"]).await;
    let ssh_session = harness
        .store
        .sessions()
        .create(
            &jaunt_store::NewSession {
                user_id: ssh.user_id.clone(),
                serial: i64::try_from(ssh.serial).unwrap(),
                node_id: stand.node_id.clone(),
                ttl_secs: 60,
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    harness
        .store
        .sessions()
        .activate(jaunt_store::ActivateSession {
            id: &ssh_session.id,
            node_id: &stand.node_id,
            user_id: &ssh.user_id,
            serial: i64::try_from(ssh.serial).unwrap(),
            login: "deploy",
            max_duration_secs: 60,
            pty: true,
            record_input: false,
            now: harness.clock.now_secs(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        end_service(
            harness,
            &stand.node_id,
            &ssh_session.id,
            ServiceOutcome::Closed,
            1
        )
        .await,
        SessionEndOutcome::Rejected
    );
    assert_eq!(
        row(harness, &ssh_session.id).await.state,
        SessionState::Active
    );
    let kube_id = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    assert_eq!(
        crate::session_support::end(
            harness,
            &stand.node_id,
            crate::session_support::end_request(&kube_id, 1),
        )
        .await,
        SessionEndOutcome::Rejected
    );
}

async fn open_one_of_each(stand: &Stand, holder: &X509) -> Vec<String> {
    let mut ids = Vec::new();
    for (kind, service) in [
        (ServiceKind::Tcp, TCP),
        (ServiceKind::Postgres, DB),
        (ServiceKind::Kubernetes, KUBE),
    ] {
        ids.push(open(stand, holder, kind, service).await);
    }
    ids
}

fn killed(stand: &Stand) -> Vec<String> {
    let mut ids: Vec<String> = stand
        .killer
        .orders()
        .into_iter()
        .flat_map(|order| order.sessions.into_iter().map(|session| session.session_id))
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn revoking_the_user_the_x509_serial_or_its_parent_cuts_every_kind_of_session() {
    for kind in ["user", "serial", "parent"] {
        let stand = stand().await;
        let harness = &stand.harness;
        let alice = person(harness, "alice", &["ops"]).await;
        let bob = person(harness, "bob", &["ops"]).await;
        let mut cut = open_one_of_each(&stand, &alice).await;
        let kept = open(&stand, &bob, ServiceKind::Tcp, TCP).await;
        let (revocation, subject) = match kind {
            "user" => (jaunt_store::RevocationKind::User, alice.user_id.clone()),
            "serial" => (
                jaunt_store::RevocationKind::Serial,
                alice.serial.to_string(),
            ),
            _ => (
                jaunt_store::RevocationKind::Serial,
                alice.parent.to_string(),
            ),
        };
        let revoked = harness
            .control
            .revocations()
            .revoke(
                &jaunt_control::RevokeRequest {
                    kind: revocation,
                    subject,
                    reason: "test".to_owned(),
                },
                "cli:tester",
            )
            .await
            .unwrap();
        assert_eq!(revoked.terminated, 3, "{kind}");
        for id in &cut {
            let closed = row(harness, id).await;
            assert_eq!(
                (closed.state, closed.end_reason),
                (SessionState::Ended, Some(SessionEndReason::Revoked)),
                "{kind}"
            );
        }
        assert_eq!(row(harness, &kept).await.state, SessionState::Active);
        cut.sort();
        assert_eq!(killed(&stand), cut, "{kind}");
    }
}

#[tokio::test]
async fn removing_the_node_or_the_approved_service_cuts_its_sessions() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let service = harness
        .store
        .services()
        .serving(jaunt_store::ServiceKind::Tcp, TCP)
        .await
        .unwrap()
        .remove(0);
    harness.store.services().remove(&service.id).await.unwrap();
    let swept = harness.control.review_access().await.unwrap();
    assert_eq!((swept.service_removed, swept.withdrawn), (1, 0));
    assert_eq!(
        row(harness, &tcp).await.end_reason,
        Some(SessionEndReason::ServiceRemoved)
    );
    assert_eq!(row(harness, &db).await.state, SessionState::Active);
    let orders = stand.killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].reason, jaunt_control::KillReason::ServiceRemoved);
    assert_eq!(orders[0].sessions[0].session_id, tcp);

    harness
        .admin
        .remove_node("svc-01", crate::support::APPROVER)
        .await
        .unwrap();
    let swept = harness.control.sweep_sessions().await.unwrap();
    assert_eq!(swept.node_removed, 1);
    assert_eq!(
        row(harness, &db).await.end_reason,
        Some(SessionEndReason::NodeRemoved)
    );
    assert!(killed(&stand).contains(&db));
}

#[tokio::test]
async fn a_policy_change_cuts_exactly_the_live_sessions_it_no_longer_allows() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let db_session = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;
    let mut as_alice = authorize_request(&alice, &db_session, ServiceKind::Postgres, DB);
    as_alice.db = db_request("alice", "main");
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, as_alice).await),
        None
    );
    let db_app = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    assert_eq!(
        harness.control.review_access().await.unwrap(),
        jaunt_control::AccessReview {
            checked: 4,
            withdrawn: 0,
            changed: 0,
            service_removed: 0,
        }
    );

    apply_policy(
        harness,
        &[format!(
            "{}  deny: {{ kubernetes: {{ clusters: {{ env: [prod] }} }} }}\n",
            OPS_ROLE.replace("users: [app, \"{username}\"]", "users: [app]")
        )],
    );
    let swept = harness.control.review_access().await.unwrap();
    assert_eq!((swept.withdrawn, swept.service_removed), (2, 0));
    for (id, reason) in [
        (&kube, Some(SessionEndReason::AccessWithdrawn)),
        (&db_session, Some(SessionEndReason::AccessWithdrawn)),
        (&tcp, None),
        (&db_app, None),
    ] {
        assert_eq!(row(harness, id).await.end_reason, reason, "{id}");
    }
    let orders = stand.killer.orders();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].reason, jaunt_control::KillReason::AccessWithdrawn);
    assert_eq!(orders[0].scope, jaunt_control::KillScope::Sessions);
}

async fn wait_for_end(stand: &Stand, id: &str) -> SessionEndReason {
    let started = std::time::Instant::now();
    loop {
        if let Some(reason) = row(&stand.harness, id).await.end_reason {
            return reason;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the session {id} was not cut"
        );
        tokio::task::yield_now().await;
    }
}

async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_access_watch_cuts_after_a_settled_reload_and_after_other_changes_within_thirty_seconds()
 {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let canary = routed_id(harness, &alice, ServiceKind::Postgres, DB).await;
    let mut as_alice = authorize_request(&alice, &canary, ServiceKind::Postgres, DB);
    as_alice.db = db_request("alice", "main");
    assert_eq!(
        denied(&authorize_service(harness, &stand.node_id, as_alice).await),
        None
    );
    let shell = crate::session_support::role("shell", "ops", false, false);
    apply_policy(harness, &[OPS_ROLE.to_owned(), shell.clone()]);
    let erin = crate::session_support::holder(harness, "erin", &["ops"]).await;
    let ssh = crate::service_support::ssh_session(&stand, &erin).await;
    let first = OPS_ROLE.replace("users: [app, \"{username}\"]", "users: [app]");
    apply_policy(harness, &[first.clone(), shell]);

    tokio::time::pause();
    let spinner = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let control = harness.control.clone();
    let watch = tokio::spawn(async move {
        control
            .watch_access(
                jaunt_control::ACCESS_REVIEW_POLL,
                jaunt_control::ACCESS_REVIEW_INTERVAL,
                jaunt_control::ACCESS_REVIEW_DEBOUNCE,
            )
            .await;
    });
    settle().await;
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        wait_for_end(&stand, &canary).await,
        SessionEndReason::AccessWithdrawn
    );
    settle().await;
    assert_eq!(row(harness, &tcp).await.end_reason, None);
    assert_eq!(row(harness, &ssh).await.end_reason, None);

    apply_policy(
        harness,
        &[first.replace(
            "tcp: { services: { team: [ops] } }",
            "tcp: { services: { team: [none] } }",
        )],
    );
    for _ in 0..5 {
        tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
        settle().await;
        assert_eq!(row(harness, &tcp).await.end_reason, None);
        assert_eq!(row(harness, &ssh).await.end_reason, None);
    }
    tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
    assert_eq!(
        wait_for_end(&stand, &tcp).await,
        SessionEndReason::AccessWithdrawn
    );
    assert_eq!(
        wait_for_end(&stand, &ssh).await,
        SessionEndReason::AccessWithdrawn
    );
    assert_eq!(row(harness, &kube).await.end_reason, None);

    harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                display_name: None,
                groups: vec!["dev".to_owned()],
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    for _ in 0..28 {
        tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL).await;
        settle().await;
    }
    assert_eq!(row(harness, &kube).await.end_reason, None);
    tokio::time::advance(jaunt_control::ACCESS_REVIEW_POLL * 2).await;
    assert_eq!(
        wait_for_end(&stand, &kube).await,
        SessionEndReason::AccessWithdrawn
    );
    assert!(
        jaunt_control::ACCESS_REVIEW_INTERVAL + jaunt_control::ACCESS_REVIEW_POLL
            <= Duration::from_secs(60)
    );
    assert!(
        jaunt_control::ACCESS_REVIEW_DEBOUNCE + jaunt_control::ACCESS_REVIEW_POLL * 2
            <= Duration::from_secs(60)
    );
    watch.abort();
    spinner.abort();
}

#[tokio::test]
async fn the_agent_routes_need_the_node_identity_and_say_nothing_on_a_deny() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let session_id = routed_id(harness, &alice, ServiceKind::Tcp, TCP).await;
    let body = serde_json::to_value(authorize_request(
        &alice,
        &session_id,
        ServiceKind::Tcp,
        TCP,
    ))
    .unwrap();
    let send = |path: &'static str, body: serde_json::Value, node: Option<String>| async move {
        crate::support::send(
            harness.agent_router.clone(),
            crate::support::request(path, &body, None, node.as_deref()),
        )
        .await
    };
    let path = "/v1/agent/service/authorize";
    assert_eq!(
        send(path, body.clone(), None).await.status,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let mut stray = body.clone();
    stray["node_id"] = serde_json::json!(stand.node_id);
    assert_eq!(
        send(path, stray, Some(stand.node_id.clone())).await.status,
        axum::http::StatusCode::BAD_REQUEST
    );
    let refused = send(path, body.clone(), Some(stand.other_node_id.clone())).await;
    assert_eq!(refused.status, axum::http::StatusCode::OK);
    assert_eq!(refused.json(), serde_json::json!({"decision": "deny"}));
    let allowed = send(path, body, Some(stand.node_id.clone())).await;
    assert_eq!(
        allowed.json(),
        serde_json::json!({"decision": "allow", "max_duration_secs": 43_200, "access": {"kind": "tcp"}})
    );

    let end = serde_json::json!({
        "session_id": session_id, "outcome": "closed", "bytes_in": 1, "bytes_out": 2,
    });
    let end_path = "/v1/agent/service/end";
    assert_eq!(
        send(end_path, end.clone(), None).await.status,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let recorded = send(end_path, end.clone(), Some(stand.node_id.clone())).await;
    assert_eq!(recorded.json(), serde_json::json!({"outcome": "recorded"}));
    harness
        .admin
        .remove_node("svc-01", crate::support::APPROVER)
        .await
        .unwrap();
    assert_eq!(
        send(end_path, end, Some(stand.node_id.clone()))
            .await
            .status,
        axum::http::StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn service_sessions_left_by_a_gone_or_silent_agent_are_closed_as_abandoned_and_free_the_cap()
{
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let mut tcp = Vec::new();
    for _ in 0..16 {
        tcp.push(open(&stand, &alice, ServiceKind::Tcp, TCP).await);
    }
    let kube = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    assert_eq!(
        route_denied(&route_service(harness, route_request(&alice, ServiceKind::Tcp, TCP)).await),
        Some(DenyReason::TooManySessions)
    );
    let ssh_holder = crate::session_support::holder(harness, "erin", &["ops"]).await;
    apply_policy(
        harness,
        &[
            OPS_ROLE.to_owned(),
            crate::session_support::role("shell", "ops", false, false),
        ],
    );
    let ssh = crate::service_support::ssh_session(&stand, &ssh_holder).await;

    let closed = harness.control.agent_gone(&stand.node_id).await.unwrap();
    assert_eq!(closed, 18);
    for id in tcp.iter().chain([&kube]) {
        let stored = row(harness, id).await;
        assert_eq!(
            (stored.end_reason, stored.outcome.as_deref()),
            (
                Some(SessionEndReason::AgentGone),
                Some(jaunt_store::ABANDONED_OUTCOME)
            ),
            "{id}"
        );
    }
    let shell = row(harness, &ssh).await;
    assert_eq!(
        (shell.end_reason, shell.outcome),
        (Some(SessionEndReason::AgentGone), None)
    );
    assert_eq!(
        route_denied(&route_service(harness, route_request(&alice, ServiceKind::Tcp, TCP)).await),
        None
    );

    let silent = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    harness
        .clock
        .advance(12 * 3600 + u64::try_from(jaunt_control::OVERDUE_MARGIN_SECS).unwrap());
    harness.control.sweep_sessions().await.unwrap();
    assert_eq!(row(harness, &silent).await.end_reason, None);
    harness.clock.advance(1);
    let swept = harness.control.sweep_sessions().await.unwrap();
    assert!(swept.expired >= 1);
    let stored = row(harness, &silent).await;
    assert_eq!(
        (stored.end_reason, stored.outcome.as_deref()),
        (
            Some(SessionEndReason::Expired),
            Some(jaunt_store::ABANDONED_OUTCOME)
        )
    );
}

#[tokio::test]
async fn recordings_are_taken_only_for_ssh_sessions_of_the_uploading_node() {
    let stand = crate::service_support::recording_stand(&[
        OPS_ROLE.to_owned(),
        crate::session_support::role("shell", "ops", false, false),
    ])
    .await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let erin = crate::session_support::holder(harness, "erin", &["ops"]).await;
    let db = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let ssh = crate::service_support::ssh_session(&stand, &erin).await;
    let post = |node_id: String, session_id: String| async move {
        let body = crate::recording_support::wire(&crate::recording_support::crafted(
            &session_id,
            0,
            b"x\n",
            false,
        ));
        crate::support::send(
            harness.agent_router.clone(),
            crate::support::request(
                &format!("/v1/agent/recordings/{session_id}/chunks"),
                &body,
                None,
                Some(&node_id),
            ),
        )
        .await
    };
    start_recording();
    for (label, node_id, session_id) in [
        ("db", stand.node_id.clone(), db.clone()),
        ("tcp", stand.node_id.clone(), tcp.clone()),
        ("other node", stand.other_node_id.clone(), ssh.clone()),
    ] {
        let reply = post(node_id, session_id).await;
        assert_eq!(reply.status, axum::http::StatusCode::NOT_FOUND, "{label}");
        assert_eq!(reply.error_code(), "session_unknown", "{label}");
    }
    let reasons: Vec<String> = events_named("recording.rejected", &take_recording())
        .iter()
        .map(|event| event["reason"].clone())
        .collect();
    assert_eq!(reasons, ["wrong_kind", "wrong_kind", "wrong_node"]);
    let accepted = post(stand.node_id.clone(), ssh.clone()).await;
    assert_eq!(
        accepted.status,
        axum::http::StatusCode::OK,
        "{}",
        accepted.text()
    );
    assert!(harness.store.recordings().get(&db).await.unwrap().is_none());
    assert!(
        harness
            .store
            .recordings()
            .get(&tcp)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn at_the_cap_only_the_users_own_oldest_session_on_an_unreachable_node_is_abandoned() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let bob = person(harness, "bob", &["ops"]).await;
    harness.clock.advance(1);
    let bobs = open(&stand, &bob, ServiceKind::Tcp, TCP).await;
    let mut alices = Vec::new();
    for _ in 0..16 {
        harness.clock.advance(1);
        alices.push(open(&stand, &alice, ServiceKind::Tcp, TCP).await);
    }
    stand.presence.disconnect(&stand.node_id);
    assert_eq!(
        route_denied(&route_service(harness, route_request(&alice, ServiceKind::Tcp, TCP)).await),
        None
    );
    assert_eq!(row(harness, &bobs).await.state, SessionState::Active);
    let closed = row(harness, &alices[0]).await;
    assert_eq!(
        (closed.end_reason, closed.outcome.as_deref()),
        (
            Some(SessionEndReason::AgentGone),
            Some(jaunt_store::ABANDONED_OUTCOME)
        )
    );
    for id in &alices[1..] {
        assert_eq!(row(harness, id).await.state, SessionState::Active, "{id}");
    }
}

#[tokio::test]
async fn an_agent_restart_and_a_daemon_restart_mark_unreported_service_sessions_abandoned() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let restarted = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let routed = routed_id(harness, &alice, ServiceKind::Tcp, TCP).await;
    let now = u64::try_from(harness.clock.now_secs()).unwrap();
    let registered_at = std::time::UNIX_EPOCH + Duration::from_secs(now + 1);
    assert_eq!(
        harness
            .control
            .agent_registered(&stand.node_id, registered_at)
            .await
            .unwrap(),
        2
    );
    let closed = row(harness, &restarted).await;
    assert_eq!(
        (closed.end_reason, closed.outcome.as_deref()),
        (
            Some(SessionEndReason::AgentRestarted),
            Some(jaunt_store::ABANDONED_OUTCOME)
        )
    );
    assert_eq!(row(harness, &routed).await.outcome, None);

    harness.clock.advance(2);
    let earlier_run = open(&stand, &alice, ServiceKind::Postgres, DB).await;
    assert_eq!(
        harness
            .control
            .close_sessions_of_earlier_runs()
            .await
            .unwrap(),
        1
    );
    let closed = row(harness, &earlier_run).await;
    assert_eq!(
        (closed.end_reason, closed.outcome.as_deref()),
        (
            Some(SessionEndReason::AgentGone),
            Some(jaunt_store::ABANDONED_OUTCOME)
        )
    );
}
