use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError, DenyReason, NodeCaller, SessionEnd,
    SessionEndOutcome,
};
use jaunt_store::{NewSession, SessionState};

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    LOGIN, NODE_NAME, ROUTED_TTL_SECS, audit_events, authorize, certificate, end, end_request,
    holder, node, plane, raw_pool, routed, scenario, stored,
};
use crate::support::{Harness, Options};

const MAX_FIELD_BYTES: usize = 256;

fn deny(reason: DenyReason) -> AuthorizeDecision {
    AuthorizeDecision::Deny { reason }
}

fn unacceptable_values() -> [String; 3] {
    [
        "value\nforged".to_owned(),
        "value\u{7}".to_owned(),
        "a".repeat(MAX_FIELD_BYTES + 1),
    ]
}

#[tokio::test]
async fn authorize_rechecks_the_certificate_and_the_user_recorded_at_route() {
    let s = scenario().await;
    let harness = &s.harness;
    let now = harness.clock.now_secs();
    let short_lived = certificate(harness, &s.alice.user_id, now - 1, now + 30).await;
    let carol = holder(harness, "carol", &["ops"]).await;
    let expiring = routed(harness, &short_lived).await;
    let rekeyed = routed(harness, &s.alice).await;
    let orphaned = routed(harness, &carol).await;
    harness.clock.advance(31);

    assert_eq!(
        authorize(harness, &s.node_id, short_lived.authorize(&expiring, LOGIN)).await,
        deny(DenyReason::CertificateExpired)
    );
    let other_key = AuthorizeRequest {
        key_id: format!("{}0", s.alice.key_id),
        ..s.alice.authorize(&rekeyed, LOGIN)
    };
    assert_eq!(
        authorize(harness, &s.node_id, other_key).await,
        deny(DenyReason::CertificateNotIssued)
    );
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&carol.user_id)
        .execute(&raw_pool(harness).await)
        .await
        .unwrap();
    assert_eq!(
        authorize(harness, &s.node_id, carol.authorize(&orphaned, LOGIN)).await,
        deny(DenyReason::UnknownUser)
    );
}

#[tokio::test]
async fn authorize_allows_in_the_last_second_of_the_binding() {
    let s = scenario().await;
    let session_id = routed(&s.harness, &s.alice).await;
    s.harness.clock.advance(ROUTED_TTL_SECS - 1);
    let decision = authorize(
        &s.harness,
        &s.node_id,
        s.alice.authorize(&session_id, LOGIN),
    )
    .await;
    assert!(matches!(decision, AuthorizeDecision::Allow { .. }));
}

#[tokio::test]
async fn a_re_enrolled_node_with_the_same_name_cannot_take_the_old_nodes_session() {
    let s = scenario().await;
    let harness = &s.harness;
    let session_id = routed(harness, &s.alice).await;
    harness.admin.remove_node(NODE_NAME).await.unwrap();
    let successor = node(harness, NODE_NAME).await;
    assert_ne!(successor, s.node_id);
    assert_eq!(
        authorize(harness, &successor, s.alice.authorize(&session_id, LOGIN)).await,
        deny(DenyReason::WrongNode)
    );
}

#[tokio::test]
async fn an_empty_policy_denies_authorize() {
    let harness = Harness::with(Options {
        empty_policy: true,
        ..Options::default()
    })
    .await;
    let node_id = node(&harness, NODE_NAME).await;
    let alice = holder(&harness, "alice", &["ops"]).await;
    let binding = harness
        .store
        .sessions()
        .create(
            &NewSession {
                user_id: alice.user_id.clone(),
                serial: i64::try_from(alice.serial).unwrap(),
                node_id: node_id.clone(),
                ttl_secs: 60,
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    assert_eq!(
        authorize(&harness, &node_id, alice.authorize(&binding.id, LOGIN)).await,
        deny(DenyReason::PolicyDenied)
    );
}

#[tokio::test]
async fn authorize_rejects_unsafe_fields_before_any_decision() {
    let s = scenario().await;
    let harness = &s.harness;
    let session_id = routed(harness, &s.alice).await;
    let base = s.alice.authorize(&session_id, LOGIN);
    start_recording();

    for bad in unacceptable_values() {
        let cases = [
            (
                s.node_id.clone(),
                AuthorizeRequest {
                    session_id: bad.clone(),
                    ..base.clone()
                },
            ),
            (
                s.node_id.clone(),
                AuthorizeRequest {
                    user_id: bad.clone(),
                    ..base.clone()
                },
            ),
            (
                s.node_id.clone(),
                AuthorizeRequest {
                    key_id: bad.clone(),
                    ..base.clone()
                },
            ),
            (
                s.node_id.clone(),
                AuthorizeRequest {
                    login: bad.clone(),
                    ..base.clone()
                },
            ),
            (
                s.node_id.clone(),
                AuthorizeRequest {
                    client_addr: bad.clone(),
                    ..base.clone()
                },
            ),
            (bad.clone(), base.clone()),
        ];
        for (caller, request) in cases {
            let outcome = plane(harness)
                .authorize(NodeCaller(caller), request.clone())
                .await;
            assert_eq!(outcome, Err(ControlError::InvalidRequest), "{request:?}");
        }
    }
    assert!(audit_events(take_recording()).is_empty());
    assert_eq!(
        stored(harness, &session_id).await.unwrap().state,
        SessionState::Routed
    );

    let longest = AuthorizeRequest {
        client_addr: "a".repeat(MAX_FIELD_BYTES),
        ..base
    };
    assert!(matches!(
        authorize(harness, &s.node_id, longest).await,
        AuthorizeDecision::Allow { .. }
    ));
}

#[tokio::test]
async fn session_end_rejects_unsafe_fields_and_counters_beyond_the_store_range() {
    let s = scenario().await;
    let harness = &s.harness;
    let session_id = routed(harness, &s.alice).await;
    let allowed = authorize(harness, &s.node_id, s.alice.authorize(&session_id, LOGIN)).await;
    assert!(matches!(allowed, AuthorizeDecision::Allow { .. }));
    let base = end_request(&session_id, 7);
    start_recording();

    let mut cases = vec![
        (
            s.node_id.clone(),
            SessionEnd {
                bytes_in: u64::MAX,
                ..base.clone()
            },
        ),
        (
            s.node_id.clone(),
            SessionEnd {
                bytes_out: u64::MAX,
                ..base.clone()
            },
        ),
    ];
    for bad in unacceptable_values() {
        cases.push((
            s.node_id.clone(),
            SessionEnd {
                session_id: bad.clone(),
                ..base.clone()
            },
        ));
        cases.push((bad, base.clone()));
    }
    for (caller, request) in cases {
        let outcome = plane(harness)
            .session_end(NodeCaller(caller), request.clone())
            .await;
        assert_eq!(outcome, Err(ControlError::InvalidRequest), "{request:?}");
    }
    assert!(audit_events(take_recording()).is_empty());
    assert_eq!(
        stored(harness, &session_id).await.unwrap().state,
        SessionState::Active
    );

    let longest = end_request(&"a".repeat(MAX_FIELD_BYTES), 7);
    assert_eq!(
        end(harness, &s.node_id, longest).await,
        SessionEndOutcome::Rejected
    );
}
