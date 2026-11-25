use jaunt_proto::{AuthorizeDecision, AuthorizeRequest, DenyReason, RouteDecision, RouteRequest};
use jaunt_store::SessionState;

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    LOGIN, NODE_NAME, audit_events, authorize, raw_pool, recorded_certificate, route, routed,
    scenario, stored, subject_fingerprint, user,
};

const MISMATCH: DenyReason = DenyReason::SubjectKeyMismatch;

async fn sessions_of(harness: &crate::support::Harness, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(&raw_pool(harness).await)
        .await
        .unwrap()
}

fn denied_reasons(phase: &str) -> Vec<String> {
    audit_events(take_recording())
        .into_iter()
        .filter(|event| event["event"] == "authz.deny" && event["phase"] == phase)
        .map(|event| event["reason"].clone())
        .collect()
}

#[tokio::test]
async fn route_refuses_another_subject_key_or_none_and_binds_no_session() {
    let s = scenario().await;
    let genuine = s.alice.route_to(NODE_NAME);
    let attacker = RouteRequest {
        subject_fingerprint: Some(subject_fingerprint()),
        ..genuine.clone()
    };
    let unnamed = RouteRequest {
        subject_fingerprint: None,
        ..genuine.clone()
    };
    start_recording();

    let forged = route(&s.harness, attacker).await;
    let silent = route(&s.harness, unnamed).await;

    assert_eq!(forged, RouteDecision::Deny { reason: MISMATCH });
    assert_eq!(silent, RouteDecision::Deny { reason: MISMATCH });
    assert_eq!(sessions_of(&s.harness, &s.alice.user_id).await, 0);
    assert_eq!(
        denied_reasons("route"),
        ["subject_key_mismatch", "subject_key_mismatch"]
    );
    assert!(matches!(
        route(&s.harness, genuine).await,
        RouteDecision::Allow { .. }
    ));
    assert_eq!(sessions_of(&s.harness, &s.alice.user_id).await, 1);
}

#[tokio::test]
async fn authorize_refuses_another_subject_key_and_accepts_an_older_agent_that_names_none() {
    let s = scenario().await;
    let harness = &s.harness;
    let session_id = routed(harness, &s.alice).await;
    let attacker = AuthorizeRequest {
        subject_fingerprint: Some(subject_fingerprint()),
        ..s.alice.authorize(&session_id, LOGIN)
    };
    start_recording();

    let forged = authorize(harness, &s.node_id, attacker).await;

    assert_eq!(forged, AuthorizeDecision::Deny { reason: MISMATCH });
    assert_eq!(denied_reasons("authorize"), ["subject_key_mismatch"]);
    assert_eq!(
        stored(harness, &session_id).await.unwrap().state,
        SessionState::Routed
    );
    let older_agent = AuthorizeRequest {
        subject_fingerprint: None,
        ..s.alice.authorize(&session_id, LOGIN)
    };
    assert!(matches!(
        authorize(harness, &s.node_id, older_agent).await,
        AuthorizeDecision::Allow { .. }
    ));

    let genuine_session = routed(harness, &s.alice).await;
    assert!(matches!(
        authorize(
            harness,
            &s.node_id,
            s.alice.authorize(&genuine_session, LOGIN)
        )
        .await,
        AuthorizeDecision::Allow { .. }
    ));
}

#[tokio::test]
async fn certificates_issued_before_subject_keys_were_recorded_pass_until_they_expire() {
    let s = scenario().await;
    let harness = &s.harness;
    let user_id = user(harness, "dave", &["ops"]).await;
    let now = harness.clock.now_secs();
    let mut older = recorded_certificate(harness, &user_id, (now - 60, now + 600), None).await;
    older.subject_fingerprint = Some(subject_fingerprint());

    let session_id = routed(harness, &older).await;
    let unnamed = RouteRequest {
        subject_fingerprint: None,
        ..older.route_to(NODE_NAME)
    };
    assert!(matches!(
        route(harness, unnamed).await,
        RouteDecision::Allow { .. }
    ));
    assert!(matches!(
        authorize(harness, &s.node_id, older.authorize(&session_id, LOGIN)).await,
        AuthorizeDecision::Allow { .. }
    ));

    harness.clock.advance(601);
    assert_eq!(
        route(harness, older.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::CertificateExpired
        }
    );
}
