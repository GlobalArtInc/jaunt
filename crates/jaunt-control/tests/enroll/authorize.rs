use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, DenyReason, SessionEndOutcome, SessionPermissions,
};
use jaunt_store::SessionState;

use crate::session_support::{
    LOGIN, NODE_NAME, ROUTED_TTL_SECS, Scenario, apply_policy, authorize, certificate, end,
    end_request, holder, node, role, routed, scenario, stored,
};

const TWELVE_HOURS: u64 = 12 * 60 * 60;

fn permissions(port_forwarding: bool, record_input: bool) -> SessionPermissions {
    SessionPermissions {
        pty: true,
        port_forwarding,
        record_input,
        max_duration_secs: TWELVE_HOURS,
    }
}

fn deny(reason: DenyReason) -> AuthorizeDecision {
    AuthorizeDecision::Deny { reason }
}

impl Scenario {
    async fn decide(&self, request: AuthorizeRequest) -> AuthorizeDecision {
        authorize(&self.harness, &self.node_id, request).await
    }

    async fn fresh_session(&self) -> String {
        routed(&self.harness, &self.alice).await
    }
}

#[tokio::test]
async fn authorize_grants_the_union_of_the_matching_roles_and_activates_the_session() {
    let s = scenario().await;
    let harness = &s.harness;
    apply_policy(
        harness,
        &[
            role("plain", "plain", false, false),
            role("forward", "forward", true, false),
            role("record", "record", false, true),
        ],
    );
    let cases = [
        ("plain", vec!["plain"], permissions(false, false)),
        ("forward", vec!["forward"], permissions(true, false)),
        ("record", vec!["record"], permissions(false, true)),
        ("both", vec!["forward", "record"], permissions(true, true)),
    ];
    for (subject, groups, expected) in cases {
        let holder = holder(harness, subject, &groups).await;
        let session_id = routed(harness, &holder).await;
        let decision = s.decide(holder.authorize(&session_id, LOGIN)).await;
        assert_eq!(
            decision,
            AuthorizeDecision::Allow {
                permissions: expected
            },
            "{subject}"
        );
        let active = stored(harness, &session_id).await.unwrap();
        assert_eq!(active.state, SessionState::Active, "{subject}");
        assert_eq!(active.login.as_deref(), Some(LOGIN), "{subject}");
        assert_eq!(active.authorized_at, Some(harness.clock.now_secs()));
    }
}

#[tokio::test]
async fn authorize_requires_the_same_holder_on_both_hops_and_a_fresh_unused_binding() {
    let s = scenario().await;
    let harness = &s.harness;
    let bob = holder(harness, "bob", &["ops"]).await;
    let now = harness.clock.now_secs();
    let second_certificate = certificate(harness, &s.alice.user_id, now - 1, now + 3600).await;

    let session_id = s.fresh_session().await;
    let other_user = AuthorizeRequest {
        user_id: bob.user_id.clone(),
        ..s.alice.authorize(&session_id, LOGIN)
    };
    assert_eq!(s.decide(other_user).await, deny(DenyReason::UserMismatch));
    let other_serial = second_certificate.authorize(&session_id, LOGIN);
    assert_eq!(
        s.decide(other_serial).await,
        deny(DenyReason::SerialMismatch)
    );
    assert_eq!(
        s.decide(bob.authorize(&session_id, LOGIN)).await,
        deny(DenyReason::UserMismatch)
    );

    let first = s.decide(s.alice.authorize(&session_id, LOGIN)).await;
    assert!(matches!(first, AuthorizeDecision::Allow { .. }));
    let replay = s.decide(s.alice.authorize(&session_id, LOGIN)).await;
    assert_eq!(replay, deny(DenyReason::SessionUsed));

    let late = s.fresh_session().await;
    harness.clock.advance(ROUTED_TTL_SECS);
    assert_eq!(
        s.decide(s.alice.authorize(&late, LOGIN)).await,
        deny(DenyReason::SessionExpired)
    );
    assert_eq!(
        stored(harness, &late).await.unwrap().state,
        SessionState::Routed
    );
}

#[tokio::test]
async fn authorize_rechecks_the_login_the_policy_and_the_node() {
    let s = scenario().await;
    let harness = &s.harness;

    for login in ["root", "bad login", ""] {
        let session_id = s.fresh_session().await;
        assert_eq!(
            s.decide(s.alice.authorize(&session_id, login)).await,
            deny(DenyReason::PolicyDenied),
            "{login:?}"
        );
    }

    let before_reload = s.fresh_session().await;
    let before_removal = s.fresh_session().await;
    apply_policy(harness, &[role("ops", "someone-else", false, false)]);
    assert_eq!(
        s.decide(s.alice.authorize(&before_reload, LOGIN)).await,
        deny(DenyReason::PolicyDenied)
    );

    apply_policy(harness, &[role("ops", "ops", false, false)]);
    harness
        .admin
        .remove_node(NODE_NAME, "cli:tester")
        .await
        .unwrap();
    assert_eq!(
        s.decide(s.alice.authorize(&before_removal, LOGIN)).await,
        deny(DenyReason::NodeInactive)
    );
    assert_eq!(
        stored(harness, &before_removal).await.unwrap().state,
        SessionState::Routed
    );
}

#[tokio::test]
async fn only_the_owning_node_ends_an_active_session_and_a_repeat_is_idempotent() {
    let s = scenario().await;
    let harness = &s.harness;
    let other_node = node(harness, "web-02").await;

    let never_authorized = s.fresh_session().await;
    assert_eq!(
        end(harness, &s.node_id, end_request(&never_authorized, 7)).await,
        SessionEndOutcome::Rejected
    );
    assert_eq!(
        end(harness, &s.node_id, end_request("unknown-session", 7)).await,
        SessionEndOutcome::Rejected
    );

    let session_id = s.fresh_session().await;
    let allowed = s.decide(s.alice.authorize(&session_id, LOGIN)).await;
    assert!(matches!(allowed, AuthorizeDecision::Allow { .. }));
    assert_eq!(
        end(harness, &other_node, end_request(&session_id, 7)).await,
        SessionEndOutcome::Rejected
    );
    assert_eq!(
        stored(harness, &session_id).await.unwrap().state,
        SessionState::Active
    );
    for _ in 0..2 {
        assert_eq!(
            end(harness, &s.node_id, end_request(&session_id, 7)).await,
            SessionEndOutcome::Recorded
        );
    }
    assert_eq!(
        end(harness, &s.node_id, end_request(&session_id, 8)).await,
        SessionEndOutcome::Rejected
    );
    let ended = stored(harness, &session_id).await.unwrap();
    assert_eq!(ended.state, SessionState::Ended);
    assert_eq!(
        (ended.exit_status, ended.bytes_in, ended.bytes_out),
        (Some(0), Some(42), Some(7))
    );
    assert_eq!(ended.recording_incomplete, Some(false));
}
