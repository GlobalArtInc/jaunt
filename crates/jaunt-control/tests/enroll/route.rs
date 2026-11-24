use jaunt_proto::{ControlError, DenyReason, RouteDecision, RouteRequest};
use jaunt_store::{NewCertificate, SessionState};
use sqlx::Row;

use crate::session_support::{
    NODE_NAME, ROUTED_TTL_SECS, authorize, certificate, end, end_request, holder, node, plane,
    raw_pool, route, routed, scenario, stored,
};
use crate::support::{Harness, Options, SUFFIX};

async fn session_rows(harness: &Harness) -> i64 {
    let pool = raw_pool(harness).await;
    sqlx::query("SELECT COUNT(*) AS rows FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("rows")
}

#[tokio::test]
async fn route_binds_a_short_lived_session_for_a_matching_role() {
    let s = scenario().await;
    let decision = route(&s.harness, s.alice.route_to(NODE_NAME)).await;
    let RouteDecision::Allow {
        session_id,
        node_id,
    } = decision
    else {
        panic!("expected an allow, got {decision:?}");
    };
    assert_eq!(node_id, s.node_id);
    let binding = stored(&s.harness, &session_id).await.unwrap();
    assert_eq!(binding.state, SessionState::Routed);
    assert_eq!(binding.user_id, s.alice.user_id);
    assert_eq!(binding.serial, i64::try_from(s.alice.serial).unwrap());
    assert_eq!(binding.node_id, s.node_id);
    assert_eq!(
        binding.expires_at,
        s.harness.clock.now_secs() + i64::try_from(ROUTED_TTL_SECS).unwrap()
    );
}

#[tokio::test]
async fn route_denies_every_holder_and_node_that_does_not_check_out() {
    let s = scenario().await;
    let harness = &s.harness;
    let alice = &s.alice;
    let bob = holder(harness, "bob", &["dev"]).await;
    let now = harness.clock.now_secs();
    let expired = certificate(harness, &alice.user_id, now - 7200, now).await;
    let not_yet = certificate(harness, &alice.user_id, now + 1, now + 7200).await;
    let web_serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let web_key_id = format!("jaunt:web:{web_serial}");
    harness
        .store
        .certificates()
        .record(&NewCertificate {
            serial: web_serial,
            user_id: alice.user_id.clone(),
            kind: "web".to_owned(),
            key_id: web_key_id.clone(),
            valid_after: now - 60,
            valid_before: now + 3600,
            issued_at: now,
        })
        .await
        .unwrap();
    node(harness, "web-02").await;
    harness.admin.remove_node("web-02").await.unwrap();
    let to_node = alice.route_to(NODE_NAME);

    let cases = [
        (
            "unknown user",
            RouteRequest {
                user_id: "00000000-0000-4000-8000-000000000000".to_owned(),
                ..to_node.clone()
            },
            DenyReason::UnknownUser,
        ),
        (
            "serial never recorded",
            RouteRequest {
                serial: 999_999,
                ..to_node.clone()
            },
            DenyReason::CertificateNotIssued,
        ),
        (
            "serial beyond the stored range",
            RouteRequest {
                serial: u64::MAX,
                ..to_node.clone()
            },
            DenyReason::CertificateNotIssued,
        ),
        (
            "certificate recorded for another user",
            RouteRequest {
                serial: bob.serial,
                key_id: bob.key_id.clone(),
                ..to_node.clone()
            },
            DenyReason::CertificateNotIssued,
        ),
        (
            "key id differs from the recorded one",
            RouteRequest {
                key_id: format!("{}0", alice.key_id),
                ..to_node.clone()
            },
            DenyReason::CertificateNotIssued,
        ),
        (
            "certificate of a non-user kind",
            RouteRequest {
                serial: u64::try_from(web_serial).unwrap(),
                key_id: web_key_id.clone(),
                ..to_node.clone()
            },
            DenyReason::CertificateNotIssued,
        ),
        (
            "certificate expired at this second",
            expired.route_to(NODE_NAME),
            DenyReason::CertificateExpired,
        ),
        (
            "certificate not yet valid",
            not_yet.route_to(NODE_NAME),
            DenyReason::CertificateExpired,
        ),
        (
            "removed node",
            alice.route_to("web-02"),
            DenyReason::NodeUnknown,
        ),
        (
            "unknown node",
            alice.route_to("ghost"),
            DenyReason::NodeUnknown,
        ),
        (
            "name in another case",
            alice.route_to("Web-01"),
            DenyReason::NodeUnknown,
        ),
        (
            "name with a trailing dot",
            alice.route_to("web-01."),
            DenyReason::NodeUnknown,
        ),
        (
            "name with the suffix",
            alice.route_to(&format!("{NODE_NAME}.{SUFFIX}")),
            DenyReason::NodeUnknown,
        ),
        (
            "no role for the user",
            bob.route_to(NODE_NAME),
            DenyReason::PolicyDenied,
        ),
    ];
    for (case, request, reason) in cases {
        assert_eq!(
            route(harness, request).await,
            RouteDecision::Deny { reason },
            "{case}"
        );
    }
    assert_eq!(session_rows(harness).await, 0);
}

#[tokio::test]
async fn a_certificate_is_usable_from_its_valid_after_second() {
    let s = scenario().await;
    let now = s.harness.clock.now_secs();
    let fresh = certificate(&s.harness, &s.alice.user_id, now, now + 3600).await;
    assert!(matches!(
        route(&s.harness, fresh.route_to(NODE_NAME)).await,
        RouteDecision::Allow { .. }
    ));
}

#[tokio::test]
async fn an_empty_policy_denies_every_route() {
    let harness = Harness::with(Options {
        empty_policy: true,
        ..Options::default()
    })
    .await;
    node(&harness, NODE_NAME).await;
    let alice = holder(&harness, "alice", &["ops"]).await;
    assert_eq!(
        route(&harness, alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::PolicyDenied
        }
    );
}

#[tokio::test]
async fn route_rejects_fields_that_cannot_be_audited_safely() {
    let s = scenario().await;
    for request in [
        RouteRequest {
            client_addr: "203.0.113.7\nforged".to_owned(),
            ..s.alice.route_to(NODE_NAME)
        },
        RouteRequest {
            node_name: "n".repeat(257),
            ..s.alice.route_to(NODE_NAME)
        },
    ] {
        assert_eq!(
            plane(&s.harness).route(request).await,
            Err(ControlError::InvalidRequest)
        );
    }
}

#[tokio::test]
async fn the_sweeper_purges_routed_sessions_an_hour_after_expiry_and_keeps_the_rest() {
    let s = scenario().await;
    let harness = &s.harness;
    let stale = routed(harness, &s.alice).await;
    let active = routed(harness, &s.alice).await;
    let ended = routed(harness, &s.alice).await;
    for session_id in [&active, &ended] {
        let request = s.alice.authorize(session_id, "deploy", true);
        assert!(matches!(
            authorize(harness, &s.node_id, request).await,
            jaunt_proto::AuthorizeDecision::Allow { .. }
        ));
    }
    end(harness, &s.node_id, end_request(&ended, 1)).await;

    harness.clock.advance(ROUTED_TTL_SECS + 3600);
    assert_eq!(harness.control.purge_stale_sessions().await.unwrap(), 0);
    harness.clock.advance(1);
    assert_eq!(harness.control.purge_stale_sessions().await.unwrap(), 1);

    assert!(stored(harness, &stale).await.is_none());
    assert_eq!(
        stored(harness, &active).await.unwrap().state,
        SessionState::Active
    );
    assert_eq!(
        stored(harness, &ended).await.unwrap().state,
        SessionState::Ended
    );
}
