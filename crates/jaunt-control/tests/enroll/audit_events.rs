use jaunt_audit::{Actor, AuditEvent, ScopedCapture};
use serde_json::json;

use crate::session_support::{
    LOGIN, NODE_NAME, authorize, end, end_request, holder, node, route, routed, scenario,
};
use crate::support::{APPROVER, Harness, new_agent};

fn lines(events: &[std::sync::Arc<AuditEvent>]) -> String {
    events
        .iter()
        .map(|event| serde_json::to_string(event.as_ref()).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn sequence(events: &[std::sync::Arc<AuditEvent>]) -> Vec<(&'static str, String)> {
    events
        .iter()
        .map(|event| (event.kind().name(), event.actor().as_wire()))
        .collect()
}

#[tokio::test]
async fn the_enrolment_flow_leaves_exactly_these_schema_events() {
    let harness = Harness::new().await;
    let capture = ScopedCapture::start();

    let first = harness.enroll("web-01").await;
    harness.approve(&first).await;
    let delivered = harness.poll(&first.handle).await.json();
    let node_id = delivered["node_id"].as_str().unwrap().to_owned();
    harness.renew(Some(&node_id), &json!({})).await;
    let second = harness.enroll("web-02").await;
    harness.admin.reject(&second.code, APPROVER).await.unwrap();
    harness.admin.remove_node("web-01", APPROVER).await.unwrap();
    let snapshot = capture.snapshot();
    let events = capture.finish().await;
    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );

    assert_eq!(
        sequence(&events),
        [
            ("node.enroll.requested", "anonymous".to_owned()),
            ("node.enroll.approved", APPROVER.to_owned()),
            ("node.enroll.delivered", format!("node:{node_id}")),
            ("node.cert.renewed", format!("node:{node_id}")),
            ("node.enroll.requested", "anonymous".to_owned()),
            ("node.enroll.rejected", APPROVER.to_owned()),
            ("node.removed", APPROVER.to_owned()),
        ]
    );
    let with_node: Vec<Option<&str>> = events.iter().map(|e| e.node()).collect();
    assert_eq!(
        with_node,
        [
            None,
            Some(node_id.as_str()),
            Some(node_id.as_str()),
            Some(node_id.as_str()),
            None,
            None,
            Some(node_id.as_str())
        ]
    );
    assert_eq!(events[0].text("name"), Some("web-01"));
    assert_eq!(events[0].flag("replace"), Some(false));
    assert!(events[0].fields().contains_key("source_network"));
    assert_eq!(events[5].text("name"), Some("web-02"));
    assert_eq!(events[6].text("reason"), Some("admin"));
    let lines = lines(&events);
    for secret in [&first.handle, &first.code, &first.agent.tls_public_key] {
        assert!(!lines.contains(secret.as_str()), "{lines}");
    }
}

#[tokio::test]
async fn route_authorize_and_session_end_leave_exactly_these_schema_events() {
    let s = scenario().await;
    let harness = &s.harness;
    let other_node = node(harness, "web-02").await;
    let bob = holder(harness, "bob", &["dev"]).await;
    let capture = ScopedCapture::start();

    route(harness, bob.route_to(NODE_NAME)).await;
    let session_id = routed(harness, &s.alice).await;
    authorize(harness, &other_node, s.alice.authorize(&session_id, LOGIN)).await;
    authorize(harness, &s.node_id, s.alice.authorize(&session_id, LOGIN)).await;
    end(harness, &s.node_id, end_request(&session_id, 20)).await;
    end(harness, &other_node, end_request(&session_id, 20)).await;
    let snapshot = capture.snapshot();
    let events = capture.finish().await;
    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );

    assert_eq!(
        sequence(&events),
        [
            ("authz.deny", bob.user_id.clone()),
            ("session.routed", s.alice.user_id.clone()),
            ("authz.deny", s.alice.user_id.clone()),
            ("session.start", s.alice.user_id.clone()),
            ("session.end", s.alice.user_id.clone()),
            ("session.end_rejected", format!("node:{other_node}")),
        ]
    );
    let sessions: Vec<Option<&str>> = events.iter().map(|e| e.session_id()).collect();
    assert_eq!(
        sessions,
        [
            None,
            Some(session_id.as_str()),
            Some(session_id.as_str()),
            Some(session_id.as_str()),
            Some(session_id.as_str()),
            Some(session_id.as_str())
        ]
    );
    let nodes: Vec<Option<&str>> = events.iter().map(|e| e.node()).collect();
    assert_eq!(nodes[0], Some(s.node_id.as_str()));
    assert_eq!(nodes[2], Some(other_node.as_str()));
    assert_eq!(nodes[3], Some(s.node_id.as_str()));
    for event in &events[..4] {
        assert_eq!(event.policy_hash(), Some(s.policy_hash.as_str()));
    }
    assert_eq!(events[0].text("phase"), Some("route"));
    assert_eq!(events[0].text("reason"), Some("policy_denied"));
    assert_eq!(events[2].text("phase"), Some("authorize"));
    assert_eq!(events[2].text("reason"), Some("wrong_node"));
    assert_eq!(events[3].text("login"), Some(LOGIN));
    assert_eq!(events[3].flag("pty"), Some(true));
    assert_eq!(events[3].text("roles"), Some("ops"));
    assert_eq!(events[4].int("bytes_out"), Some(20));
    assert_eq!(events[5].text("reason"), Some("wrong_node"));
    assert_eq!(events[1].actor(), &Actor::User(s.alice.user_id.clone()));
    let lines = lines(&events);
    assert!(!lines.contains(&s.alice.key_id), "{lines}");
    assert!(!lines.contains("ssh-ed25519"), "{lines}");
}

#[tokio::test]
async fn replacing_a_node_on_approval_attributes_the_removal_to_the_approver() {
    let harness = Harness::new().await;
    let first = harness.enroll("web-01").await;
    let old = harness.approve(&first).await;
    let agent = new_agent();
    let mut body = agent.enroll_body("web-01");
    body["replace"] = json!(true);
    let requested = harness.enroll_body(&body).await.json();
    let code = requested["code"].as_str().unwrap().to_owned();
    let capture = ScopedCapture::start();

    let new = harness
        .admin
        .approve(&code, "cli:replacer", None)
        .await
        .unwrap();
    let snapshot = capture.snapshot();
    let events = capture.finish().await;

    assert_eq!(
        sequence(&events),
        [
            ("node.enroll.approved", "cli:replacer".to_owned()),
            ("node.removed", "cli:replacer".to_owned()),
        ]
    );
    assert_eq!(events[0].node(), Some(new.node.id.as_str()));
    assert_eq!(events[1].node(), Some(old.node.id.as_str()));
    assert_eq!(events[1].text("reason"), Some("replaced"));
    assert_eq!(snapshot.fields_dropped, 0);
}
