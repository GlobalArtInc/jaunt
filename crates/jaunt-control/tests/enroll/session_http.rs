use axum::http::StatusCode;
use jaunt_store::SessionState;
use serde_json::{Value, json};

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    CLIENT, Holder, LOGIN, NODE_NAME, Scenario, audit_events, holder, node, routed, scenario,
    stored,
};
use crate::support::{Harness, Reply, request, request_raw, send};

const AUTHORIZE: &str = "/v1/agent/authorize";
const END: &str = "/v1/agent/session/end";
const UNKNOWN_SESSION: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

fn authorize_body(holder: &Holder, session_id: &str) -> Value {
    json!({
        "session_id": session_id,
        "user_id": holder.user_id,
        "serial": holder.serial,
        "key_id": holder.key_id,
        "login": LOGIN,
        "term": true,
        "client_addr": CLIENT,
    })
}

fn end_body(session_id: &str) -> Value {
    json!({
        "session_id": session_id,
        "exit_status": 3,
        "bytes_in": 10,
        "bytes_out": 20,
        "recording_incomplete": true,
    })
}

async fn agent_call(harness: &Harness, path: &str, node_id: Option<&str>, body: &Value) -> Reply {
    send(
        harness.agent_router.clone(),
        request(path, body, None, node_id),
    )
    .await
}

impl Scenario {
    async fn authorize_over_http(&self, node_id: &str, session_id: &str) -> Reply {
        agent_call(
            &self.harness,
            AUTHORIZE,
            Some(node_id),
            &authorize_body(&self.alice, session_id),
        )
        .await
    }
}

#[tokio::test]
async fn the_agent_routes_answer_allow_and_deny_without_a_reason() {
    let s = scenario().await;
    let session_id = routed(&s.harness, &s.alice).await;

    let allowed = s.authorize_over_http(&s.node_id, &session_id).await;
    assert_eq!(allowed.status, StatusCode::OK);
    assert_eq!(
        allowed.json(),
        json!({"decision": "allow", "permissions": {
            "pty": true, "port_forwarding": false, "record_input": false,
            "max_duration_secs": 43_200,
        }})
    );
    let replayed = s.authorize_over_http(&s.node_id, &session_id).await;
    assert_eq!(replayed.status, StatusCode::OK);
    assert_eq!(replayed.json(), json!({"decision": "deny"}));

    let ended = agent_call(&s.harness, END, Some(&s.node_id), &end_body(&session_id)).await;
    assert_eq!(ended.status, StatusCode::OK);
    assert_eq!(ended.json(), json!({"outcome": "recorded"}));
}

#[tokio::test]
async fn an_agent_cannot_tell_another_nodes_session_from_an_unknown_one() {
    let s = scenario().await;
    let harness = &s.harness;
    let other_node = node(harness, "web-02").await;
    let foreign = routed(harness, &s.alice).await;
    start_recording();

    let probe = s.authorize_over_http(&other_node, &foreign).await;
    let unknown = s.authorize_over_http(&other_node, UNKNOWN_SESSION).await;
    assert_eq!(probe.status, unknown.status);
    assert_eq!(probe.body, unknown.body);
    assert_eq!(probe.json(), json!({"decision": "deny"}));

    let reasons: Vec<String> = take_recording()
        .into_iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("authz.deny"))
        .map(|event| event["reason"].clone())
        .collect();
    assert_eq!(reasons, ["wrong_node", "session_unknown"]);
    assert_eq!(
        stored(harness, &foreign).await.unwrap().state,
        SessionState::Routed
    );

    let owner = s.authorize_over_http(&s.node_id, &foreign).await;
    assert_eq!(owner.json()["decision"], "allow");
    let end_probe = agent_call(harness, END, Some(&other_node), &end_body(&foreign)).await;
    let end_unknown = agent_call(harness, END, Some(&other_node), &end_body(UNKNOWN_SESSION)).await;
    assert_eq!(end_probe.status, end_unknown.status);
    assert_eq!(end_probe.body, end_unknown.body);
    assert_eq!(end_probe.json(), json!({"outcome": "rejected"}));
}

#[tokio::test]
async fn the_agent_routes_reject_unauthenticated_overlong_and_node_naming_bodies() {
    let s = scenario().await;
    let harness = &s.harness;
    let session_id = routed(harness, &s.alice).await;
    let bodies = [
        (AUTHORIZE, authorize_body(&s.alice, &session_id)),
        (END, end_body(&session_id)),
    ];
    for (path, body) in bodies {
        let anonymous = agent_call(harness, path, None, &body).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{path}");

        let mut naming = body.clone();
        naming["node_id"] = json!(s.node_id);
        let rejected = agent_call(harness, path, Some(&s.node_id), &naming).await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(rejected.error_code(), "invalid_request");

        let oversized = send(
            harness.agent_router.clone(),
            request_raw(
                path,
                "application/json",
                vec![b' '; 16 * 1024 + 1],
                None,
                Some(&s.node_id),
            ),
        )
        .await;
        assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");

        let public = send(
            harness.router.clone(),
            request(path, &body, Some("203.0.113.10"), Some(&s.node_id)),
        )
        .await;
        assert_eq!(public.status, StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(
        stored(harness, &session_id).await.unwrap().state,
        SessionState::Routed
    );
}

#[tokio::test]
async fn the_session_lifecycle_emits_stable_audit_events_without_credentials() {
    let s = scenario().await;
    let harness = &s.harness;
    let other_node = node(harness, "web-02").await;
    let bob = holder(harness, "bob", &["dev"]).await;
    start_recording();

    crate::session_support::route(harness, bob.route_to(NODE_NAME)).await;
    let session_id = routed(harness, &s.alice).await;
    s.authorize_over_http(&other_node, &session_id).await;
    s.authorize_over_http(&s.node_id, &session_id).await;
    agent_call(harness, END, Some(&s.node_id), &end_body(&session_id)).await;
    agent_call(harness, END, Some(&other_node), &end_body(&session_id)).await;

    let events = audit_events(take_recording());
    let names: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
    assert_eq!(
        names,
        [
            "authz.deny",
            "session.routed",
            "authz.deny",
            "session.start",
            "session.end",
            "session.end.rejected"
        ]
    );
    let field = |index: usize, name: &str| events[index].get(name).cloned();
    let some = |value: &str| Some(value.to_owned());

    assert_eq!(field(0, "phase"), some("route"));
    assert_eq!(field(0, "reason"), some("policy_denied"));
    assert_eq!(field(0, "user_id"), Some(bob.user_id.clone()));
    assert_eq!(field(0, "node_id"), Some(s.node_id.clone()));
    assert_eq!(field(0, "session_id"), None);

    assert_eq!(field(1, "session_id"), Some(session_id.clone()));
    assert_eq!(field(1, "node_id"), Some(s.node_id.clone()));
    assert_eq!(field(1, "client_addr"), some(CLIENT));

    assert_eq!(field(2, "phase"), some("authorize"));
    assert_eq!(field(2, "reason"), some("wrong_node"));
    assert_eq!(field(2, "node_id"), Some(other_node.clone()));
    assert_eq!(field(2, "session_id"), Some(session_id.clone()));

    assert_eq!(field(3, "login"), some(LOGIN));
    assert_eq!(field(3, "term"), some("true"));
    assert_eq!(field(3, "pty"), some("true"));
    assert_eq!(field(3, "port_forwarding"), some("false"));
    assert_eq!(field(3, "record_input"), some("false"));
    assert_eq!(field(3, "max_duration_secs"), some("43200"));
    assert_eq!(field(3, "roles"), some("ops"));

    assert_eq!(field(4, "exit_status"), some("3"));
    assert_eq!(field(4, "bytes_in"), some("10"));
    assert_eq!(field(4, "bytes_out"), some("20"));
    assert_eq!(field(4, "recording_incomplete"), some("true"));
    assert_eq!(field(4, "login"), some(LOGIN));

    assert_eq!(field(5, "node_id"), Some(other_node.clone()));
    assert_eq!(field(5, "session_id"), Some(session_id.clone()));
    assert_eq!(field(5, "reason"), some("wrong_node"));

    for event in &events[..4] {
        assert_eq!(event.get("policy_hash"), Some(&s.policy_hash), "{event:?}");
    }
    for event in &events {
        for value in event.values() {
            assert!(!value.contains(&s.alice.key_id), "{event:?}");
            assert!(!value.contains(&bob.key_id), "{event:?}");
            assert!(!value.contains("ssh-ed25519"), "{event:?}");
        }
    }
}
