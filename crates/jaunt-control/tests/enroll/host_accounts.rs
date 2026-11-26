use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use jaunt_control::{AgentPresence, AuthenticatedNode};
use jaunt_proto::AuthorizeDecision;
use serde_json::{Value, json};

use crate::audit::{Captured, start_recording, take_recording};
use crate::session_support::{LOGIN, NODE_NAME, Scenario, authorize, node, routed, scenario};
use crate::support::{APPROVER, Reply, request, send};
use crate::web_support::{admin, get, web_harness};

const ACCOUNT: &str = "/v1/agent/session/account";
const CAPABILITIES: &str = "/v1/agent/capabilities";
const REFERENCE: &str = "H-9D0311FE";

fn report(session_id: &str, login: &str, event: &str) -> Value {
    let mut body = json!({"session_id": session_id, "login": login, "event": event,
                          "ref": REFERENCE});
    match event {
        "created" => {
            body["uid"] = json!(30_000);
            body["home"] = json!("/home/deploy");
            body["groups"] = json!(["deploy", "staff"]);
        }
        "refused" => body["reason"] = json!("max_users"),
        "failed" => {
            body["stage"] = json!("useradd");
            body["exit_code"] = json!(12);
        }
        _ => {}
    }
    body
}

fn host_user_events(recorded: Vec<Captured>) -> Vec<Captured> {
    recorded
        .into_iter()
        .filter(|event| {
            event["target"] == "jaunt::audit"
                && event
                    .get("event")
                    .is_some_and(|name| name.starts_with("host_user."))
        })
        .collect()
}

impl Scenario {
    async fn active_session(&self) -> String {
        let session_id = routed(&self.harness, &self.alice).await;
        let decision = authorize(
            &self.harness,
            &self.node_id,
            self.alice.authorize(&session_id, LOGIN),
        )
        .await;
        assert!(matches!(decision, AuthorizeDecision::Allow { .. }));
        session_id
    }

    async fn report_as(&self, node_id: Option<&str>, body: &Value) -> Reply {
        send(
            self.harness.agent_router.clone(),
            request(ACCOUNT, body, None, node_id),
        )
        .await
    }
}

#[tokio::test]
async fn only_the_node_of_an_active_session_reports_on_its_login_in_order_and_refusals_write_nothing()
 {
    let s = scenario().await;
    let other_node = node(&s.harness, "web-02").await;
    let session_id = s.active_session().await;
    let only_routed = routed(&s.harness, &s.alice).await;
    start_recording();

    for (caller, body) in [
        (other_node.as_str(), report(&session_id, LOGIN, "creating")),
        (s.node_id.as_str(), report(&only_routed, LOGIN, "creating")),
        (
            s.node_id.as_str(),
            report("5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11", LOGIN, "creating"),
        ),
        (s.node_id.as_str(), report(&session_id, "root", "creating")),
    ] {
        let reply = s.report_as(Some(caller), &body).await;
        assert_eq!(reply.status, StatusCode::CONFLICT, "{body}");
        assert_eq!(reply.error_code(), "account_report_refused");
    }
    let creating = s
        .report_as(Some(&s.node_id), &report(&session_id, LOGIN, "creating"))
        .await;
    assert_eq!(creating.status, StatusCode::NO_CONTENT);
    let again = s
        .report_as(Some(&s.node_id), &report(&session_id, LOGIN, "creating"))
        .await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    let created = s
        .report_as(Some(&s.node_id), &report(&session_id, LOGIN, "created"))
        .await;
    assert_eq!(created.status, StatusCode::NO_CONTENT);
    for event in ["created", "refused", "missing"] {
        let late = s
            .report_as(Some(&s.node_id), &report(&session_id, LOGIN, event))
            .await;
        assert_eq!(late.status, StatusCode::CONFLICT, "{event}");
    }

    let events = host_user_events(take_recording());
    assert_eq!(events.len(), 1, "{events:#?}");
    let created = &events[0];
    for (field, value) in [
        ("event", "host_user.created"),
        ("user_id", s.alice.user_id.as_str()),
        ("node_id", s.node_id.as_str()),
        ("session_id", session_id.as_str()),
        ("login", LOGIN),
        ("uid", "30000"),
        ("home", "/home/deploy"),
        ("groups", "deploy,staff"),
        ("ref", REFERENCE),
    ] {
        assert_eq!(created[field], value, "{field}");
    }
}

#[tokio::test]
async fn refusals_and_helper_failures_are_audited_with_the_checked_fields_only() {
    let s = scenario().await;
    let refused_session = s.active_session().await;
    let failed_session = s.active_session().await;
    let missing_session = s.active_session().await;
    start_recording();

    for (session_id, event) in [
        (&refused_session, "refused"),
        (&failed_session, "failed"),
        (&missing_session, "missing"),
    ] {
        let reply = s
            .report_as(Some(&s.node_id), &report(session_id, LOGIN, event))
            .await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT, "{event}");
    }

    let events = host_user_events(take_recording());
    assert_eq!(events.len(), 2, "{events:#?}");
    let (refused, failed) = (&events[0], &events[1]);
    assert_eq!(refused["event"], "host_user.refused");
    assert_eq!(refused["session_id"], refused_session);
    assert_eq!(refused["user_id"], s.alice.user_id);
    assert_eq!(
        (&refused["reason"], &refused["ref"], &refused["suppressed"]),
        (
            &"max_users".to_owned(),
            &REFERENCE.to_owned(),
            &"0".to_owned()
        )
    );
    assert_eq!(failed["event"], "host_user.helper_failed");
    assert_eq!(failed["session_id"], failed_session);
    assert_eq!(
        (&failed["stage"], &failed["exit_status"], &failed["ref"]),
        (
            &"useradd".to_owned(),
            &"12".to_owned(),
            &REFERENCE.to_owned()
        )
    );
}

#[tokio::test]
async fn a_report_needs_a_node_identity_a_consistent_body_and_must_come_soon_after_authorization() {
    let s = scenario().await;
    let session_id = s.active_session().await;
    let unauthenticated = s
        .report_as(None, &report(&session_id, LOGIN, "creating"))
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);
    let mut inconsistent = report(&session_id, LOGIN, "creating");
    inconsistent["uid"] = json!(1);
    let reply = s.report_as(Some(&s.node_id), &inconsistent).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let mut actor = report(&session_id, LOGIN, "creating");
    actor["user_id"] = json!("someone-else");
    let reply = s.report_as(Some(&s.node_id), &actor).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    s.harness.clock.advance(51);
    let late = s
        .report_as(Some(&s.node_id), &report(&session_id, LOGIN, "creating"))
        .await;
    assert_eq!(late.status, StatusCode::CONFLICT);
}

struct Switchable(Mutex<Option<SystemTime>>);

impl AgentPresence for Switchable {
    fn connected_since(&self, _node_id: &str) -> Option<SystemTime> {
        *self.0.lock().unwrap()
    }
}

fn announce(node_id: &str, creates_accounts: bool) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(CAPABILITIES)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"creates_accounts": creates_accounts}).to_string(),
        ))
        .unwrap();
    request
        .extensions_mut()
        .insert(AuthenticatedNode(node_id.to_owned()));
    request
}

#[tokio::test]
async fn the_creates_accounts_flag_lives_only_as_long_as_the_connection_it_was_announced_on() {
    let harness = web_harness(&[]).await;
    let alice = admin(&harness, "approver").await;
    let node_id = node(&harness, NODE_NAME).await;
    let presence = Arc::new(Switchable(Mutex::new(Some(
        SystemTime::now() - Duration::from_secs(3600),
    ))));
    harness.control.install_agent_presence(presence.clone());
    let flag = || async {
        let reply = get(&harness, "/v1/admin/nodes", &alice).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        reply.json()["nodes"][0]["creates_accounts"].clone()
    };
    assert_eq!(flag().await, false);

    let announced = send(harness.agent_router.clone(), announce(&node_id, true)).await;
    assert_eq!(announced.status, StatusCode::NO_CONTENT);
    assert_eq!(flag().await, true);
    let withdrawn = send(harness.agent_router.clone(), announce(&node_id, false)).await;
    assert_eq!(withdrawn.status, StatusCode::NO_CONTENT);
    assert_eq!(flag().await, false);

    send(harness.agent_router.clone(), announce(&node_id, true)).await;
    *presence.0.lock().unwrap() = None;
    assert_eq!(flag().await, false);
    *presence.0.lock().unwrap() = Some(SystemTime::now() + Duration::from_secs(3600));
    assert_eq!(flag().await, false);

    let mut unsigned = announce(&node_id, true);
    unsigned.extensions_mut().remove::<AuthenticatedNode>();
    let reply = send(harness.agent_router.clone(), unsigned).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_malformed_report_gets_the_same_answer_for_an_own_a_foreign_and_an_unknown_session() {
    let s = scenario().await;
    let other_node = node(&s.harness, "web-02").await;
    let session_id = s.active_session().await;
    let mut replies = Vec::new();
    for (caller, session_id) in [
        (s.node_id.clone(), session_id.clone()),
        (other_node, session_id),
        (
            s.node_id.clone(),
            "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11".to_owned(),
        ),
    ] {
        let mut body = report(&session_id, LOGIN, "creating");
        body["uid"] = json!(1);
        let reply = s.report_as(Some(&caller), &body).await;
        replies.push((reply.status, reply.text()));
    }
    assert_eq!(replies[0].0, StatusCode::BAD_REQUEST);
    assert!(
        replies.iter().all(|reply| *reply == replies[0]),
        "{replies:?}"
    );
}

#[tokio::test]
async fn a_removed_node_can_neither_announce_nor_report() {
    let s = scenario().await;
    let session_id = s.active_session().await;
    s.harness
        .admin
        .remove_node(NODE_NAME, APPROVER)
        .await
        .unwrap();

    let announced = send(s.harness.agent_router.clone(), announce(&s.node_id, true)).await;
    let reported = s
        .report_as(Some(&s.node_id), &report(&session_id, LOGIN, "creating"))
        .await;
    for reply in [announced, reported] {
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(reply.error_code(), "node_removed");
    }
}
