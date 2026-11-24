use std::sync::Arc;

use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlPlane, NodeCaller, RouteDecision, RouteRequest,
    SessionEnd, SessionEndOutcome,
};
use jaunt_store::{NewCertificate, NewUser, Session};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

use crate::audit::Captured;

use crate::support::Harness;

pub const LOGIN: &str = "deploy";
pub const CLIENT: &str = "203.0.113.7:50000";
pub const NODE_NAME: &str = "web-01";
pub const ROUTED_TTL_SECS: u64 = 60;

#[derive(Clone)]
pub struct Holder {
    pub user_id: String,
    pub serial: u64,
    pub key_id: String,
}

impl Holder {
    pub fn route_to(&self, node_name: &str) -> RouteRequest {
        RouteRequest {
            user_id: self.user_id.clone(),
            serial: self.serial,
            key_id: self.key_id.clone(),
            node_name: node_name.to_owned(),
            client_addr: CLIENT.to_owned(),
        }
    }

    pub fn authorize(&self, session_id: &str, login: &str, term: bool) -> AuthorizeRequest {
        AuthorizeRequest {
            session_id: session_id.to_owned(),
            user_id: self.user_id.clone(),
            serial: self.serial,
            key_id: self.key_id.clone(),
            login: login.to_owned(),
            term,
            client_addr: CLIENT.to_owned(),
        }
    }
}

pub async fn raw_pool(harness: &Harness) -> SqlitePool {
    SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(&harness.db_path)
            .foreign_keys(false),
    )
    .await
    .unwrap()
}

pub fn audit_events(recorded: Vec<Captured>) -> Vec<Captured> {
    recorded
        .into_iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect()
}

pub fn role(name: &str, group: &str, port_forwarding: bool, record_input: bool) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  \
         members: {{ groups: [{group}] }}\n  ssh:\n    nodes: {{ env: [prod] }}\n    \
         logins: [{LOGIN}]\n    portForwarding: {port_forwarding}\n    \
         recordInput: {record_input}\n"
    )
}

pub fn apply_policy(harness: &Harness, roles: &[String]) -> String {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("roles.yaml"), roles.join("---\n")).unwrap();
    let outcome = harness.control.policy().reload(dir.path());
    assert!(outcome.applied, "{:?}", outcome.errors);
    outcome.hash.unwrap()
}

pub async fn user(harness: &Harness, subject: &str, groups: &[&str]) -> String {
    harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: subject.to_owned(),
                email: format!("{subject}@example.com"),
                username: subject.to_owned(),
                display_name: None,
                groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap()
        .id
}

pub async fn certificate(
    harness: &Harness,
    user_id: &str,
    valid_after: i64,
    valid_before: i64,
) -> Holder {
    let certificates = harness.store.certificates();
    let serial = certificates.allocate_serial().await.unwrap();
    let key_id = format!("jaunt:{user_id}@example.com:{serial}");
    certificates
        .record(&NewCertificate {
            serial,
            user_id: user_id.to_owned(),
            kind: "user".to_owned(),
            key_id: key_id.clone(),
            valid_after,
            valid_before,
            issued_at: harness.clock.now_secs(),
        })
        .await
        .unwrap();
    Holder {
        user_id: user_id.to_owned(),
        serial: u64::try_from(serial).unwrap(),
        key_id,
    }
}

pub async fn holder(harness: &Harness, subject: &str, groups: &[&str]) -> Holder {
    let user_id = user(harness, subject, groups).await;
    let now = harness.clock.now_secs();
    certificate(harness, &user_id, now - 120, now + 8 * 3600).await
}

pub fn plane(harness: &Harness) -> Arc<dyn ControlPlane> {
    Arc::new(harness.control.clone())
}

pub async fn route(harness: &Harness, request: RouteRequest) -> RouteDecision {
    plane(harness).route(request).await.unwrap()
}

pub async fn routed(harness: &Harness, holder: &Holder) -> String {
    match route(harness, holder.route_to(NODE_NAME)).await {
        RouteDecision::Allow { session_id, .. } => session_id,
        other => panic!("the route was denied: {other:?}"),
    }
}

pub async fn authorize(
    harness: &Harness,
    node_id: &str,
    request: AuthorizeRequest,
) -> AuthorizeDecision {
    plane(harness)
        .authorize(NodeCaller(node_id.to_owned()), request)
        .await
        .unwrap()
}

pub async fn end(harness: &Harness, node_id: &str, request: SessionEnd) -> SessionEndOutcome {
    plane(harness)
        .session_end(NodeCaller(node_id.to_owned()), request)
        .await
        .unwrap()
}

pub fn end_request(session_id: &str, bytes_out: u64) -> SessionEnd {
    SessionEnd {
        session_id: session_id.to_owned(),
        exit_status: Some(0),
        bytes_in: 42,
        bytes_out,
        recording_incomplete: false,
    }
}

pub async fn stored(harness: &Harness, session_id: &str) -> Option<Session> {
    harness.store.sessions().get(session_id).await.unwrap()
}

pub async fn node(harness: &Harness, name: &str) -> String {
    let (_, delivered) = harness.enrolled_node(name).await;
    delivered["node_id"].as_str().unwrap().to_owned()
}

pub struct Scenario {
    pub harness: Harness,
    pub alice: Holder,
    pub node_id: String,
    pub policy_hash: String,
}

pub async fn scenario() -> Scenario {
    let harness = Harness::new().await;
    let node_id = node(&harness, NODE_NAME).await;
    let policy_hash = apply_policy(&harness, &[role("ops", "ops", false, false)]);
    let alice = holder(&harness, "alice", &["ops"]).await;
    Scenario {
        harness,
        alice,
        node_id,
        policy_hash,
    }
}
