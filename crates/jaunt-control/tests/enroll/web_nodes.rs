use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use jaunt_control::{
    AgentPresence, KillOrder, KillReason, KillScope, RevokeRequest, SessionKiller,
};
use jaunt_proto::BoxFuture;
use jaunt_store::{RevocationKind, SessionEndReason, SessionState};
use serde_json::{Value, json};

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    LOGIN, NODE_NAME, apply_policy, authorize, holder, node, role, routed, stored,
};
use crate::support::{APPROVER, Harness};
use crate::web_support::{ADMIN_ROLES, admin, delete, get, web_harness};

#[derive(Default)]
struct RecordingKiller(Mutex<Vec<KillOrder>>);

impl SessionKiller for RecordingKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(order.clone());
        Box::pin(async {})
    }
}

struct OnlyConnected {
    node_id: String,
    since: SystemTime,
}

impl AgentPresence for OnlyConnected {
    fn connected_since(&self, node_id: &str) -> Option<SystemTime> {
        (node_id == self.node_id).then_some(self.since)
    }
}

fn names(body: &Value) -> Vec<String> {
    body["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["name"].as_str().unwrap().to_owned())
        .collect()
}

async fn list(harness: &Harness, alice: &crate::web_support::Admin, query: &str) -> Value {
    let reply = get(harness, &format!("/v1/admin/nodes{query}"), alice).await;
    assert_eq!(reply.status, StatusCode::OK, "{query}: {}", reply.text());
    reply.json()
}

#[tokio::test]
async fn the_node_list_filters_pages_and_reports_presence_revocation_and_certificates() {
    let harness = web_harness(&[]).await;
    let alice = admin(&harness, "approver").await;
    let web = node(&harness, "web-01").await;
    let db = node(&harness, "db-01").await;
    let gone = node(&harness, "web-02").await;
    harness.enroll("web-03").await;
    let since = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    harness
        .control
        .install_agent_presence(Arc::new(OnlyConnected {
            node_id: web.clone(),
            since,
        }));
    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::Node,
                subject: gone.clone(),
                reason: "stolen".to_owned(),
            },
            APPROVER,
        )
        .await
        .unwrap();

    let all = list(&harness, &alice, "").await;
    assert_eq!(names(&all), ["db-01", "web-01", "web-02"]);
    assert_eq!(all["pending_enrolments"], 1);
    assert_eq!(all["next"], Value::Null);
    let by_id = |id: &str| {
        all["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["id"] == id)
            .unwrap()
            .clone()
    };
    let online = by_id(&web);
    assert_eq!(
        (&online["connected"], &online["connected_since"]),
        (&json!(true), &json!(1_700_000_000))
    );
    assert_eq!(online["state"], "active");
    assert_eq!(online["revoked"], false);
    assert_eq!(online["agent_version"], "0.1.0");
    assert_eq!(online["certificates"]["state"], "delivered");
    assert!(online["certificates"]["x509_expires_at"].as_i64().unwrap() > harness.clock.now_secs());
    assert!(online["certificates"]["ssh_host_expires_at"].is_i64());
    assert_eq!(by_id(&db)["connected"], false);
    let revoked = by_id(&gone);
    assert_eq!(
        (
            &revoked["state"],
            &revoked["revoked"],
            &revoked["connected"]
        ),
        (&json!("removed"), &json!(true), &json!(false))
    );

    let first = list(&harness, &alice, "?limit=1").await;
    assert_eq!(names(&first), ["db-01"]);
    node(&harness, "aaa-01").await;
    let cursor = first["next"].as_str().unwrap().to_owned();
    let second = list(&harness, &alice, &format!("?limit=2&cursor={cursor}")).await;
    assert_eq!(names(&second), ["web-01", "web-02"]);
    assert_eq!(second["next"], Value::Null);

    for (query, expected) in [
        ("?state=active&q=web", vec!["web-01"]),
        ("?state=removed", vec!["web-02"]),
        ("?label=env:prod&q=db", vec!["db-01"]),
        ("?label=env:dev", vec![]),
    ] {
        assert_eq!(
            names(&list(&harness, &alice, query).await),
            expected,
            "{query}"
        );
    }
    for (query, status, code) in [
        (
            "?state=pending",
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_state",
        ),
        (
            "?limit=500",
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_limit",
        ),
        ("?cursor=broken", StatusCode::BAD_REQUEST, "invalid_request"),
    ] {
        let reply = get(&harness, &format!("/v1/admin/nodes{query}"), &alice).await;
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (status, code),
            "{query}"
        );
    }
}

#[tokio::test]
async fn a_node_detail_adds_its_keys_and_session_counts() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let alice = admin(&harness, "approver").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;

    let reply = get(&harness, &format!("/v1/admin/nodes/{node_id}"), &alice).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    let stored_node = harness.store.nodes().get(&node_id).await.unwrap().unwrap();
    assert_eq!(body["name"], NODE_NAME);
    assert_eq!(body["tls_spki_sha256"], stored_node.tls_spki_sha256);
    assert_eq!(
        body["ssh_host_key_fingerprint"],
        stored_node.ssh_host_key_fingerprint
    );
    assert_eq!(body["sessions"], json!({"open": 1, "last_24h": 1}));
    for missing in ["/v1/admin/nodes/unknown-id", "/v1/admin/nodes/bad%2Fid"] {
        assert_eq!(
            get(&harness, missing, &alice).await.status,
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn removal_needs_the_exact_name_and_closes_the_node_sessions_at_once() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let alice = admin(&harness, "approver").await;
    let node_id = node(&harness, NODE_NAME).await;
    let bob = holder(&harness, "bob", &["ops"]).await;
    let session_id = routed(&harness, &bob).await;
    authorize(&harness, &node_id, bob.authorize(&session_id, LOGIN)).await;
    let path = format!("/v1/admin/nodes/{node_id}");
    start_recording();

    for wrong in ["WEB-01", "web-01 ", ""] {
        let refused = delete(&harness, &path, &alice, &json!({"confirm_name": wrong})).await;
        assert_eq!(
            (refused.status, refused.error_code().as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, "confirm_name_mismatch"),
            "{wrong:?}"
        );
    }
    assert_eq!(
        stored(&harness, &session_id).await.unwrap().state,
        SessionState::Active
    );

    let removed = delete(&harness, &path, &alice, &json!({"confirm_name": NODE_NAME})).await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text());
    assert_eq!(removed.json()["state"], "removed");
    assert_eq!(removed.json()["sessions_closed"], 1);
    let closed = stored(&harness, &session_id).await.unwrap();
    assert_eq!(
        (closed.state, closed.end_reason),
        (SessionState::Ended, Some(SessionEndReason::NodeRemoved))
    );
    let orders = killer.0.lock().unwrap().clone();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        (orders[0].scope.clone(), orders[0].reason),
        (
            KillScope::Node {
                node_id: node_id.clone()
            },
            KillReason::NodeRemoved
        )
    );
    assert_eq!(orders[0].sessions[0].session_id, session_id);

    let again = delete(&harness, &path, &alice, &json!({"confirm_name": NODE_NAME})).await;
    assert_eq!(
        (again.status, again.error_code().as_str()),
        (StatusCode::CONFLICT, "node_not_active")
    );
    let unknown = delete(
        &harness,
        "/v1/admin/nodes/no-such-node",
        &alice,
        &json!({"confirm_name": NODE_NAME}),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    let events = take_recording();
    let removals: Vec<_> = events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("node.removed"))
        .collect();
    assert_eq!(removals.len(), 1);
    assert_eq!(removals[0]["removed_by"], alice.actor());
    assert_eq!(removals[0]["reason"], "admin");
}

#[tokio::test]
async fn the_cli_and_the_api_remove_with_the_same_effect_and_event() {
    let harness = web_harness(&[]).await;
    let alice = admin(&harness, "approver").await;
    let by_cli = node(&harness, "web-01").await;
    let by_api = node(&harness, "web-02").await;
    start_recording();

    harness.admin.remove_node("web-01", APPROVER).await.unwrap();
    let reply = delete(
        &harness,
        &format!("/v1/admin/nodes/{by_api}"),
        &alice,
        &json!({"confirm_name": "web-02"}),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    for id in [&by_cli, &by_api] {
        let stored = harness.store.nodes().get(id).await.unwrap().unwrap();
        assert_eq!(stored.state, jaunt_store::NodeState::Removed);
    }
    let events = take_recording();
    let removals: Vec<_> = events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("node.removed"))
        .collect();
    assert_eq!(removals.len(), 2);
    assert_eq!(
        (
            removals[0]["removed_by"].as_str(),
            removals[0]["reason"].as_str()
        ),
        (APPROVER, "admin")
    );
    assert_eq!(
        (
            removals[1]["removed_by"].clone(),
            removals[1]["reason"].as_str()
        ),
        (alice.actor(), "admin")
    );
    assert_eq!(
        removals[0].keys().collect::<Vec<_>>(),
        removals[1].keys().collect::<Vec<_>>()
    );
}

fn access_roles(body: &Value) -> Vec<String> {
    body["roles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|role| role["role"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn who_can_reach_a_node_follows_the_current_policy() {
    let ops_group = role("ops", "ops", true, false);
    let named = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: named }\nspec:\n  \
                 members: { users: [carol@example.com] }\n  ssh:\n    nodes: { env: [prod] }\n    \
                 logins: [\"{username}\"]\n    recordInput: true\n  admin: [sessions.read]\n"
        .to_owned();
    let elsewhere = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: dev }\nspec:\n  \
                     members: { groups: [dev] }\n  ssh: { nodes: { env: [dev] }, logins: [dev] }\n"
        .to_owned();
    let harness = web_harness(&[ops_group.clone(), named.clone(), elsewhere.clone()]).await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;
    let path = format!("/v1/admin/nodes/{node_id}/access");

    let reply = get(&harness, &path, &reader).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    assert_eq!(access_roles(&body), ["named", "ops"]);
    assert_eq!(body["node_name"], NODE_NAME);
    assert_eq!(
        body["policy_hash"],
        harness.control.policy().snapshot().hash()
    );
    assert!(body["policy_loaded_at"].is_i64());
    assert_eq!(
        body["roles"][0],
        json!({
            "role": "named",
            "users": ["carol@example.com"],
            "groups": [],
            "logins": ["{username}"],
            "port_forwarding": false,
            "record_input": true,
            "admin": ["sessions.read"],
        })
    );
    assert_eq!(body["roles"][1]["groups"], json!(["ops"]));
    assert_eq!(body["roles"][1]["port_forwarding"], true);

    let hash = apply_policy(&harness, &[ADMIN_ROLES.to_owned(), elsewhere]);
    let after = get(&harness, &path, &reader).await.json();
    assert!(access_roles(&after).is_empty());
    assert_eq!(after["policy_hash"], hash);
    assert_eq!(
        get(&harness, "/v1/admin/nodes/none/access", &reader)
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_agent_version_outlives_the_enrolment_row_and_a_removed_node_has_no_access_answer() {
    let harness = web_harness(&[role("ops", "ops", false, false)]).await;
    let alice = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, NODE_NAME).await;

    harness.clock.advance(4 * 3600);
    assert!(harness.control.purge_stored_enrollments().await.unwrap() >= 1);
    assert!(
        harness
            .store
            .enrollments()
            .agent_versions(std::slice::from_ref(&node_id))
            .await
            .unwrap()
            .is_empty()
    );
    let detail = get(&harness, &format!("/v1/admin/nodes/{node_id}"), &alice).await;
    assert_eq!(detail.json()["agent_version"], "0.1.0");
    let listed = list(&harness, &alice, "").await;
    assert_eq!(listed["nodes"][0]["agent_version"], "0.1.0");

    let access = format!("/v1/admin/nodes/{node_id}/access");
    assert_eq!(get(&harness, &access, &reader).await.status, StatusCode::OK);
    harness
        .admin
        .remove_node(NODE_NAME, APPROVER)
        .await
        .unwrap();
    let removed = get(&harness, &access, &reader).await;
    assert_eq!(
        (removed.status, removed.error_code().as_str()),
        (StatusCode::NOT_FOUND, "not_found")
    );
}
