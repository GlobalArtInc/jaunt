use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use jaunt_proto::{DenyReason, RouteDecision, ServiceList};
use serde_json::{Value, json};

use crate::audit::{Captured, start_recording, take_recording};
use crate::client_api::bearer;
use crate::session_support::{
    NODE_NAME, apply_policy, audit_events, node, raw_pool, route, scenario,
};
use crate::support::{APPROVER, Harness, Reply, request, request_raw, send};
use crate::web_signed::{issue, signed};
use crate::web_support::{ADMIN_ROLES, Admin, admin, delete, get, post, web_harness};

const ANNOUNCE: &str = "/v1/agent/services";

fn tcp(name: &str, team: &str) -> Value {
    json!({"kind": "tcp", "name": name, "labels": {"team": team}, "address": "10.0.0.5:3000"})
}

fn set(services: &[Value]) -> Value {
    json!({ "services": services })
}

async fn announce(harness: &Harness, node_id: Option<&str>, body: &Value) -> Reply {
    send(
        harness.agent_router.clone(),
        request(ANNOUNCE, body, None, node_id),
    )
    .await
}

async fn announced(harness: &Harness, node_id: &str, body: &Value) {
    let reply = announce(harness, Some(node_id), body).await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text());
}

async fn listed(harness: &Harness, admin: &Admin, query: &str) -> Vec<Value> {
    let reply = get(harness, &format!("/v1/admin/services?{query}"), admin).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()["services"].as_array().unwrap().clone()
}

async fn only_pending(harness: &Harness, admin: &Admin) -> Value {
    let pending = listed(harness, admin, "state=pending").await;
    assert_eq!(pending.len(), 1, "{pending:?}");
    pending[0].clone()
}

async fn approve(harness: &Harness, admin: &Admin, id: &Value, body: &Value) -> Reply {
    post(
        harness,
        &format!("/v1/admin/services/{}/approve", id.as_str().unwrap()),
        admin,
        body,
    )
    .await
}

async fn offered(harness: &Harness, token: &str) -> ServiceList {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/v1/services")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let reply = send(harness.router.clone(), request).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    serde_json::from_slice(&reply.body).unwrap()
}

fn names(list: &ServiceList) -> Vec<String> {
    list.services
        .iter()
        .map(|service| format!("{}/{}", service.kind, service.name))
        .collect()
}

fn service_events(recorded: Vec<Captured>) -> Vec<Captured> {
    audit_events(recorded)
        .into_iter()
        .filter(|event| {
            event
                .get("event")
                .is_some_and(|name| name.starts_with("service.") || name == "node.ssh_changed")
        })
        .collect()
}

fn named<'a>(events: &'a [Captured], name: &str) -> &'a Captured {
    events
        .iter()
        .find(|event| event["event"] == name)
        .unwrap_or_else(|| panic!("no {name} in {events:?}"))
}

#[tokio::test]
async fn an_announcement_needs_the_node_identity_and_touches_only_that_node() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let first = node(&harness, "web-01").await;
    let second = node(&harness, "web-02").await;
    let gone = node(&harness, "web-03").await;
    harness.admin.remove_node("web-03", APPROVER).await.unwrap();

    let anonymous = announce(&harness, None, &set(&[tcp("grafana", "ops")])).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let removed = announce(&harness, Some(&gone), &set(&[tcp("grafana", "ops")])).await;
    assert_eq!(
        (removed.status, removed.error_code().as_str()),
        (StatusCode::FORBIDDEN, "node_removed")
    );
    let mut aimed = set(&[tcp("grafana", "ops")]);
    aimed["node_id"] = json!(second);
    assert_eq!(
        announce(&harness, Some(&first), &aimed).await.status,
        StatusCode::BAD_REQUEST
    );
    assert!(listed(&harness, &approver, "").await.is_empty());

    announced(&harness, &first, &set(&[tcp("grafana", "ops")])).await;
    announced(&harness, &second, &set(&[])).await;
    announced(&harness, &second, &set(&[tcp("grafana", "dev")])).await;

    let all = listed(&harness, &approver, "").await;
    assert_eq!(all.len(), 2);
    let mine = listed(&harness, &approver, &format!("node_id={first}")).await;
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0]["node"]["id"], json!(first));
    assert_eq!(mine[0]["announced"], json!(true));
    assert_eq!(mine[0]["labels"], json!({"team": "ops"}));
    assert_eq!(mine[0]["address_hint"], json!("10.0.0.5:3000"));
}

#[tokio::test]
async fn announcements_are_validated_bounded_and_rate_limited() {
    let harness = web_harness(&[]).await;
    let node_id = node(&harness, "web-01").await;
    let labelled = |labels: Value| {
        let mut service = tcp("grafana", "ops");
        service["labels"] = labels;
        set(&[service])
    };
    let many_labels: serde_json::Map<String, Value> =
        (0..17).map(|n| (format!("k{n}"), json!("v"))).collect();
    let too_many: Vec<Value> = (0..65).map(|n| tcp(&format!("s{n}"), "ops")).collect();
    let mut foreign = tcp("grafana", "ops");
    foreign["kubernetes"] = json!({});
    let mut unknown = tcp("grafana", "ops");
    unknown["port"] = json!(3000);
    let cases: Vec<(Value, StatusCode, &str)> = vec![
        (
            set(&[tcp("Grafana", "ops")]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_service_name",
        ),
        (
            set(&[tcp(&"a".repeat(64), "ops")]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_service_name",
        ),
        (
            labelled(json!({"name": "grafana"})),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_labels",
        ),
        (
            labelled(json!({"Team": "ops"})),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_labels",
        ),
        (
            labelled(Value::Object(many_labels)),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_labels",
        ),
        (
            set(&[tcp("grafana", "ops"), tcp("grafana", "dev")]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "duplicate_service",
        ),
        (
            set(&too_many),
            StatusCode::UNPROCESSABLE_ENTITY,
            "too_many_services",
        ),
        (
            set(&[foreign]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_settings",
        ),
        (set(&[unknown]), StatusCode::BAD_REQUEST, "invalid_request"),
        (
            set(&[json!({"kind": "ssh", "name": "x"})]),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
    ];
    for (body, status, code) in cases {
        harness.clock.advance(60);
        let reply = announce(&harness, Some(&node_id), &body).await;
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (status, code),
            "{body}"
        );
    }
    harness.clock.advance(60);
    let plain = send(
        harness.agent_router.clone(),
        request_raw(
            ANNOUNCE,
            "text/plain",
            br#"{"services":[]}"#.to_vec(),
            None,
            Some(&node_id),
        ),
    )
    .await;
    assert_eq!(plain.status, StatusCode::BAD_REQUEST);
    harness.clock.advance(60);
    let padding = "x".repeat(256 * 1024);
    let oversized = announce(
        &harness,
        Some(&node_id),
        &json!({"services": [], "padding": padding}),
    )
    .await;
    assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);

    harness.clock.advance(60);
    for _ in 0..6 {
        announced(&harness, &node_id, &set(&[])).await;
    }
    let limited = announce(&harness, Some(&node_id), &set(&[])).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.get("retry-after").is_some());
    let other = node(&harness, "web-02").await;
    announced(&harness, &other, &set(&[])).await;
    harness.clock.advance(10);
    announced(&harness, &node_id, &set(&[])).await;
}

#[tokio::test]
async fn the_same_set_twice_changes_nothing_and_a_new_service_waits_for_approval() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    apply_policy(
        &harness,
        &[
            ADMIN_ROLES.to_owned(),
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
             members: { groups: [ops] }\n  tcp: { services: { team: [ops] } }\n"
                .to_owned(),
        ],
    );
    let token = bearer(&harness, "alice@example.com", &["ops"]).await;
    start_recording();

    announced(&harness, &node_id, &set(&[tcp("grafana", "ops")])).await;
    let first = service_events(take_recording());
    let pending = only_pending(&harness, &approver).await;
    start_recording();
    announced(&harness, &node_id, &set(&[tcp("grafana", "ops")])).await;
    let second = service_events(take_recording());

    assert_eq!(first.len(), 1, "{first:?}");
    let requested = named(&first, "service.requested");
    assert_eq!(requested["node_id"], node_id);
    assert_eq!(requested["service_id"], pending["id"].as_str().unwrap());
    assert_eq!(requested["labels"], "team=ops");
    assert!(second.is_empty(), "{second:?}");
    assert_eq!(pending["state"], json!("pending"));
    assert_eq!(pending["revision"], json!(1));
    assert_eq!(pending["settings"], json!({"idle_timeout_secs": 3600}));
    assert_eq!(only_pending(&harness, &approver).await["id"], pending["id"]);
    assert!(
        listed(&harness, &approver, "state=approved")
            .await
            .is_empty()
    );
    assert!(offered(&harness, &token).await.services.is_empty());
}

#[tokio::test]
async fn approval_needs_nodes_approve_and_works_by_session_and_by_signature() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let node_id = node(&harness, "web-01").await;
    announced(
        &harness,
        &node_id,
        &set(&[tcp("grafana", "ops"), tcp("vault", "sec")]),
    )
    .await;
    let pending = listed(&harness, &approver, "state=pending").await;
    let id_of = |name: &str| {
        pending
            .iter()
            .find(|service| service["name"] == name)
            .unwrap()["id"]
            .clone()
    };
    let (grafana, vault) = (&id_of("grafana"), &id_of("vault"));

    let denied = get(&harness, "/v1/admin/services", &reader).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let denied = approve(&harness, &reader, grafana, &json!({})).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    let reserved = approve(
        &harness,
        &approver,
        grafana,
        &json!({"labels": {"name": "x"}}),
    )
    .await;
    assert_eq!(
        (reserved.status, reserved.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_labels")
    );
    let missing = approve(
        &harness,
        &approver,
        &json!("67e55044-10b1-426f-9247-bb680e5fe0c8"),
        &json!({}),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(listed(&harness, &approver, "state=pending").await.len(), 2);

    start_recording();
    let by_session = approve(
        &harness,
        &approver,
        grafana,
        &json!({"labels": {"team": "ops", "env": "prod"}}),
    )
    .await;
    let signer = issue(&harness, &approver.user_id).await;
    let by_signature = signed(
        &harness,
        &signer,
        Method::POST,
        &format!("/v1/admin/services/{}/approve", vault.as_str().unwrap()),
        Some(&json!({})),
    )
    .await;
    let events = service_events(take_recording());

    assert_eq!(by_session.status, StatusCode::OK, "{}", by_session.text());
    let body = by_session.json();
    assert_eq!(body["service"]["state"], json!("approved"));
    assert_eq!(
        body["service"]["labels"],
        json!({"env": "prod", "team": "ops"})
    );
    assert_eq!(body["service"]["announced_labels"], json!({"team": "ops"}));
    assert_eq!(body["service"]["approved_by"], json!(approver.actor()));
    assert_eq!(
        by_signature.status,
        StatusCode::OK,
        "{}",
        by_signature.text()
    );
    let signed_actor = format!("signed:{}", approver.user_id);
    assert_eq!(
        by_signature.json()["service"]["approved_by"],
        json!(signed_actor)
    );
    let approvals: Vec<&Captured> = events
        .iter()
        .filter(|event| event["event"] == "service.approved")
        .collect();
    assert_eq!(approvals.len(), 2);
    assert_eq!(approvals[0]["approved_by"], approver.actor());
    assert_eq!(approvals[0]["labels_overridden"], "true");
    assert_eq!(approvals[0]["node_id"], node_id);
    assert_eq!(approvals[1]["approved_by"], signed_actor);
    assert_eq!(approvals[1]["labels_overridden"], "false");
    let again = approve(&harness, &approver, grafana, &json!({})).await;
    assert_eq!(
        (again.status, again.error_code().as_str()),
        (StatusCode::CONFLICT, "service_approved")
    );
}

#[tokio::test]
async fn changed_labels_wait_while_the_approved_revision_stays_offered() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    apply_policy(
        &harness,
        &[
            ADMIN_ROLES.to_owned(),
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: all }\nspec:\n  \
             members: { groups: [ops] }\n  tcp: { services: { team: ['*'] } }\n"
                .to_owned(),
        ],
    );
    let token = bearer(&harness, "alice@example.com", &["ops"]).await;
    announced(&harness, &node_id, &set(&[tcp("grafana", "ops")])).await;
    let first = only_pending(&harness, &approver).await;
    let reply = approve(&harness, &approver, &first["id"], &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    announced(&harness, &node_id, &set(&[tcp("grafana", "dev")])).await;
    let revision = only_pending(&harness, &approver).await;
    assert_eq!(revision["revision"], json!(2));
    assert_eq!(revision["labels"], json!({"team": "dev"}));
    assert_eq!(revision["replaces"]["id"], first["id"]);
    assert_eq!(revision["replaces"]["labels"], json!({"team": "ops"}));
    let list = offered(&harness, &token).await;
    assert_eq!(names(&list), ["tcp/grafana"]);
    assert_eq!(list.services[0].labels["team"], "ops");
    announced(&harness, &node_id, &set(&[tcp("grafana", "web")])).await;
    let newer = only_pending(&harness, &approver).await;
    assert_eq!(newer["labels"], json!({"team": "web"}));
    let stale = approve(&harness, &approver, &revision["id"], &json!({})).await;
    assert_eq!(stale.status, StatusCode::NOT_FOUND, "{}", stale.text());
    assert_eq!(
        offered(&harness, &token).await.services[0].labels["team"],
        "ops"
    );

    let mut moved = tcp("grafana", "ops");
    moved["address"] = json!("10.0.0.6:3000");
    moved["tcp"] = json!({"idle_timeout_secs": 60});
    start_recording();
    announced(&harness, &node_id, &set(&[moved])).await;
    let events = service_events(take_recording());
    let names_of: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
    assert_eq!(names_of, ["service.superseded"]);
    assert!(
        listed(&harness, &approver, "state=pending")
            .await
            .is_empty()
    );
    let approved = listed(&harness, &approver, "state=approved").await;
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0]["id"], first["id"]);
    assert_eq!(approved[0]["address_hint"], json!("10.0.0.6:3000"));
    assert_eq!(approved[0]["settings"], json!({"idle_timeout_secs": 60}));
    assert_eq!(approved[0]["labels"], json!({"team": "ops"}));

    start_recording();
    announced(&harness, &node_id, &set(&[])).await;
    let events = service_events(take_recording());
    assert_eq!(named(&events, "service.withdrawn")["state"], "approved");
    assert!(offered(&harness, &token).await.services.is_empty());
    assert_eq!(
        listed(&harness, &approver, "state=approved").await[0]["announced"],
        json!(false)
    );
}

#[tokio::test]
async fn an_approved_name_belongs_to_one_node_and_decisions_are_audited() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let first = node(&harness, "web-01").await;
    let second = node(&harness, "web-02").await;
    announced(&harness, &first, &set(&[tcp("grafana", "ops")])).await;
    announced(&harness, &second, &set(&[tcp("grafana", "ops")])).await;
    let ours = listed(&harness, &approver, &format!("node_id={first}")).await[0].clone();
    let theirs = listed(&harness, &approver, &format!("node_id={second}")).await[0].clone();
    let reply = approve(&harness, &approver, &ours["id"], &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());

    let taken = approve(&harness, &approver, &theirs["id"], &json!({})).await;
    assert_eq!(
        (taken.status, taken.error_code().as_str()),
        (StatusCode::CONFLICT, "service_name_taken")
    );
    let shown = only_pending(&harness, &approver).await;
    assert_eq!(shown["id"], theirs["id"]);
    assert_eq!(shown["state"], json!("pending"));
    assert_eq!(
        shown["conflict"],
        json!({"node_id": first, "node_name": "web-01"})
    );

    start_recording();
    let rejected = post(
        &harness,
        &format!(
            "/v1/admin/services/{}/reject",
            theirs["id"].as_str().unwrap()
        ),
        &approver,
        &json!({}),
    )
    .await;
    let not_approved = delete(
        &harness,
        &format!("/v1/admin/services/{}", theirs["id"].as_str().unwrap()),
        &approver,
        &json!({}),
    )
    .await;
    let removed = delete(
        &harness,
        &format!("/v1/admin/services/{}", ours["id"].as_str().unwrap()),
        &approver,
        &json!({}),
    )
    .await;
    let events = service_events(take_recording());

    assert_eq!(rejected.status, StatusCode::OK, "{}", rejected.text());
    assert_eq!(rejected.json()["service"]["state"], json!("removed"));
    assert_eq!(
        (not_approved.status, not_approved.error_code().as_str()),
        (StatusCode::CONFLICT, "service_removed")
    );
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text());
    assert_eq!(removed.json()["service"]["state"], json!("removed"));
    assert_eq!(
        named(&events, "service.rejected")["rejected_by"],
        approver.actor()
    );
    assert_eq!(named(&events, "service.rejected")["node_id"], second);
    assert_eq!(
        named(&events, "service.removed")["removed_by"],
        approver.actor()
    );
    assert_eq!(listed(&harness, &approver, "state=removed").await.len(), 2);
    assert!(listed(&harness, &approver, "").await.is_empty());
}

#[tokio::test]
async fn the_service_list_returns_only_what_the_policy_allows_for_each_kind() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    apply_policy(
        &harness,
        &[
            ADMIN_ROLES.to_owned(),
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
             members: { groups: [ops] }\n  \
             kubernetes: { clusters: { env: [prod] }, users: [dev] }\n  \
             databases: { servers: { env: [prod, secret] }, users: [readonly], names: [app, secrets] }\n  \
             tcp: { services: { team: [ops] } }\n  \
             deny:\n    tcp: { services: { name: [vault] } }\n    \
             databases: { servers: { env: [prod] }, names: [secrets] }\n---\n\
             apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: limits }\nspec:\n  \
             members: { groups: [ops] }\n  \
             deny: { databases: { servers: { env: [secret] } } }\n"
                .to_owned(),
        ],
    );
    let postgres = |name: &str, env: &str| {
        json!({"kind": "postgres", "name": name, "labels": {"env": env},
               "address": "127.0.0.1:5432", "postgres": {"tls": {"server_name": "db-01"}}})
    };
    let offered_set = vec![
        json!({"kind": "kubernetes", "name": "prod-eu", "labels": {"env": "prod"}}),
        json!({"kind": "kubernetes", "name": "stage", "labels": {"env": "stage"}}),
        tcp("grafana", "ops"),
        tcp("vault", "ops"),
        postgres("lk", "prod"),
        postgres("vault-db", "secret"),
        postgres("stage-db", "stage"),
    ];
    announced(&harness, &node_id, &set(&offered_set)).await;
    for pending in listed(&harness, &approver, "state=pending").await {
        let reply = approve(&harness, &approver, &pending["id"], &json!({})).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }
    harness.clock.advance(60);
    let mut with_waiting = offered_set;
    with_waiting.push(tcp("waiting", "ops"));
    with_waiting.push(postgres("waiting-db", "prod"));
    announced(&harness, &node_id, &set(&with_waiting)).await;
    let alice = bearer(&harness, "alice@example.com", &["ops"]).await;
    let bob = bearer(&harness, "bob@example.com", &["dev"]).await;

    let list = offered(&harness, &alice).await;
    assert_eq!(
        names(&list),
        ["kubernetes/prod-eu", "postgres/lk", "tcp/grafana"]
    );
    assert!(!list.truncated);
    assert!(list.services.iter().all(|service| !service.connected));
    assert!(offered(&harness, &bob).await.services.is_empty());
    let raw = send(
        harness.router.clone(),
        Request::builder()
            .uri("/v1/services")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(raw.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_saved_approval_is_answered_even_when_reading_it_back_fails() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    announced(&harness, &node_id, &set(&[tcp("grafana", "ops")])).await;
    let pending = only_pending(&harness, &approver).await;
    let id = pending["id"].as_str().unwrap().to_owned();
    sqlx::query("UPDATE services SET settings = 'not json' WHERE id = ?")
        .bind(&id)
        .execute(&raw_pool(&harness).await)
        .await
        .unwrap();
    start_recording();

    let reply = approve(&harness, &approver, &pending["id"], &json!({})).await;

    let events = service_events(take_recording());
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.json(),
        json!({"service": {"id": id, "state": "approved"}})
    );
    assert_eq!(named(&events, "service.approved")["service_id"], id);
    let stored = harness.store.services().get(&id).await.unwrap().unwrap();
    assert_eq!(stored.state, jaunt_store::ServiceState::Approved);
}

#[tokio::test]
async fn a_node_without_ssh_is_neither_routed_nor_listed_and_old_agents_stay_targets() {
    let s = scenario().await;
    let harness = &s.harness;
    let token = bearer(harness, "carol@example.com", &["ops"]).await;
    let ssh_nodes = |reply: Reply| -> Vec<String> {
        reply.json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|node| node["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let nodes = || async {
        let request = Request::builder()
            .uri("/v1/nodes")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        ssh_nodes(send(harness.router.clone(), request).await)
    };
    assert!(matches!(
        route(harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Allow { .. }
    ));
    assert_eq!(nodes().await, [NODE_NAME]);

    start_recording();
    announced(
        harness,
        &s.node_id,
        &json!({"ssh_enabled": false, "services": []}),
    )
    .await;
    let events = service_events(take_recording());
    assert_eq!(named(&events, "node.ssh_changed")["ssh_enabled"], "false");
    assert_eq!(named(&events, "node.ssh_changed")["node_id"], s.node_id);
    assert_eq!(
        route(harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Deny {
            reason: DenyReason::NodeUnknown
        }
    );
    assert!(nodes().await.is_empty());
    assert!(
        !harness
            .store
            .nodes()
            .get(&s.node_id)
            .await
            .unwrap()
            .unwrap()
            .ssh_enabled
    );

    announced(harness, &s.node_id, &json!({"services": []})).await;
    assert!(matches!(
        route(harness, s.alice.route_to(NODE_NAME)).await,
        RouteDecision::Allow { .. }
    ));
    assert_eq!(nodes().await, [NODE_NAME]);
}

struct ConnectedOnly(String);

impl jaunt_control::AgentPresence for ConnectedOnly {
    fn connected_since(&self, node_id: &str) -> Option<std::time::SystemTime> {
        (node_id == self.0).then(std::time::SystemTime::now)
    }
}

fn names_set(prefix: &str, count: usize) -> Value {
    let services: Vec<Value> = (0..count)
        .map(|index| tcp(&format!("{prefix}{index}"), "ops"))
        .collect();
    set(&services)
}

const OPS_TCP: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
     members: { groups: [ops] }\n  tcp: { services: { team: [ops] } }\n";

#[tokio::test]
async fn a_flood_of_new_names_stays_bounded_and_other_nodes_stay_visible() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let honest = node(&harness, "web-01").await;
    let flooding = node(&harness, "web-02").await;
    announced(&harness, &honest, &set(&[tcp("grafana", "ops")])).await;
    harness.clock.advance(1);
    let mut previous: Vec<Value> = Vec::new();
    for prefix in ["a", "b", "c"] {
        announced(&harness, &flooding, &names_set(prefix, 64)).await;
        let queue = listed(&harness, &approver, "limit=200").await;
        assert_eq!(queue.len(), 65, "{prefix}");
        assert!(
            queue
                .iter()
                .any(|service| service["node"]["id"] == json!(honest)),
            "{prefix}"
        );
        for gone in &previous {
            assert!(
                !queue.iter().any(|service| service["id"] == *gone),
                "{prefix}"
            );
        }
        previous = queue
            .iter()
            .filter(|service| service["node"]["id"] == json!(flooding))
            .map(|service| service["id"].clone())
            .collect();
    }
    let first_page = listed(&harness, &approver, "").await;
    assert!(
        first_page
            .iter()
            .any(|service| service["node"]["id"] == json!(honest))
    );

    for pending in listed(
        &harness,
        &approver,
        &format!("node_id={flooding}&limit=200"),
    )
    .await
    {
        let reply = approve(&harness, &approver, &pending["id"], &json!({})).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }
    harness.clock.advance(60);
    announced(&harness, &flooding, &names_set("d", 64)).await;
    let d = listed(
        &harness,
        &approver,
        &format!("state=pending&node_id={flooding}&limit=200"),
    )
    .await;
    let reply = approve(&harness, &approver, &d[0]["id"], &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let before = listed(
        &harness,
        &approver,
        &format!("node_id={flooding}&limit=200"),
    )
    .await;
    assert_eq!(before.len(), 128);
    start_recording();
    let refused = announce(&harness, Some(&flooding), &names_set("e", 64)).await;
    let events = service_events(take_recording());
    assert_eq!(
        (refused.status, refused.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "too_many_services")
    );
    let refusal = named(&events, "service.announce_refused");
    assert_eq!(refusal["reason"], "too_many_services");
    assert_eq!(refusal["node_id"], flooding);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        listed(
            &harness,
            &approver,
            &format!("node_id={flooding}&limit=200")
        )
        .await,
        before
    );
}

#[tokio::test]
async fn reject_and_remove_need_nodes_approve_on_every_path() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let nobody = admin(&harness, "nobody").await;
    let node_id = node(&harness, "web-01").await;
    announced(
        &harness,
        &node_id,
        &set(&[tcp("a", "ops"), tcp("b", "ops")]),
    )
    .await;
    let pending = listed(&harness, &approver, "state=pending").await;
    let reply = approve(&harness, &approver, &pending[1]["id"], &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let waiting = pending[0]["id"].as_str().unwrap().to_owned();
    let live = pending[1]["id"].as_str().unwrap().to_owned();
    let signer = issue(&harness, &reader.user_id).await;

    for who in [&reader, &nobody] {
        let rejected = post(
            &harness,
            &format!("/v1/admin/services/{waiting}/reject"),
            who,
            &json!({}),
        )
        .await;
        assert_eq!(rejected.status, StatusCode::FORBIDDEN);
        let removed = delete(
            &harness,
            &format!("/v1/admin/services/{live}"),
            who,
            &json!({}),
        )
        .await;
        assert_eq!(removed.status, StatusCode::FORBIDDEN);
    }
    let signed_delete = signed(
        &harness,
        &signer,
        Method::DELETE,
        &format!("/v1/admin/services/{live}"),
        None,
    )
    .await;
    assert_eq!(
        signed_delete.status,
        StatusCode::FORBIDDEN,
        "{}",
        signed_delete.text()
    );
    let services = harness.store.services();
    assert_eq!(
        services.get(&waiting).await.unwrap().unwrap().state,
        jaunt_store::ServiceState::Pending
    );
    assert_eq!(
        services.get(&live).await.unwrap().unwrap().state,
        jaunt_store::ServiceState::Approved
    );
}

#[tokio::test]
async fn a_removed_node_offers_nothing_and_its_pending_services_cannot_be_approved() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    apply_policy(&harness, &[ADMIN_ROLES.to_owned(), OPS_TCP.to_owned()]);
    let token = bearer(&harness, "alice@example.com", &["ops"]).await;
    harness
        .control
        .install_agent_presence(std::sync::Arc::new(ConnectedOnly(node_id.clone())));
    announced(
        &harness,
        &node_id,
        &set(&[tcp("grafana", "ops"), tcp("vault", "ops")]),
    )
    .await;
    let pending = listed(&harness, &approver, "state=pending").await;
    let grafana = pending
        .iter()
        .find(|service| service["name"] == "grafana")
        .unwrap()["id"]
        .clone();
    let vault = pending
        .iter()
        .find(|service| service["name"] == "vault")
        .unwrap()["id"]
        .clone();
    let reply = approve(&harness, &approver, &grafana, &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let list = offered(&harness, &token).await;
    assert_eq!(names(&list), ["tcp/grafana"]);
    assert!(list.services[0].connected);

    harness.admin.remove_node("web-01", APPROVER).await.unwrap();

    assert!(offered(&harness, &token).await.services.is_empty());
    assert!(harness.store.services().offered().await.unwrap().is_empty());
    let late = approve(&harness, &approver, &vault, &json!({})).await;
    assert_eq!(
        (late.status, late.error_code().as_str()),
        (StatusCode::CONFLICT, "node_not_active")
    );
}

#[tokio::test]
async fn a_legal_announcement_above_sixteen_kibibytes_is_accepted() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let node_id = node(&harness, "web-01").await;
    let services: Vec<Value> = (0..40)
        .map(|index| {
            let labels: serde_json::Map<String, Value> = (0..16)
                .map(|label| {
                    (
                        format!("k{label:02}{}", "a".repeat(60)),
                        json!("v".repeat(63)),
                    )
                })
                .collect();
            let mut service = tcp(&format!("s{index}"), "ops");
            service["labels"] = Value::Object(labels);
            service
        })
        .collect();
    let body = set(&services);
    let size = serde_json::to_vec(&body).unwrap().len();
    assert!((16 * 1024..256 * 1024).contains(&size), "{size}");

    announced(&harness, &node_id, &body).await;

    assert_eq!(listed(&harness, &approver, "limit=200").await.len(), 40);
}

async fn served(harness: &Harness, node_id: Option<&str>) -> Reply {
    crate::issuance_support::get(&harness.agent_router, ANNOUNCE, None, node_id).await
}

async fn served_names(harness: &Harness, node_id: &str) -> Vec<String> {
    let reply = served(harness, Some(node_id)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let parsed: jaunt_proto::NodeServices = serde_json::from_slice(&reply.body).unwrap();
    parsed
        .services
        .iter()
        .map(|service| format!("{}/{}", service.kind, service.name))
        .collect()
}

#[tokio::test]
async fn a_node_reads_only_its_own_approved_and_announced_services() {
    let harness = web_harness(&[]).await;
    let approver = admin(&harness, "approver").await;
    let first = node(&harness, "web-01").await;
    let second = node(&harness, "web-02").await;
    announced(
        &harness,
        &first,
        &set(&[
            tcp("grafana", "ops"),
            tcp("vault", "ops"),
            tcp("loki", "ops"),
        ]),
    )
    .await;
    announced(&harness, &second, &set(&[tcp("other", "ops")])).await;
    let pending = listed(&harness, &approver, "state=pending").await;
    let id_of = |name: &str| {
        pending
            .iter()
            .find(|service| service["name"] == name)
            .unwrap()["id"]
            .clone()
    };
    for name in ["grafana", "vault", "other"] {
        let reply = approve(&harness, &approver, &id_of(name), &json!({})).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    }

    let reply = served(&harness, Some(&first)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.json(),
        json!({"services": [
            {"id": id_of("grafana"), "kind": "tcp", "name": "grafana"},
            {"id": id_of("vault"), "kind": "tcp", "name": "vault"},
        ]})
    );
    assert_eq!(served_names(&harness, &second).await, ["tcp/other"]);

    announced(
        &harness,
        &first,
        &set(&[tcp("grafana", "ops"), tcp("loki", "ops")]),
    )
    .await;
    assert_eq!(served_names(&harness, &first).await, ["tcp/grafana"]);
    let grafana = id_of("grafana");
    let removed = delete(
        &harness,
        &format!("/v1/admin/services/{}", grafana.as_str().unwrap()),
        &approver,
        &json!({}),
    )
    .await;
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text());
    assert!(served_names(&harness, &first).await.is_empty());
    assert_eq!(served_names(&harness, &second).await, ["tcp/other"]);
}

#[tokio::test]
async fn reading_the_services_needs_an_active_node_and_is_rate_limited_per_node() {
    let harness = web_harness(&[]).await;
    let first = node(&harness, "web-01").await;
    let second = node(&harness, "web-02").await;
    let gone = node(&harness, "web-03").await;
    harness.admin.remove_node("web-03", APPROVER).await.unwrap();

    assert_eq!(
        served(&harness, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    let removed = served(&harness, Some(&gone)).await;
    assert_eq!(
        (removed.status, removed.error_code().as_str()),
        (StatusCode::FORBIDDEN, "node_removed")
    );
    for _ in 0..12 {
        assert_eq!(served(&harness, Some(&first)).await.status, StatusCode::OK);
    }
    let limited = served(&harness, Some(&first)).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.get("retry-after").is_some());
    assert_eq!(served(&harness, Some(&second)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn at_most_sixty_four_services_are_read() {
    let harness = web_harness(&[]).await;
    let node_id = node(&harness, "web-01").await;
    let pool = raw_pool(&harness).await;
    for index in 0..65 {
        sqlx::query(
            "INSERT INTO services (id, node_id, kind, name, labels, announced_labels, settings, \
             address_hint, state, revision, announced, approved_by, approved_at, created_at, \
             last_seen_at) VALUES (?, ?, 'tcp', ?, '{}', '{}', '{}', NULL, 'approved', 1, 1, \
             'cli:root', 1, 1, 1)",
        )
        .bind(format!("svc-{index:03}"))
        .bind(&node_id)
        .bind(format!("s{index:03}"))
        .execute(&pool)
        .await
        .unwrap();
    }
    let names = served_names(&harness, &node_id).await;
    assert_eq!(names.len(), 64);
    assert_eq!(names[0], "tcp/s000");
    assert_eq!(names[63], "tcp/s063");
}

#[tokio::test]
async fn a_removed_node_is_rate_limited_before_the_store_is_read() {
    let harness = web_harness(&[]).await;
    let gone = node(&harness, "web-01").await;
    harness.admin.remove_node("web-01", APPROVER).await.unwrap();
    for _ in 0..12 {
        let removed = served(&harness, Some(&gone)).await;
        assert_eq!(
            (removed.status, removed.error_code().as_str()),
            (StatusCode::FORBIDDEN, "node_removed")
        );
    }
    let limited = served(&harness, Some(&gone)).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.get("retry-after").is_some());
}
