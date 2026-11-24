use std::fs;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use jaunt_ca::ssh_key::PublicKey;
use jaunt_control::Labels;
use jaunt_store::{NewApiToken, NewCertificate, NewUser};
use serde_json::{Value, json};

use crate::support::{APPROVER, Harness, Options, Reply, send, sha256_hex};

const PROD_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: prod }\nspec:\n  members: { users: [alice@example.com], groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy] }\n";
const DEV_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: dev }\nspec:\n  members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [dev] }, logins: [deploy] }\n";

async fn get(harness: &Harness, path: &str, authorization: Option<&str>) -> Reply {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(value) = authorization {
        builder = builder.header("authorization", value);
    }
    send(harness.router.clone(), builder.body(Body::empty()).unwrap()).await
}

async fn bearer(harness: &Harness, email: &str, groups: &[&str]) -> String {
    let now = harness.clock.now_secs();
    let user = harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: email.to_owned(),
                email: email.to_owned(),
                username: String::new(),
                display_name: None,
                groups: groups.iter().map(|group| (*group).to_owned()).collect(),
            },
            now,
        )
        .await
        .unwrap();
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    harness
        .store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user.id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:{email}:{serial}"),
            valid_after: now - 120,
            valid_before: now + 3600,
            issued_at: now,
        })
        .await
        .unwrap();
    let secret = format!("jt_{}{:0>42}", "Q", serial);
    harness
        .store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: sha256_hex(&secret),
            user_id: user.id,
            cert_serial: serial,
            created_at: now,
            expires_at: now + 3600,
        })
        .await
        .unwrap();
    secret
}

async fn node(harness: &Harness, index: usize, name: &str, env: &str) {
    let peer = format!("10.1.0.{index}");
    let enrolled = harness.enroll_from_peer(&peer, name).await;
    let labels = Labels::parse_assignments(&format!("env={env}")).unwrap();
    harness
        .admin
        .approve(&enrolled.code, APPROVER, Some(labels))
        .await
        .unwrap();
}

fn load_policy(harness: &Harness, roles: &[&str]) {
    let dir = tempfile::tempdir().unwrap();
    for (index, role) in roles.iter().enumerate() {
        fs::write(dir.path().join(format!("role-{index}.yaml")), role).unwrap();
    }
    let outcome = harness.policy.reload(dir.path());
    assert!(outcome.applied, "{:?}", outcome.errors);
}

fn names(reply: &Reply) -> Vec<String> {
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn client_config_is_public_and_lists_the_suffix_the_gate_and_the_host_keys() {
    for (configured, host, port) in [
        ("Gate.Example.com:2222", "gate.example.com", 2222),
        ("gate.example.com", "gate.example.com", 22),
    ] {
        let harness = Harness::with(Options {
            gate_endpoint: Some(configured),
            ..Options::default()
        })
        .await;

        let reply = get(&harness, "/v1/client-config", None).await;

        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        assert_eq!(reply.headers["cache-control"], "no-store");
        let body = reply.json();
        assert_eq!(body["ssh_suffix"], "jaunt.test");
        assert_eq!(body["gate"], json!({"host": host, "port": port}));
        let keys = body["host_ca_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let served = PublicKey::from_openssh(keys[0].as_str().unwrap()).unwrap();
        assert_eq!(served.key_data(), harness.host_ca.key_data());
        assert_eq!(body.as_object().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn client_config_without_a_gate_endpoint_answers_not_configured() {
    let harness = Harness::new().await;

    let reply = get(&harness, "/v1/client-config", None).await;

    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(reply.json(), json!({"error": "not_configured"}));
    assert_eq!(reply.headers["cache-control"], "no-store");
}

#[tokio::test]
async fn nodes_refuses_every_credential_that_whoami_refuses_in_the_same_way() {
    let harness = Harness::new().await;
    let token = bearer(&harness, "alice@example.com", &[]).await;
    let unknown = format!("jt_{}", "A".repeat(43));
    let cases: Vec<Option<String>> = vec![
        None,
        Some("Bearer garbage".to_owned()),
        Some("Bearer ".to_owned()),
        Some(format!("Bearer {unknown}")),
        Some(format!("Basic {token}")),
        Some(token.clone()),
        Some(format!("Bearer  {token}")),
    ];
    for case in &cases {
        let whoami = get(&harness, "/v1/whoami", case.as_deref()).await;
        let nodes = get(&harness, "/v1/nodes", case.as_deref()).await;
        assert_eq!(nodes.status, StatusCode::UNAUTHORIZED, "{case:?}");
        assert_eq!(nodes.status, whoami.status, "{case:?}");
        assert_eq!(nodes.headers["www-authenticate"], "Bearer", "{case:?}");
        assert!(nodes.body.is_empty(), "{case:?}");
    }

    let accepted = get(&harness, "/v1/nodes", Some(&format!("Bearer {token}"))).await;
    assert_eq!(accepted.status, StatusCode::OK);
    harness.clock.advance(3600);
    let expired = get(&harness, "/v1/nodes", Some(&format!("Bearer {token}"))).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert!(expired.body.is_empty());
}

#[tokio::test]
async fn nodes_lists_only_active_nodes_the_current_policy_routes_sorted_by_name() {
    let harness = Harness::new().await;
    node(&harness, 1, "web-3", "prod").await;
    node(&harness, 2, "db-1", "dev").await;
    node(&harness, 3, "web-1", "prod").await;
    node(&harness, 4, "web-2", "prod").await;
    harness
        .admin
        .remove_node("web-2", "cli:tester")
        .await
        .unwrap();
    let alice = format!(
        "Bearer {}",
        bearer(&harness, "alice@example.com", &[]).await
    );
    let bob = format!("Bearer {}", bearer(&harness, "bob@example.com", &[]).await);
    let carol = format!(
        "Bearer {}",
        bearer(&harness, "carol@example.com", &["ops"]).await
    );

    assert!(names(&get(&harness, "/v1/nodes", Some(&alice)).await).is_empty());

    load_policy(&harness, &[PROD_ROLE]);
    let listed = get(&harness, "/v1/nodes", Some(&alice)).await;
    assert_eq!(names(&listed), ["web-1", "web-3"]);
    assert_eq!(listed.headers["cache-control"], "no-store");
    let body = listed.json();
    assert_eq!(body["truncated"], json!(false));
    assert_eq!(
        body["nodes"][0],
        json!({
            "name": "web-1",
            "labels": {"env": "prod"},
            "hostname": "web-1.internal.example.com",
            "connected": false,
        })
    );
    assert_eq!(
        names(&get(&harness, "/v1/nodes", Some(&carol)).await),
        ["web-1", "web-3"]
    );
    assert!(names(&get(&harness, "/v1/nodes", Some(&bob)).await).is_empty());

    load_policy(&harness, &[PROD_ROLE, DEV_ROLE]);
    assert_eq!(
        names(&get(&harness, "/v1/nodes", Some(&alice)).await),
        ["db-1", "web-1", "web-3"]
    );
    assert_eq!(
        names(&get(&harness, "/v1/nodes", Some(&carol)).await),
        ["web-1", "web-3"]
    );

    harness
        .admin
        .remove_node("web-1", "cli:tester")
        .await
        .unwrap();
    assert_eq!(
        names(&get(&harness, "/v1/nodes", Some(&alice)).await),
        ["db-1", "web-3"]
    );
}

#[tokio::test]
async fn nodes_reads_the_policy_snapshot_on_every_request() {
    let harness = Harness::new().await;
    node(&harness, 1, "web-1", "prod").await;
    let alice = format!(
        "Bearer {}",
        bearer(&harness, "alice@example.com", &[]).await
    );
    load_policy(&harness, &[PROD_ROLE]);
    assert_eq!(
        names(&get(&harness, "/v1/nodes", Some(&alice)).await),
        ["web-1"]
    );

    load_policy(&harness, &[DEV_ROLE]);

    assert!(names(&get(&harness, "/v1/nodes", Some(&alice)).await).is_empty());
    let value: Value = get(&harness, "/v1/nodes", Some(&alice)).await.json();
    assert_eq!(value, json!({"nodes": [], "truncated": false}));
}
