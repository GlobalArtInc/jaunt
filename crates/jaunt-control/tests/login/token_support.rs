use axum::http::{Method, StatusCode};
use jaunt_store::{
    AdminToken, AdminTokenCaps, AdminTokenCreated, NewAdminToken, NewUser, SecretHash, User,
};
use serde_json::Value;
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;

use crate::audit::Captured;
use crate::signed_support::{Holder, pairs, send_pairs, sign};
use crate::support::{DEFAULT_PEER, Harness, Options, PUBLIC_ORIGIN, Reply, sha256_hex};

pub const TOKENS: &str = "/v1/admin/tokens";
pub const AUDIT: &str = "/v1/admin/audit";
pub const SESSIONS: &str = "/v1/admin/sessions";
pub const WHOAMI: &str = "/v1/admin/whoami";
pub const DAY: i64 = 86_400;

const PLANT_CAPS: AdminTokenCaps = AdminTokenCaps {
    max_live_per_creator: 20,
    max_dead_per_creator: 100,
    max_created_per_window: 1_000_000,
    window_secs: 1,
};

pub const ROLES: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: token-admins }
spec:
  members: { users: [alice@example.com] }
  admin: [nodes.approve, sessions.read, audit.read, tokens.write]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: readers }
spec:
  members: { users: [carol@example.com] }
  admin: [nodes.approve, sessions.read, audit.read]
";

pub async fn token_harness_with(options: Options) -> Harness {
    let harness = Harness::with(Options {
        web: true,
        ..options
    })
    .await;
    harness.load_policy(ROLES);
    harness
}

pub async fn token_harness() -> Harness {
    token_harness_with(Options::default()).await
}

pub async fn signed_call(
    harness: &Harness,
    holder: &Holder,
    method: Method,
    path: &str,
    body: &[u8],
) -> Reply {
    let signed = sign(
        holder,
        method.as_str(),
        path,
        body,
        harness.clock.now_secs(),
    );
    send_pairs(harness, method, path, &pairs(&signed), body).await
}

pub async fn create_signed(harness: &Harness, holder: &Holder, body: &Value) -> Reply {
    let bytes = serde_json::to_vec(body).unwrap();
    signed_call(harness, holder, Method::POST, TOKENS, &bytes).await
}

pub async fn stored_user(harness: &Harness, name: &str) -> User {
    harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: format!("subject-{name}"),
                email: format!("{name}@example.com"),
                username: name.to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap()
}

pub struct Planted<'a> {
    pub creator: &'a str,
    pub id: &'a str,
    pub scope: &'a [&'a str],
    pub cidrs: &'a [&'a str],
    pub ttl_secs: i64,
}

pub async fn plant(harness: &Harness, planted: Planted<'_>) -> String {
    let text = format!("jat_{}_{}", planted.id, "k".repeat(43));
    let created = harness
        .store
        .admin_tokens()
        .create(
            &NewAdminToken {
                id: planted.id.to_owned(),
                name: format!("planted-{}", planted.id.to_ascii_lowercase()),
                creator_user_id: planted.creator.to_owned(),
                secret_hash: SecretHash::new(sha256_hex(&text)),
                scope: planted
                    .scope
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                cidrs: planted
                    .cidrs
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                ttl_secs: planted.ttl_secs,
            },
            harness.clock.now_secs(),
            PLANT_CAPS,
        )
        .await
        .unwrap();
    assert!(matches!(created, AdminTokenCreated::Created(_)));
    text
}

pub async fn all_tokens(harness: &Harness) -> Vec<AdminToken> {
    harness
        .store
        .admin_tokens()
        .list(harness.clock.now_secs(), 0, 100_000)
        .await
        .unwrap()
        .tokens
}

pub async fn last_used(harness: &Harness, id: &str) -> Option<i64> {
    harness
        .store
        .admin_tokens()
        .get_for_use(id)
        .await
        .unwrap()
        .unwrap()
        .token
        .last_used_at
}

pub async fn set_scope(harness: &Harness, id: &str, scope: &str) {
    let pool =
        SqlitePool::connect_with(SqliteConnectOptions::new().filename(harness.database_path()))
            .await
            .unwrap();
    sqlx::query("UPDATE admin_tokens SET scope = ? WHERE id = ?")
        .bind(scope)
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

pub struct Console {
    pub cookie: String,
    pub csrf: String,
}

pub async fn console(harness: &Harness, user_id: &str) -> Console {
    let opened = harness.control.open_web_session(user_id).await.unwrap();
    Console {
        cookie: opened.cookie,
        csrf: opened.csrf_token,
    }
}

pub async fn console_call(
    harness: &Harness,
    console: &Console,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Reply {
    let headers = [
        ("cookie", console.cookie.as_str()),
        ("x-jaunt-csrf", console.csrf.as_str()),
        ("origin", PUBLIC_ORIGIN),
    ];
    let body = body.map(|body| ("application/json", serde_json::to_vec(body).unwrap()));
    harness
        .request_as(method, path, DEFAULT_PEER, &headers, body)
        .await
}

pub async fn bearer_from(
    harness: &Harness,
    token: &str,
    method: Method,
    path: &str,
    peer: &str,
    extra: &[(&str, &str)],
) -> Reply {
    let authorization = format!("Bearer {token}");
    let mut headers: Vec<(&str, &str)> = vec![("authorization", &authorization)];
    headers.extend_from_slice(extra);
    harness.request_as(method, path, peer, &headers, None).await
}

pub async fn bearer(harness: &Harness, token: &str, path: &str) -> Reply {
    bearer_from(harness, token, Method::GET, path, DEFAULT_PEER, &[]).await
}

pub fn named<'a>(events: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some(name))
        .collect()
}

pub fn assert_nowhere(events: &[Captured], needle: &str) {
    for event in events {
        for (field, value) in event {
            assert!(
                !value.contains(needle),
                "{field} carries a secret: {event:?}"
            );
        }
    }
}

pub fn assert_status(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.text());
    assert_eq!(reply.error_code(), code);
}
