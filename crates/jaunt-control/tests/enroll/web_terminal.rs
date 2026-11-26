use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use jaunt_control::{
    GateLink, GateRefusal, GateRequest, Labels, RevokeRequest, TerminalGate, WebTerminalSettings,
};
use jaunt_store::RevocationKind;
use serde_json::{Value, json};

use crate::session_support::{LOGIN, apply_policy, user};
use crate::support::{APPROVER, Harness, Options, PUBLIC_ORIGIN, Reply, send};

const TERMINAL: &str = "/v1/web/terminal";
const TICKET: &str = "/v1/web/terminal/ticket";
const TARGETS: &str = "/v1/web/terminal/targets";
const QUERY: &str = "node=web-01&login=deploy&cols=80&rows=24";
const ROLES: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
     members: { groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy, \"{username}\"] }\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: dev }\nspec:\n  \
     members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [dev] }, logins: [app] }\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: approvers }\nspec:\n  \
     members: { users: [alice@example.com, carol@example.com] }\n  admin: [nodes.approve]\n";

const ADMINS_ONLY: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: approvers }\nspec:\n  \
     members: { users: [alice@example.com] }\n  admin: [nodes.approve]\n";

#[derive(Default)]
struct CountingGate {
    connects: AtomicUsize,
}

impl TerminalGate for CountingGate {
    fn host_name(&self) -> String {
        "gate.jaunt.test".to_owned()
    }

    fn connect(&self, _request: GateRequest) -> Result<GateLink, GateRefusal> {
        self.connects.fetch_add(1, Ordering::SeqCst);
        Err(GateRefusal::Busy)
    }
}

struct Browser {
    cookie: String,
    csrf: String,
}

struct Stand {
    harness: Harness,
    gate: Arc<CountingGate>,
    alice: Browser,
    bob: Browser,
    carol: Browser,
}

async fn browser(harness: &Harness, subject: &str, groups: &[&str]) -> Browser {
    let user_id = user(harness, subject, groups).await;
    let opened = harness.control.open_web_session(&user_id).await.unwrap();
    Browser {
        cookie: opened.cookie,
        csrf: opened.csrf_token,
    }
}

async fn node(harness: &Harness, name: &str, env: &str) {
    let enrolled = harness.enroll(name).await;
    let labels = Labels::new(BTreeMap::from([("env".to_owned(), env.to_owned())])).unwrap();
    harness
        .admin
        .approve(&enrolled.code, APPROVER, Some(labels))
        .await
        .unwrap();
}

async fn stand() -> Stand {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    node(&harness, "web-01", "prod").await;
    node(&harness, "web-02", "prod").await;
    node(&harness, "dev-01", "dev").await;
    let gate = Arc::new(CountingGate::default());
    harness
        .control
        .install_web_terminal(gate.clone(), WebTerminalSettings::default());
    let alice = browser(&harness, "alice", &["ops"]).await;
    let bob = browser(&harness, "bob", &["ops"]).await;
    let carol = browser(&harness, "carol", &[]).await;
    Stand {
        harness,
        gate,
        alice,
        bob,
        carol,
    }
}

async fn ticket_reply(harness: &Harness, who: &Browser, body: &Value) -> Reply {
    let request = Request::builder()
        .method(Method::POST)
        .uri(TICKET)
        .header(header::COOKIE, &who.cookie)
        .header("x-jaunt-csrf", &who.csrf)
        .header(header::ORIGIN, PUBLIC_ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    send(harness.router.clone(), request).await
}

async fn ticket(harness: &Harness, who: &Browser, node: &str, login: &str) -> String {
    let reply = ticket_reply(harness, who, &json!({"node": node, "login": login})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["expires_in"], 30);
    reply.json()["ticket"].as_str().unwrap().to_owned()
}

struct Handshake<'a> {
    method: Method,
    cookie: Option<&'a str>,
    origin: Option<&'a str>,
    protocols: Option<String>,
    second_protocol_line: Option<String>,
    query: &'a str,
    upgrade: bool,
}

impl<'a> Handshake<'a> {
    fn of(who: &'a Browser, ticket: &str) -> Handshake<'a> {
        Handshake {
            method: Method::GET,
            cookie: Some(&who.cookie),
            origin: Some(PUBLIC_ORIGIN),
            protocols: Some(format!("jaunt-terminal.v1, jaunt-ticket.{ticket}")),
            second_protocol_line: None,
            query: QUERY,
            upgrade: true,
        }
    }

    async fn send(self, harness: &Harness, csrf: Option<&str>) -> Reply {
        let mut builder = Request::builder()
            .method(self.method)
            .uri(format!("{TERMINAL}?{}", self.query));
        if self.upgrade {
            builder = builder
                .header(header::CONNECTION, "upgrade")
                .header(header::UPGRADE, "websocket")
                .header(header::SEC_WEBSOCKET_VERSION, "13")
                .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==");
        }
        if let Some(cookie) = self.cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        if let Some(origin) = self.origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        if let Some(protocols) = self.protocols {
            builder = builder.header(header::SEC_WEBSOCKET_PROTOCOL, protocols);
        }
        if let Some(line) = self.second_protocol_line {
            builder = builder.header(header::SEC_WEBSOCKET_PROTOCOL, line);
        }
        if let Some(csrf) = csrf {
            builder = builder.header("x-jaunt-csrf", csrf);
        }
        send(harness.router.clone(), builder.body(Body::empty()).unwrap()).await
    }
}

const PASSED_EVERY_CHECK: StatusCode = StatusCode::UPGRADE_REQUIRED;

#[tokio::test]
async fn a_ticket_is_issued_only_for_a_reachable_node_and_login_and_every_other_pair_gets_the_same_denial()
 {
    let stand = stand().await;
    let harness = &stand.harness;
    let issued = ticket(harness, &stand.alice, "web-01", LOGIN).await;
    assert_eq!(issued.len(), 43);
    assert_ne!(issued, ticket(harness, &stand.alice, "web-01", LOGIN).await);
    ticket(harness, &stand.alice, "web-01", "alice").await;
    ticket(harness, &stand.alice, "dev-01", "app").await;
    harness.admin.remove_node("web-02", APPROVER).await.unwrap();

    for (who, node, login) in [
        (&stand.alice, "web-01", "root"),
        (&stand.alice, "dev-01", LOGIN),
        (&stand.alice, "absent", LOGIN),
        (&stand.alice, "web-02", LOGIN),
        (&stand.bob, "dev-01", "app"),
        (&stand.carol, "web-01", LOGIN),
    ] {
        let reply = ticket_reply(harness, who, &json!({"node": node, "login": login})).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{node} {login}");
        assert_eq!(reply.error_code(), "denied", "{node} {login}");
    }
    for body in [
        json!({"node": "web-01"}),
        json!({"node": "web-01", "login": LOGIN, "extra": 1}),
        json!({"node": "Web-01", "login": LOGIN}),
        json!({"node": "web-01.jaunt.test", "login": LOGIN}),
        json!({"node": "web-01", "login": "-oProxyCommand=x"}),
        json!({"node": "web-01", "login": "Alice"}),
    ] {
        let reply = ticket_reply(harness, &stand.alice, &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
    }
    let forged = Browser {
        cookie: stand.alice.cookie.clone(),
        csrf: stand.bob.csrf.clone(),
    };
    let reply = ticket_reply(harness, &forged, &json!({"node": "web-01", "login": LOGIN})).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(stand.gate.connects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_handshake_refusal_happens_before_the_upgrade_and_leaves_the_ticket_usable() {
    let stand = stand().await;
    let harness = &stand.harness;
    let issued = ticket(harness, &stand.alice, "web-01", LOGIN).await;
    let alice = || Handshake::of(&stand.alice, &issued);
    let cases: Vec<(&str, Handshake<'_>, Option<&str>, StatusCode)> = vec![
        (
            "no cookie",
            Handshake {
                cookie: None,
                ..alice()
            },
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "a foreign origin",
            Handshake {
                origin: Some("https://evil.example"),
                ..alice()
            },
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "no origin",
            Handshake {
                origin: None,
                ..alice()
            },
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "another subprotocol",
            Handshake {
                protocols: Some(format!("jaunt-terminal.v2, jaunt-ticket.{issued}")),
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "an extra subprotocol",
            Handshake {
                protocols: Some(format!("jaunt-terminal.v1, chat, jaunt-ticket.{issued}")),
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "the ticket on a second protocol header line",
            Handshake {
                protocols: Some("jaunt-terminal.v1".to_owned()),
                second_protocol_line: Some(format!("jaunt-ticket.{issued}")),
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "no ticket",
            Handshake {
                protocols: Some("jaunt-terminal.v1".to_owned()),
                ..alice()
            },
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "another node",
            Handshake {
                query: "node=web-02&login=deploy&cols=80&rows=24",
                ..alice()
            },
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "another login",
            Handshake {
                query: "node=web-01&login=alice&cols=80&rows=24",
                ..alice()
            },
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "a login outside the grammar",
            Handshake {
                query: "node=web-01&login=Alice&cols=80&rows=24",
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "another web session",
            Handshake::of(&stand.bob, &issued),
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "a size out of bounds",
            Handshake {
                query: "node=web-01&login=deploy&cols=501&rows=24",
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
        (
            "a post",
            Handshake {
                method: Method::POST,
                ..alice()
            },
            Some(&stand.alice.csrf),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "not a websocket request",
            Handshake {
                upgrade: false,
                ..alice()
            },
            None,
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (name, handshake, csrf, status) in cases {
        let reply = handshake.send(harness, csrf).await;
        assert_eq!(reply.status, status, "{name}: {}", reply.text());
        assert!(
            reply.headers.get(header::SEC_WEBSOCKET_ACCEPT).is_none(),
            "{name}"
        );
    }
    let reply = alice().send(harness, None).await;
    assert_eq!(reply.status, PASSED_EVERY_CHECK, "{}", reply.text());
    assert_eq!(stand.gate.connects.load(Ordering::SeqCst), 0);
    assert_eq!(harness.control.web_terminal_counters().open, 0);
}

#[tokio::test]
async fn an_expired_ticket_a_removed_node_and_a_revoked_or_signed_out_user_are_refused() {
    let stand = stand().await;
    let harness = &stand.harness;

    let expiring = ticket(harness, &stand.alice, "web-01", LOGIN).await;
    harness.clock.advance(30);
    let reply = Handshake::of(&stand.alice, &expiring)
        .send(harness, None)
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let removed = ticket(harness, &stand.alice, "web-02", LOGIN).await;
    harness.admin.remove_node("web-02", APPROVER).await.unwrap();
    let reply = Handshake {
        query: "node=web-02&login=deploy&cols=80&rows=24",
        ..Handshake::of(&stand.alice, &removed)
    }
    .send(harness, None)
    .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.error_code(), "denied");

    let bobs = ticket(harness, &stand.bob, "web-01", LOGIN).await;
    let bob_id = user(harness, "bob", &["ops"]).await;
    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::User,
                subject: bob_id,
                reason: "test".to_owned(),
            },
            APPROVER,
        )
        .await
        .unwrap();
    let reply = Handshake::of(&stand.bob, &bobs).send(harness, None).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

    let before_logout = ticket(harness, &stand.alice, "web-01", LOGIN).await;
    let logout = Request::builder()
        .method(Method::POST)
        .uri("/v1/web/logout")
        .header(header::COOKIE, &stand.alice.cookie)
        .header("x-jaunt-csrf", &stand.alice.csrf)
        .header(header::ORIGIN, PUBLIC_ORIGIN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(harness.router.clone(), logout).await.status,
        StatusCode::NO_CONTENT
    );
    let reply = Handshake::of(&stand.alice, &before_logout)
        .send(harness, None)
        .await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(stand.gate.connects.load(Ordering::SeqCst), 0);
}

async fn targets(harness: &Harness, who: Option<&Browser>) -> Reply {
    let mut builder = Request::builder().method(Method::GET).uri(TARGETS);
    if let Some(who) = who {
        builder = builder.header(header::COOKIE, &who.cookie);
    }
    send(harness.router.clone(), builder.body(Body::empty()).unwrap()).await
}

#[tokio::test]
async fn targets_list_the_active_nodes_the_current_policy_reaches_with_their_logins() {
    let stand = stand().await;
    let harness = &stand.harness;
    harness.admin.remove_node("web-02", APPROVER).await.unwrap();

    let reply = targets(harness, Some(&stand.alice)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        reply.json(),
        json!([
            {"node": "dev-01", "labels": {"env": "dev"}, "connected": false, "logins": ["app"]},
            {"node": "web-01", "labels": {"env": "prod"}, "connected": false, "logins": ["alice", "deploy"]},
        ])
    );
    let reply = targets(harness, Some(&stand.bob)).await;
    assert_eq!(
        reply.json(),
        json!([{"node": "web-01", "labels": {"env": "prod"}, "connected": false, "logins": ["bob", "deploy"]}])
    );
    let dave = browser(harness, "Dave", &["ops"]).await;
    assert_eq!(
        targets(harness, Some(&dave)).await.json(),
        json!([{"node": "web-01", "labels": {"env": "prod"}, "connected": false, "logins": ["deploy"]}])
    );
    assert_eq!(targets(harness, Some(&stand.carol)).await.json(), json!([]));
    assert_eq!(
        targets(harness, None).await.status,
        StatusCode::UNAUTHORIZED
    );

    apply_policy(harness, &[ADMINS_ONLY.to_owned()]);
    assert_eq!(targets(harness, Some(&stand.alice)).await.json(), json!([]));
}

#[tokio::test]
async fn the_terminal_routes_are_absent_until_a_terminal_is_installed() {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    node(&harness, "web-01", "prod").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    let reply = ticket_reply(&harness, &alice, &json!({"node": "web-01", "login": LOGIN})).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(
        targets(&harness, Some(&alice)).await.status,
        StatusCode::NOT_FOUND
    );
    let reply = Handshake::of(&alice, &"a".repeat(43))
        .send(&harness, None)
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
