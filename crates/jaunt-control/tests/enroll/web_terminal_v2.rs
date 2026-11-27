use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use jaunt_audit::ScopedCapture;
use jaunt_control::{
    GateLink, GateRefusal, GateRequest, KillOrder, KillReason, KillScope, Labels, SessionKiller,
    TerminalGate, WebTerminalSettings,
};
use jaunt_proto::{AuthorizeDecision, BoxFuture, is_denial_reference};
use jaunt_store::{
    ActivateSession, AuditRecord, NewSession, SessionEndReason, SessionOrigin, SessionState,
};
use serde_json::{Value, json};

use crate::audit::{start_recording, take_recording};
use crate::session_support::{
    apply_policy, authorize, raw_pool, recorded_certificate, route, subject_fingerprint, user,
};
use crate::support::{APPROVER, Harness, Options, PUBLIC_ORIGIN, Reply, send};
use crate::web_signed::{issue, signed};
use crate::web_support::{Admin, Csrf, admin, call, get};

const ROLES: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  \
     members: { groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy, \"{username}\", \"x-{groups}\"] }\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: terminators }\nspec:\n  \
     members: { users: [approver@example.com] }\n  admin: [sessions.read, sessions.terminate, audit.read]\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: readers }\nspec:\n  \
     members: { users: [reader@example.com] }\n  admin: [sessions.read, audit.read]\n";

const TICKET: &str = "/v1/web/terminal/ticket";
const TARGETS: &str = "/v1/web/terminal/targets";
const RECENT: &str = "/v1/web/terminal/recent";
const LIMITS: &str = "/v1/web/terminal/limits";

struct NoGate;

impl TerminalGate for NoGate {
    fn host_name(&self) -> String {
        "gate.jaunt.test".to_owned()
    }

    fn connect(&self, _request: GateRequest) -> Result<GateLink, GateRefusal> {
        Err(GateRefusal::Busy)
    }
}

#[derive(Default)]
struct RecordingKiller(Mutex<Vec<KillOrder>>);

impl SessionKiller for RecordingKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(order.clone());
        Box::pin(async {})
    }
}

struct Browser {
    user_id: String,
    cookie: String,
    csrf: String,
}

async fn browser(harness: &Harness, subject: &str, groups: &[&str]) -> Browser {
    let user_id = user(harness, subject, groups).await;
    let opened = harness.control.open_web_session(&user_id).await.unwrap();
    Browser {
        user_id,
        cookie: opened.cookie,
        csrf: opened.csrf_token,
    }
}

async fn node(harness: &Harness, name: &str, env: &str) -> String {
    let enrolled = harness.enroll(name).await;
    let labels = Labels::new(BTreeMap::from([("env".to_owned(), env.to_owned())])).unwrap();
    harness
        .admin
        .approve(&enrolled.code, APPROVER, Some(labels))
        .await
        .unwrap();
    harness
        .store
        .nodes()
        .get_active_by_name(name)
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn stand(max_per_user: usize) -> Harness {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    harness.control.install_web_terminal(
        Arc::new(NoGate),
        WebTerminalSettings {
            max_per_user,
            ..WebTerminalSettings::default()
        },
    );
    harness
}

async fn web(
    harness: &Harness,
    who: &Browser,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, &who.cookie)
        .header("x-jaunt-csrf", &who.csrf)
        .header(header::ORIGIN, PUBLIC_ORIGIN);
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap())),
        None => {
            builder = builder.header(header::CONTENT_LENGTH, "0");
            builder.body(Body::empty())
        }
    }
    .unwrap();
    send(harness.router.clone(), request).await
}

fn target<'a>(listed: &'a Value, name: &str) -> &'a Value {
    listed
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["node"] == name)
        .unwrap_or_else(|| panic!("{name} is not a target: {listed}"))
}

#[tokio::test]
async fn targets_name_the_hidden_logins_up_to_eight_and_mark_only_the_users_own_pins() {
    let harness = stand(4).await;
    node(&harness, "web-01", "prod").await;
    node(&harness, "web-02", "prod").await;
    let groups = ["ops", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9"];
    let odd = browser(&harness, "Rozmarin", &groups).await;
    let bob = browser(&harness, "bob", &["ops"]).await;

    let pinned = web(&harness, &odd, Method::PUT, "/v1/web/pins/web-02", None).await;
    assert_eq!(pinned.status, StatusCode::NO_CONTENT, "{}", pinned.text());

    let listed = web(&harness, &odd, Method::GET, TARGETS, None).await.json();
    let mut dropped: Vec<String> = groups[1..]
        .iter()
        .map(|group| format!("x-{group}"))
        .collect();
    dropped.push("Rozmarin".to_owned());
    dropped.sort();
    dropped.truncate(8);
    for name in ["web-01", "web-02"] {
        let shown = target(&listed, name);
        assert_eq!(shown["logins"], json!(["deploy", "x-ops"]));
        assert_eq!(shown["hidden_logins"], json!(dropped));
        assert_eq!(shown["pinned"], name == "web-02");
    }
    let listed = web(&harness, &bob, Method::GET, TARGETS, None).await.json();
    let shown = target(&listed, "web-02");
    assert_eq!(shown["hidden_logins"], json!([]));
    assert_eq!(shown["pinned"], false);
}

#[tokio::test]
async fn pins_are_idempotent_need_csrf_hide_unseen_nodes_and_stop_at_fifty_active_ones() {
    let harness = stand(4).await;
    let web_01 = node(&harness, "web-01", "prod").await;
    node(&harness, "dev-01", "dev").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    let pin = |method: Method, name: &str| {
        let path = format!("/v1/web/pins/{name}");
        let alice = &alice;
        let harness = &harness;
        async move { web(harness, alice, method, &path, None).await.status }
    };

    assert_eq!(pin(Method::PUT, "web-01").await, StatusCode::NO_CONTENT);
    assert_eq!(pin(Method::PUT, "web-01").await, StatusCode::NO_CONTENT);
    assert_eq!(pin(Method::DELETE, "web-01").await, StatusCode::NO_CONTENT);
    assert_eq!(pin(Method::DELETE, "web-01").await, StatusCode::NO_CONTENT);
    for unseen in ["dev-01", "absent", "Web-01"] {
        assert_eq!(
            pin(Method::PUT, unseen).await,
            StatusCode::NOT_FOUND,
            "{unseen}"
        );
        assert_eq!(
            pin(Method::DELETE, unseen).await,
            StatusCode::NOT_FOUND,
            "{unseen}"
        );
    }
    let forged = Request::builder()
        .method(Method::PUT)
        .uri("/v1/web/pins/web-01")
        .header(header::COOKIE, &alice.cookie)
        .header(header::ORIGIN, PUBLIC_ORIGIN)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(harness.router.clone(), forged).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(
        harness
            .store
            .user_pins()
            .node_ids(&alice.user_id)
            .await
            .unwrap()
            .is_empty()
    );

    let raw = raw_pool(&harness).await;
    for index in 0..50 {
        let id = format!("filler-{index}");
        sqlx::query(
            "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, ssh_host_public_key, \
             tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, created_at) \
             VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)",
        )
        .bind(&id)
        .bind(&id)
        .execute(&raw)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_pins (user_id, node_id, created_at) VALUES (?, ?, 1)")
            .bind(&alice.user_id)
            .bind(&id)
            .execute(&raw)
            .await
            .unwrap();
    }
    let full = web(&harness, &alice, Method::PUT, "/v1/web/pins/web-01", None).await;
    assert_eq!(full.status, StatusCode::CONFLICT);
    assert_eq!(full.error_code(), "too_many_pins");
    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = 'filler-0'")
        .execute(&raw)
        .await
        .unwrap();
    assert_eq!(pin(Method::PUT, "web-01").await, StatusCode::NO_CONTENT);
    let listed = web(&harness, &alice, Method::GET, TARGETS, None)
        .await
        .json();
    assert_eq!(target(&listed, "web-01")["pinned"], true);
    assert!(
        harness
            .store
            .user_pins()
            .node_ids(&alice.user_id)
            .await
            .unwrap()
            .contains(&web_01)
    );
}

async fn web_session_at(
    harness: &Harness,
    user_id: &str,
    node_id: &str,
    login: &str,
    at: i64,
    origin: SessionOrigin,
) {
    let holder = recorded_certificate(
        harness,
        user_id,
        (at - 60, at + 3600),
        Some(subject_fingerprint()),
    )
    .await;
    let sessions = harness.store.sessions();
    let session = sessions
        .create(
            &NewSession {
                user_id: user_id.to_owned(),
                serial: i64::try_from(holder.serial).unwrap(),
                node_id: node_id.to_owned(),
                ttl_secs: 60,
            },
            at,
        )
        .await
        .unwrap();
    sessions
        .activate_as(
            ActivateSession {
                id: &session.id,
                node_id,
                user_id,
                serial: i64::try_from(holder.serial).unwrap(),
                login,
                max_duration_secs: 3600,
                pty: true,
                record_input: false,
                now: at,
            },
            origin,
        )
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn recent_pairs_are_the_users_own_still_allowed_web_terminals_newest_first_and_five_at_most()
{
    let harness = stand(4).await;
    let web_01 = node(&harness, "web-01", "prod").await;
    let web_02 = node(&harness, "web-02", "prod").await;
    let dev_01 = node(&harness, "dev-01", "dev").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    let bob = browser(&harness, "bob", &["ops"]).await;
    let now = harness.clock.now_secs();
    let ssh = SessionOrigin::Ssh;
    let web_origin = SessionOrigin::Web;
    for (node_id, login, at, origin) in [
        (&web_01, "deploy", now - 100, web_origin),
        (&web_02, "deploy", now - 90, web_origin),
        (&web_01, "alice", now - 80, web_origin),
        (&web_02, "alice", now - 70, web_origin),
        (&web_01, "x-ops", now - 60, web_origin),
        (&web_02, "x-ops", now - 50, web_origin),
        (&web_01, "deploy", now - 40, web_origin),
        (&dev_01, "deploy", now - 30, web_origin),
        (&web_01, "root", now - 20, web_origin),
        (&web_02, "deploy", now - 10, ssh),
    ] {
        web_session_at(&harness, &alice.user_id, node_id, login, at, origin).await;
    }
    web_session_at(&harness, &bob.user_id, &web_02, "bob", now - 5, web_origin).await;

    let recent = web(&harness, &alice, Method::GET, RECENT, None).await;
    assert_eq!(recent.status, StatusCode::OK, "{}", recent.text());
    let pairs: Vec<(String, String, i64)> = recent
        .json()
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| {
            (
                pair["node"].as_str().unwrap().to_owned(),
                pair["login"].as_str().unwrap().to_owned(),
                pair["last_at"].as_i64().unwrap(),
            )
        })
        .collect();
    let expected = [
        ("web-01", "deploy", now - 40),
        ("web-02", "x-ops", now - 50),
        ("web-01", "x-ops", now - 60),
        ("web-02", "alice", now - 70),
        ("web-01", "alice", now - 80),
    ];
    assert_eq!(
        pairs,
        expected.map(|(node, login, at)| (node.to_owned(), login.to_owned(), at))
    );
    assert_eq!(
        web(&harness, &bob, Method::GET, RECENT, None).await.json(),
        json!([{"node": "web-02", "login": "bob", "last_at": now - 5}])
    );
    harness.admin.remove_node("web-01", APPROVER).await.unwrap();
    let remaining = web(&harness, &alice, Method::GET, RECENT, None)
        .await
        .json();
    let nodes: Vec<&str> = remaining
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| pair["node"].as_str().unwrap())
        .collect();
    assert_eq!(nodes, ["web-02", "web-02", "web-02"]);
}

#[tokio::test]
async fn ticket_refusals_carry_a_reference_the_audit_search_finds_and_the_limit_counts_every_browser()
 {
    let harness = stand(2).await;
    let web_01 = node(&harness, "web-01", "prod").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    let laptop = browser(&harness, "alice", &["ops"]).await;
    let auditor = admin(&harness, "approver").await;
    let held = [
        harness
            .control
            .hold_web_terminal(&alice.user_id, "first", &web_01)
            .unwrap(),
        harness
            .control
            .hold_web_terminal(&laptop.user_id, "second", &web_01)
            .unwrap(),
    ];
    let capture = ScopedCapture::start();

    let limited = web(
        &harness,
        &laptop,
        Method::POST,
        TICKET,
        Some(&json!({"node": "web-01", "login": "deploy"})),
    )
    .await;
    let denied = web(
        &harness,
        &alice,
        Method::POST,
        TICKET,
        Some(&json!({"node": "web-01", "login": "root"})),
    )
    .await;
    let events = capture.finish().await;

    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let body = limited.json();
    assert_eq!(
        (
            body["error"].clone(),
            body["open"].clone(),
            body["max"].clone()
        ),
        (json!("limit"), json!(2), json!(2))
    );
    let limit_ref = body["ref"].as_str().unwrap().to_owned();
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.json()["error"], "denied");
    let denied_ref = denied.json()["ref"].as_str().unwrap().to_owned();
    for reference in [&limit_ref, &denied_ref] {
        assert!(is_denial_reference(reference), "{reference}");
    }
    assert_ne!(limit_ref, denied_ref);
    let records: Vec<AuditRecord> = events.iter().map(|event| event.to_record()).collect();
    let mut host_user = records[0].clone();
    host_user.id = "host-user-event".to_owned();
    host_user.event_type = "host_user.refused".to_owned();
    host_user.payload = r#"{"reason":"name_rule","ref":"H-9D0311FE"}"#.to_owned();
    harness
        .store
        .audit_events()
        .append(&[records, vec![host_user]].concat())
        .await
        .unwrap();

    let found = |query: String| {
        let harness = &harness;
        let auditor = &auditor;
        async move { get(harness, &format!("/v1/admin/audit?{query}"), auditor).await }
    };
    let by_limit = found(format!("ref={limit_ref}")).await.json();
    assert_eq!(
        by_limit["events"].as_array().unwrap().len(),
        1,
        "{by_limit}"
    );
    assert_eq!(by_limit["events"][0]["fields"]["reason"], "limit");
    let event_id = by_limit["events"][0]["id"].as_str().unwrap();
    assert_eq!(
        format!("D-{}", event_id[16..24].to_ascii_uppercase()),
        limit_ref
    );
    let by_denial = found(format!("ref={denied_ref}&type=terminal.denied"))
        .await
        .json();
    assert_eq!(by_denial["events"][0]["fields"]["reason"], "denied");
    assert!(
        found(format!("ref={denied_ref}&type=host_user."))
            .await
            .json()["events"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let by_account = found("ref=H-9D0311FE".to_owned()).await.json();
    assert_eq!(by_account["events"][0]["type"], "host_user.refused");
    for invalid in ["ref=D-0123abcd", "ref=Z-01234567", "ref=D-0123"] {
        let refused = found(invalid.to_owned()).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{invalid}");
        assert_eq!(refused.error_code(), "invalid_ref");
    }
    let twice = found(format!("ref={limit_ref}&ref={limit_ref}")).await;
    assert_eq!(twice.status, StatusCode::BAD_REQUEST);
    drop(held);
}

async fn open_session(harness: &Harness, user_id: &str) -> (String, u64) {
    let holder = recorded_certificate(
        harness,
        user_id,
        (
            harness.clock.now_secs() - 60,
            harness.clock.now_secs() + 3600,
        ),
        Some(subject_fingerprint()),
    )
    .await;
    let session_id = match route(harness, holder.route_to("web-01")).await {
        jaunt_proto::RouteDecision::Allow { session_id, .. } => session_id,
        other => panic!("the route was denied: {other:?}"),
    };
    (session_id, holder.serial)
}

#[tokio::test]
async fn terminate_needs_its_right_and_csrf_ends_exactly_one_session_and_audits_who_and_why() {
    let harness = stand(4).await;
    let node_id = node(&harness, "web-01", "prod").await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let alice = user(&harness, "alice", &["ops"]).await;
    let (target, _) = open_session(&harness, &alice).await;
    let (other, _) = open_session(&harness, &alice).await;
    let terminal = harness
        .control
        .hold_web_terminal(&alice, "browser", &node_id)
        .unwrap();
    terminal.routed(&target);
    let bystander = harness
        .control
        .hold_web_terminal(&alice, "browser", &node_id)
        .unwrap();
    bystander.routed(&other);
    let approver = admin(&harness, "approver").await;
    let reader = admin(&harness, "reader").await;
    let path = format!("/v1/admin/sessions/{target}/terminate");
    let reason = json!({"reason": "left open over the weekend"});
    let terminate = |who: &'static str, csrf: Csrf, body: Option<Value>| {
        let harness = &harness;
        let path = &path;
        let who: &Admin = if who == "approver" {
            &approver
        } else {
            &reader
        };
        async move { call(harness, Method::POST, path, Some(who), csrf, body.as_ref()).await }
    };

    assert_eq!(
        terminate("reader", Csrf::Valid, Some(reason.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        terminate("approver", Csrf::Missing, Some(reason.clone()))
            .await
            .status,
        StatusCode::FORBIDDEN
    );
    let long = json!({"reason": "x".repeat(201)});
    let refused = terminate("approver", Csrf::Valid, Some(long)).await;
    assert_eq!(
        (refused.status, refused.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_reason")
    );
    assert_eq!(
        harness
            .store
            .sessions()
            .get(&target)
            .await
            .unwrap()
            .unwrap()
            .state,
        SessionState::Routed
    );
    start_recording();
    let done = terminate("approver", Csrf::Valid, Some(reason.clone())).await;
    let events = take_recording();

    assert_eq!(done.status, StatusCode::NO_CONTENT, "{}", done.text());
    let stored = harness
        .store
        .sessions()
        .get(&target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Terminated))
    );
    assert_eq!(
        harness
            .store
            .sessions()
            .get(&other)
            .await
            .unwrap()
            .unwrap()
            .state,
        SessionState::Routed
    );
    assert_eq!(
        terminal.closed_with(),
        Some((Some(4004), Some("terminated")))
    );
    assert_eq!(bystander.closed_with(), None);
    let orders = killer.0.lock().unwrap().clone();
    assert_eq!(orders.len(), 1);
    assert_eq!(
        (&orders[0].scope, orders[0].reason, orders[0].sessions.len()),
        (&KillScope::Sessions, KillReason::Terminated, 1)
    );
    assert_eq!(orders[0].sessions[0].session_id, target);
    let terminated: Vec<_> = events
        .iter()
        .filter(|event| event.get("event").map(String::as_str) == Some("session.terminated"))
        .collect();
    assert_eq!(terminated.len(), 1);
    assert_eq!(terminated[0]["by"], approver.actor());
    assert_eq!(terminated[0]["reason"], "left open over the weekend");
    assert_eq!(terminated[0]["session_id"], target);
    assert_eq!(terminated[0]["user_id"], alice);

    let again = terminate("approver", Csrf::Valid, None).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT, "{}", again.text());
    assert_eq!(killer.0.lock().unwrap().len(), 2);
    let unknown = call(
        &harness,
        Method::POST,
        "/v1/admin/sessions/67e55044-10b1-426f-9247-bb680e5fe0c8/terminate",
        Some(&approver),
        Csrf::Valid,
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let signer = issue(&harness, &approver.user_id).await;
    start_recording();
    let by_signature = signed(
        &harness,
        &signer,
        Method::POST,
        &format!("/v1/admin/sessions/{other}/terminate"),
        None,
    )
    .await;
    let events = take_recording();
    assert_eq!(
        by_signature.status,
        StatusCode::NO_CONTENT,
        "{}",
        by_signature.text()
    );
    assert_eq!(
        bystander.closed_with(),
        Some((Some(4004), Some("terminated")))
    );
    let signed_event = events
        .iter()
        .find(|event| event.get("event").map(String::as_str) == Some("session.terminated"))
        .unwrap();
    assert_eq!(signed_event["by"], format!("signed:{}", approver.user_id));
    assert!(!signed_event.contains_key("reason"));
}

#[tokio::test]
async fn the_origin_is_web_only_for_a_certificate_a_live_terminal_holds_and_the_list_filters_it() {
    let harness = stand(4).await;
    let node_id = node(&harness, "web-01", "prod").await;
    let alice = user(&harness, "alice", &["ops"]).await;
    let bob = user(&harness, "bob", &["ops"]).await;
    let (from_web, web_serial) = open_session(&harness, &alice).await;
    let (from_ssh, ssh_serial) = open_session(&harness, &alice).await;
    let (foreign, foreign_serial) = open_session(&harness, &bob).await;
    let terminal = harness
        .control
        .hold_web_terminal(&alice, "browser", &node_id)
        .unwrap();
    terminal.certificate_issued(web_serial);
    let elsewhere = harness
        .control
        .hold_web_terminal(&alice, "browser", &node_id)
        .unwrap();
    elsewhere.certificate_issued(foreign_serial);
    let certificates = harness.store.certificates();
    for (session_id, user_id, serial) in [
        (&from_web, &alice, web_serial),
        (&from_ssh, &alice, ssh_serial),
        (&foreign, &bob, foreign_serial),
    ] {
        let stored = certificates
            .get(i64::try_from(serial).unwrap())
            .await
            .unwrap()
            .unwrap();
        let decision = authorize(
            &harness,
            &node_id,
            jaunt_proto::AuthorizeRequest {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                serial,
                key_id: stored.key_id,
                login: "deploy".to_owned(),
                client_addr: "203.0.113.7:50000".to_owned(),
                subject_fingerprint: stored.subject_fingerprint,
            },
        )
        .await;
        assert!(
            matches!(decision, AuthorizeDecision::Allow { .. }),
            "{decision:?}"
        );
    }
    let origin = |id: &String| {
        let harness = &harness;
        let id = id.clone();
        async move {
            harness
                .store
                .sessions()
                .get(&id)
                .await
                .unwrap()
                .unwrap()
                .origin
        }
    };
    assert_eq!(origin(&from_web).await, SessionOrigin::Web);
    assert_eq!(origin(&from_ssh).await, SessionOrigin::Ssh);
    assert_eq!(origin(&foreign).await, SessionOrigin::Ssh);

    let reader = admin(&harness, "reader").await;
    let listed = get(&harness, "/v1/admin/sessions?origin=web", &reader)
        .await
        .json();
    let ids: Vec<&str> = listed["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|session| session["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [from_web.as_str()]);
    assert_eq!(listed["sessions"][0]["origin"], "web");
    let ssh_only = get(&harness, "/v1/admin/sessions?origin=ssh", &reader)
        .await
        .json();
    assert_eq!(ssh_only["sessions"].as_array().unwrap().len(), 2);
    let invalid = get(&harness, "/v1/admin/sessions?origin=cli", &reader).await;
    assert_eq!(
        (invalid.status, invalid.error_code().as_str()),
        (StatusCode::BAD_REQUEST, "invalid_origin")
    );
}

#[tokio::test]
async fn the_limits_route_shows_the_configured_values_to_a_signed_in_browser_only() {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    harness.control.install_web_terminal(
        Arc::new(NoGate),
        WebTerminalSettings {
            max_per_user: 3,
            idle_timeout: std::time::Duration::from_secs(900),
            ..WebTerminalSettings::default()
        },
    );
    let alice = browser(&harness, "alice", &["ops"]).await;

    let shown = web(&harness, &alice, Method::GET, LIMITS, None).await;
    assert_eq!(shown.status, StatusCode::OK, "{}", shown.text());
    assert_eq!(
        shown.json(),
        json!({"max_per_user": 3, "idle_timeout_secs": 900})
    );
    let anonymous = Request::builder()
        .method(Method::GET)
        .uri(LIMITS)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        send(harness.router.clone(), anonymous).await.status,
        StatusCode::UNAUTHORIZED
    );
}

const ONLY_USERNAME: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: lab }\nspec:\n  \
     members: { groups: [lab] }\n  ssh: { nodes: { env: [lab] }, logins: [\"{username}\"] }\n";

#[derive(Default)]
struct Switchable {
    delivers: std::sync::atomic::AtomicBool,
    orders: std::sync::atomic::AtomicUsize,
}

impl SessionKiller for Switchable {
    fn kill<'a>(&'a self, _order: &'a KillOrder) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn kill_and_report<'a>(&'a self, _order: &'a KillOrder) -> BoxFuture<'a, bool> {
        self.orders
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let delivers = self.delivers.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move { delivers })
    }
}

#[tokio::test]
async fn a_node_reached_only_through_hidden_logins_is_listed_with_no_usable_login() {
    let harness = stand(4).await;
    apply_policy(&harness, &[ROLES.to_owned(), ONLY_USERNAME.to_owned()]);
    node(&harness, "lab-01", "lab").await;
    let odd = browser(&harness, "Rozmarin", &["lab"]).await;

    let listed = web(&harness, &odd, Method::GET, TARGETS, None).await.json();

    assert_eq!(
        listed,
        json!([{"node": "lab-01", "labels": {"env": "lab"}, "connected": false,
                "creates_accounts": false, "logins": [], "hidden_logins": ["Rozmarin"],
                "pinned": false}])
    );
}

#[tokio::test]
async fn unclaimed_tickets_filling_the_table_refuse_without_terminal_counts() {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    harness.control.install_web_terminal(
        Arc::new(NoGate),
        WebTerminalSettings {
            max_tickets: 1,
            ..WebTerminalSettings::default()
        },
    );
    node(&harness, "web-01", "prod").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    let bob = browser(&harness, "bob", &["ops"]).await;
    let target = json!({"node": "web-01", "login": "deploy"});

    let first = web(&harness, &alice, Method::POST, TICKET, Some(&target)).await;
    let full = web(&harness, &bob, Method::POST, TICKET, Some(&target)).await;

    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    assert_eq!(full.status, StatusCode::TOO_MANY_REQUESTS);
    let body = full.json();
    assert_eq!(body["error"], "limit");
    assert!(is_denial_reference(body["ref"].as_str().unwrap()), "{body}");
    assert!(
        body.get("open").is_none() && body.get("max").is_none(),
        "{body}"
    );
}

#[tokio::test]
async fn pins_are_absent_while_no_terminal_is_installed() {
    let harness = Harness::with(Options {
        web: true,
        ..Options::default()
    })
    .await;
    apply_policy(&harness, &[ROLES.to_owned()]);
    node(&harness, "web-01", "prod").await;
    let alice = browser(&harness, "alice", &["ops"]).await;
    for method in [Method::PUT, Method::DELETE] {
        let reply = web(
            &harness,
            &alice,
            method.clone(),
            "/v1/web/pins/web-01",
            None,
        )
        .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{method}");
    }
    assert!(
        harness
            .store
            .user_pins()
            .node_ids(&alice.user_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn without_a_session_killer_terminate_answers_unavailable_and_the_session_stays_open() {
    let harness = stand(4).await;
    node(&harness, "web-01", "prod").await;
    let alice = user(&harness, "alice", &["ops"]).await;
    let (session_id, _) = open_session(&harness, &alice).await;
    let approver = admin(&harness, "approver").await;

    let reply = call(
        &harness,
        Method::POST,
        &format!("/v1/admin/sessions/{session_id}/terminate"),
        Some(&approver),
        Csrf::Valid,
        None,
    )
    .await;

    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    let stored = harness
        .store
        .sessions()
        .get(&session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Routed, None)
    );
}

#[tokio::test]
async fn an_undelivered_terminate_says_so_and_the_stored_event_names_who_and_why() {
    let harness = stand(4).await;
    let node_id = node(&harness, "web-01", "prod").await;
    harness
        .control
        .install_session_killer(Arc::new(Switchable::default()));
    let alice = user(&harness, "alice", &["ops"]).await;
    let (unreached, _) = open_session(&harness, &alice).await;
    let (held, _) = open_session(&harness, &alice).await;
    let terminal = harness
        .control
        .hold_web_terminal(&alice, "browser", &node_id)
        .unwrap();
    terminal.routed(&held);
    let approver = admin(&harness, "approver").await;
    let terminate = |id: String, body: Value| {
        let harness = &harness;
        let approver = &approver;
        async move {
            call(
                harness,
                Method::POST,
                &format!("/v1/admin/sessions/{id}/terminate"),
                Some(approver),
                Csrf::Valid,
                Some(&body),
            )
            .await
        }
    };
    let capture = ScopedCapture::start();

    let not_delivered = terminate(unreached.clone(), json!({"reason": "node offline"})).await;
    let delivered = terminate(held.clone(), json!({})).await;
    let events = capture.finish().await;

    assert_eq!(not_delivered.status, StatusCode::ACCEPTED);
    assert_eq!(not_delivered.json(), json!({"delivered": false}));
    assert_eq!(
        delivered.status,
        StatusCode::NO_CONTENT,
        "{}",
        delivered.text()
    );
    assert_eq!(
        terminal.closed_with(),
        Some((Some(4004), Some("terminated")))
    );
    let stored: Vec<Value> = events
        .iter()
        .filter(|event| event.kind().name() == "session.terminated")
        .map(|event| {
            let record = event.to_record();
            let mut payload: Value = serde_json::from_str(&record.payload).unwrap();
            payload["session"] = json!(record.session_id);
            payload["actor"] = json!(record.actor);
            payload
        })
        .collect();
    assert_eq!(stored.len(), 2, "{stored:?}");
    assert_eq!(stored[0]["session"], unreached);
    assert_eq!(stored[0]["by"], approver.actor());
    assert_eq!(stored[0]["reason"], "node offline");
    assert_eq!(stored[0]["actor"], alice);
    assert_eq!(stored[1]["session"], held);
    assert_eq!(stored[1]["by"], approver.actor());
    assert!(stored[1].get("reason").is_none());
}

#[tokio::test]
async fn a_terminate_that_did_not_reach_the_node_can_be_sent_again_without_a_second_record() {
    let harness = stand(4).await;
    node(&harness, "web-01", "prod").await;
    let killer = Arc::new(Switchable::default());
    harness.control.install_session_killer(killer.clone());
    let alice = user(&harness, "alice", &["ops"]).await;
    let (target, _) = open_session(&harness, &alice).await;
    let (revoked, _) = open_session(&harness, &alice).await;
    harness
        .store
        .sessions()
        .close(
            jaunt_store::OpenSessions::OfId(&revoked),
            SessionEndReason::Revoked,
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    let approver = admin(&harness, "approver").await;
    let terminate = |id: String| {
        let harness = &harness;
        let approver = &approver;
        async move {
            call(
                harness,
                Method::POST,
                &format!("/v1/admin/sessions/{id}/terminate"),
                Some(approver),
                Csrf::Valid,
                Some(&json!({"reason": "first try"})),
            )
            .await
        }
    };
    let capture = ScopedCapture::start();

    let first = terminate(target.clone()).await;
    killer
        .delivers
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let (left, right) = tokio::join!(terminate(target.clone()), terminate(target.clone()));
    let other_reason = terminate(revoked.clone()).await;
    let events = capture.finish().await;

    assert_eq!(first.status, StatusCode::ACCEPTED);
    assert_eq!(first.json(), json!({"delivered": false}));
    assert_eq!(
        (left.status, right.status),
        (StatusCode::NO_CONTENT, StatusCode::NO_CONTENT)
    );
    assert_eq!(killer.orders.load(std::sync::atomic::Ordering::SeqCst), 3);
    assert_eq!(
        (other_reason.status, other_reason.error_code().as_str()),
        (StatusCode::CONFLICT, "already_ended")
    );
    let stored = harness
        .store
        .sessions()
        .get(&target)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Terminated))
    );
    let count = |name: &str| {
        events
            .iter()
            .filter(|event| {
                event.kind().name() == name && event.session_id() == Some(target.as_str())
            })
            .count()
    };
    assert_eq!((count("session.terminated"), count("session.end")), (1, 1));
}
