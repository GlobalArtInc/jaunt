use std::collections::BTreeSet;
use std::future::Future;
use std::net::SocketAddr;
use std::task::Poll;
use std::time::Duration;

use axum::extract::ConnectInfo;

use axum::http::{StatusCode, header};
use jaunt_proto::{
    AGENT_EVENTS_PATH, AGENT_SESSION_CHILD_PATH, ServiceKind, ServiceOutcome, SessionEndOutcome,
    is_kube_child_session_id,
};
use jaunt_record::{SessionKind as CastKind, SessionManifest};
use jaunt_store::{
    ChildOpened, NewRevocation, OpenChildSession, RevocationKind, SessionEndReason, SessionKind,
    SessionState,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::audit::{Captured, peek_recording, start_recording, take_recording};
use crate::recording_support::{
    Session as Recorded, cast_of, crafted, manifest_for, metadata_only as metadata_manifest, wire,
};
use crate::service_support::{
    KUBE, OPS_ROLE, Stand, TCP, X509, announce, approve, authorize_request, authorize_service,
    denied, end_service, kube_service, open, person, recording_stand, row, ssh_session, stand,
    stand_with_policy, web_recording_stand,
};
use crate::session_support::{apply_policy, holder, raw_pool, role};
use crate::support::{DEFAULT_PEER, Reply, request, request_raw, send};
use crate::web_support::{admin, get, post};

const STAGE: &str = "stage";
const COPY_AS_KUBE: &str = "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, \
    expires_at, authorized_at, kind, record, parent_session_id) SELECT ?1, user_id, serial, node_id, \
    'active', created_at, expires_at, authorized_at, 'kube', 1, ?2 FROM sessions WHERE id = ?3";
const UNKNOWN_PARENT: &str = "k-ffffffffffffffffffffffffffffffff";
const WATCHERS: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: watchers }\nspec:\n  \
    members: { users: [watcher@example.com] }\n  \
    admin: [sessions.read, sessions.terminate, recordings.read]\n";

fn kube_role(name: &str, group: &str, grant: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  \
         members: {{ groups: [{group}] }}\n  \
         kubernetes: {{ clusters: {{ env: [prod] }}, groups: [view]{grant} }}\n"
    )
}

fn body(parent: &str) -> Value {
    json!({
        "parent_session_id": parent, "namespace": "default", "pod": "web-0",
        "container": "app", "tty": true, "kind": "exec",
    })
}

async fn ask(stand: &Stand, node_id: &str, body: &Value) -> Reply {
    send(
        stand.harness.agent_router.clone(),
        request(AGENT_SESSION_CHILD_PATH, body, None, Some(node_id)),
    )
    .await
}

async fn grant(stand: &Stand, parent: &str) -> Value {
    let reply = ask(stand, &stand.node_id, &body(parent)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()
}

async fn child(stand: &Stand, parent: &str) -> String {
    grant(stand, parent).await["session_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn audited<'a>(recorded: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    recorded
        .iter()
        .filter(|event| event["target"] == "jaunt::audit" && event["event"] == name)
        .collect()
}

async fn other_node_parent(stand: &Stand, holder: &X509) -> String {
    let harness = &stand.harness;
    announce(harness, &stand.other_node_id, &[kube_service(STAGE)]).await;
    approve(harness, &stand.other_node_id, "kubernetes", STAGE).await;
    let id = "k-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    let decision = authorize_service(
        harness,
        &stand.other_node_id,
        authorize_request(holder, id, ServiceKind::Kubernetes, STAGE),
    )
    .await;
    assert_eq!(denied(&decision), None);
    id.to_owned()
}

fn killed(stand: &Stand) -> Vec<String> {
    stand
        .killer
        .orders()
        .into_iter()
        .flat_map(|order| order.sessions.into_iter().map(|session| session.session_id))
        .collect()
}

#[tokio::test]
async fn a_child_of_a_live_kube_session_gets_a_control_made_id_and_inherits_the_parent() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    start_recording();
    let granted = grant(&stand, &parent).await;
    let recorded = take_recording();

    let id = granted["session_id"].as_str().unwrap();
    assert!(is_kube_child_session_id(id), "{id}");
    assert_eq!(
        granted,
        json!({"session_id": id, "record": true, "record_input": true})
    );
    let (parent_row, child_row) = (
        row(&stand.harness, &parent).await,
        row(&stand.harness, id).await,
    );
    assert_eq!(
        (
            &child_row.user_id,
            child_row.serial,
            &child_row.node_id,
            child_row.origin
        ),
        (
            &parent_row.user_id,
            parent_row.serial,
            &parent_row.node_id,
            parent_row.origin
        )
    );
    assert_eq!(
        (
            &child_row.roles,
            &child_row.decision_hash,
            &child_row.service_name
        ),
        (
            &parent_row.roles,
            &parent_row.decision_hash,
            &parent_row.service_name
        )
    );
    assert_eq!(
        (
            child_row.kind,
            child_row.state,
            child_row.target.as_deref(),
            child_row.parent_session_id.as_deref()
        ),
        (
            SessionKind::Kube,
            SessionState::Active,
            Some("default/web-0/app"),
            Some(parent.as_str())
        )
    );
    let created = audited(&recorded, "session.child.created");
    assert_eq!(created.len(), 1);
    let fields: Vec<&str> = [
        "session_id",
        "parent_session_id",
        "user_id",
        "node_id",
        "kind",
        "namespace",
        "pod",
        "container",
        "tty",
        "record",
        "record_input",
    ]
    .iter()
    .map(|field| created[0][*field].as_str())
    .collect();
    assert_eq!(
        fields,
        [
            id,
            parent.as_str(),
            alice.user_id.as_str(),
            stand.node_id.as_str(),
            "exec",
            "default",
            "web-0",
            "app",
            "true",
            "true",
            "true"
        ]
    );

    let mut chosen = body(&parent);
    chosen["session_id"] = json!("kx-00000000000000000000000000000000");
    let refused = ask(&stand, &stand.node_id, &chosen).await;
    assert_eq!(
        (refused.status, refused.error_code()),
        (StatusCode::BAD_REQUEST, "invalid".to_owned())
    );
    assert_ne!(child(&stand, &parent).await, id);
}

#[tokio::test]
async fn every_refusal_answers_its_stable_code_and_audits_its_precise_reason() {
    let stand = stand_with_policy(&[OPS_ROLE.to_owned(), role("shell", "ops", false, false)]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let erin = holder(harness, "erin", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let foreign = other_node_parent(&stand, &alice).await;
    let ssh = ssh_session(&stand, &erin).await;
    let db = open(
        &stand,
        &alice,
        ServiceKind::Postgres,
        crate::service_support::DB,
    )
    .await;
    let tcp = open(&stand, &alice, ServiceKind::Tcp, TCP).await;
    let nested = child(&stand, &parent).await;
    let ended = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    end_service(harness, &stand.node_id, &ended, ServiceOutcome::Closed, 0).await;
    let with = |field: &str, value: Value| {
        let mut changed = body(&parent);
        changed[field] = value;
        changed
    };
    let cases = [
        ("extra field", with("command", json!("sh")), 400, "invalid"),
        (
            "bad namespace",
            with("namespace", json!("Default")),
            400,
            "invalid",
        ),
        ("bad pod", with("pod", json!("web_0")), 400, "invalid"),
        (
            "bad container",
            with("container", json!("a/b")),
            400,
            "invalid",
        ),
        ("bad parent id", body("../x"), 400, "invalid"),
        (
            "unknown parent",
            body(UNKNOWN_PARENT),
            404,
            "unknown_parent",
        ),
        ("foreign parent", body(&foreign), 404, "unknown_parent"),
        ("ssh parent", body(&ssh), 409, "not_kube"),
        ("db parent", body(&db), 409, "not_kube"),
        ("tcp parent", body(&tcp), 409, "not_kube"),
        ("child as parent", body(&nested), 409, "not_kube"),
        ("ended parent", body(&ended), 409, "parent_ended"),
    ];
    start_recording();
    let malformed = send(
        harness.agent_router.clone(),
        request_raw(
            AGENT_SESSION_CHILD_PATH,
            "application/json",
            b"{".to_vec(),
            None,
            Some(&stand.node_id),
        ),
    )
    .await;
    assert_eq!(
        (malformed.status, malformed.error_code()),
        (StatusCode::BAD_REQUEST, "invalid".to_owned())
    );
    for (label, request, status, code) in cases {
        let reply = ask(&stand, &stand.node_id, &request).await;
        assert_eq!(reply.status.as_u16(), status, "{label}: {}", reply.text());
        assert_eq!(reply.json(), json!({"error": code}), "{label}");
    }
    let recorded = take_recording();

    let refused = audited(&recorded, "session.child.refused");
    let reasons: BTreeSet<&str> = refused
        .iter()
        .map(|event| event["reason"].as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "malformed",
        "invalid_name",
        "invalid_parent",
        "unknown_parent",
        "foreign_parent",
        "not_kube",
        "nested_parent",
        "parent_ended",
    ]
    .into_iter()
    .collect();
    assert_eq!(reasons, expected);
    for event in &refused {
        assert_eq!(event["node_id"], stand.node_id);
        let named_parent = event.get("parent_session_id").map(String::as_str);
        match event["reason"].as_str() {
            "malformed" | "invalid_parent" => assert_eq!(named_parent, None),
            "foreign_parent" => assert_eq!(named_parent, Some(foreign.as_str())),
            "unknown_parent" => assert_eq!(named_parent, Some(UNKNOWN_PARENT)),
            _ => assert!(named_parent.is_some()),
        }
    }
    assert!(audited(&recorded, "session.child.created").is_empty());
}

#[tokio::test]
async fn a_revoked_user_gets_no_child_before_or_after_the_revocation_is_enforced() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind: RevocationKind::Serial,
                subject: alice.parent.to_string(),
                reason: "test".to_owned(),
                created_by: "cli:tester".to_owned(),
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    start_recording();
    let stored = ask(&stand, &stand.node_id, &body(&parent)).await;
    let recorded = take_recording();
    assert_eq!(
        (stored.status, stored.error_code()),
        (StatusCode::CONFLICT, "parent_ended".to_owned())
    );
    let refused = audited(&recorded, "session.child.refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["reason"], "revoked");
    assert_eq!(row(harness, &parent).await.state, SessionState::Active);

    harness
        .control
        .revocations()
        .revoke(
            &jaunt_control::RevokeRequest {
                kind: RevocationKind::User,
                subject: alice.user_id.clone(),
                reason: "test".to_owned(),
            },
            "cli:tester",
        )
        .await
        .unwrap();
    assert_eq!(row(harness, &parent).await.state, SessionState::Ended);
    let enforced = ask(&stand, &stand.node_id, &body(&parent)).await;
    assert_eq!(
        (enforced.status, enforced.error_code()),
        (StatusCode::CONFLICT, "parent_ended".to_owned())
    );
}

async fn fill(stand: &Stand, parent: &str, count: usize, next: &mut usize) {
    let sessions = stand.harness.store.service_sessions();
    for _ in 0..count {
        *next += 1;
        let id = format!("kx-{:032x}", *next);
        let opened = sessions
            .open_child(&OpenChildSession {
                id: &id,
                parent_id: parent,
                node_id: &stand.node_id,
                target: "default/web-0",
                tty: true,
                max_per_parent: 64,
                max_per_node: 512,
                now: stand.harness.clock.now_secs(),
            })
            .await
            .unwrap();
        assert!(matches!(opened, ChildOpened::Opened(_)), "{opened:?}");
    }
}

#[tokio::test]
async fn children_are_capped_at_64_per_parent_and_512_per_node() {
    let stand = stand().await;
    let alice = person(&stand.harness, "alice", &["ops"]).await;
    let mut parents = Vec::new();
    for _ in 0..9 {
        parents.push(open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await);
    }
    let mut next = 0;
    fill(&stand, &parents[0], 63, &mut next).await;
    child(&stand, &parents[0]).await;
    start_recording();
    let full_parent = ask(&stand, &stand.node_id, &body(&parents[0])).await;
    assert_eq!(
        (full_parent.status, full_parent.error_code()),
        (StatusCode::CONFLICT, "too_many_children".to_owned())
    );
    for parent in &parents[1..7] {
        fill(&stand, parent, 64, &mut next).await;
    }
    fill(&stand, &parents[7], 63, &mut next).await;
    child(&stand, &parents[7]).await;
    let full_node = ask(&stand, &stand.node_id, &body(&parents[8])).await;
    let recorded = take_recording();
    assert_eq!(
        (full_node.status, full_node.error_code()),
        (StatusCode::CONFLICT, "too_many_children".to_owned())
    );
    let reasons: Vec<&str> = audited(&recorded, "session.child.refused")
        .iter()
        .map(|event| event["reason"].as_str())
        .collect();
    assert_eq!(reasons, ["parent_cap", "node_cap"]);
}

#[tokio::test]
async fn the_child_route_is_limited_per_node_before_the_database_is_read() {
    let stand = stand().await;
    for attempt in 0..60 {
        let reply = ask(&stand, "ghost-node", &body(UNKNOWN_PARENT)).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{attempt}");
        assert_eq!(reply.error_code(), "node_removed");
    }
    let limited = ask(&stand, "ghost-node", &body(UNKNOWN_PARENT)).await;
    assert_eq!(
        (limited.status, limited.error_code()),
        (StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_owned())
    );
    assert_eq!(limited.headers[header::RETRY_AFTER], "1");
    let malformed = send(
        stand.harness.agent_router.clone(),
        request_raw(
            AGENT_SESSION_CHILD_PATH,
            "application/json",
            b"{".to_vec(),
            None,
            Some("ghost-node"),
        ),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::TOO_MANY_REQUESTS);
    let other = ask(&stand, &stand.node_id, &body(UNKNOWN_PARENT)).await;
    assert_eq!(other.status, StatusCode::NOT_FOUND);
    stand.harness.clock.advance(1);
    for attempt in 0..30 {
        let refilled = ask(&stand, "ghost-node", &body(UNKNOWN_PARENT)).await;
        assert_eq!(refilled.status, StatusCode::FORBIDDEN, "{attempt}");
    }
    let again = ask(&stand, "ghost-node", &body(UNKNOWN_PARENT)).await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_repeated_refusal_is_audited_once_per_node_and_reason_with_the_count_held_back() {
    let stand = stand().await;
    let refused = |recorded: &[Captured]| -> Vec<(String, String, String)> {
        audited(recorded, "session.child.refused")
            .iter()
            .map(|event| {
                (
                    event["node_id"].clone(),
                    event["reason"].clone(),
                    event["suppressed"].clone(),
                )
            })
            .collect()
    };
    start_recording();
    for node in [
        &stand.node_id,
        &stand.node_id,
        &stand.node_id,
        &stand.other_node_id,
    ] {
        let reply = ask(&stand, node, &body(UNKNOWN_PARENT)).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
    }
    let first = take_recording();
    let reason = "unknown_parent".to_owned();
    assert_eq!(
        refused(&first),
        [
            (stand.node_id.clone(), reason.clone(), "0".to_owned()),
            (stand.other_node_id.clone(), reason.clone(), "0".to_owned()),
        ]
    );
    stand.harness.clock.advance(10);
    start_recording();
    ask(&stand, &stand.node_id, &body(UNKNOWN_PARENT)).await;
    assert_eq!(
        refused(&take_recording()),
        [(stand.node_id.clone(), reason, "2".to_owned())]
    );
}

#[tokio::test]
async fn a_child_is_created_and_audited_once_even_when_the_agent_drops_the_request() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let mut asked = request(
        AGENT_SESSION_CHILD_PATH,
        &body(&parent),
        None,
        Some(&stand.node_id),
    );
    let peer: SocketAddr = format!("{DEFAULT_PEER}:40000").parse().unwrap();
    asked.extensions_mut().insert(ConnectInfo(peer));
    start_recording();
    let mut call = Box::pin(harness.agent_router.clone().oneshot(asked));
    let first = std::future::poll_fn(|context| Poll::Ready(call.as_mut().poll(context))).await;
    assert!(first.is_pending());
    drop(call);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while audited(&peek_recording(), "session.child.created").is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the dropped request created no child"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let recorded = take_recording();
    assert_eq!(audited(&recorded, "session.child.created").len(), 1);
    let (children,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE parent_session_id = ?")
            .bind(&parent)
            .fetch_one(&raw_pool(harness).await)
            .await
            .unwrap();
    assert_eq!(children, 1);
}

#[tokio::test]
async fn the_record_flags_follow_the_grant_the_parent_was_opened_with() {
    let roles = [
        OPS_ROLE.to_owned(),
        kube_role("quiet", "quiet", ", recordExec: false, recordInput: true"),
        kube_role("plain", "plain", ""),
    ];
    let stand = stand_with_policy(&roles).await;
    let harness = &stand.harness;
    let cases = [
        ("alice", "ops", "exec", (true, true)),
        ("alice", "ops", "attach", (true, true)),
        ("quinn", "quiet", "exec", (false, false)),
        ("quinn", "quiet", "attach", (false, false)),
        ("paul", "plain", "exec", (true, false)),
    ];
    let mut alices = None;
    for (subject, group, kind, (record, record_input)) in cases {
        let holder = person(harness, subject, &[group]).await;
        let parent = open(&stand, &holder, ServiceKind::Kubernetes, KUBE).await;
        let mut request = body(&parent);
        request["kind"] = json!(kind);
        let reply = ask(&stand, &stand.node_id, &request).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        let granted = reply.json();
        assert_eq!(
            (granted["record"].clone(), granted["record_input"].clone()),
            (json!(record), json!(record_input)),
            "{subject} {kind}"
        );
        if subject == "alice" {
            alices = Some((holder, parent));
        }
    }
    let (alice, opened_before) = alices.unwrap();
    apply_policy(
        harness,
        &[OPS_ROLE.replace("recordInput: true", "recordExec: false, recordInput: true")],
    );
    assert_eq!(grant(&stand, &opened_before).await["record"], json!(true));
    let opened_after = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    assert_eq!(grant(&stand, &opened_after).await["record"], json!(false));
}

async fn upload(stand: &Stand, node_id: &str, id: &str, login: &str) -> (Reply, Reply, Vec<u8>) {
    let alice = row(&stand.harness, id).await.user_id;
    let session = Recorded {
        id: id.to_owned(),
        node_id: row(&stand.harness, id).await.node_id,
        user_id: alice,
    };
    let chunk = crafted(id, 0, b"$ ls\r\nREADME\r\n", true);
    let mut manifest: SessionManifest = manifest_for(&session, std::slice::from_ref(&chunk));
    manifest.login = login.to_owned();
    let agent = stand.harness.agent_router.clone();
    let sent = send(
        agent.clone(),
        request(
            &format!("/v1/agent/recordings/{id}/chunks"),
            &wire(&chunk),
            None,
            Some(node_id),
        ),
    )
    .await;
    let completed = send(
        agent,
        request(
            &format!("/v1/agent/recordings/{id}/complete"),
            &json!({ "manifest": manifest }),
            None,
            Some(node_id),
        ),
    )
    .await;
    (sent, completed, cast_of(id, &[chunk]))
}

#[tokio::test]
async fn a_recording_is_taken_only_for_a_recording_child_of_the_uploading_node() {
    let roles = [
        OPS_ROLE.to_owned(),
        kube_role("quiet", "quiet", ", recordExec: false"),
    ];
    let stand = recording_stand(&roles).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let quinn = person(harness, "quinn", &["quiet"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let recording = child(&stand, &parent).await;
    let (sent, completed, _) = upload(&stand, &stand.node_id, &recording, "").await;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text());
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    assert!(
        harness
            .store
            .recordings()
            .get(&recording)
            .await
            .unwrap()
            .is_some_and(|stored| stored.state.is_stored())
    );

    let unrecorded_parent = open(&stand, &quinn, ServiceKind::Kubernetes, KUBE).await;
    let unrecorded = child(&stand, &unrecorded_parent).await;
    let mut no_tty = body(&parent);
    no_tty["tty"] = json!(false);
    let reply = ask(&stand, &stand.node_id, &no_tty).await;
    let metadata_only = reply.json()["session_id"].as_str().unwrap().to_owned();
    let foreign_parent = other_node_parent(&stand, &alice).await;
    let elsewhere = {
        let reply = ask(&stand, &stand.other_node_id, &body(&foreign_parent)).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
        reply.json()["session_id"].as_str().unwrap().to_owned()
    };
    let named_login = child(&stand, &parent).await;
    let pool = raw_pool(harness).await;
    let parentless = "kx-11111111111111111111111111111111".to_owned();
    let foreign_parented = "kx-22222222222222222222222222222222".to_owned();
    for (id, parent_id) in [
        (&parentless, None),
        (&foreign_parented, Some(foreign_parent.as_str())),
    ] {
        sqlx::query(COPY_AS_KUBE)
            .bind(id)
            .bind(parent_id)
            .bind(&parent)
            .execute(&pool)
            .await
            .unwrap();
    }
    start_recording();
    for (label, node_id, id, code) in [
        (
            "the id of the parent, which is not a child id",
            &stand.node_id,
            &parent,
            "session_unknown",
        ),
        (
            "a kube session without a parent under a child id",
            &stand.node_id,
            &parentless,
            "session_unknown",
        ),
        (
            "a child of this node whose parent is on another node",
            &stand.node_id,
            &foreign_parented,
            "session_unknown",
        ),
        (
            "a child of another node",
            &stand.node_id,
            &elsewhere,
            "session_unknown",
        ),
        (
            "record false",
            &stand.node_id,
            &unrecorded,
            "session_not_recordable",
        ),
        (
            "no terminal",
            &stand.node_id,
            &metadata_only,
            "session_not_recordable",
        ),
    ] {
        let (sent, _, _) = upload(&stand, node_id, id, "").await;
        assert_eq!(sent.error_code(), code, "{label}");
        let kept = harness.store.recordings().get(id).await.unwrap();
        assert!(
            kept.is_none_or(|recording| !recording.state.is_stored()),
            "{label}"
        );
    }
    let reasons: Vec<(Option<String>, String)> = audited(&take_recording(), "recording.rejected")
        .iter()
        .map(|event| (event.get("session_id").cloned(), event["reason"].clone()))
        .collect();
    for (id, reason) in [
        (None, "unknown_session"),
        (Some(&parentless), "wrong_kind"),
        (Some(&foreign_parented), "wrong_kind"),
        (Some(&elsewhere), "wrong_node"),
    ] {
        assert!(
            reasons.contains(&(id.cloned(), reason.to_owned())),
            "{id:?} {reason} {reasons:?}"
        );
    }
    let (_, completed, _) = upload(&stand, &stand.node_id, &named_login, "deploy").await;
    assert_eq!(completed.error_code(), "conflict");
    let mut no_tty_again = body(&parent);
    no_tty_again["tty"] = json!(false);
    let reply = ask(&stand, &stand.node_id, &no_tty_again).await;
    let metadata = reply.json()["session_id"].as_str().unwrap().to_owned();
    let mut manifest = metadata_manifest(
        &Recorded {
            id: metadata.clone(),
            node_id: stand.node_id.clone(),
            user_id: alice.user_id.clone(),
        },
        CastKind::Exec,
    );
    manifest.login = String::new();
    let completed = send(
        harness.agent_router.clone(),
        request(
            &format!("/v1/agent/recordings/{metadata}/complete"),
            &json!({ "manifest": manifest }),
            None,
            Some(&stand.node_id),
        ),
    )
    .await;
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    let (sent, _, _) = upload(&stand, &stand.other_node_id, &elsewhere, "").await;
    assert_eq!(sent.status, StatusCode::OK, "{}", sent.text());
}

#[tokio::test]
async fn the_admin_sessions_api_links_a_child_to_its_parent_and_plays_its_recording() {
    let stand = web_recording_stand(&[OPS_ROLE.to_owned(), WATCHERS.to_owned()]).await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let id = child(&stand, &parent).await;
    let (_, completed, cast) = upload(&stand, &stand.node_id, &id, "").await;
    assert_eq!(completed.status, StatusCode::OK, "{}", completed.text());
    let watcher = admin(harness, "watcher").await;

    let listed = get(harness, "/v1/admin/sessions", &watcher).await.json();
    let entry = |wanted: &str| {
        listed["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|session| session["id"] == wanted)
            .cloned()
            .unwrap()
    };
    let (listed_child, listed_parent) = (entry(&id), entry(&parent));
    assert_eq!(listed_child["parent_session_id"], json!(parent));
    assert_eq!(listed_child["target"], "default/web-0/app");
    assert_eq!(listed_child["recording"], "complete");
    assert_eq!(listed_parent["parent_session_id"], Value::Null);
    let card = get(harness, &format!("/v1/admin/sessions/{id}"), &watcher).await;
    assert_eq!(card.status, StatusCode::OK, "{}", card.text());
    assert_eq!(card.json()["parent_session_id"], json!(parent));
    let played = get(
        harness,
        &format!("/v1/admin/sessions/{id}/recording"),
        &watcher,
    )
    .await;
    assert_eq!(played.status, StatusCode::OK, "{}", played.text());
    assert_eq!(played.body, cast);

    let path = |session: &str| format!("/v1/admin/sessions/{session}/terminate");
    let refused = post(harness, &path(&id), &watcher, &json!({})).await;
    assert_eq!(
        (refused.status, refused.error_code()),
        (StatusCode::CONFLICT, "child_session".to_owned())
    );
    assert_eq!(row(harness, &id).await.state, SessionState::Active);
    let terminated = post(harness, &path(&parent), &watcher, &json!({})).await;
    assert!(terminated.status.is_success(), "{}", terminated.text());
    assert_eq!(
        row(harness, &id).await.end_reason,
        Some(SessionEndReason::Terminated)
    );
    assert_eq!(killed(&stand), [parent]);
}

#[tokio::test]
async fn cutting_a_kube_session_ends_its_children_with_its_reason_and_orders_only_the_parent() {
    for reason in [
        SessionEndReason::Revoked,
        SessionEndReason::AccessWithdrawn,
        SessionEndReason::NodeRemoved,
        SessionEndReason::Expired,
        SessionEndReason::AgentGone,
    ] {
        let stand = stand().await;
        let harness = &stand.harness;
        let alice = person(harness, "alice", &["ops"]).await;
        let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
        let first = child(&stand, &parent).await;
        let second = child(&stand, &parent).await;
        start_recording();
        match reason {
            SessionEndReason::Revoked => {
                let revoked = harness
                    .control
                    .revocations()
                    .revoke(
                        &jaunt_control::RevokeRequest {
                            kind: RevocationKind::User,
                            subject: alice.user_id.clone(),
                            reason: "test".to_owned(),
                        },
                        "cli:tester",
                    )
                    .await
                    .unwrap();
                assert_eq!(revoked.terminated, 1);
            }
            SessionEndReason::AccessWithdrawn => {
                apply_policy(
                    harness,
                    &[format!(
                        "{OPS_ROLE}  deny: {{ kubernetes: {{ clusters: {{ env: [prod] }} }} }}\n"
                    )],
                );
                let review = harness.control.review_access().await.unwrap();
                assert_eq!((review.checked, review.withdrawn), (1, 1));
            }
            SessionEndReason::NodeRemoved => {
                harness
                    .admin
                    .remove_node("svc-01", crate::support::APPROVER)
                    .await
                    .unwrap();
                let swept = harness.control.sweep_sessions().await.unwrap();
                assert_eq!(swept.node_removed, 1);
            }
            SessionEndReason::Expired => {
                harness.clock.advance(12 * 3600 + 301);
                let swept = harness.control.sweep_sessions().await.unwrap();
                assert_eq!(swept.expired, 1);
            }
            _ => {
                let closed = harness.control.agent_gone(&stand.node_id).await.unwrap();
                assert_eq!(closed, 1);
            }
        }
        let recorded = take_recording();
        for id in [&parent, &first, &second] {
            let closed = row(harness, id).await;
            assert_eq!(
                (closed.state, closed.end_reason),
                (SessionState::Ended, Some(reason)),
                "{reason:?} {id}"
            );
        }
        let ended: BTreeSet<&str> = audited(&recorded, "session.end")
            .iter()
            .filter(|event| event["outcome"] == reason.as_str())
            .map(|event| event["session_id"].as_str())
            .collect();
        assert!(
            ended.contains(first.as_str()) && ended.contains(second.as_str()),
            "{reason:?} {ended:?}"
        );
        assert_eq!(killed(&stand), std::slice::from_ref(&parent), "{reason:?}");
        let terminated: Vec<&str> = audited(&recorded, "session.terminated")
            .iter()
            .map(|event| event["session_id"].as_str())
            .collect();
        assert!(
            !terminated.contains(&first.as_str()) && !terminated.contains(&second.as_str()),
            "{reason:?}"
        );
    }
}

#[tokio::test]
async fn a_child_ends_through_service_end_and_once_more_after_its_parent_ended() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let own = child(&stand, &parent).await;
    let orphan = child(&stand, &parent).await;
    let node = stand.node_id.clone();
    let closed = ServiceOutcome::Closed;
    assert_eq!(
        end_service(harness, &node, &own, closed, 7).await,
        SessionEndOutcome::Recorded
    );
    assert_eq!(
        end_service(harness, &node, &own, closed, 7).await,
        SessionEndOutcome::Recorded
    );
    assert_eq!(
        end_service(harness, &stand.other_node_id, &orphan, closed, 7).await,
        SessionEndOutcome::Rejected
    );
    assert_eq!(row(harness, &orphan).await.state, SessionState::Active);

    start_recording();
    assert_eq!(
        end_service(harness, &node, &parent, closed, 9).await,
        SessionEndOutcome::Recorded
    );
    let recorded = take_recording();
    let swept = row(harness, &orphan).await;
    assert_eq!(
        (swept.state, swept.end_reason, swept.outcome),
        (
            SessionState::Ended,
            Some(SessionEndReason::ParentEnded),
            None
        )
    );
    assert!(
        audited(&recorded, "session.end")
            .iter()
            .any(|event| event["session_id"] == orphan && event["outcome"] == "parent_ended")
    );
    for _ in 0..2 {
        assert_eq!(
            end_service(harness, &node, &orphan, closed, 3).await,
            SessionEndOutcome::Recorded
        );
    }
    let reported = row(harness, &orphan).await;
    assert_eq!(
        (reported.outcome.as_deref(), reported.bytes_out),
        (Some("closed"), Some(3))
    );
    assert_eq!(
        end_service(harness, &node, &orphan, closed, 4).await,
        SessionEndOutcome::Rejected
    );
    let late = ask(&stand, &node, &body(&parent)).await;
    assert_eq!(late.error_code(), "parent_ended");
}

#[tokio::test]
async fn exec_events_are_accepted_under_a_child_id_of_this_node_only() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let id = child(&stand, &parent).await;
    let event = |seq: u64, name: &str| {
        json!({"events": [{"session_id": id, "seq": seq, "observed_at": 0, "name": name,
            "fields": {"namespace": "default", "pod": "web-0", "container": "app", "tty": true}}],
            "dropped": []})
    };
    let post_events = |node: String, batch: Value| async move {
        send(
            harness.agent_router.clone(),
            request(AGENT_EVENTS_PATH, &batch, None, Some(&node)),
        )
        .await
    };
    start_recording();
    let accepted = post_events(stand.node_id.clone(), event(1, "kube.exec.start")).await;
    let recorded = take_recording();
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());
    assert_eq!(accepted.json()["accepted"], 1);
    let written = audited(&recorded, "kube.exec.start");
    assert_eq!(written.len(), 1);
    assert_eq!(
        (
            written[0]["session_id"].as_str(),
            written[0]["user_id"].as_str()
        ),
        (id.as_str(), alice.user_id.as_str())
    );
    let foreign = post_events(stand.other_node_id.clone(), event(2, "kube.exec.end")).await;
    assert_eq!(foreign.status, StatusCode::BAD_REQUEST);
    end_service(harness, &stand.node_id, &parent, ServiceOutcome::Closed, 1).await;
    let after = post_events(stand.node_id.clone(), event(3, "kube.exec.end")).await;
    assert_eq!(after.json()["accepted"], 1, "{}", after.text());
}

#[tokio::test]
async fn the_sweep_ends_a_live_child_whose_parent_is_no_longer_live() {
    let stand = stand().await;
    let harness = &stand.harness;
    let alice = person(harness, "alice", &["ops"]).await;
    let parent = open(&stand, &alice, ServiceKind::Kubernetes, KUBE).await;
    let id = child(&stand, &parent).await;
    sqlx::query("UPDATE sessions SET state = 'ended', end_reason = 'revoked' WHERE id = ?")
        .bind(&parent)
        .execute(&raw_pool(harness).await)
        .await
        .unwrap();
    let swept = harness.control.sweep_sessions().await.unwrap();
    assert_eq!(swept.orphaned, 1);
    let ended = row(harness, &id).await;
    assert_eq!(
        (ended.state, ended.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Revoked))
    );
    assert_eq!(harness.control.sweep_sessions().await.unwrap().orphaned, 0);
    assert!(stand.killer.orders().is_empty());
}
