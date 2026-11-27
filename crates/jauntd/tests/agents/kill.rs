use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use jaunt_control::{RevocationAdmin, RevokeRequest, system_clock};
use jaunt_proto::SessionEndOutcome;
use jaunt_store::{
    ActivateSession, NewCertificate, NewSession, NewUser, RevocationKind, SessionEndReason,
    SessionState, Store,
};
use jauntd::agents::{AgentServer, AgentServerParts, AgentsSettings};
use russh::ChannelMsg;
use tower::ServiceExt;

use crate::stand::{Inner, Outer, Stand};
use crate::support::{AGENTS_NAME, Harness, Options, PUBLIC_ORIGIN, eventually, unix_secs, within};

const KILL_BUDGET: Duration = Duration::from_secs(5);
const WATCH_BUDGET: Duration = Duration::from_millis(2500);
const IDLE: Duration = Duration::from_secs(3600);

fn inline_enforcement_only() -> Options {
    Options {
        revocation_watch_interval: Some(IDLE),
        reconcile_interval: Some(IDLE),
        ..Options::default()
    }
}

#[derive(Debug, Clone, Copy)]
struct Teardown {
    gate_end: Duration,
    both_ends: Duration,
}

async fn torn_down(
    started: Instant,
    budget: Duration,
    stand: &Stand,
    node: usize,
    session_id: &str,
    outer: Option<&Outer>,
    inner: &Inner,
) -> Teardown {
    let mut gate_end = None;
    loop {
        let outer_closed = outer.is_none_or(|outer| outer.handle.is_closed());
        if outer_closed && gate_end.is_none() {
            gate_end = Some(started.elapsed());
        }
        let agent_done = !stand.nodes[node].log.ends_of(session_id).is_empty();
        if outer_closed && agent_done && inner.handle.is_closed() {
            return Teardown {
                gate_end: gate_end.unwrap_or_default(),
                both_ends: started.elapsed(),
            };
        }
        assert!(
            started.elapsed() < budget,
            "not torn down within {budget:?}: gate {outer_closed}, agent {agent_done}, inner {}",
            inner.handle.is_closed()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn closed_as_revoked_with_the_late_report(stand: &Stand, node: usize, session_id: &str) {
    assert_eq!(
        stand.nodes[node].log.ends_of(session_id),
        [SessionEndOutcome::Recorded]
    );
    let stored = stand.stored(session_id).await;
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Revoked))
    );
    assert_eq!((stored.bytes_in, stored.bytes_out), (Some(0), Some(0)));
}

fn millis(durations: &[Duration]) -> Vec<u128> {
    durations.iter().map(Duration::as_millis).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_user_loses_the_live_session_on_both_ends_within_five_seconds_in_ten_runs() {
    let stand = Stand::start_with(&["web-01"], inline_enforcement_only()).await;
    let mut gate_ends = Vec::new();
    let mut both_ends = Vec::new();
    for _ in 0..10 {
        let identity = stand.identity().await;
        let (outer, inner) = stand.session(&identity, "web-01").await;
        let session_id = stand.nodes[0].log.last_authorized();
        assert_eq!(stand.stored(&session_id).await.state, SessionState::Active);

        let started = Instant::now();
        let revoked = stand.revoke(RevocationKind::User, &stand.user_id).await;
        let teardown = torn_down(
            started,
            KILL_BUDGET,
            &stand,
            0,
            &session_id,
            Some(&outer),
            &inner,
        )
        .await;

        gate_ends.push(teardown.gate_end);
        both_ends.push(teardown.both_ends);
        assert_eq!(revoked.terminated, 1);
        closed_as_revoked_with_the_late_report(&stand, 0, &session_id).await;
        let refused = stand.connect(&identity).await;
        assert!(refused.forward("web-01").await.is_err());
        stand
            .harness
            .control
            .revocations()
            .remove(&revoked.revocation.id, "cli:stand")
            .await
            .unwrap();
    }

    eprintln!(
        "user revocation, gate end ms: {:?}; both ends ms: {:?}",
        millis(&gate_ends),
        millis(&both_ends)
    );
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_serial_or_node_loses_its_session_and_every_new_connection() {
    for kind in [RevocationKind::Serial, RevocationKind::Node] {
        let stand = Stand::start_with(&["web-01"], inline_enforcement_only()).await;
        let identity = stand.identity().await;
        let spare = stand.identity().await;
        let (outer, mut inner) = stand.session(&identity, "web-01").await;
        let session_id = stand.nodes[0].log.last_authorized();
        let subject = match kind {
            RevocationKind::Serial => identity.serial.to_string(),
            _ => stand.nodes[0].node_id.clone(),
        };

        let started = Instant::now();
        let revoked = stand.revoke(kind, &subject).await;
        let tunnel_after_revoke = stand.connected(0);
        let gate_side = (kind == RevocationKind::Serial).then_some(&outer);
        let teardown = torn_down(
            started,
            KILL_BUDGET,
            &stand,
            0,
            &session_id,
            gate_side,
            &inner,
        )
        .await;

        eprintln!("{kind:?} revocation: {teardown:?}");
        assert_eq!(revoked.terminated, 1);
        inner.ended().await;
        closed_as_revoked_with_the_late_report(&stand, 0, &session_id).await;
        assert_eq!(tunnel_after_revoke, kind == RevocationKind::Serial);
        assert_eq!(stand.connected(0), kind == RevocationKind::Serial);
        let again = stand.connect(&identity).await;
        assert!(again.forward("web-01").await.is_err(), "{kind:?}");
        let other = stand.connect(&spare).await;
        let spare_opened = other.open(&spare, "web-01").await;
        assert_eq!(
            spare_opened.is_ok(),
            kind == RevocationKind::Serial,
            "{kind:?}"
        );
        stand.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_one_serial_leaves_the_connection_of_the_other_serial_alive() {
    let stand = Stand::start(&["web-01"]).await;
    let first = stand.identity().await;
    let second = stand.identity().await;
    let (first_outer, first_inner) = stand.session(&first, "web-01").await;
    let first_id = stand.nodes[0].log.last_authorized();
    let (second_outer, second_inner) = stand.session(&second, "web-01").await;
    let second_id = stand.nodes[0].log.last_authorized();

    let started = Instant::now();
    stand
        .revoke(RevocationKind::Serial, &first.serial.to_string())
        .await;
    torn_down(
        started,
        KILL_BUDGET,
        &stand,
        0,
        &first_id,
        Some(&first_outer),
        &first_inner,
    )
    .await;

    assert!(!second_outer.handle.is_closed());
    assert!(!second_inner.handle.is_closed());
    assert_eq!(stand.stored(&second_id).await.state, SessionState::Active);
    assert_eq!(second_inner.echo().await, b"ok\n");
    assert!(stand.nodes[0].log.ends_of(&second_id).is_empty());
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoked_user_loses_the_sessions_on_both_nodes() {
    let stand = Stand::start_with(&["web-01", "web-02"], inline_enforcement_only()).await;
    let identity = stand.identity().await;
    let (first_outer, first) = stand.session(&identity, "web-01").await;
    let (second_outer, second) = stand.session(&identity, "web-02").await;
    let ids = [
        stand.nodes[0].log.last_authorized(),
        stand.nodes[1].log.last_authorized(),
    ];

    let started = Instant::now();
    let revoked = stand.revoke(RevocationKind::User, &stand.user_id).await;
    torn_down(
        started,
        KILL_BUDGET,
        &stand,
        0,
        &ids[0],
        Some(&first_outer),
        &first,
    )
    .await;
    torn_down(
        started,
        KILL_BUDGET,
        &stand,
        1,
        &ids[1],
        Some(&second_outer),
        &second,
    )
    .await;

    assert_eq!(revoked.terminated, 2);
    for (node, session_id) in ids.iter().enumerate() {
        closed_as_revoked_with_the_late_report(&stand, node, session_id).await;
    }
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_still_waiting_for_authorize_is_closed_by_the_revocation() {
    let stand = Stand::start_with(&["web-01"], inline_enforcement_only()).await;
    let identity = stand.identity().await;
    let outer = stand.connect(&identity).await;
    let mut forward = outer.forward("web-01").await.unwrap();
    let routed = stand.sessions_of_user().await;
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].state, SessionState::Routed);

    let started = Instant::now();
    let revoked = stand.revoke(RevocationKind::User, &stand.user_id).await;
    while !outer.handle.is_closed() {
        assert!(
            started.elapsed() < KILL_BUDGET,
            "the gate kept the connection"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert_eq!(revoked.terminated, 1);
    let closed = stand.stored(&routed[0].id).await;
    assert_eq!(closed.end_reason, Some(SessionEndReason::Revoked));
    loop {
        match within("the forward to close", forward.wait()).await {
            Some(ChannelMsg::Close) | None => break,
            Some(_) => {}
        }
    }
    assert!(stand.nodes[0].log.ends_of(&routed[0].id).is_empty());
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_stream_dies_even_without_the_gate_side_of_the_killer() {
    let stand = Stand::start(&["web-01"]).await;
    stand.kill_without_the_gate();
    let identity = stand.identity().await;
    let (_outer, inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();

    let started = Instant::now();
    stand.revoke(RevocationKind::User, &stand.user_id).await;
    let teardown = torn_down(started, KILL_BUDGET, &stand, 0, &session_id, None, &inner).await;

    eprintln!("agent side only: {teardown:?}");
    closed_as_revoked_with_the_late_report(&stand, 0, &session_id).await;
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revocation_written_by_another_process_kills_within_about_a_second() {
    let stand = Stand::start(&["web-01"]).await;
    let identity = stand.identity().await;
    let (outer, inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();
    let other_store = Store::open(&stand.harness.db_path).await.unwrap();

    let started = Instant::now();
    let written = RevocationAdmin::new(other_store, system_clock())
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::Serial,
                subject: identity.serial.to_string(),
                reason: "from the command line".to_owned(),
            },
            "cli:root",
        )
        .await
        .unwrap();
    let refused_at = {
        let refused = stand.connect(&identity).await;
        assert!(refused.forward("web-01").await.is_err());
        started.elapsed()
    };
    let teardown = torn_down(
        started,
        WATCH_BUDGET,
        &stand,
        0,
        &session_id,
        Some(&outer),
        &inner,
    )
    .await;

    eprintln!("written elsewhere: refused after {refused_at:?}, {teardown:?}");
    assert_eq!(written.terminated, 0);
    closed_as_revoked_with_the_late_report(&stand, 0, &session_id).await;
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_that_registers_again_closes_the_sessions_it_never_reported() {
    let mut stand = Stand::start(&["web-01"]).await;
    let identity = stand.identity().await;
    let (_outer, inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();
    stand.backdate(&session_id, 10).await;
    stand.nodes[0].log.fall_silent();

    stand.restart_agent(0).await;

    let closed = stand
        .settles(&session_id, SessionEndReason::AgentRestarted)
        .await;
    assert_eq!(closed.state, SessionState::Ended);
    eventually("the client to lose the session", || {
        inner.handle.is_closed()
    })
    .await;
    assert!(stand.nodes[0].log.ends_of(&session_id).is_empty());
    let (_again, _fresh) = stand.session(&identity, "web-01").await;
    let fresh_id = stand.nodes[0].log.last_authorized();
    assert_eq!(stand.stored(&fresh_id).await.state, SessionState::Active);
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_starting_agent_server_closes_the_sessions_an_earlier_run_left_open() {
    let harness = Harness::start(Options::default()).await;
    let enrolled = harness.enroll("web-01").await;
    let store = &harness.store;
    let now = i64::try_from(unix_secs(SystemTime::now())).unwrap();
    let user_id = store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "alice".to_owned(),
                email: "alice@example.com".to_owned(),
                username: "alice".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            now,
        )
        .await
        .unwrap()
        .id;
    let serial = store.certificates().allocate_serial().await.unwrap();
    store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user_id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:alice@example.com:{serial}"),
            valid_after: now - 60,
            valid_before: now + 3600,
            issued_at: now,
            ca_fingerprint: None,
            host_trust_id: None,
            subject_fingerprint: None,
        })
        .await
        .unwrap();
    let routed = store
        .sessions()
        .create(
            &NewSession {
                user_id: user_id.clone(),
                serial,
                node_id: enrolled.node_id.clone(),
                ttl_secs: 60,
            },
            now,
        )
        .await
        .unwrap();
    store
        .sessions()
        .activate(ActivateSession {
            id: &routed.id,
            node_id: &enrolled.node_id,
            user_id: &user_id,
            serial,
            login: "deploy",
            max_duration_secs: 3600,
            pty: true,
            record_input: false,
            now,
        })
        .await
        .unwrap()
        .unwrap();

    let restarted = AgentServer::start(AgentServerParts::new(
        AgentsSettings {
            listen: "127.0.0.1:0".parse().unwrap(),
            server_name: AGENTS_NAME.to_owned(),
        },
        harness.control.clone(),
        store.clone(),
        Arc::new(SystemTime::now),
    ))
    .await
    .unwrap();

    let closed = store.sessions().get(&routed.id).await.unwrap().unwrap();
    assert_eq!(
        (closed.state, closed.end_reason),
        (SessionState::Ended, Some(SessionEndReason::AgentGone))
    );
    restarted.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sessions_of_an_agent_that_stays_away_are_closed_as_gone() {
    let mut stand = Stand::start_with(
        &["web-01"],
        Options {
            session_sweep_interval: Some(Duration::from_millis(100)),
            agent_gone_after: Some(Duration::from_millis(300)),
            ..Options::default()
        },
    )
    .await;
    let identity = stand.identity().await;
    let (_outer, _inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();
    stand.nodes[0].log.fall_silent();

    stand.stop_agent(0).await;

    let closed = stand
        .settles(&session_id, SessionEndReason::AgentGone)
        .await;
    assert_eq!(closed.state, SessionState::Ended);
    assert!(!stand.connected(0));
    stand.stop().await;
}

async fn terminate(stand: &Stand, session_id: &str) -> http::StatusCode {
    let opened = stand
        .harness
        .control
        .open_web_session(&stand.user_id)
        .await
        .unwrap();
    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/v1/admin/sessions/{session_id}/terminate"))
        .header(http::header::COOKIE, opened.cookie)
        .header("x-jaunt-csrf", opened.csrf_token)
        .header(http::header::ORIGIN, PUBLIC_ORIGIN)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"reason":"stand"}"#))
        .unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            40000,
        ))));
    stand
        .harness
        .control
        .router()
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_administrator_terminates_one_ssh_session_within_five_seconds_and_spares_the_rest() {
    let stand = Stand::start_with(
        &["web-01"],
        Options {
            web: true,
            ..inline_enforcement_only()
        },
    )
    .await;
    stand.grant_session_terminate();
    let identity = stand.identity().await;
    let (outer, inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();
    let (_other_outer, other_inner) = stand.session(&identity, "web-01").await;
    let other_id = stand.nodes[0].log.last_authorized();
    assert_ne!(session_id, other_id);

    let started = Instant::now();
    assert_eq!(
        terminate(&stand, &session_id).await,
        http::StatusCode::NO_CONTENT
    );
    let teardown = torn_down(started, KILL_BUDGET, &stand, 0, &session_id, None, &inner).await;

    eprintln!("terminate: {teardown:?}");
    let stored = stand.stored(&session_id).await;
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Ended, Some(SessionEndReason::Terminated))
    );
    assert!(!outer.handle.is_closed());
    assert!(!other_inner.handle.is_closed());
    assert_eq!(stand.stored(&other_id).await.state, SessionState::Active);
    assert_eq!(
        terminate(&stand, &session_id).await,
        http::StatusCode::NO_CONTENT
    );
    assert_eq!(stand.stored(&other_id).await.state, SessionState::Active);
    stand.stop().await;
}
