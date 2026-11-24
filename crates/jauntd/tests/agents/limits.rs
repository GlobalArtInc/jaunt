use std::time::{Duration, Instant};

use http::{Method, Request, StatusCode};
use jaunt_tunnel::ALPN_AGENT_API;
use jauntd::agents::ApiLimits;
use tokio::io::AsyncWriteExt;

use crate::client::ApiClient;
use crate::support::*;

const GRACE: Duration = Duration::from_secs(5);
const PROMPTLY: Duration = Duration::from_secs(3);
const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const EMPTY_SETTINGS: &[u8] = &[0, 0, 0, 4, 0, 0, 0, 0, 0];

async fn harness_with(limits: ApiLimits) -> Harness {
    Harness::start(Options {
        api_limits: Some(limits),
        ..Options::default()
    })
    .await
}

fn patient() -> ApiLimits {
    ApiLimits {
        idle_timeout: Duration::from_secs(30),
        ..ApiLimits::default()
    }
}

async fn closed_after_sending(harness: &Harness, agent: &EnrolledAgent, bytes: &[&[u8]]) -> bool {
    let dialed = dial(harness, agent.chain.clone(), agent.key(), ALPN_AGENT_API).await;
    let mut stream = dialed.stream.unwrap();
    for chunk in bytes {
        stream.write_all(chunk).await.unwrap();
    }
    stream.flush().await.unwrap();
    closed_by_server(Dialed {
        local_addr: dialed.local_addr,
        stream: Ok(stream),
    })
    .await
}

#[tokio::test]
async fn api_sessions_of_a_removed_node_are_closed_by_the_reconciler() {
    let harness = Harness::start(Options::default()).await;
    let removed = harness.enroll("web-01").await;
    let kept = harness.enroll("web-02").await;
    let mut doomed = ApiClient::open(&harness, &removed).await;
    let mut survivor = ApiClient::open(&harness, &kept).await;
    for client in [&mut doomed, &mut survivor] {
        let reply = api_request(&mut client.sender, Method::GET, "/healthz", &[], None).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND);
    }

    harness
        .admin
        .remove_node(&removed.name, "cli:tester")
        .await
        .unwrap();

    within("the removed node's session to close", &mut doomed.ended)
        .await
        .unwrap();
    assert!(doomed.saw_only_graceful_goaway());
    let ended = audited("agent.disconnected", |event| {
        field(event, "event") == "agent.disconnected" && field(event, "node_id") == removed.node_id
    })
    .await;
    assert_eq!(field(&ended, "alpn"), "jaunt-agent/1");
    assert_eq!(field(&ended, "reason"), "removed");
    let reply = api_request(&mut survivor.sender, Method::GET, "/healthz", &[], None).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert!(survivor.goaway_codes.lock().unwrap().is_empty());
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn an_api_session_is_closed_at_its_maximum_lifetime_even_while_busy() {
    let harness = harness_with(ApiLimits {
        max_lifetime: Duration::from_millis(400),
        ..patient()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let client = ApiClient::open(&harness, &agent).await;
    let opened = Instant::now();

    let mut answered = 0_u32;
    loop {
        let Ok(mut ready) = client.sender.clone().ready().await else {
            break;
        };
        let request = Request::builder()
            .method(Method::GET)
            .uri(format!("https://{AGENTS_NAME}/healthz"))
            .body(())
            .unwrap();
        let Ok((response, _)) = ready.send_request(request, true) else {
            break;
        };
        match within("a busy request", response).await {
            Ok(response) => {
                assert_eq!(response.status(), StatusCode::NOT_FOUND);
                answered += 1;
            }
            Err(_) => break,
        }
    }

    assert!(answered > 1);
    assert!(opened.elapsed() < PROMPTLY);
    within("the session to close", client.ended).await.unwrap();
    let graceful = {
        let codes = client.goaway_codes.lock().unwrap();
        !codes.is_empty() && codes.iter().all(|code| *code == 0)
    };
    assert!(graceful);
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn a_stalled_request_is_cut_at_the_request_timeout_and_the_idle_clock_restarts_after_it() {
    let idle = Duration::from_secs(1);
    let harness = harness_with(ApiLimits {
        idle_timeout: idle,
        request_timeout: Duration::from_secs(2),
        ..ApiLimits::default()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let mut client = ApiClient::open(&harness, &agent).await;

    let stalled = client.stalled_renew().await;
    let started = Instant::now();
    let response = within("the stalled request", stalled.response)
        .await
        .unwrap();
    let finished = Instant::now();

    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(finished - started > idle);
    within("the idle session to close", &mut client.ended)
        .await
        .unwrap();
    let idle_after_request = finished.elapsed();
    assert!(idle_after_request >= idle / 2, "{idle_after_request:?}");
    assert!(idle_after_request <= idle * 3 / 2, "{idle_after_request:?}");
    assert!(client.saw_only_graceful_goaway());
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn silent_partial_and_idle_api_connections_are_closed() {
    let harness = harness_with(ApiLimits {
        preface_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_millis(500),
        ..ApiLimits::default()
    })
    .await;
    let agent = harness.enroll("web-01").await;

    for (label, bytes) in [
        ("silent", &[][..]),
        ("ten bytes of the preface", &[&CLIENT_PREFACE[..10]][..]),
    ] {
        let begun = Instant::now();
        assert!(
            closed_after_sending(&harness, &agent, bytes).await,
            "{label}"
        );
        assert!(begun.elapsed() < PROMPTLY, "{label}");
    }

    let mut client = ApiClient::open(&harness, &agent).await;
    let reply = api_request(&mut client.sender, Method::GET, "/healthz", &[], None).await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let idle_since = Instant::now();
    within("the idle connection to close", &mut client.ended)
        .await
        .unwrap();
    assert!(idle_since.elapsed() < PROMPTLY);
    assert!(client.saw_only_graceful_goaway());
    eventually("every session to end", || {
        harness.server.hub_stats().api_sessions_open == 0
    })
    .await;
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn the_api_advertises_its_stream_limit_and_refuses_an_oversized_header_list() {
    let harness = harness_with(patient()).await;
    let agent = harness.enroll("web-01").await;
    let dialed = dial(&harness, agent.chain.clone(), agent.key(), ALPN_AGENT_API).await;
    let (mut sender, mut connection) = h2::client::handshake(dialed.stream.unwrap()).await.unwrap();
    let reply = tokio::select! {
        reply = api_request(&mut sender, Method::GET, "/healthz", &[], None) => reply,
        ended = &mut connection => panic!("the connection ended: {ended:?}"),
    };
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(connection.max_concurrent_send_streams(), 32);

    let filler = "a".repeat(20 * 1024);
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("https://{AGENTS_NAME}/healthz"))
        .header("x-filler", filler)
        .body(())
        .unwrap();
    let mut ready = sender.clone().ready().await.unwrap();
    let (response, _) = ready.send_request(request, true).unwrap();
    let answered = tokio::select! {
        answered = response => answered,
        ended = &mut connection => panic!("the connection ended: {ended:?}"),
    };
    assert!(
        answered.as_ref().map_or(true, |response| response.status()
            == StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
        "{answered:?}"
    );
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn a_client_that_ignores_pings_is_dropped() {
    let harness = harness_with(ApiLimits {
        keepalive_interval: Duration::from_millis(200),
        keepalive_timeout: Duration::from_millis(200),
        ..patient()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let begun = Instant::now();

    assert!(closed_after_sending(&harness, &agent, &[CLIENT_PREFACE, EMPTY_SETTINGS]).await);

    assert!(begun.elapsed() < PROMPTLY);
    harness.server.shutdown(GRACE).await;
}

#[tokio::test]
async fn a_stream_left_open_after_goaway_is_cut_at_the_close_grace() {
    let harness = harness_with(ApiLimits {
        max_lifetime: Duration::from_millis(300),
        close_grace: Duration::from_millis(300),
        ..patient()
    })
    .await;
    let agent = harness.enroll("web-01").await;
    let client = ApiClient::open(&harness, &agent).await;
    let stalled = client.stalled_renew().await;
    let begun = Instant::now();

    within("the connection to be cut", client.ended)
        .await
        .unwrap();

    assert!(begun.elapsed() < PROMPTLY);
    assert!(!client.goaway_codes.lock().unwrap().is_empty());
    let cut = within("the stalled response", stalled.response).await;
    assert!(cut.is_err());
    harness.server.shutdown(GRACE).await;
}
