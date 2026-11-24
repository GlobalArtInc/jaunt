mod support;

use std::sync::Arc;

use http::{Method, StatusCode};
use jaunt_tunnel::{
    ClientError, ClientEvent, ConnectFailure, IncomingStream, SessionId, TunnelClient,
    TunnelClientConfig, agent_client_config,
};
use support::*;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

type Headers = Vec<(&'static str, Vec<u8>)>;
type Case = (&'static str, Method, &'static str, Headers, StatusCode);

fn headers(session: &[u8], kind: &[u8], client: &[u8]) -> Headers {
    vec![
        ("x-jaunt-session", session.to_vec()),
        ("x-jaunt-kind", kind.to_vec()),
        ("x-jaunt-client", client.to_vec()),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_rejects_bad_requests_before_they_reach_the_handler() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let (addr, gate_rx) = start_fake_gate(&pki).await;
    let waiting = handler(|stream: IncomingStream| async move {
        let mut io = stream.io;
        let mut byte = [0_u8; 1];
        drop(io.read(&mut byte).await);
    });
    let agent = spawn_agent(addr, &pki, &leaf, waiting, AgentOptions::default());
    let mut gate = gate_rx.await.unwrap();

    let mut doubled = headers(b"s1", b"ssh", b"203.0.113.9:1");
    doubled.push(("x-jaunt-session", b"s2".to_vec()));
    let mut without_session = headers(b"s1", b"ssh", b"203.0.113.9:1");
    without_session.remove(0);
    let long_session = vec![b'a'; 65];
    let long_client = vec![b'1'; 129];
    let cases: Vec<Case> = vec![
        (
            "valid",
            Method::POST,
            "/v1/stream",
            headers(b"ok-1", b"ssh", b"203.0.113.9:1"),
            StatusCode::OK,
        ),
        (
            "space in session",
            Method::POST,
            "/v1/stream",
            headers(b"bad id", b"ssh", b"203.0.113.9:1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "session too long",
            Method::POST,
            "/v1/stream",
            headers(&long_session, b"ssh", b"203.0.113.9:1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "missing session",
            Method::POST,
            "/v1/stream",
            without_session,
            StatusCode::BAD_REQUEST,
        ),
        (
            "duplicate session header",
            Method::POST,
            "/v1/stream",
            doubled,
            StatusCode::BAD_REQUEST,
        ),
        (
            "unknown kind",
            Method::POST,
            "/v1/stream",
            headers(b"s1", b"tcp", b"203.0.113.9:1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "client too long",
            Method::POST,
            "/v1/stream",
            headers(b"s1", b"ssh", &long_client),
            StatusCode::BAD_REQUEST,
        ),
        (
            "client not ascii",
            Method::POST,
            "/v1/stream",
            headers(b"s1", b"ssh", b"\xff\xfe"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "wrong method",
            Method::GET,
            "/v1/stream",
            headers(b"s1", b"ssh", b"203.0.113.9:1"),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "unknown path",
            Method::POST,
            "/v1/other",
            headers(b"s1", b"ssh", b"203.0.113.9:1"),
            StatusCode::NOT_FOUND,
        ),
    ];
    for (name, method, path, request_headers, expected) in cases {
        let borrowed: Vec<(&str, &[u8])> = request_headers
            .iter()
            .map(|(key, value)| (*key, value.as_slice()))
            .collect();
        let (status, _send) = gate.request(method, path, &borrowed, true).await;
        assert_eq!(status, expected, "{name}");
    }
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_refuses_a_repeated_session_and_a_second_control_stream() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let (addr, gate_rx) = start_fake_gate(&pki).await;
    let waiting = handler(|stream: IncomingStream| async move {
        let mut io = stream.io;
        let mut byte = [0_u8; 1];
        drop(io.read(&mut byte).await);
    });
    let agent = spawn_agent(addr, &pki, &leaf, waiting, AgentOptions::default());
    let mut gate = gate_rx.await.unwrap();

    let first_headers = headers(b"dup", b"ssh", b"203.0.113.9:1");
    let borrowed: Vec<(&str, &[u8])> = first_headers
        .iter()
        .map(|(key, value)| (*key, value.as_slice()))
        .collect();
    let (status, held) = gate
        .request(Method::POST, "/v1/stream", &borrowed, false)
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = gate
        .request(Method::POST, "/v1/stream", &borrowed, true)
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(agent.sessions.active(), [SessionId::new("dup").unwrap()]);
    drop(held);
    eventually("the held session to end", || {
        agent.sessions.active().is_empty()
    })
    .await;

    let (status, _control) = gate.request(Method::POST, "/v1/control", &[], false).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = gate.request(Method::POST, "/v1/control", &[], false).await;
    assert_eq!(status, StatusCode::CONFLICT);
    agent.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_refuses_to_start_with_an_unusable_identity() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let tls = Arc::new(agent_client_config(pki.roots(), leaf.chain.clone(), leaf.key()).unwrap());
    let cases = [
        ("not a name!", "agent/1", ClientError::InvalidServerName),
        (AGENT_SNI, "has space", ClientError::InvalidAgentVersion),
        (AGENT_SNI, "", ClientError::InvalidAgentVersion),
    ];
    for (sni, version, expected) in cases {
        let config = TunnelClientConfig::new(tls.clone(), "127.0.0.1:1", sni, version);
        let outcome = TunnelClient::run(config, idle_handler(), CancellationToken::new()).await;
        assert_eq!(outcome, Err(expected), "{sni} / {version}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_sends_goaway_when_it_shuts_down_normally() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let (addr, gate_rx) = start_fake_gate(&pki).await;
    let mut agent = spawn_agent(addr, &pki, &leaf, idle_handler(), AgentOptions::default());
    let gate = soon("the agent connection", gate_rx).await.unwrap();
    next_event(
        &mut agent.events,
        "the agent to serve the connection",
        |event| matches!(event, ClientEvent::Connected),
    )
    .await;
    assert!(gate.goaway_codes.lock().unwrap().is_empty());
    agent.stop().await;
    eventually("goaway from the agent", || {
        !gate.goaway_codes.lock().unwrap().is_empty()
    })
    .await;
    assert!(
        gate.goaway_codes
            .lock()
            .unwrap()
            .iter()
            .all(|code| *code == 0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_agent_reports_a_gate_that_negotiates_no_application_protocol() {
    let pki = Pki::new("ca");
    let leaf = pki.client_leaf("node-a");
    let addr = start_alpnless_gate(&pki).await;
    let mut agent = spawn_agent(addr, &pki, &leaf, idle_handler(), AgentOptions::default());
    let event = next_event(&mut agent.events, "the connection failure", |event| {
        matches!(event, ClientEvent::ConnectFailed(_))
    })
    .await;
    assert_eq!(
        event,
        ClientEvent::ConnectFailed(ConnectFailure::UnexpectedProtocol)
    );
    agent.stop().await;
}
