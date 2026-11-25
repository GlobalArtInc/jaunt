use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{Method, Request, StatusCode, header};
use jaunt_store::{SessionEndReason, SessionState};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::stand::Stand;
use crate::support::Options;

const ORIGIN: &str = "https://jaunt.example.test";
const BUDGET: Duration = Duration::from_secs(1);
const NEVER: Duration = Duration::from_secs(3600);

async fn admin_call(
    stand: &Stand,
    cookie: &str,
    csrf: &str,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header("x-jaunt-csrf", csrf)
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(match body {
            Some(body) => Body::from(body.to_string()),
            None => Body::empty(),
        })
        .unwrap();
    let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = stand
        .harness
        .control
        .router()
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn listed<'a>(list: &'a Value, name: &str) -> &'a Value {
    list["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == name)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn removing_a_node_through_the_admin_api_drops_its_agent_and_live_session_within_a_second() {
    let stand = Stand::start_with(
        &["web-01", "web-02"],
        Options {
            web: true,
            reconcile_interval: Some(NEVER),
            session_sweep_interval: Some(NEVER),
            ..Options::default()
        },
    )
    .await;
    stand.grant_node_admin();
    let web = stand
        .harness
        .control
        .open_web_session(&stand.user_id)
        .await
        .unwrap();
    let call = |method, path: String, body| {
        let stand = &stand;
        let (cookie, csrf) = (web.cookie.clone(), web.csrf_token.clone());
        async move { admin_call(stand, &cookie, &csrf, method, &path, body).await }
    };
    let identity = stand.identity().await;
    let (_outer, inner) = stand.session(&identity, "web-01").await;
    let session_id = stand.nodes[0].log.last_authorized();
    let node_id = stand.nodes[0].node_id.clone();

    let (status, before) = call(Method::GET, "/v1/admin/nodes".to_owned(), None).await;
    assert_eq!(status, StatusCode::OK, "{before}");
    assert_eq!(listed(&before, "web-01")["connected"], true);

    let started = Instant::now();
    let (status, removed) = call(
        Method::DELETE,
        format!("/v1/admin/nodes/{node_id}"),
        Some(json!({"confirm_name": "web-01"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{removed}");
    assert_eq!(removed["sessions_closed"], 1);
    while stand.connected(0) || !inner.handle.is_closed() {
        assert!(
            started.elapsed() < BUDGET,
            "still up after {BUDGET:?}: tunnel {}, inner session closed {}",
            stand.connected(0),
            inner.handle.is_closed()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    eprintln!("node removal teardown: {:?}", started.elapsed());

    let stored = stand.stored(&session_id).await;
    assert_eq!(
        (stored.state, stored.end_reason),
        (SessionState::Ended, Some(SessionEndReason::NodeRemoved))
    );
    assert!(stand.connected(1));
    let (_, after) = call(Method::GET, "/v1/admin/nodes".to_owned(), None).await;
    let gone = listed(&after, "web-01");
    assert_eq!(
        (&gone["state"], &gone["connected"]),
        (&json!("removed"), &json!(false))
    );
    assert_eq!(listed(&after, "web-02")["connected"], true);
    stand.stop().await;
}
