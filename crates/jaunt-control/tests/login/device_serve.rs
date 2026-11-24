use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::support::{Harness, challenge_for};

const DEADLINE: Duration = Duration::from_secs(10);

fn http_post(addr: SocketAddr, path: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: jaunt.example\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn the_served_router_hands_the_tcp_peer_address_to_the_device_routes() {
    let harness = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(harness.control.clone().serve(listener, async move {
        let _ = stopped.await;
    }));
    let body = json!({
        "code_challenge": challenge_for(&harness.next_verifier()),
        "code_challenge_method": "S256",
    })
    .to_string();

    let response =
        tokio::task::spawn_blocking(move || http_post(addr, "/v1/login/device/start", &body))
            .await
            .unwrap();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let payload = response.split_once("\r\n\r\n").unwrap().1;
    let started: Value = serde_json::from_str(payload).unwrap();
    let stored = harness
        .store
        .login_requests()
        .get(started["login_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.requester_ip.as_deref(), Some("127.0.0.1"));

    stop.send(()).unwrap();
    tokio::time::timeout(DEADLINE, server)
        .await
        .expect("serve did not stop")
        .unwrap()
        .unwrap();
}
