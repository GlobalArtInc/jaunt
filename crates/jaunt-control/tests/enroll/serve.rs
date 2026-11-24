use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use crate::flow::{assert_consistent, raw_pool, settled_snapshot};
use crate::support::{Harness, new_agent, sha256_hex};

async fn post(addr: std::net::SocketAddr, path: &str, body: &Value) -> (u16, Value) {
    let payload = serde_json::to_vec(body).unwrap();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: jaunt.test\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap())
}

#[tokio::test]
async fn enrolling_over_a_real_connection_records_the_peer_address() {
    let harness = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(harness.control.clone().serve(listener, async move {
        let _ = stopped.await;
    }));

    let (status, body) = post(addr, "/v1/agent/enroll", &new_agent().enroll_body("web-01")).await;
    let (poll_status, poll_body) = post(
        addr,
        "/v1/agent/enroll/poll",
        &json!({"handle": body["handle"]}),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!((poll_status, poll_body), (200, json!({"state": "pending"})));
    let handle = body["handle"].as_str().unwrap();
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&sha256_hex(handle))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.source_ip, "127.0.0.1");
    assert_eq!(stored.peer_addr, "127.0.0.1");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_that_hang_up_during_the_delivery_never_leave_an_enrollment_stuck() {
    let harness = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(harness.control.clone().serve(listener, async move {
        let _ = stopped.await;
    }));

    let mut enrollments = Vec::new();
    for n in 0..150 {
        let peer = format!("10.2.{}.{}", n / 200, n % 200 + 1);
        let enrolled = harness.enroll_from_peer(&peer, &format!("web-{n}")).await;
        harness.approve(&enrolled).await;
        let payload = serde_json::to_vec(&json!({"handle": enrolled.handle})).unwrap();
        let head = format!(
            "POST /v1/agent/enroll/poll HTTP/1.1\r\nHost: jaunt.test\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            payload.len()
        );
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(head.as_bytes()).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        drop(stream);
        enrollments.push(enrolled);
    }

    let pool = raw_pool(&harness).await;
    for enrolled in &enrollments {
        let snapshot = settled_snapshot(&pool, &harness, enrolled).await;
        assert_consistent(&snapshot, &enrolled.handle_hash());
    }
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
