use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use jaunt_proto::ServiceOutcome;

use super::support::{
    Alpn, CONFIGMAPS, Kube, Options, PODS, Session, TestBody, USER_B, alice, body_text, h1,
    h1_request, h2, h2_request, pattern_sum,
};
use crate::clock::Clock;
use crate::kube::{KUBE_LIMITS, KubeLimits};
use crate::testkit::{eventually, soon};

const CUT: Duration = Duration::from_secs(1);
const TOTAL: u64 = 16 * 1024 * 1024;
const BOUND: u64 = 4 * 1024 * 1024;

async fn next_event(body: &mut Incoming) -> String {
    let frame = soon("a watch event", body.frame()).await.unwrap().unwrap();
    String::from_utf8(frame.into_data().unwrap().to_vec()).unwrap()
}

async fn ends_cleanly_within(body: &mut Incoming, limit: Duration) -> bool {
    tokio::time::timeout(limit, async {
        while let Some(frame) = body.frame().await {
            if frame.is_err() {
                return false;
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

async fn finishes_within(session: Session, limit: Duration) -> ServiceOutcome {
    tokio::time::timeout(limit, session.serving)
        .await
        .expect("the handler did not finish in time")
        .unwrap()
        .unwrap()
}

async fn settled(counter: &AtomicU64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last = counter.load(Ordering::SeqCst);
    let mut stable_since = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let current = counter.load(Ordering::SeqCst);
        if current != last {
            last = current;
            stable_since = Instant::now();
        } else if stable_since.elapsed() >= Duration::from_millis(300) {
            return last;
        }
        assert!(Instant::now() < deadline, "the stream never settled");
    }
}

#[tokio::test]
async fn a_watch_outlives_every_request_timeout_and_ends_within_a_second_of_cancellation() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{PODS}?watch=1"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    for round in 0..3 {
        kube_api.api.watch_event(&format!("event-{round}")).await;
        assert_eq!(next_event(&mut body).await, format!("event-{round}\n"));
        kube_api.clock.advance(KUBE_LIMITS.head_timeout * 2);
    }
    session.cancel.cancel();
    assert!(ends_cleanly_within(&mut body, CUT).await);
    assert_eq!(finishes_within(session, CUT).await, ServiceOutcome::Closed);
}

#[tokio::test]
async fn a_large_upload_is_streamed_with_backpressure() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut client = h1(session.take()).await;
    let produced = Arc::new(AtomicU64::new(0));
    let request = h1_request(
        Method::PUT,
        &format!("{CONFIGMAPS}/upload"),
        TestBody::generated(TOTAL, Arc::clone(&produced)),
    );
    let sending = tokio::spawn(client.send_request(request));
    eventually("the upload to reach the API", || {
        kube_api.api.seen().len() == 1 && produced.load(Ordering::SeqCst) >= 64 * 1024
    })
    .await;
    let stalled = settled(&produced).await;
    assert!(
        stalled < BOUND,
        "{stalled} bytes were taken while the API read nothing"
    );
    kube_api.api.open_uploads();
    let response = soon("the upload to finish", sending)
        .await
        .unwrap()
        .unwrap();
    let (status, body) = body_text(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("{{\"bytes\":{TOTAL},\"sum\":{}}}", pattern_sum(TOTAL))
    );
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_large_download_is_streamed_with_backpressure() {
    let kube_api = Kube::new().await;
    let produced = kube_api.api.serve_download(TOTAL);
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{CONFIGMAPS}/big"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stalled = settled(&produced).await;
    assert!(
        stalled < BOUND,
        "{stalled} bytes were produced while the client read nothing"
    );
    let mut body = response.into_body();
    let (mut bytes, mut sum) = (0_u64, 0_u64);
    while let Some(frame) = soon("the download", body.frame()).await {
        let data = frame.unwrap().into_data().unwrap();
        bytes += data.len() as u64;
        sum += data.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    }
    assert_eq!((bytes, sum), (TOTAL, pattern_sum(TOTAL)));
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_client_that_reads_nothing_for_the_progress_time_loses_only_its_stream() {
    let limits = KubeLimits {
        api_connections: 1,
        api_streams_per_connection: 1,
        progress_timeout: Duration::from_secs(30),
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let produced = kube_api.api.serve_download(TOTAL);
    let mut stalled = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(stalled.take()).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{CONFIGMAPS}/big"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    settled(&produced).await;
    kube_api
        .clock
        .advance(limits.progress_timeout + Duration::from_secs(1));
    let mut other = kube_api.open_as(USER_B, alice(), Alpn::H2).await;
    let mut other_client = h2(other.take()).await;
    let (status, _) = body_text(
        other_client
            .send_request(h2_request(
                Method::GET,
                &format!("{CONFIGMAPS}/c"),
                TestBody::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut body = response.into_body();
    let ended = soon("the stalled stream to fail", async {
        loop {
            match body.frame().await {
                Some(Ok(_)) => continue,
                Some(Err(_)) => return true,
                None => return false,
            }
        }
    })
    .await;
    assert!(
        ended,
        "the stalled response ended cleanly instead of being reset"
    );
    let (status, _) = body_text(
        client
            .send_request(h2_request(
                Method::GET,
                &format!("{CONFIGMAPS}/c"),
                TestBody::empty(),
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for session in [stalled, other] {
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn a_client_that_stops_sending_its_body_loses_the_request() {
    let limits = KubeLimits {
        progress_timeout: Duration::from_secs(30),
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    kube_api.api.open_uploads();
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    sender
        .send(bytes::Bytes::from_static(b"first part"))
        .await
        .unwrap();
    let sending = tokio::spawn(client.send_request(h2_request(
        Method::PUT,
        &format!("{CONFIGMAPS}/upload"),
        TestBody::Channel(receiver),
    )));
    eventually("the first part to reach the API", || {
        kube_api.api.upload_received() == 10
    })
    .await;
    let idle_deadline = kube_api.clock.now() + limits.progress_timeout;
    kube_api.clock.wait_for_sleeper(idle_deadline).await;
    kube_api.clock.advance(limits.progress_timeout);
    let response = soon("the stalled upload to be answered", sending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    eventually("the API to see the reset", || {
        kube_api.api.upload_failures() == 1
    })
    .await;
    drop(sender);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_followed_log_waits_for_its_head_without_the_head_timeout() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let asked_at = kube_api.clock.now();
    let following = tokio::spawn(client.send_request(h2_request(
        Method::GET,
        &format!("{PODS}/web/log?follow=true"),
        TestBody::empty(),
    )));
    eventually("the log request to reach the API", || {
        kube_api.api.seen().len() == 1
    })
    .await;
    assert!(
        !kube_api
            .clock
            .sleepers()
            .contains(&(asked_at + KUBE_LIMITS.head_timeout)),
        "a followed log has a head timeout"
    );
    kube_api.clock.advance(Duration::from_secs(70));
    kube_api.api.release_logs();
    let response = soon("the log head", following).await.unwrap().unwrap();
    let (status, body) = body_text(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "log line 1\n");
    session.cancel.cancel();
    session.finished().await;
}
