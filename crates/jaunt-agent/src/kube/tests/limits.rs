use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use jaunt_proto::ServiceOutcome;

use super::support::{
    Alpn, CONFIGMAPS, Kube, Options, PODS, TestBody, USER_B, alice, body_text, h2, h2_request,
    message, write_all,
};
use crate::clock::Clock;
use crate::kube::{KUBE_LIMITS, KubeLimits};
use crate::testkit::{eventually, soon};

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

fn get(path: &str) -> http::Request<TestBody> {
    h2_request(Method::GET, path, TestBody::empty())
}

#[tokio::test]
async fn stalled_downloads_of_one_user_do_not_delay_another_users_small_object() {
    let kube_api = Kube::new().await;
    let produced = kube_api.api.serve_download(256 * 1024 * 1024);
    let mut stalled = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(stalled.take()).await;
    let mut held = Vec::new();
    for _ in 0..24 {
        let response = client
            .send_request(get(&format!("{CONFIGMAPS}/big")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        held.push(response);
    }
    let filled = 24 * u64::from(KUBE_LIMITS.stream_window);
    eventually(
        "every stalled stream to fill its window towards the agent",
        || produced.load(Ordering::SeqCst) >= filled,
    )
    .await;
    settled(&produced).await;
    let mut other = kube_api.open_as(USER_B, alice(), Alpn::H2).await;
    let mut other_client = h2(other.take()).await;
    let response = other_client
        .send_request(get(&format!("{CONFIGMAPS}/c")))
        .await
        .unwrap();
    let body = soon("the small object", response.into_body().collect())
        .await
        .unwrap()
        .to_bytes();
    assert!(body.starts_with(b"{\"kind\":\"Echo\""));
    assert_eq!(kube_api.handler.open_upstream_connections(), 1);
    drop(held);
    for session in [stalled, other] {
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn a_user_at_its_cap_gets_429_and_cannot_take_slots_from_another_user() {
    let limits = KubeLimits {
        api_connections: 1,
        api_streams_per_connection: 4,
        slots_per_user: 2,
        slots_per_connection: 32,
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let watch = format!("{PODS}?watch=1");
    let mut first = kube_api.open(alice(), Alpn::H2).await;
    let mut first_client = h2(first.take()).await;
    let mut second = kube_api.open(alice(), Alpn::H2).await;
    let mut second_client = h2(second.take()).await;
    let held = vec![
        first_client.send_request(get(&watch)).await.unwrap(),
        second_client.send_request(get(&watch)).await.unwrap(),
    ];
    assert!(
        held.iter()
            .all(|response| response.status() == StatusCode::OK)
    );
    for client in [&mut first_client, &mut second_client] {
        let response = client.send_request(get(&watch)).await.unwrap();
        assert_eq!(response.headers()["retry-after"], "1");
        let (status, body) = body_text(response).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        assert!(message(&body).contains("at most 2 per user"), "{body}");
    }
    let mut other = kube_api.open_as(USER_B, alice(), Alpn::H2).await;
    let mut other_client = h2(other.take()).await;
    for _ in 0..2 {
        let (status, _) = body_text(
            other_client
                .send_request(get(&format!("{CONFIGMAPS}/c")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    drop(held);
    for session in [first, second, other] {
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn one_connection_holds_at_most_its_own_share_of_the_users_slots() {
    let limits = KubeLimits {
        slots_per_user: 4,
        slots_per_connection: 1,
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let watch = format!("{PODS}?watch=1");
    let mut first = kube_api.open(alice(), Alpn::H2).await;
    let mut first_client = h2(first.take()).await;
    let held = first_client.send_request(get(&watch)).await.unwrap();
    assert_eq!(held.status(), StatusCode::OK);
    let (status, _) = body_text(first_client.send_request(get(&watch)).await.unwrap()).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let mut second = kube_api.open(alice(), Alpn::H2).await;
    let mut second_client = h2(second.take()).await;
    let (status, _) = body_text(
        second_client
            .send_request(get(&format!("{CONFIGMAPS}/c")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    drop(held);
    eventually("the watch to be closed upstream", || {
        kube_api.api.open_watches() == 0
    })
    .await;
    let (status, _) = body_text(
        first_client
            .send_request(get(&format!("{CONFIGMAPS}/c")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for session in [first, second] {
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn the_pool_is_bounded_and_a_watch_holds_its_slot_until_it_closes() {
    let limits = KubeLimits {
        api_connections: 1,
        api_streams_per_connection: 2,
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let watch = format!("{PODS}?watch=1");
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let client = h2(session.take()).await;
    let mut first = client.clone().send_request(get(&watch)).await.unwrap();
    let second = client.clone().send_request(get(&watch)).await.unwrap();
    assert_eq!(kube_api.handler.open_upstream_connections(), 1);
    let waiting_since = kube_api.clock.now();
    let waiting = tokio::spawn({
        let mut client = client.clone();
        let watch = watch.clone();
        async move { client.send_request(get(&watch)).await.unwrap() }
    });
    kube_api
        .clock
        .wait_for_sleeper(waiting_since + KUBE_LIMITS.slot_wait)
        .await;
    assert_eq!(kube_api.api.seen().len(), 2);
    kube_api.clock.advance(KUBE_LIMITS.slot_wait);
    let response = soon("the waiting watch", waiting).await.unwrap();
    assert_eq!(response.headers()["retry-after"], "1");
    let (status, body) = body_text(response).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    kube_api.api.watch_event("still-open").await;
    assert!(
        soon("a watch event", first.body_mut().frame())
            .await
            .is_some()
    );
    drop(first);
    let (status, _) = body_text(
        client
            .clone()
            .send_request(get(&format!("{CONFIGMAPS}/c")))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(kube_api.api.seen().len(), 3);
    assert_eq!(kube_api.handler.open_upstream_connections(), 1);
    drop(second);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_full_connection_to_the_api_makes_the_pool_open_another() {
    let limits = KubeLimits {
        api_connections: 2,
        api_streams_per_connection: 2,
        ..KUBE_LIMITS
    };
    let kube_api = Kube::with(Options {
        limits,
        ..Options::default()
    })
    .await;
    let watch = format!("{PODS}?watch=1");
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let mut held = Vec::new();
    for expected in [1, 1, 2, 2] {
        held.push(client.send_request(get(&watch)).await.unwrap());
        assert_eq!(kube_api.handler.open_upstream_connections(), expected);
    }
    drop(held);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_hundred_parallel_short_requests_on_one_connection_all_succeed() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let client = h2(session.take()).await;
    let requests: Vec<_> = (0..100)
        .map(|index| {
            let mut client = client.clone();
            tokio::spawn(async move {
                let response = client
                    .send_request(get(&format!("/apis/group{index}.example/v1")))
                    .await
                    .unwrap();
                body_text(response).await.0
            })
        })
        .collect();
    for request in requests {
        assert_eq!(
            soon("a parallel request", request).await.unwrap(),
            StatusCode::OK
        );
    }
    assert_eq!(kube_api.api.seen().len(), 100);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_silent_http1_client_is_closed_after_the_idle_time() {
    let kube_api = Kube::with(Options {
        limits: KubeLimits {
            idle_keep_alive: Duration::from_millis(200),
            ..KUBE_LIMITS
        },
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let _silent = session.take();
    assert_eq!(session.finished().await, ServiceOutcome::IdleTimeout);
}

#[tokio::test]
async fn an_http2_client_that_does_not_answer_pings_is_closed() {
    let kube_api = Kube::with(Options {
        limits: KubeLimits {
            ping_interval: Duration::from_millis(100),
            ping_timeout: Duration::from_millis(100),
            ..KUBE_LIMITS
        },
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut tls = session.take();
    write_all(
        &mut tls,
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
    )
    .await;
    eventually("the handler to close the connection", || {
        session.serving.is_finished()
    })
    .await;
    assert_eq!(session.finished().await, ServiceOutcome::IdleTimeout);
    drop(tls);
}
