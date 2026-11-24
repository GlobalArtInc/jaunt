use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::support::{Harness, LOGIN_TTL_SECS};

const RETENTION_SECS: u64 = 3600;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const DEADLINE: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn expired_login_requests_are_purged_only_after_the_retention_period() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    let requests = harness.store.login_requests();

    harness.clock.advance(LOGIN_TTL_SECS + RETENTION_SECS);
    assert_eq!(harness.control.purge_stored_requests().await.unwrap(), 0);
    assert!(requests.get(&session.login_id).await.unwrap().is_some());

    harness.clock.advance(1);
    assert_eq!(harness.control.purge_stored_requests().await.unwrap(), 1);
    assert!(requests.get(&session.login_id).await.unwrap().is_none());
    assert_eq!(harness.control.purge_stored_requests().await.unwrap(), 0);
}

async fn is_swept(harness: &Harness, login_id: &str) -> bool {
    let stored = harness.store.login_requests().get(login_id).await.unwrap();
    harness.control.pending_len() == 0 && stored.is_none()
}

async fn wait_until_swept(harness: &Harness, login_id: &str, what: &str) {
    let started = Instant::now();
    while !is_swept(harness, login_id).await {
        assert!(started.elapsed() < DEADLINE, "timed out waiting for {what}");
        tokio::task::yield_now().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_background_sweeper_runs_on_its_interval_and_shutdown_ends_serve() {
    let harness = Harness::new().await;
    let stale = harness.begin().await;
    harness.clock.advance(LOGIN_TTL_SECS + RETENTION_SECS + 1);
    assert_eq!(harness.control.pending_len(), 1);

    tokio::time::pause();
    let spinner = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(harness.control.clone().serve(listener, async move {
        let _ = stopped.await;
    }));
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(1)).await;
    wait_until_swept(&harness, &stale.login_id, "the first sweep").await;

    let fresh = harness.begin().await;
    harness.clock.advance(LOGIN_TTL_SECS + RETENTION_SECS + 1);
    for _ in 0..100 {
        tokio::task::yield_now().await;
    }
    assert!(!is_swept(&harness, &fresh.login_id).await);

    tokio::time::advance(SWEEP_INTERVAL).await;
    wait_until_swept(&harness, &fresh.login_id, "the interval sweep").await;

    stop.send(()).unwrap();
    let started = Instant::now();
    while !server.is_finished() {
        assert!(started.elapsed() < DEADLINE, "serve did not stop");
        tokio::task::yield_now().await;
    }
    server.await.unwrap().unwrap();
    spinner.abort();
}
