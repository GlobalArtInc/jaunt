use std::time::{Duration, Instant};

use axum::http::StatusCode;
use jaunt_store::EnrollmentState;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::session_support::{routed, scenario, stored};
use crate::support::{Enrolled, Harness};

const RETENTION_SECS: u64 = 3600;
const STALE_DELIVERY_SECS: u64 = 120;
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const DEADLINE: Duration = Duration::from_secs(60);

struct RunningServer {
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), jaunt_control::ControlError>>,
    spinner: JoinHandle<()>,
}

async fn serve_with_paused_time(harness: &Harness) -> RunningServer {
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
    tokio::time::advance(SWEEP_INTERVAL).await;
    RunningServer {
        stop,
        server,
        spinner,
    }
}

impl RunningServer {
    async fn shut_down(self) {
        self.stop.send(()).unwrap();
        self.server.await.unwrap().unwrap();
        self.spinner.abort();
    }
}

async fn begin_delivery_directly(harness: &Harness, enrolled: &Enrolled) {
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap();
    harness
        .store
        .enrollments()
        .begin_delivery(&stored.id, harness.clock.now_secs())
        .await
        .unwrap()
        .unwrap();
}

async fn state_of(harness: &Harness, enrolled: &Enrolled) -> EnrollmentState {
    harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap()
        .state
}

#[tokio::test]
async fn enrollments_are_purged_only_an_hour_after_they_expired() {
    let harness = Harness::new().await;
    let stale = harness.enroll("web-01").await;

    harness.clock.advance(900 + RETENTION_SECS);
    assert_eq!(harness.control.purge_stored_enrollments().await.unwrap(), 0);
    assert_eq!(harness.poll(&stale.handle).await.state(), "expired");

    harness.clock.advance(1);
    assert_eq!(harness.control.purge_stored_enrollments().await.unwrap(), 1);
    assert_eq!(
        harness.poll(&stale.handle).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_delivery_stuck_for_more_than_two_minutes_goes_back_to_approved_and_can_be_collected() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    harness.approve(&enrolled).await;
    begin_delivery_directly(&harness, &enrolled).await;

    harness.clock.advance(STALE_DELIVERY_SECS);
    assert_eq!(harness.control.recover_stale_deliveries().await.unwrap(), 0);
    assert_eq!(
        state_of(&harness, &enrolled).await,
        EnrollmentState::Delivering
    );
    harness.clock.advance(1);
    assert_eq!(harness.control.recover_stale_deliveries().await.unwrap(), 1);

    assert_eq!(
        state_of(&harness, &enrolled).await,
        EnrollmentState::Approved
    );
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "approved");
    assert_eq!(harness.control.recover_stale_deliveries().await.unwrap(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn the_background_sweeper_purges_stored_enrollments() {
    let harness = Harness::new().await;
    let stale = harness.enroll("web-01").await;
    harness.clock.advance(900 + RETENTION_SECS + 1);

    let running = serve_with_paused_time(&harness).await;

    let started = Instant::now();
    while harness.poll(&stale.handle).await.status != StatusCode::NOT_FOUND {
        assert!(
            started.elapsed() < DEADLINE,
            "the enrollment was not purged"
        );
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }
    running.shut_down().await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_background_sweeper_recovers_interrupted_deliveries() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    harness.approve(&enrolled).await;
    begin_delivery_directly(&harness, &enrolled).await;
    harness.clock.advance(STALE_DELIVERY_SECS + 1);

    let running = serve_with_paused_time(&harness).await;

    let started = Instant::now();
    while state_of(&harness, &enrolled).await != EnrollmentState::Approved {
        assert!(
            started.elapsed() < DEADLINE,
            "the delivery was not recovered"
        );
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }
    running.shut_down().await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_background_sweeper_purges_stale_routed_sessions() {
    let s = scenario().await;
    let session_id = routed(&s.harness, &s.alice).await;
    s.harness.clock.advance(60 + RETENTION_SECS + 1);

    let running = serve_with_paused_time(&s.harness).await;

    let started = Instant::now();
    while stored(&s.harness, &session_id).await.is_some() {
        assert!(
            started.elapsed() < DEADLINE,
            "the routed session was not purged"
        );
        tokio::time::advance(SWEEP_INTERVAL).await;
        tokio::task::yield_now().await;
    }
    running.shut_down().await;
}
