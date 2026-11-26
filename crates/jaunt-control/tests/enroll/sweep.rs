use std::time::{Duration, Instant};

use axum::http::StatusCode;
use jaunt_control::ControlError;
use jaunt_store::EnrollmentState;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::session_support::{routed, scenario, stored};
use crate::support::{Enrolled, Harness};

const RETENTION_SECS: u64 = 3600;
const STALE_DELIVERY_SECS: u64 = 120;
const SWEEP_INTERVAL: Duration = Duration::from_millis(20);
const POLL_EVERY: Duration = Duration::from_millis(10);
const DEADLINE: Duration = Duration::from_secs(30);

struct RunningServer {
    stop: oneshot::Sender<()>,
    server: JoinHandle<Result<(), ControlError>>,
}

async fn serve_sweeping_often(harness: &Harness) -> RunningServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(harness.control.clone().serve_with_sweep_interval(
        listener,
        async move {
            let _ = stopped.await;
        },
        SWEEP_INTERVAL,
    ));
    RunningServer { stop, server }
}

impl RunningServer {
    async fn shut_down(self) {
        self.stop.send(()).unwrap();
        self.server.await.unwrap().unwrap();
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

async fn wait_until_purged(harness: &Harness, enrolled: &Enrolled, what: &str) {
    let started = Instant::now();
    while harness.poll(&enrolled.handle).await.status != StatusCode::NOT_FOUND {
        assert!(started.elapsed() < DEADLINE, "{what} was not purged");
        tokio::time::sleep(POLL_EVERY).await;
    }
}

#[tokio::test]
async fn the_background_sweeper_purges_stored_enrollments_on_every_pass() {
    let harness = Harness::new().await;
    let first = harness.enroll("web-01").await;
    harness.clock.advance(900 + RETENTION_SECS + 1);

    let running = serve_sweeping_often(&harness).await;
    wait_until_purged(&harness, &first, "the enrollment stale before serving").await;

    let second = harness.enroll("web-02").await;
    assert_eq!(harness.poll(&second.handle).await.state(), "pending");
    harness.clock.advance(900 + RETENTION_SECS + 1);
    wait_until_purged(&harness, &second, "the enrollment gone stale while serving").await;

    running.shut_down().await;
}

#[tokio::test]
async fn the_background_sweeper_recovers_interrupted_deliveries() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    harness.approve(&enrolled).await;
    begin_delivery_directly(&harness, &enrolled).await;
    harness.clock.advance(STALE_DELIVERY_SECS + 1);

    let running = serve_sweeping_often(&harness).await;

    let started = Instant::now();
    while state_of(&harness, &enrolled).await != EnrollmentState::Approved {
        assert!(
            started.elapsed() < DEADLINE,
            "the delivery was not recovered"
        );
        tokio::time::sleep(POLL_EVERY).await;
    }
    running.shut_down().await;
}

#[tokio::test]
async fn the_background_sweeper_purges_stale_routed_sessions() {
    let s = scenario().await;
    let session_id = routed(&s.harness, &s.alice).await;
    s.harness.clock.advance(60 + RETENTION_SECS + 1);

    let running = serve_sweeping_often(&s.harness).await;

    let started = Instant::now();
    while stored(&s.harness, &session_id).await.is_some() {
        assert!(
            started.elapsed() < DEADLINE,
            "the routed session was not purged"
        );
        tokio::time::sleep(POLL_EVERY).await;
    }
    running.shut_down().await;
}

#[tokio::test]
async fn serving_with_a_zero_sweep_interval_is_refused() {
    let harness = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let served = tokio::time::timeout(
        DEADLINE,
        harness.control.clone().serve_with_sweep_interval(
            listener,
            std::future::ready(()),
            Duration::ZERO,
        ),
    )
    .await
    .expect("serving with a zero sweep interval neither returned nor refused");

    assert!(
        matches!(served, Err(ControlError::ZeroSweepInterval)),
        "a zero sweep interval was not refused"
    );
}
