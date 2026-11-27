use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jaunt_proto::ServiceAnnouncement;
use jaunt_tunnel::{BoxFuture, ClientEvent, ConnectFailure};
use tokio::sync::{broadcast, mpsc};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{AnnounceTiming, Delivery, ServiceSink, announce_services, delivery_of};
use crate::run::api::ApiError;
use crate::testkit::soon;

const TIMING: AnnounceTiming = AnnounceTiming {
    first_retry: Duration::from_secs(5),
    max_retry: Duration::from_secs(20),
    call_timeout: Duration::from_secs(10),
};

const NEXT_LIMIT: Duration = Duration::from_secs(3600);

struct Scripted {
    replies: Mutex<VecDeque<Delivery>>,
    seen: mpsc::UnboundedSender<Instant>,
}

impl ServiceSink for Scripted {
    fn announce<'a>(&'a self, announcement: &'a ServiceAnnouncement) -> BoxFuture<'a, Delivery> {
        assert!(!announcement.ssh_enabled);
        self.seen.send(Instant::now()).unwrap();
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Delivery::Accepted);
        Box::pin(async move { reply })
    }
}

struct Running {
    events: broadcast::Sender<ClientEvent>,
    seen: mpsc::UnboundedReceiver<Instant>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

fn start(replies: Vec<Delivery>) -> Running {
    let (events, receiver) = broadcast::channel(16);
    let (sender, seen) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let task = tokio::spawn(announce_services(
        Arc::new(ServiceAnnouncement {
            ssh_enabled: false,
            services: Vec::new(),
        }),
        Arc::new(Scripted {
            replies: Mutex::new(replies.into()),
            seen: sender,
        }),
        receiver,
        TIMING,
        stop.clone(),
    ));
    Running {
        events,
        seen,
        stop,
        task,
    }
}

impl Running {
    async fn next(&mut self) -> Instant {
        tokio::time::timeout(NEXT_LIMIT, self.seen.recv())
            .await
            .expect("an announcement within the limit")
            .unwrap()
    }

    async fn quiet_for(&mut self, wait: Duration) {
        tokio::time::sleep(wait).await;
        assert!(self.seen.try_recv().is_err(), "an unexpected announcement");
    }

    async fn finish(self) {
        self.stop.cancel();
        soon("the announcer to stop", self.task).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn the_set_is_announced_once_per_connection() {
    let mut running = start(Vec::new());
    running
        .events
        .send(ClientEvent::ConnectFailed(ConnectFailure::Timeout))
        .unwrap();
    running.quiet_for(Duration::from_secs(60)).await;
    running.events.send(ClientEvent::Connected).unwrap();
    running.next().await;
    running.quiet_for(Duration::from_secs(3600)).await;
    running
        .events
        .send(ClientEvent::Disconnected {
            lasted: Duration::from_secs(1),
        })
        .unwrap();
    running.events.send(ClientEvent::Connected).unwrap();
    running.next().await;
    running.finish().await;
}

#[tokio::test(start_paused = true)]
async fn failures_are_retried_with_backoff_until_accepted_or_disconnected() {
    let mut running = start(vec![
        Delivery::Retry(None),
        Delivery::Retry(None),
        Delivery::Retry(Some(Duration::from_secs(12))),
        Delivery::Retry(None),
        Delivery::Retry(None),
        Delivery::Accepted,
        Delivery::Retry(None),
    ]);
    running.events.send(ClientEvent::Connected).unwrap();
    let mut at = running.next().await;
    for expected in [5, 10, 20, 20, 20] {
        let next = running.next().await;
        assert_eq!(next - at, Duration::from_secs(expected));
        at = next;
    }
    running.quiet_for(Duration::from_secs(600)).await;

    running.events.send(ClientEvent::Connected).unwrap();
    running.next().await;
    running
        .events
        .send(ClientEvent::Disconnected {
            lasted: Duration::from_secs(1),
        })
        .unwrap();
    running.quiet_for(Duration::from_secs(600)).await;
    running.finish().await;
}

#[tokio::test(start_paused = true)]
async fn a_refusal_or_an_old_control_plane_waits_for_the_next_connection() {
    let mut running = start(vec![
        Delivery::Refused("HTTP 422 (invalid_labels)".to_owned()),
        Delivery::Unsupported,
    ]);
    for _ in 0..2 {
        running.events.send(ClientEvent::Connected).unwrap();
        running.next().await;
        running.quiet_for(Duration::from_secs(600)).await;
    }
    running.finish().await;
}

#[test]
fn answers_are_sorted_into_retry_refusal_and_success() {
    let status = |status: u16, retry_after: Option<Duration>| ApiError::Status {
        status,
        code: "code".to_owned(),
        retry_after,
    };
    assert_eq!(delivery_of(Ok(())), Delivery::Accepted);
    assert_eq!(delivery_of(Err(status(404, None))), Delivery::Unsupported);
    assert_eq!(
        delivery_of(Err(status(429, Some(Duration::from_secs(9))))),
        Delivery::Retry(Some(Duration::from_secs(9)))
    );
    assert!(matches!(
        delivery_of(Err(status(422, None))),
        Delivery::Refused(reason) if reason.contains("422")
    ));
    assert!(matches!(
        delivery_of(Err(ApiError::NodeRemoved)),
        Delivery::Refused(_)
    ));
    for retried in [
        status(500, None),
        status(503, None),
        ApiError::CallTimeout,
        ApiError::ConnectTimeout,
        ApiError::Shutdown,
    ] {
        assert_eq!(delivery_of(Err(retried)), Delivery::Retry(None));
    }
}
