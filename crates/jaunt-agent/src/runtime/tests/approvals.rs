use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jaunt_proto::{NodeService, NodeServices, ServiceKind};
use jaunt_tunnel::{BoxFuture, ClientEvent, StreamKind};
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;

use super::support::{approved, fixed};
use crate::run::api::ApiError;
use crate::runtime::approvals::{
    APPROVAL_TIMING, ApprovalPoller, ApprovalProblem, ApprovalSource, ApprovalTiming, approved_of,
};
use crate::runtime::directory::ApprovedService;

fn listed(entries: &[(&str, ServiceKind, &str)]) -> NodeServices {
    NodeServices {
        services: entries
            .iter()
            .map(|(id, kind, name)| NodeService {
                id: (*id).to_owned(),
                kind: *kind,
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

fn grafana() -> NodeServices {
    listed(&[("id-grafana", ServiceKind::Tcp, "grafana")])
}

fn status(status: u16) -> ApiError {
    ApiError::Status {
        status,
        code: "test".to_owned(),
        retry_after: None,
    }
}

#[derive(Default)]
struct Scripted {
    replies: Mutex<VecDeque<Result<NodeServices, ApiError>>>,
    reads: AtomicUsize,
}

impl Scripted {
    fn reply(&self, reply: Result<NodeServices, ApiError>) {
        self.replies.lock().unwrap().push_back(reply);
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

impl ApprovalSource for Scripted {
    fn read(&self) -> BoxFuture<'_, Result<NodeServices, ApiError>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(status(500)));
        Box::pin(async move { reply })
    }
}

struct Polling {
    source: Arc<Scripted>,
    approved: watch::Receiver<Vec<ApprovedService>>,
    events: broadcast::Sender<ClientEvent>,
    announced: Arc<Notify>,
    stop: CancellationToken,
}

fn polling(timing: ApprovalTiming) -> Polling {
    let source = Arc::new(Scripted::default());
    let (approved, receiver) = watch::channel(Vec::new());
    let (events, subscribed) = broadcast::channel(8);
    let announced = Arc::new(Notify::new());
    let stop = CancellationToken::new();
    let poller = ApprovalPoller {
        source: source.clone(),
        approved,
        events: subscribed,
        announced: announced.clone(),
        sample: fixed(1.0),
        timing,
    };
    tokio::spawn(poller.run(stop.clone()));
    Polling {
        source,
        approved: receiver,
        events,
        announced,
        stop,
    }
}

async fn reads_reach(polling: &Polling, count: usize) {
    for _ in 0..1000 {
        if polling.source.reads() >= count {
            tokio::task::yield_now().await;
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!(
        "the poller read {} times, not {count}",
        polling.source.reads()
    );
}

const DAY: ApprovalTiming = ApprovalTiming {
    every_min: Duration::from_secs(86_400),
    every_max: Duration::from_secs(86_400),
};

#[tokio::test(start_paused = true)]
async fn the_set_is_read_on_connect_after_an_announcement_and_about_every_minute() {
    let polling = polling(APPROVAL_TIMING);
    polling.source.reply(Ok(grafana()));
    polling.events.send(ClientEvent::Connected).unwrap();
    reads_reach(&polling, 1).await;
    assert_eq!(
        *polling.approved.borrow(),
        [approved(StreamKind::Tcp, "grafana")]
    );
    polling.source.reply(Ok(listed(&[])));
    polling.announced.notify_one();
    reads_reach(&polling, 2).await;
    assert!(polling.approved.borrow().is_empty());

    tokio::time::sleep(APPROVAL_TIMING.every_max - Duration::from_secs(1)).await;
    assert_eq!(polling.source.reads(), 2);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(polling.source.reads(), 3);
    assert!(polling.approved.borrow().is_empty());
    polling.stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn an_old_control_plane_is_asked_again_only_after_a_reconnection() {
    for old in [404, 405] {
        let polling = polling(APPROVAL_TIMING);
        polling.source.reply(Ok(grafana()));
        polling.events.send(ClientEvent::Connected).unwrap();
        reads_reach(&polling, 1).await;
        assert_eq!(polling.approved.borrow().len(), 1);
        polling.source.reply(Err(status(old)));
        polling.announced.notify_one();
        reads_reach(&polling, 2).await;
        assert!(polling.approved.borrow().is_empty(), "{old}");

        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(polling.source.reads(), 2, "{old}");
        polling.source.reply(Ok(grafana()));
        polling.events.send(ClientEvent::Connected).unwrap();
        reads_reach(&polling, 3).await;
        assert_eq!(polling.approved.borrow().len(), 1);
        tokio::time::sleep(APPROVAL_TIMING.every_max + Duration::from_secs(1)).await;
        assert_eq!(polling.source.reads(), 4, "{old}");
        polling.stop.cancel();
    }
}

#[tokio::test(start_paused = true)]
async fn a_good_read_after_an_old_answer_turns_the_periodic_reads_back_on() {
    for old in [404, 405] {
        let polling = polling(APPROVAL_TIMING);
        polling.source.reply(Err(status(old)));
        polling.events.send(ClientEvent::Connected).unwrap();
        reads_reach(&polling, 1).await;
        tokio::time::sleep(Duration::from_secs(600)).await;
        assert_eq!(polling.source.reads(), 1, "{old}");
        polling.source.reply(Ok(grafana()));
        polling.announced.notify_one();
        reads_reach(&polling, 2).await;
        assert_eq!(polling.approved.borrow().len(), 1, "{old}");
        tokio::time::sleep(APPROVAL_TIMING.every_max + Duration::from_secs(1)).await;
        assert_eq!(polling.source.reads(), 3, "{old}");
        polling.stop.cancel();
    }
}

#[tokio::test(start_paused = true)]
async fn reading_the_same_set_again_wakes_nobody() {
    let mut polling = polling(DAY);
    polling.source.reply(Ok(grafana()));
    polling.events.send(ClientEvent::Connected).unwrap();
    reads_reach(&polling, 1).await;
    assert!(polling.approved.has_changed().unwrap());
    polling.approved.mark_unchanged();
    polling.source.reply(Ok(grafana()));
    polling.announced.notify_one();
    reads_reach(&polling, 2).await;
    assert!(!polling.approved.has_changed().unwrap());
    polling.stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn an_unusable_or_failed_reply_keeps_the_set_and_a_removed_node_serves_nothing() {
    let polling = polling(DAY);
    polling.source.reply(Ok(grafana()));
    polling.events.send(ClientEvent::Connected).unwrap();
    reads_reach(&polling, 1).await;
    let too_many: Vec<(String, String)> = (0..65)
        .map(|index| (format!("id-{index}"), format!("s{index}")))
        .collect();
    let too_many = NodeServices {
        services: too_many
            .iter()
            .map(|(id, name)| NodeService {
                id: id.clone(),
                kind: ServiceKind::Tcp,
                name: name.clone(),
            })
            .collect(),
    };
    let kept: Vec<Result<NodeServices, ApiError>> = vec![
        Ok(listed(&[("id-x", ServiceKind::Tcp, "Not_A_Label")])),
        Ok(listed(&[("id x", ServiceKind::Tcp, "loki")])),
        Ok(too_many),
        Err(status(500)),
        Err(ApiError::CallTimeout),
    ];
    let mut reads = 1;
    for reply in kept {
        polling.source.reply(reply);
        polling.announced.notify_one();
        reads += 1;
        reads_reach(&polling, reads).await;
        assert_eq!(
            *polling.approved.borrow(),
            [approved(StreamKind::Tcp, "grafana")],
            "read {reads}"
        );
    }
    polling.source.reply(Err(ApiError::NodeRemoved));
    polling.announced.notify_one();
    reads_reach(&polling, reads + 1).await;
    assert!(polling.approved.borrow().is_empty());
    polling.stop.cancel();
}

#[test]
fn a_listed_set_becomes_approved_services_only_when_every_entry_is_usable() {
    let services = approved_of(listed(&[
        (
            "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11",
            ServiceKind::Kubernetes,
            "prod-eu",
        ),
        ("id-2", ServiceKind::Postgres, "billing"),
    ]))
    .unwrap();
    assert_eq!(services[0].kind, StreamKind::Kube);
    assert_eq!(services[1].kind, StreamKind::Db);
    assert_eq!(services[1].name.as_str(), "billing");
    let long_id = "a".repeat(129);
    for (entries, problem) in [
        (vec![("", ServiceKind::Tcp, "a")], ApprovalProblem::Id),
        (
            vec![(long_id.as_str(), ServiceKind::Tcp, "a")],
            ApprovalProblem::Id,
        ),
        (vec![("id/1", ServiceKind::Tcp, "a")], ApprovalProblem::Id),
        (vec![("id-1", ServiceKind::Tcp, "")], ApprovalProblem::Name),
        (
            vec![("id-1", ServiceKind::Tcp, "a.b")],
            ApprovalProblem::Name,
        ),
    ] {
        assert_eq!(approved_of(listed(&entries)), Err(problem), "{entries:?}");
    }
}
