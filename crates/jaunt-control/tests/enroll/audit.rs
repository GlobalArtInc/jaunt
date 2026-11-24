use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Once;

use serde_json::json;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use crate::support::{APPROVER, Harness, new_agent};

pub type Captured = BTreeMap<String, String>;

thread_local! {
    static RECORDING: RefCell<Option<Vec<Captured>>> = const { RefCell::new(None) };
}

struct Fields<'a>(&'a mut Captured);

impl Visit for Fields<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
}

struct ThreadRecorder;

impl Subscriber for ThreadRecorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = Captured::new();
        captured.insert("target".to_owned(), event.metadata().target().to_owned());
        event.record(&mut Fields(&mut captured));
        RECORDING.with(|recording| {
            if let Some(events) = recording.borrow_mut().as_mut() {
                events.push(captured);
            }
        });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

pub fn install_recorder() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(ThreadRecorder).unwrap();
    });
}

fn start_recording() {
    RECORDING.with(|recording| *recording.borrow_mut() = Some(Vec::new()));
}

fn take_recording() -> Vec<Captured> {
    RECORDING
        .with(|recording| recording.borrow_mut().take())
        .unwrap()
}

#[tokio::test]
async fn the_lifecycle_emits_stable_events_and_none_of_them_carries_a_secret() {
    let harness = Harness::new().await;
    start_recording();

    let first = harness.enroll("web-01").await;
    harness.approve(&first).await;
    let delivered = harness.poll(&first.handle).await.json();
    let node_id = delivered["node_id"].as_str().unwrap().to_owned();
    harness.renew(Some(&node_id), &json!({})).await;
    harness
        .renew(
            Some(&node_id),
            &json!({"ssh_host_public_key": new_agent().ssh_line}),
        )
        .await;
    harness
        .renew(
            Some(&node_id),
            &json!({"tls_public_key": new_agent().tls_public_key}),
        )
        .await;
    let second = harness.enroll("web-02").await;
    harness.admin.reject(&second.code).await.unwrap();
    let third = harness.enroll("web-03").await;
    harness.clock.advance(901);
    harness.poll(&third.handle).await;
    harness.admin.remove_node("web-01").await.unwrap();

    let events: Vec<Captured> = take_recording()
        .into_iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect();
    let names: Vec<&str> = events.iter().map(|event| event["event"].as_str()).collect();
    assert_eq!(
        names,
        [
            "node.enroll.requested",
            "node.enroll.approved",
            "node.enroll.delivered",
            "node.cert.renewed",
            "node.cert.renewed",
            "node.cert.renewed",
            "node.enroll.requested",
            "node.enroll.rejected",
            "node.enroll.requested",
            "node.enroll.expired",
            "node.removed",
        ]
    );
    let by_name = |name: &str| events.iter().find(|event| event["event"] == name).unwrap();
    assert_eq!(by_name("node.enroll.approved")["approved_by"], APPROVER);
    assert_eq!(by_name("node.enroll.delivered")["node_id"], node_id);
    assert!(by_name("node.enroll.delivered").contains_key("x509_serial"));
    let rotated: Vec<&str> = events
        .iter()
        .filter(|event| event["event"] == "node.cert.renewed")
        .map(|event| event["rotated"].as_str())
        .collect();
    assert_eq!(rotated, ["false", "true", "true"]);
    assert_eq!(by_name("node.removed")["reason"], "admin");

    let mut secrets: Vec<String> = Vec::new();
    for enrolled in [&first, &second, &third] {
        let bare_code: String = enrolled.code.chars().filter(|ch| *ch != '-').collect();
        secrets.extend([
            enrolled.handle.clone(),
            enrolled.code.clone(),
            bare_code,
            enrolled.agent.tls_public_key.clone(),
            enrolled.agent.ssh_line.clone(),
            enrolled
                .agent
                .ssh_line
                .split(' ')
                .nth(1)
                .unwrap()
                .to_owned(),
            enrolled.handle_hash(),
        ]);
    }
    for event in &events {
        for (field, value) in event {
            for secret in &secrets {
                assert!(!value.contains(secret.as_str()), "{field} leaks {secret}");
            }
        }
    }
}

#[tokio::test]
async fn the_request_event_names_the_exact_peer_and_its_network() {
    let harness = Harness::new().await;
    start_recording();

    harness.enroll_from_peer("2001:db8:1:2::5", "web-v6").await;
    harness.enroll_from_peer("203.0.113.9", "web-v4").await;

    let events: Vec<Captured> = take_recording()
        .into_iter()
        .filter(|event| event["event"] == "node.enroll.requested")
        .collect();
    let sources: Vec<(&str, &str)> = events
        .iter()
        .map(|event| {
            (
                event["source_ip"].as_str(),
                event["source_network"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        sources,
        [
            ("2001:db8:1:2::5", "2001:db8:1:2::/64"),
            ("203.0.113.9", "203.0.113.9")
        ]
    );
}

#[tokio::test]
async fn an_expiry_is_reported_once_whoever_notices_it_first() {
    let harness = Harness::new().await;
    let polled = harness.enroll("polled").await;
    let swept = harness.enroll("swept").await;
    let delivering = harness.enroll("delivering").await;
    harness.approve(&delivering).await;
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&delivering.handle_hash())
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
    let id_of = |handle_hash: String| {
        let store = harness.store.clone();
        async move {
            store
                .enrollments()
                .get_by_handle_hash(&handle_hash)
                .await
                .unwrap()
                .unwrap()
                .id
        }
    };
    let polled_id = id_of(polled.handle_hash()).await;
    let swept_id = id_of(swept.handle_hash()).await;
    harness.clock.advance(900);
    start_recording();

    for _ in 0..10 {
        assert_eq!(harness.poll(&polled.handle).await.state(), "expired");
    }
    let after_polls = expiry_events(&take_recording());
    assert_eq!(after_polls, [polled_id]);

    harness.clock.advance(3600 + 1);
    start_recording();
    assert_eq!(harness.control.purge_stored_enrollments().await.unwrap(), 3);
    let mut after_purge = expiry_events(&take_recording());
    after_purge.sort();
    let mut expected = vec![swept_id, stored.id];
    expected.sort();
    assert_eq!(after_purge, expected);
}

fn expiry_events(events: &[Captured]) -> Vec<String> {
    events
        .iter()
        .filter(|event| event["event"] == "node.enroll.expired")
        .map(|event| event["enrollment_id"].clone())
        .collect()
}
