use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{Filtered, Targets};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use uuid::Uuid;

use crate::clock::Clock;
use crate::event::{AuditEvent, RawValue};
use crate::limiter::IntervalCounter;
use crate::pipeline::Pipeline;
use crate::spec::{Classified, EventType};

pub const AUDIT_TARGET: &str = "jaunt::audit";

const EVENT_FIELD: &str = "event";
const MAX_RAW_FIELDS: usize = 32;
const MAX_DEBUG_CHARS: usize = 1024;
const MAX_EVENT_NAME_CHARS: usize = 64;
const REPORT_INTERVAL_MS: i64 = 60_000;
const LOG_TARGET: &str = "jaunt::daemon";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the audit tap is already bound to a pipeline")]
pub struct AlreadyBound;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "audit events are compiled out of this build: a dependency enables a tracing max_level \
     feature below INFO"
)]
pub struct AuditLevelCompiledOut;

pub fn ensure_audit_level_compiled_in() -> Result<(), AuditLevelCompiledOut> {
    if tracing::level_filters::STATIC_MAX_LEVEL >= Level::INFO {
        Ok(())
    } else {
        Err(AuditLevelCompiledOut)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TapSnapshot {
    pub captured: u64,
    pub unbound: u64,
    pub unmapped: u64,
    pub fields_dropped: u64,
    pub dropped_after_close: u64,
}

struct TapInner {
    clock: Arc<dyn Clock>,
    pipeline: OnceLock<Pipeline>,
    sequence: AtomicU64,
    captured: AtomicU64,
    unbound: AtomicU64,
    unmapped: IntervalCounter,
    fields_dropped: AtomicU64,
    fields_dropped_report: IntervalCounter,
}

#[derive(Clone)]
pub struct AuditTap {
    inner: Arc<TapInner>,
}

impl AuditTap {
    pub fn new(clock: Arc<dyn Clock>) -> AuditTap {
        AuditTap {
            inner: Arc::new(TapInner {
                clock,
                pipeline: OnceLock::new(),
                sequence: AtomicU64::new(0),
                captured: AtomicU64::new(0),
                unbound: AtomicU64::new(0),
                unmapped: IntervalCounter::new(REPORT_INTERVAL_MS),
                fields_dropped: AtomicU64::new(0),
                fields_dropped_report: IntervalCounter::new(REPORT_INTERVAL_MS),
            }),
        }
    }

    pub fn bind(&self, pipeline: Pipeline) -> Result<(), AlreadyBound> {
        self.inner.pipeline.set(pipeline).map_err(|_| AlreadyBound)
    }

    pub fn layer<S>(&self) -> Filtered<AuditLayer, Targets, S>
    where
        S: Subscriber + for<'span> LookupSpan<'span>,
    {
        AuditLayer {
            inner: Arc::clone(&self.inner),
        }
        .with_filter(Targets::new().with_target(AUDIT_TARGET, Level::INFO))
    }

    pub fn snapshot(&self) -> TapSnapshot {
        TapSnapshot {
            captured: self.inner.captured.load(Ordering::Relaxed),
            unbound: self.inner.unbound.load(Ordering::Relaxed),
            unmapped: self.inner.unmapped.total(),
            fields_dropped: self.inner.fields_dropped.load(Ordering::Relaxed),
            dropped_after_close: self
                .inner
                .pipeline
                .get()
                .map_or(0, Pipeline::dropped_after_close),
        }
    }
}

pub struct AuditLayer {
    inner: Arc<TapInner>,
}

#[derive(Default)]
struct Collector {
    fields: Vec<(&'static str, RawValue)>,
}

impl Collector {
    fn push(&mut self, field: &Field, value: RawValue) {
        if self.fields.len() < MAX_RAW_FIELDS {
            self.fields.push((field.name(), value));
        }
    }
}

impl Visit for Collector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, RawValue::Text(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, RawValue::Signed(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, RawValue::Unsigned(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, RawValue::Bool(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        let text: String = format!("{value:?}").chars().take(MAX_DEBUG_CHARS).collect();
        self.push(field, RawValue::Text(text));
    }
}

impl<S: Subscriber> Layer<S> for AuditLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() != AUDIT_TARGET {
            return;
        }
        let mut collector = Collector::default();
        event.record(&mut collector);
        let name = collector
            .fields
            .iter()
            .find_map(|(field, value)| match value {
                RawValue::Text(text) if *field == EVENT_FIELD => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or_default();
        match EventType::classify(name) {
            Classified::Ignored => {}
            Classified::Unknown => self.report_unmapped(name),
            Classified::Mapped(kind) => self.capture(kind, &collector.fields),
        }
    }
}

impl AuditLayer {
    fn capture(&self, kind: EventType, raw: &[(&str, RawValue)]) {
        let Some(pipeline) = self.inner.pipeline.get() else {
            self.inner.unbound.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let sequence = self.inner.sequence.fetch_add(1, Ordering::Relaxed);
        let id = format!("{sequence:016x}{}", Uuid::new_v4().simple());
        let (event, report) = AuditEvent::from_raw(kind, raw, id, self.inner.clock.now());
        let dropped = u64::try_from(report.fields_dropped).unwrap_or(u64::MAX);
        self.inner
            .fields_dropped
            .fetch_add(dropped, Ordering::Relaxed);
        if dropped > 0 {
            let now = self.inner.clock.now().millis();
            if let Some(events) = self.inner.fields_dropped_report.record(now) {
                tracing::warn!(
                    target: LOG_TARGET,
                    event = kind.name(),
                    fields = report.dropped_names.join(",").as_str(),
                    events_with_dropped_fields = events,
                    fields_dropped_total = self.inner.fields_dropped.load(Ordering::Relaxed),
                    unbound_total = self.inner.unbound.load(Ordering::Relaxed),
                    "audit fields outside the schema were dropped"
                );
            }
        }
        self.inner.captured.fetch_add(1, Ordering::Relaxed);
        pipeline.submit(Arc::new(event));
    }

    fn report_unmapped(&self, name: &str) {
        let now = self.inner.clock.now().millis();
        if let Some(count) = self.inner.unmapped.record(now) {
            let shown: String = name.chars().take(MAX_EVENT_NAME_CHARS).collect();
            tracing::warn!(
                target: LOG_TARGET,
                event = shown.as_str(),
                count,
                "audit events with no schema mapping were not recorded"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    use super::AuditTap;
    use crate::clock::ManualClock;
    use crate::event::{Actor, AuditEvent};
    use crate::pipeline::Pipeline;
    use crate::sink::MemorySink;

    struct Stand {
        tap: AuditTap,
        pipeline: Pipeline,
        sink: MemorySink,
    }

    fn stand() -> Stand {
        let clock = Arc::new(ManualClock::new(1_700_000_000_123));
        let tap = AuditTap::new(clock.clone());
        let pipeline = Pipeline::new(clock, 64);
        let sink = MemorySink::new();
        pipeline.add_sink(sink.clone()).unwrap();
        tap.bind(pipeline.clone()).unwrap();
        Stand {
            tap,
            pipeline,
            sink,
        }
    }

    async fn drained(stand: &Stand) -> Vec<Arc<AuditEvent>> {
        stand.pipeline.shutdown(Duration::from_secs(5)).await;
        stand.sink.events()
    }

    #[tokio::test]
    async fn audit_events_become_schema_events_and_other_targets_and_levels_are_ignored() {
        let stand = stand();
        let subscriber = Registry::default().with(stand.tap.layer());

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "l-1");
            tracing::info!(target: "jaunt::control", event = "login.started", login_id = "other");
            tracing::debug!(target: "jaunt::audit", event = "login.started", login_id = "debug");
            tracing::info!(
                target: "jaunt::audit",
                event = "cert.issued",
                login_id = "l-1",
                user_id = "u-1",
                serial = 7_u64,
                email = "ada@example.com"
            );
            tracing::info!(
                target: "jaunt::audit",
                event = "gate.ssh.connect",
                client_addr = %"203.0.113.9:5000",
                peer_addr = %"10.0.0.1:443",
                proxied = true
            );
        });

        let events = drained(&stand).await;
        let names: Vec<&str> = events.iter().map(|event| event.kind.name()).collect();
        assert_eq!(names, ["login.started", "cert.issued", "gate.connect"]);
        assert_eq!(events[0].actor, Actor::Anonymous);
        assert_eq!(events[1].actor, Actor::User("u-1".to_owned()));
        assert_eq!(events[1].int("serial"), Some(7));
        assert!(!serde_json::to_string(&events[1]).unwrap().contains("ada@"));
        assert_eq!(events[2].text("client_addr"), Some("203.0.113.9:5000"));
        assert_eq!(events[2].flag("proxied"), Some(true));
        assert_eq!(events[0].time.millis(), 1_700_000_000_123);
        assert!(events[0].id < events[1].id && events[1].id < events[2].id);
        assert_eq!(stand.tap.snapshot().captured, 3);
    }

    #[tokio::test]
    async fn ignored_unmapped_and_unbound_events_are_counted_apart_and_never_recorded() {
        let stand = stand();
        let unbound_tap = AuditTap::new(Arc::new(ManualClock::new(1_700_000_000_000)));
        let subscriber = Registry::default()
            .with(stand.tap.layer())
            .with(unbound_tap.layer());

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "jaunt::audit", event = "agent.ssh.end", session_id = "s");
            tracing::info!(target: "jaunt::audit", event = "revoke.made", who = "u");
            tracing::info!(target: "jaunt::audit", note = "no event name");
        });

        assert!(drained(&stand).await.is_empty());
        let bound = stand.tap.snapshot();
        assert_eq!((bound.captured, bound.unmapped), (0, 2));
        assert_eq!(unbound_tap.snapshot().unmapped, 2);
    }

    #[tokio::test]
    async fn events_before_the_pipeline_is_bound_are_counted_and_binding_twice_is_refused() {
        let clock = Arc::new(ManualClock::new(1_700_000_000_000));
        let tap = AuditTap::new(clock.clone());
        let subscriber = Registry::default().with(tap.layer());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "l-1");
        });

        assert_eq!(tap.snapshot().unbound, 1);
        tap.bind(Pipeline::new(clock.clone(), 4)).unwrap();
        assert!(tap.bind(Pipeline::new(clock, 4)).is_err());
    }

    #[tokio::test]
    async fn secret_looking_fields_and_values_never_reach_a_sink() {
        let stand = stand();
        let subscriber = Registry::default().with(stand.tap.layer());

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                target: "jaunt::audit",
                event = "login.finish_failed",
                login_id = "l-1",
                reason = "-----BEGIN OPENSSH PRIVATE KEY-----",
                api_token = "jnt_secret_token",
                completion_code = "code-123",
                private_key = "-----BEGIN PRIVATE KEY-----",
                certificate = "ssh-ed25519-cert-v01@openssh.com AAAA",
                authorization = "Bearer abc"
            );
        });

        let events = drained(&stand).await;
        let line = serde_json::to_string(&events[0]).unwrap();
        for leaked in ["BEGIN", "jnt_secret_token", "code-123", "Bearer", "AAAA"] {
            assert!(!line.contains(leaked), "{line}");
        }
        assert_eq!(events[0].text("login_id"), Some("l-1"));
        assert_eq!(events[0].fields.len(), 1);
        assert_eq!(stand.tap.snapshot().fields_dropped, 6);
    }

    #[test]
    fn the_audit_level_is_compiled_into_this_build() {
        assert_eq!(super::ensure_audit_level_compiled_in(), Ok(()));
    }

    #[tokio::test]
    async fn the_shapes_emitted_by_the_gate_and_the_daemon_map_to_their_schema_types() {
        let stand = stand();
        let subscriber = Registry::default().with(stand.tap.layer());

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(
                target: "jaunt::audit", event = "gate.ssh.auth", outcome = "ok",
                client_addr = %"203.0.113.9:5000", user_id = "u-1", serial = 9_u64, login = "deploy"
            );
            tracing::info!(
                target: "jaunt::audit", event = "gate.ssh.auth", outcome = "denied",
                reason = "login_not_allowed", client_addr = %"203.0.113.9:5000", login = "root"
            );
            tracing::info!(
                target: "jaunt::audit", event = "gate.ssh.forward", outcome = "allowed",
                client_addr = %"203.0.113.9:5000", node = "web-01", session_id = "s-1"
            );
            tracing::info!(
                target: "jaunt::audit", event = "gate.ssh.stream_end", client_addr = %"203.0.113.9:5000",
                node = "web-01", session_id = "s-1", bytes_up = 10_u64, bytes_down = 20_u64,
                duration_ms = 1500_u64, reason = "closed"
            );
            tracing::info!(
                target: "jaunt::audit", event = "agent.connected", node_id = "n-1",
                remote_addr = %"10.0.0.7:4444", alpn = %"jaunt-tunnel/1", replaced = false
            );
            tracing::info!(
                target: "jaunt::audit", event = "authz.deny", phase = "admin",
                permission = "sessions.read", reason = "policy_denied", user_id = "u-2",
                policy_hash = "h-1"
            );
            tracing::info!(
                target: "jaunt::audit", event = "policy.reload", applied = true,
                hash = "h-2", error_count = 0_usize
            );
            tracing::warn!(
                target: "jaunt::audit", event = "policy.reload", applied = false,
                error_count = 1_usize, error_1 = "roles.yaml: bad"
            );
            tracing::info!(
                target: "jaunt::audit", event = "agent.cert.rotated", not_after = 1_800_000_000_u64
            );
        });

        let events = drained(&stand).await;
        let shown: Vec<(&str, String, Option<&str>, Option<&str>)> = events
            .iter()
            .map(|event| {
                (
                    event.kind.name(),
                    event.actor.as_wire(),
                    event.session_id.as_deref(),
                    event.policy_hash.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                ("gate.auth", "u-1".to_owned(), None, None),
                ("gate.auth", "anonymous".to_owned(), None, None),
                ("gate.forward", "anonymous".to_owned(), Some("s-1"), None),
                ("gate.stream_end", "anonymous".to_owned(), Some("s-1"), None),
                ("agent.connected", "node:n-1".to_owned(), None, None),
                ("authz.deny", "u-2".to_owned(), None, Some("h-1")),
                ("policy.reload", "system".to_owned(), None, Some("h-2")),
                ("policy.reload", "system".to_owned(), None, None),
                ("cert.rotated", "system".to_owned(), None, None),
            ]
        );
        assert_eq!(events[0].int("serial"), Some(9));
        assert_eq!(events[1].text("reason"), Some("login_not_allowed"));
        assert_eq!(events[3].int("bytes_down"), Some(20));
        assert_eq!(events[3].text("node"), Some("web-01"));
        assert_eq!(events[4].text("alpn"), Some("jaunt-tunnel/1"));
        assert_eq!(events[4].node.as_deref(), Some("n-1"));
        assert_eq!(events[5].text("permission"), Some("sessions.read"));
        assert_eq!(events[7].flag("applied"), Some(false));
        assert_eq!(events[7].text("error_1"), Some("roles.yaml: bad"));
        assert_eq!(events[8].int("not_after"), Some(1_800_000_000));
        assert_eq!(stand.tap.snapshot().fields_dropped, 0);
    }
}
