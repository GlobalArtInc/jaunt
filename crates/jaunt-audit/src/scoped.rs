use std::sync::{Arc, Once};
use std::time::Duration;

use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

use crate::capture::{AuditTap, TapSnapshot};
use crate::clock::system_clock;
use crate::event::AuditEvent;
use crate::pipeline::Pipeline;
use crate::sink::MemorySink;

const QUEUE: usize = 4096;
const FLUSH_DEADLINE: Duration = Duration::from_secs(10);

struct EnabledEverywhere;

impl Subscriber for EnabledEverywhere {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

pub fn keep_callsites_enabled_for_scoped_capture() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        if tracing::subscriber::set_global_default(EnabledEverywhere).is_err() {
            tracing::debug!(
                target: "jaunt::daemon",
                "a global subscriber exists already, which keeps callsites enabled"
            );
        }
    });
}

pub struct ScopedCapture {
    guard: DefaultGuard,
    tap: AuditTap,
    pipeline: Pipeline,
    sink: MemorySink,
}

impl ScopedCapture {
    pub fn start() -> ScopedCapture {
        keep_callsites_enabled_for_scoped_capture();
        let clock = system_clock();
        let tap = AuditTap::new(Arc::clone(&clock));
        let pipeline = Pipeline::new(clock, QUEUE);
        let sink = MemorySink::new();
        let wired = pipeline.add_sink(sink.clone()).is_ok() && tap.bind(pipeline.clone()).is_ok();
        debug_assert!(wired);
        let guard = tracing::subscriber::set_default(Registry::default().with(tap.layer()));
        ScopedCapture {
            guard,
            tap,
            pipeline,
            sink,
        }
    }

    pub fn snapshot(&self) -> TapSnapshot {
        self.tap.snapshot()
    }

    pub async fn finish(self) -> Vec<Arc<AuditEvent>> {
        drop(self.guard);
        self.pipeline.shutdown(FLUSH_DEADLINE).await;
        self.sink.events()
    }
}
