use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub type Captured = BTreeMap<String, String>;

thread_local! {
    static RECORDED: RefCell<Vec<Captured>> = const { RefCell::new(Vec::new()) };
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
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "jaunt::audit"
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = Captured::new();
        captured.insert(
            "level".to_owned(),
            event.metadata().level().as_str().to_owned(),
        );
        event.record(&mut Fields(&mut captured));
        RECORDED.with(|recorded| recorded.borrow_mut().push(captured));
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

pub fn audit_events() -> Vec<Captured> {
    RECORDED.with(|recorded| recorded.borrow().clone())
}
