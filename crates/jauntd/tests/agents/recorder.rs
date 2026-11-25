use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};

pub type Captured = BTreeMap<String, String>;

thread_local! {
    static RECORDED: RefCell<Vec<Captured>> = const { RefCell::new(Vec::new()) };
    static EVERYTHING: Cell<bool> = const { Cell::new(false) };
    static ALL_TEXT: RefCell<String> = const { RefCell::new(String::new()) };
}

const AUDIT_TARGET: &str = "jaunt::audit";

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

fn keep_text(captured: &Captured) {
    ALL_TEXT.with(|text| {
        let mut text = text.borrow_mut();
        for (name, value) in captured {
            text.push_str(name);
            text.push('=');
            text.push_str(value);
            text.push('\n');
        }
    });
}

impl Subscriber for ThreadRecorder {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == AUDIT_TARGET || EVERYTHING.with(Cell::get)
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        if EVERYTHING.with(Cell::get) {
            let mut captured = Captured::new();
            attributes.record(&mut Fields(&mut captured));
            keep_text(&captured);
        }
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, values: &Record<'_>) {
        if EVERYTHING.with(Cell::get) {
            let mut captured = Captured::new();
            values.record(&mut Fields(&mut captured));
            keep_text(&captured);
        }
    }

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut captured = Captured::new();
        event.record(&mut Fields(&mut captured));
        if EVERYTHING.with(Cell::get) {
            keep_text(&captured);
        }
        if event.metadata().target() == AUDIT_TARGET {
            RECORDED.with(|recorded| recorded.borrow_mut().push(captured));
        }
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

pub fn capture_everything() {
    EVERYTHING.with(|everything| everything.set(true));
}

pub fn everything_logged() -> String {
    ALL_TEXT.with(|text| text.borrow().clone())
}

pub fn audit_events() -> Vec<Captured> {
    RECORDED.with(|recorded| recorded.borrow().clone())
}
