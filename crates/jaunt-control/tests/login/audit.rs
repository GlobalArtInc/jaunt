use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Once;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

use crate::support::{Harness, ed25519_public_key_line};

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

pub fn start_recording() {
    install_recorder();
    RECORDING.with(|recording| *recording.borrow_mut() = Some(Vec::new()));
}

pub fn take_recording() -> Vec<Captured> {
    RECORDING
        .with(|recording| recording.borrow_mut().take())
        .unwrap()
}

pub fn install_recorder() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(ThreadRecorder).unwrap();
    });
}

fn base64_part(line: &str) -> String {
    line.split(' ').nth(1).unwrap().to_owned()
}

async fn scenario() -> Vec<String> {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    let code = harness.browser_code(&session);
    let approved = harness
        .callback(&format!("code={code}&state={}", session.state))
        .await;
    let completion = session.record_completion(approved.location()).to_owned();
    let key = ed25519_public_key_line("alice@laptop");
    harness
        .finish_raw(
            &session.login_id,
            &harness.next_verifier(),
            &completion,
            &key,
        )
        .await;
    let flipped = if completion.starts_with('A') {
        'B'
    } else {
        'A'
    };
    let wrong_completion = format!("{flipped}{}", &completion[1..]);
    harness
        .finish_raw(
            &session.login_id,
            &session.verifier,
            &wrong_completion,
            &key,
        )
        .await;
    let issued = harness.finish(&session, &key).await.json();

    let denied = harness.begin().await;
    harness
        .callback(&format!(
            "error=access_denied&error_description=provider+words&state={}",
            denied.state
        ))
        .await;
    harness.callback("code=stray-code&state=stray-state").await;

    vec![
        code,
        completion,
        wrong_completion,
        session.state,
        session.verifier,
        denied.state,
        issued["api_token"].as_str().unwrap().to_owned(),
        base64_part(&key),
        base64_part(issued["certificate"].as_str().unwrap()),
        "provider+words".to_owned(),
        "stray-code".to_owned(),
        "stray-state".to_owned(),
    ]
}

#[tokio::test]
async fn audit_events_have_stable_fields_and_never_carry_secrets() {
    start_recording();

    let secrets = scenario().await;

    let events = take_recording();
    let audit: Vec<&Captured> = events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .collect();
    let names: Vec<(&str, Option<&str>)> = audit
        .iter()
        .map(|event| {
            (
                event["event"].as_str(),
                event.get("reason").map(String::as_str),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("login.started", None),
            ("login.approved", None),
            ("login.finish_failed", Some("bad_verifier")),
            ("login.finish_failed", Some("bad_completion_code")),
            ("cert.issued", None),
            ("login.started", None),
            ("login.denied", Some("provider_error")),
            ("login.callback_refused", Some("unknown_state")),
        ]
    );

    let field = |index: usize, name: &str| audit[index].get(name).map(String::as_str);
    let login_id = field(0, "login_id").unwrap();
    assert_eq!(field(1, "login_id"), Some(login_id));
    assert_eq!(field(2, "login_id"), Some(login_id));
    assert_eq!(field(3, "login_id"), Some(login_id));
    assert_eq!(field(4, "login_id"), Some(login_id));
    let user_id = field(1, "user_id").unwrap();
    assert_eq!(field(4, "user_id"), Some(user_id));
    assert_eq!(field(1, "email"), Some("alice@example.com"));
    assert_eq!(field(4, "email"), Some("alice@example.com"));
    assert_eq!(field(4, "serial"), Some("1"));
    assert_eq!(field(7, "login_id"), None);

    let everything = format!("{events:?}");
    for secret in secrets {
        assert!(!everything.contains(&secret), "{secret} was logged");
    }
}
