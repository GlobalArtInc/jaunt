use jaunt_audit::{Actor, ScopedCapture};

use crate::support::Harness;

#[tokio::test]
async fn a_login_a_certificate_and_a_denied_callback_leave_exactly_these_schema_events() {
    let harness = Harness::new().await;
    let capture = ScopedCapture::start();

    let issued = harness.login().await;
    harness.callback("code=stray-code&state=stray-state").await;
    let snapshot = capture.snapshot();
    let events = capture.finish().await;
    assert_eq!(
        (snapshot.fields_dropped, snapshot.unmapped, snapshot.unbound),
        (0, 0, 0)
    );

    let names: Vec<&str> = events.iter().map(|event| event.kind().name()).collect();
    assert_eq!(
        names,
        [
            "login.started",
            "login.approved",
            "cert.issued",
            "login.denied"
        ]
    );
    assert_eq!(events[0].actor(), &Actor::Anonymous);
    let Actor::User(user_id) = events[1].actor().clone() else {
        panic!("the approval has no user actor: {:?}", events[1].actor());
    };
    assert_eq!(events[2].actor(), &Actor::User(user_id));
    assert_eq!(events[3].actor(), &Actor::Anonymous);
    let login_id = events[0].text("login_id").unwrap();
    assert_eq!(events[1].text("login_id"), Some(login_id));
    assert_eq!(events[2].text("login_id"), Some(login_id));
    assert!(events[2].int("serial").is_some());
    assert_eq!(events[3].text("reason"), Some("unknown_state"));
    let lines: String = events
        .iter()
        .map(|event| serde_json::to_string(event.as_ref()).unwrap())
        .collect();
    for secret in [
        issued["api_token"].as_str().unwrap(),
        issued["certificate"].as_str().unwrap(),
        "alice@example.com",
        "stray-code",
        "stray-state",
    ] {
        assert!(!lines.contains(secret), "{lines}");
    }
}
