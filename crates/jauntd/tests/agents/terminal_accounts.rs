use std::sync::atomic::Ordering;

use http::StatusCode;
use serde_json::{Value, json};

use crate::support::{audited, field};
use crate::terminal_support::{RECORDED_LOGIN, Received, TerminalStand};

const REFERENCE: &str = "H-9D0311FE";

fn creating(reference: &str) -> Value {
    json!({"event": "creating", "ref": reference})
}

fn created() -> Value {
    json!({"event": "created", "ref": REFERENCE, "uid": 30_000, "home": "/home/deploy",
           "groups": ["deploy"]})
}

fn refused(reference: &str, reason: &str) -> Value {
    json!({"event": "refused", "ref": reference, "reason": reason})
}

fn failed(reference: &str) -> Value {
    json!({"event": "failed", "ref": reference, "stage": "useradd", "exit_code": 12})
}

fn missing(reference: &str) -> Value {
    json!({"event": "missing", "ref": reference})
}

fn progress() -> Value {
    json!({"t": "progress", "stage": "account"})
}

#[tokio::test]
async fn a_login_that_creates_the_account_shows_the_step_and_the_ready_frame_names_the_home() {
    let stand = TerminalStand::start().await;
    stand
        .accounts
        .plan(vec![creating(REFERENCE), created()], false);
    let mut ws = stand.open(&stand.alice, RECORDED_LOGIN).await;

    assert_eq!(ws.next().await, Received::Json(progress()));
    let Received::Json(ready) = ws.next().await else {
        panic!("the terminal did not become ready");
    };
    let session_id = ready["session_id"].as_str().unwrap().to_owned();
    assert_eq!(
        ready,
        json!({"t": "ready", "session_id": session_id, "account_created": true,
               "home": "/home/deploy"})
    );
    assert_eq!(
        stand.accounts.answers(),
        [StatusCode::NO_CONTENT, StatusCode::NO_CONTENT]
    );
    let created = audited("the account creation", |event| {
        field(event, "event") == "host_user.created" && field(event, "session_id") == session_id
    })
    .await;
    assert_eq!(field(&created, "user_id"), stand.alice.user_id);
    assert_eq!(field(&created, "node_id"), stand.node_id);
    assert_eq!(field(&created, "login"), RECORDED_LOGIN);
    assert_eq!(field(&created, "ref"), REFERENCE);
}

#[tokio::test]
async fn without_a_report_the_ready_frame_says_no_account_was_created() {
    let stand = TerminalStand::start().await;
    let mut ws = stand.open(&stand.alice, RECORDED_LOGIN).await;

    let Received::Json(ready) = ws.next().await else {
        panic!("the terminal did not become ready");
    };
    let session_id = ready["session_id"].as_str().unwrap().to_owned();
    assert_eq!(
        ready,
        json!({"t": "ready", "session_id": session_id, "account_created": false})
    );
}

#[tokio::test]
async fn a_refused_failed_or_missing_account_closes_with_its_own_code_and_reference() {
    let stand = TerminalStand::start().await;
    for (reports, code, reference) in [
        (
            vec![creating("H-0000000A"), refused("H-0000000A", "name_rule")],
            "account_refused",
            "H-0000000A",
        ),
        (
            vec![creating("H-0000000B"), refused("H-0000000B", "rate_limit")],
            "account_failed",
            "H-0000000B",
        ),
        (
            vec![creating("H-0000000C"), failed("H-0000000C")],
            "account_failed",
            "H-0000000C",
        ),
        (vec![missing("H-0000000D")], "no_account", "H-0000000D"),
    ] {
        let progressed = reports.len() > 1;
        let answered = vec![StatusCode::NO_CONTENT; reports.len()];
        stand.accounts.plan(reports, true);
        let mut ws = stand.open(&stand.alice, RECORDED_LOGIN).await;

        let (messages, closed) = ws.ending().await;
        let error = json!({"t": "error", "code": code, "ref": reference});
        let expected = if progressed {
            vec![progress(), error]
        } else {
            vec![error]
        };
        assert_eq!(messages, expected, "{code}");
        assert_eq!(closed, Some(1008), "{code}");
        assert_eq!(stand.accounts.answers(), answered, "{code}");
        let denied = audited(code, |event| {
            field(event, "event") == "terminal.denied"
                && field(event, "reason") == code
                && field(event, "ref") == reference
        })
        .await;
        assert_eq!(field(&denied, "user_id"), stand.alice.user_id, "{code}");
    }
    assert_eq!(stand.sshd.log.logins.load(Ordering::SeqCst), 0);
    let refusal = audited("the account refusal", |event| {
        field(event, "event") == "host_user.refused" && field(event, "ref") == "H-0000000A"
    })
    .await;
    assert_eq!(field(&refusal, "user_id"), stand.alice.user_id);
    assert_eq!(field(&refusal, "reason"), "name_rule");
    let failure = audited("the helper failure", |event| {
        field(event, "event") == "host_user.helper_failed" && field(event, "ref") == "H-0000000C"
    })
    .await;
    assert_eq!(field(&failure, "stage"), "useradd");
}
