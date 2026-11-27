use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use jaunt_ca::fingerprint_hex;
use jaunt_ca::ssh_key::{Certificate as UserCertificate, PublicKey as CaPublicKey};
use jaunt_control::{RevokeRequest, WebTerminalSettings};
use jaunt_ssh::{ChannelExit, EphemeralKey, TerminalSize, WEB_WINDOW};
use jaunt_store::{NewRevocation, RevocationKind};
use serde_json::{Value, json};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use crate::recorder::{Captured, capture_everything, everything_logged};
use crate::support::{APPROVER, PUBLIC_ORIGIN, audited, eventually, field};
use crate::terminal_support::{
    BROWSER_ADDR, Browser, HOSTILE, ManualTime, NODE, PLAIN_LOGIN, RECORDED_LOGIN, RawBrowser,
    Received, SSHD_WINDOW, STEP, StandOptions, TerminalStand, Ws, without_reference,
};

const BOUND: u64 = 64 << 20;
const CHUNK: u64 = 32 * 1024;
const WRITER_CHUNKS: u64 = 6;

fn opened_event(session_id: &str) -> impl FnMut(&Captured) -> bool + '_ {
    move |event| {
        field(event, "event") == "terminal.opened" && field(event, "session_id") == session_id
    }
}

fn closed_event(session_id: &str) -> impl FnMut(&Captured) -> bool + '_ {
    move |event| {
        field(event, "event") == "terminal.closed" && field(event, "session_id") == session_id
    }
}

async fn ended_with(ws: &mut Ws, error: Option<&str>, code: u16) -> Vec<Value> {
    let (messages, closed) = ws.ending().await;
    assert_eq!(closed, Some(code), "{messages:?}");
    if let Some(error) = error {
        let stripped: Vec<Value> = messages
            .iter()
            .map(|message| without_reference(message, "D-"))
            .collect();
        assert_eq!(stripped, [json!({"t": "error", "code": error})]);
    }
    messages
}

async fn pong(ws: &mut Ws) {
    ws.send_text(r#"{"t":"ping"}"#).await;
    loop {
        match ws.next().await {
            Received::Output(data) => ws.output.extend_from_slice(&data),
            Received::Json(value) if value == json!({"t": "pong"}) => return,
            other => panic!("no pong: {other:?}"),
        }
    }
}

async fn pong_after_a_probe_interval(ws: &mut Ws) -> Option<u64> {
    ws.send_text(r#"{"t":"ping"}"#).await;
    loop {
        match ws.next().await {
            Received::Output(data) => ws.output.extend_from_slice(&data),
            Received::Json(value) if value["t"] == "pong" => {
                let fields: Vec<&String> = value.as_object().unwrap().keys().collect();
                assert!(
                    fields
                        .iter()
                        .all(|field| *field == "t" || *field == "node_ms"),
                    "{value}"
                );
                return value.get("node_ms").map(|node_ms| {
                    let measured = node_ms.as_u64().expect("node_ms is not a whole number");
                    assert!(measured <= 20_000, "{value}");
                    measured
                });
            }
            other => panic!("no pong: {other:?}"),
        }
    }
}

async fn settled(what: &str, counter: impl Fn() -> u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = counter();
    let mut since = Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = counter();
        if now != last {
            last = now;
            since = Instant::now();
        } else if since.elapsed() >= Duration::from_secs(1) {
            return now;
        }
        assert!(Instant::now() < deadline, "{what} never stopped growing");
    }
}

#[tokio::test]
async fn a_browser_opens_a_terminal_types_resizes_and_sees_the_exit_status() {
    capture_everything();
    let stand = TerminalStand::start().await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    assert_eq!(ws.stages, ["node", "shell"]);
    ws.send(b"size\r").await;
    ws.output_until(b"80x24\r\n").await;
    ws.send_text(r#"{"t":"resize","cols":120,"rows":40}"#).await;
    ws.send(b"size\r").await;
    ws.output_until(b"120x40\r\n").await;
    pong(&mut ws).await;
    ws.send(b"hostile\r").await;
    ws.output_until(HOSTILE).await;
    ws.send(b"exit 3\r").await;
    let messages = ended_with(&mut ws, None, 1000).await;
    assert_eq!(
        messages,
        [json!({"t": "exit", "status": 3, "signal": null})]
    );

    let opened = audited("terminal.opened", opened_event(&session_id)).await;
    assert_eq!(field(&opened, "node"), NODE);
    assert_eq!(field(&opened, "login"), RECORDED_LOGIN);
    assert_eq!(field(&opened, "user_id"), stand.alice.user_id);
    assert_eq!(field(&opened, "client_addr"), format!("{BROWSER_ADDR}:0"));
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "exit");
    assert_eq!(field(&closed, "bytes_in"), "25");
    let routed = audited("session.routed", |event| {
        field(event, "event") == "session.routed" && field(event, "session_id") == session_id
    })
    .await;
    assert_eq!(field(&routed, "client_addr"), format!("{BROWSER_ADDR}:0"));
    let connected = audited("the in-process gate connection", |event| {
        field(event, "event") == "gate.ssh.connect" && field(event, "peer_addr") == "in-process"
    })
    .await;
    assert_eq!(
        field(&connected, "client_addr"),
        format!("{BROWSER_ADDR}:0")
    );

    let serial: i64 = field(&opened, "serial").parse().unwrap();
    let row = stand
        .harness
        .store
        .certificates()
        .get(serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.valid_before - row.issued_at, 120);
    assert_eq!(row.kind, "user");
    assert_eq!(row.key_id, format!("jaunt:alice@example.com:{serial}"));
    let seed = stand.keys.seeds()[0];
    let public = EphemeralKey::from_seed(&seed).public_openssh().unwrap();
    assert_eq!(
        row.subject_fingerprint.as_deref(),
        Some(fingerprint_hex(&CaPublicKey::from_openssh(&public).unwrap()).as_str())
    );
    let lines = stand.harness.control.web_terminal_certificates();
    assert_eq!(lines.len(), 1);
    let certificate = UserCertificate::from_openssh(&lines[0]).unwrap();
    assert_eq!(certificate.serial(), u64::try_from(serial).unwrap());
    assert_eq!(
        certificate
            .extensions()
            .get("jaunt-origin@globalart.dev")
            .map(String::as_str),
        Some("web")
    );

    eventually("the agent to finish the recording", || {
        stand
            .capture
            .of(&session_id)
            .is_some_and(|recorded| recorded.manifest.is_some())
    })
    .await;
    let recorded = stand.capture.of(&session_id).unwrap();
    assert!(recorded.record_input);
    let terminal = recorded.terminal.unwrap();
    assert_eq!(terminal.term, "xterm-256color");
    assert_eq!((terminal.size.columns, terminal.size.rows), (80, 24));
    assert_eq!(
        recorded.resizes,
        [TerminalSize {
            columns: 120,
            rows: 40,
            pixel_width: 0,
            pixel_height: 0,
        }]
    );
    assert_eq!(recorded.output, ws.output);
    assert_eq!(recorded.input, b"size\rsize\rhostile\rexit 3\r");
    assert_eq!(recorded.exit, Some(ChannelExit::Status(3)));
    let manifest = recorded.manifest.unwrap();
    assert!(manifest.input_recorded);
    assert!(!manifest.incomplete);
    assert!(recorded.cast.contains("\"i\""), "{}", recorded.cast);
    assert!(recorded.cast.contains("120x40"));

    eventually("the ephemeral key to be released", || {
        stand.keys.all_released()
    })
    .await;
    let logged = everything_logged();
    assert!(logged.contains("terminal.closed"));
    let blob = lines[0].split_whitespace().nth(1).unwrap();
    let private = russh::keys::PrivateKey::from(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed),
    )
    .to_openssh(russh::keys::ssh_key::LineEnding::LF)
    .unwrap();
    let hex: String = seed.iter().map(|byte| format!("{byte:02x}")).collect();
    for secret in [
        hex,
        STANDARD.encode(seed),
        URL_SAFE_NO_PAD.encode(seed),
        blob.to_owned(),
        blob[..64].to_owned(),
    ]
    .into_iter()
    .chain(
        private
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::to_owned),
    ) {
        assert!(!logged.contains(&secret), "a secret reached the logs");
    }
}

#[tokio::test]
async fn a_login_the_roles_stop_allowing_is_denied_without_any_sshd_login() {
    let stand = TerminalStand::start().await;
    let ticket = stand.ticket(&stand.alice, RECORDED_LOGIN).await;
    stand.deny_the_recorded_login();
    let mut ws = stand
        .open_with_ticket(&stand.alice, RECORDED_LOGIN, &ticket)
        .await
        .unwrap();
    ended_with(&mut ws, Some("denied"), 1008).await;
    assert_eq!(stand.sshd.log.logins.load(Ordering::SeqCst), 0);
    audited("the authorize denial", |event| {
        field(event, "event") == "authz.deny"
            && field(event, "phase") == "authorize"
            && field(event, "login") == RECORDED_LOGIN
    })
    .await;
    audited("the terminal denial", |event| {
        field(event, "event") == "terminal.denied" && field(event, "reason") == "denied"
    })
    .await;
    let (status, body) = stand
        .post(
            &stand.alice,
            "/v1/web/terminal/ticket",
            &json!({"node": NODE, "login": RECORDED_LOGIN}),
        )
        .await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert_eq!(without_reference(&body, "D-"), json!({"error": "denied"}));
}

#[tokio::test]
async fn input_reaches_the_recording_only_when_the_role_records_it() {
    let stand = TerminalStand::start().await;
    let (mut ws, session_id) = stand.ready(&stand.alice, PLAIN_LOGIN).await;
    ws.send(b"size\r").await;
    ws.output_until(b"80x24\r\n").await;
    ws.send(b"exit 0\r").await;
    ended_with(&mut ws, None, 1000).await;
    eventually("the agent to finish the recording", || {
        stand
            .capture
            .of(&session_id)
            .is_some_and(|recorded| recorded.manifest.is_some())
    })
    .await;
    let recorded = stand.capture.of(&session_id).unwrap();
    assert!(!recorded.record_input);
    let manifest = recorded.manifest.unwrap();
    assert!(!manifest.input_recorded);
    assert_eq!(manifest.bytes_in, 12);
    assert!(!recorded.cast.contains("\"i\""), "{}", recorded.cast);
    assert!(recorded.cast.contains("80x24"));
    assert_eq!(recorded.output, ws.output);
}

#[tokio::test]
async fn revoking_the_certificate_the_user_or_the_node_closes_the_terminal_with_4001_in_time() {
    let stand = TerminalStand::start().await;
    let cases: [(&Browser, RevocationKind); 3] = [
        (&stand.alice, RevocationKind::Serial),
        (&stand.bob, RevocationKind::User),
        (&stand.carol, RevocationKind::Node),
    ];
    for (who, kind) in cases {
        let (mut ws, session_id) = stand.ready(who, RECORDED_LOGIN).await;
        let subject = match kind {
            RevocationKind::Serial => {
                let opened = audited("terminal.opened", opened_event(&session_id)).await;
                field(&opened, "serial").to_owned()
            }
            RevocationKind::User => who.user_id.clone(),
            RevocationKind::Node => stand.node_id.clone(),
        };
        let started = Instant::now();
        stand
            .harness
            .control
            .revocations()
            .revoke(
                &RevokeRequest {
                    kind,
                    subject,
                    reason: "test".to_owned(),
                },
                APPROVER,
            )
            .await
            .unwrap();
        ended_with(&mut ws, Some("revoked"), 4001).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{kind:?} took {:?}",
            started.elapsed()
        );
        let closed = audited("terminal.closed", closed_event(&session_id)).await;
        assert_eq!(field(&closed, "reason"), "revoked");
    }
}

#[tokio::test]
async fn the_fifth_terminal_of_a_user_and_one_past_the_global_cap_are_refused_with_limit() {
    let stand = TerminalStand::start_with(StandOptions {
        settings: WebTerminalSettings {
            max_per_user: 4,
            max_total: 5,
            ..WebTerminalSettings::default()
        },
        ..StandOptions::default()
    })
    .await;
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(stand.ready(&stand.alice, RECORDED_LOGIN).await.0);
    }
    let (status, body) = stand
        .post(
            &stand.alice,
            "/v1/web/terminal/ticket",
            &json!({"node": NODE, "login": RECORDED_LOGIN}),
        )
        .await;
    assert_eq!(status, http::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        without_reference(&body, "D-"),
        json!({"error": "limit", "open": 4, "max": 4})
    );
    open.push(stand.ready(&stand.bob, RECORDED_LOGIN).await.0);
    let mut sixth = stand.open(&stand.carol, RECORDED_LOGIN).await;
    ended_with(&mut sixth, Some("limit"), 1008).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 5);
    audited("the limit denial", |event| {
        field(event, "event") == "terminal.denied" && field(event, "reason") == "limit"
    })
    .await;
    drop(open);
    eventually("every terminal to close", || {
        stand.harness.control.web_terminal_counters().open == 0
    })
    .await;
}

#[tokio::test]
async fn idleness_a_logout_and_the_daemon_stop_close_the_terminal() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut idle, idle_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    time.advance_ticker(Duration::from_secs(30 * 60));
    ended_with(&mut idle, Some("timeout"), 4002).await;
    let closed = audited("terminal.closed", closed_event(&idle_id)).await;
    assert_eq!(field(&closed, "reason"), "idle_timeout");

    let (mut bobs, bob_id) = stand.ready(&stand.bob, RECORDED_LOGIN).await;
    let started = Instant::now();
    let (status, _) = stand.post(&stand.bob, "/v1/web/logout", &json!({})).await;
    assert_eq!(status, http::StatusCode::NO_CONTENT);
    ended_with(&mut bobs, Some("timeout"), 1008).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the logout took {:?} to close the terminal",
        started.elapsed()
    );
    let closed = audited("terminal.closed", closed_event(&bob_id)).await;
    assert_eq!(field(&closed, "reason"), "web_session_ended");

    eventually("the closed terminals to leave", || {
        stand.harness.control.web_terminal_counters().open == 0
    })
    .await;
    let (mut carols, _) = stand.ready(&stand.carol, RECORDED_LOGIN).await;
    assert_eq!(
        stand
            .harness
            .control
            .close_web_terminals(Duration::from_secs(5))
            .await,
        1
    );
    ended_with(&mut carols, Some("unavailable"), 1001).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 0);
    let mut late = stand.open(&stand.alice, RECORDED_LOGIN).await;
    ended_with(&mut late, Some("unavailable"), 1001).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 0);
}

#[tokio::test]
async fn without_any_hook_the_recheck_closes_terminals_of_a_gone_web_session_or_a_revoked_user() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        quiet_watchers: true,
        ..StandOptions::default()
    })
    .await;
    let (mut signed_out, signed_out_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    let (mut revoked, revoked_id) = stand.ready(&stand.bob, RECORDED_LOGIN).await;
    let pool =
        SqlitePool::connect_with(SqliteConnectOptions::new().filename(&stand.harness.db_path))
            .await
            .unwrap();
    sqlx::query("DELETE FROM web_sessions WHERE user_id = ?")
        .bind(&stand.alice.user_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO revocations (id, kind, subject, reason, created_at, created_by) \
         VALUES ('r-recheck', ?, ?, 'test', 0, 'cli:tester')",
    )
    .bind(RevocationKind::User.as_str())
    .bind(&stand.bob.user_id)
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    time.advance_ticker(Duration::from_secs(30));
    pong_after_a_probe_interval(&mut signed_out).await;
    pong_after_a_probe_interval(&mut revoked).await;
    time.advance_ticker(Duration::from_secs(31));
    ended_with(&mut signed_out, Some("timeout"), 1008).await;
    ended_with(&mut revoked, Some("revoked"), 4001).await;
    let closed = audited("terminal.closed", closed_event(&signed_out_id)).await;
    assert_eq!(field(&closed, "reason"), "web_session_ended");
    let closed = audited("terminal.closed", closed_event(&revoked_id)).await;
    assert_eq!(field(&closed, "reason"), "revoked");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    RevokedNode,
    RemovedNode,
    RevokedUser,
    RevokedSerial,
    DroppedAgent,
    DroppedAgentWithSweep,
}

fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn revoke_quietly(stand: &TerminalStand, kind: RevocationKind, subject: String) {
    stand
        .harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind,
                subject,
                reason: "test".to_owned(),
                created_by: APPROVER.to_owned(),
            },
            unix_now(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_terminal_cut_off_without_an_exit_status_ends_by_the_stored_cause_never_as_an_exit() {
    for (cut, error, code) in [
        (Cut::RevokedNode, "revoked", 4001),
        (Cut::RemovedNode, "unavailable", 1011),
        (Cut::RevokedUser, "revoked", 4001),
        (Cut::RevokedSerial, "revoked", 4001),
        (Cut::DroppedAgent, "unavailable", 1011),
        (Cut::DroppedAgentWithSweep, "unavailable", 1011),
    ] {
        let mut stand = TerminalStand::start_with(StandOptions {
            quiet_watchers: cut != Cut::DroppedAgentWithSweep,
            eager_sweep: cut == Cut::DroppedAgentWithSweep,
            ..StandOptions::default()
        })
        .await;
        let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
        match cut {
            Cut::RevokedNode => {
                revoke_quietly(&stand, RevocationKind::Node, stand.node_id.clone()).await;
            }
            Cut::RemovedNode => {
                stand
                    .harness
                    .store
                    .nodes()
                    .remove_by_name(NODE, unix_now())
                    .await
                    .unwrap()
                    .unwrap();
            }
            Cut::RevokedUser => {
                revoke_quietly(&stand, RevocationKind::User, stand.alice.user_id.clone()).await;
                stand.cut_agent().await;
            }
            Cut::RevokedSerial => {
                let opened = audited("terminal.opened", opened_event(&session_id)).await;
                let serial = field(&opened, "serial").to_owned();
                revoke_quietly(&stand, RevocationKind::Serial, serial).await;
                stand.cut_agent().await;
            }
            Cut::DroppedAgent | Cut::DroppedAgentWithSweep => stand.cut_agent().await,
        }
        let messages = ended_with(&mut ws, Some(error), code).await;
        assert!(
            !messages.iter().any(|message| message["t"] == "exit"),
            "{cut:?}: {messages:?}"
        );
        let closed = audited("terminal.closed", closed_event(&session_id)).await;
        assert_eq!(field(&closed, "reason"), error, "{cut:?}");
    }
}

#[tokio::test]
async fn a_shell_ended_by_a_signal_reports_the_signal_and_closes_normally() {
    let stand = TerminalStand::start().await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"signal\r").await;
    let messages = ended_with(&mut ws, None, 1000).await;
    assert_eq!(
        messages,
        [json!({"t": "exit", "status": null, "signal": "TERM"})]
    );
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "exit");
}

#[tokio::test]
async fn output_flowing_to_a_silent_browser_does_not_keep_it_alive() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"ticker\r").await;
    ws.output_until(b"tick\r\n").await;
    time.advance_ticker(Duration::from_secs(21));
    eventually("the browser to be pinged", || pings(&stand) >= 1).await;
    time.advance_ticker(Duration::from_secs(40));
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "dead_peer");
    assert_eq!(ws.ending().await.1, None);
}

fn pings(stand: &TerminalStand) -> u64 {
    stand.harness.control.web_terminal_counters().pings
}

#[tokio::test]
async fn a_browser_reading_steady_output_and_answering_pings_is_never_a_dead_peer() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"flood\r").await;
    let (_sink, mut stream) = ws.socket.split();
    let seen = Arc::new(AtomicU64::new(0));
    let read = Arc::clone(&seen);
    let reader = tokio::spawn(async move {
        while let Some(Ok(message)) = stream.next().await {
            if let Message::Binary(data) = message {
                read.fetch_add(u64::try_from(data.len()).unwrap(), Ordering::SeqCst);
            }
        }
    });
    eventually("the flood to reach the browser", || {
        seen.load(Ordering::SeqCst) > 1 << 20
    })
    .await;
    for round in 1..=4 {
        time.advance_ticker(Duration::from_secs(21));
        eventually("a ping between the output chunks", || {
            pings(&stand) >= round
        })
        .await;
        let flowing = seen.load(Ordering::SeqCst);
        eventually("the output to keep flowing", || {
            seen.load(Ordering::SeqCst) > flowing
        })
        .await;
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 1);
    assert!(!reader.is_finished());
    reader.abort();
}

#[tokio::test]
async fn a_browser_reading_steady_output_but_never_answering_pings_is_a_dead_peer() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut raw, session_id) = stand.raw(&stand.alice, RECORDED_LOGIN).await;
    raw.send(b"flood\r").await;
    let seen = Arc::clone(&raw.seen);
    eventually("the flood to reach the browser", || {
        seen.output.load(Ordering::SeqCst) > 1 << 20
    })
    .await;
    time.advance_ticker(Duration::from_secs(21));
    eventually("a ping between the output chunks", || {
        seen.pings.load(Ordering::SeqCst) >= 1
    })
    .await;
    time.advance_ticker(Duration::from_secs(40));
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "dead_peer");
    eventually("the dead peer to be cut off", || {
        seen.closed.load(Ordering::SeqCst)
    })
    .await;
}

#[tokio::test]
async fn a_terminal_whose_input_waits_without_progress_either_way_is_closed_as_wedged() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut raw, session_id) = stand.raw(&stand.alice, RECORDED_LOGIN).await;
    raw.send(b"sink\r").await;
    let seen = Arc::clone(&raw.seen);
    eventually("the node to stop reading", || {
        seen.output.load(Ordering::SeqCst) >= u64::try_from(b"sinking\r\n".len()).unwrap()
    })
    .await;
    let typed = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&typed);
    let typist = tokio::spawn(async move {
        let frame = vec![b't'; 32 * 1024];
        while raw.try_send(&frame).await {
            counted.fetch_add(32 * 1024, Ordering::SeqCst);
        }
    });
    settled("the typed input", || typed.load(Ordering::SeqCst)).await;
    time.advance_ticker(Duration::from_secs(50));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 1);
    time.advance_ticker(Duration::from_secs(11));
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "wedged");
    eventually("the wedged terminal to close", || {
        seen.closed.load(Ordering::SeqCst)
    })
    .await;
    assert_eq!(*seen.close_code.lock().unwrap(), Some(4003));
    let last = seen.texts.lock().unwrap().last().cloned().unwrap();
    assert_eq!(
        without_reference(&last, "D-"),
        json!({"t": "error", "code": "stalled"})
    );
    typist.abort();
}

fn socket_progress(stand: &TerminalStand) -> u64 {
    stand
        .harness
        .control
        .web_terminal_counters()
        .socket_progress
}

async fn flood(raw: &mut RawBrowser) {
    raw.send(b"flood\r").await;
    let seen = Arc::clone(&raw.seen);
    eventually("the flood to reach the browser", || {
        seen.output.load(Ordering::SeqCst) > 1 << 20
    })
    .await;
}

async fn stop_reading(stand: &TerminalStand, raw: &RawBrowser) {
    raw.read_output(false);
    let log = Arc::clone(&stand.sshd.log);
    settled("the flood", || log.flooded.load(Ordering::SeqCst)).await;
}

#[tokio::test]
async fn a_browser_that_reads_between_short_stalls_is_not_closed_as_stalled() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut raw, _) = stand.raw(&stand.alice, RECORDED_LOGIN).await;
    flood(&mut raw).await;
    for _ in 0..4 {
        stop_reading(&stand, &raw).await;
        time.advance_ticker(Duration::from_secs(45));
        raw.pong().await;
        let before = socket_progress(&stand);
        raw.read_output(true);
        eventually("the socket to take more output", || {
            socket_progress(&stand) > before
        })
        .await;
    }
    assert_eq!(stand.harness.control.web_terminal_counters().open, 1);
    assert!(!raw.seen.closed.load(Ordering::SeqCst));
}

#[tokio::test]
async fn a_browser_that_stops_reading_output_is_closed_as_stalled_at_the_threshold() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut raw, session_id) = stand.raw(&stand.alice, RECORDED_LOGIN).await;
    flood(&mut raw).await;
    stop_reading(&stand, &raw).await;
    time.advance_ticker(Duration::from_secs(50));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(stand.harness.control.web_terminal_counters().open, 1);
    time.advance_ticker(Duration::from_secs(11));
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "wedged");
    raw.read_output(true);
    let seen = Arc::clone(&raw.seen);
    eventually("the stalled terminal to close", || {
        seen.closed.load(Ordering::SeqCst)
    })
    .await;
}

fn ticks(output: &[u8]) -> usize {
    output
        .windows(b"tick\r\n".len())
        .filter(|window| *window == b"tick\r\n")
        .count()
}

async fn next_tick(ws: &mut Ws) {
    let seen = ticks(&ws.output);
    while ticks(&ws.output) == seen {
        match ws.next().await {
            Received::Output(data) => ws.output.extend_from_slice(&data),
            other => panic!("the terminal ended while output flowed: {other:?}"),
        }
    }
}

const PAST_IDLE_STEPS: usize = 37;
const STEP_UNDER_DEAD_PEER: Duration = Duration::from_secs(50);

#[tokio::test]
async fn output_alone_keeps_a_terminal_open_past_the_idle_timeout() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"ticker\r").await;
    for _ in 0..PAST_IDLE_STEPS {
        time.advance_ticker(STEP_UNDER_DEAD_PEER);
        next_tick(&mut ws).await;
        pong_after_a_probe_interval(&mut ws).await;
    }
    while ticks(&ws.output) < 45 {
        next_tick(&mut ws).await;
    }
    time.advance_ticker(Duration::from_secs(31 * 60));
    ended_with(&mut ws, Some("timeout"), 4002).await;
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "idle_timeout");
}

#[tokio::test]
async fn input_alone_keeps_a_terminal_open_past_the_idle_timeout() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"sink\r").await;
    ws.output_until(b"sinking\r\n").await;
    for _ in 0..PAST_IDLE_STEPS {
        time.advance_ticker(STEP_UNDER_DEAD_PEER);
        ws.send(b"k").await;
        pong_after_a_probe_interval(&mut ws).await;
    }
    time.advance_ticker(Duration::from_secs(31 * 60));
    ended_with(&mut ws, Some("timeout"), 4002).await;
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "idle_timeout");
}

#[tokio::test]
async fn a_node_with_an_untrusted_host_certificate_is_unavailable_and_the_reason_is_recorded() {
    capture_everything();
    let stand = TerminalStand::start_with(StandOptions {
        foreign_host_certificate: true,
        ..StandOptions::default()
    })
    .await;
    let mut ws = stand.open(&stand.alice, RECORDED_LOGIN).await;
    ended_with(&mut ws, Some("unavailable"), 1011).await;
    let denied = audited("the node host key refusal", |event| {
        field(event, "event") == "terminal.denied" && field(event, "reason") == "node_host_key"
    })
    .await;
    assert_eq!(field(&denied, "node"), NODE);
    let logged = everything_logged();
    assert!(logged.contains("a web terminal could not reach the node"));
    assert!(!logged.contains("BEGIN OPENSSH"));
}

#[tokio::test]
async fn the_web_session_expiry_and_the_session_time_limit_close_the_terminal() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let pool =
        SqlitePool::connect_with(SqliteConnectOptions::new().filename(&stand.harness.db_path))
            .await
            .unwrap();
    sqlx::query("UPDATE web_sessions SET expires_at = expires_at + 86400 WHERE user_id = ?")
        .bind(&stand.carol.user_id)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let (mut expiring, expiring_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    let (mut limited, limited_id) = stand.ready(&stand.carol, RECORDED_LOGIN).await;

    time.advance_clock(Duration::from_secs(8 * 3600 + 1));
    ended_with(&mut expiring, Some("timeout"), 1008).await;
    let closed = audited("terminal.closed", closed_event(&expiring_id)).await;
    assert_eq!(field(&closed, "reason"), "web_session_ended");
    pong(&mut limited).await;

    time.advance_clock(Duration::from_secs(4 * 3600 + 5));
    ended_with(&mut limited, Some("timeout"), 1008).await;
    let closed = audited("terminal.closed", closed_event(&limited_id)).await;
    assert_eq!(field(&closed, "reason"), "max_duration");
}

#[tokio::test]
async fn a_silent_browser_is_dropped_as_a_dead_peer_while_a_responsive_one_stays() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut silent, silent_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    let (responsive, _) = stand.ready(&stand.bob, RECORDED_LOGIN).await;
    let (mut sink, mut stream) = responsive.socket.split();
    let pings = Arc::new(AtomicU64::new(0));
    let pongs = Arc::new(AtomicU64::new(0));
    let (seen_pings, seen_pongs) = (Arc::clone(&pings), Arc::clone(&pongs));
    let reader = tokio::spawn(async move {
        while let Some(Ok(message)) = stream.next().await {
            match message {
                Message::Ping(_) => {
                    seen_pings.fetch_add(1, Ordering::SeqCst);
                }
                Message::Text(text)
                    if serde_json::from_str::<Value>(text.as_str())
                        .is_ok_and(|frame| frame["t"] == "pong") =>
                {
                    seen_pongs.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
    });
    time.advance_ticker(Duration::from_secs(21));
    eventually("the browsers to be pinged", || {
        pings.load(Ordering::SeqCst) > 0 && stand.harness.control.web_terminal_counters().pings >= 2
    })
    .await;
    sink.send(Message::Text(r#"{"t":"ping"}"#.into()))
        .await
        .unwrap();
    eventually("the responsive browser to be heard", || {
        pongs.load(Ordering::SeqCst) > 0
    })
    .await;
    time.advance_ticker(Duration::from_secs(40));
    let closed = audited("terminal.closed", closed_event(&silent_id)).await;
    assert_eq!(field(&closed, "reason"), "dead_peer");
    assert_eq!(silent.ending().await.1, None);
    eventually("only the responsive terminal to stay", || {
        stand.harness.control.web_terminal_counters().open == 1
    })
    .await;
    assert!(!reader.is_finished());
    reader.abort();
}

#[tokio::test]
async fn a_flooding_node_stalls_while_the_browser_does_not_read() {
    let stand = TerminalStand::start().await;
    let (mut ws, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"flood\r").await;
    let log = Arc::clone(&stand.sshd.log);
    let stalled = settled("the flood", || log.flooded.load(Ordering::SeqCst)).await;
    assert!(stalled > 0 && stalled < BOUND, "{stalled}");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let counters = stand.harness.control.web_terminal_counters();
    assert!(
        counters.max_node_ahead <= u64::from(WEB_WINDOW)
            && counters.max_node_ahead + CHUNK >= u64::from(WEB_WINDOW),
        "{counters:?}"
    );
    assert!(
        counters.max_pending_output <= WRITER_CHUNKS * CHUNK,
        "{counters:?}"
    );
    let mut read = 0_u64;
    while log.flooded.load(Ordering::SeqCst) < stalled + 2 * u64::from(WEB_WINDOW) {
        match ws.next().await {
            Received::Output(data) => read += u64::try_from(data.len()).unwrap(),
            other => panic!("the flood ended: {other:?}"),
        }
    }
    assert!(read > 0);
    assert!(
        stand
            .harness
            .control
            .web_terminal_counters()
            .max_pending_output
            <= u64::from(WEB_WINDOW)
    );
    assert!(log.tasks.load(Ordering::SeqCst) > 0);
    drop(ws);
    eventually(
        "the fake sshd to end the tasks of the closed terminal",
        || log.tasks.load(Ordering::SeqCst) == 0,
    )
    .await;
}

const PASTES: [usize; 3] = [2 << 20, 4 << 20, 16 << 20];
const PASTE_STALL: Duration = Duration::from_secs(10);

async fn paste_and_echo(stand: &TerminalStand, size: usize) {
    let (ws, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    let (mut sink, mut stream) = ws.socket.split();
    let typist = tokio::spawn(async move {
        let frame = Bytes::from(vec![b'p'; 32 * 1024]);
        let mut sent = 0;
        while sent < size {
            sink.send(Message::Binary(frame.clone())).await.unwrap();
            sent += frame.len();
        }
        sink
    });
    let mut echoed = 0;
    while echoed < size {
        let message = tokio::time::timeout(PASTE_STALL, stream.next())
            .await
            .unwrap_or_else(|_| panic!("a paste of {size} bytes wedged after {echoed} echoed"));
        match message {
            Some(Ok(Message::Binary(data))) => echoed += data.len(),
            Some(Ok(_)) => {}
            other => panic!("the terminal ended during a paste of {size} bytes: {other:?}"),
        }
    }
    assert_eq!(echoed, size);
    let sink = tokio::time::timeout(PASTE_STALL, typist)
        .await
        .expect("the paste never finished sending")
        .unwrap();
    drop(sink.reunite(stream));
}

#[tokio::test(flavor = "current_thread")]
async fn a_paste_echoed_back_by_the_node_never_wedges_on_one_thread() {
    let stand = TerminalStand::start().await;
    for size in PASTES {
        paste_and_echo(&stand, size).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paste_echoed_back_by_the_node_never_wedges_on_many_threads() {
    let stand = TerminalStand::start().await;
    for size in PASTES {
        paste_and_echo(&stand, size).await;
    }
}

#[tokio::test]
async fn a_flooding_browser_stalls_while_the_node_does_not_read() {
    let stand = TerminalStand::start().await;
    let (mut ws, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    ws.send(b"sink\r").await;
    ws.output_until(b"sinking\r\n").await;
    let (mut sink, _stream) = ws.socket.split();
    let sent = Arc::new(AtomicU64::new(0));
    let counted = Arc::clone(&sent);
    let flood = tokio::spawn(async move {
        let frame = Bytes::from(vec![b'y'; 60 * 1024]);
        while sink.send(Message::Binary(frame.clone())).await.is_ok() {
            counted.fetch_add(60 * 1024, Ordering::SeqCst);
        }
    });
    let stalled = settled("the browser flood", || sent.load(Ordering::SeqCst)).await;
    assert!(stalled > 0 && stalled < BOUND, "{stalled}");
    let log = Arc::clone(&stand.sshd.log);
    let reached = settled("the node input", || log.input.load(Ordering::SeqCst)).await;
    assert!(reached <= u64::from(SSHD_WINDOW) + 64 * 1024, "{reached}");
    let counters = stand.harness.control.web_terminal_counters();
    assert!(counters.max_pending_input <= 64 * 1024, "{counters:?}");
    flood.abort();
}

#[tokio::test]
async fn oversized_frames_and_malformed_messages_close_the_terminal() {
    let stand = TerminalStand::start().await;
    let (mut big, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    big.send(&vec![b'z'; 70 * 1024]).await;
    ended_with(&mut big, None, 1009).await;
    for text in [
        "not json",
        r#"{"t":"exec","command":"id"}"#,
        r#"{"t":"resize","cols":0,"rows":1}"#,
    ] {
        let (mut malformed, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
        malformed.send_text(text).await;
        ended_with(&mut malformed, None, 1008).await;
        let closed = audited("terminal.closed", closed_event(&session_id)).await;
        assert_eq!(field(&closed, "reason"), "malformed", "{text}");
    }
}

#[tokio::test]
async fn a_browser_gone_during_the_handshake_leaves_nothing_open_and_its_ticket_spent() {
    let stand = TerminalStand::start().await;
    let ticket = stand.ticket(&stand.alice, RECORDED_LOGIN).await;
    let mut tcp = TcpStream::connect(stand.http).await.unwrap();
    let request = format!(
        "GET /v1/web/terminal?node={NODE}&login={RECORDED_LOGIN}&cols=80&rows=24 HTTP/1.1\r\n\
         Host: jaunt.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Origin: {PUBLIC_ORIGIN}\r\nCookie: {}\r\n\
         Sec-WebSocket-Protocol: jaunt-terminal.v1, jaunt-ticket.{ticket}\r\n\r\n",
        stand.alice.cookie
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 101"));
    drop(tcp);

    let gate = Arc::clone(stand.gate.gate());
    eventually("the abandoned terminal to leave nothing behind", || {
        stand.harness.control.web_terminal_counters().open == 0
            && gate.authenticated() == 0
            && gate.unauthenticated() == 0
            && gate.open_streams() == 0
    })
    .await;
    let reused = stand
        .open_with_ticket(&stand.alice, RECORDED_LOGIN, &ticket)
        .await;
    assert!(matches!(reused, Err(http::StatusCode::FORBIDDEN)));
    eventually("the abandoned key to be released", || {
        stand.keys.all_released()
    })
    .await;
}

async fn quiet_for(ws: &mut Ws, span: Duration) {
    let deadline = tokio::time::Instant::now() + span;
    loop {
        match tokio::time::timeout_at(deadline, ws.socket.next()).await {
            Err(_) => return,
            Ok(Some(Ok(Message::Text(text)))) => panic!("the terminal sent {text} too early"),
            Ok(Some(Ok(Message::Binary(data)))) => ws.output.extend_from_slice(&data),
            Ok(Some(Ok(Message::Close(frame)))) => panic!("the terminal closed early: {frame:?}"),
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) => panic!("the terminal failed: {error}"),
            Ok(None) => panic!("the terminal ended early"),
        }
    }
}

async fn idle_warning(ws: &mut Ws) -> u64 {
    loop {
        match ws.next().await {
            Received::Output(data) => ws.output.extend_from_slice(&data),
            Received::Json(value) if value["t"] == "idle" => {
                assert_eq!(value.as_object().unwrap().len(), 2, "{value}");
                return value["seconds_left"].as_u64().unwrap();
            }
            other => panic!("no idle warning: {other:?}"),
        }
    }
}

#[tokio::test]
async fn the_idle_warning_comes_once_active_postpones_the_close_and_ping_does_not() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        settings: WebTerminalSettings {
            idle_timeout: Duration::from_secs(300),
            ..WebTerminalSettings::default()
        },
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;

    time.advance_ticker(Duration::from_secs(175));
    quiet_for(&mut ws, Duration::from_millis(1500)).await;
    time.advance_ticker(Duration::from_secs(5));
    let left = idle_warning(&mut ws).await;
    assert!((115..=120).contains(&left), "{left}");
    quiet_for(&mut ws, Duration::from_millis(2500)).await;

    ws.send_text(r#"{"t":"active"}"#).await;
    quiet_for(&mut ws, Duration::from_secs(1)).await;
    time.advance_ticker(Duration::from_secs(8));
    ws.send_text(r#"{"t":"active"}"#).await;
    quiet_for(&mut ws, Duration::from_millis(1500)).await;
    time.advance_ticker(Duration::from_secs(282));
    let left = idle_warning(&mut ws).await;
    assert!(left <= 15, "{left}");
    pong_after_a_probe_interval(&mut ws).await;
    time.advance_ticker(Duration::from_secs(12));
    tokio::time::timeout(
        Duration::from_millis(3500),
        ended_with(&mut ws, Some("timeout"), 4002),
    )
    .await
    .expect("the close came late: the second active inside ten seconds was counted");
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "idle_timeout");
}

#[tokio::test]
async fn pong_carries_the_node_round_trip_only_after_the_first_probe_answered() {
    let time = ManualTime::default();
    let stand = TerminalStand::start_with(StandOptions {
        time: Some(time.clone()),
        ..StandOptions::default()
    })
    .await;
    let (mut ws, _) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    pong(&mut ws).await;
    time.advance_ticker(Duration::from_secs(21));
    let deadline = Instant::now() + STEP;
    let measured = loop {
        if let Some(measured) = pong_after_a_probe_interval(&mut ws).await {
            break measured;
        }
        assert!(Instant::now() < deadline, "no pong carried node_ms");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(measured < 5_000, "{measured}");
}

#[tokio::test]
async fn an_administrator_terminate_sends_terminated_with_a_reference_and_closes_with_4004() {
    let stand = TerminalStand::start().await;
    let (mut ws, session_id) = stand.ready(&stand.alice, RECORDED_LOGIN).await;
    let started = Instant::now();

    let (status, body) = stand
        .post(
            &stand.carol,
            &format!("/v1/admin/sessions/{session_id}/terminate"),
            &json!({"reason": "end of shift"}),
        )
        .await;

    assert_eq!(status, http::StatusCode::NO_CONTENT, "{body}");
    let messages = ended_with(&mut ws, Some("terminated"), 4004).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    let reference = messages[0]["ref"].as_str().unwrap().to_owned();
    let closed = audited("terminal.closed", closed_event(&session_id)).await;
    assert_eq!(field(&closed, "reason"), "terminated");
    assert_eq!(field(&closed, "ref"), reference);
    let terminated = audited("session.terminated", |event| {
        field(event, "event") == "session.terminated" && field(event, "session_id") == session_id
    })
    .await;
    assert_eq!(
        field(&terminated, "by"),
        format!("web:{}", stand.carol.user_id)
    );
    assert_eq!(field(&terminated, "reason"), "end of shift");
    let (status, _) = stand
        .post(
            &stand.alice,
            &format!("/v1/admin/sessions/{session_id}/terminate"),
            &json!({}),
        )
        .await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_access_review_closes_a_web_terminal_whose_login_the_policy_took_away_and_keeps_the_rest()
 {
    let stand = TerminalStand::start().await;
    let (mut kept, kept_id) = stand.ready(&stand.alice, PLAIN_LOGIN).await;
    let (mut cut, cut_id) = stand.ready(&stand.bob, RECORDED_LOGIN).await;
    assert_eq!(
        stand
            .harness
            .control
            .review_access()
            .await
            .unwrap()
            .withdrawn,
        0
    );

    stand.deny_the_recorded_login();
    let started = Instant::now();
    let review = stand.harness.control.review_access().await.unwrap();
    assert_eq!(review.withdrawn, 1);
    ended_with(&mut cut, Some("revoked"), 4001).await;
    assert!(started.elapsed() < Duration::from_secs(5));
    let closed = audited("terminal.closed", closed_event(&cut_id)).await;
    assert_eq!(field(&closed, "reason"), "revoked");
    let sessions = stand.harness.store.sessions();
    assert_eq!(
        sessions.get(&cut_id).await.unwrap().unwrap().end_reason,
        Some(jaunt_store::SessionEndReason::AccessWithdrawn)
    );
    pong(&mut kept).await;
    assert_eq!(
        sessions.get(&kept_id).await.unwrap().unwrap().end_reason,
        None
    );
}
