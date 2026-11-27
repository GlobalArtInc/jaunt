use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use jaunt_host_users::{
    EnsureRequest, FailedStage, HostUsersSection, Name, NamesSection, Reason, Response,
    encode_response, parse_request,
};
use jaunt_proto::{
    AGENT_SESSION_ACCOUNT_PATH, AccountEvent, AccountEventKind, AccountReference, AccountRefusal,
    AccountReport, AccountStage,
};
use jaunt_ssh::{AccountKeeper, AccountStep};
use jaunt_tunnel::{BoxFuture, ClientEvent, ConnectFailure};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::announce::CapabilitySink;
use super::lookup::{LookupError, PasswdLookup, Presence};
use super::{
    ACCOUNT_TIMINGS, AccountParts, AccountService, AccountTimings, Availability, HostUsersPaths,
    announce_capabilities,
};
use crate::testkit::{ApiStep, FakeGate, LogCapture, ManualClock, eventually, gate_and_api, soon};

const UID: u32 = 30_001;
const AUDIT_LINE: &str = "\"target\":\"jaunt::audit\"";

#[derive(Clone)]
enum Reply {
    Answer(Response),
    Raw(&'static [u8]),
    Close,
    Hang,
    Held(Arc<Notify>, Box<Reply>),
    Slow(Duration, Box<Reply>),
}

#[derive(Default)]
struct HelperSeen {
    script: Mutex<VecDeque<Reply>>,
    requests: Mutex<Vec<EnsureRequest>>,
    connections: AtomicUsize,
    live: AtomicUsize,
    peak: AtomicUsize,
}

struct FakeHelper {
    seen: Arc<HelperSeen>,
    task: JoinHandle<()>,
}

impl Drop for FakeHelper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeHelper {
    fn start(socket: &Path) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        let seen = Arc::new(HelperSeen::default());
        let shared = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_helper(Arc::clone(&shared), stream));
            }
        });
        Self { seen, task }
    }

    fn script(&self, replies: impl IntoIterator<Item = Reply>) {
        self.seen.script.lock().unwrap().extend(replies);
    }

    fn connections(&self) -> usize {
        self.seen.connections.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<EnsureRequest> {
        self.seen.requests.lock().unwrap().clone()
    }
}

async fn serve_helper(seen: Arc<HelperSeen>, mut stream: UnixStream) {
    seen.connections.fetch_add(1, Ordering::SeqCst);
    let live = seen.live.fetch_add(1, Ordering::SeqCst) + 1;
    seen.peak.fetch_max(live, Ordering::SeqCst);
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    while stream.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    seen.requests
        .lock()
        .unwrap()
        .push(parse_request(&line).unwrap());
    let mut reply = seen
        .script
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(Reply::Answer(Response::Exists));
    loop {
        match reply {
            Reply::Held(release, then) => {
                release.notified().await;
                reply = *then;
            }
            Reply::Slow(delay, then) => {
                tokio::time::sleep(delay).await;
                reply = *then;
            }
            Reply::Answer(response) => {
                let encoded = encode_response(&response).unwrap();
                seen.live.fetch_sub(1, Ordering::SeqCst);
                stream.write_all(&encoded).await.unwrap();
                return;
            }
            Reply::Raw(bytes) => {
                seen.live.fetch_sub(1, Ordering::SeqCst);
                stream.write_all(bytes).await.unwrap();
                return;
            }
            Reply::Close => {
                seen.live.fetch_sub(1, Ordering::SeqCst);
                return;
            }
            Reply::Hang => std::future::pending::<()>().await,
        }
    }
}

#[derive(Default)]
struct FakeLookup {
    answers: Mutex<HashMap<String, Option<Presence>>>,
    calls: AtomicUsize,
}

impl FakeLookup {
    fn set(&self, login: &str, answer: Option<Presence>) {
        self.answers
            .lock()
            .unwrap()
            .insert(login.to_owned(), answer);
    }
}

impl PasswdLookup for FakeLookup {
    fn passwd<'a>(&'a self, login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self
            .answers
            .lock()
            .unwrap()
            .get(login.as_str())
            .copied()
            .unwrap_or(Some(Presence::Absent));
        Box::pin(async move { answer.ok_or(LookupError::Exit(Some(1))) })
    }
}

fn enabled() -> HostUsersSection {
    HostUsersSection {
        enabled: true,
        ..HostUsersSection::default()
    }
}

const FAST: AccountTimings = AccountTimings {
    helper: Duration::from_millis(500),
    report: Duration::from_millis(500),
    ..ACCOUNT_TIMINGS
};

struct Harness {
    gate: FakeGate,
    helper: FakeHelper,
    lookup: Arc<FakeLookup>,
    clock: Arc<ManualClock>,
    service: Arc<AccountService>,
    _dir: tempfile::TempDir,
}

struct Setup {
    section: HostUsersSection,
    nsswitch: &'static str,
    helper_socket: bool,
    timings: AccountTimings,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            section: enabled(),
            nsswitch: "passwd: files systemd\n",
            helper_socket: true,
            timings: FAST,
        }
    }
}

async fn harness(setup: Setup) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let served = dir.path().join("h.sock");
    let helper = FakeHelper::start(&served);
    let paths = HostUsersPaths {
        socket: if setup.helper_socket {
            served
        } else {
            dir.path().join("absent.sock")
        },
        nsswitch: dir.path().join("nsswitch.conf"),
        sssd_conf: dir.path().join("sssd.conf"),
    };
    std::fs::write(&paths.nsswitch, setup.nsswitch).unwrap();
    let (gate, api) = gate_and_api().await;
    let lookup = Arc::new(FakeLookup::default());
    let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000));
    let service = AccountService::new(AccountParts {
        availability: Arc::new(Availability::new(&setup.section, paths)),
        lookup: Arc::clone(&lookup) as Arc<dyn PasswdLookup>,
        api,
        clock: clock.clone(),
        timings: setup.timings,
    });
    Harness {
        gate,
        helper,
        lookup,
        clock,
        service: Arc::new(service),
        _dir: dir,
    }
}

impl Harness {
    async fn ensure(&self, login: &str, session: &str) -> AccountStep {
        soon("the account step", self.service.ensure(login, session)).await
    }

    fn reports(&self, session: &str) -> Vec<AccountReport> {
        self.gate
            .requests(AGENT_SESSION_ACCOUNT_PATH)
            .iter()
            .map(|seen| serde_json::from_slice::<AccountReport>(&seen.body).unwrap())
            .filter(|report| report.session_id == session)
            .collect()
    }

    fn all_reports(&self) -> usize {
        self.gate.requests(AGENT_SESSION_ACCOUNT_PATH).len()
    }
}

fn kinds(reports: &[AccountReport]) -> Vec<AccountEventKind> {
    reports.iter().map(|report| report.event).collect()
}

fn reference_of(report: &AccountReport) -> AccountReference {
    report.reference.clone().unwrap()
}

fn audits(capture: &LogCapture, event: &str, session: &str) -> Vec<Value> {
    every_audit(capture, event)
        .into_iter()
        .filter(|fields| fields["session_id"] == session)
        .collect()
}

fn every_audit(capture: &LogCapture, event: &str) -> Vec<Value> {
    capture
        .text()
        .lines()
        .filter(|line| line.contains(AUDIT_LINE))
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .map(|line| line["fields"].clone())
        .filter(|fields| fields["event"] == event)
        .collect()
}

fn host_user_audits(capture: &LogCapture, session: &str) -> usize {
    capture
        .text()
        .lines()
        .filter(|line| line.contains(AUDIT_LINE))
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|line| {
            line["fields"]["session_id"] == session
                && line["fields"]["event"]
                    .as_str()
                    .is_some_and(|event| event.starts_with("agent.host_user."))
        })
        .count()
}

fn created(uid: u32, login: &str) -> Response {
    Response::Created {
        uid,
        home: format!("/home/{login}"),
        groups: vec![Name::parse(login).unwrap(), Name::parse("users").unwrap()],
    }
}

type ExpectedEvent = Box<dyn Fn(AccountReference) -> Option<AccountEvent>>;

struct Case {
    name: String,
    reply: Reply,
    step: AccountStep,
    outcome: ExpectedEvent,
    audit: Option<(&'static str, &'static str, Value)>,
}

fn failed(stage: AccountStage, exit_code: Option<i32>) -> ExpectedEvent {
    Box::new(move |reference| {
        Some(AccountEvent::Failed {
            reference,
            stage,
            exit_code,
        })
    })
}

fn helper_cases() -> Vec<Case> {
    let mut cases = vec![
        Case {
            name: "created".to_owned(),
            reply: Reply::Answer(created(UID, "u0")),
            step: AccountStep::Continue,
            outcome: Box::new(|reference| {
                Some(AccountEvent::Created {
                    reference,
                    uid: UID,
                    home: "/home/u0".to_owned(),
                    groups: vec!["u0".to_owned(), "users".to_owned()],
                })
            }),
            audit: Some(("agent.host_user.created", "uid", json!(UID))),
        },
        Case {
            name: "exists".to_owned(),
            reply: Reply::Answer(Response::Exists),
            step: AccountStep::Continue,
            outcome: Box::new(|_| None),
            audit: None,
        },
        Case {
            name: "disabled".to_owned(),
            reply: Reply::Answer(Response::Disabled),
            step: AccountStep::NoAccount,
            outcome: Box::new(|reference| Some(AccountEvent::Missing { reference })),
            audit: Some(("agent.host_user.missing", "cause", json!("helper_disabled"))),
        },
        Case {
            name: "uid zero".to_owned(),
            reply: Reply::Answer(created(0, "u3")),
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Verify, None),
            audit: Some(("agent.host_user.helper_failed", "stage", json!("verify"))),
        },
        Case {
            name: "uid outside the range".to_owned(),
            reply: Reply::Answer(created(40_000, "u4")),
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Verify, None),
            audit: Some(("agent.host_user.helper_failed", "stage", json!("verify"))),
        },
        Case {
            name: "timeout".to_owned(),
            reply: Reply::Hang,
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Request, None),
            audit: Some(("agent.host_user.helper_failed", "cause", json!("timeout"))),
        },
        Case {
            name: "closed".to_owned(),
            reply: Reply::Close,
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Request, None),
            audit: Some(("agent.host_user.helper_failed", "cause", json!("closed"))),
        },
        Case {
            name: "garbage".to_owned(),
            reply: Reply::Raw(b"{\"v\":1,\"result\":\"created\",\"uid\":5}\n"),
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Request, None),
            audit: Some(("agent.host_user.helper_failed", "cause", json!("malformed"))),
        },
        Case {
            name: "home elsewhere".to_owned(),
            reply: Reply::Answer(Response::Created {
                uid: UID,
                home: "/srv/u8".to_owned(),
                groups: vec![Name::parse("u8").unwrap()],
            }),
            step: AccountStep::Failed,
            outcome: failed(AccountStage::Verify, None),
            audit: Some(("agent.host_user.helper_failed", "cause", json!("home"))),
        },
    ];
    for (reason, refusal) in [
        (Reason::NameRule, AccountRefusal::NameRule),
        (Reason::ReservedName, AccountRefusal::ReservedName),
        (Reason::GroupCollision, AccountRefusal::GroupCollision),
        (Reason::HomeExists, AccountRefusal::HomeExists),
        (Reason::MaxUsers, AccountRefusal::MaxUsers),
        (Reason::RateLimit, AccountRefusal::RateLimit),
        (Reason::UidRange, AccountRefusal::UidRange),
    ] {
        cases.push(Case {
            name: format!("refused {}", reason.as_str()),
            reply: Reply::Answer(Response::Refused { reason }),
            step: AccountStep::Refused,
            outcome: Box::new(move |reference| {
                Some(AccountEvent::Refused {
                    reference,
                    reason: refusal,
                })
            }),
            audit: Some(("agent.host_user.refused", "reason", json!(refusal.as_str()))),
        });
    }
    for (stage, expected) in [
        (FailedStage::Busy, AccountStage::Busy),
        (FailedStage::Request, AccountStage::Request),
        (FailedStage::State, AccountStage::State),
        (FailedStage::Lookup, AccountStage::Lookup),
        (FailedStage::Tool, AccountStage::Tool),
        (FailedStage::Useradd, AccountStage::Useradd),
        (FailedStage::Verify, AccountStage::Verify),
        (FailedStage::Partial, AccountStage::Partial),
    ] {
        cases.push(Case {
            name: format!("failed {}", stage.as_str()),
            reply: Reply::Answer(Response::Failed {
                stage,
                exit_code: Some(12),
            }),
            step: AccountStep::Failed,
            outcome: failed(expected, Some(12)),
            audit: Some((
                "agent.host_user.helper_failed",
                "stage",
                json!(expected.as_str()),
            )),
        });
    }
    cases
}

#[tokio::test]
async fn every_helper_answer_gives_its_step_its_reports_and_its_audit_line() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup::default()).await;
    for (index, case) in helper_cases().into_iter().enumerate() {
        let login = format!("u{index}");
        let session = format!("s-{index}");
        harness.helper.script([case.reply]);
        let step = harness.ensure(&login, &session).await;
        assert_eq!(step, case.step, "{}", case.name);
        let request = harness.helper.requests().pop().unwrap();
        assert_eq!(request.login, login, "{}", case.name);
        assert_eq!(request.session.as_str(), session, "{}", case.name);
        let expected = (case.outcome)(AccountReference::parse(request.reference.as_str()).unwrap());
        let wanted = 1 + usize::from(expected.is_some());
        eventually(&case.name, || harness.reports(&session).len() == wanted).await;
        let reports = harness.reports(&session);
        assert_eq!(
            reports[0].event,
            AccountEventKind::Creating,
            "{}",
            case.name
        );
        assert_eq!(
            reports[0].reference.as_ref().map(AccountReference::as_str),
            Some(request.reference.as_str()),
            "{}",
            case.name
        );
        assert!(reports.iter().all(|report| report.login == login));
        assert_eq!(
            reports.get(1).map(|report| report.event().unwrap()),
            expected,
            "{}",
            case.name
        );
        match case.audit {
            Some((event, key, value)) => {
                let lines = audits(&capture, event, &session);
                assert_eq!(lines.len(), 1, "{}: {lines:?}", case.name);
                assert_eq!(lines[0]["ref"], request.reference.as_str(), "{}", case.name);
                assert_eq!(lines[0][key], value, "{}", case.name);
            }
            None => assert_eq!(host_user_audits(&capture, &session), 0, "{}", case.name),
        }
    }
}

#[tokio::test]
async fn an_existing_account_or_a_failed_lookup_continues_without_the_helper() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup::default()).await;
    harness.lookup.set("alice", Some(Presence::Present));
    harness.lookup.set("bob", None);
    assert_eq!(harness.ensure("alice", "s-1").await, AccountStep::Continue);
    assert_eq!(harness.ensure("bob", "s-2").await, AccountStep::Continue);
    assert_eq!(harness.lookup.calls.load(Ordering::SeqCst), 2);
    assert_eq!(harness.helper.connections(), 0);
    assert_eq!(harness.all_reports(), 0);
    assert_eq!(host_user_audits(&capture, "s-1"), 0);
    assert_eq!(host_user_audits(&capture, "s-2"), 0);
}

#[tokio::test]
async fn without_creation_a_missing_account_is_reported_as_missing() {
    let invalid = HostUsersSection {
        uid_max: 70_000,
        ..enabled()
    };
    let cases = [
        (
            "disabled",
            HostUsersSection::default(),
            "passwd: files\n",
            true,
        ),
        ("invalid_config", invalid, "passwd: files\n", true),
        ("no_helper", enabled(), "passwd: files\n", false),
        ("directory", enabled(), "passwd: files ldap\n", true),
    ];
    for (cause, section, nsswitch, helper_socket) in cases {
        let capture = LogCapture::default();
        let _logs = capture.install();
        let harness = harness(Setup {
            section,
            nsswitch,
            helper_socket,
            ..Setup::default()
        })
        .await;
        assert_eq!(
            harness.ensure("alice", "s-1").await,
            AccountStep::NoAccount,
            "{cause}"
        );
        let reports = harness.reports("s-1");
        assert_eq!(kinds(&reports), [AccountEventKind::Missing], "{cause}");
        let lines = audits(&capture, "agent.host_user.missing", "s-1");
        assert_eq!(lines.len(), 1, "{cause}");
        assert_eq!(lines[0]["cause"], cause);
        assert_eq!(lines[0]["ref"], reference_of(&reports[0]).as_str());
        assert_eq!(harness.helper.connections(), 0, "{cause}");
    }
}

#[tokio::test]
async fn the_node_rules_of_the_agent_refuse_without_asking_the_helper() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup {
        section: HostUsersSection {
            names: NamesSection {
                deny: vec!["blocked".to_owned()],
                ..NamesSection::default()
            },
            ..enabled()
        },
        ..Setup::default()
    })
    .await;
    for (login, session, reason) in [
        ("blocked", "s-1", AccountRefusal::NameRule),
        ("postgres", "s-2", AccountRefusal::ReservedName),
        ("Upper", "s-3", AccountRefusal::NameRule),
    ] {
        assert_eq!(
            harness.ensure(login, session).await,
            AccountStep::Refused,
            "{login}"
        );
        let reports = harness.reports(session);
        assert_eq!(kinds(&reports), [AccountEventKind::Refused], "{login}");
        assert_eq!(reports[0].reason, Some(reason), "{login}");
        let lines = audits(&capture, "agent.host_user.refused", session);
        assert_eq!(lines[0]["reason"], reason.as_str(), "{login}");
        assert_eq!(lines[0]["ref"], reference_of(&reports[0]).as_str());
    }
    assert_eq!(harness.helper.connections(), 0);
}

#[tokio::test]
async fn eight_sessions_for_one_login_share_one_helper_request() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup::default()).await;
    let release = Arc::new(Notify::new());
    harness.helper.script([Reply::Held(
        Arc::clone(&release),
        Box::new(Reply::Answer(created(UID, "alice"))),
    )]);
    let sessions: Vec<String> = (0..8).map(|index| format!("s-{index}")).collect();
    let mut running = Vec::new();
    for session in &sessions {
        let service = Arc::clone(&harness.service);
        let session = session.clone();
        running.push(tokio::spawn(async move {
            service.ensure("alice", &session).await
        }));
    }
    eventually("every session to report creating", || {
        harness.all_reports() == sessions.len() && harness.helper.connections() == 1
    })
    .await;
    release.notify_one();
    for task in running {
        assert_eq!(
            soon("a session", task).await.unwrap(),
            AccountStep::Continue
        );
    }
    assert_eq!(harness.helper.connections(), 1);
    let reference = harness.helper.requests()[0].reference.as_str().to_owned();
    for session in &sessions {
        let reports = harness.reports(session);
        assert_eq!(
            kinds(&reports),
            [AccountEventKind::Creating, AccountEventKind::Created],
            "{session}"
        );
        assert!(
            reports
                .iter()
                .all(|report| reference_of(report).as_str() == reference)
        );
    }
    let created = every_audit(&capture, "agent.host_user.created");
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(created[0]["ref"], reference.as_str());
    assert_eq!(
        created[0]["session_id"],
        harness.helper.requests()[0].session.as_str()
    );
}

#[tokio::test]
async fn a_refusal_is_remembered_for_a_minute_with_its_reference() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup::default()).await;
    let refusal = Reply::Answer(Response::Refused {
        reason: Reason::MaxUsers,
    });
    harness.helper.script([refusal.clone(), refusal]);
    assert_eq!(harness.ensure("alice", "s-1").await, AccountStep::Refused);
    let first = reference_of(&harness.reports("s-1")[1]);
    harness.clock.advance(Duration::from_secs(59));
    assert_eq!(harness.ensure("alice", "s-2").await, AccountStep::Refused);
    let remembered = harness.reports("s-2");
    assert_eq!(kinds(&remembered), [AccountEventKind::Refused]);
    assert_eq!(reference_of(&remembered[0]), first);
    assert_eq!(remembered[0].reason, Some(AccountRefusal::MaxUsers));
    assert_eq!(harness.helper.connections(), 1);
    assert_eq!(audits(&capture, "agent.host_user.refused", "s-1").len(), 1);
    assert_eq!(host_user_audits(&capture, "s-2"), 0);
    assert_eq!(harness.ensure("bob", "s-3").await, AccountStep::Refused);
    assert_eq!(harness.helper.connections(), 2);
    harness.clock.advance(Duration::from_secs(1));
    harness
        .helper
        .script([Reply::Answer(created(UID, "alice"))]);
    assert_eq!(harness.ensure("alice", "s-4").await, AccountStep::Continue);
    assert_eq!(harness.helper.connections(), 3);
    assert_ne!(reference_of(&harness.reports("s-4")[0]), first);
}

#[tokio::test]
async fn requests_to_the_helper_are_serialized() {
    let harness = harness(Setup {
        timings: AccountTimings {
            helper: Duration::from_secs(10),
            ..FAST
        },
        ..Setup::default()
    })
    .await;
    let slow = Reply::Slow(
        Duration::from_millis(40),
        Box::new(Reply::Answer(Response::Exists)),
    );
    harness.helper.script(std::iter::repeat_n(slow, 4));
    let mut running = Vec::new();
    for index in 0..4 {
        let service = Arc::clone(&harness.service);
        running.push(tokio::spawn(async move {
            service
                .ensure(&format!("user{index}"), &format!("s-{index}"))
                .await
        }));
    }
    for task in running {
        assert_eq!(
            soon("a session", task).await.unwrap(),
            AccountStep::Continue
        );
    }
    assert_eq!(harness.helper.connections(), 4);
    assert_eq!(harness.helper.seen.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn control_refusals_and_timeouts_never_break_the_login_or_repeat_a_report() {
    let hold = Arc::new(Notify::new());
    let answers = [
        ("404", None),
        (
            "409",
            Some(ApiStep::Json(
                409,
                json!({"error": "account_report_refused"}),
            )),
        ),
        (
            "timeout",
            Some(ApiStep::Held(
                Arc::clone(&hold),
                Box::new(ApiStep::Json(204, Value::Null)),
            )),
        ),
        ("accepted", Some(ApiStep::Json(200, json!({})))),
    ];
    for (name, answer) in answers {
        let harness = harness(Setup {
            timings: AccountTimings {
                report: Duration::from_millis(200),
                ..FAST
            },
            ..Setup::default()
        })
        .await;
        if let Some(answer) = answer {
            harness
                .gate
                .set_standing(AGENT_SESSION_ACCOUNT_PATH, answer);
        }
        harness
            .helper
            .script([Reply::Answer(created(UID, "alice"))]);
        assert_eq!(
            harness.ensure("alice", "s-1").await,
            AccountStep::Continue,
            "{name}"
        );
        assert_eq!(
            harness.ensure("postgres", "s-2").await,
            AccountStep::Refused,
            "{name}"
        );
        assert_eq!(
            kinds(&harness.reports("s-1")),
            [AccountEventKind::Creating, AccountEventKind::Created],
            "{name}"
        );
        assert_eq!(
            kinds(&harness.reports("s-2")),
            [AccountEventKind::Refused],
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_cancelled_first_session_still_leaves_one_audit_line_for_its_attempt() {
    let capture = LogCapture::default();
    let _logs = capture.install();
    let harness = harness(Setup::default()).await;
    let release = Arc::new(Notify::new());
    harness.helper.script([Reply::Held(
        Arc::clone(&release),
        Box::new(Reply::Answer(created(UID, "alice"))),
    )]);
    let start = |session: &'static str| {
        let service = Arc::clone(&harness.service);
        tokio::spawn(async move { service.ensure("alice", session).await })
    };
    let first = start("s-1");
    eventually("the helper to hold the request", || {
        harness.helper.connections() == 1 && harness.reports("s-1").len() == 1
    })
    .await;
    first.abort();
    assert!(
        soon("the first session to stop", first)
            .await
            .unwrap_err()
            .is_cancelled()
    );
    let second = start("s-2");
    eventually("the second session to join", || {
        harness.reports("s-2").len() == 1
    })
    .await;
    release.notify_one();
    assert_eq!(
        soon("the second session", second).await.unwrap(),
        AccountStep::Continue
    );
    let reference = harness.helper.requests()[0].reference.as_str().to_owned();
    let created = every_audit(&capture, "agent.host_user.created");
    assert_eq!(created.len(), 1, "{created:?}");
    assert_eq!(created[0]["session_id"], "s-1");
    assert_eq!(created[0]["ref"], reference.as_str());
    assert_eq!(created[0]["uid"], json!(UID));
    let joined = harness.reports("s-2");
    assert_eq!(
        kinds(&joined),
        [AccountEventKind::Creating, AccountEventKind::Created]
    );
    assert!(
        joined
            .iter()
            .all(|report| reference_of(report).as_str() == reference)
    );
    assert_eq!(host_user_audits(&capture, "s-2"), 0);
    harness.helper.script([Reply::Answer(Response::Exists)]);
    assert_eq!(harness.ensure("alice", "s-3").await, AccountStep::Continue);
    assert_eq!(harness.helper.connections(), 2);
}

#[tokio::test]
async fn only_a_refusal_is_remembered_and_failures_ask_the_helper_again() {
    let harness = harness(Setup::default()).await;
    harness.helper.script([
        Reply::Answer(Response::Failed {
            stage: FailedStage::Useradd,
            exit_code: Some(1),
        }),
        Reply::Hang,
        Reply::Answer(Response::Exists),
    ]);
    assert_eq!(harness.ensure("alice", "s-1").await, AccountStep::Failed);
    assert_eq!(harness.ensure("alice", "s-2").await, AccountStep::Failed);
    assert_eq!(harness.ensure("alice", "s-3").await, AccountStep::Continue);
    assert_eq!(harness.helper.connections(), 3);
}

#[test]
fn the_account_timings_follow_the_design() {
    assert_eq!(ACCOUNT_TIMINGS.helper, Duration::from_secs(11));
    assert_eq!(ACCOUNT_TIMINGS.report, Duration::from_secs(2));
    assert_eq!(ACCOUNT_TIMINGS.lookup, Duration::from_secs(2));
    assert_eq!(ACCOUNT_TIMINGS.refusal_memory, Duration::from_secs(60));
    assert_eq!(ACCOUNT_TIMINGS.announce_every, Duration::from_secs(60));
}

struct Announced(mpsc::UnboundedSender<bool>);

impl CapabilitySink for Announced {
    fn announce(&self, capabilities: jaunt_proto::AgentCapabilities) -> BoxFuture<'_, ()> {
        self.0.send(capabilities.creates_accounts).unwrap();
        Box::pin(async {})
    }
}

fn availability_in(dir: &Path, section: &HostUsersSection, nsswitch: &str) -> Arc<Availability> {
    let paths = HostUsersPaths {
        socket: dir.join("h.sock"),
        nsswitch: dir.join("nsswitch.conf"),
        sssd_conf: dir.join("missing-sssd.conf"),
    };
    std::fs::write(&paths.nsswitch, nsswitch).unwrap();
    Arc::new(Availability::new(section, paths))
}

async fn first_announcement(availability: Arc<Availability>) -> bool {
    let (events, receiver) = broadcast::channel(4);
    let (sink, mut announced) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let task = tokio::spawn(announce_capabilities(
        availability,
        Arc::new(Announced(sink)),
        receiver,
        Duration::from_secs(3600),
        stop.clone(),
    ));
    events.send(ClientEvent::Connected).unwrap();
    let value = soon("the announcement", announced.recv()).await.unwrap();
    stop.cancel();
    soon("the announcer to stop", task).await.unwrap();
    value
}

#[tokio::test]
async fn the_announced_value_is_true_only_when_every_condition_holds() {
    let local = "passwd: files systemd\n";
    let cases = [
        ("ready", enabled(), local, true, true),
        ("disabled", HostUsersSection::default(), local, true, false),
        ("directory", enabled(), "passwd: files ldap\n", true, false),
        ("no socket", enabled(), local, false, false),
    ];
    for (name, section, nsswitch, listening, expected) in cases {
        let dir = tempfile::tempdir().unwrap();
        let availability = availability_in(dir.path(), &section, nsswitch);
        let _listener = listening.then(|| UnixListener::bind(dir.path().join("h.sock")).unwrap());
        assert_eq!(first_announcement(availability).await, expected, "{name}");
    }
}

async fn announcement(announced: &mut mpsc::UnboundedReceiver<bool>) -> Option<bool> {
    tokio::time::timeout(Duration::from_secs(3600), announced.recv())
        .await
        .expect("an announcement")
}

fn probes(listener: &std::os::unix::net::UnixListener) -> usize {
    let mut count = 0;
    loop {
        match listener.accept() {
            Ok(_) => count += 1,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return count,
            Err(error) => panic!("accepting a probe failed: {error}"),
        }
    }
}

#[tokio::test(start_paused = true)]
async fn announcements_repeat_while_connected_and_probe_the_helper_once_per_connection() {
    let dir = tempfile::tempdir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(dir.path().join("h.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let (events, receiver) = broadcast::channel(16);
    let (sink, mut announced) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let every = Duration::from_secs(60);
    let task = tokio::spawn(announce_capabilities(
        availability_in(dir.path(), &enabled(), "passwd: files\n"),
        Arc::new(Announced(sink)),
        receiver,
        every,
        stop.clone(),
    ));
    let quiet = Duration::from_secs(3600);
    events
        .send(ClientEvent::ConnectFailed(ConnectFailure::Timeout))
        .unwrap();
    events
        .send(ClientEvent::Disconnected {
            lasted: Duration::ZERO,
        })
        .unwrap();
    assert!(tokio::time::timeout(quiet, announced.recv()).await.is_err());
    assert_eq!(probes(&listener), 0);

    events.send(ClientEvent::Connected).unwrap();
    assert_eq!(announcement(&mut announced).await, Some(true));
    assert_eq!(probes(&listener), 1);
    let first = tokio::time::Instant::now();
    for _ in 0..3 {
        assert_eq!(announcement(&mut announced).await, Some(true));
    }
    assert_eq!(first.elapsed(), every * 3);
    assert_eq!(probes(&listener), 0);

    events
        .send(ClientEvent::Disconnected {
            lasted: Duration::ZERO,
        })
        .unwrap();
    assert!(tokio::time::timeout(quiet, announced.recv()).await.is_err());
    assert_eq!(probes(&listener), 0);

    events.send(ClientEvent::Connected).unwrap();
    assert_eq!(announcement(&mut announced).await, Some(true));
    assert_eq!(probes(&listener), 1);
    stop.cancel();
    task.await.unwrap();
}
