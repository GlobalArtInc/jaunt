use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use jaunt_audit::new_denial_reference;
use jaunt_ca::ssh_key::PublicKey;
use jaunt_proto::{AccountEvent, AccountReference, AccountRefusal};
use jaunt_ssh::{
    ForwardRefusal, HostAuthorities, JumpError, JumpRequest, TerminalDimensions, TerminalEvent,
    TerminalExit, TerminalInput, TerminalOutput, WindowGrant, open_terminal,
};
use jaunt_store::{Node, Subjects, User};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::authorize::DEFAULT_MAX_SESSION_SECS;
use crate::control::Control;
use crate::host_accounts::AccountNotice;
use crate::principal::{self, Channel, Refusal};
use crate::revocation::revoked;
use crate::serve::SocketWrites;
use crate::user_cert::{self, CertOrigin};

use super::audit::{self, Denial};
use super::live::{Admission, End, Refused, Stop};
use super::protocol::{self, Command, Recording, Stage};
use super::{
    GateEvent, GateEvents, GateRequest, Installed, TERMINAL_DEAD_PEER_TIMEOUT,
    TERMINAL_MAX_FRAME_BYTES, TERMINAL_PING_INTERVAL, TERMINAL_WEDGE_TIMEOUT,
    WEB_CERTIFICATE_VALIDITY,
};

const SETUP_TIMEOUT: Duration = Duration::from_secs(50);
const WATCH_INTERVAL: Duration = Duration::from_secs(1);
const CLOSE_GRACE: Duration = Duration::from_secs(5);
const GATE_GRACE: Duration = Duration::from_secs(3);
const PUMP_GRACE: Duration = Duration::from_secs(2);
const SESSION_RECHECK: Duration = Duration::from_secs(60);
const OUTGOING_QUEUE: usize = 4;
const STORE_DEADLINE: Duration = Duration::from_secs(2);
const IDLE_WARNING: Duration = Duration::from_secs(120);
const MIN_WARNED_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const ACTIVE_INTERVAL: Duration = Duration::from_secs(10);
const NODE_PROBE_INTERVAL: Duration = Duration::from_secs(20);
const NODE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const NODE_LATENCY_STALE: Duration = Duration::from_secs(60);

pub(crate) struct Plan {
    pub(crate) user: User,
    pub(crate) web_session: String,
    pub(crate) web_expires_at: i64,
    pub(crate) node: Node,
    pub(crate) login: String,
    pub(crate) size: TerminalDimensions,
    pub(crate) client_addr: SocketAddr,
    pub(crate) socket_writes: Option<SocketWrites>,
    pub(crate) installed: Arc<Installed>,
}

enum Out {
    Output { data: Bytes, window: WindowGrant },
    Text(String),
    Close(Option<CloseFrame>),
}

const NOT_PINGED: u64 = u64::MAX;
const NOT_WRITING: u64 = u64::MAX;
const NOT_WARNED: u64 = u64::MAX;
const NEVER_ACTIVE: u64 = u64::MAX;

struct Flow {
    pending_output: AtomicU64,
    pending_input: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    delivered: AtomicU64,
    activity_ms: AtomicU64,
    heard_ms: AtomicU64,
    unanswered_ms: AtomicU64,
    writing_ms: AtomicU64,
    socket_written: AtomicU64,
    socket_ms: AtomicU64,
    reading_blocked: AtomicBool,
    ping_due: AtomicBool,
    ping_wanted: Notify,
    warned_ms: AtomicU64,
    active_ms: AtomicU64,
    probe_wanted: Notify,
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

impl Flow {
    fn starting(now: Duration) -> Flow {
        let flow = Flow {
            pending_output: AtomicU64::new(0),
            pending_input: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            activity_ms: AtomicU64::new(0),
            heard_ms: AtomicU64::new(0),
            unanswered_ms: AtomicU64::new(NOT_PINGED),
            writing_ms: AtomicU64::new(NOT_WRITING),
            socket_written: AtomicU64::new(0),
            socket_ms: AtomicU64::new(millis(now)),
            reading_blocked: AtomicBool::new(false),
            ping_due: AtomicBool::new(false),
            ping_wanted: Notify::new(),
            warned_ms: AtomicU64::new(NOT_WARNED),
            active_ms: AtomicU64::new(NEVER_ACTIVE),
            probe_wanted: Notify::new(),
        };
        flow.touch(now);
        flow.heard(now);
        flow
    }

    fn touch(&self, now: Duration) {
        self.activity_ms.store(millis(now), Ordering::Relaxed);
    }

    fn heard(&self, now: Duration) {
        self.heard_ms.store(millis(now), Ordering::Relaxed);
        self.unanswered_ms.store(NOT_PINGED, Ordering::Relaxed);
    }

    fn pinged(&self, now: Duration) {
        self.unanswered_ms.fetch_min(millis(now), Ordering::Relaxed);
    }

    fn ask_for_ping(&self) {
        self.ping_due.store(true, Ordering::Relaxed);
        self.ping_wanted.notify_one();
    }

    fn unanswered_for(&self, now: Duration) -> Duration {
        match self.unanswered_ms.load(Ordering::Relaxed) {
            NOT_PINGED => Duration::ZERO,
            since => Duration::from_millis(millis(now).saturating_sub(since)),
        }
    }

    fn writing(&self, now: Duration) {
        self.writing_ms.store(millis(now), Ordering::Relaxed);
    }

    fn wrote(&self) {
        self.writing_ms.store(NOT_WRITING, Ordering::Relaxed);
    }

    fn socket_wrote(&self, total: u64, now: Duration) -> bool {
        if self.socket_written.swap(total, Ordering::Relaxed) == total {
            return false;
        }
        self.socket_ms.store(millis(now), Ordering::Relaxed);
        true
    }

    fn since_socket_or(&self, mark: u64, now: Duration) -> Duration {
        let latest = mark.max(self.socket_ms.load(Ordering::Relaxed));
        Duration::from_millis(millis(now).saturating_sub(latest))
    }

    fn stuck_writing_for(&self, now: Duration) -> Duration {
        match self.writing_ms.load(Ordering::Relaxed) {
            NOT_WRITING => Duration::ZERO,
            since => self.since_socket_or(since, now),
        }
    }

    fn output_stalled_for(&self, now: Duration) -> Duration {
        if self.pending_output.load(Ordering::Relaxed) == 0 {
            return Duration::ZERO;
        }
        self.since_socket_or(self.activity_ms.load(Ordering::Relaxed), now)
    }

    fn input_stalled_for(&self, now: Duration) -> Duration {
        if self.pending_input.load(Ordering::Relaxed) == 0 {
            return Duration::ZERO;
        }
        self.idle_for(now)
    }

    fn idle_for(&self, now: Duration) -> Duration {
        Duration::from_millis(millis(now).saturating_sub(self.activity_ms.load(Ordering::Relaxed)))
    }

    fn silent_for(&self, now: Duration) -> Duration {
        Duration::from_millis(millis(now).saturating_sub(self.heard_ms.load(Ordering::Relaxed)))
    }

    fn idle_warning(&self, now: Duration, idle_timeout: Duration) -> Option<IdleWarning> {
        if idle_timeout < MIN_WARNED_IDLE_TIMEOUT {
            return None;
        }
        let mark = self.activity_ms.load(Ordering::Relaxed);
        let idle = Duration::from_millis(millis(now).saturating_sub(mark));
        if idle < idle_timeout.saturating_sub(IDLE_WARNING)
            || idle >= idle_timeout
            || self.warned_ms.load(Ordering::Relaxed) == mark
        {
            return None;
        }
        let left = millis(idle_timeout.saturating_sub(idle));
        Some(IdleWarning {
            seconds_left: left.div_ceil(1000),
            mark,
        })
    }

    fn warned(&self, warning: &IdleWarning) {
        self.warned_ms.store(warning.mark, Ordering::Relaxed);
    }

    fn active(&self, now: Duration) -> bool {
        let last = self.active_ms.load(Ordering::Relaxed);
        if last != NEVER_ACTIVE
            && Duration::from_millis(millis(now).saturating_sub(last)) < ACTIVE_INTERVAL
        {
            return false;
        }
        self.active_ms.store(millis(now), Ordering::Relaxed);
        self.touch(now);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cadence {
    every: Duration,
    last: Duration,
}

impl Cadence {
    fn starting(every: Duration, now: Duration) -> Cadence {
        Cadence { every, last: now }
    }

    fn due(&mut self, now: Duration) -> bool {
        if now.saturating_sub(self.last) < self.every {
            return false;
        }
        self.last = now;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IdleWarning {
    seconds_left: u64,
    mark: u64,
}

#[derive(Default)]
struct NodeLatency {
    last: Mutex<Option<(u64, u64)>>,
}

impl NodeLatency {
    fn record(&self, round_trip: Duration, now: Duration) {
        let measured = millis(round_trip).min(millis(NODE_PROBE_TIMEOUT));
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Some((measured, millis(now)));
    }

    fn current(&self, now: Duration) -> Option<u64> {
        let (measured, at) = (*self.last.lock().unwrap_or_else(PoisonError::into_inner))?;
        (millis(now).saturating_sub(at) <= millis(NODE_LATENCY_STALE)).then_some(measured)
    }
}

const NO_STAGE: u8 = 0;

const fn stage_rank(stage: Stage) -> u8 {
    match stage {
        Stage::Node => 1,
        Stage::Account => 2,
        Stage::Shell => 3,
    }
}

#[derive(Default)]
struct Steps {
    reached: AtomicU8,
    changed: Notify,
}

impl Steps {
    fn reach(&self, stage: Stage) {
        self.reached.fetch_max(stage_rank(stage), Ordering::Relaxed);
        self.changed.notify_one();
    }

    fn reached(&self) -> Option<Stage> {
        match self.reached.load(Ordering::Relaxed) {
            NO_STAGE => None,
            1 => Some(Stage::Node),
            2 => Some(Stage::Account),
            _ => Some(Stage::Shell),
        }
    }
}

fn due_stages(sent: Option<Stage>, reached: Option<Stage>, creating: bool) -> Vec<Stage> {
    let reached = reached.map_or(NO_STAGE, stage_rank);
    let sent = sent.map_or(NO_STAGE, stage_rank);
    [
        (Stage::Node, reached >= stage_rank(Stage::Node) || creating),
        (Stage::Account, creating),
        (Stage::Shell, reached >= stage_rank(Stage::Shell)),
    ]
    .into_iter()
    .filter(|(stage, due)| *due && stage_rank(*stage) > sent)
    .map(|(stage, _)| stage)
    .collect()
}

fn recording_mode(recordings_on: bool, record_input: Option<bool>) -> Recording {
    match (recordings_on, record_input) {
        (false, _) => Recording::Off,
        (true, Some(false)) => Recording::Output,
        (true, Some(true) | None) => Recording::Full,
    }
}

struct Writer {
    tx: mpsc::Sender<Out>,
    task: JoinHandle<()>,
}

impl Writer {
    fn spawn(mut sink: SplitSink<WebSocket, Message>, control: Control, flow: Arc<Flow>) -> Writer {
        let (tx, mut rx) = mpsc::channel::<Out>(OUTGOING_QUEUE);
        let task = tokio::spawn(async move {
            loop {
                let out = tokio::select! {
                    biased;
                    () = flow.ping_wanted.notified() => None,
                    out = rx.recv() => match out {
                        Some(out) => Some(out),
                        None => break,
                    },
                };
                if flow.ping_due.swap(false, Ordering::Relaxed) {
                    flow.writing(control.tick());
                    if sink.send(Message::Ping(Bytes::new())).await.is_err() {
                        break;
                    }
                    flow.wrote();
                    flow.pinged(control.tick());
                    control.web.terminals.counters.pinged();
                }
                let Some(out) = out else {
                    continue;
                };
                let (message, delivered, last) = match out {
                    Out::Output { data, window } => {
                        let length = data.len();
                        (Message::Binary(data), Some((window, length)), false)
                    }
                    Out::Text(text) => (Message::Text(text.into()), None, false),
                    Out::Close(frame) => (Message::Close(frame), None, true),
                };
                flow.writing(control.tick());
                if sink.send(message).await.is_err() {
                    break;
                }
                flow.wrote();
                if let Some((window, length)) = delivered {
                    let written = u64::try_from(length).unwrap_or(u64::MAX);
                    flow.delivered.fetch_add(written, Ordering::Relaxed);
                    flow.pending_output.fetch_sub(written, Ordering::Relaxed);
                    window.consumed(length);
                    flow.touch(control.tick());
                }
                if last {
                    break;
                }
            }
        });
        Writer { tx, task }
    }

    async fn finish(self, end: End, exit: Option<&TerminalExit>, reference: Option<&str>) {
        let closing = protocol::closing(end);
        let Some(code) = closing.code else {
            self.task.abort();
            return;
        };
        let Writer { tx, mut task } = self;
        let mut messages = Vec::new();
        if end == End::Exited {
            messages.push(Out::Text(protocol::exit(exit)));
        }
        if let Some(error) = closing.error {
            messages.push(Out::Text(protocol::error(error, reference)));
        }
        messages.push(Out::Close(Some(CloseFrame {
            code,
            reason: closing.reason.into(),
        })));
        let delivered = tokio::time::timeout(CLOSE_GRACE, async {
            for message in messages {
                if tx.send(message).await.is_err() {
                    break;
                }
            }
            drop(tx);
            (&mut task).await
        })
        .await;
        if delivered.is_err() {
            task.abort();
            tracing::debug!(target: "jaunt::web", "a web terminal could not deliver its close in time");
        }
    }
}

struct GateGuard {
    task: Option<JoinHandle<()>>,
    token: CancellationToken,
}

impl GateGuard {
    async fn finish(mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        if tokio::time::timeout(GATE_GRACE, &mut task).await.is_ok() {
            return;
        }
        self.token.cancel();
        if tokio::time::timeout(GATE_GRACE, &mut task).await.is_err() {
            tracing::warn!(target: "jaunt::web", "the gate side of a web terminal did not end in time");
            task.abort();
        }
    }
}

impl Drop for GateGuard {
    fn drop(&mut self) {
        self.token.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct Opened {
    input: Arc<TerminalInput>,
    output: TerminalOutput,
    session_id: String,
    deadline: i64,
    recording: Recording,
}

struct Attempt {
    serial: Option<u64>,
    gate: Option<GateGuard>,
    detail: Option<&'static str>,
}

#[derive(Default)]
struct AccountWatch {
    receiver: OnceLock<watch::Receiver<AccountNotice>>,
    subscribed: Notify,
}

impl AccountWatch {
    fn subscribe(&self, control: &Control, session_id: &str) {
        if self.receiver.get().is_some() {
            return;
        }
        let receiver = control
            .host_accounts
            .notices
            .subscribe(session_id, control.tick());
        if self.receiver.set(receiver).is_ok() {
            self.subscribed.notify_one();
        }
    }

    fn latest(&self) -> AccountNotice {
        self.receiver
            .get()
            .map(|receiver| receiver.borrow().clone())
            .unwrap_or_default()
    }
}

async fn account_changed(watching: &mut Option<watch::Receiver<AccountNotice>>) {
    if let Some(receiver) = watching
        && receiver.changed().await.is_ok()
    {
        return;
    }
    std::future::pending().await
}

fn account_end(end: End, notice: &AccountNotice) -> (End, Option<&AccountReference>) {
    if !matches!(end, End::Denied | End::Unavailable) {
        return (end, None);
    }
    match &notice.outcome {
        Some(
            AccountEvent::Refused {
                reference,
                reason: AccountRefusal::RateLimit,
            }
            | AccountEvent::Failed { reference, .. },
        ) => (End::AccountFailed, Some(reference)),
        Some(AccountEvent::Refused { reference, .. }) => (End::AccountRefused, Some(reference)),
        Some(AccountEvent::Missing { reference }) => (End::NoAccount, Some(reference)),
        Some(AccountEvent::Creating { .. } | AccountEvent::Created { .. }) | None => (end, None),
    }
}

fn created_home(notice: &AccountNotice) -> Option<&str> {
    match &notice.outcome {
        Some(AccountEvent::Created { home, .. }) => Some(home.as_str()),
        _ => None,
    }
}

fn denial_end(error: &JumpError, refused: Option<ForwardRefusal>) -> End {
    match error {
        JumpError::ForwardRefused => match refused {
            Some(ForwardRefusal::Unavailable) => End::Unavailable,
            Some(ForwardRefusal::Limit) => End::Limit,
            Some(ForwardRefusal::Denied | ForwardRefusal::BadTarget) | None => End::Denied,
        },
        JumpError::NodeRefused | JumpError::TerminalRefused => End::Denied,
        _ => End::Unavailable,
    }
}

fn setup_reason(end: End) -> &'static str {
    protocol::closing(end).audit
}

async fn issue_certificate(
    control: &Control,
    plan: &Plan,
    stop: &Stop,
) -> Result<(jaunt_ssh::EphemeralKey, String, HostAuthorities, u64), End> {
    match principal::refuse_revoked(control, &plan.user.id, None, Channel::Certificate).await {
        Ok(()) => {}
        Err(Refusal::Revoked) => return Err(End::Revoked),
        Err(Refusal::Unavailable) => return Err(End::Unavailable),
    }
    let key = control.web.terminals.new_key().map_err(|err| {
        tracing::error!(target: "jaunt::web", error = %err, "a terminal key could not be made");
        End::Unavailable
    })?;
    let subject = key
        .public_openssh()
        .map_err(|err| err.to_string())
        .and_then(|text| PublicKey::from_openssh(&text).map_err(|err| err.to_string()))
        .map_err(|err| {
            tracing::error!(target: "jaunt::web", error = %err, "a terminal public key could not be read back");
            End::Unavailable
        })?;
    let now = control.now().ok_or(End::Unavailable)?;
    let signed = user_cert::issue(
        control,
        &plan.user,
        subject,
        WEB_CERTIFICATE_VALIDITY,
        CertOrigin::Web,
        now,
    )
    .await
    .map_err(|_| End::Unavailable)?;
    control.web.terminals.note_issued(&signed.line);
    let serial = u64::try_from(signed.serial).map_err(|_| End::Unavailable)?;
    stop.certificate_issued(serial);
    let authorities = HostAuthorities::from_openssh_lines(&signed.host_ca_keys).map_err(|err| {
        tracing::error!(target: "jaunt::web", error = %err, "the host authorities cannot verify a node");
        End::Unavailable
    })?;
    Ok((key, signed.line, authorities, serial))
}

async fn setup(
    control: &Control,
    plan: &Plan,
    stop: &Arc<Stop>,
    watches: (&Arc<AccountWatch>, &Arc<Steps>),
    attempt: &mut Attempt,
) -> Result<Opened, End> {
    let (account, steps) = watches;
    let (key, certificate, authorities, serial) = issue_certificate(control, plan, stop).await?;
    attempt.serial = Some(serial);
    let refused: Arc<OnceLock<ForwardRefusal>> = Arc::default();
    let events: GateEvents = {
        let stop = Arc::clone(stop);
        let refused = Arc::clone(&refused);
        let account = Arc::clone(account);
        let control = control.clone();
        Arc::new(move |event| match event {
            GateEvent::Routed { session_id } => {
                stop.routed(&session_id);
                account.subscribe(&control, &session_id);
            }
            GateEvent::Refused(refusal) => {
                refused.get_or_init(|| refusal);
            }
        })
    };
    let token = stop.token().child_token();
    steps.reach(Stage::Node);
    let link = plan
        .installed
        .gate
        .connect(GateRequest {
            client_addr: plan.client_addr,
            shutdown: token.clone(),
            events,
        })
        .map_err(|_| End::Limit)?;
    attempt.gate = Some(GateGuard {
        task: Some(tokio::spawn(link.serve)),
        token,
    });
    let node_host = format!("{}.{}", plan.node.name, control.ssh_suffix.as_str());
    let gate_host = plan.installed.gate.host_name();
    let now_unix = control
        .now()
        .and_then(|now| u64::try_from(now.secs).ok())
        .ok_or(End::Unavailable)?;
    let logged_in = {
        let steps = Arc::clone(steps);
        move || steps.reach(Stage::Shell)
    };
    let opened = open_terminal(
        link.stream,
        key,
        JumpRequest {
            gate_host: &gate_host,
            node_host: &node_host,
            login: &plan.login,
            certificate: &certificate,
            authorities: &authorities,
            size: plan.size,
            now_unix,
            logged_in: &logged_in,
        },
    )
    .await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(error) => {
            attempt.detail = Some(error.reason());
            unreachable_node(&plan.node.name, &error);
            return Err(denial_end(&error, refused.get().copied()));
        }
    };
    let session_id = stop.session_id().ok_or(End::Unavailable)?.to_owned();
    let (deadline, record_input) = session_terms(control, &session_id).await;
    let (input, output) = opened.split();
    Ok(Opened {
        input: Arc::new(input),
        output,
        session_id,
        deadline,
        recording: recording_mode(control.recordings.is_some(), record_input),
    })
}

async fn session_terms(control: &Control, session_id: &str) -> (i64, Option<bool>) {
    let now = control.now().map_or(0, |now| now.secs);
    let default = i64::try_from(DEFAULT_MAX_SESSION_SECS).unwrap_or(i64::MAX);
    match control.store.sessions().get(session_id).await {
        Ok(Some(session)) => (
            session
                .authorized_at
                .unwrap_or(now)
                .saturating_add(session.max_duration_secs.unwrap_or(default)),
            session.record_input,
        ),
        Ok(None) => (now.saturating_add(default), None),
        Err(err) => {
            tracing::warn!(target: "jaunt::web", error = %err, "loading a terminal session failed");
            (now.saturating_add(default), None)
        }
    }
}

fn read_end(error: &axum::Error) -> End {
    let inner = std::error::Error::source(error)
        .and_then(|source| source.downcast_ref::<tungstenite::Error>());
    match inner {
        Some(tungstenite::Error::Capacity(_)) => End::TooBig,
        Some(tungstenite::Error::Protocol(_) | tungstenite::Error::Utf8(_)) => End::Malformed,
        _ => End::ClientClosed,
    }
}

struct Waiting<'a> {
    stop: &'a Arc<Stop>,
    tx: &'a mpsc::Sender<Out>,
    account: &'a Arc<AccountWatch>,
    steps: &'a Arc<Steps>,
}

async fn send_stages(waiting: &Waiting<'_>, sent: &mut Option<Stage>) {
    let creating = waiting.account.latest().creating.is_some();
    for stage in due_stages(*sent, waiting.steps.reached(), creating) {
        *sent = Some(stage);
        send_or_stop(
            waiting.tx,
            waiting.stop,
            Out::Text(protocol::progress(stage)),
        )
        .await;
    }
}

async fn wait_for_setup(
    control: &Control,
    plan: &Plan,
    waiting: &Waiting<'_>,
    stream: &mut SplitStream<WebSocket>,
    early: &mut Vec<Message>,
    attempt: &mut Attempt,
) -> Result<Opened, End> {
    let started = bounded_setup(setup(
        control,
        plan,
        waiting.stop,
        (waiting.account, waiting.steps),
        attempt,
    ));
    await_setup(started, waiting, stream, early).await
}

async fn bounded_setup<T, F>(setup: F) -> Result<T, End>
where
    F: std::future::Future<Output = Result<T, End>>,
{
    tokio::time::timeout(SETUP_TIMEOUT, setup)
        .await
        .unwrap_or(Err(End::Unavailable))
}

async fn await_setup<T, F, S>(
    started: F,
    waiting: &Waiting<'_>,
    stream: &mut S,
    early: &mut Vec<Message>,
) -> Result<T, End>
where
    F: std::future::Future<Output = Result<T, End>>,
    S: futures_util::Stream<Item = Result<Message, axum::Error>> + Unpin,
{
    let stop = waiting.stop;
    let mut early_bytes = 0_usize;
    let mut watching = None;
    let mut sent = None;
    tokio::pin!(started);
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => return Err(stop.end().unwrap_or(End::Unavailable)),
            done = &mut started => {
                if done.is_ok() {
                    send_stages(waiting, &mut sent).await;
                }
                return done;
            }
            () = waiting.account.subscribed.notified(), if watching.is_none() => {
                watching = waiting.account.receiver.get().cloned();
            }
            () = account_changed(&mut watching) => {}
            () = waiting.steps.changed.notified() => {}
            message = stream.next() => match message {
                None | Some(Ok(Message::Close(_))) => return Err(End::ClientClosed),
                Some(Err(error)) => return Err(read_end(&error)),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(message)) => {
                    early_bytes = early_bytes.saturating_add(message_len(&message));
                    if early_bytes > TERMINAL_MAX_FRAME_BYTES {
                        return Err(End::Malformed);
                    }
                    early.push(message);
                }
            },
        }
        send_stages(waiting, &mut sent).await;
    }
}

fn message_len(message: &Message) -> usize {
    match message {
        Message::Text(text) => text.len(),
        Message::Binary(data) | Message::Ping(data) | Message::Pong(data) => data.len(),
        Message::Close(_) => 0,
    }
}

fn unreachable_node(node: &str, error: &JumpError) {
    match error {
        JumpError::GateHostKey | JumpError::NodeHostKey | JumpError::NodeViolation => {
            tracing::info!(
                target: "jaunt::web",
                reason = error.reason(),
                node,
                "a web terminal could not reach the node"
            );
        }
        _ => {
            tracing::debug!(target: "jaunt::web", reason = error.reason(), node, "a web terminal did not start");
        }
    }
}

async fn abrupt_cause<F, E>(revocation: F) -> End
where
    F: std::future::Future<Output = Result<bool, E>>,
{
    match tokio::time::timeout(STORE_DEADLINE, revocation).await {
        Ok(Ok(true)) => End::Revoked,
        Ok(Ok(false) | Err(_)) => End::Unavailable,
        Err(_) => {
            tracing::warn!(target: "jaunt::web", "the revocation lookup for an ended terminal timed out");
            End::Unavailable
        }
    }
}

async fn abrupt_end(control: &Control, stop: &Stop) -> End {
    let serial = stop.serial().and_then(|serial| i64::try_from(serial).ok());
    abrupt_cause(revoked(
        control,
        Subjects {
            user_id: &stop.user_id,
            serial,
            node_id: Some(stop.node_id()),
        },
    ))
    .await
}

fn output_end(exit: Option<&TerminalExit>, violated: bool) -> Option<End> {
    match (exit, violated) {
        (_, true) => Some(End::NodeViolation),
        (Some(_), false) => Some(End::Exited),
        (None, false) => None,
    }
}

async fn send_or_stop(tx: &mpsc::Sender<Out>, stop: &Stop, out: Out) -> bool {
    tokio::select! {
        biased;
        () = stop.cancelled() => false,
        sent = tx.send(out) => {
            if sent.is_err() {
                stop.stop(End::ClientClosed);
            }
            sent.is_ok()
        }
    }
}

struct Pump {
    control: Control,
    stop: Arc<Stop>,
    flow: Arc<Flow>,
    latency: Arc<NodeLatency>,
    tx: mpsc::Sender<Out>,
}

impl Pump {
    async fn output(self, mut output: TerminalOutput) -> Option<TerminalExit> {
        let window = output.window();
        let mut exit = None;
        loop {
            let event = tokio::select! {
                biased;
                () = self.stop.cancelled() => return exit,
                event = output.next() => event,
            };
            match event {
                Some(TerminalEvent::Output(data)) => {
                    let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    let pending = self
                        .flow
                        .pending_output
                        .fetch_add(length, Ordering::Relaxed)
                        .saturating_add(length);
                    self.control.web.terminals.counters.pending_output(pending);
                    self.flow.bytes_out.fetch_add(length, Ordering::Relaxed);
                    self.flow.touch(self.control.tick());
                    let out = Out::Output {
                        data,
                        window: window.clone(),
                    };
                    if !send_or_stop(&self.tx, &self.stop, out).await {
                        return exit;
                    }
                }
                Some(TerminalEvent::Exit(outcome)) => exit = Some(outcome),
                None => {
                    let violated = output.violated();
                    if violated {
                        tracing::info!(
                            target: "jaunt::web",
                            reason = "node_violation",
                            node_id = self.stop.node_id(),
                            "a web terminal was cut off from a node that broke the ssh flow control"
                        );
                    }
                    let end = match output_end(exit.as_ref(), violated) {
                        Some(end) => end,
                        None => abrupt_end(&self.control, &self.stop).await,
                    };
                    self.stop.stop(end);
                    return exit;
                }
            }
        }
    }

    async fn input(
        self,
        mut stream: SplitStream<WebSocket>,
        early: Vec<Message>,
        input: Arc<TerminalInput>,
    ) {
        for message in early {
            if !self.handle(message, &input).await {
                return;
            }
        }
        loop {
            let message = tokio::select! {
                biased;
                () = self.stop.cancelled() => return,
                message = stream.next() => message,
            };
            let message = match message {
                None => {
                    self.stop.stop(End::ClientClosed);
                    return;
                }
                Some(Err(error)) => {
                    self.stop.stop(read_end(&error));
                    return;
                }
                Some(Ok(message)) => message,
            };
            if !self.handle(message, &input).await {
                return;
            }
        }
    }

    async fn handle(&self, message: Message, input: &TerminalInput) -> bool {
        self.flow.heard(self.control.tick());
        match message {
            Message::Binary(data) => {
                let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                let pending = self
                    .flow
                    .pending_input
                    .fetch_add(length, Ordering::Relaxed)
                    .saturating_add(length);
                self.control.web.terminals.counters.pending_input(pending);
                self.flow.touch(self.control.tick());
                self.flow.reading_blocked.store(true, Ordering::Relaxed);
                let sent = tokio::select! {
                    biased;
                    () = self.stop.cancelled() => return false,
                    sent = input.send(data) => sent,
                };
                self.flow.reading_blocked.store(false, Ordering::Relaxed);
                self.flow.heard(self.control.tick());
                self.flow.touch(self.control.tick());
                self.flow.pending_input.fetch_sub(length, Ordering::Relaxed);
                if sent.is_err() {
                    return false;
                }
                self.flow.bytes_in.fetch_add(length, Ordering::Relaxed);
                true
            }
            Message::Text(text) => match protocol::parse_text(text.as_str()) {
                Ok(Command::Resize(size)) => {
                    let resized = tokio::select! {
                        biased;
                        () = self.stop.cancelled() => return false,
                        resized = input.resize(size) => resized,
                    };
                    if resized.is_err() {
                        return false;
                    }
                    true
                }
                Ok(Command::Ping) => {
                    let node_ms = self.latency.current(self.control.tick());
                    send_or_stop(&self.tx, &self.stop, Out::Text(protocol::pong(node_ms))).await
                }
                Ok(Command::Active) => {
                    self.flow.active(self.control.tick());
                    true
                }
                Err(_) => {
                    self.stop.stop(End::Malformed);
                    false
                }
            },
            Message::Ping(_) | Message::Pong(_) => true,
            Message::Close(_) => {
                self.stop.stop(End::ClientClosed);
                false
            }
        }
    }
}

async fn recheck_cause<S, E, R>(session: S, revocation: R) -> Option<End>
where
    S: std::future::Future<Output = Result<bool, E>>,
    E: std::fmt::Display,
    R: std::future::Future<Output = Result<(), Refusal>>,
{
    match tokio::time::timeout(STORE_DEADLINE, session).await {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return Some(End::WebSessionEnded),
        Ok(Err(err)) => {
            tracing::warn!(target: "jaunt::web", error = %err, "checking the web session of a terminal failed");
            return None;
        }
        Err(_) => {
            tracing::warn!(target: "jaunt::web", "checking the web session of a terminal timed out");
            return None;
        }
    }
    match tokio::time::timeout(STORE_DEADLINE, revocation).await {
        Ok(Err(Refusal::Revoked)) => Some(End::Revoked),
        Ok(Ok(()) | Err(Refusal::Unavailable)) => None,
        Err(_) => {
            tracing::warn!(target: "jaunt::web", "checking the revocations of a terminal user timed out");
            None
        }
    }
}

async fn recheck(control: &Control, plan: &Plan) -> Option<End> {
    let now = control.now()?;
    let sessions = control.store.web_sessions();
    recheck_cause(
        async {
            sessions
                .find_valid(&plan.web_session, now.secs)
                .await
                .map(|found| found.is_some())
        },
        principal::refuse_revoked(control, &plan.user.id, None, Channel::WebSession),
    )
    .await
}

fn verdict(flow: &Flow, tick: Duration, idle_timeout: Duration) -> Option<End> {
    if flow.idle_for(tick) >= idle_timeout {
        return Some(End::IdleTimeout);
    }
    if flow.stuck_writing_for(tick) >= TERMINAL_WEDGE_TIMEOUT
        || flow.output_stalled_for(tick) >= TERMINAL_WEDGE_TIMEOUT
        || flow.input_stalled_for(tick) >= TERMINAL_WEDGE_TIMEOUT
    {
        return Some(End::Wedged);
    }
    if !flow.reading_blocked.load(Ordering::Relaxed)
        && flow.unanswered_for(tick) >= TERMINAL_PING_INTERVAL
        && flow.silent_for(tick) >= TERMINAL_DEAD_PEER_TIMEOUT
    {
        return Some(End::DeadPeer);
    }
    None
}

fn observe(flow: &Flow, writes: &SocketWrites, tick: Duration) -> bool {
    flow.socket_wrote(writes.total(), tick)
}

async fn watch(
    control: &Control,
    plan: &Plan,
    stop: &Stop,
    flow: &Flow,
    tx: &mpsc::Sender<Out>,
    window: &WindowGrant,
    deadline: i64,
) {
    let settings = plan.installed.settings;
    let mut interval = tokio::time::interval(WATCH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_ping = control.tick();
    let mut probes = Cadence::starting(NODE_PROBE_INTERVAL, control.tick());
    let mut last_recheck = control.tick();
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            _ = interval.tick() => {}
        }
        let tick = control.tick();
        if let Some(writes) = &plan.socket_writes
            && observe(flow, writes, tick)
        {
            control.web.terminals.counters.socket_progressed();
        }
        control.web.terminals.counters.node_ahead(
            window
                .kept()
                .saturating_sub(flow.delivered.load(Ordering::Relaxed)),
        );
        if tx.is_closed() {
            stop.stop(End::ClientClosed);
            return;
        }
        if let Some(warning) = flow.idle_warning(tick, settings.idle_timeout)
            && tx
                .try_send(Out::Text(protocol::idle(warning.seconds_left)))
                .is_ok()
        {
            flow.warned(&warning);
        }
        if let Some(end) = verdict(flow, tick, settings.idle_timeout) {
            if end == End::Wedged {
                tracing::info!(
                    target: "jaunt::web",
                    node_id = stop.node_id(),
                    "a web terminal made no progress while bytes were waiting and was closed"
                );
            }
            stop.stop(end);
            return;
        }
        if let Some(now) = control.now() {
            if now.secs >= plan.web_expires_at {
                stop.stop(End::WebSessionEnded);
                return;
            }
            if now.secs >= deadline {
                stop.stop(End::MaxDuration);
                return;
            }
        }
        if tick.saturating_sub(last_ping) >= TERMINAL_PING_INTERVAL {
            last_ping = tick;
            flow.ask_for_ping();
        }
        if probes.due(tick) {
            flow.probe_wanted.notify_one();
        }
        if tick.saturating_sub(last_recheck) >= SESSION_RECHECK {
            last_recheck = tick;
            if let Some(end) = recheck(control, plan).await {
                stop.stop(end);
                return;
            }
        }
    }
}

async fn probe_node(
    control: Control,
    stop: Arc<Stop>,
    flow: Arc<Flow>,
    input: Arc<TerminalInput>,
    latency: Arc<NodeLatency>,
) {
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = flow.probe_wanted.notified() => {}
        }
        let started = control.tick();
        let answered = tokio::select! {
            biased;
            () = stop.cancelled() => return,
            answered = tokio::time::timeout(NODE_PROBE_TIMEOUT, input.probe()) => answered,
        };
        match answered {
            Ok(Ok(())) => {
                let now = control.tick();
                latency.record(now.saturating_sub(started), now);
            }
            Ok(Err(_)) => return,
            Err(_) => {
                tracing::debug!(target: "jaunt::web", "a node did not answer a keepalive in time");
            }
        }
    }
}

async fn settle<T>(task: JoinHandle<T>) -> Option<T> {
    let mut task = task;
    match tokio::time::timeout(PUMP_GRACE, &mut task).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(_)) => None,
        Err(_) => {
            task.abort();
            None
        }
    }
}

fn record_denial(
    control: &Control,
    plan: &Plan,
    reason: &str,
    reference: Option<&str>,
) -> Option<String> {
    control.web.terminals.denials.record(
        &Denial {
            user_id: &plan.user.id,
            reason,
            reference,
            node: &plan.node.name,
            login: &plan.login,
            client_addr: Some(plan.client_addr),
        },
        control.tick(),
    )
}

pub(crate) async fn run(
    control: Control,
    socket: WebSocket,
    plan: Plan,
    admission: Result<Admission, Refused>,
) {
    let flow = Arc::new(Flow::starting(control.tick()));
    let (sink, mut stream) = socket.split();
    let writer = Writer::spawn(sink, control.clone(), Arc::clone(&flow));
    let admission = match admission {
        Ok(admission) => admission,
        Err(refused) => {
            let end = match refused {
                Refused::Full => End::Limit,
                Refused::Closing => End::Shutdown,
            };
            let reference = record_denial(&control, &plan, setup_reason(end), None);
            writer.finish(end, None, reference.as_deref()).await;
            return;
        }
    };
    let stop = Arc::clone(&admission.stop);
    let account = Arc::new(AccountWatch::default());
    let steps = Arc::new(Steps::default());
    let mut early = Vec::new();
    let mut attempt = Attempt {
        serial: None,
        gate: None,
        detail: None,
    };
    let opened = wait_for_setup(
        &control,
        &plan,
        &Waiting {
            stop: &stop,
            tx: &writer.tx,
            account: &account,
            steps: &steps,
        },
        &mut stream,
        &mut early,
        &mut attempt,
    )
    .await;
    let notice = account.latest();
    let opened = match opened {
        Ok(opened) => opened,
        Err(end) => {
            stop.stop(end);
            let (end, reference) = account_end(stop.end().unwrap_or(end), &notice);
            let reason = match (end, attempt.detail) {
                (End::Unavailable, Some(detail)) => detail,
                _ => setup_reason(end),
            };
            let reference = record_denial(
                &control,
                &plan,
                reason,
                reference.map(AccountReference::as_str),
            );
            writer.finish(end, None, reference.as_deref()).await;
            if let Some(gate) = attempt.gate.take() {
                gate.finish().await;
            }
            drop(admission);
            return;
        }
    };
    let serial = attempt.serial.unwrap_or_default();
    let started = control.tick();
    send_or_stop(
        &writer.tx,
        &stop,
        Out::Text(protocol::ready(
            &opened.session_id,
            created_home(&notice),
            opened.recording,
        )),
    )
    .await;
    flow.touch(control.tick());
    audit::opened(&audit::Opened {
        user_id: &plan.user.id,
        session_id: &opened.session_id,
        node_id: &plan.node.id,
        node: &plan.node.name,
        login: &plan.login,
        serial,
        client_addr: plan.client_addr,
    });
    let latency = Arc::new(NodeLatency::default());
    let pump = |stop: &Arc<Stop>| Pump {
        control: control.clone(),
        stop: Arc::clone(stop),
        flow: Arc::clone(&flow),
        latency: Arc::clone(&latency),
        tx: writer.tx.clone(),
    };
    let window = opened.output.window();
    let outputs = tokio::spawn(pump(&stop).output(opened.output));
    let inputs = tokio::spawn(pump(&stop).input(stream, early, Arc::clone(&opened.input)));
    let probes = tokio::spawn(probe_node(
        control.clone(),
        Arc::clone(&stop),
        Arc::clone(&flow),
        Arc::clone(&opened.input),
        Arc::clone(&latency),
    ));
    watch(
        &control,
        &plan,
        &stop,
        &flow,
        &writer.tx,
        &window,
        opened.deadline,
    )
    .await;
    drop(window);
    let end = stop.end().unwrap_or(End::Unavailable);
    let exit = settle(outputs).await.flatten();
    if settle(inputs).await.is_none() {
        tracing::debug!(target: "jaunt::web", "the input pump of a web terminal was stopped");
    }
    if settle(probes).await.is_none() {
        tracing::debug!(target: "jaunt::web", "the node probe of a web terminal was stopped");
    }
    let closing = protocol::closing(end);
    let reference = (closing.code.is_some() && closing.error.is_some()).then(new_denial_reference);
    writer
        .finish(end, exit.as_ref(), reference.as_deref())
        .await;
    if tokio::time::timeout(PUMP_GRACE, opened.input.disconnect())
        .await
        .is_err()
    {
        tracing::debug!(target: "jaunt::web", "a web terminal did not say goodbye to the node in time");
    }
    drop(opened.input);
    if let Some(gate) = attempt.gate.take() {
        gate.finish().await;
    }
    audit::closed(&audit::Closed {
        user_id: &plan.user.id,
        session_id: &opened.session_id,
        node_id: &plan.node.id,
        reason: closing.audit,
        bytes_in: flow.bytes_in.load(Ordering::Relaxed),
        bytes_out: flow.bytes_out.load(Ordering::Relaxed),
        duration: control.tick().saturating_sub(started),
        serial,
        reference: reference.as_deref(),
    });
    drop(admission);
}

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};
    use std::time::Duration;

    use tokio::time::Instant;

    use std::sync::atomic::Ordering;

    use jaunt_ssh::TerminalExit;

    use jaunt_proto::{AccountEvent, AccountReference, AccountRefusal, AccountStage};

    use super::{
        AccountWatch, Cadence, Flow, NodeLatency, Out, SETUP_TIMEOUT, STORE_DEADLINE, Steps,
        Waiting, abrupt_cause, account_end, await_setup, bounded_setup, created_home, due_stages,
        observe, output_end, recheck_cause, recording_mode, verdict,
    };
    use crate::host_accounts::AccountNotice;
    use crate::principal::Refusal;
    use crate::serve::SocketWrites;
    use crate::web::terminal::live::End;
    use crate::web::terminal::live::{Limits, LiveTerminals};
    use crate::web::terminal::protocol::{Recording, Stage, progress};

    const PATIENCE: Duration = Duration::from_secs(10);
    const IDLE: Duration = Duration::from_secs(1800);

    fn at(secs: u64) -> Duration {
        Duration::from_secs(secs)
    }

    #[test]
    fn a_quiet_browser_is_a_dead_peer_only_after_a_ping_it_left_unanswered() {
        let flow = Flow::starting(at(0));
        assert_eq!(verdict(&flow, at(100), IDLE), None);
        flow.pinged(at(81));
        assert_eq!(verdict(&flow, at(100), IDLE), None);
        assert_eq!(verdict(&flow, at(101), IDLE), Some(End::DeadPeer));
        flow.reading_blocked.store(true, Ordering::Relaxed);
        assert_eq!(verdict(&flow, at(101), IDLE), None);
        flow.reading_blocked.store(false, Ordering::Relaxed);
        flow.heard(at(90));
        flow.pinged(at(95));
        assert_eq!(verdict(&flow, at(149), IDLE), None);
        assert_eq!(verdict(&flow, at(150), IDLE), Some(End::DeadPeer));
    }

    #[test]
    fn waiting_bytes_without_progress_and_a_stuck_write_are_wedged() {
        let flow = Flow::starting(at(0));
        flow.pending_input.store(1, Ordering::Relaxed);
        assert_eq!(verdict(&flow, at(59), IDLE), None);
        assert_eq!(verdict(&flow, at(60), IDLE), Some(End::Wedged));
        flow.pending_input.store(0, Ordering::Relaxed);
        flow.pending_output.store(1, Ordering::Relaxed);
        assert_eq!(verdict(&flow, at(60), IDLE), Some(End::Wedged));
        flow.touch(at(30));
        assert_eq!(verdict(&flow, at(89), IDLE), None);
        flow.pending_output.store(0, Ordering::Relaxed);
        assert_eq!(verdict(&flow, at(600), IDLE), None);
        flow.writing(at(600));
        assert_eq!(verdict(&flow, at(659), IDLE), None);
        assert_eq!(verdict(&flow, at(660), IDLE), Some(End::Wedged));
        flow.wrote();
        assert_eq!(verdict(&flow, at(660), IDLE), None);
        assert_eq!(verdict(&flow, at(1830), IDLE), Some(End::IdleTimeout));
    }

    #[test]
    fn a_socket_taking_a_byte_every_20_seconds_stays_and_a_stopped_one_goes_at_the_threshold() {
        let flow = Flow::starting(at(0));
        flow.pending_output.store(32 * 1024, Ordering::Relaxed);
        flow.writing(at(0));
        let mut taken = 0;
        for second in 1..=600 {
            if second % 20 == 0 {
                taken += 1;
                assert!(flow.socket_wrote(taken, at(second)));
            }
            assert_eq!(verdict(&flow, at(second), IDLE), None, "{second}");
        }
        assert!(!flow.socket_wrote(taken, at(601)));
        assert_eq!(verdict(&flow, at(659), IDLE), None);
        assert_eq!(verdict(&flow, at(660), IDLE), Some(End::Wedged));
    }

    #[test]
    fn only_bytes_the_socket_took_move_the_progress_mark() {
        let flow = Flow::starting(at(0));
        flow.pending_output.store(1, Ordering::Relaxed);
        flow.bytes_out.store(4096, Ordering::Relaxed);
        let writes = SocketWrites::default();
        assert!(!observe(&flow, &writes, at(30)));
        assert_eq!(verdict(&flow, at(60), IDLE), Some(End::Wedged));
        writes.add(5);
        assert!(observe(&flow, &writes, at(40)));
        assert_eq!(verdict(&flow, at(99), IDLE), None);
        assert!(!observe(&flow, &writes, at(50)));
        assert_eq!(verdict(&flow, at(100), IDLE), Some(End::Wedged));
    }

    #[test]
    fn socket_progress_keeps_waiting_output_alive_but_never_stuck_input() {
        let output = Flow::starting(at(0));
        output.pending_output.store(1, Ordering::Relaxed);
        assert!(output.socket_wrote(10, at(50)));
        assert_eq!(verdict(&output, at(109), IDLE), None);
        assert_eq!(verdict(&output, at(110), IDLE), Some(End::Wedged));
        let input = Flow::starting(at(0));
        input.pending_input.store(1, Ordering::Relaxed);
        assert!(input.socket_wrote(10, at(50)));
        assert_eq!(verdict(&input, at(60), IDLE), Some(End::Wedged));
    }

    #[test]
    fn progress_goes_node_then_account_only_when_creating_then_shell_and_never_back() {
        let steps = Steps::default();
        assert_eq!(due_stages(None, steps.reached(), false), []);
        steps.reach(Stage::Node);
        assert_eq!(due_stages(None, steps.reached(), false), [Stage::Node]);
        assert_eq!(due_stages(Some(Stage::Node), steps.reached(), false), []);
        assert_eq!(
            due_stages(Some(Stage::Node), steps.reached(), true),
            [Stage::Account]
        );
        steps.reach(Stage::Shell);
        steps.reach(Stage::Node);
        assert_eq!(steps.reached(), Some(Stage::Shell));
        assert_eq!(
            due_stages(Some(Stage::Account), steps.reached(), true),
            [Stage::Shell]
        );
        assert_eq!(
            due_stages(None, steps.reached(), true),
            [Stage::Node, Stage::Account, Stage::Shell]
        );
        assert_eq!(
            due_stages(None, steps.reached(), false),
            [Stage::Node, Stage::Shell]
        );
        assert_eq!(due_stages(Some(Stage::Shell), steps.reached(), true), []);
    }

    #[tokio::test]
    async fn stages_not_yet_sent_reach_the_browser_in_order_before_a_setup_done_in_one_poll() {
        let live = std::sync::Arc::new(LiveTerminals::default());
        let admission = live
            .admit(
                "alice",
                "s-1",
                "n-1",
                &Limits {
                    per_user: 1,
                    total: 1,
                },
            )
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let account = std::sync::Arc::new(AccountWatch::default());
        let (_notices, receiver) = tokio::sync::watch::channel(AccountNotice {
            creating: Some(AccountReference::parse("H-00000001").unwrap()),
            outcome: None,
        });
        assert!(account.receiver.set(receiver).is_ok());
        let steps = std::sync::Arc::new(Steps::default());
        let waiting = Waiting {
            stop: &admission.stop,
            tx: &tx,
            account: &account,
            steps: &steps,
        };
        let mut stream = futures_util::stream::pending();
        let mut early = Vec::new();
        let setup = async {
            steps.reach(Stage::Node);
            steps.reach(Stage::Shell);
            Ok::<u8, End>(7)
        };

        let finished = await_setup(setup, &waiting, &mut stream, &mut early).await;

        assert_eq!(finished, Ok(7));
        drop(tx);
        let mut frames = Vec::new();
        while let Some(out) = rx.recv().await {
            if let Out::Text(text) = out {
                frames.push(text);
            }
        }
        assert_eq!(
            frames,
            [
                progress(Stage::Node),
                progress(Stage::Account),
                progress(Stage::Shell)
            ]
        );
    }

    #[tokio::test]
    async fn a_setup_that_failed_leaves_no_progress_frame_in_the_queue() {
        let live = std::sync::Arc::new(LiveTerminals::default());
        let admission = live
            .admit(
                "alice",
                "s-1",
                "n-1",
                &Limits {
                    per_user: 1,
                    total: 1,
                },
            )
            .unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let account = std::sync::Arc::new(AccountWatch::default());
        let steps = std::sync::Arc::new(Steps::default());
        let waiting = Waiting {
            stop: &admission.stop,
            tx: &tx,
            account: &account,
            steps: &steps,
        };
        let mut stream = futures_util::stream::pending();
        let mut early = Vec::new();
        let setup = async {
            steps.reach(Stage::Node);
            steps.reach(Stage::Shell);
            Err::<u8, End>(End::Unavailable)
        };

        let finished = await_setup(setup, &waiting, &mut stream, &mut early).await;

        assert_eq!(finished, Err(End::Unavailable));
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_setup_that_never_finishes_ends_as_unavailable_at_the_setup_timeout() {
        let started = Instant::now();
        let ended = bounded_setup(pending::<Result<u8, End>>()).await;
        assert_eq!(ended, Err(End::Unavailable));
        assert!(started.elapsed() >= SETUP_TIMEOUT);
        assert!(started.elapsed() < SETUP_TIMEOUT + Duration::from_secs(1));
        assert_eq!(bounded_setup(ready(Ok::<u8, End>(3))).await, Ok(3));
    }

    #[test]
    fn a_probe_is_due_once_per_interval_and_the_mark_moves_with_it() {
        let mut probes = Cadence::starting(Duration::from_secs(20), at(100));
        assert!(!probes.due(at(100)));
        assert!(!probes.due(Duration::from_millis(119_999)));
        assert!(probes.due(at(120)));
        assert!(!probes.due(at(120)));
        assert!(!probes.due(Duration::from_millis(139_999)));
        assert!(probes.due(at(145)));
        assert!(!probes.due(at(164)));
        assert!(probes.due(at(165)));
    }

    #[test]
    fn the_recording_mode_follows_the_server_store_and_the_input_decision() {
        for (recordings_on, record_input, expected) in [
            (true, Some(true), Recording::Full),
            (true, Some(false), Recording::Output),
            (true, None, Recording::Full),
            (false, Some(true), Recording::Off),
            (false, None, Recording::Off),
        ] {
            assert_eq!(
                recording_mode(recordings_on, record_input),
                expected,
                "{recordings_on} {record_input:?}"
            );
        }
    }

    #[test]
    fn the_node_latency_appears_after_a_measurement_is_clamped_and_goes_when_stale() {
        let latency = NodeLatency::default();
        assert_eq!(latency.current(at(5)), None);
        latency.record(Duration::from_millis(37), at(10));
        assert_eq!(latency.current(at(10)), Some(37));
        assert_eq!(latency.current(at(70)), Some(37));
        assert_eq!(latency.current(at(71)), None);
        latency.record(Duration::from_secs(3600), at(100));
        assert_eq!(latency.current(at(100)), Some(20_000));
        latency.record(Duration::ZERO, at(120));
        assert_eq!(latency.current(at(119)), Some(0));
    }

    #[test]
    fn the_idle_warning_comes_once_two_minutes_before_the_timeout_and_activity_rearms_it() {
        let flow = Flow::starting(at(0));
        assert_eq!(flow.idle_warning(at(1679), IDLE), None);
        let warning = flow.idle_warning(at(1680), IDLE).unwrap();
        assert_eq!(warning.seconds_left, 120);
        assert_eq!(
            flow.idle_warning(at(1681), IDLE)
                .map(|warning| warning.seconds_left),
            Some(119)
        );
        flow.warned(&warning);
        assert_eq!(flow.idle_warning(at(1700), IDLE), None);
        assert_eq!(flow.idle_warning(at(1800), IDLE), None);
        flow.touch(at(1750));
        assert_eq!(flow.idle_warning(at(3429), IDLE), None);
        assert!(flow.idle_warning(at(3430), IDLE).is_some());
        let short = Flow::starting(at(0));
        assert_eq!(short.idle_warning(at(100), Duration::from_secs(179)), None);
        assert!(
            short
                .idle_warning(at(60), Duration::from_secs(180))
                .is_some()
        );
    }

    #[test]
    fn active_resets_the_idle_timer_at_most_once_in_ten_seconds_and_ping_never_does() {
        let flow = Flow::starting(at(0));
        flow.pinged(at(1000));
        flow.heard(at(1000));
        assert_eq!(verdict(&flow, at(1800), IDLE), Some(End::IdleTimeout));
        assert!(flow.active(at(1700)));
        assert_eq!(verdict(&flow, at(1800), IDLE), None);
        assert!(!flow.active(at(1709)));
        assert_eq!(verdict(&flow, at(3500), IDLE), Some(End::IdleTimeout));
        assert!(flow.active(at(1710)));
        assert_eq!(verdict(&flow, at(3509), IDLE), None);
        assert_eq!(verdict(&flow, at(3510), IDLE), Some(End::IdleTimeout));
    }

    #[test]
    fn output_cut_by_a_node_violation_ends_as_one_even_after_an_exit_status() {
        let exit = TerminalExit::Status(0);
        assert_eq!(output_end(Some(&exit), true), Some(End::NodeViolation));
        assert_eq!(output_end(None, true), Some(End::NodeViolation));
        assert_eq!(output_end(Some(&exit), false), Some(End::Exited));
        assert_eq!(output_end(None, false), None);
    }

    #[test]
    fn the_setup_timeout_covers_every_step_of_a_first_login_inside_the_agent_deadline() {
        let authorize = at(10);
        let account_lookup = at(2);
        let reports = at(4);
        let helper = at(10);
        let inner_login = at(10);
        let agent_auth_deadline = at(45);
        assert!(authorize + account_lookup + reports + helper + inner_login <= agent_auth_deadline);
        assert!(agent_auth_deadline < SETUP_TIMEOUT);
        assert_eq!(SETUP_TIMEOUT, at(50));
    }

    #[test]
    fn a_reported_account_outcome_names_the_refusal_only_when_setup_was_refused() {
        let reference = AccountReference::parse("H-9D0311FE").unwrap();
        let notice = |outcome| AccountNotice {
            creating: Some(reference.clone()),
            outcome: Some(outcome),
        };
        let refused = |reason| AccountEvent::Refused {
            reference: reference.clone(),
            reason,
        };
        let created = AccountEvent::Created {
            reference: reference.clone(),
            uid: 30_000,
            home: "/home/alice".to_owned(),
            groups: Vec::new(),
        };
        let failed = AccountEvent::Failed {
            reference: reference.clone(),
            stage: AccountStage::Useradd,
            exit_code: Some(12),
        };
        let h_ref = Some(&reference);
        for (end, outcome, expected) in [
            (
                End::Denied,
                Some(refused(AccountRefusal::NameRule)),
                (End::AccountRefused, h_ref),
            ),
            (
                End::Denied,
                Some(refused(AccountRefusal::UidRange)),
                (End::AccountRefused, h_ref),
            ),
            (
                End::Denied,
                Some(refused(AccountRefusal::RateLimit)),
                (End::AccountFailed, h_ref),
            ),
            (
                End::Unavailable,
                Some(failed.clone()),
                (End::AccountFailed, h_ref),
            ),
            (
                End::Denied,
                Some(AccountEvent::Missing {
                    reference: reference.clone(),
                }),
                (End::NoAccount, h_ref),
            ),
            (End::Denied, Some(created.clone()), (End::Denied, None)),
            (End::Denied, None, (End::Denied, None)),
            (End::Revoked, Some(failed), (End::Revoked, None)),
            (
                End::Limit,
                Some(AccountEvent::Missing {
                    reference: reference.clone(),
                }),
                (End::Limit, None),
            ),
        ] {
            let notice = match outcome {
                Some(outcome) => notice(outcome),
                None => AccountNotice::default(),
            };
            assert_eq!(account_end(end, &notice), expected, "{end:?} {notice:?}");
        }
        assert_eq!(created_home(&notice(created)), Some("/home/alice"));
        assert_eq!(created_home(&AccountNotice::default()), None);
    }

    #[tokio::test(start_paused = true)]
    async fn an_abrupt_end_is_revoked_only_when_the_store_says_so_in_time() {
        assert_eq!(
            abrupt_cause(ready(Ok::<bool, ()>(true))).await,
            End::Revoked
        );
        assert_eq!(
            abrupt_cause(ready(Ok::<bool, ()>(false))).await,
            End::Unavailable
        );
        assert_eq!(
            abrupt_cause(ready(Err::<bool, ()>(()))).await,
            End::Unavailable
        );
        let started = Instant::now();
        let stuck = tokio::time::timeout(PATIENCE, abrupt_cause(pending::<Result<bool, ()>>()))
            .await
            .expect("a stuck store held the ended terminal");
        assert_eq!(stuck, End::Unavailable);
        assert!(started.elapsed() >= STORE_DEADLINE);
    }

    #[tokio::test(start_paused = true)]
    async fn the_recheck_acts_only_on_a_clear_answer_and_fails_open_on_a_stuck_store() {
        let valid = || ready(Ok::<bool, &str>(true));
        let clean = || ready(Ok::<(), Refusal>(()));
        assert_eq!(
            recheck_cause(ready(Ok::<bool, &str>(false)), clean()).await,
            Some(End::WebSessionEnded)
        );
        assert_eq!(
            recheck_cause(valid(), ready(Err(Refusal::Revoked))).await,
            Some(End::Revoked)
        );
        assert_eq!(recheck_cause(valid(), clean()).await, None);
        assert_eq!(
            recheck_cause(valid(), ready(Err(Refusal::Unavailable))).await,
            None
        );
        assert_eq!(
            recheck_cause(ready(Err::<bool, &str>("store")), clean()).await,
            None
        );
        let started = Instant::now();
        let stuck_session = tokio::time::timeout(
            PATIENCE,
            recheck_cause(pending::<Result<bool, &str>>(), clean()),
        )
        .await
        .expect("a stuck session lookup froze the watch loop");
        assert_eq!(stuck_session, None);
        let stuck_revocation = tokio::time::timeout(
            PATIENCE,
            recheck_cause(valid(), pending::<Result<(), Refusal>>()),
        )
        .await
        .expect("a stuck revocation lookup froze the watch loop");
        assert_eq!(stuck_revocation, None);
        assert!(started.elapsed() >= STORE_DEADLINE * 2);
    }
}
