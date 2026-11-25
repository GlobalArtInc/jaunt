use std::collections::{BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use russh::server::{self, ChannelOpenHandle, Msg};
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelOpenFailure, ChannelReadHalf, ChannelWriteHalf, Pty,
    Sig, client,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::inner::{InnerClient, OUTPUT_WINDOW};
use crate::intake::{ChannelGrant, ChannelIntake, IntakeError, IntakeEvent, IntakeReader};
use crate::observer::{
    ChannelExit, ChannelProgram, ChannelStart, ObserverCell, OutputStream, Terminal, TerminalSize,
};
use crate::output::{ExitSignal, InnerGrant, OutputError, OutputEvent, OutputQueue, OutputReader};

const REQUEST_QUEUE: usize = 32;
const MAX_ENV_NAME: usize = 64;
const MAX_ENV_VALUE: usize = 256;
const STDERR: u32 = 1;
const INNER_CLOSE_GRACE: Duration = Duration::from_secs(1);
pub(crate) const TERMINAL_REFUSED: &[u8] = b"jaunt: a terminal is not allowed by your roles\r\n";

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
pub(crate) struct Traffic {
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    exit_status: Mutex<Option<i32>>,
}

impl Traffic {
    pub(crate) fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Acquire)
    }

    pub(crate) fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Acquire)
    }

    pub(crate) fn exit_status(&self) -> Option<i32> {
        *lock(&self.exit_status)
    }

    fn add(counter: &AtomicU64, len: usize) {
        counter.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::AcqRel);
    }

    pub(crate) fn add_in(&self, len: usize) {
        Self::add(&self.bytes_in, len);
    }

    fn record_exit(&self, status: Option<i32>) {
        *lock(&self.exit_status) = status;
    }
}

#[derive(Default)]
pub(crate) struct LiveChannels(Mutex<BTreeSet<ChannelId>>);

impl LiveChannels {
    pub(crate) fn snapshot(&self) -> Vec<ChannelId> {
        lock(&self.0).iter().copied().collect()
    }

    fn insert(&self, id: ChannelId) {
        lock(&self.0).insert(id);
    }

    fn remove(&self, id: ChannelId) {
        lock(&self.0).remove(&id);
    }
}

#[derive(Clone)]
pub(crate) struct BridgeContext {
    pub(crate) session_id: Arc<str>,
    pub(crate) tracker: TaskTracker,
    pub(crate) stop: CancellationToken,
    pub(crate) traffic: Arc<Traffic>,
    pub(crate) observer: Arc<ObserverCell>,
    pub(crate) live: Arc<LiveChannels>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChannelKind {
    Session,
    Forward,
}

pub(crate) const DIRECT_TCPIP: &str = "direct-tcpip";

pub(crate) enum InnerOpened {
    Ready(Channel<client::Msg>),
    Refused(russh::Error),
    TimedOut,
    Cancelled,
}

pub(crate) async fn wait_open<F>(
    open: Pin<&mut F>,
    cancel: &CancellationToken,
    deadline: Duration,
) -> InnerOpened
where
    F: Future<Output = Result<Channel<client::Msg>, russh::Error>>,
{
    tokio::select! {
        biased;
        () = cancel.cancelled() => InnerOpened::Cancelled,
        opened = open => match opened {
            Ok(channel) => InnerOpened::Ready(channel),
            Err(error) => InnerOpened::Refused(error),
        },
        () = tokio::time::sleep(deadline) => InnerOpened::TimedOut,
    }
}

pub(crate) async fn close_late<F>(open: Pin<&mut F>, deadline: Duration, stop: &CancellationToken)
where
    F: Future<Output = Result<Channel<client::Msg>, russh::Error>>,
{
    let late = async {
        match open.await {
            Ok(late) => late.close().await,
            Err(_) => Ok(()),
        }
    };
    let bounded = tokio::time::timeout(deadline.saturating_mul(2), late);
    if !matches!(stop.run_until_cancelled(bounded).await, Some(Ok(Ok(())))) {
        tracing::debug!(
            target: "jaunt::agent",
            event = "agent.ssh.late_channel_abandoned"
        );
    }
}

pub(crate) struct DataPath {
    pub(crate) outer: ChannelWriteHalf<Msg>,
    pub(crate) server: server::Handle,
    pub(crate) id: ChannelId,
    pub(crate) reader: IntakeReader,
    pub(crate) replies: Replies,
    pub(crate) kind: ChannelKind,
    pub(crate) cancel: CancellationToken,
    pub(crate) closing: CancellationToken,
}

impl DataPath {
    pub(crate) fn spawn(
        self,
        channel: Channel<client::Msg>,
        handle: &Arc<client::Handle<InnerClient>>,
        context: &BridgeContext,
    ) -> Arc<ChannelWriteHalf<client::Msg>> {
        let grants = InnerGrant::new(handle, channel.id());
        let (output, events) = OutputQueue::new(OUTPUT_WINDOW, grants);
        let (inner_read, inner_write) = channel.split();
        let inner_write = Arc::new(inner_write);
        context.tracker.spawn(pump_input(
            self.reader,
            Arc::clone(&inner_write),
            self.cancel.clone(),
            self.closing,
        ));
        let drain = OutputDrain {
            inner: inner_read,
            inner_write: Arc::clone(&inner_write),
            output,
            replies: self.replies,
            observer: Arc::clone(&context.observer),
            traffic: Arc::clone(&context.traffic),
            kind: self.kind,
            number: self.id.number(),
            session_id: Arc::clone(&context.session_id),
            cancel: self.cancel.clone(),
            started: false,
            exit: ChannelExit::Unknown,
        };
        let drained = context.tracker.spawn(drain.run());
        let pump = OutputPump {
            events,
            drained,
            outer: self.outer,
            server: self.server,
            id: self.id,
            kind: self.kind,
            traffic: Arc::clone(&context.traffic),
            observer: Arc::clone(&context.observer),
            live: Arc::clone(&context.live),
            cancel: self.cancel,
        };
        context.tracker.spawn(pump.run());
        inner_write
    }
}

pub(crate) struct InnerOpen {
    pub(crate) handle: Arc<client::Handle<InnerClient>>,
    pub(crate) deadline: Duration,
}

struct Pending {
    reply: oneshot::Sender<bool>,
    start: Option<ChannelStart>,
}

#[derive(Clone, Default)]
pub(crate) struct Replies(Arc<Mutex<VecDeque<Pending>>>);

impl Replies {
    fn push(&self, reply: oneshot::Sender<bool>, start: Option<ChannelStart>) {
        lock(&self.0).push_back(Pending { reply, start });
    }

    fn resolve(&self, granted: bool, observer: &ObserverCell, number: u32) -> bool {
        let head = lock(&self.0).pop_front();
        let Some(pending) = head else {
            return false;
        };
        let started = match (granted && !pending.reply.is_closed(), &pending.start) {
            (true, Some(start)) => {
                observer.call(|observer| observer.channel_start(number, start));
                true
            }
            _ => false,
        };
        answer(pending.reply, granted);
        started
    }

    fn fail_all(&self) {
        let waiting: Vec<_> = lock(&self.0).drain(..).collect();
        for pending in waiting {
            answer(pending.reply, false);
        }
    }
}

fn answer(reply: oneshot::Sender<bool>, granted: bool) -> bool {
    let told = reply.send(granted).is_ok();
    if !told {
        tracing::debug!(target: "jaunt::agent", event = "agent.ssh.late_reply", granted);
    }
    told
}

#[derive(Default)]
struct ResizeSlot(Mutex<ResizeState>);

#[derive(Default)]
struct ResizeState {
    size: Option<TerminalSize>,
    queued: bool,
}

impl ResizeSlot {
    fn offer(&self, size: TerminalSize, requests: &mpsc::Sender<InnerRequest>) {
        let mut state = lock(&self.0);
        state.size = Some(size);
        if !state.queued {
            state.queued = requests.try_send(InnerRequest::Resize).is_ok();
        }
    }

    fn take(&self) -> Option<TerminalSize> {
        let mut state = lock(&self.0);
        state.queued = false;
        state.size.take()
    }
}

enum InnerRequest {
    Pty {
        terminal: Terminal,
        modes: Vec<(Pty, u32)>,
        reply: oneshot::Sender<bool>,
    },
    Env {
        name: String,
        value: String,
    },
    Start {
        start: ChannelStart,
        reply: oneshot::Sender<bool>,
    },
    Resize,
    Signal(Sig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Opened,
    Started,
    Closing,
}

enum TerminalState {
    None,
    Granted(Terminal),
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Granted,
    Refused,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartReply {
    Refused,
    TimedOut,
    Started,
    StartedWithNotice(&'static [u8]),
}

pub(crate) struct SessionBridge {
    number: u32,
    phase: Phase,
    terminal: TerminalState,
    env_count: usize,
    intake: ChannelIntake,
    requests: mpsc::Sender<InnerRequest>,
    resize: Arc<ResizeSlot>,
    cancel: CancellationToken,
    closing: CancellationToken,
    settled: CancellationToken,
    observer: Arc<ObserverCell>,
    traffic: Arc<Traffic>,
}

impl SessionBridge {
    pub(crate) fn open(
        outer: Channel<Msg>,
        reply: ChannelOpenHandle,
        inner: InnerOpen,
        server: server::Handle,
        window: u32,
        context: &BridgeContext,
    ) -> Self {
        let id = outer.id();
        let (outer_read, outer_write) = outer.split();
        drop(outer_read);
        let cancel = context.stop.child_token();
        let closing = CancellationToken::new();
        let settled = CancellationToken::new();
        let (intake, reader) = ChannelIntake::new(window, ChannelGrant::new(server.clone(), id));
        let (requests, queue) = mpsc::channel(REQUEST_QUEUE);
        let resize = Arc::new(ResizeSlot::default());
        let establish = Establish {
            reply,
            inner,
            outer: outer_write,
            server,
            id,
            reader,
            queue,
            replies: Replies::default(),
            resize: Arc::clone(&resize),
            cancel: cancel.clone(),
            closing: closing.clone(),
            settled: settled.clone(),
            context: context.clone(),
        };
        context.tracker.spawn(establish.run());
        Self {
            number: id.number(),
            phase: Phase::Opened,
            terminal: TerminalState::None,
            env_count: 0,
            intake,
            requests,
            resize,
            cancel,
            closing,
            settled,
            observer: Arc::clone(&context.observer),
            traffic: Arc::clone(&context.traffic),
        }
    }

    pub(crate) fn finished(&self) -> bool {
        self.cancel.is_cancelled() && self.settled.is_cancelled()
    }

    pub(crate) async fn request_pty(
        &mut self,
        permitted: bool,
        terminal: Terminal,
        modes: Vec<(Pty, u32)>,
        timeout: Duration,
    ) -> Verdict {
        if self.phase != Phase::Opened || !matches!(self.terminal, TerminalState::None) {
            return Verdict::Refused;
        }
        if !permitted {
            self.terminal = TerminalState::Refused;
            return Verdict::Refused;
        }
        let request = terminal.clone();
        let verdict = self
            .ask(
                |reply| InnerRequest::Pty {
                    terminal: request,
                    modes,
                    reply,
                },
                timeout,
            )
            .await;
        match verdict {
            Verdict::Granted => self.terminal = TerminalState::Granted(terminal),
            Verdict::TimedOut => self.abandon(),
            Verdict::Refused => {}
        }
        verdict
    }

    pub(crate) fn env(&mut self, name: &str, value: &str, max_env: usize) -> bool {
        if self.phase != Phase::Opened || self.env_count >= max_env || !env_allowed(name, value) {
            return false;
        }
        let queued = self
            .requests
            .try_send(InnerRequest::Env {
                name: name.to_owned(),
                value: value.to_owned(),
            })
            .is_ok();
        if queued {
            self.env_count += 1;
        }
        queued
    }

    pub(crate) async fn start(&mut self, program: ChannelProgram, timeout: Duration) -> StartReply {
        if self.phase != Phase::Opened {
            return StartReply::Refused;
        }
        let (terminal, notice) = match &self.terminal {
            TerminalState::Granted(terminal) => (Some(terminal.clone()), false),
            TerminalState::Refused => (None, program == ChannelProgram::Shell),
            TerminalState::None => (None, false),
        };
        let start = ChannelStart { program, terminal };
        let verdict = self
            .ask(|reply| InnerRequest::Start { start, reply }, timeout)
            .await;
        match verdict {
            Verdict::Granted => {}
            Verdict::Refused => return StartReply::Refused,
            Verdict::TimedOut => {
                self.abandon();
                return StartReply::TimedOut;
            }
        }
        self.phase = Phase::Started;
        if notice {
            StartReply::StartedWithNotice(TERMINAL_REFUSED)
        } else {
            StartReply::Started
        }
    }

    pub(crate) fn resize(&self, size: TerminalSize) {
        let number = self.number;
        self.observer.call(|observer| observer.resize(number, size));
        self.resize.offer(size, &self.requests);
    }

    pub(crate) fn signal(&self, signal: Sig) -> bool {
        self.requests.try_send(InnerRequest::Signal(signal)).is_ok()
    }

    pub(crate) fn data(&self, data: &[u8]) -> Result<(), IntakeError> {
        match self.phase {
            Phase::Closing => return Ok(()),
            Phase::Opened => return self.intake.consume_extended(data.len()),
            Phase::Started => {}
        }
        let number = self.number;
        self.observer.call(|observer| observer.input(number, data));
        if self.observer.failed() {
            return Ok(());
        }
        self.intake.push_data(data)?;
        Traffic::add(&self.traffic.bytes_in, data.len());
        Ok(())
    }

    pub(crate) fn extended_data(&self, len: usize) -> Result<(), IntakeError> {
        if self.phase == Phase::Closing {
            return Ok(());
        }
        self.intake.consume_extended(len)
    }

    pub(crate) fn eof(&self) {
        if self.phase != Phase::Closing {
            self.intake.push_eof();
        }
    }

    pub(crate) fn close(mut self) {
        self.abandon();
    }

    fn abandon(&mut self) {
        if self.phase != Phase::Closing {
            self.phase = Phase::Closing;
            self.intake.push_close();
            self.closing.cancel();
        }
    }

    async fn ask(
        &self,
        request: impl FnOnce(oneshot::Sender<bool>) -> InnerRequest,
        timeout: Duration,
    ) -> Verdict {
        let (reply, mut answer) = oneshot::channel();
        if self.requests.try_send(request(reply)).is_err() {
            return Verdict::Refused;
        }
        match self
            .cancel
            .run_until_cancelled(tokio::time::timeout(timeout, &mut answer))
            .await
        {
            Some(Ok(Ok(true))) => Verdict::Granted,
            Some(Err(_)) => Verdict::TimedOut,
            Some(Ok(Ok(false) | Err(_))) => Verdict::Refused,
            None => match answer.try_recv() {
                Ok(true) => Verdict::Granted,
                Ok(false) | Err(_) => Verdict::Refused,
            },
        }
    }
}

pub(crate) fn env_allowed(name: &str, value: &str) -> bool {
    (name == "LANG" || name.starts_with("LC_"))
        && name.len() <= MAX_ENV_NAME
        && value.len() <= MAX_ENV_VALUE
}

struct Establish {
    reply: ChannelOpenHandle,
    inner: InnerOpen,
    outer: ChannelWriteHalf<Msg>,
    server: server::Handle,
    id: ChannelId,
    reader: IntakeReader,
    queue: mpsc::Receiver<InnerRequest>,
    replies: Replies,
    resize: Arc<ResizeSlot>,
    cancel: CancellationToken,
    closing: CancellationToken,
    settled: CancellationToken,
    context: BridgeContext,
}

impl Establish {
    async fn run(self) {
        let _settled = self.settled.clone().drop_guard();
        let open = self.inner.handle.channel_open_session();
        tokio::pin!(open);
        let session_id = &self.context.session_id;
        let channel = match wait_open(open.as_mut(), &self.cancel, self.inner.deadline).await {
            InnerOpened::Ready(channel) => channel,
            InnerOpened::Cancelled => return,
            InnerOpened::Refused(_) => {
                self.cancel.cancel();
                self.reply.reject(ChannelOpenFailure::ConnectFailed).await;
                audit_open(session_id, "failed");
                return;
            }
            InnerOpened::TimedOut => {
                self.cancel.cancel();
                self.reply.reject(ChannelOpenFailure::ConnectFailed).await;
                audit_open(session_id, "timeout");
                close_late(open, self.inner.deadline, &self.context.stop).await;
                return;
            }
        };
        self.reply.accept().await;
        audit_open(session_id, "opened");
        self.context.live.insert(self.id);
        let path = DataPath {
            outer: self.outer,
            server: self.server,
            id: self.id,
            reader: self.reader,
            replies: self.replies.clone(),
            kind: ChannelKind::Session,
            cancel: self.cancel.clone(),
            closing: self.closing,
        };
        let inner_write = path.spawn(channel, &self.inner.handle, &self.context);
        self.context.tracker.spawn(forward_requests(
            self.queue,
            inner_write,
            self.replies,
            self.resize,
            self.cancel,
        ));
    }
}

fn audit_open(session_id: &str, outcome: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.ssh.channel",
        session_id,
        kind = "session",
        outcome
    );
}

pub(crate) fn audit_forward(session_id: &str, port: u32, outcome: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.ssh.channel",
        session_id,
        kind = DIRECT_TCPIP,
        port,
        outcome
    );
}

enum Written {
    Done,
    Abandoned,
    Failed,
}

async fn write_unless_closing<E>(
    cancel: &CancellationToken,
    closing: &CancellationToken,
    write: impl Future<Output = Result<(), E>>,
) -> Written {
    tokio::select! {
        biased;
        written = write => match written {
            Ok(()) => Written::Done,
            Err(_) => Written::Failed,
        },
        () = closing.cancelled() => Written::Abandoned,
        () = cancel.cancelled() => Written::Failed,
    }
}

async fn pump_input(
    mut reader: IntakeReader,
    inner: Arc<ChannelWriteHalf<client::Msg>>,
    cancel: CancellationToken,
    closing: CancellationToken,
) {
    while let Some(Some(event)) = cancel.run_until_cancelled(reader.next()).await {
        match event {
            IntakeEvent::Data(bytes) => {
                let len = bytes.len();
                match write_unless_closing(&cancel, &closing, inner.data_bytes(bytes)).await {
                    Written::Done => {
                        if reader.consumed(len).is_err() {
                            return;
                        }
                    }
                    Written::Abandoned => {}
                    Written::Failed => return,
                }
            }
            IntakeEvent::Eof => {
                if !sent(&cancel, inner.eof()).await {
                    return;
                }
            }
            IntakeEvent::Close => {
                if !sent(&cancel, inner.close()).await {
                    tracing::debug!(target: "jaunt::agent", event = "agent.ssh.inner_close_lost");
                }
                cancel.cancel();
                return;
            }
        }
    }
}

async fn sent<E>(cancel: &CancellationToken, write: impl Future<Output = Result<(), E>>) -> bool {
    matches!(cancel.run_until_cancelled(write).await, Some(Ok(())))
}

async fn forward_requests(
    mut queue: mpsc::Receiver<InnerRequest>,
    inner: Arc<ChannelWriteHalf<client::Msg>>,
    replies: Replies,
    resize: Arc<ResizeSlot>,
    cancel: CancellationToken,
) {
    while let Some(Some(request)) = cancel.run_until_cancelled(queue.recv()).await {
        let forwarded = send_request(&inner, &replies, &resize, request);
        if !sent(&cancel, forwarded).await {
            return;
        }
    }
}

async fn send_request(
    inner: &ChannelWriteHalf<client::Msg>,
    replies: &Replies,
    resize: &ResizeSlot,
    request: InnerRequest,
) -> Result<(), russh::Error> {
    match request {
        InnerRequest::Pty {
            terminal,
            modes,
            reply,
        } => {
            replies.push(reply, None);
            let size = terminal.size;
            inner
                .request_pty(
                    true,
                    &terminal.term,
                    size.columns,
                    size.rows,
                    size.pixel_width,
                    size.pixel_height,
                    &modes,
                )
                .await
        }
        InnerRequest::Env { name, value } => inner.set_env(false, name, value).await,
        InnerRequest::Start { start, reply } => {
            let program = start.program.clone();
            replies.push(reply, Some(start));
            match program {
                ChannelProgram::Shell => inner.request_shell(true).await,
                ChannelProgram::Exec(command) => inner.exec(true, command).await,
                ChannelProgram::Subsystem(name) => inner.request_subsystem(true, name).await,
            }
        }
        InnerRequest::Resize => match resize.take() {
            Some(size) => {
                inner
                    .window_change(size.columns, size.rows, size.pixel_width, size.pixel_height)
                    .await
            }
            None => Ok(()),
        },
        InnerRequest::Signal(signal) => inner.signal(signal).await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Closed { eof_sent: bool },
    InnerGone,
    UserGone,
    Cancelled,
}

enum Drained {
    Open,
    Ended,
}

struct DrainEnd {
    started: bool,
    exit: ChannelExit,
}

struct OutputDrain {
    inner: ChannelReadHalf,
    inner_write: Arc<ChannelWriteHalf<client::Msg>>,
    output: OutputQueue,
    replies: Replies,
    observer: Arc<ObserverCell>,
    traffic: Arc<Traffic>,
    kind: ChannelKind,
    number: u32,
    session_id: Arc<str>,
    cancel: CancellationToken,
    started: bool,
    exit: ChannelExit,
}

impl OutputDrain {
    async fn run(mut self) -> DrainEnd {
        let failure = loop {
            let Some(message) = self.cancel.run_until_cancelled(self.inner.wait()).await else {
                break None;
            };
            match self.take(message) {
                Ok(Drained::Open) => {}
                Ok(Drained::Ended) => break None,
                Err(error) => break Some(error),
            }
        };
        let Self {
            inner,
            inner_write,
            output,
            replies,
            session_id,
            started,
            exit,
            ..
        } = self;
        drop(inner);
        replies.fail_all();
        if let Some(error) = failure {
            let closed = tokio::time::timeout(INNER_CLOSE_GRACE, inner_write.close()).await;
            if !matches!(closed, Ok(Ok(()))) {
                tracing::debug!(target: "jaunt::agent", event = "agent.ssh.inner_close_lost");
            }
            output.push_gone();
            if error != OutputError::SessionGone {
                tracing::warn!(
                    target: "jaunt::audit",
                    event = "agent.ssh.node_protocol_violation",
                    session_id = &*session_id,
                    error = %error
                );
            }
        }
        DrainEnd { started, exit }
    }

    fn take(&mut self, message: Option<ChannelMsg>) -> Result<Drained, OutputError> {
        match message {
            None => {
                self.output.push_gone();
                return Ok(Drained::Ended);
            }
            Some(ChannelMsg::Close) => {
                self.output.push_close();
                return Ok(Drained::Ended);
            }
            Some(ChannelMsg::Data { data }) => {
                self.output.push_data(OutputStream::Stdout, &data)?
            }
            Some(ChannelMsg::ExtendedData { data, ext: STDERR }) => {
                self.output.push_data(OutputStream::Stderr, &data)?
            }
            Some(ChannelMsg::ExtendedData { data, .. }) => {
                self.output.discard_extended(data.len())?
            }
            Some(ChannelMsg::Eof) => self.output.push_eof(),
            Some(ChannelMsg::ExitStatus { .. } | ChannelMsg::ExitSignal { .. })
                if self.kind == ChannelKind::Forward => {}
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                if self.first_exit(ChannelExit::Status(exit_status)) {
                    self.traffic.record_exit(i32::try_from(exit_status).ok());
                }
                self.output.push_exit_status(exit_status)
            }
            Some(ChannelMsg::ExitSignal {
                signal_name,
                core_dumped,
                error_message,
                lang_tag,
            }) => {
                if self.first_exit(ChannelExit::Signal(signal_text(&signal_name))) {
                    self.traffic.record_exit(None);
                }
                self.output.push_exit_signal(ExitSignal {
                    name: signal_name,
                    core_dumped,
                    message: error_message,
                    lang: lang_tag,
                })
            }
            Some(ChannelMsg::Success) => {
                self.started |= self.replies.resolve(true, &self.observer, self.number);
            }
            Some(ChannelMsg::Failure) => {
                self.replies.resolve(false, &self.observer, self.number);
            }
            Some(_) => {}
        }
        Ok(Drained::Open)
    }

    fn first_exit(&mut self, exit: ChannelExit) -> bool {
        if self.exit != ChannelExit::Unknown {
            return false;
        }
        self.exit = exit;
        true
    }
}

struct OutputPump {
    events: OutputReader,
    drained: JoinHandle<DrainEnd>,
    outer: ChannelWriteHalf<Msg>,
    server: server::Handle,
    id: ChannelId,
    kind: ChannelKind,
    traffic: Arc<Traffic>,
    observer: Arc<ObserverCell>,
    live: Arc<LiveChannels>,
    cancel: CancellationToken,
}

impl OutputPump {
    async fn run(mut self) {
        let ending = self.forward().await;
        self.live.remove(self.id);
        let closed = match ending {
            Ending::Closed { eof_sent: false } => {
                sent(&self.cancel, self.outer.eof()).await
                    && sent(&self.cancel, self.outer.close()).await
            }
            Ending::Closed { eof_sent: true } | Ending::InnerGone => {
                sent(&self.cancel, self.outer.close()).await
            }
            Ending::UserGone | Ending::Cancelled => true,
        };
        if !closed {
            tracing::debug!(target: "jaunt::agent", event = "agent.ssh.outer_close_lost");
        }
        self.cancel.cancel();
        let drained = match (&mut self.drained).await {
            Ok(drained) => drained,
            Err(error) => {
                tracing::error!(
                    target: "jaunt::agent",
                    event = "agent.ssh.output_drain_failed",
                    panicked = error.is_panic()
                );
                DrainEnd {
                    started: false,
                    exit: ChannelExit::Unknown,
                }
            }
        };
        let number = self.id.number();
        match self.kind {
            ChannelKind::Session if drained.started => self
                .observer
                .call(|observer| observer.channel_end(number, &drained.exit)),
            ChannelKind::Session => {}
            ChannelKind::Forward => self
                .observer
                .call(|observer| observer.forward_close(number)),
        }
    }

    async fn forward(&mut self) -> Ending {
        let mut eof_sent = false;
        loop {
            let Some(event) = self.cancel.run_until_cancelled(self.events.next()).await else {
                return Ending::Cancelled;
            };
            let delivered = match event {
                None | Some(OutputEvent::Gone) => return Ending::InnerGone,
                Some(OutputEvent::Close) => return Ending::Closed { eof_sent },
                Some(OutputEvent::Stdout(data)) => self.output(OutputStream::Stdout, data).await,
                Some(OutputEvent::Stderr(data)) => self.output(OutputStream::Stderr, data).await,
                Some(OutputEvent::Eof) => {
                    eof_sent = true;
                    self.deliver(self.outer.eof()).await
                }
                Some(OutputEvent::ExitStatus(status)) => {
                    self.deliver(self.outer.exit_status(status)).await
                }
                Some(OutputEvent::ExitSignal(signal)) => {
                    let request = self.server.exit_signal_request(
                        self.id,
                        signal.name,
                        signal.core_dumped,
                        signal.message,
                        signal.lang,
                    );
                    self.deliver(request).await
                }
            };
            if let Err(ending) = delivered {
                return ending;
            }
        }
    }

    async fn output(&mut self, stream: OutputStream, data: Bytes) -> Result<(), Ending> {
        let len = data.len();
        let number = self.id.number();
        if self.kind == ChannelKind::Session {
            self.observer
                .call(|observer| observer.output(number, stream, &data));
        }
        match stream {
            OutputStream::Stdout => self.deliver(self.outer.data_bytes(data)).await?,
            OutputStream::Stderr => {
                self.deliver(self.outer.extended_data_bytes(STDERR, data))
                    .await?
            }
        }
        Traffic::add(&self.traffic.bytes_out, len);
        self.events.consumed(len).map_err(|_gone| Ending::InnerGone)
    }

    async fn deliver<E>(&self, write: impl Future<Output = Result<(), E>>) -> Result<(), Ending> {
        match self.cancel.run_until_cancelled(write).await {
            Some(Ok(())) => Ok(()),
            Some(Err(_)) => Err(Ending::UserGone),
            None => Err(Ending::Cancelled),
        }
    }
}

pub(crate) fn signal_text(signal: &Sig) -> String {
    let name = match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => name.as_str(),
    };
    name.to_owned()
}

#[cfg(test)]
mod drain_tests;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
    use std::time::Duration;

    use jaunt_proto::SessionPermissions;
    use russh::Sig;
    use tokio::sync::oneshot::error::TryRecvError;
    use tokio::sync::{mpsc, oneshot};
    use tokio_util::sync::CancellationToken;

    use super::{
        InnerRequest, Phase, REQUEST_QUEUE, Replies, ResizeSlot, SessionBridge, StartReply,
        TerminalState, Traffic, env_allowed, signal_text,
    };
    use crate::intake::{ChannelIntake, SessionGone, WindowGrant};
    use crate::observer::{
        ChannelProgram, ChannelStart, ObserverCell, ObserverFactory, SessionInfo, SessionObserver,
    };

    struct NoGrants;

    impl WindowGrant for NoGrants {
        fn grant(&self, _bytes: u32) -> Result<(), SessionGone> {
            Ok(())
        }
    }

    fn opened_bridge() -> (SessionBridge, mpsc::Receiver<InnerRequest>) {
        let (requests, queue) = mpsc::channel(REQUEST_QUEUE);
        let (intake, _reader) = ChannelIntake::new(1024, NoGrants);
        let bridge = SessionBridge {
            number: 0,
            phase: Phase::Opened,
            terminal: TerminalState::None,
            env_count: 0,
            intake,
            requests,
            resize: Arc::new(ResizeSlot::default()),
            cancel: CancellationToken::new(),
            closing: CancellationToken::new(),
            settled: CancellationToken::new(),
            observer: Arc::new(ObserverCell::new(CancellationToken::new())),
            traffic: Arc::new(Traffic::default()),
        };
        (bridge, queue)
    }

    fn exec() -> ChannelProgram {
        ChannelProgram::Exec(b"true".to_vec())
    }

    #[tokio::test]
    async fn requests_pile_up_only_to_the_queue_bound_and_a_start_is_then_refused_at_once() {
        let (mut bridge, _queue) = opened_bridge();
        let queued = (0..300).filter(|_| bridge.signal(Sig::USR1)).count();
        assert_eq!(queued, REQUEST_QUEUE);
        assert!(!bridge.env("LANG", "C", 16));
        let refused = tokio::time::timeout(
            Duration::from_secs(1),
            bridge.start(exec(), Duration::from_secs(30)),
        )
        .await
        .expect("a full queue must refuse at once");
        assert_eq!(refused, StartReply::Refused);
    }

    #[tokio::test]
    async fn a_reply_given_before_the_bridge_ended_counts_even_without_task_budget() {
        let (mut bridge, mut queue) = opened_bridge();
        let cancel = bridge.cancel.clone();
        let mut start = std::pin::pin!(bridge.start(exec(), Duration::from_secs(30)));
        let waiting =
            std::future::poll_fn(|cx| Poll::Ready(start.as_mut().poll(cx).is_pending())).await;
        assert!(waiting);
        let Some(InnerRequest::Start { reply, .. }) = queue.recv().await else {
            panic!("the start was not forwarded");
        };
        reply.send(true).unwrap();
        cancel.cancel();
        let verdict = std::future::poll_fn(|cx| {
            while let Poll::Ready(progress) = tokio::task::coop::poll_proceed(cx) {
                progress.made_progress();
            }
            start.as_mut().poll(cx)
        })
        .await;
        assert_eq!(verdict, StartReply::Started);
    }

    type Answer = Arc<Mutex<oneshot::Receiver<bool>>>;

    struct StartProbe {
        answer: Answer,
        undelivered_at_start: Arc<Mutex<Vec<bool>>>,
    }

    impl SessionObserver for StartProbe {
        fn channel_start(&mut self, _channel: u32, _start: &ChannelStart) {
            let undelivered = matches!(
                self.answer.lock().unwrap().try_recv(),
                Err(TryRecvError::Empty)
            );
            self.undelivered_at_start.lock().unwrap().push(undelivered);
        }
    }

    struct Probes(Answer, Arc<Mutex<Vec<bool>>>);

    impl ObserverFactory for Probes {
        fn create(&self, _: &SessionInfo, _: &SessionPermissions) -> Box<dyn SessionObserver> {
            Box::new(StartProbe {
                answer: Arc::clone(&self.0),
                undelivered_at_start: Arc::clone(&self.1),
            })
        }
    }

    fn start() -> Option<ChannelStart> {
        Some(ChannelStart {
            program: ChannelProgram::Shell,
            terminal: None,
        })
    }

    #[test]
    fn a_start_reaches_the_observer_before_the_waiter_and_never_after_it_gave_up() {
        let (reply, answer) = oneshot::channel();
        let answer = Arc::new(Mutex::new(answer));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let observer = ObserverCell::new(CancellationToken::new());
        let permissions = SessionPermissions {
            pty: true,
            port_forwarding: false,
            record_input: true,
            max_duration_secs: 60,
        };
        observer
            .create(
                &Probes(Arc::clone(&answer), Arc::clone(&starts)),
                &SessionInfo {
                    session_id: "s".to_owned(),
                    user_id: "u".to_owned(),
                    login: "deploy".to_owned(),
                    client_addr: "203.0.113.5:40000".to_owned(),
                },
                &permissions,
            )
            .unwrap();
        let replies = Replies::default();
        replies.push(reply, start());
        assert!(replies.resolve(true, &observer, 3));
        assert_eq!(*starts.lock().unwrap(), [true]);
        assert_eq!(answer.lock().unwrap().try_recv(), Ok(true));
        let (abandoned, gave_up) = oneshot::channel();
        drop(gave_up);
        replies.push(abandoned, start());
        assert!(!replies.resolve(true, &observer, 3));
        assert_eq!(starts.lock().unwrap().len(), 1);
    }

    #[test]
    fn only_locale_variables_of_bounded_size_pass_the_env_filter() {
        let long_name = format!("LC_{}", "X".repeat(61));
        let too_long_name = format!("LC_{}", "X".repeat(62));
        let long_value = "v".repeat(256);
        let too_long_value = "v".repeat(257);
        for (name, value, allowed) in [
            ("LANG", "en_US.UTF-8", true),
            ("LC_ALL", "C", true),
            ("LC_", "", true),
            (long_name.as_str(), "C", true),
            ("LANG", long_value.as_str(), true),
            (too_long_name.as_str(), "C", false),
            ("LANG", too_long_value.as_str(), false),
            ("LANGUAGE", "en", false),
            ("lang", "C", false),
            ("PATH", "/tmp", false),
            ("LD_PRELOAD", "/tmp/x.so", false),
            ("", "", false),
        ] {
            assert_eq!(env_allowed(name, value), allowed, "{name}={value}");
        }
    }

    #[test]
    fn signals_keep_their_ssh_names() {
        assert_eq!(signal_text(&Sig::TERM), "TERM");
        assert_eq!(signal_text(&Sig::Custom("WINCH".to_owned())), "WINCH");
    }
}
