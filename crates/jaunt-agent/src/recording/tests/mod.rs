mod cast;
mod rules;
mod upload;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{
    BoxFuture, RecordingAck, RecordingChunk, RecordingComplete, RecordingKind, RecordingManifest,
    RecordingReceipt, RecordingState, SessionPermissions,
};
use jaunt_record::{
    Assembler, Chunk, Clock as CastClock, Limits, SessionKind, SessionManifest, Sink, SinkError,
};
use jaunt_ssh::{
    ChannelProgram, ChannelStart, ObserverFactory, OutputStream, SessionInfo, SessionObserver,
    Terminal, TerminalSize,
};
use serde_json::Value;

use super::{RecordingLimits, RecordingParts, RecordingTransport, Recordings};
use crate::run::api::ApiError;
use crate::testkit::ManualClock;

pub(super) const USER: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
pub(super) const NODE: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
pub(super) const LOGIN: &str = "deploy";

pub(super) fn start() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

#[derive(Default)]
pub(super) struct StepClock(AtomicU64);

impl CastClock for StepClock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.fetch_add(1, Ordering::Relaxed))
    }
}

pub(super) struct PanicClock {
    calls: AtomicU64,
    panic_at: u64,
}

impl CastClock for PanicClock {
    fn elapsed(&self) -> Duration {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        assert!(call < self.panic_at, "the recorder clock broke");
        Duration::from_millis(call)
    }
}

pub(super) fn panic_clocks(panic_at: u64) -> super::CastClocks {
    Arc::new(move || {
        Box::new(PanicClock {
            calls: AtomicU64::new(0),
            panic_at,
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Step {
    Ack(Option<u64>),
    Refuse(u16, &'static str, Option<u64>),
    Network,
    LostReply,
    Hang,
    Panic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Seen {
    Chunk(String, u64),
    Complete(String),
}

#[derive(Default)]
pub(super) struct VecSink(Vec<u8>);

impl Sink for VecSink {
    fn write(&mut self, _seq: u64, raw: &[u8]) -> Result<(), SinkError> {
        self.0.extend_from_slice(raw);
        Ok(())
    }
}

#[derive(Default)]
pub(super) struct Stored {
    assembler: Option<Assembler>,
    accepted: Vec<(u64, usize, bool)>,
    sink: VecSink,
    manifest: Option<RecordingManifest>,
}

#[derive(Default)]
pub(super) struct FakeServer {
    chunk_script: Mutex<VecDeque<Step>>,
    complete_script: Mutex<VecDeque<Step>>,
    standing: Mutex<Option<Step>>,
    uploads: Mutex<HashMap<String, Stored>>,
    seen: Mutex<Vec<Seen>>,
}

impl FakeServer {
    pub(super) fn script_chunks(&self, steps: &[Step]) {
        self.chunk_script
            .lock()
            .unwrap()
            .extend(steps.iter().copied());
    }

    pub(super) fn script_complete(&self, steps: &[Step]) {
        self.complete_script
            .lock()
            .unwrap()
            .extend(steps.iter().copied());
    }

    pub(super) fn always(&self, step: Option<Step>) {
        *self.standing.lock().unwrap() = step;
    }

    pub(super) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub(super) fn cast(&self, session_id: &str) -> Vec<u8> {
        self.uploads
            .lock()
            .unwrap()
            .get(session_id)
            .map(|stored| stored.sink.0.clone())
            .unwrap_or_default()
    }

    pub(super) fn accepted(&self, session_id: &str) -> Vec<(u64, usize, bool)> {
        self.uploads
            .lock()
            .unwrap()
            .get(session_id)
            .map(|stored| stored.accepted.clone())
            .unwrap_or_default()
    }

    pub(super) fn manifest(&self, session_id: &str) -> Option<RecordingManifest> {
        self.uploads
            .lock()
            .unwrap()
            .get(session_id)
            .and_then(|stored| stored.manifest.clone())
    }

    fn next(&self, script: &Mutex<VecDeque<Step>>) -> Step {
        let scripted = script.lock().unwrap().pop_front();
        scripted
            .or(*self.standing.lock().unwrap())
            .unwrap_or(Step::Ack(None))
    }

    fn accept_chunk(&self, session_id: &str, body: &RecordingChunk) -> Result<Option<u64>, ()> {
        let chunk = Chunk {
            session_id: session_id.to_owned(),
            seq: body.seq,
            raw_len: body.raw_len,
            compressed: STANDARD.decode(&body.data).map_err(|_| ())?,
            sha256: body.sha256.clone(),
            is_last: body.is_last,
        };
        let mut uploads = self.uploads.lock().unwrap();
        let stored = uploads.entry(session_id.to_owned()).or_default();
        let assembler = stored
            .assembler
            .get_or_insert_with(|| Assembler::new(session_id, Limits::default()));
        assembler.accept(&chunk, &mut stored.sink).map_err(|_| ())?;
        stored
            .accepted
            .push((chunk.seq, chunk.compressed.len(), chunk.is_last));
        Ok(Some(body.seq))
    }

    fn accept_complete(&self, session_id: &str, body: &RecordingComplete) -> Result<u64, ()> {
        let manifest = session_manifest(&body.manifest);
        let mut uploads = self.uploads.lock().unwrap();
        let stored = uploads.entry(session_id.to_owned()).or_default();
        if let Some(known) = &stored.manifest {
            return if *known == body.manifest {
                Ok(known.chunks)
            } else {
                Err(())
            };
        }
        let assembler = stored
            .assembler
            .get_or_insert_with(|| Assembler::new(session_id, Limits::default()));
        let verified = assembler
            .complete(
                &manifest,
                manifest.kind == SessionKind::Shell,
                &mut stored.sink,
            )
            .map_err(|_| ())?;
        stored.manifest = Some(body.manifest.clone());
        Ok(verified.received_chunks)
    }
}

fn refusal(status: u16, code: &str, retry_after: Option<u64>) -> ApiError {
    ApiError::Status {
        status,
        code: code.to_owned(),
        retry_after: retry_after.map(Duration::from_secs),
    }
}

impl RecordingTransport for FakeServer {
    fn chunk<'a>(
        &'a self,
        session_id: &'a str,
        chunk: &'a RecordingChunk,
    ) -> BoxFuture<'a, Result<RecordingAck, ApiError>> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push(Seen::Chunk(session_id.to_owned(), chunk.seq));
            match self.next(&self.chunk_script) {
                Step::Hang => std::future::pending().await,
                Step::Panic => panic!("the transport broke"),
                Step::Network => Err(ApiError::CallTimeout),
                Step::Refuse(status, code, after) => Err(refusal(status, code, after)),
                step @ (Step::Ack(_) | Step::LostReply) => {
                    let acked = self
                        .accept_chunk(session_id, chunk)
                        .map_err(|()| refusal(422, "bad_chunk", None))?;
                    match step {
                        Step::LostReply => Err(ApiError::CallTimeout),
                        Step::Ack(Some(claimed)) => Ok(RecordingAck {
                            acked_through: Some(claimed),
                        }),
                        _ => Ok(RecordingAck {
                            acked_through: acked,
                        }),
                    }
                }
            }
        })
    }

    fn complete<'a>(
        &'a self,
        session_id: &'a str,
        complete: &'a RecordingComplete,
    ) -> BoxFuture<'a, Result<RecordingReceipt, ApiError>> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push(Seen::Complete(session_id.to_owned()));
            match self.next(&self.complete_script) {
                Step::Hang | Step::Panic => std::future::pending().await,
                Step::Network => Err(ApiError::CallTimeout),
                Step::Refuse(status, code, after) => Err(refusal(status, code, after)),
                Step::Ack(_) | Step::LostReply => {
                    let chunks = self
                        .accept_complete(session_id, complete)
                        .map_err(|()| refusal(409, "conflict", None))?;
                    Ok(RecordingReceipt {
                        state: if complete.manifest.incomplete {
                            RecordingState::Incomplete
                        } else {
                            RecordingState::Complete
                        },
                        chunks,
                    })
                }
            }
        })
    }
}

fn session_manifest(wire: &RecordingManifest) -> SessionManifest {
    SessionManifest {
        version: wire.version,
        session_id: wire.session_id.clone(),
        kind: match wire.kind {
            RecordingKind::Shell => SessionKind::Shell,
            RecordingKind::Exec => SessionKind::Exec,
            RecordingKind::Sftp => SessionKind::Sftp,
        },
        node: wire.node.clone(),
        user: wire.user.clone(),
        login: wire.login.clone(),
        started_at: wire.started_at,
        ended_at: wire.ended_at,
        exit_status: wire.exit_status,
        command: wire.command.clone(),
        bytes_out: wire.bytes_out,
        bytes_in: wire.bytes_in,
        input_recorded: wire.input_recorded,
        chunks: wire.chunks,
        raw_bytes: wire.raw_bytes,
        incomplete: wire.incomplete,
        dropped_chunks: wire.dropped_chunks,
        digest: wire.digest.clone(),
    }
}

pub(super) struct Bench {
    pub(super) server: Arc<FakeServer>,
    pub(super) clock: Arc<ManualClock>,
    pub(super) recordings: Recordings,
}

impl Bench {
    pub(super) fn new(limits: RecordingLimits) -> Self {
        Self::with_clocks(limits, Arc::new(|| Box::new(StepClock::default())))
    }

    pub(super) fn with_clocks(limits: RecordingLimits, cast_clocks: super::CastClocks) -> Self {
        let server = Arc::new(FakeServer::default());
        let clock = ManualClock::new(start());
        let recordings = Recordings::new(RecordingParts {
            node_id: NODE.to_owned(),
            limits,
            transport: server.clone(),
            clock: clock.clone(),
            jitter: Arc::new(|| 1.0),
            cast_clocks,
        });
        Self {
            server,
            clock,
            recordings,
        }
    }

    pub(super) fn open(&self, session_id: &str, record_input: bool) -> Box<dyn SessionObserver> {
        self.recordings
            .create(&info(session_id), &permissions(record_input))
    }

    pub(super) fn open_without_pty(&self, session_id: &str) -> Box<dyn SessionObserver> {
        let permissions = SessionPermissions {
            pty: false,
            ..permissions(false)
        };
        self.recordings.create(&info(session_id), &permissions)
    }
}

pub(super) fn limits() -> RecordingLimits {
    RecordingLimits {
        session_queue_bytes: 64 * 1024 * 1024,
        memory_budget_bytes: 256 * 1024 * 1024,
        max_uploads: 8,
    }
}

pub(super) fn info(session_id: &str) -> SessionInfo {
    SessionInfo {
        session_id: session_id.to_owned(),
        user_id: USER.to_owned(),
        login: LOGIN.to_owned(),
        client_addr: "203.0.113.5:40000".to_owned(),
    }
}

pub(super) fn permissions(record_input: bool) -> SessionPermissions {
    SessionPermissions {
        pty: true,
        port_forwarding: true,
        record_input,
        max_duration_secs: 3600,
    }
}

pub(super) fn shell(columns: u32, rows: u32) -> ChannelStart {
    ChannelStart {
        program: ChannelProgram::Shell,
        terminal: Some(Terminal {
            term: "xterm-256color".to_owned(),
            size: TerminalSize {
                columns,
                rows,
                pixel_width: 0,
                pixel_height: 0,
            },
        }),
    }
}

pub(super) fn exec_with_terminal(command: &str) -> ChannelStart {
    ChannelStart {
        program: ChannelProgram::Exec(command.as_bytes().to_vec()),
        terminal: shell(100, 30).terminal,
    }
}

pub(super) fn exec(command: &str) -> ChannelStart {
    ChannelStart {
        program: ChannelProgram::Exec(command.as_bytes().to_vec()),
        terminal: None,
    }
}

pub(super) fn out(observer: &mut dyn SessionObserver, channel: u32, data: &[u8]) {
    observer.output(channel, OutputStream::Stdout, data);
}

pub(super) struct Event {
    pub(super) kind: String,
    pub(super) data: String,
}

pub(super) struct Cast {
    pub(super) width: u64,
    pub(super) height: u64,
    pub(super) events: Vec<Event>,
}

impl Cast {
    pub(super) fn joined(&self, kind: &str) -> String {
        self.events
            .iter()
            .filter(|event| event.kind == kind)
            .map(|event| event.data.as_str())
            .collect()
    }

    pub(super) fn markers(&self) -> Vec<&str> {
        self.events
            .iter()
            .filter(|event| event.kind == "m")
            .map(|event| event.data.as_str())
            .collect()
    }
}

pub(super) fn parse_cast(bytes: &[u8]) -> Result<Cast, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not utf-8".to_owned())?;
    if !text.ends_with('\n') {
        return Err("missing trailing newline".to_owned());
    }
    let mut lines = text.split_terminator('\n');
    let header: Value =
        serde_json::from_str(lines.next().ok_or("empty")?).map_err(|e| e.to_string())?;
    let header = header.as_object().ok_or("header is not an object")?;
    let mut keys: Vec<&str> = header.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != ["env", "height", "timestamp", "version", "width"] || header["version"] != 2 {
        return Err("bad header".to_owned());
    }
    let number = |key: &str| header[key].as_u64().ok_or(format!("{key} is not a number"));
    let (width, height) = (number("width")?, number("height")?);
    number("timestamp")?;
    let env = header["env"].as_object().ok_or("env is not an object")?;
    if env.len() != 2 || !env["SHELL"].is_string() || !env["TERM"].is_string() {
        return Err("bad env".to_owned());
    }
    let mut events = Vec::new();
    let mut previous = 0.0;
    for line in lines {
        let value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let items = value.as_array().ok_or("event is not an array")?;
        let [time, kind, data] = items.as_slice() else {
            return Err("event arity".to_owned());
        };
        let time = time.as_f64().ok_or("time is not a number")?;
        if time < previous {
            return Err("time decreased".to_owned());
        }
        previous = time;
        let kind = kind.as_str().ok_or("kind is not a string")?;
        let data = data.as_str().ok_or("data is not a string")?;
        if !matches!(kind, "o" | "i" | "r" | "m") {
            return Err("unknown kind".to_owned());
        }
        events.push(Event {
            kind: kind.to_owned(),
            data: data.to_owned(),
        });
    }
    Ok(Cast {
        width,
        height,
        events,
    })
}
