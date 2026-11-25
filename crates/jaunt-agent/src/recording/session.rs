use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jaunt_record::{
    AckError, Chunk, ChunkQueue, Clock as CastClock, MAX_MARKER_BYTES, MetadataOnly, Pushed,
    RecordError, Recorder, RecorderConfig, SessionKind, SessionManifest,
};
use jaunt_ssh::{
    ChannelExit, ChannelProgram, ChannelStart, ForwardTarget, OutputStream, Recording,
    SessionObserver, Terminal, TerminalSize,
};
use std::time::SystemTime;

use tokio::sync::Notify;

use super::budget::Budget;
use crate::clock::{Clock, unix_secs};

pub(crate) const EARLY_MARKERS: usize = 64;
pub(crate) const MAX_COMMAND_BYTES: usize = MAX_MARKER_BYTES;
pub(crate) const GAP_ALLOWANCE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_WIDTH: u16 = 80;
const DEFAULT_HEIGHT: u16 = 24;
pub(crate) const MAX_TERM_BYTES: usize = 256;
const SFTP: &str = "sftp";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    Stored,
    Failed,
    Refused(&'static str),
    Disabled,
    GaveUp,
    Shutdown,
}

impl End {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            End::Stored => "stored",
            End::Failed => "recorder_failed",
            End::Refused(reason) => reason,
            End::Disabled => "recording_disabled",
            End::GaveUp => "retry_window_exceeded",
            End::Shutdown => "agent_shutdown",
        }
    }
}

struct Slot {
    recorder: Option<Recorder>,
    queue: ChunkQueue,
    last: Option<Chunk>,
    last_held: usize,
    gap: bool,
    beyond_gap: usize,
    withheld: u64,
    manifest: Option<SessionManifest>,
    finished_at: Option<SystemTime>,
    end: Option<End>,
}

pub(crate) enum Work {
    Chunk(Chunk),
    Complete(SessionManifest),
    Idle,
    Done,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) queued_chunks: usize,
    pub(crate) queued_bytes: usize,
    pub(crate) queue_dropped: u64,
    pub(crate) withheld: u64,
    pub(crate) end: Option<End>,
    pub(crate) finished: bool,
}

pub(crate) struct Shared {
    slot: Mutex<Slot>,
    budget: Arc<Budget>,
    wake: Notify,
}

impl Shared {
    pub(crate) fn new(queue_bytes: usize, budget: Arc<Budget>) -> Self {
        Self {
            slot: Mutex::new(Slot {
                recorder: None,
                queue: ChunkQueue::new(queue_bytes),
                last: None,
                last_held: 0,
                gap: false,
                beyond_gap: 0,
                withheld: 0,
                manifest: None,
                finished_at: None,
                end: None,
            }),
            budget,
            wake: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn finished_at(&self) -> Option<SystemTime> {
        self.lock().finished_at
    }

    pub(crate) fn ended(&self) -> bool {
        self.lock().end.is_some()
    }

    pub(crate) async fn woken(&self) {
        self.wake.notified().await;
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Snapshot {
        let slot = self.lock();
        Snapshot {
            queued_chunks: slot.queue.len(),
            queued_bytes: slot.queue.pending_bytes(),
            queue_dropped: slot.queue.dropped(),
            withheld: slot.withheld,
            end: slot.end,
            finished: slot.manifest.is_some(),
        }
    }

    fn absorb(&self, slot: &mut Slot, chunks: Vec<Chunk>) -> bool {
        let mut queued = false;
        for chunk in chunks {
            let size = chunk.compressed.len();
            if chunk.is_last {
                slot.last_held = if self.budget.try_reserve(size) {
                    size
                } else {
                    0
                };
                slot.last = Some(chunk);
                queued = true;
                continue;
            }
            if slot.gap && slot.beyond_gap.saturating_add(size) > GAP_ALLOWANCE_BYTES {
                slot.withheld = slot.withheld.saturating_add(1);
                continue;
            }
            if !self.budget.try_reserve(size) {
                slot.withheld = slot.withheld.saturating_add(1);
                slot.gap = true;
                continue;
            }
            match slot.queue.push(chunk) {
                Pushed::Pushed => {
                    if slot.gap {
                        slot.beyond_gap = slot.beyond_gap.saturating_add(size);
                    }
                    queued = true;
                }
                Pushed::Dropped => {
                    self.budget.release(size);
                    slot.gap = true;
                }
            }
        }
        queued
    }

    fn end_locked(&self, slot: &mut Slot, end: End) -> bool {
        if slot.end.is_some() {
            return false;
        }
        let held = slot.queue.pending_bytes().saturating_add(slot.last_held);
        slot.queue.ack(u64::MAX);
        slot.last = None;
        slot.last_held = 0;
        self.budget.release(held);
        slot.recorder = None;
        slot.manifest = None;
        slot.end = Some(end);
        true
    }

    pub(crate) fn end(&self, end: End) -> bool {
        let ended = {
            let mut slot = self.lock();
            self.end_locked(&mut slot, end)
        };
        self.wake.notify_one();
        ended
    }

    pub(crate) fn next_work(&self) -> Work {
        let slot = self.lock();
        if slot.end.is_some() {
            return Work::Done;
        }
        if let Some(head) = slot.queue.peek().or(slot.last.as_ref()) {
            return Work::Chunk(head.clone());
        }
        match &slot.manifest {
            Some(manifest) => Work::Complete(manifest.clone()),
            None => Work::Idle,
        }
    }

    pub(crate) fn acked(&self, seq: u64) -> Result<(), AckError> {
        let mut slot = self.lock();
        if slot.end.is_some() {
            return Ok(());
        }
        if slot.queue.is_empty() && slot.last.as_ref().is_some_and(|last| last.seq == seq) {
            slot.last = None;
            self.budget.release(std::mem::take(&mut slot.last_held));
            return Ok(());
        }
        let before = slot.queue.pending_bytes();
        slot.queue.ack_checked(seq)?;
        let after = slot.queue.pending_bytes();
        self.budget.release(before.saturating_sub(after));
        Ok(())
    }

    pub(crate) fn flush(&self) -> Result<(), RecordError> {
        let mut slot = self.lock();
        let Some(recorder) = slot.recorder.as_mut() else {
            return Ok(());
        };
        let flushed = catch_unwind(AssertUnwindSafe(|| {
            recorder.flush()?;
            Ok(recorder.take_chunks())
        }));
        match flushed {
            Ok(Ok(chunks)) => {
                self.absorb(&mut slot, chunks);
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(RecordError::Compress),
        }
    }
}

pub(crate) struct CastIdentity {
    pub(crate) session_id: String,
    pub(crate) node: String,
    pub(crate) user: String,
    pub(crate) login: String,
    pub(crate) started_at: u64,
    pub(crate) record_input: bool,
    pub(crate) pty_allowed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Stream {
    Stdout,
    Stderr,
    Input,
}

const STREAMS: [Stream; 3] = [Stream::Stdout, Stream::Stderr, Stream::Input];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Program {
    Cast,
    Other,
}

pub(crate) struct SessionRecorder {
    shared: Arc<Shared>,
    identity: CastIdentity,
    cast_clock: Option<Box<dyn CastClock>>,
    clock: Arc<dyn Clock>,
    channels: HashMap<u32, Program>,
    tails: HashMap<(u32, Stream), Vec<u8>>,
    early: Vec<String>,
    early_omitted: u64,
    first_command: Option<String>,
    exec_seen: bool,
    sftp_seen: bool,
    other_out: u64,
    other_in: u64,
    last_exit: Option<i32>,
}

impl SessionRecorder {
    pub(crate) fn new(
        shared: Arc<Shared>,
        identity: CastIdentity,
        cast_clock: Box<dyn CastClock>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            shared,
            identity,
            cast_clock: Some(cast_clock),
            clock,
            channels: HashMap::new(),
            tails: HashMap::new(),
            early: Vec::new(),
            early_omitted: 0,
            first_command: None,
            exec_seen: false,
            sftp_seen: false,
            other_out: 0,
            other_in: 0,
            last_exit: None,
        }
    }

    fn guarded(
        &mut self,
        work: impl FnOnce(&mut Self, &mut Option<Recorder>) -> Result<(), RecordError>,
    ) {
        let shared = Arc::clone(&self.shared);
        let mut slot = shared.lock();
        if slot.end.is_some() || slot.manifest.is_some() {
            return;
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            work(self, &mut slot.recorder)?;
            Ok::<_, RecordError>(slot.recorder.as_mut().map(Recorder::take_chunks))
        }));
        let (wake, failed) = match outcome {
            Ok(Ok(Some(chunks))) => (shared.absorb(&mut slot, chunks), false),
            Ok(Ok(None)) => (false, false),
            Ok(Err(_)) | Err(_) => (true, shared.end_locked(&mut slot, End::Failed)),
        };
        drop(slot);
        if failed {
            dropped(&self.identity.session_id, End::Failed);
        }
        if wake {
            shared.wake.notify_one();
        }
    }

    fn marker(&mut self, recorder: &mut Option<Recorder>, text: String) -> Result<(), RecordError> {
        let text = bounded(text, MAX_MARKER_BYTES);
        match recorder {
            Some(recorder) => recorder.marker(&text),
            None if self.early.len() < EARLY_MARKERS => {
                self.early.push(text);
                Ok(())
            }
            None => {
                self.early_omitted = self.early_omitted.saturating_add(1);
                Ok(())
            }
        }
    }

    fn open_cast(
        &mut self,
        recorder: &mut Option<Recorder>,
        terminal: Option<&Terminal>,
    ) -> Result<(), RecordError> {
        if recorder.is_some() {
            return Ok(());
        }
        let Some(clock) = self.cast_clock.take() else {
            return Err(RecordError::Finished);
        };
        let (width, height, term) = match terminal {
            Some(terminal) => (
                dimension(terminal.size.columns, DEFAULT_WIDTH),
                dimension(terminal.size.rows, DEFAULT_HEIGHT),
                bounded(terminal.term.clone(), MAX_TERM_BYTES),
            ),
            None => (DEFAULT_WIDTH, DEFAULT_HEIGHT, String::new()),
        };
        let config = RecorderConfig {
            session_id: self.identity.session_id.clone(),
            kind: SessionKind::Shell,
            node: self.identity.node.clone(),
            user: self.identity.user.clone(),
            login: self.identity.login.clone(),
            command: None,
            started_at: self.identity.started_at,
            width,
            height,
            shell: String::new(),
            term,
            record_input: self.identity.record_input,
        };
        let mut opened = Recorder::new(config, clock)?;
        for text in self.early.drain(..) {
            opened.marker(&text)?;
        }
        if self.early_omitted > 0 {
            opened.marker(&format!("{} earlier markers omitted", self.early_omitted))?;
        }
        *recorder = Some(opened);
        Ok(())
    }

    fn push(
        &mut self,
        recorder: &mut Recorder,
        channel: u32,
        stream: Stream,
        data: &[u8],
    ) -> Result<(), RecordError> {
        let key = (channel, stream);
        let Some(mut pending) = self.tails.remove(&key) else {
            let complete = complete_prefix(data);
            if complete < data.len() {
                self.tails.insert(key, data[complete..].to_vec());
            }
            return deliver(recorder, stream, &data[..complete]);
        };
        pending.extend_from_slice(data);
        let complete = complete_prefix(&pending);
        let rest = pending.split_off(complete);
        if !rest.is_empty() {
            self.tails.insert(key, rest);
        }
        deliver(recorder, stream, &pending)
    }

    fn flush_tails(&mut self, recorder: &mut Recorder, channel: u32) -> Result<(), RecordError> {
        for stream in STREAMS {
            if let Some(tail) = self.tails.remove(&(channel, stream)) {
                let text = String::from_utf8_lossy(&tail).into_owned();
                deliver(recorder, stream, text.as_bytes())?;
            }
        }
        Ok(())
    }

    fn conclude(&mut self, slot: &mut Slot, ended_at: u64) -> Result<Recording, RecordError> {
        if slot.end.is_some() {
            return Ok(Recording::Incomplete);
        }
        let mut manifest = match slot.recorder.take() {
            Some(mut recorder) => {
                let open: Vec<u32> = self.tails.keys().map(|(channel, _)| *channel).collect();
                for channel in open {
                    self.flush_tails(&mut recorder, channel)?;
                }
                let manifest = recorder.finish(self.last_exit, ended_at)?;
                let chunks = recorder.take_chunks();
                self.shared.absorb(slot, chunks);
                manifest
            }
            None => {
                let kind = if self.exec_seen || !self.sftp_seen {
                    SessionKind::Exec
                } else {
                    SessionKind::Sftp
                };
                Recorder::metadata_only(MetadataOnly {
                    session_id: self.identity.session_id.clone(),
                    kind,
                    node: self.identity.node.clone(),
                    user: self.identity.user.clone(),
                    login: self.identity.login.clone(),
                    command: if kind == SessionKind::Exec {
                        self.first_command.clone()
                    } else {
                        None
                    },
                    started_at: self.identity.started_at,
                    ended_at: Some(ended_at),
                    exit_status: self.last_exit,
                    bytes_out: self.other_out,
                    bytes_in: self.other_in,
                })?
            }
        };
        slot.queue.mark_manifest(&mut manifest);
        manifest.dropped_chunks = manifest.dropped_chunks.saturating_add(slot.withheld);
        manifest.incomplete = manifest.incomplete || slot.withheld > 0;
        let recording = if manifest.incomplete {
            Recording::Incomplete
        } else {
            Recording::Complete
        };
        slot.manifest = Some(manifest);
        Ok(recording)
    }
}

impl SessionObserver for SessionRecorder {
    fn channel_start(&mut self, channel: u32, start: &ChannelStart) {
        self.guarded(|this, recorder| {
            let casts = this.identity.pty_allowed
                && (start.terminal.is_some() || start.program == ChannelProgram::Shell);
            let text = match &start.program {
                ChannelProgram::Shell => format!("channel {channel} shell start"),
                ChannelProgram::Exec(command) => {
                    this.exec_seen = true;
                    let text = bounded(
                        String::from_utf8_lossy(command).into_owned(),
                        MAX_COMMAND_BYTES,
                    );
                    let marker = format!("channel {channel} exec {text}");
                    if this.first_command.is_none() {
                        this.first_command = Some(text);
                    }
                    marker
                }
                ChannelProgram::Subsystem(name) => {
                    this.sftp_seen |= name == SFTP;
                    format!("channel {channel} subsystem {name}")
                }
            };
            if casts {
                this.channels.insert(channel, Program::Cast);
                this.open_cast(recorder, start.terminal.as_ref())?;
            } else {
                this.channels.insert(channel, Program::Other);
            }
            this.marker(recorder, text)
        });
    }

    fn input(&mut self, channel: u32, data: &[u8]) {
        self.guarded(|this, recorder| {
            match (this.channels.get(&channel), recorder.as_mut()) {
                (Some(Program::Cast), Some(recorder)) => {
                    this.push(recorder, channel, Stream::Input, data)?;
                }
                _ => this.other_in = this.other_in.saturating_add(widen(data.len())),
            }
            Ok(())
        });
    }

    fn output(&mut self, channel: u32, stream: OutputStream, data: &[u8]) {
        let stream = match stream {
            OutputStream::Stdout => Stream::Stdout,
            OutputStream::Stderr => Stream::Stderr,
        };
        self.guarded(|this, recorder| {
            match (this.channels.get(&channel), recorder.as_mut()) {
                (Some(Program::Cast), Some(recorder)) => {
                    this.push(recorder, channel, stream, data)?
                }
                _ => this.other_out = this.other_out.saturating_add(widen(data.len())),
            }
            Ok(())
        });
    }

    fn resize(&mut self, channel: u32, size: TerminalSize) {
        self.guarded(
            |this, recorder| match (this.channels.get(&channel), recorder.as_mut()) {
                (Some(Program::Cast), Some(recorder)) => recorder.resize(
                    dimension(size.columns, DEFAULT_WIDTH),
                    dimension(size.rows, DEFAULT_HEIGHT),
                ),
                _ => Ok(()),
            },
        );
    }

    fn channel_end(&mut self, channel: u32, exit: &ChannelExit) {
        self.guarded(|this, recorder| {
            if this.channels.remove(&channel).is_none() {
                return Ok(());
            }
            if let Some(recorder) = recorder.as_mut() {
                this.flush_tails(recorder, channel)?;
            }
            let text = match exit {
                ChannelExit::Status(code) => {
                    this.last_exit = i32::try_from(*code).ok();
                    format!("channel {channel} exit {code}")
                }
                ChannelExit::Signal(name) => {
                    this.last_exit = None;
                    format!("channel {channel} signal {name}")
                }
                ChannelExit::Unknown => {
                    this.last_exit = None;
                    format!("channel {channel} closed")
                }
            };
            this.marker(recorder, text)
        });
    }

    fn forward_open(&mut self, channel: u32, target: &ForwardTarget) {
        self.guarded(|this, recorder| {
            this.marker(
                recorder,
                format!("channel {channel} forward {}:{}", target.host, target.port),
            )
        });
    }

    fn forward_close(&mut self, channel: u32) {
        self.guarded(|this, recorder| {
            this.marker(recorder, format!("channel {channel} forward closed"))
        });
    }

    fn finish(&mut self) -> Recording {
        let shared = Arc::clone(&self.shared);
        let now = self.clock.now();
        let ended_at = u64::try_from(unix_secs(now)).unwrap_or(0);
        let mut slot = shared.lock();
        slot.finished_at = Some(now);
        let outcome = catch_unwind(AssertUnwindSafe(|| self.conclude(&mut slot, ended_at)));
        let (recording, failed) = match outcome {
            Ok(Ok(recording)) => (recording, false),
            Ok(Err(_)) | Err(_) => (
                Recording::Incomplete,
                shared.end_locked(&mut slot, End::Failed),
            ),
        };
        drop(slot);
        if failed {
            dropped(&self.identity.session_id, End::Failed);
        }
        shared.wake.notify_one();
        recording
    }
}

pub(crate) struct Discard;

impl SessionObserver for Discard {
    fn finish(&mut self) -> Recording {
        Recording::Incomplete
    }
}

pub(crate) fn dropped(session_id: &str, end: End) {
    tracing::warn!(
        target: "jaunt::audit",
        event = "agent.ssh.recording_dropped",
        session_id,
        reason = end.reason(),
        "the recording of this session was dropped"
    );
}

fn dimension(value: u32, default: u16) -> u16 {
    match u16::try_from(value) {
        Ok(0) => default,
        Ok(value) => value,
        Err(_) => u16::MAX,
    }
}

fn widen(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) fn bounded(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        let mut cut = limit;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text
}

fn deliver(recorder: &mut Recorder, stream: Stream, data: &[u8]) -> Result<(), RecordError> {
    if data.is_empty() {
        return Ok(());
    }
    match stream {
        Stream::Stdout | Stream::Stderr => recorder.push_output(data),
        Stream::Input => recorder.push_input(data).map(|_| ()),
    }
}

pub(crate) fn complete_prefix(bytes: &[u8]) -> usize {
    let len = bytes.len();
    for back in 1..=len.min(3) {
        let start = len - back;
        let byte = bytes[start];
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        let needed = match byte {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return len,
        };
        return if back < needed { start } else { len };
    }
    len
}
