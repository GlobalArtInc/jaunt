use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use bytes::Bytes;
use russh::client::Handle;
use russh::{ChannelId, Sig};
use tokio::sync::Notify;

use crate::inner::InnerClient;
use crate::intake::{SessionGone, WindowGrant};
use crate::observer::OutputStream;

const MAX_CHUNK: u64 = 64 * 1024;
const WORD_BITS: usize = u64::BITS as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum OutputError {
    #[error("sshd sent more channel data than its window allows")]
    WindowOverrun,
    #[error("sshd sent channel data after closing the channel")]
    DataAfterClose,
    #[error("the inner SSH session ended")]
    SessionGone,
}

pub(crate) struct InnerGrant {
    handle: Weak<Handle<InnerClient>>,
    channel: ChannelId,
}

impl InnerGrant {
    pub(crate) fn new(handle: &Arc<Handle<InnerClient>>, channel: ChannelId) -> Self {
        Self {
            handle: Arc::downgrade(handle),
            channel,
        }
    }
}

impl WindowGrant for InnerGrant {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone> {
        let handle = self.handle.upgrade().ok_or(SessionGone)?;
        handle
            .grant_window(self.channel, bytes)
            .map_err(|_| SessionGone)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ExitSignal {
    pub(crate) name: Sig,
    pub(crate) core_dumped: bool,
    pub(crate) message: String,
    pub(crate) lang: String,
}

#[derive(Debug, Clone)]
pub(crate) enum OutputEvent {
    Stdout(Bytes),
    Stderr(Bytes),
    Eof,
    ExitStatus(u32),
    ExitSignal(ExitSignal),
    Close,
    Gone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Close,
    Gone,
}

struct Ring {
    bytes: Box<[u8]>,
    tags: Box<[u64]>,
    head: usize,
    len: usize,
}

impl Ring {
    fn new(window: u32) -> Self {
        let capacity = (window as usize).max(1);
        Self {
            bytes: vec![0; capacity].into_boxed_slice(),
            tags: vec![0; capacity.div_ceil(WORD_BITS)].into_boxed_slice(),
            head: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn push(&mut self, data: &[u8], stderr: bool) -> Option<()> {
        let capacity = self.capacity();
        if data.len() > capacity - self.len {
            return None;
        }
        let tail = (self.head + self.len) % capacity;
        let (first, second) = data.split_at_checked((capacity - tail).min(data.len()))?;
        self.write(tail, first, stderr)?;
        self.write(0, second, stderr)?;
        self.len += data.len();
        Some(())
    }

    fn write(&mut self, at: usize, data: &[u8], stderr: bool) -> Option<()> {
        let end = at.checked_add(data.len())?;
        self.bytes.get_mut(at..end)?.copy_from_slice(data);
        let mut position = at;
        while position < end {
            let bit = position % WORD_BITS;
            let span = (WORD_BITS - bit).min(end - position);
            let mask = if span == WORD_BITS {
                u64::MAX
            } else {
                ((1u64 << span) - 1) << bit
            };
            let word = self.tags.get_mut(position / WORD_BITS)?;
            if stderr {
                *word |= mask;
            } else {
                *word &= !mask;
            }
            position += span;
        }
        Some(())
    }

    fn run(&self, limit: usize) -> (bool, usize) {
        let limit = limit.min(self.len);
        let stderr = self
            .tags
            .get(self.head / WORD_BITS)
            .is_some_and(|word| (word >> (self.head % WORD_BITS)) & 1 == 1);
        if limit == 0 {
            return (stderr, 0);
        }
        let first_end = (self.head + limit).min(self.capacity());
        let first = self.scan(self.head, first_end, stderr);
        if self.head + first < first_end {
            return (stderr, first);
        }
        (stderr, first + self.scan(0, limit - first, stderr))
    }

    fn scan(&self, from: usize, to: usize, stderr: bool) -> usize {
        let mut position = from;
        while position < to {
            let Some(word) = self.tags.get(position / WORD_BITS) else {
                break;
            };
            let bit = position % WORD_BITS;
            let differing = if stderr { !word } else { *word } >> bit;
            if differing == 0 {
                position += WORD_BITS - bit;
            } else {
                position += differing.trailing_zeros() as usize;
                break;
            }
        }
        position.min(to) - from
    }

    fn take(&mut self, len: usize) -> Option<Bytes> {
        let len = len.min(self.len);
        let capacity = self.capacity();
        let first = len.min(capacity - self.head);
        let mut chunk = Vec::with_capacity(len);
        chunk.extend_from_slice(self.bytes.get(self.head..self.head + first)?);
        chunk.extend_from_slice(self.bytes.get(..len - first)?);
        self.head = (self.head + len) % capacity;
        self.len -= len;
        Some(Bytes::from(chunk))
    }
}

struct State {
    ring: Ring,
    start: u64,
    received: u64,
    unreleased: u32,
    eof: Option<u64>,
    eof_seen: bool,
    exit: Option<(u64, OutputEvent)>,
    exit_seen: bool,
    end: Option<(u64, End)>,
    writer_gone: bool,
}

impl State {
    fn next_marker_after(&self, position: u64) -> Option<u64> {
        [
            self.eof,
            self.exit.as_ref().map(|(at, _)| *at),
            self.end.map(|(at, _)| at),
        ]
        .into_iter()
        .flatten()
        .filter(|at| *at > position)
        .min()
    }
}

struct Shared {
    state: Mutex<State>,
    ready: Notify,
    grants: Box<dyn WindowGrant>,
    window: u32,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn admit(&self, unreleased: u32, len: usize) -> Result<u32, OutputError> {
        u32::try_from(len)
            .ok()
            .and_then(|len| unreleased.checked_add(len))
            .filter(|total| *total <= self.window)
            .ok_or(OutputError::WindowOverrun)
    }
}

pub(crate) struct OutputQueue {
    shared: Arc<Shared>,
}

pub(crate) struct OutputReader {
    shared: Arc<Shared>,
    batch: u32,
    delivered: u32,
    pending_grant: u32,
    finished: bool,
}

impl OutputQueue {
    pub(crate) fn new<G: WindowGrant>(window: u32, grants: G) -> (Self, OutputReader) {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                ring: Ring::new(window),
                start: 0,
                received: 0,
                unreleased: 0,
                eof: None,
                eof_seen: false,
                exit: None,
                exit_seen: false,
                end: None,
                writer_gone: false,
            }),
            ready: Notify::new(),
            grants: Box::new(grants),
            window,
        });
        let reader = OutputReader {
            shared: Arc::clone(&shared),
            batch: (window / 4).max(1),
            delivered: 0,
            pending_grant: 0,
            finished: false,
        };
        (Self { shared }, reader)
    }

    pub(crate) fn push_data(&self, stream: OutputStream, data: &[u8]) -> Result<(), OutputError> {
        let mut state = self.shared.state();
        if state.end.is_some() {
            return Err(OutputError::DataAfterClose);
        }
        if data.is_empty() {
            return Ok(());
        }
        let unreleased = self.shared.admit(state.unreleased, data.len())?;
        state
            .ring
            .push(data, stream == OutputStream::Stderr)
            .ok_or(OutputError::WindowOverrun)?;
        state.unreleased = unreleased;
        state.received += data.len() as u64;
        drop(state);
        self.shared.ready.notify_one();
        Ok(())
    }

    pub(crate) fn discard_extended(&self, len: usize) -> Result<(), OutputError> {
        let state = self.shared.state();
        if state.end.is_some() {
            return Err(OutputError::DataAfterClose);
        }
        self.shared.admit(state.unreleased, len)?;
        drop(state);
        match u32::try_from(len) {
            Ok(0) => Ok(()),
            Ok(bytes) => self
                .shared
                .grants
                .grant(bytes)
                .map_err(|SessionGone| OutputError::SessionGone),
            Err(_) => Err(OutputError::WindowOverrun),
        }
    }

    pub(crate) fn push_eof(&self) {
        let mut state = self.shared.state();
        if state.eof_seen || state.end.is_some() {
            return;
        }
        state.eof_seen = true;
        state.eof = Some(state.received);
        drop(state);
        self.shared.ready.notify_one();
    }

    pub(crate) fn push_exit_status(&self, status: u32) {
        self.push_exit(OutputEvent::ExitStatus(status));
    }

    pub(crate) fn push_exit_signal(&self, signal: ExitSignal) {
        self.push_exit(OutputEvent::ExitSignal(signal));
    }

    pub(crate) fn push_close(&self) {
        self.push_end(End::Close);
    }

    pub(crate) fn push_gone(&self) {
        self.push_end(End::Gone);
    }

    fn push_exit(&self, event: OutputEvent) {
        let mut state = self.shared.state();
        if state.exit_seen || state.end.is_some() {
            return;
        }
        state.exit_seen = true;
        state.exit = Some((state.received, event));
        drop(state);
        self.shared.ready.notify_one();
    }

    fn push_end(&self, end: End) {
        let mut state = self.shared.state();
        if state.end.is_some() {
            return;
        }
        state.end = Some((state.received, end));
        drop(state);
        self.shared.ready.notify_one();
    }
}

impl Drop for OutputQueue {
    fn drop(&mut self) {
        self.shared.state().writer_gone = true;
        self.shared.ready.notify_one();
    }
}

impl OutputReader {
    pub(crate) async fn next(&mut self) -> Option<OutputEvent> {
        loop {
            if self.finished {
                return None;
            }
            if let Some(event) = self.take_ready() {
                return Some(event);
            }
            if self.finished {
                return None;
            }
            if self.flush_grant().is_err() {
                self.finished = true;
                return None;
            }
            self.shared.ready.notified().await;
        }
    }

    pub(crate) fn consumed(&mut self, len: usize) -> Result<(), SessionGone> {
        let len = u32::try_from(len).unwrap_or(u32::MAX).min(self.delivered);
        self.delivered -= len;
        self.pending_grant = self.pending_grant.saturating_add(len);
        if self.pending_grant >= self.batch {
            self.flush_grant()?;
        }
        Ok(())
    }

    fn take_ready(&mut self) -> Option<OutputEvent> {
        let mut state = self.shared.state();
        let start = state.start;
        if state.eof.is_some_and(|at| at <= start) {
            state.eof = None;
            return Some(OutputEvent::Eof);
        }
        if state.exit.as_ref().is_some_and(|(at, _)| *at <= start) {
            return state.exit.take().map(|(_, event)| event);
        }
        if let Some((at, end)) = state.end
            && at <= start
        {
            self.finished = true;
            return Some(match end {
                End::Close => OutputEvent::Close,
                End::Gone => OutputEvent::Gone,
            });
        }
        if state.received > start {
            let limit = [Some(start + MAX_CHUNK), state.next_marker_after(start)]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(start);
            let (stderr, len) = state.ring.run(usize::try_from(limit - start).unwrap_or(0));
            if len > 0
                && let Some(chunk) = state.ring.take(len)
            {
                state.start = start + len as u64;
                self.delivered = self
                    .delivered
                    .saturating_add(u32::try_from(len).unwrap_or(u32::MAX));
                return Some(if stderr {
                    OutputEvent::Stderr(chunk)
                } else {
                    OutputEvent::Stdout(chunk)
                });
            }
        }
        if state.writer_gone {
            self.finished = true;
        }
        None
    }

    fn flush_grant(&mut self) -> Result<(), SessionGone> {
        if self.pending_grant == 0 {
            return Ok(());
        }
        let bytes = self.pending_grant;
        self.pending_grant = 0;
        {
            let mut state = self.shared.state();
            state.unreleased = state.unreleased.saturating_sub(bytes);
        }
        self.shared.grants.grant(bytes)
    }

    #[cfg(test)]
    fn footprint(&self) -> (usize, usize) {
        let state = self.shared.state();
        (state.ring.bytes.len(), state.ring.tags.len())
    }
}

#[cfg(test)]
mod tests;
