use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::{Bytes, BytesMut};
use russh::ChannelId;
use russh::server::Handle;
use tokio::sync::Notify;

const MAX_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum IntakeError {
    #[error("the client sent more channel data than its window allows")]
    WindowOverrun,
    #[error("the client sent channel data after EOF or close")]
    DataAfterEof,
    #[error("the SSH session ended")]
    SessionGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the SSH session ended")]
pub(crate) struct SessionGone;

pub(crate) trait WindowGrant: Send + Sync + 'static {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone>;
}

pub(crate) struct ChannelGrant {
    handle: Handle,
    channel: ChannelId,
}

impl ChannelGrant {
    pub(crate) fn new(handle: Handle, channel: ChannelId) -> Self {
        Self { handle, channel }
    }
}

impl WindowGrant for ChannelGrant {
    fn grant(&self, bytes: u32) -> Result<(), SessionGone> {
        self.handle
            .grant_window(self.channel, bytes)
            .map_err(|_| SessionGone)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IntakeEvent {
    Data(Bytes),
    Eof,
    Close,
}

struct State {
    buffer: BytesMut,
    unreleased: u32,
    eof: bool,
    close: bool,
    writer_gone: bool,
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
}

pub(crate) struct ChannelIntake {
    shared: Arc<Shared>,
}

pub(crate) struct IntakeReader {
    shared: Arc<Shared>,
    batch: u32,
    delivered: u32,
    pending_grant: u32,
    eof_delivered: bool,
    finished: bool,
}

impl ChannelIntake {
    pub(crate) fn new<G: WindowGrant>(window: u32, grants: G) -> (Self, IntakeReader) {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                buffer: BytesMut::new(),
                unreleased: 0,
                eof: false,
                close: false,
                writer_gone: false,
            }),
            ready: Notify::new(),
            grants: Box::new(grants),
            window,
        });
        let reader = IntakeReader {
            shared: Arc::clone(&shared),
            batch: (window / 4).max(1),
            delivered: 0,
            pending_grant: 0,
            eof_delivered: false,
            finished: false,
        };
        (Self { shared }, reader)
    }

    pub(crate) fn push_data(&self, data: &[u8]) -> Result<(), IntakeError> {
        let mut state = self.shared.state();
        if state.eof || state.close {
            return Err(IntakeError::DataAfterEof);
        }
        if data.is_empty() {
            return Ok(());
        }
        state.unreleased = self.admit(state.unreleased, data.len())?;
        state.buffer.extend_from_slice(data);
        drop(state);
        self.shared.ready.notify_one();
        Ok(())
    }

    pub(crate) fn consume_extended(&self, len: usize) -> Result<(), IntakeError> {
        let state = self.shared.state();
        self.admit(state.unreleased, len)?;
        drop(state);
        match u32::try_from(len) {
            Ok(0) => Ok(()),
            Ok(bytes) => self
                .shared
                .grants
                .grant(bytes)
                .map_err(|SessionGone| IntakeError::SessionGone),
            Err(_) => Err(IntakeError::WindowOverrun),
        }
    }

    pub(crate) fn push_eof(&self) {
        self.shared.state().eof = true;
        self.shared.ready.notify_one();
    }

    pub(crate) fn push_close(&self) {
        self.shared.state().close = true;
        self.shared.ready.notify_one();
    }

    fn admit(&self, unreleased: u32, len: usize) -> Result<u32, IntakeError> {
        u32::try_from(len)
            .ok()
            .and_then(|len| unreleased.checked_add(len))
            .filter(|total| *total <= self.shared.window)
            .ok_or(IntakeError::WindowOverrun)
    }
}

impl Drop for ChannelIntake {
    fn drop(&mut self) {
        self.shared.state().writer_gone = true;
        self.shared.ready.notify_one();
    }
}

impl IntakeReader {
    pub(crate) async fn next(&mut self) -> Option<IntakeEvent> {
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
        self.delivered = self.delivered.saturating_sub(len);
        self.pending_grant = self.pending_grant.saturating_add(len);
        if self.pending_grant >= self.batch {
            self.flush_grant()?;
        }
        Ok(())
    }

    fn take_ready(&mut self) -> Option<IntakeEvent> {
        let mut state = self.shared.state();
        if !state.buffer.is_empty() {
            let take = state.buffer.len().min(MAX_CHUNK);
            let chunk = state.buffer.split_to(take);
            let len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
            self.delivered = self.delivered.saturating_add(len);
            return Some(IntakeEvent::Data(chunk.freeze()));
        }
        if state.eof && !self.eof_delivered {
            self.eof_delivered = true;
            return Some(IntakeEvent::Eof);
        }
        if state.close {
            self.finished = true;
            return Some(IntakeEvent::Close);
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
    fn buffered_capacity(&self) -> usize {
        self.shared.state().buffer.capacity()
    }
}

#[cfg(test)]
mod tests;
