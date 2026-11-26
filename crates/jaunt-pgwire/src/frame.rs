use std::fmt;

use bytes::{Bytes, BytesMut};

use crate::error::DecodeError;

#[derive(Clone, PartialEq, Eq)]
pub struct Frame<M> {
    message: M,
    raw: Bytes,
    remaining: usize,
}

impl<M> Frame<M> {
    pub(crate) fn new(message: M, raw: Bytes, remaining: usize) -> Self {
        Self {
            message,
            raw,
            remaining,
        }
    }

    pub fn message(&self) -> &M {
        &self.message
    }

    pub fn into_message(self) -> M {
        self.message
    }

    pub fn raw(&self) -> &Bytes {
        &self.raw
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

impl<M: fmt::Debug> fmt::Debug for Frame<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("message", &self.message)
            .field("raw_length", &self.raw.len())
            .field("remaining", &self.remaining)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Chunk(Bytes);

impl Chunk {
    pub fn bytes(&self) -> &Bytes {
        &self.0
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event<M> {
    Frame(Frame<M>),
    Continuation(Chunk),
}

pub(crate) struct Stream {
    buffer: BytesMut,
    remaining: usize,
    poisoned: bool,
    max_pending: usize,
}

impl Stream {
    pub(crate) fn new(max_pending: usize) -> Self {
        Self {
            buffer: BytesMut::new(),
            remaining: 0,
            poisoned: false,
            max_pending,
        }
    }

    pub(crate) fn push(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        if self.poisoned {
            return Err(DecodeError::Poisoned);
        }
        let length = self.buffer.len().saturating_add(input.len());
        if length > self.max_pending {
            self.poison();
            return Err(DecodeError::PendingTooLarge {
                length,
                limit: self.max_pending,
            });
        }
        self.buffer.extend_from_slice(input);
        Ok(())
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
        self.buffer = BytesMut::new();
        self.remaining = 0;
    }

    pub(crate) fn pending(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn buffered(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn in_continuation(&self) -> bool {
        self.remaining > 0
    }

    pub(crate) fn continuation(&mut self) -> Option<Chunk> {
        if self.remaining == 0 || self.buffer.is_empty() {
            return None;
        }
        let count = self.remaining.min(self.buffer.len());
        self.remaining -= count;
        Some(Chunk(self.buffer.split_to(count).freeze()))
    }

    pub(crate) fn split(&mut self, count: usize, remaining: usize) -> Bytes {
        self.remaining = remaining;
        self.buffer.split_to(count).freeze()
    }
}
