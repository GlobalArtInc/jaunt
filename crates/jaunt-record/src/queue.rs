use std::collections::VecDeque;

use crate::chunk::Chunk;
use crate::error::AckError;
use crate::manifest::SessionManifest;

pub const DEFAULT_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    Pushed,
    Dropped,
}

#[derive(Debug)]
pub struct ChunkQueue {
    max_bytes: usize,
    items: VecDeque<Chunk>,
    pending_bytes: usize,
    dropped: u64,
    highest_admitted: Option<u64>,
}

impl ChunkQueue {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            items: VecDeque::new(),
            pending_bytes: 0,
            dropped: 0,
            highest_admitted: None,
        }
    }

    pub fn push(&mut self, chunk: Chunk) -> Pushed {
        let size = chunk.compressed.len();
        if self.pending_bytes.saturating_add(size) > self.max_bytes {
            self.dropped = self.dropped.saturating_add(1);
            return Pushed::Dropped;
        }
        self.pending_bytes += size;
        self.highest_admitted = Some(
            self.highest_admitted
                .map_or(chunk.seq, |highest| highest.max(chunk.seq)),
        );
        self.items.push_back(chunk);
        Pushed::Pushed
    }

    pub fn peek(&self) -> Option<&Chunk> {
        self.items.front()
    }

    pub fn ack(&mut self, seq: u64) -> usize {
        let mut removed = 0;
        while self.items.front().is_some_and(|chunk| chunk.seq <= seq) {
            if let Some(chunk) = self.items.pop_front() {
                self.pending_bytes -= chunk.compressed.len();
                removed += 1;
            }
        }
        removed
    }

    pub fn ack_checked(&mut self, seq: u64) -> Result<usize, AckError> {
        if self.highest_admitted.is_none_or(|highest| seq > highest) {
            return Err(AckError::AboveHighest { seq });
        }
        Ok(self.ack(seq))
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn pending_bytes(&self) -> usize {
        self.pending_bytes
    }

    pub fn incomplete(&self) -> bool {
        self.dropped > 0
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn mark_manifest(&self, manifest: &mut SessionManifest) {
        manifest.incomplete = manifest.incomplete || self.incomplete();
        manifest.dropped_chunks = self.dropped;
    }
}

impl Default for ChunkQueue {
    fn default() -> Self {
        Self::new(DEFAULT_QUEUE_MAX_BYTES)
    }
}
