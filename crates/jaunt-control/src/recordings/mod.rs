mod audit;
mod flow;
mod handlers;
mod uploads;

use std::sync::Arc;
use std::time::Duration;

use jaunt_audit::RecordingSink;
use jaunt_record::Limits;

use crate::control::Control;

pub use flow::RecoveredRecordings;
pub(crate) use flow::{recover, sweep};
pub(crate) use handlers::{chunk, complete};
pub use uploads::PENDING_CHUNK_OVERHEAD;
pub(crate) use uploads::{RejectionLog, Uploads};

pub const DEFAULT_SESSION_PENDING_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_UPLOADS_PER_NODE: usize = 64;
pub const DEFAULT_MAX_UPLOADS_TOTAL: usize = 1024;
pub const DEFAULT_PENDING_BYTES_PER_NODE: u64 = 256 * 1024 * 1024;
pub const DEFAULT_PENDING_BYTES_TOTAL: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
pub const DEFAULT_MAX_CHUNKS: u64 = 200_000;
pub const DEFAULT_STORE_RETRY: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_MAX_STORE_COMMITS: usize = 8;
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(24 * 60 * 60);
pub const LATE_UPLOAD_SECS: i64 = 24 * 60 * 60;
pub const MAX_COMPLETE_BODY_BYTES: usize = 64 * 1024;
pub const CHUNK_ENVELOPE_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordingLimits {
    pub chunk: Limits,
    pub max_uploads_per_node: usize,
    pub max_uploads_total: usize,
    pub max_pending_bytes_per_node: u64,
    pub max_pending_bytes_total: u64,
    pub idle_timeout: Duration,
    pub store_retry: Duration,
    pub max_store_commits: usize,
    pub max_wait: Duration,
}

impl Default for RecordingLimits {
    fn default() -> RecordingLimits {
        RecordingLimits {
            chunk: Limits {
                max_pending_bytes: DEFAULT_SESSION_PENDING_BYTES,
                max_chunks: DEFAULT_MAX_CHUNKS,
                ..Limits::default()
            },
            max_uploads_per_node: DEFAULT_MAX_UPLOADS_PER_NODE,
            max_uploads_total: DEFAULT_MAX_UPLOADS_TOTAL,
            max_pending_bytes_per_node: DEFAULT_PENDING_BYTES_PER_NODE,
            max_pending_bytes_total: DEFAULT_PENDING_BYTES_TOTAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            store_retry: DEFAULT_STORE_RETRY,
            max_store_commits: DEFAULT_MAX_STORE_COMMITS,
            max_wait: DEFAULT_MAX_WAIT,
        }
    }
}

impl RecordingLimits {
    pub fn is_usable(&self) -> bool {
        self.chunk.max_chunk_compressed > 0
            && self.chunk.max_chunk_raw > 0
            && self.chunk.max_chunks > 0
            && self.chunk.max_total_raw > 0
            && self.chunk.max_pending_bytes > 0
            && self.max_uploads_per_node > 0
            && self.max_uploads_total > 0
            && self.max_pending_bytes_per_node > 0
            && self.max_pending_bytes_total > 0
            && !self.idle_timeout.is_zero()
            && !self.store_retry.is_zero()
            && self.max_store_commits > 0
            && self.max_wait >= self.store_retry
    }

    pub fn chunk_body_limit(&self) -> usize {
        chunk_body_limit(self.chunk.max_chunk_compressed)
    }
}

pub fn chunk_body_limit(max_chunk_compressed: usize) -> usize {
    max_chunk_compressed
        .div_ceil(3)
        .saturating_mul(4)
        .saturating_add(CHUNK_ENVELOPE_BYTES)
}

#[derive(Clone)]
pub struct RecordingSettings {
    pub sink: Arc<dyn RecordingSink>,
    pub limits: RecordingLimits,
}

impl std::fmt::Debug for RecordingSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingSettings")
            .field("limits", &self.limits)
            .finish()
    }
}

pub(crate) async fn reconcile_after_end(
    control: &Control,
    session_id: &str,
    node_id: &str,
    session_incomplete: bool,
) {
    flow::reconcile(control, session_id, node_id, session_incomplete).await;
}

pub(crate) fn chunk_route_limit(control: &Control) -> usize {
    control
        .recordings
        .as_ref()
        .map_or_else(RecordingLimits::default, Uploads::limits)
        .chunk_body_limit()
}

impl Control {
    pub fn recordings_given_up(&self) -> u64 {
        self.recordings.as_ref().map_or(0, Uploads::given_up)
    }

    pub fn recordings_retries(&self) -> u64 {
        self.recordings.as_ref().map_or(0, Uploads::retries)
    }

    pub fn recordings_conflicted_ids(&self, limit: usize) -> Vec<String> {
        self.recordings
            .as_ref()
            .map_or_else(Vec::new, |uploads| uploads.conflicted_ids(limit))
    }

    pub fn recordings_held_ids(&self, limit: usize) -> Vec<String> {
        self.recordings
            .as_ref()
            .map_or_else(Vec::new, |uploads| uploads.held_ids(limit))
    }

    pub fn recordings_conflicts(&self) -> u64 {
        self.recordings.as_ref().map_or(0, Uploads::conflicts)
    }
}
