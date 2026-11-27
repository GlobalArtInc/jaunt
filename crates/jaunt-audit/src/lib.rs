mod capture;
mod clock;
mod event;
mod limiter;
mod pipeline;
mod query;
mod recording;
mod reference;
mod retention;
#[cfg(feature = "testing")]
mod scoped;
mod sink;
mod spec;
mod time;

pub use capture::{
    AUDIT_TARGET, AlreadyBound, AuditLayer, AuditLevelCompiledOut, AuditTap, TapSnapshot,
    ensure_audit_level_compiled_in,
};
pub use clock::{Clock, ManualClock, SystemClock, system_clock};
pub use event::{
    Actor, AuditEvent, BuildReport, EventError, FieldValue, RawValue, SCHEMA_VERSION, clean_text,
};
pub use pipeline::{
    DEFAULT_QUEUE, DEFAULT_RETRY_BACKOFF, LaneSnapshot, MAX_QUEUE, Pipeline, PipelineClosed,
    ShutdownReport,
};
pub use query::{
    AuditFilter, AuditPage, DEFAULT_PAGE, FilterError, MAX_PAGE, QueryError, encode_cursor, query,
};
pub use recording::{
    CAST_CONFLICT, CAST_SUFFIX, CastProof, Committed, DEFAULT_MIN_FREE_BYTES, DirectoryLimits,
    DirectorySink, DirectoryStaged, FILE_MODE, FreeSpace, IDENTITY_CONFLICT, Identity,
    LENGTH_CONFLICT, Leftovers, LocalProof, MANIFEST_CONFLICT, MANIFEST_SUFFIX, MAX_MANIFEST_BYTES,
    PART_SUFFIX, PENDING_SUFFIX, PendingManifest, ROOT_MODE, RecordingKey, RecordingKeyError,
    RecordingSink, RecordingStoreError, Resolution, STRUCTURE_CONFLICT, StagedRecording,
    StagedSink, StoreProof, StoredRecording, UNREADABLE_CONFLICT, VerifiedRecording, VerifyFailure,
    cast_sha256, manifest_bytes, manifest_sha256, read_store_proof, resolve_existing,
    store_error_of, verify_stored,
};
pub use reference::new_denial_reference;
pub use retention::{
    DEFAULT_RETENTION_DAYS, MASS_DELETE_MIN_ROWS, MAX_RETENTION_DAYS, PRUNE_INTERVAL, PruneOutcome,
    Pruner, prune_once, prune_with_limits,
};
#[cfg(feature = "testing")]
pub use scoped::{ScopedCapture, keep_callsites_enabled_for_scoped_capture};
pub use sink::{AuditSink, JsonlOpenError, JsonlSink, MemorySink, SinkError, StoreSink};
pub use spec::{
    ActorRule, Class, Classified, EventSpec, EventType, FieldKind, FieldSpec, IGNORED_PREFIXES,
};
pub use time::{TimeError, Timestamp};
