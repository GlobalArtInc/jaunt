use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use jaunt_audit::{Committed, RecordingSink, RecordingStoreError, StagedRecording, StagedSink};
use jaunt_record::{
    Accepted, AssembleError, Assembler, Chunk, SessionManifest, SinkError, Verified, VerifyError,
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use super::audit::Reason;
use super::{RecordingLimits, RecordingSettings};

pub const PENDING_CHUNK_OVERHEAD: u64 = 256;

const DISK_FULL_REPORT_SECS: i64 = 60;
const REJECTION_WINDOW_SECS: i64 = 60;
const MAX_TRACKED_REJECTIONS: usize = 4096;

#[derive(Debug)]
pub(crate) enum FinishError {
    Verify(VerifyError),
    Commit(RecordingStoreError),
}

pub(crate) struct Upload {
    pub(crate) assembler: Assembler,
    pub(crate) staged: Option<Box<dyn StagedRecording>>,
    contiguous: Option<u64>,
    out_of_order: BTreeMap<u64, u64>,
    pending: u64,
    persisted_chunks: u64,
    pub(crate) received: u64,
}

impl Upload {
    pub(crate) fn new(assembler: Assembler, staged: Box<dyn StagedRecording>) -> Upload {
        Upload {
            assembler,
            staged: Some(staged),
            contiguous: None,
            out_of_order: BTreeMap::new(),
            pending: 0,
            persisted_chunks: 0,
            received: 0,
        }
    }

    pub(crate) fn accept(&mut self, chunk: &Chunk) -> Result<Accepted, AssembleError> {
        let Some(staged) = self.staged.as_mut() else {
            return Err(AssembleError::Sink(SinkError::new(
                RecordingStoreError::Finished,
            )));
        };
        self.assembler
            .accept(chunk, &mut StagedSink(staged.as_mut()))
    }

    pub(crate) fn finish(
        &mut self,
        manifest: &SessionManifest,
        expects_cast: bool,
    ) -> Result<(Verified, Committed), FinishError> {
        let Some(mut staged) = self.staged.take() else {
            return Err(FinishError::Commit(RecordingStoreError::Finished));
        };
        match self
            .assembler
            .complete(manifest, expects_cast, &mut StagedSink(staged.as_mut()))
        {
            Ok(verified) => staged
                .commit(manifest)
                .map(|committed| (verified, committed))
                .map_err(FinishError::Commit),
            Err(error) => {
                self.staged = Some(staged);
                Err(FinishError::Verify(error))
            }
        }
    }

    pub(crate) fn acked_through(&self) -> Option<u64> {
        self.contiguous
    }

    fn next_expected(&self) -> Option<u64> {
        match self.contiguous {
            None => Some(0),
            Some(seq) => seq.checked_add(1),
        }
    }

    pub(crate) fn knows(&self, seq: u64) -> bool {
        self.contiguous.is_some_and(|through| seq <= through)
            || self.out_of_order.contains_key(&seq)
    }

    pub(crate) fn arrives_in_order(&self, seq: u64) -> bool {
        self.next_expected() == Some(seq)
    }

    pub(crate) fn pending(&self) -> u64 {
        self.pending
    }

    pub(crate) fn pending_cost(&self, seq: u64, compressed_len: usize) -> u64 {
        if self.knows(seq) || self.arrives_in_order(seq) {
            0
        } else {
            u64::try_from(compressed_len)
                .unwrap_or(u64::MAX)
                .saturating_add(PENDING_CHUNK_OVERHEAD)
        }
    }

    pub(crate) fn delivered_chunks(&self) -> u64 {
        self.contiguous.map_or(0, |seq| seq.saturating_add(1))
    }

    pub(crate) fn delivered_bytes(&self) -> u64 {
        self.staged.as_ref().map_or(0, |staged| staged.written())
    }

    pub(crate) fn delivered_sha256(&self) -> Option<String> {
        self.staged.as_ref().map(|staged| staged.prefix_sha256())
    }

    pub(crate) fn unpersisted_progress(&self) -> bool {
        self.delivered_chunks() > self.persisted_chunks
    }

    pub(crate) fn mark_persisted(&mut self, chunks: u64) {
        self.persisted_chunks = chunks;
    }

    fn record_new(&mut self, seq: u64, reserved: u64) -> u64 {
        self.received += 1;
        if !self.arrives_in_order(seq) {
            self.out_of_order.insert(seq, reserved);
            self.pending = self.pending.saturating_add(reserved);
            return 0;
        }
        self.contiguous = Some(seq);
        let mut released: u64 = 0;
        while let Some(next) = self.next_expected() {
            let Some(size) = self.out_of_order.remove(&next) else {
                break;
            };
            released = released.saturating_add(size);
            self.contiguous = Some(next);
        }
        self.pending = self.pending.saturating_sub(released);
        released
    }
}

pub(crate) enum Slot {
    Opening,
    Open(Box<Upload>),
    Closed,
    Gone,
}

pub(crate) struct Entry {
    pub(crate) session_id: String,
    pub(crate) node_id: String,
    last_seen: AtomicI64,
    waiting: AtomicUsize,
    slot: Arc<AsyncMutex<Slot>>,
}

struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Entry {
    pub(crate) fn touch(&self, now: i64) {
        self.last_seen.store(now, Ordering::SeqCst);
    }

    pub(crate) fn last_seen(&self) -> i64 {
        self.last_seen.load(Ordering::SeqCst)
    }

    pub(crate) async fn lock(&self) -> OwnedMutexGuard<Slot> {
        self.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(&self.waiting);
        self.slot.clone().lock_owned().await
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Usage {
    uploads: usize,
    pending: u64,
}

#[derive(Default)]
struct Table {
    entries: HashMap<String, Arc<Entry>>,
    nodes: HashMap<String, Usage>,
    uploads_total: usize,
    pending_total: u64,
}

impl Table {
    fn usage(&mut self, node_id: &str) -> &mut Usage {
        self.nodes.entry(node_id.to_owned()).or_default()
    }

    fn forget_idle_node(&mut self, node_id: &str) {
        if self
            .nodes
            .get(node_id)
            .is_some_and(|usage| usage.uploads == 0 && usage.pending == 0)
        {
            self.nodes.remove(node_id);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Admitted,
    TooMany,
}

pub(crate) enum Created {
    Fresh(Arc<Entry>, OwnedMutexGuard<Slot>),
    Exists,
    Refused,
}

pub(crate) struct Uploads {
    sink: Arc<dyn RecordingSink>,
    limits: RecordingLimits,
    table: Mutex<Table>,
    disk_full: Mutex<Throttled>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Throttled {
    started: Option<i64>,
    suppressed: u64,
}

impl Throttled {
    fn admit(&mut self, now: i64, window: i64) -> Option<u64> {
        if self
            .started
            .is_some_and(|started| now.saturating_sub(started) < window)
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        let suppressed = self.suppressed;
        *self = Throttled {
            started: Some(now),
            suppressed: 0,
        };
        Some(suppressed)
    }
}

type RejectionKey = (String, Option<String>, Reason);

#[derive(Default)]
pub(crate) struct RejectionLog {
    windows: Mutex<HashMap<RejectionKey, Throttled>>,
}

impl RejectionLog {
    pub(crate) fn admit(
        &self,
        node_id: &str,
        session_id: Option<&str>,
        reason: Reason,
        now: i64,
    ) -> Option<u64> {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (node_id.to_owned(), session_id.map(str::to_owned), reason);
        if let Some(window) = windows.get_mut(&key) {
            return window.admit(now, REJECTION_WINDOW_SECS);
        }
        if windows.len() >= MAX_TRACKED_REJECTIONS {
            windows.retain(|_, window| {
                window
                    .started
                    .is_some_and(|started| now.saturating_sub(started) < REJECTION_WINDOW_SECS)
            });
            if windows.len() >= MAX_TRACKED_REJECTIONS {
                return None;
            }
        }
        windows
            .entry(key)
            .or_default()
            .admit(now, REJECTION_WINDOW_SECS)
    }
}

impl Uploads {
    pub(crate) fn new(settings: RecordingSettings) -> Uploads {
        Uploads {
            sink: settings.sink,
            limits: settings.limits,
            table: Mutex::new(Table::default()),
            disk_full: Mutex::new(Throttled::default()),
        }
    }

    pub(crate) fn limits(&self) -> RecordingLimits {
        self.limits
    }

    pub(crate) fn sink(&self) -> Arc<dyn RecordingSink> {
        self.sink.clone()
    }

    fn table(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn find(&self, session_id: &str) -> Option<Arc<Entry>> {
        self.table().entries.get(session_id).cloned()
    }

    pub(crate) fn waiting_for(&self, session_id: &str) -> usize {
        self.find(session_id)
            .map_or(0, |entry| entry.waiting.load(Ordering::SeqCst))
    }

    pub(crate) fn create(&self, session_id: &str, node_id: &str, now: i64) -> Created {
        let mut table = self.table();
        if table.entries.contains_key(session_id) {
            return Created::Exists;
        }
        let node_uploads = table.nodes.get(node_id).map_or(0, |usage| usage.uploads);
        if node_uploads >= self.limits.max_uploads_per_node
            || table.uploads_total >= self.limits.max_uploads_total
        {
            return Created::Refused;
        }
        let entry = Arc::new(Entry {
            session_id: session_id.to_owned(),
            node_id: node_id.to_owned(),
            last_seen: AtomicI64::new(now),
            waiting: AtomicUsize::new(0),
            slot: Arc::new(AsyncMutex::new(Slot::Opening)),
        });
        let Ok(guard) = entry.slot.clone().try_lock_owned() else {
            return Created::Exists;
        };
        table.entries.insert(session_id.to_owned(), entry.clone());
        table.uploads_total += 1;
        table.usage(node_id).uploads += 1;
        Created::Fresh(entry, guard)
    }

    pub(crate) fn remove(&self, entry: &Entry, pending: u64) {
        let mut table = self.table();
        let owned = table
            .entries
            .get(&entry.session_id)
            .is_some_and(|stored| std::ptr::eq(stored.as_ref(), entry));
        if !owned {
            return;
        }
        table.entries.remove(&entry.session_id);
        table.uploads_total = table.uploads_total.saturating_sub(1);
        table.pending_total = table.pending_total.saturating_sub(pending);
        let usage = table.usage(&entry.node_id);
        usage.uploads = usage.uploads.saturating_sub(1);
        usage.pending = usage.pending.saturating_sub(pending);
        table.forget_idle_node(&entry.node_id);
    }

    pub(crate) fn reserve(&self, node_id: &str, bytes: u64) -> Admission {
        if bytes == 0 {
            return Admission::Admitted;
        }
        let mut table = self.table();
        let node_pending = table.nodes.get(node_id).map_or(0, |usage| usage.pending);
        let fits_node = node_pending
            .checked_add(bytes)
            .is_some_and(|total| total <= self.limits.max_pending_bytes_per_node);
        let fits_total = table
            .pending_total
            .checked_add(bytes)
            .is_some_and(|total| total <= self.limits.max_pending_bytes_total);
        if !fits_node || !fits_total {
            return Admission::TooMany;
        }
        table.pending_total += bytes;
        table.usage(node_id).pending += bytes;
        Admission::Admitted
    }

    pub(crate) fn release(&self, node_id: &str, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let mut table = self.table();
        table.pending_total = table.pending_total.saturating_sub(bytes);
        let usage = table.usage(node_id);
        usage.pending = usage.pending.saturating_sub(bytes);
        table.forget_idle_node(node_id);
    }

    pub(crate) fn record_new(&self, node_id: &str, upload: &mut Upload, seq: u64, reserved: u64) {
        let released = upload.record_new(seq, reserved);
        self.release(node_id, released);
    }

    pub(crate) fn candidates_idle_since(
        &self,
        now: i64,
    ) -> Vec<(Arc<Entry>, OwnedMutexGuard<Slot>)> {
        let idle_secs = i64::try_from(self.limits.idle_timeout.as_secs()).unwrap_or(i64::MAX);
        let table = self.table();
        table
            .entries
            .values()
            .filter(|entry| {
                entry
                    .last_seen
                    .load(Ordering::SeqCst)
                    .saturating_add(idle_secs)
                    <= now
            })
            .filter_map(|entry| {
                entry
                    .slot
                    .clone()
                    .try_lock_owned()
                    .ok()
                    .map(|guard| (entry.clone(), guard))
            })
            .collect()
    }

    pub(crate) fn report_disk_full(&self, now: i64) -> Option<u64> {
        self.disk_full
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(now, DISK_FULL_REPORT_SECS)
    }

    #[cfg(test)]
    fn pending_of(&self, node_id: &str) -> (u64, u64) {
        let table = self.table();
        (
            table.nodes.get(node_id).map_or(0, |usage| usage.pending),
            table.pending_total,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingKey};
    use jaunt_record::{Assembler, Limits};

    use super::{Admission, Created, MAX_TRACKED_REJECTIONS, RejectionLog, Slot, Upload, Uploads};
    use crate::recordings::audit::Reason;
    use crate::recordings::{RecordingLimits, RecordingSettings};

    const NODE: &str = "node-1";

    fn uploads(dir: &tempfile::TempDir, limits: RecordingLimits) -> Uploads {
        let sink = DirectorySink::create(
            &dir.path().join("r"),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1024,
            },
        )
        .unwrap();
        Uploads::new(RecordingSettings {
            sink: Arc::new(sink),
            limits,
        })
    }

    fn upload(uploads: &Uploads) -> Upload {
        let key = RecordingKey::new("5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11", 0).unwrap();
        Upload::new(
            Assembler::new(key.session_id(), Limits::default()),
            uploads.sink().begin(&key).unwrap(),
        )
    }

    #[test]
    fn the_acknowledged_prefix_and_pending_bytes_follow_out_of_order_arrival() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = uploads(
            &dir,
            RecordingLimits {
                max_pending_bytes_per_node: 25,
                max_pending_bytes_total: 100,
                ..RecordingLimits::default()
            },
        );
        let mut upload = upload(&uploads);
        assert!(upload.arrives_in_order(0));
        for (seq, size) in [(2, 10), (3, 15)] {
            assert_eq!(uploads.reserve(NODE, size), Admission::Admitted);
            uploads.record_new(NODE, &mut upload, seq, size);
        }
        assert_eq!(uploads.reserve(NODE, 1), Admission::TooMany);
        assert_eq!(upload.acked_through(), None);
        assert_eq!(uploads.pending_of(NODE), (25, 25));
        assert!(upload.knows(3) && !upload.knows(1));

        uploads.record_new(NODE, &mut upload, 0, 0);
        assert_eq!(upload.acked_through(), Some(0));
        uploads.record_new(NODE, &mut upload, 1, 0);
        assert_eq!(upload.acked_through(), Some(3));
        assert_eq!(upload.pending(), 0);
        assert_eq!(uploads.pending_of(NODE), (0, 0));
        assert_eq!(upload.received, 4);
    }

    #[test]
    fn the_node_and_global_caps_count_live_uploads_and_removal_frees_them() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = uploads(
            &dir,
            RecordingLimits {
                max_uploads_per_node: 2,
                max_uploads_total: 3,
                idle_timeout: Duration::from_secs(10),
                ..RecordingLimits::default()
            },
        );
        let mut held = Vec::new();
        for (session, node) in [("a", NODE), ("b", NODE), ("c", "node-2")] {
            match uploads.create(session, node, 100) {
                Created::Fresh(entry, guard) => held.push((entry, guard)),
                _ => panic!("{session} was not admitted"),
            }
        }
        assert!(matches!(uploads.create("a", NODE, 100), Created::Exists));
        assert!(matches!(uploads.create("d", NODE, 100), Created::Refused));
        assert!(matches!(
            uploads.create("d", "node-3", 100),
            Created::Refused
        ));

        let (entry, mut guard) = held.remove(0);
        *guard = Slot::Gone;
        drop(guard);
        uploads.remove(&entry, 0);
        assert!(matches!(
            uploads.create("d", NODE, 100),
            Created::Fresh(_, _)
        ));
        drop(held);
        let idle: Vec<String> = uploads
            .candidates_idle_since(110)
            .into_iter()
            .map(|(entry, _)| entry.session_id.clone())
            .collect();
        assert_eq!(idle.len(), 3);
        assert!(uploads.candidates_idle_since(109).is_empty());
    }

    #[test]
    fn a_full_disk_is_reported_at_most_once_a_minute() {
        let dir = tempfile::tempdir().unwrap();
        let uploads = uploads(&dir, RecordingLimits::default());
        assert_eq!(uploads.report_disk_full(1000), Some(0));
        assert_eq!(uploads.report_disk_full(1059), None);
        assert_eq!(uploads.report_disk_full(1059), None);
        assert_eq!(uploads.report_disk_full(1060), Some(2));
    }

    #[test]
    fn a_rejection_is_reported_once_a_minute_per_node_session_and_reason() {
        let log = RejectionLog::default();
        let report = |node, session, reason, now| log.admit(node, session, reason, now);
        assert_eq!(report(NODE, Some("s"), Reason::BadChunk, 100), Some(0));
        assert_eq!(report(NODE, Some("s"), Reason::BadChunk, 159), None);
        assert_eq!(report(NODE, Some("s"), Reason::BadState, 159), Some(0));
        assert_eq!(report(NODE, Some("t"), Reason::BadChunk, 159), Some(0));
        assert_eq!(report("node-2", Some("s"), Reason::BadChunk, 159), Some(0));
        assert_eq!(report(NODE, None, Reason::BadChunk, 159), Some(0));
        assert_eq!(report(NODE, Some("s"), Reason::BadChunk, 160), Some(1));
        for index in 0..MAX_TRACKED_REJECTIONS {
            let session = format!("x{index}");
            log.admit(NODE, Some(&session), Reason::UnknownSession, 200);
        }
        assert_eq!(
            report(NODE, Some("full"), Reason::UnknownSession, 200),
            None
        );
        assert_eq!(
            report(NODE, Some("full"), Reason::UnknownSession, 260),
            Some(0)
        );
    }
}
