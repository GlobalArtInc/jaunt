use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use jaunt_store::{MAX_AUDIT_PAYLOAD_BYTES, Store, StoreError};
use rustix::fs::{Mode, OFlags};

use crate::event::AuditEvent;

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("the audit sink could not write: {0}")]
    Io(#[from] io::Error),
    #[error("the audit sink could not store the events: {0}")]
    Store(#[from] StoreError),
    #[error("the audit sink could not encode an event: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("the audit sink writer task failed")]
    Task,
}

pub trait AuditSink: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn write(
        &self,
        batch: &[Arc<AuditEvent>],
    ) -> impl Future<Output = Result<(), SinkError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum JsonlOpenError {
    #[error("cannot open the audit log {}: {source}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the audit log {} is not a regular file", path.display())]
    NotRegular { path: PathBuf },
}

const LOG_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::RGRP);
const OTHERS_WRITE: u32 = 0o002;

struct Output {
    writer: Box<dyn Write + Send>,
    torn: bool,
}

pub struct JsonlSink {
    output: Arc<Mutex<Output>>,
}

fn writable_by_others(mode: u32) -> bool {
    mode & OTHERS_WRITE != 0
}

impl JsonlSink {
    pub fn stdout() -> JsonlSink {
        JsonlSink::from_writer(io::stdout())
    }

    pub fn from_writer(writer: impl Write + Send + 'static) -> JsonlSink {
        JsonlSink {
            output: Arc::new(Mutex::new(Output {
                writer: Box::new(writer),
                torn: false,
            })),
        }
    }

    pub fn file(path: &Path) -> Result<JsonlSink, JsonlOpenError> {
        let open = |source| JsonlOpenError::Open {
            path: path.to_path_buf(),
            source,
        };
        let descriptor = rustix::fs::open(
            path,
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            LOG_FILE_MODE,
        )
        .map_err(|errno| open(io::Error::from(errno)))?;
        let file = File::from(descriptor);
        let metadata = file.metadata().map_err(open)?;
        if !metadata.is_file() {
            return Err(JsonlOpenError::NotRegular {
                path: path.to_path_buf(),
            });
        }
        if writable_by_others(metadata.permissions().mode()) {
            tracing::warn!(
                target: "jaunt::daemon",
                path = %path.display(),
                "the audit log is writable by other users"
            );
        }
        Ok(JsonlSink::from_writer(file))
    }
}

impl AuditSink for JsonlSink {
    fn name(&self) -> &'static str {
        "jsonl"
    }

    async fn write(&self, batch: &[Arc<AuditEvent>]) -> Result<(), SinkError> {
        let lines = batch
            .iter()
            .map(|event| {
                let mut line = serde_json::to_vec(event.as_ref())?;
                line.push(b'\n');
                Ok(line)
            })
            .collect::<Result<Vec<Vec<u8>>, serde_json::Error>>()?;
        let output = Arc::clone(&self.output);
        tokio::task::spawn_blocking(move || {
            let mut guard = output.lock().unwrap_or_else(PoisonError::into_inner);
            let output = &mut *guard;
            if output.torn {
                output.writer.write_all(b"\n")?;
                output.writer.flush()?;
                output.torn = false;
            }
            for line in &lines {
                output.torn = true;
                output.writer.write_all(line)?;
                output.writer.flush()?;
                output.torn = false;
            }
            Ok(())
        })
        .await
        .map_err(|_| SinkError::Task)?
        .map_err(SinkError::Io)
    }
}

pub struct StoreSink {
    store: Store,
    oversized: Arc<AtomicU64>,
}

impl StoreSink {
    pub fn new(store: Store) -> StoreSink {
        StoreSink {
            store,
            oversized: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn oversized(&self) -> u64 {
        self.oversized.load(Ordering::Relaxed)
    }
}

impl AuditSink for StoreSink {
    fn name(&self) -> &'static str {
        "database"
    }

    async fn write(&self, batch: &[Arc<AuditEvent>]) -> Result<(), SinkError> {
        let (records, oversized): (Vec<_>, Vec<_>) = batch
            .iter()
            .map(|event| event.to_record())
            .partition(|record| record.payload.len() <= MAX_AUDIT_PAYLOAD_BYTES);
        if !oversized.is_empty() {
            let skipped = u64::try_from(oversized.len()).unwrap_or(u64::MAX);
            let total = self.oversized.fetch_add(skipped, Ordering::Relaxed) + skipped;
            let types: Vec<&str> = oversized
                .iter()
                .map(|record| record.event_type.as_str())
                .collect();
            tracing::error!(
                target: "jaunt::daemon",
                skipped,
                total,
                types = types.join(",").as_str(),
                "audit events larger than the database payload limit were not stored; the rest of the batch was"
            );
        }
        self.store.audit_events().append(&records).await?;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemorySink {
    events: Arc<Mutex<Vec<Arc<AuditEvent>>>>,
}

impl MemorySink {
    pub fn new() -> MemorySink {
        MemorySink::default()
    }

    pub fn events(&self) -> Vec<Arc<AuditEvent>> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl AuditSink for MemorySink {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn write(&self, batch: &[Arc<AuditEvent>]) -> Result<(), SinkError> {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(batch.iter().cloned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::os::unix::fs::{MetadataExt, symlink};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use rustix::fs::{Mode, OFlags};

    use super::{AuditSink, JsonlOpenError, JsonlSink, LOG_FILE_MODE, writable_by_others};
    use crate::event::{AuditEvent, RawValue};
    use crate::spec::EventType;
    use crate::time::Timestamp;

    fn event(id: &str) -> Arc<AuditEvent> {
        let (event, _) = AuditEvent::from_raw(
            EventType::LoginStarted,
            &[("login_id", RawValue::Text("l-1".to_owned()))],
            id.to_owned(),
            Timestamp::from_millis(1_700_000_000_000).unwrap(),
        );
        Arc::new(event)
    }

    #[tokio::test]
    async fn one_record_over_the_payload_limit_is_skipped_and_the_rest_of_the_batch_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let store = jaunt_store::Store::open(&dir.path().join("jaunt.db"))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let sink = super::StoreSink::new(store.clone());
        let (wide, _) = AuditEvent::from_raw(
            EventType::DbQuery,
            &[("text", RawValue::Text("€".repeat(8192)))],
            "wide".to_owned(),
            Timestamp::from_millis(1_700_000_000_000).unwrap(),
        );
        assert!(wide.payload_json().len() > jaunt_store::MAX_AUDIT_PAYLOAD_BYTES);

        sink.write(&[event("a"), Arc::new(wide), event("b")])
            .await
            .unwrap();

        assert_eq!(sink.oversized(), 1);
        let stored = store
            .audit_events()
            .query(&jaunt_store::AuditQuery::newest(10))
            .await
            .unwrap();
        let mut ids: Vec<&str> = stored.iter().map(|record| record.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["a", "b"]);
    }

    #[tokio::test]
    async fn a_record_of_exactly_the_payload_limit_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let store = jaunt_store::Store::open(&dir.path().join("jaunt.db"))
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let sink = super::StoreSink::new(store.clone());
        let text = format!("{}{}", "\"".repeat(8181), "a".repeat(11));
        let (exact, _) = AuditEvent::from_raw(
            EventType::DbQuery,
            &[("text", RawValue::Text(text))],
            "exact".to_owned(),
            Timestamp::from_millis(1_700_000_000_000).unwrap(),
        );
        assert_eq!(
            exact.to_record().payload.len(),
            jaunt_store::MAX_AUDIT_PAYLOAD_BYTES
        );

        sink.write(&[Arc::new(exact)]).await.unwrap();

        assert_eq!(sink.oversized(), 0);
        let stored = store
            .audit_events()
            .query(&jaunt_store::AuditQuery::newest(10))
            .await
            .unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "exact");
        assert_eq!(
            stored[0].payload.len(),
            jaunt_store::MAX_AUDIT_PAYLOAD_BYTES
        );
    }

    #[tokio::test]
    async fn the_jsonl_file_gets_one_parseable_line_per_event_with_mode_0640() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlSink::file(&path).unwrap();

        sink.write(&[event("a"), event("b")]).await.unwrap();
        sink.write(&[event("c")]).await.unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let ids: Vec<String> = text
            .lines()
            .map(|line| AuditEvent::from_json_line(line).unwrap().id().to_owned())
            .collect();
        assert_eq!(ids, ["a", "b", "c"]);
        let mode = std::fs::metadata(&path).unwrap().mode() & 0o7777;
        assert_eq!(mode & 0o7137, 0, "{mode:o}");
        assert_eq!(mode & 0o600, 0o600, "{mode:o}");
    }

    #[test]
    fn the_file_mode_constant_is_0640_and_world_writable_files_are_flagged() {
        assert_eq!(LOG_FILE_MODE, Mode::from_raw_mode(0o640));
        for (mode, flagged) in [
            (0o640, false),
            (0o600, false),
            (0o660, false),
            (0o666, true),
            (0o602, true),
        ] {
            assert_eq!(writable_by_others(mode), flagged, "{mode:o}");
        }
    }

    #[tokio::test]
    async fn an_existing_file_is_appended_to_and_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "earlier line\n").unwrap();
        let sink = JsonlSink::file(&path).unwrap();

        sink.write(&[event("a")]).await.unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("earlier line\n{"), "{text}");
    }

    #[test]
    fn a_fifo_at_the_log_path_neither_hangs_the_open_nor_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.fifo");
        let made = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        let started = Instant::now();

        let without_reader = JsonlSink::file(&path);
        let reader =
            rustix::fs::open(&path, OFlags::RDONLY | OFlags::NONBLOCK, Mode::empty()).unwrap();
        let with_reader = JsonlSink::file(&path);

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(matches!(without_reader, Err(JsonlOpenError::Open { .. })));
        assert!(matches!(
            with_reader,
            Err(JsonlOpenError::NotRegular { .. })
        ));
        drop(reader);
    }

    #[derive(Clone, Default)]
    struct Torn {
        bytes: Arc<Mutex<Vec<u8>>>,
        fail_next_after: Arc<Mutex<Option<usize>>>,
    }

    impl Write for Torn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut fail = self.fail_next_after.lock().unwrap();
            if let Some(keep) = fail.take() {
                self.bytes
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..keep.min(buf.len())]);
                return Err(io::Error::other("no space left on device"));
            }
            self.bytes.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_retry_after_a_cut_line_starts_on_a_fresh_line() {
        let torn = Torn::default();
        let sink = JsonlSink::from_writer(torn.clone());
        sink.write(&[event("a")]).await.unwrap();
        *torn.fail_next_after.lock().unwrap() = Some(7);

        assert!(sink.write(&[event("b")]).await.is_err());
        sink.write(&[event("b")]).await.unwrap();
        sink.write(&[event("c")]).await.unwrap();

        let text = String::from_utf8(torn.bytes.lock().unwrap().clone()).unwrap();
        let parsed: Vec<Option<String>> = text
            .lines()
            .map(|line| {
                AuditEvent::from_json_line(line)
                    .ok()
                    .map(|e| e.id().to_owned())
            })
            .collect();
        assert_eq!(
            parsed,
            [
                Some("a".to_owned()),
                None,
                Some("b".to_owned()),
                Some("c".to_owned())
            ]
        );
        assert_eq!(text.matches('\n').count(), 4);
    }

    struct Stuck {
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Write for Stuck {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.entered.send(()).ok();
            self.release.recv().ok();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_writer_stuck_in_a_blocking_thread_ends_with_the_bounded_shutdown() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let report = runtime.block_on(async {
            let pipeline =
                crate::Pipeline::new(Arc::new(crate::ManualClock::new(1_700_000_000_000)), 8);
            pipeline
                .add_sink(JsonlSink::from_writer(Stuck {
                    entered: entered_tx,
                    release: release_rx,
                }))
                .unwrap();
            pipeline.submit(event("a"));
            tokio::task::spawn_blocking(move || {
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            })
            .await
            .unwrap();
            pipeline.shutdown(Duration::from_millis(100)).await
        });
        assert!(report.timed_out);
        let before = Instant::now();

        runtime.shutdown_timeout(Duration::from_millis(100));

        assert!(before.elapsed() < Duration::from_secs(5));
        release_tx.send(()).ok();
    }

    #[test]
    fn a_symlink_a_directory_and_a_missing_parent_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "").unwrap();
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap();

        assert!(matches!(
            JsonlSink::file(&link),
            Err(JsonlOpenError::Open { .. })
        ));
        assert!(matches!(
            JsonlSink::file(dir.path()),
            Err(JsonlOpenError::Open { .. } | JsonlOpenError::NotRegular { .. })
        ));
        assert!(matches!(
            JsonlSink::file(&dir.path().join("missing").join("audit.jsonl")),
            Err(JsonlOpenError::Open { .. })
        ));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
    }
}
