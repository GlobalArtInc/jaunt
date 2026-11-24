use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jaunt_audit::{
    AlreadyBound, AuditLevelCompiledOut, AuditTap, Clock, DEFAULT_QUEUE, DEFAULT_RETENTION_DAYS,
    JsonlOpenError, JsonlSink, MAX_QUEUE, MAX_RETENTION_DAYS, PRUNE_INTERVAL, Pipeline,
    PipelineClosed, Pruner, ShutdownReport, StoreSink, ensure_audit_level_compiled_in,
};
use jaunt_store::Store;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Unexpected, Visitor};

pub const FLUSH_DEADLINE: Duration = Duration::from_secs(10);
pub const RUNTIME_GRACE: Duration = Duration::from_secs(2);

pub fn finish_runtime(runtime: tokio::runtime::Runtime, grace: Duration) {
    runtime.shutdown_timeout(grace);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonlTarget {
    Stdout,
    File(PathBuf),
    Off,
}

impl<'de> Deserialize<'de> for JsonlTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<JsonlTarget, D::Error> {
        deserializer.deserialize_any(TargetVisitor)
    }
}

struct TargetVisitor;

impl<'de> Visitor<'de> for TargetVisitor {
    type Value = JsonlTarget;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("\"stdout\", \"off\" or a map with a `file` path")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<JsonlTarget, E> {
        if value {
            Err(E::invalid_value(Unexpected::Bool(value), &self))
        } else {
            Ok(JsonlTarget::Off)
        }
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<JsonlTarget, E> {
        match value {
            "stdout" => Ok(JsonlTarget::Stdout),
            "off" => Ok(JsonlTarget::Off),
            other => Err(E::invalid_value(Unexpected::Str(other), &self)),
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonlTarget, A::Error> {
        let key: Option<String> = map.next_key()?;
        if key.as_deref() != Some("file") {
            return Err(de::Error::custom("expected the single key `file`"));
        }
        let path: PathBuf = map.next_value()?;
        if map.next_key::<String>()?.is_some() {
            return Err(de::Error::custom("expected the single key `file`"));
        }
        Ok(JsonlTarget::File(path))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditSection {
    #[serde(default = "default_jsonl")]
    pub jsonl: JsonlTarget,
    #[serde(default = "default_database")]
    pub database: bool,
    #[serde(default = "default_queue")]
    pub queue: usize,
    #[serde(default, deserialize_with = "explicit_retention")]
    pub retention_days: Option<Option<u32>>,
}

fn explicit_retention<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<u32>>, D::Error> {
    Option::<u32>::deserialize(deserializer).map(Some)
}

impl Default for AuditSection {
    fn default() -> AuditSection {
        AuditSection {
            jsonl: default_jsonl(),
            database: default_database(),
            queue: default_queue(),
            retention_days: None,
        }
    }
}

fn default_jsonl() -> JsonlTarget {
    JsonlTarget::Stdout
}

fn default_database() -> bool {
    true
}

fn default_queue() -> usize {
    DEFAULT_QUEUE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSettings {
    pub jsonl: JsonlTarget,
    pub database: bool,
    pub queue: usize,
    pub retention_days: Option<u32>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuditConfigError {
    #[error("audit.queue must be between 1 and {MAX_QUEUE}")]
    QueueOutOfRange,
    #[error(
        "audit.retention_days must be between 1 and {MAX_RETENTION_DAYS}, or 0 or null to keep \
         everything"
    )]
    RetentionOutOfRange,
    #[error("audit.retention_days needs audit.database to be true")]
    RetentionWithoutDatabase,
    #[error("audit needs a sink: set audit.jsonl or audit.database")]
    NoSink,
    #[error("audit.jsonl.file must not be empty")]
    EmptyFilePath,
}

impl AuditSection {
    pub fn into_settings(self) -> Result<AuditSettings, AuditConfigError> {
        if !(1..=MAX_QUEUE).contains(&self.queue) {
            return Err(AuditConfigError::QueueOutOfRange);
        }
        let retention_days = match self.retention_days {
            None => self.database.then_some(DEFAULT_RETENTION_DAYS),
            Some(None | Some(0)) => None,
            Some(Some(days)) => {
                if !(1..=MAX_RETENTION_DAYS).contains(&days) {
                    return Err(AuditConfigError::RetentionOutOfRange);
                }
                if !self.database {
                    return Err(AuditConfigError::RetentionWithoutDatabase);
                }
                Some(days)
            }
        };
        if let JsonlTarget::File(path) = &self.jsonl
            && path.as_os_str().is_empty()
        {
            return Err(AuditConfigError::EmptyFilePath);
        }
        if self.jsonl == JsonlTarget::Off && !self.database {
            return Err(AuditConfigError::NoSink);
        }
        Ok(AuditSettings {
            jsonl: self.jsonl,
            database: self.database,
            queue: self.queue,
            retention_days,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditStartError {
    #[error(transparent)]
    Jsonl(#[from] JsonlOpenError),
    #[error(transparent)]
    Bind(#[from] AlreadyBound),
    #[error(transparent)]
    Closed(#[from] PipelineClosed),
    #[error(transparent)]
    Level(#[from] AuditLevelCompiledOut),
    #[error(
        "no audit sink is usable for this command: set audit.database to true or audit.jsonl to a \
         file"
    )]
    NoSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Surface {
    Daemon,
    Cli,
}

#[derive(Clone)]
pub struct AuditRuntime {
    pipeline: Pipeline,
    pruner: Arc<Mutex<Option<Pruner>>>,
    tap: AuditTap,
}

pub fn start(
    settings: &AuditSettings,
    surface: Surface,
    store: &Store,
    tap: &AuditTap,
    clock: Arc<dyn Clock>,
) -> Result<AuditRuntime, AuditStartError> {
    ensure_audit_level_compiled_in()?;
    let pipeline = Pipeline::new(Arc::clone(&clock), settings.queue);
    let mut sinks = 0;
    match (&settings.jsonl, surface) {
        (JsonlTarget::Stdout, Surface::Daemon) => {
            pipeline.add_sink(JsonlSink::stdout())?;
            sinks += 1;
        }
        (JsonlTarget::File(path), _) => {
            pipeline.add_sink(JsonlSink::file(path)?)?;
            sinks += 1;
        }
        (JsonlTarget::Stdout, Surface::Cli) | (JsonlTarget::Off, _) => {}
    }
    if settings.database {
        pipeline.add_sink(StoreSink::new(store.clone()))?;
        sinks += 1;
    }
    if sinks == 0 && surface == Surface::Cli {
        return Err(AuditStartError::NoSink);
    }
    tap.bind(pipeline.clone())?;
    let pruner = match (surface, settings.retention_days, settings.database) {
        (Surface::Daemon, Some(days), true) => {
            Some(Pruner::spawn(store.clone(), clock, days, PRUNE_INTERVAL))
        }
        _ => None,
    };
    Ok(AuditRuntime {
        pipeline,
        pruner: Arc::new(Mutex::new(pruner)),
        tap: tap.clone(),
    })
}

impl AuditRuntime {
    pub async fn shutdown(&self, deadline: Duration) -> ShutdownReport {
        let pruner = self
            .pruner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(pruner) = pruner {
            pruner.stop();
        }
        let report = self.pipeline.shutdown(deadline).await;
        let tap = self.tap.snapshot();
        let lost = report.lost_total();
        if lost > 0 || tap.unbound > 0 || tap.fields_dropped > 0 || tap.unmapped > 0 {
            tracing::warn!(
                target: "jaunt::daemon",
                lost,
                captured = tap.captured,
                unbound = tap.unbound,
                unmapped = tap.unmapped,
                fields_dropped = tap.fields_dropped,
                dropped_after_close = report.dropped_after_close,
                "audit events were lost or malformed during this run"
            );
            for lane in report.lanes.iter().filter(|lane| lane.lost_total() > 0) {
                tracing::warn!(
                    target: "jaunt::daemon",
                    sink = lane.sink,
                    accepted = lane.accepted,
                    written = lane.written,
                    dropped_full = lane.dropped_full,
                    dropped_noisy = lane.dropped_noisy,
                    lost_after_retries = lane.lost_after_retries,
                    unwritten = lane.unwritten,
                    "an audit sink lost events"
                );
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use jaunt_audit::{
        AuditEvent, AuditTap, Timestamp, keep_callsites_enabled_for_scoped_capture, system_clock,
    };
    use jaunt_store::{AuditQuery, AuditRecord, Store};
    use tracing_subscriber::Registry;
    use tracing_subscriber::layer::SubscriberExt;

    use super::{
        AuditConfigError, AuditSection, AuditStartError, JsonlTarget, Surface, finish_runtime,
        start,
    };

    fn parse(text: &str) -> Result<AuditSection, String> {
        serde_saphyr::from_str(text).map_err(|err| err.to_string())
    }

    #[test]
    fn the_defaults_are_jsonl_to_stdout_the_database_on_and_a_year_of_retention() {
        let section = parse("{}").unwrap();

        let settings = section.into_settings().unwrap();

        assert_eq!(settings.jsonl, JsonlTarget::Stdout);
        assert!(settings.database);
        assert_eq!(settings.queue, 1024);
        assert_eq!(settings.retention_days, Some(365));
    }

    #[test]
    fn retention_can_be_set_and_explicitly_disabled_by_zero_or_null() {
        let days = |text: &str| parse(text).unwrap().into_settings().unwrap().retention_days;

        assert_eq!(days("retention_days: 90"), Some(90));
        assert_eq!(days("retention_days: 36500"), Some(36500));
        assert_eq!(days("retention_days: 0"), None);
        assert_eq!(days("retention_days: null"), None);
        assert_eq!(days("retention_days: ~"), None);
        assert_eq!(days("retention_days:"), None);
        assert_eq!(days("database: false"), None);
        assert_eq!(days("database: false\nretention_days: 0"), None);
    }

    #[test]
    fn every_jsonl_form_parses_and_the_rest_is_refused() {
        for (text, expected) in [
            ("jsonl: stdout", JsonlTarget::Stdout),
            ("jsonl: off", JsonlTarget::Off),
            ("jsonl: \"off\"", JsonlTarget::Off),
            (
                "jsonl: { file: /var/log/jaunt/audit.jsonl }",
                JsonlTarget::File("/var/log/jaunt/audit.jsonl".into()),
            ),
        ] {
            assert_eq!(parse(text).unwrap().jsonl, expected, "{text}");
        }
        for bad in [
            "jsonl: stderr",
            "jsonl: true",
            "jsonl: \"yes\"",
            "jsonl: {}",
            "jsonl: { path: /x }",
            "jsonl: { file: /x, extra: 1 }",
            "unknown: 1",
            "queue: many",
            "database: maybe",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn invalid_combinations_are_refused_with_typed_errors() {
        let section = |text: &str| parse(text).unwrap().into_settings();

        assert_eq!(
            section("queue: 0").unwrap_err(),
            AuditConfigError::QueueOutOfRange
        );
        assert_eq!(
            section("queue: 2000000").unwrap_err(),
            AuditConfigError::QueueOutOfRange
        );
        assert_eq!(
            section("retention_days: 36501").unwrap_err(),
            AuditConfigError::RetentionOutOfRange
        );
        assert_eq!(
            section("retention_days: 90\ndatabase: false").unwrap_err(),
            AuditConfigError::RetentionWithoutDatabase
        );
        assert_eq!(
            section("jsonl: off\ndatabase: false").unwrap_err(),
            AuditConfigError::NoSink
        );
        assert_eq!(
            section("jsonl: { file: \"\" }").unwrap_err(),
            AuditConfigError::EmptyFilePath
        );
        assert!(section("retention_days: 90").is_ok());
        assert!(section("jsonl: off").is_ok());
        assert!(section("database: false").is_ok());
    }

    #[tokio::test]
    async fn one_event_reaches_both_the_jsonl_file_and_the_database_and_shutdown_flushes() {
        keep_callsites_enabled_for_scoped_capture();
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        let log = dir.path().join("audit.jsonl");
        let settings = parse(&format!(
            "jsonl: {{ file: {} }}\nretention_days: 30",
            log.display()
        ))
        .unwrap()
        .into_settings()
        .unwrap();
        let tap = AuditTap::new(system_clock());
        let runtime = start(&settings, Surface::Daemon, &store, &tap, system_clock()).unwrap();

        tracing::subscriber::with_default(Registry::default().with(tap.layer()), || {
            tracing::info!(target: "jaunt::audit", event = "login.started", login_id = "wired");
        });
        let report = runtime.shutdown(super::FLUSH_DEADLINE).await;

        assert!(!report.timed_out);
        let line = std::fs::read_to_string(&log).unwrap();
        let from_file = AuditEvent::from_json_line(line.trim_end()).unwrap();
        let rows = store
            .audit_events()
            .query(&AuditQuery::newest(10))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, from_file.id());
        assert_eq!(from_file.text("login_id"), Some("wired"));
        let again = start(&settings, Surface::Daemon, &store, &tap, system_clock());
        assert!(again.is_err());
    }

    fn old_and_recent_rows() -> Vec<AuditRecord> {
        let now = Timestamp::now().millis();
        let day = 86_400_000;
        let row = |id: &str, age_days: i64| AuditRecord {
            id: id.to_owned(),
            time_ms: now - age_days * day,
            event_type: "gate.connect".to_owned(),
            actor: "anonymous".to_owned(),
            node: None,
            session_id: None,
            policy_hash: None,
            payload: "{}".to_owned(),
            v: 1,
        };
        vec![row("ancient", 400), row("old", 60), row("recent", 1)]
    }

    async fn stored_ids(store: &Store) -> Vec<String> {
        let rows = store
            .audit_events()
            .query(&AuditQuery::newest(10))
            .await
            .unwrap();
        rows.into_iter().map(|row| row.id).collect()
    }

    async fn wait_until_pruned(store: &Store, remaining: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while stored_ids(store).await.len() > remaining {
            assert!(Instant::now() < deadline, "the pruner did not run");
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn the_daemon_prunes_by_the_retention_with_a_year_by_default_and_the_cli_never_does() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        store
            .audit_events()
            .append(&old_and_recent_rows())
            .await
            .unwrap();
        let thirty = parse("jsonl: off\nretention_days: 30")
            .unwrap()
            .into_settings()
            .unwrap();
        let by_default = parse("jsonl: off").unwrap().into_settings().unwrap();

        let cli = start(
            &thirty,
            Surface::Cli,
            &store,
            &AuditTap::new(system_clock()),
            system_clock(),
        )
        .unwrap();
        cli.shutdown(super::FLUSH_DEADLINE).await;
        assert_eq!(stored_ids(&store).await.len(), 3);

        let default_run = start(
            &by_default,
            Surface::Daemon,
            &store,
            &AuditTap::new(system_clock()),
            system_clock(),
        )
        .unwrap();
        wait_until_pruned(&store, 2).await;
        default_run.shutdown(super::FLUSH_DEADLINE).await;
        assert_eq!(stored_ids(&store).await, ["recent", "old"]);

        let thirty_run = start(
            &thirty,
            Surface::Daemon,
            &store,
            &AuditTap::new(system_clock()),
            system_clock(),
        )
        .unwrap();
        wait_until_pruned(&store, 1).await;
        thirty_run.shutdown(super::FLUSH_DEADLINE).await;
        assert_eq!(stored_ids(&store).await, ["recent"]);
    }

    #[test]
    fn a_blocking_task_that_never_returns_cannot_hold_the_runtime_shutdown() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (release, parked) = std::sync::mpsc::channel::<()>();
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        runtime.spawn_blocking(move || {
            started_tx.send(()).ok();
            parked.recv().ok();
        });
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let before = Instant::now();

        finish_runtime(runtime, Duration::from_millis(100));

        assert!(before.elapsed() < Duration::from_secs(5));
        release.send(()).ok();
    }

    #[tokio::test]
    async fn a_command_without_any_usable_sink_is_refused_while_the_daemon_still_has_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        let settings = parse("database: false").unwrap().into_settings().unwrap();
        assert_eq!(settings.jsonl, JsonlTarget::Stdout);
        let tap = AuditTap::new(system_clock());

        let command = start(&settings, Surface::Cli, &store, &tap, system_clock());
        let daemon = start(&settings, Surface::Daemon, &store, &tap, system_clock());

        assert!(matches!(command, Err(AuditStartError::NoSink)));
        let daemon = daemon.unwrap();
        daemon.shutdown(super::FLUSH_DEADLINE).await;
        let with_file = parse("database: false\njsonl: { file: audit.jsonl }")
            .unwrap()
            .into_settings()
            .unwrap();
        assert_eq!(with_file.jsonl, JsonlTarget::File("audit.jsonl".into()));
    }
}
