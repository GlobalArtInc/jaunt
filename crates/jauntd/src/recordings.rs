use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use jaunt_audit::{
    DEFAULT_MIN_FREE_BYTES, DirectoryLimits, DirectorySink, RecordingKey, RecordingSink,
    RecordingStoreError, verify_stored,
};
use jaunt_control::{
    Control, ControlError, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CHUNKS, DEFAULT_MAX_STORE_COMMITS,
    DEFAULT_MAX_UPLOADS_PER_NODE, DEFAULT_MAX_UPLOADS_TOTAL, DEFAULT_MAX_WAIT,
    DEFAULT_PENDING_BYTES_PER_NODE, DEFAULT_PENDING_BYTES_TOTAL, DEFAULT_PLAYBACK_LIMIT_BYTES,
    DEFAULT_SESSION_PENDING_BYTES, DEFAULT_STORE_RETRY, RecordingLimits, RecordingSettings,
};
use jaunt_record::Limits;
use jaunt_recording_s3::{
    ConfigError as S3ConfigError, Credentials, DEFAULT_PART_SIZE, DEFAULT_PREFIX,
    DEFAULT_UPLOAD_DEADLINE, ProbeError, S3Config, S3Sink, Sse,
};
use jaunt_store::{Store, StoreError, is_session_id};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use serde::Deserialize;

use crate::config;

const DATABASE_FILE: &str = "jaunt.db";
const DEFAULT_STAGING_DIR: &str = "recording-staging";
const MAX_UPLOADS_LIMIT: u64 = 65_536;
const MIN_IDLE_TIMEOUT_SECS: u64 = 60;
const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;
const MAX_STORE_RETRY_SECS: u64 = 86_400;
const MAX_STORE_COMMITS_LIMIT: u64 = 1024;
const MAX_WAIT_LIMIT_SECS: u64 = 30 * 86_400;
const MAX_CHUNK_COMPRESSED_LIMIT: u64 = 16 * 1024 * 1024;
const MAX_CHUNK_RAW_LIMIT: u64 = 64 * 1024 * 1024;
const MIN_PLAYBACK_BYTES: u64 = 1024 * 1024;
const MAX_PLAYBACK_BYTES: u64 = 512 * 1024 * 1024;
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    #[default]
    Directory,
    S3,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SseSection {
    #[default]
    None,
    Aes256,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Section {
    pub endpoint: Option<String>,
    pub region: String,
    pub bucket: String,
    #[serde(default = "default_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub path_style: bool,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub sse: SseSection,
    #[serde(default = "default_conditional_put")]
    pub conditional_put: bool,
    #[serde(default = "default_part_size")]
    pub part_size: u64,
    #[serde(default = "default_upload_deadline_secs")]
    pub upload_deadline_secs: u64,
    pub access_key_file: Option<PathBuf>,
    pub secret_key_file: Option<PathBuf>,
}

fn default_prefix() -> String {
    DEFAULT_PREFIX.to_owned()
}

fn default_conditional_put() -> bool {
    true
}

fn default_part_size() -> u64 {
    widen(DEFAULT_PART_SIZE)
}

fn default_upload_deadline_secs() -> u64 {
    DEFAULT_UPLOAD_DEADLINE.as_secs()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingsSection {
    #[serde(default)]
    pub store: StoreKind,
    pub dir: Option<PathBuf>,
    pub staging_dir: Option<PathBuf>,
    pub s3: Option<S3Section>,
    #[serde(default = "default_min_free_bytes")]
    pub min_free_bytes: u64,
    #[serde(default = "default_max_uploads_per_node")]
    pub max_uploads_per_node: u64,
    #[serde(default = "default_max_uploads_total")]
    pub max_uploads_total: u64,
    #[serde(default = "default_max_pending_bytes_per_node")]
    pub max_pending_bytes_per_node: u64,
    #[serde(default = "default_max_pending_bytes_total")]
    pub max_pending_bytes_total: u64,
    #[serde(default = "default_max_pending_bytes")]
    pub max_pending_bytes: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_store_retry_secs")]
    pub store_retry_secs: u64,
    #[serde(default = "default_max_store_commits")]
    pub max_store_commits: u64,
    #[serde(default = "default_max_wait_secs")]
    pub max_wait_secs: u64,
    #[serde(default = "default_max_chunk_compressed")]
    pub max_chunk_compressed: u64,
    #[serde(default = "default_max_chunk_raw")]
    pub max_chunk_raw: u64,
    #[serde(default = "default_max_chunks")]
    pub max_chunks: u64,
    #[serde(default = "default_max_total_raw")]
    pub max_total_raw: u64,
    #[serde(default = "default_max_playback_bytes")]
    pub max_playback_bytes: u64,
}

impl Default for RecordingsSection {
    fn default() -> RecordingsSection {
        RecordingsSection {
            store: StoreKind::Directory,
            dir: None,
            staging_dir: None,
            s3: None,
            min_free_bytes: default_min_free_bytes(),
            max_uploads_per_node: default_max_uploads_per_node(),
            max_uploads_total: default_max_uploads_total(),
            max_pending_bytes_per_node: default_max_pending_bytes_per_node(),
            max_pending_bytes_total: default_max_pending_bytes_total(),
            max_pending_bytes: default_max_pending_bytes(),
            idle_timeout_secs: default_idle_timeout_secs(),
            store_retry_secs: default_store_retry_secs(),
            max_store_commits: default_max_store_commits(),
            max_wait_secs: default_max_wait_secs(),
            max_chunk_compressed: default_max_chunk_compressed(),
            max_chunk_raw: default_max_chunk_raw(),
            max_chunks: default_max_chunks(),
            max_total_raw: default_max_total_raw(),
            max_playback_bytes: default_max_playback_bytes(),
        }
    }
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn default_min_free_bytes() -> u64 {
    DEFAULT_MIN_FREE_BYTES
}

fn default_max_uploads_per_node() -> u64 {
    widen(DEFAULT_MAX_UPLOADS_PER_NODE)
}

fn default_max_uploads_total() -> u64 {
    widen(DEFAULT_MAX_UPLOADS_TOTAL)
}

fn default_max_pending_bytes_per_node() -> u64 {
    DEFAULT_PENDING_BYTES_PER_NODE
}

fn default_max_pending_bytes_total() -> u64 {
    DEFAULT_PENDING_BYTES_TOTAL
}

fn default_max_pending_bytes() -> u64 {
    widen(DEFAULT_SESSION_PENDING_BYTES)
}

fn default_idle_timeout_secs() -> u64 {
    DEFAULT_IDLE_TIMEOUT.as_secs()
}

fn default_store_retry_secs() -> u64 {
    DEFAULT_STORE_RETRY.as_secs()
}

fn default_max_wait_secs() -> u64 {
    DEFAULT_MAX_WAIT.as_secs()
}

fn default_max_store_commits() -> u64 {
    widen(DEFAULT_MAX_STORE_COMMITS)
}

fn default_max_chunk_compressed() -> u64 {
    widen(Limits::default().max_chunk_compressed)
}

fn default_max_chunk_raw() -> u64 {
    Limits::default().max_chunk_raw
}

fn default_max_chunks() -> u64 {
    DEFAULT_MAX_CHUNKS
}

fn default_max_total_raw() -> u64 {
    Limits::default().max_total_raw
}

fn default_max_playback_bytes() -> u64 {
    DEFAULT_PLAYBACK_LIMIT_BYTES
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSettings {
    Directory { dir: PathBuf },
    S3(Box<S3Settings>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Settings {
    pub config: S3Config,
    pub staging_dir: PathBuf,
    pub credential_files: Option<(PathBuf, PathBuf)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingsSettings {
    pub store: StoreSettings,
    pub min_free_bytes: u64,
    pub max_playback_bytes: u64,
    pub limits: RecordingLimits,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordingsConfigError {
    #[error("recordings.dir must be an absolute path")]
    RelativeDir,
    #[error("recordings.{0} must be an absolute path")]
    RelativePath(&'static str),
    #[error("recordings.dir belongs to the directory store: remove it or use store: directory")]
    DirWithS3,
    #[error("recordings.s3 and recordings.staging_dir belong to store: s3")]
    S3OptionsWithDirectory,
    #[error("store: s3 needs a recordings.s3 section")]
    S3SectionMissing,
    #[error("recordings.s3.access_key_file and secret_key_file must be set together")]
    CredentialFilesIncomplete,
    #[error("recordings.s3.{0} is out of range")]
    S3OutOfRange(&'static str),
    #[error("recordings.s3: {0}")]
    S3(#[from] S3ConfigError),
    #[error("recordings.{field} must be between {min} and {max}")]
    OutOfRange {
        field: &'static str,
        min: u64,
        max: u64,
    },
}

fn bounded(
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
) -> Result<u64, RecordingsConfigError> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(RecordingsConfigError::OutOfRange { field, min, max })
    }
}

fn narrow(
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
) -> Result<usize, RecordingsConfigError> {
    let max = max.min(widen(usize::MAX));
    bounded(field, value, min, max).and_then(|value| {
        usize::try_from(value).map_err(|_| RecordingsConfigError::OutOfRange { field, min, max })
    })
}

fn absolute(field: &'static str, path: PathBuf) -> Result<PathBuf, RecordingsConfigError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(RecordingsConfigError::RelativePath(field))
    }
}

impl S3Section {
    fn into_settings(self, staging_dir: PathBuf) -> Result<S3Settings, RecordingsConfigError> {
        let credential_files = match (self.access_key_file, self.secret_key_file) {
            (Some(access), Some(secret)) => Some((
                absolute("s3.access_key_file", access)?,
                absolute("s3.secret_key_file", secret)?,
            )),
            (None, None) => None,
            _ => return Err(RecordingsConfigError::CredentialFilesIncomplete),
        };
        let config = S3Config {
            endpoint: self.endpoint,
            region: self.region,
            bucket: self.bucket,
            prefix: self.prefix,
            path_style: self.path_style,
            allow_insecure_http: self.allow_insecure_http,
            sse: match self.sse {
                SseSection::None => Sse::None,
                SseSection::Aes256 => Sse::Aes256,
            },
            conditional_put: self.conditional_put,
            part_size: usize::try_from(self.part_size)
                .map_err(|_| RecordingsConfigError::S3OutOfRange("part_size"))?,
            upload_deadline: Duration::from_secs(self.upload_deadline_secs),
        };
        config.validate()?;
        Ok(S3Settings {
            config,
            staging_dir,
            credential_files,
        })
    }
}

impl RecordingsSection {
    pub fn into_settings(
        self,
        data_dir: &Path,
    ) -> Result<Option<RecordingsSettings>, RecordingsConfigError> {
        let max_uploads_total = narrow(
            "max_uploads_total",
            self.max_uploads_total,
            1,
            MAX_UPLOADS_LIMIT,
        )?;
        let max_uploads_per_node = narrow(
            "max_uploads_per_node",
            self.max_uploads_per_node,
            1,
            widen(max_uploads_total),
        )?;
        let max_pending_bytes_total = bounded(
            "max_pending_bytes_total",
            self.max_pending_bytes_total,
            1,
            u64::MAX,
        )?;
        let max_pending_bytes_per_node = bounded(
            "max_pending_bytes_per_node",
            self.max_pending_bytes_per_node,
            1,
            max_pending_bytes_total,
        )?;
        let max_pending_bytes = narrow(
            "max_pending_bytes",
            self.max_pending_bytes,
            1,
            max_pending_bytes_per_node,
        )?;
        let idle_timeout_secs = bounded(
            "idle_timeout_secs",
            self.idle_timeout_secs,
            MIN_IDLE_TIMEOUT_SECS,
            MAX_IDLE_TIMEOUT_SECS,
        )?;
        let store_retry_secs = bounded(
            "store_retry_secs",
            self.store_retry_secs,
            1,
            MAX_STORE_RETRY_SECS,
        )?;
        let max_store_commits = narrow(
            "max_store_commits",
            self.max_store_commits,
            1,
            MAX_STORE_COMMITS_LIMIT,
        )?;
        let max_wait_secs = bounded(
            "max_wait_secs",
            self.max_wait_secs,
            store_retry_secs,
            MAX_WAIT_LIMIT_SECS,
        )?;
        let max_chunk_compressed = narrow(
            "max_chunk_compressed",
            self.max_chunk_compressed,
            1,
            MAX_CHUNK_COMPRESSED_LIMIT,
        )?;
        let max_chunk_raw = bounded("max_chunk_raw", self.max_chunk_raw, 1, MAX_CHUNK_RAW_LIMIT)?;
        let max_chunks = bounded("max_chunks", self.max_chunks, 1, u64::MAX)?;
        let max_total_raw = bounded("max_total_raw", self.max_total_raw, 1, u64::MAX)?;
        let max_playback_bytes = bounded(
            "max_playback_bytes",
            self.max_playback_bytes,
            MIN_PLAYBACK_BYTES,
            MAX_PLAYBACK_BYTES,
        )?;
        let store = match self.store {
            StoreKind::Directory => {
                if self.s3.is_some() || self.staging_dir.is_some() {
                    return Err(RecordingsConfigError::S3OptionsWithDirectory);
                }
                let Some(dir) = self.dir else {
                    return Ok(None);
                };
                if !dir.is_absolute() {
                    return Err(RecordingsConfigError::RelativeDir);
                }
                StoreSettings::Directory { dir }
            }
            StoreKind::S3 => {
                if self.dir.is_some() {
                    return Err(RecordingsConfigError::DirWithS3);
                }
                let section = self.s3.ok_or(RecordingsConfigError::S3SectionMissing)?;
                let staging_dir = match self.staging_dir {
                    Some(dir) => absolute("staging_dir", dir)?,
                    None => data_dir.join(DEFAULT_STAGING_DIR),
                };
                StoreSettings::S3(Box::new(section.into_settings(staging_dir)?))
            }
        };
        Ok(Some(RecordingsSettings {
            store,
            min_free_bytes: self.min_free_bytes,
            max_playback_bytes,
            limits: RecordingLimits {
                chunk: Limits {
                    max_chunk_compressed,
                    max_chunk_raw,
                    max_chunks,
                    max_total_raw,
                    max_pending_bytes,
                },
                max_uploads_per_node,
                max_uploads_total,
                max_pending_bytes_per_node,
                max_pending_bytes_total,
                idle_timeout: Duration::from_secs(idle_timeout_secs),
                store_retry: Duration::from_secs(store_retry_secs),
                max_store_commits,
                max_wait: Duration::from_secs(max_wait_secs),
            },
        }))
    }
}

impl RecordingsSettings {
    fn directory_limits(&self) -> DirectoryLimits {
        DirectoryLimits {
            min_free_bytes: self.min_free_bytes,
            max_total_raw: self.limits.chunk.max_total_raw,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingsStartError {
    #[error("cannot prepare the recording directory {}: {source}", path.display())]
    Directory {
        path: PathBuf,
        #[source]
        source: RecordingStoreError,
    },
    #[error("recording credentials: {0}")]
    Credentials(#[source] S3ConfigError),
    #[error("cannot set up the recording object store client: {0}")]
    Client(#[source] S3ConfigError),
    #[error("the recording object store check failed: {0}")]
    Probe(#[from] ProbeError),
    #[error("the recording object store check did not finish")]
    ProbeTask,
    #[error(transparent)]
    Recover(#[from] ControlError),
    #[error("recovering staged recordings did not finish")]
    RecoverTask,
    #[error("cannot recover staged recordings: {0}")]
    RecoverStaged(#[source] RecordingStoreError),
}

#[derive(Clone)]
enum Backend {
    Directory(Arc<DirectorySink>),
    S3(Arc<S3Sink>),
}

#[derive(Clone)]
pub struct PreparedRecordings {
    pub settings: RecordingSettings,
    backend: Backend,
    path: PathBuf,
}

impl PreparedRecordings {
    pub fn for_s3_sink(
        sink: Arc<S3Sink>,
        limits: RecordingLimits,
        path: PathBuf,
    ) -> PreparedRecordings {
        PreparedRecordings {
            settings: RecordingSettings {
                sink: sink.clone(),
                limits,
            },
            backend: Backend::S3(sink),
            path,
        }
    }
}

pub type EnvText<'a> = &'a dyn Fn(&str) -> Option<String>;

fn load_credentials(
    settings: &S3Settings,
    env: EnvText<'_>,
) -> Result<Credentials, RecordingsStartError> {
    match &settings.credential_files {
        Some((access, secret)) => Credentials::from_files(access, secret),
        None => Credentials::from_env(env),
    }
    .map_err(RecordingsStartError::Credentials)
}

fn staging_sink(
    settings: &RecordingsSettings,
    s3: &S3Settings,
) -> Result<DirectorySink, RecordingsStartError> {
    DirectorySink::create(&s3.staging_dir, settings.directory_limits()).map_err(|source| {
        RecordingsStartError::Directory {
            path: s3.staging_dir.clone(),
            source,
        }
    })
}

pub fn prepare(
    settings: &RecordingsSettings,
    env: EnvText<'_>,
) -> Result<PreparedRecordings, RecordingsStartError> {
    match &settings.store {
        StoreSettings::Directory { dir } => {
            let directory =
                DirectorySink::create(dir, settings.directory_limits()).map_err(|source| {
                    RecordingsStartError::Directory {
                        path: dir.clone(),
                        source,
                    }
                })?;
            let directory = Arc::new(directory);
            Ok(PreparedRecordings {
                settings: RecordingSettings {
                    sink: directory.clone(),
                    limits: settings.limits,
                },
                backend: Backend::Directory(directory),
                path: dir.clone(),
            })
        }
        StoreSettings::S3(s3) => {
            let credentials = load_credentials(s3, env)?;
            let staging = staging_sink(settings, s3)?;
            let sink = S3Sink::connect(
                &s3.config,
                &credentials,
                staging,
                tokio::runtime::Handle::current(),
            )
            .map_err(RecordingsStartError::Client)?;
            let sink = Arc::new(sink);
            Ok(PreparedRecordings {
                settings: RecordingSettings {
                    sink: sink.clone(),
                    limits: settings.limits,
                },
                backend: Backend::S3(sink),
                path: s3.staging_dir.clone(),
            })
        }
    }
}

pub async fn probe(prepared: &PreparedRecordings) -> Result<(), RecordingsStartError> {
    let Backend::S3(sink) = &prepared.backend else {
        return Ok(());
    };
    let sink = sink.clone();
    let probed = tokio::task::spawn_blocking(move || sink.probe())
        .await
        .map_err(|_| RecordingsStartError::ProbeTask)?;
    match probed {
        Ok(()) => Ok(()),
        Err(ProbeError::Unreachable(reason)) => {
            tracing::warn!(
                target: "jaunt::daemon",
                reason,
                retry_every_secs = RETRY_INTERVAL.as_secs(),
                "the recording object store is not reachable now: recordings stay staged on disk and the daemon retries storing them every few minutes"
            );
            Ok(())
        }
        Err(refused) => Err(RecordingsStartError::Probe(refused)),
    }
}

pub async fn recover(
    prepared: &PreparedRecordings,
    control: &Control,
) -> Result<(), RecordingsStartError> {
    if let Backend::S3(sink) = &prepared.backend {
        publish_staged(sink, control).await?;
    }
    let recovered = control.recover_recordings().await?;
    let leftovers = match &prepared.backend {
        Backend::Directory(directory) => {
            directory.remove_leftovers_except(&recovered.left_receiving)
        }
        Backend::S3(sink) => sink
            .staging()
            .remove_leftovers_except(&recovered.left_receiving),
    }
    .map_err(|source| RecordingsStartError::Directory {
        path: prepared.path.clone(),
        source,
    })?;
    if recovered.salvaged > 0
        || recovered.failed > 0
        || leftovers.parts > 0
        || leftovers.orphan_casts > 0
        || !recovered.left_receiving.is_empty()
    {
        tracing::warn!(
            target: "jaunt::daemon",
            salvaged = recovered.salvaged,
            failed = recovered.failed,
            kept_receiving = recovered.left_receiving.len(),
            parts = leftovers.parts,
            orphan_casts = leftovers.orphan_casts,
            "recordings interrupted by the last stop were stored as incomplete or discarded; the ones the object store could not take stay staged"
        );
    }
    Ok(())
}

async fn publish_staged(sink: &Arc<S3Sink>, control: &Control) -> Result<(), RecordingsStartError> {
    let sink = sink.clone();
    let staged = tokio::task::spawn_blocking(move || sink.recover_pending())
        .await
        .map_err(|_| RecordingsStartError::RecoverTask)?
        .map_err(RecordingsStartError::RecoverStaged)?;
    if staged.published > 0 || staged.deferred > 0 || staged.refused > 0 || staged.quarantined > 0 {
        tracing::warn!(
            target: "jaunt::daemon",
            published = staged.published,
            deferred = staged.deferred,
            refused = staged.refused,
            quarantined = staged.quarantined,
            refused_ids = ?staged.refused_ids,
            quarantined_ids = ?staged.quarantined_ids,
            conflicted_ids = ?control.recordings_conflicted_ids(LISTED_IDS),
            held_ids = ?control.recordings_held_ids(LISTED_IDS),
            "recordings interrupted around the object store were finished or kept for the next attempt"
        );
    }
    Ok(())
}

const LISTED_IDS: usize = 20;

pub const RETRY_INTERVAL: Duration = Duration::from_secs(300);

pub async fn retry_staged(
    prepared: &PreparedRecordings,
    control: &Control,
) -> Result<(), RecordingsStartError> {
    let Backend::S3(sink) = &prepared.backend else {
        return Ok(());
    };
    publish_staged(sink, control).await?;
    let recovered = control.recover_recordings().await?;
    if recovered.adopted > 0 || recovered.salvaged > 0 || recovered.failed > 0 {
        tracing::warn!(
            target: "jaunt::daemon",
            adopted = recovered.adopted,
            salvaged = recovered.salvaged,
            failed = recovered.failed,
            "recordings that waited for the object store were stored"
        );
    }
    Ok(())
}

pub async fn every<F, Fut>(interval: Duration, mut tick: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        tick().await;
    }
}

pub const SCAN_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

pub struct Maintenance {
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Maintenance {
    pub fn stop(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

async fn scan_once(sink: &Arc<S3Sink>, now: &(dyn Fn() -> i64 + Send + Sync)) {
    let sweeper = sink.clone();
    let moment = now();
    let scan = tokio::task::spawn_blocking(move || {
        sweeper.sweep_orphans(moment, jaunt_recording_s3::ScanBudget::default())
    })
    .await;
    match scan {
        Ok(Ok(swept)) => {
            if swept.removed > 0 || swept.truncated {
                tracing::warn!(target: "jaunt::daemon", scanned = swept.scanned, removed = swept.removed, truncated = swept.truncated, "the recording object store was scanned for cast objects without a manifest");
            }
        }
        Ok(Err(err)) => {
            tracing::warn!(target: "jaunt::daemon", error = %err, "the scan for cast objects without a manifest did not finish");
        }
        Err(_) => {
            tracing::warn!(target: "jaunt::daemon", "the scan for cast objects without a manifest panicked");
        }
    }
}

pub fn start_scans(
    sink: Arc<S3Sink>,
    interval: Duration,
    now: impl Fn() -> i64 + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        scan_once(&sink, &now).await;
        every(interval, || scan_once(&sink, &now)).await;
    })
}

pub fn start_maintenance(
    prepared: Option<&PreparedRecordings>,
    control: &Control,
    interval: Duration,
    scan_interval: Duration,
) -> Maintenance {
    let Some(prepared) = prepared else {
        return Maintenance { tasks: Vec::new() };
    };
    let Backend::S3(sink) = &prepared.backend else {
        return Maintenance { tasks: Vec::new() };
    };
    let scans = start_scans(sink.clone(), scan_interval, || {
        jaunt_audit::Timestamp::now().millis() / 1000
    });
    let retrier = prepared.clone();
    let control = control.clone();
    let retries = tokio::spawn(async move {
        every(interval, || async {
            if let Err(err) = retry_staged(&retrier, &control).await {
                tracing::warn!(target: "jaunt::daemon", error = %err, "storing the recordings that wait for the object store did not succeed");
            }
        })
        .await;
    });
    Maintenance {
        tasks: vec![scans, retries],
    }
}

const OPEN_FILES_WANTED: u64 = 65_536;

fn open_files_target(current: Option<u64>, maximum: Option<u64>) -> Option<u64> {
    let wanted = maximum.map_or(OPEN_FILES_WANTED, |hard| hard.min(OPEN_FILES_WANTED));
    current.filter(|soft| *soft < wanted).map(|_| wanted)
}

pub fn raise_open_file_limit() {
    let limit = getrlimit(Resource::Nofile);
    let Some(target) = open_files_target(limit.current, limit.maximum) else {
        return;
    };
    let raised = setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(target),
            maximum: limit.maximum,
        },
    );
    match raised {
        Ok(()) => tracing::info!(
            target: "jaunt::daemon",
            from = limit.current,
            to = target,
            "raised the open file limit for recording uploads"
        ),
        Err(err) => tracing::warn!(
            target: "jaunt::daemon",
            error = %err,
            current = limit.current,
            "could not raise the open file limit: each recording upload holds two files"
        ),
    }
}

#[derive(Debug, thiserror::Error)]
enum VerifyCommandError {
    #[error("{0}")]
    Config(String),
    #[error("recordings are not configured: recording is disabled")]
    Disabled,
    #[error("{0:?} is not a session id")]
    SessionId(String),
    #[error("the database {} does not exist: start the daemon once to create it", .0.display())]
    NoDatabase(PathBuf),
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("cannot open the database: {0}")]
    Store(#[source] StoreError),
    #[error("no recording is stored for session {0}")]
    NotFound(String),
    #[error("the session of the recording cannot name its location")]
    Location,
    #[error("cannot open the recording directory: {0}")]
    Directory(#[source] RecordingStoreError),
    #[error("recording credentials: {0}")]
    Credentials(#[source] S3ConfigError),
    #[error("cannot set up the recording object store client: {0}")]
    Client(#[source] S3ConfigError),
    #[error("recording {session_id} failed verification: {reason}")]
    Failed { session_id: String, reason: String },
    #[error("cannot write the output: {0}")]
    Output(#[source] io::Error),
}

impl VerifyCommandError {
    fn exit_code(&self) -> u8 {
        match self {
            VerifyCommandError::SessionId(_) => EXIT_USAGE,
            _ => EXIT_FAILED,
        }
    }
}

pub fn verify_command(config_path: &Path, session_id: &str) -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    ExitCode::from(verify(config_path, session_id, &mut stdout, &mut stderr))
}

pub fn verify(
    config_path: &Path,
    session_id: &str,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match attempt_verify(config_path, session_id, stdout) {
        Ok(()) => EXIT_OK,
        Err(err) => {
            if writeln!(stderr, "{err}").is_err() {
                return EXIT_FAILED;
            }
            err.exit_code()
        }
    }
}

fn attempt_verify(
    config_path: &Path,
    session_id: &str,
    stdout: &mut dyn Write,
) -> Result<(), VerifyCommandError> {
    if !is_session_id(session_id) {
        return Err(VerifyCommandError::SessionId(session_id.to_owned()));
    }
    let config = config::load(config_path).map_err(VerifyCommandError::Config)?;
    let settings = config
        .recordings
        .into_settings(&config.data_dir)
        .map_err(|err| VerifyCommandError::Config(err.to_string()))?
        .ok_or(VerifyCommandError::Disabled)?;
    let database = config.data_dir.join(DATABASE_FILE);
    if !database.is_file() {
        return Err(VerifyCommandError::NoDatabase(database));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(VerifyCommandError::Runtime)?;
    let (row, session) = runtime.block_on(async {
        let store = Store::open(&database)
            .await
            .map_err(VerifyCommandError::Store)?;
        store.migrate().await.map_err(VerifyCommandError::Store)?;
        let row = store
            .recordings()
            .get(session_id)
            .await
            .map_err(VerifyCommandError::Store)?;
        let session = store
            .sessions()
            .get(session_id)
            .await
            .map_err(VerifyCommandError::Store)?;
        Ok::<_, VerifyCommandError>((row, session))
    })?;
    let row = row.ok_or_else(|| VerifyCommandError::NotFound(session_id.to_owned()))?;
    let started = session
        .and_then(|session| session.authorized_at)
        .ok_or(VerifyCommandError::Location)?;
    let key = RecordingKey::new(session_id, started).map_err(|_| VerifyCommandError::Location)?;
    let (sink, _reader_runtime): (Box<dyn RecordingSink>, Option<tokio::runtime::Runtime>) =
        match &settings.store {
            StoreSettings::Directory { dir } => (
                Box::new(
                    DirectorySink::open_existing(dir, settings.directory_limits())
                        .map_err(VerifyCommandError::Directory)?,
                ),
                None,
            ),
            StoreSettings::S3(s3) => {
                let reader_runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(VerifyCommandError::Runtime)?;
                let credentials = load_credentials(s3, &|name| std::env::var(name).ok()).map_err(
                    |err| match err {
                        RecordingsStartError::Credentials(inner) => {
                            VerifyCommandError::Credentials(inner)
                        }
                        other => VerifyCommandError::Config(other.to_string()),
                    },
                )?;
                let sink = S3Sink::connect_reader(
                    &s3.config,
                    &credentials,
                    reader_runtime.handle().clone(),
                )
                .map_err(VerifyCommandError::Client)?;
                (Box::new(sink), Some(reader_runtime))
            }
        };
    let verified =
        verify_stored(sink.as_ref(), &key, &row).map_err(|failure| VerifyCommandError::Failed {
            session_id: session_id.to_owned(),
            reason: failure.to_string(),
        })?;
    writeln!(
        stdout,
        "recording {session_id} verified: {} chunks, {} bytes, {}, cast sha256 {}",
        verified.chunks,
        verified.raw_bytes,
        if verified.incomplete {
            "incomplete"
        } else {
            "complete"
        },
        verified.cast_sha256.as_deref().unwrap_or("none")
    )
    .map_err(VerifyCommandError::Output)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingKey, RecordingSink};
    use jaunt_control::RecordingLimits;
    use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
    use jaunt_store::{
        ActivateSession, NewCertificate, NewSession, NewUser, Store, StoredRecording,
    };
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;

    use super::{
        RecordingsConfigError, RecordingsSection, StoreSettings, open_files_target, prepare, verify,
    };

    const NOW: i64 = 1_764_028_800;
    const NODE: &str = "node-a";
    const DATA_DIR: &str = "/var/lib/jaunt";

    fn section(text: &str) -> Result<RecordingsSection, String> {
        serde_saphyr::from_str(text).map_err(|err| err.to_string())
    }

    #[test]
    fn the_section_is_off_without_a_directory_and_takes_the_documented_defaults() {
        assert_eq!(
            RecordingsSection::default().into_settings(Path::new(DATA_DIR)),
            Ok(None)
        );
        let settings = section("dir: /var/lib/jaunt/recordings\n")
            .unwrap()
            .into_settings(Path::new(DATA_DIR))
            .unwrap()
            .unwrap();
        assert_eq!(settings.limits, RecordingLimits::default());
        assert_eq!(settings.min_free_bytes, 1024 * 1024 * 1024);
        assert_eq!(settings.limits.chunk.max_pending_bytes, 64 * 1024 * 1024);
        assert_eq!(settings.limits.max_uploads_per_node, 64);
        assert_eq!(settings.limits.max_uploads_total, 1024);
        assert_eq!(settings.limits.idle_timeout.as_secs(), 7200);
        assert_eq!(settings.limits.chunk.max_chunks, 200_000);
        assert_eq!(settings.max_playback_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn the_section_is_strict_and_bounded() {
        assert!(section("dir: /r\nextra: 1\n").is_err());
        assert_eq!(
            section("dir: recordings\n")
                .unwrap()
                .into_settings(Path::new(DATA_DIR)),
            Err(RecordingsConfigError::RelativeDir)
        );
        for (text, field) in [
            ("max_uploads_per_node: 0\n", "max_uploads_per_node"),
            (
                "max_uploads_total: 8\nmax_uploads_per_node: 9\n",
                "max_uploads_per_node",
            ),
            ("max_pending_bytes_total: 0\n", "max_pending_bytes_total"),
            (
                "max_pending_bytes_per_node: 2048\nmax_pending_bytes: 4096\n",
                "max_pending_bytes",
            ),
            ("idle_timeout_secs: 59\n", "idle_timeout_secs"),
            ("store_retry_secs: 0\n", "store_retry_secs"),
            ("store_retry_secs: 86401\n", "store_retry_secs"),
            ("max_store_commits: 0\n", "max_store_commits"),
            ("max_store_commits: 1025\n", "max_store_commits"),
            (
                "store_retry_secs: 600\nmax_wait_secs: 599\n",
                "max_wait_secs",
            ),
            ("max_wait_secs: 2592001\n", "max_wait_secs"),
            ("max_chunk_compressed: 16777217\n", "max_chunk_compressed"),
            ("max_chunk_raw: 0\n", "max_chunk_raw"),
            ("max_chunks: 0\n", "max_chunks"),
            ("max_total_raw: 0\n", "max_total_raw"),
            ("max_playback_bytes: 1048575\n", "max_playback_bytes"),
            ("max_playback_bytes: 536870913\n", "max_playback_bytes"),
        ] {
            let err = section(&format!("dir: /r\n{text}"))
                .unwrap()
                .into_settings(Path::new(DATA_DIR))
                .err()
                .unwrap();
            assert!(
                matches!(err, RecordingsConfigError::OutOfRange { field: found, .. } if found == field),
                "{text}: {err}"
            );
        }
    }

    const S3_SECTION: &str = "store: s3\ns3:\n  region: eu-west-1\n  bucket: jaunt-recordings\n";

    fn s3_settings(text: &str) -> Result<super::RecordingsSettings, RecordingsConfigError> {
        section(text)
            .unwrap()
            .into_settings(Path::new(DATA_DIR))
            .map(Option::unwrap)
    }

    #[test]
    fn the_s3_store_takes_documented_defaults_and_keeps_credentials_out_of_the_yaml() {
        let settings = s3_settings(S3_SECTION).unwrap();
        let StoreSettings::S3(s3) = settings.store else {
            panic!("not the s3 store");
        };
        assert_eq!(
            s3.staging_dir,
            Path::new("/var/lib/jaunt/recording-staging")
        );
        assert_eq!(s3.credential_files, None);
        assert_eq!(s3.config.prefix, "recordings/");
        assert_eq!(s3.config.part_size, 8 * 1024 * 1024);
        assert_eq!(s3.config.upload_deadline.as_secs(), 120);
        assert!(s3.config.conditional_put && !s3.config.path_style);
        assert_eq!(s3.config.sse, jaunt_recording_s3::Sse::None);
        assert_eq!(s3.config.endpoint, None);

        let full = format!(
            "{S3_SECTION}  endpoint: https://s3.example.com\n  prefix: a/b/\n  path_style: true\n  sse: aes256\n  \
             part_size: 16777216\n  upload_deadline_secs: 30\n  access_key_file: /run/secrets/key\n  \
             secret_key_file: /run/secrets/secret\nstaging_dir: /var/stage\n"
        );
        let StoreSettings::S3(s3) = s3_settings(&full).unwrap().store else {
            panic!("not the s3 store");
        };
        assert_eq!(s3.staging_dir, Path::new("/var/stage"));
        assert_eq!(
            s3.credential_files,
            Some(("/run/secrets/key".into(), "/run/secrets/secret".into()))
        );
        assert_eq!(s3.config.sse, jaunt_recording_s3::Sse::Aes256);
        assert_eq!(s3.config.part_size, 16 * 1024 * 1024);
        for secret_in_yaml in ["access_key", "secret_key", "access_key_id", "password"] {
            let text = format!("{S3_SECTION}  {secret_in_yaml}: value\n");
            assert!(section(&text).is_err(), "{secret_in_yaml}");
        }
    }

    #[test]
    fn an_invalid_s3_configuration_refuses_to_start_with_a_clear_error() {
        let cases: [(String, RecordingsConfigError); 9] = [
            (
                "store: s3\n".to_owned(),
                RecordingsConfigError::S3SectionMissing,
            ),
            (
                format!("{S3_SECTION}dir: /r\n"),
                RecordingsConfigError::DirWithS3,
            ),
            (
                format!("{S3_SECTION}staging_dir: relative\n"),
                RecordingsConfigError::RelativePath("staging_dir"),
            ),
            (
                "dir: /r\nstaging_dir: /s\n".to_owned(),
                RecordingsConfigError::S3OptionsWithDirectory,
            ),
            (
                "dir: /r\ns3:\n  region: r\n  bucket: bbb\n".to_owned(),
                RecordingsConfigError::S3OptionsWithDirectory,
            ),
            (
                format!("{S3_SECTION}  access_key_file: /a\n"),
                RecordingsConfigError::CredentialFilesIncomplete,
            ),
            (
                format!("{S3_SECTION}  access_key_file: a\n  secret_key_file: /b\n"),
                RecordingsConfigError::RelativePath("s3.access_key_file"),
            ),
            (
                format!("{S3_SECTION}  endpoint: http://s3.example.com\n"),
                jaunt_recording_s3::ConfigError::InsecureEndpoint.into(),
            ),
            (
                format!("{S3_SECTION}  part_size: 1024\n"),
                jaunt_recording_s3::ConfigError::PartSize {
                    min: jaunt_recording_s3::MIN_PART_SIZE,
                    max: jaunt_recording_s3::MAX_PART_SIZE,
                }
                .into(),
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(
                section(&text).unwrap().into_settings(Path::new(DATA_DIR)),
                Err(expected),
                "{text}"
            );
        }
        assert!(section("store: gcs\n").is_err());
        assert!(section(&format!("{S3_SECTION}  sse: kms\n")).is_err());
    }

    fn verify_config(dir: &Path, extra: &str, secret_mode: u32) -> PathBuf {
        let access = dir.join("access");
        let secret = dir.join("secret");
        fs::write(&access, "AKIDVALUE").unwrap();
        fs::write(&secret, "secret-value-42").unwrap();
        fs::set_permissions(&access, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(secret_mode)).unwrap();
        let config = dir.join("jauntd.yaml");
        fs::write(
            &config,
            format!(
                "data_dir: {}\nrecordings:\n  store: s3\n  staging_dir: {}\n  s3:\n    region: eu-west-1\n    bucket: jaunt-recordings\n    \
                 access_key_file: {}\n    secret_key_file: {}\n{extra}",
                dir.display(),
                dir.join("staging").display(),
                access.display(),
                secret.display()
            ),
        )
        .unwrap();
        config
    }

    fn run_verify(config: &Path, id: &str) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = verify(config, id, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn credentials_with_loose_permissions_stop_the_verify_command_without_echoing_them() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session_id, _) = store_with_session(dir.path()).await;
        store
            .recordings()
            .begin(&session_id, NODE, NOW + 2)
            .await
            .unwrap();
        let config = verify_config(dir.path(), "", 0o644);
        let (code, _, err) = tokio::task::block_in_place(|| run_verify(&config, &session_id));
        assert_eq!(code, 1, "{err}");
        assert!(err.contains("readable by everyone"), "{err}");
        assert!(
            !err.contains("secret-value-42") && !err.contains("AKIDVALUE"),
            "{err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verifying_against_the_object_store_needs_no_staging_directory_and_creates_none() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session_id, _) = store_with_session(dir.path()).await;
        store
            .recordings()
            .begin(&session_id, NODE, NOW + 2)
            .await
            .unwrap();
        let config = verify_config(dir.path(), "", 0o600);
        let (code, _, err) = tokio::task::block_in_place(|| run_verify(&config, &session_id));
        assert_eq!(code, 1, "{err}");
        assert!(err.contains("never stored"), "{err}");
        assert!(!err.contains("directory"), "{err}");
        assert!(!dir.path().join("staging").exists());
    }

    fn minio_setting(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set: run just s3-tests"))
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs MinIO: run just s3-tests"]
    async fn the_verify_command_reads_a_recording_from_the_object_store_and_fails_after_one_flipped_bit()
     {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let (store, session_id, started) = store_with_session(dir.path()).await;
        let access = dir.path().join("access");
        let secret = dir.path().join("secret");
        fs::write(&access, minio_setting("JAUNT_S3_TEST_ACCESS_KEY")).unwrap();
        fs::write(&secret, minio_setting("JAUNT_S3_TEST_SECRET_KEY")).unwrap();
        for file in [&access, &secret] {
            fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let staging = dir.path().join("staging");
        let prefix = format!("verify-{}/", std::process::id());
        let config = dir.path().join("jauntd.yaml");
        let mut text = fs::File::create(&config).unwrap();
        write!(
            text,
            "data_dir: {}\nrecordings:\n  store: s3\n  staging_dir: {}\n  min_free_bytes: 0\n  s3:\n    region: us-east-1\n    bucket: {}\n    \
             endpoint: {}\n    prefix: {prefix}\n    path_style: true\n    allow_insecure_http: true\n    access_key_file: {}\n    \
             secret_key_file: {}\n",
            dir.path().display(),
            staging.display(),
            minio_setting("JAUNT_S3_TEST_BUCKET"),
            minio_setting("JAUNT_S3_TEST_ENDPOINT"),
            access.display(),
            secret.display()
        )
        .unwrap();
        drop(text);
        let loaded = crate::config::load(&config).unwrap();
        let settings = loaded
            .recordings
            .into_settings(&loaded.data_dir)
            .unwrap()
            .unwrap();
        let StoreSettings::S3(s3) = &settings.store else {
            panic!("not the s3 store");
        };
        let credentials = jaunt_recording_s3::Credentials::from_files(&access, &secret).unwrap();
        let sink = jaunt_recording_s3::S3Sink::connect(
            &s3.config,
            &credentials,
            DirectorySink::create(&staging, settings.directory_limits()).unwrap(),
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        let key = RecordingKey::new(&session_id, started).unwrap();
        let cast_line = b"[0.5,\"o\",\"hello\"]\n";
        let written = manifest(&session_id, u64::try_from(cast_line.len()).unwrap());
        let committed = {
            let key = key.clone();
            let written = written.clone();
            tokio::task::spawn_blocking(move || {
                let mut staged = sink.begin(&key).unwrap();
                staged.write(0, cast_line).unwrap();
                staged.commit(&written).unwrap()
            })
            .await
            .unwrap()
        };
        store
            .recordings()
            .begin(&session_id, NODE, NOW + 2)
            .await
            .unwrap();
        assert!(
            store
                .recordings()
                .mark_complete(&StoredRecording {
                    session_id: &session_id,
                    node_id: NODE,
                    chunks: 1,
                    raw_bytes: committed.cast_bytes,
                    digest: written.digest.as_deref(),
                    input_recorded: false,
                    dropped_chunks: 0,
                    location: &committed.location,
                    cast_sha256: committed.cast_sha256.as_deref(),
                    manifest_sha256: &committed.manifest_sha256,
                    now: NOW + 3,
                })
                .await
                .unwrap()
        );

        let (code, out, err) = tokio::task::block_in_place(|| run_verify(&config, &session_id));
        assert_eq!(code, 0, "{err}");
        assert!(
            out.contains("verified: 1 chunks, 18 bytes, complete"),
            "{out}"
        );

        let object_store = jaunt_recording_s3::build_store(&s3.config, &credentials).unwrap();
        let path = object_store::path::Path::parse(format!("{prefix}{}.cast", committed.location))
            .unwrap();
        let mut bytes = object_store::ObjectStoreExt::get(object_store.as_ref(), &path)
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec();
        bytes[7] ^= 0x04;
        object_store::ObjectStoreExt::put(
            object_store.as_ref(),
            &path,
            object_store::PutPayload::from(bytes),
        )
        .await
        .unwrap();
        let (code, _, err) = tokio::task::block_in_place(|| run_verify(&config, &session_id));
        assert_eq!(code, 1);
        assert!(err.contains("does not match its stored sha256"), "{err}");
    }

    async fn store_with_session(data_dir: &Path) -> (Store, String, i64) {
        let path = data_dir.join("jaunt.db");
        let store = Store::open(&path).await.unwrap();
        store.migrate().await.unwrap();
        let raw = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, ssh_host_public_key, \
             tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, created_at) \
             VALUES (?, 'web', '{}', 'h', 't', 's', 'f', 'f', 'active', 'cli:root', 1)",
        )
        .bind(NODE)
        .execute(&raw)
        .await
        .unwrap();
        let user = store
            .users()
            .upsert(
                &NewUser {
                    issuer: "https://idp.example".to_owned(),
                    subject: "alice".to_owned(),
                    email: "alice@example.com".to_owned(),
                    username: "alice".to_owned(),
                    display_name: None,
                    groups: Vec::new(),
                },
                NOW,
            )
            .await
            .unwrap();
        let serial = store.certificates().allocate_serial().await.unwrap();
        store
            .certificates()
            .record(&NewCertificate {
                serial,
                user_id: user.id.clone(),
                kind: "user".to_owned(),
                key_id: format!("jaunt:alice@example.com:{serial}"),
                valid_after: NOW - 60,
                valid_before: NOW + 3600,
                issued_at: NOW,
                ca_fingerprint: None,
                host_trust_id: None,
                subject_fingerprint: None,
            })
            .await
            .unwrap();
        let session = store
            .sessions()
            .create(
                &NewSession {
                    user_id: user.id.clone(),
                    serial,
                    node_id: NODE.to_owned(),
                    ttl_secs: 60,
                },
                NOW,
            )
            .await
            .unwrap();
        store
            .sessions()
            .activate(ActivateSession {
                id: &session.id,
                node_id: NODE,
                user_id: &user.id,
                serial,
                login: "deploy",
                max_duration_secs: 3600,
                pty: true,
                record_input: false,
                now: NOW + 1,
            })
            .await
            .unwrap()
            .unwrap();
        (store, session.id, NOW + 1)
    }

    fn manifest(session_id: &str, raw_bytes: u64) -> SessionManifest {
        SessionManifest {
            version: MANIFEST_VERSION,
            session_id: session_id.to_owned(),
            kind: SessionKind::Shell,
            node: NODE.to_owned(),
            user: "user".to_owned(),
            login: "deploy".to_owned(),
            started_at: 1,
            ended_at: Some(2),
            exit_status: Some(0),
            command: None,
            bytes_out: raw_bytes,
            bytes_in: 0,
            input_recorded: false,
            chunks: 1,
            raw_bytes,
            incomplete: false,
            dropped_chunks: 0,
            digest: Some("a".repeat(64)),
        }
    }

    #[test]
    fn startup_creates_the_directory_with_its_mode_and_probes_renaming() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("fresh");
        let settings = section(&format!("dir: {}\n", fresh.display()))
            .unwrap()
            .into_settings(Path::new(DATA_DIR))
            .unwrap()
            .unwrap();
        let prepared = prepare(&settings, &|_| None).unwrap();
        assert_eq!(prepared.settings.limits, settings.limits);
        assert_eq!(
            fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o750
        );
        assert!(fs::read_dir(&fresh).unwrap().next().is_none());
    }

    #[test]
    fn the_open_file_limit_is_raised_towards_the_hard_limit_only() {
        for (current, maximum, expected) in [
            (Some(1024), Some(1_048_576), Some(65_536)),
            (Some(1024), Some(4096), Some(4096)),
            (Some(1024), None, Some(65_536)),
            (Some(65_536), None, None),
            (Some(100_000), Some(200_000), None),
            (None, None, None),
        ] {
            assert_eq!(
                open_files_target(current, maximum),
                expected,
                "{current:?} {maximum:?}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_verify_command_passes_on_a_stored_recording_and_fails_after_one_flipped_bit() {
        let dir = tempfile::tempdir().unwrap();
        let (store, session_id, started) = store_with_session(dir.path()).await;
        let root = dir.path().join("recordings");
        let sink = DirectorySink::create(
            &root,
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1024,
            },
        )
        .unwrap();
        let key = RecordingKey::new(&session_id, started).unwrap();
        let mut staged = sink.begin(&key).unwrap();
        let cast_line = b"[0.5,\"o\",\"hello\"]\n";
        staged.write(0, cast_line).unwrap();
        let written = manifest(&session_id, u64::try_from(cast_line.len()).unwrap());
        let committed = staged.commit(&written).unwrap();
        store
            .recordings()
            .begin(&session_id, NODE, NOW + 2)
            .await
            .unwrap();
        assert!(
            store
                .recordings()
                .mark_complete(&StoredRecording {
                    session_id: &session_id,
                    node_id: NODE,
                    chunks: 1,
                    raw_bytes: committed.cast_bytes,
                    digest: written.digest.as_deref(),
                    input_recorded: false,
                    dropped_chunks: 0,
                    location: &committed.location,
                    cast_sha256: committed.cast_sha256.as_deref(),
                    manifest_sha256: &committed.manifest_sha256,
                    now: NOW + 3,
                })
                .await
                .unwrap()
        );
        let config = dir.path().join("jauntd.yaml");
        fs::write(
            &config,
            format!(
                "data_dir: {}\nrecordings:\n  dir: {}\n",
                dir.path().display(),
                root.display()
            ),
        )
        .unwrap();

        let run = |id: &str| {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let code = verify(&config, id, &mut out, &mut err);
            (
                code,
                String::from_utf8(out).unwrap(),
                String::from_utf8(err).unwrap(),
            )
        };
        let (code, out, _) = tokio::task::block_in_place(|| run(&session_id));
        assert_eq!(code, 0);
        assert!(
            out.contains("verified: 1 chunks, 18 bytes, complete"),
            "{out}"
        );

        let cast = root.join(format!("{}.cast", committed.location));
        let mut bytes = fs::read(&cast).unwrap();
        bytes[7] ^= 0x04;
        fs::write(&cast, &bytes).unwrap();
        let (code, _, err) = tokio::task::block_in_place(|| run(&session_id));
        assert_eq!(code, 1);
        assert!(err.contains("does not match its stored sha256"), "{err}");

        let (code, _, err) = tokio::task::block_in_place(|| run("../etc/passwd"));
        assert_eq!(code, 2, "{err}");
    }
}
