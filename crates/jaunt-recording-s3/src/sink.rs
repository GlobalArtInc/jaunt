use std::collections::{HashMap, HashSet};
use std::io::Read;
#[cfg(feature = "testing")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::TryStreamExt;
use jaunt_audit::{
    CastProof, Committed, DirectoryLimits, DirectorySink, DirectoryStaged, Identity, LocalProof,
    MAX_MANIFEST_BYTES, PendingManifest, RecordingKey, RecordingSink, RecordingStoreError,
    Resolution, StagedRecording, StoredRecording, cast_sha256, manifest_bytes, read_store_proof,
    resolve_existing,
};
use jaunt_record::SessionManifest;
use object_store::ObjectStore;
use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey, Checksum, S3ConditionalPut};
use object_store::{ClientOptions, RetryConfig};
use tokio::runtime::Handle;

use crate::config::{ConfigError, Credentials, S3Config, Sse};
use crate::remote::{
    CastReader, CastSource, Layout, ObjectKind, Remote, RemoteSettings, sha256_hex,
};
use crate::retry::{RemoteError, RetryPolicy, SystemTimer, Timer};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const SLOWEST_UPLOAD_BYTES_PER_SEC: u64 = 256 * 1024;
pub const DEFAULT_BREAKER_WINDOW: Duration = Duration::from_secs(15);
pub const ORPHAN_AGE_FLOOR_SECS: u64 = 3600;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROBE_DEADLINE: Duration = Duration::from_secs(10);
const SECONDS_PER_DAY: i64 = 86_400;
const PLACEHOLDER_SESSION: &str = "00000000-0000-4000-8000-000000000000";

#[derive(Clone)]
pub struct SinkOptions {
    pub prefix: String,
    pub part_size: usize,
    pub conditional_put: bool,
    pub retry: RetryPolicy,
    pub secrets: Vec<String>,
    pub breaker_window: Duration,
}

impl std::fmt::Debug for SinkOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkOptions")
            .field("prefix", &self.prefix)
            .field("part_size", &self.part_size)
            .field("conditional_put", &self.conditional_put)
            .field("retry", &self.retry)
            .field("breaker_window", &self.breaker_window)
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

impl SinkOptions {
    pub fn from_config(config: &S3Config, credentials: &Credentials) -> SinkOptions {
        SinkOptions {
            prefix: config.prefix.clone(),
            part_size: config.part_size,
            conditional_put: config.conditional_put,
            retry: RetryPolicy::new(config.upload_deadline),
            secrets: credentials.secrets(),
            breaker_window: DEFAULT_BREAKER_WINDOW,
        }
    }
}

pub fn request_timeout(part_size: usize) -> Duration {
    let slowest = u64::try_from(part_size).unwrap_or(u64::MAX) / SLOWEST_UPLOAD_BYTES_PER_SEC;
    REQUEST_TIMEOUT.max(Duration::from_secs(slowest))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanBudget {
    pub max_objects: u64,
    pub deadline: Duration,
}

impl Default for ScanBudget {
    fn default() -> ScanBudget {
        ScanBudget {
            max_objects: 500_000,
            deadline: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OrphanSweep {
    pub scanned: u64,
    pub removed: u64,
    pub truncated: bool,
}

pub const QUARANTINE_AFTER_ATTEMPTS: u32 = 5;
pub const LISTED_IDS: usize = 20;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct S3Recovery {
    pub live: u64,
    pub published: u64,
    pub deferred: u64,
    pub refused: u64,
    pub quarantined: u64,
    pub refused_ids: Vec<String>,
    pub quarantined_ids: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error(
        "the object store refused the credentials or the access ({0}): they need ListBucket, GetObject, PutObject, DeleteObject and AbortMultipartUpload on the bucket"
    )]
    Denied(String),
    #[error(
        "the object store rejects the requests for good, check the endpoint and the encryption settings: {0}"
    )]
    Rejected(String),
    #[error("the bucket does not exist or is not visible to these credentials")]
    BucketMissing,
    #[error("the object store could not be reached: {0}")]
    Unreachable(String),
}

#[derive(Debug, Default)]
pub struct LiveKeys {
    counts: Mutex<HashMap<String, usize>>,
}

impl LiveKeys {
    fn counts(&self) -> std::sync::MutexGuard<'_, HashMap<String, usize>> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn register(&self, session_id: &str) {
        *self.counts().entry(session_id.to_owned()).or_default() += 1;
    }

    fn unregister(&self, session_id: &str) {
        let mut counts = self.counts();
        if let Some(count) = counts.get_mut(session_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(session_id);
            }
        }
    }

    pub fn contains(&self, session_id: &str) -> bool {
        self.counts().contains_key(session_id)
    }
}

pub struct S3Sink {
    remote: Arc<Remote>,
    layout: Layout,
    staging: Arc<DirectorySink>,
    live: Arc<LiveKeys>,
    refused: Arc<Mutex<HashSet<String>>>,
    #[cfg(feature = "testing")]
    hash_runs: AtomicU64,
    #[cfg(feature = "testing")]
    hash_faults: AtomicU64,
    #[cfg(feature = "testing")]
    open_faults: Arc<AtomicU64>,
    invalid: Mutex<HashMap<String, u32>>,
    scratch: Option<tempfile::TempDir>,
}

impl std::fmt::Debug for S3Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Sink")
            .field("layout", &self.layout)
            .finish()
    }
}

fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none()
        && rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
    {
        tracing::debug!(target: "jaunt::recordings", "another thread installed the TLS crypto provider first");
    }
}

pub fn build_store(
    config: &S3Config,
    credentials: &Credentials,
) -> Result<Arc<dyn ObjectStore>, ConfigError> {
    config.validate()?;
    ensure_crypto_provider();
    let mut builder = AmazonS3Builder::new()
        .with_region(&config.region)
        .with_bucket_name(&config.bucket)
        .with_access_key_id(&credentials.access_key)
        .with_secret_access_key(credentials.secret_key.expose())
        .with_virtual_hosted_style_request(!config.path_style)
        .with_checksum_algorithm(Checksum::SHA256)
        .with_retry(RetryConfig {
            max_retries: 0,
            ..RetryConfig::default()
        })
        .with_client_options(
            ClientOptions::new()
                .with_timeout(request_timeout(config.part_size))
                .with_connect_timeout(CONNECT_TIMEOUT)
                .with_allow_http(config.allow_insecure_http),
        );
    if let Some(endpoint) = &config.endpoint {
        builder = builder.with_endpoint(endpoint);
    }
    if let Some(token) = &credentials.session_token {
        builder = builder.with_token(token.expose());
    }
    if !config.conditional_put {
        builder = builder.with_conditional_put(S3ConditionalPut::Disabled);
    }
    if config.sse == Sse::Aes256 {
        let key: AmazonS3ConfigKey = "aws_server_side_encryption".parse().map_err(|_| {
            ConfigError::Client("server side encryption is not supported".to_owned())
        })?;
        builder = builder.with_config(key, "AES256");
    }
    let store = builder
        .build()
        .map_err(|error| ConfigError::Client(error.to_string()))?;
    Ok(Arc::new(store))
}

impl S3Sink {
    pub fn connect(
        config: &S3Config,
        credentials: &Credentials,
        staging: DirectorySink,
        handle: Handle,
    ) -> Result<S3Sink, ConfigError> {
        let store = build_store(config, credentials)?;
        Ok(S3Sink::with_store(
            store,
            SinkOptions::from_config(config, credentials),
            staging,
            handle,
            Arc::new(SystemTimer::new()),
        ))
    }

    pub fn with_store(
        store: Arc<dyn ObjectStore>,
        options: SinkOptions,
        staging: DirectorySink,
        handle: Handle,
        timer: Arc<dyn Timer>,
    ) -> S3Sink {
        S3Sink {
            remote: Arc::new(Remote::new(
                store,
                handle,
                timer,
                RemoteSettings {
                    policy: options.retry,
                    part_size: options.part_size,
                    conditional_put: options.conditional_put,
                    secrets: options.secrets,
                    breaker_window: options.breaker_window,
                },
            )),
            layout: Layout::new(&options.prefix),
            staging: Arc::new(staging),
            live: Arc::new(LiveKeys::default()),
            refused: Arc::new(Mutex::new(HashSet::new())),
            #[cfg(feature = "testing")]
            hash_runs: AtomicU64::new(0),
            #[cfg(feature = "testing")]
            hash_faults: AtomicU64::new(0),
            #[cfg(feature = "testing")]
            open_faults: Arc::new(AtomicU64::new(0)),
            invalid: Mutex::new(HashMap::new()),
            scratch: None,
        }
    }

    pub fn connect_reader(
        config: &S3Config,
        credentials: &Credentials,
        handle: Handle,
    ) -> Result<S3Sink, ConfigError> {
        let scratch = tempfile::tempdir().map_err(|err| {
            ConfigError::Client(format!("cannot create a scratch directory: {err}"))
        })?;
        let staging = DirectorySink::create(
            &scratch.path().join("staging"),
            DirectoryLimits {
                min_free_bytes: 0,
                max_total_raw: 1,
            },
        )
        .map_err(|err| ConfigError::Client(err.to_string()))?;
        let mut sink = S3Sink::connect(config, credentials, staging, handle)?;
        sink.scratch = Some(scratch);
        Ok(sink)
    }

    #[cfg(feature = "testing")]
    pub fn staged_hash_runs(&self) -> u64 {
        self.hash_runs.load(Ordering::SeqCst)
    }

    #[cfg(feature = "testing")]
    pub fn fail_staged_hash_reads(&self, times: u64) {
        self.hash_faults.store(times, Ordering::SeqCst);
    }

    #[cfg(feature = "testing")]
    pub fn fail_staged_opens_while_storing(&self, times: u64) {
        self.open_faults.store(times, Ordering::SeqCst);
    }

    #[cfg(feature = "testing")]
    fn take_hash_fault(&self) -> bool {
        take_fault(&self.hash_faults)
    }

    fn hash_staged(&self, file: &mut std::fs::File) -> Result<(u64, String), RecordingStoreError> {
        #[cfg(feature = "testing")]
        if self.take_hash_fault() {
            return Err(RecordingStoreError::Io {
                operation: "read a staged recording",
                source: std::io::Error::from_raw_os_error(5),
            });
        }
        cast_sha256(file)
    }

    fn is_refused(&self, session_id: &str) -> bool {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(session_id)
    }

    fn refuse(&self, session_id: &str) {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id.to_owned());
    }

    pub fn is_live(&self, session_id: &str) -> bool {
        self.live.contains(session_id)
    }

    pub fn staging(&self) -> &DirectorySink {
        &self.staging
    }

    pub fn probe(&self) -> Result<(), ProbeError> {
        let root = self
            .layout
            .root()
            .map_err(|err| ProbeError::Unreachable(err.to_string()))?;
        let probe_path = self
            .layout
            .probe()
            .map_err(|err| ProbeError::Unreachable(err.to_string()))?;
        let policy = RetryPolicy::new(self.remote.policy().deadline.min(PROBE_DEADLINE));
        let remote = &self.remote;
        let root = root.as_ref();
        let probe_path = &probe_path;
        let outcome = remote.run(async {
            let start = remote.started();
            remote
                .retry_with(&policy, start, || async {
                    remote.probe_listing(root).await
                })
                .await?;
            remote
                .retry_with(&policy, start, || async {
                    remote.probe_write(probe_path).await
                })
                .await
        });
        match outcome {
            Ok(()) => Ok(()),
            Err(RemoteError::Denied(detail)) => Err(ProbeError::Denied(detail)),
            Err(RemoteError::Missing(_)) => Err(ProbeError::BucketMissing),
            Err(RemoteError::Permanent(detail)) => Err(ProbeError::Rejected(detail)),
            Err(other) => Err(ProbeError::Unreachable(other.to_string())),
        }
    }

    pub fn recover_pending(&self) -> Result<S3Recovery, RecordingStoreError> {
        let mut recovery = S3Recovery::default();
        for pending in self.staging.pending_manifests()? {
            let id = pending.key.session_id();
            if self.live.contains(id) {
                recovery.live += 1;
                continue;
            }
            match self.publish_pending(&pending) {
                PendingOutcome::Published => recovery.published += 1,
                PendingOutcome::Deferred | PendingOutcome::Invalid => recovery.deferred += 1,
                PendingOutcome::Refused => {
                    recovery.refused += 1;
                    if recovery.refused_ids.len() < LISTED_IDS {
                        recovery.refused_ids.push(id.to_owned());
                    }
                }
                PendingOutcome::Quarantined => {
                    recovery.quarantined += 1;
                    if recovery.quarantined_ids.len() < LISTED_IDS {
                        recovery.quarantined_ids.push(id.to_owned());
                    }
                }
            }
        }
        Ok(recovery)
    }

    fn publish_pending(&self, pending: &PendingManifest) -> PendingOutcome {
        let session_id = pending.key.session_id();
        if self.is_refused(session_id) {
            return PendingOutcome::Refused;
        }
        if self.remote.is_waiting() {
            return PendingOutcome::Deferred;
        }
        let outcome = self.publish_pending_checked(pending);
        match outcome {
            PendingOutcome::Refused => self.refuse(session_id),
            PendingOutcome::Invalid => return self.note_invalid(&pending.key),
            _ => {}
        }
        outcome
    }

    fn note_invalid(&self, key: &RecordingKey) -> PendingOutcome {
        let attempts = {
            let mut invalid = self.invalid.lock().unwrap_or_else(PoisonError::into_inner);
            let attempts = invalid.entry(key.session_id().to_owned()).or_default();
            *attempts += 1;
            *attempts
        };
        if attempts < QUARANTINE_AFTER_ATTEMPTS {
            return PendingOutcome::Invalid;
        }
        match self.staging.quarantine_staged(key) {
            Ok(()) => {
                self.invalid
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(key.session_id());
                tracing::error!(target: "jaunt::recordings", session_id = key.session_id(), attempts, reason = "quarantined", "the staged files of a recording stayed unusable and were moved to the quarantine directory of the staging root: the recording is given up");
                PendingOutcome::Quarantined
            }
            Err(err) => {
                tracing::error!(target: "jaunt::recordings", session_id = key.session_id(), error = %err, "the staged files of an unusable recording could not be quarantined");
                PendingOutcome::Invalid
            }
        }
    }

    fn publish_pending_checked(&self, pending: &PendingManifest) -> PendingOutcome {
        let session_id = pending.key.session_id();
        let manifest: SessionManifest = match serde_json::from_slice(&pending.bytes) {
            Ok(manifest) => manifest,
            Err(_) => {
                tracing::error!(target: "jaunt::recordings", session_id, "a pending manifest is not valid: the files are kept");
                return PendingOutcome::Invalid;
            }
        };
        if manifest.session_id != session_id {
            tracing::error!(target: "jaunt::recordings", session_id, "a pending manifest belongs to another session: the files are kept");
            return PendingOutcome::Invalid;
        }
        let staging = self.staging.clone();
        let key = pending.key.clone();
        let open = move || {
            staging
                .open_staged_cast(&key)?
                .ok_or(RecordingStoreError::Finished)
        };
        let cast = match self.staging.open_staged_cast(&pending.key) {
            Ok(Some(mut file)) => match self.hash_staged(&mut file) {
                Ok((len, sha256)) => {
                    #[cfg(feature = "testing")]
                    self.hash_runs.fetch_add(1, Ordering::SeqCst);
                    Some((len, sha256))
                }
                Err(err) => {
                    tracing::error!(target: "jaunt::recordings", session_id, error = %err, "a staged cast cannot be read: the files are kept and the attempt is repeated");
                    return PendingOutcome::Deferred;
                }
            },
            Ok(None) => None,
            Err(err) => {
                tracing::error!(target: "jaunt::recordings", session_id, error = %err, "a staged cast cannot be opened: the files are kept and the attempt is repeated");
                return PendingOutcome::Deferred;
            }
        };
        let consistent = match &cast {
            Some((len, _)) => manifest.chunks > 0 && *len <= manifest.raw_bytes,
            None => manifest.chunks == 0,
        };
        if !consistent {
            tracing::error!(target: "jaunt::recordings", session_id, "a pending manifest does not match the staged cast: the files are kept");
            return PendingOutcome::Invalid;
        }
        let source = cast.as_ref().map(|(len, sha256)| CastSource {
            open: &open,
            len: *len,
            sha256,
        });
        match self.publish(&pending.key, source.as_ref(), &pending.bytes) {
            Ok(()) => self.finish_published(pending, "a recording interrupted before its manifest was stored was published from its staged files"),
            Err(RecordingStoreError::Unavailable) => {
                tracing::warn!(target: "jaunt::recordings", session_id, "the object store is unavailable: the staged recording is kept for the next attempt");
                PendingOutcome::Deferred
            }
            Err(RecordingStoreError::Exists) => {
                let proof = cast
                    .as_ref()
                    .and_then(|(len, sha256)| CastProof::of(*len, sha256.clone()));
                self.settle_existing(pending, &manifest, proof.as_ref())
            }
            Err(err) => {
                tracing::error!(target: "jaunt::recordings", session_id, error = %err, "a staged recording cannot be published: the files are kept and the attempt is repeated");
                PendingOutcome::Deferred
            }
        }
    }

    fn finish_published(&self, pending: &PendingManifest, message: &'static str) -> PendingOutcome {
        let session_id = pending.key.session_id();
        if self.live.contains(session_id) {
            return PendingOutcome::Published;
        }
        if let Err(err) = self.staging.remove_staged(&pending.key) {
            tracing::warn!(target: "jaunt::recordings", session_id, error = %err, "the staged files of a published recording could not be removed");
        }
        tracing::warn!(target: "jaunt::recordings", session_id, "{message}");
        PendingOutcome::Published
    }

    fn settle_existing(
        &self,
        pending: &PendingManifest,
        manifest: &SessionManifest,
        cast: Option<&CastProof>,
    ) -> PendingOutcome {
        let session_id = pending.key.session_id();
        let identity = Identity {
            session_id: session_id.to_owned(),
            node: manifest.node.clone(),
            user: manifest.user.clone(),
            login: Some(manifest.login.clone()),
        };
        let found = read_store_proof(self, &pending.key);
        let local = LocalProof {
            manifest: Some(manifest),
            cast,
            chunks: None,
        };
        match resolve_existing(&identity, Some(&local), &found) {
            Resolution::Adopt => self.finish_published(
                pending,
                "a staged recording found an acceptable recording in the object store: the staged files were released",
            ),
            Resolution::Nothing | Resolution::Retry => PendingOutcome::Deferred,
            Resolution::Conflict(reason) => {
                tracing::error!(target: "jaunt::recordings", session_id, reason, "a staged recording conflicts with what the object store holds: nothing in the store is touched and the staged files are kept");
                PendingOutcome::Refused
            }
        }
    }

    fn publish(
        &self,
        key: &RecordingKey,
        cast: Option<&CastSource<'_>>,
        manifest: &[u8],
    ) -> Result<(), RecordingStoreError> {
        publish(&self.remote, &self.layout, key, cast, manifest)
    }

    pub fn sweep_orphans(
        &self,
        now_secs: i64,
        budget: ScanBudget,
    ) -> Result<OrphanSweep, RecordingStoreError> {
        let pending: Vec<RecordingKey> = self
            .staging
            .pending_manifests()?
            .into_iter()
            .map(|pending| pending.key)
            .collect();
        let mut months = Vec::new();
        for back_days in [0, 15, 32] {
            let moment = now_secs.saturating_sub(back_days * SECONDS_PER_DAY);
            if let Ok(key) = RecordingKey::new(PLACEHOLDER_SESSION, moment)
                && let Some((month, _)) = key.location().rsplit_once('/')
                && !months.iter().any(|seen| seen == month)
            {
                months.push(month.to_owned());
            }
        }
        let min_age = i64::try_from(
            ORPHAN_AGE_FLOOR_SECS.max(self.remote.policy().deadline.as_secs().saturating_mul(2)),
        )
        .unwrap_or(i64::MAX);
        let remote = &self.remote;
        let pending = &pending;
        remote
            .run(remote.guarded_read(async {
                let start = remote.started();
                let mut sweep = OrphanSweep::default();
                for month in &months {
                    let directory = self.layout.directory(month).map_err(RemoteError::Local)?;
                    let mut listing = remote.list_stream(Some(&directory));
                    let mut held: Option<(RecordingKey, object_store::ObjectMeta)> = None;
                    loop {
                        let spent = remote.started().saturating_sub(start);
                        if sweep.scanned >= budget.max_objects || spent > budget.deadline {
                            sweep.truncated = true;
                            break;
                        }
                        let Some(meta) = listing
                            .try_next()
                            .await
                            .map_err(|error| remote.classify(error))?
                        else {
                            break;
                        };
                        sweep.scanned += 1;
                        match self.layout.classify(&meta.location) {
                            Some((key, ObjectKind::Cast)) => {
                                if let Some(previous) = held.replace((key, meta)) {
                                    sweep.removed += u64::from(
                                        self.reap(
                                            &previous.0,
                                            &previous.1,
                                            now_secs,
                                            min_age,
                                            pending,
                                        )
                                        .await?,
                                    );
                                }
                            }
                            Some((key, ObjectKind::Manifest))
                                if held.as_ref().is_some_and(|(held_key, _)| *held_key == key) =>
                            {
                                held = None;
                            }
                            Some((_, ObjectKind::Manifest)) | None => {}
                        }
                    }
                    if let Some(last) = held.take() {
                        sweep.removed += u64::from(
                            self.reap(&last.0, &last.1, now_secs, min_age, pending)
                                .await?,
                        );
                    }
                    if sweep.truncated {
                        break;
                    }
                }
                Ok(sweep)
            }))
            .map_err(unavailable(remote))
    }

    async fn reap(
        &self,
        key: &RecordingKey,
        meta: &object_store::ObjectMeta,
        now_secs: i64,
        min_age: i64,
        pending: &[RecordingKey],
    ) -> Result<bool, RemoteError> {
        let young = now_secs.saturating_sub(meta.last_modified.timestamp()) < min_age;
        if young
            || pending.contains(key)
            || self.live.contains(key.session_id())
            || self
                .staging
                .open_staged_cast(key)
                .map_err(RemoteError::Local)?
                .is_some()
        {
            return Ok(false);
        }
        let paths = self.layout.paths(key).map_err(RemoteError::Local)?;
        let remote = &self.remote;
        let start = remote.started();
        let paths = &paths;
        let removed = remote
            .retry(start, || async move {
                if remote.stat(&paths.manifest).await?.is_some() {
                    return Ok(false);
                }
                remote.delete(&paths.cast).await?;
                Ok(true)
            })
            .await?;
        if removed {
            tracing::warn!(target: "jaunt::recordings", session_id = key.session_id(), "a cast object without a manifest and without staged files was removed");
        }
        Ok(removed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOutcome {
    Published,
    Deferred,
    Invalid,
    Refused,
    Quarantined,
}

fn unavailable(remote: &Remote) -> impl Fn(RemoteError) -> RecordingStoreError + '_ {
    move |error| match error {
        RemoteError::Local(local) => local,
        RemoteError::Conflict => RecordingStoreError::Exists,
        RemoteError::Waiting => RecordingStoreError::Unavailable,
        other => {
            tracing::warn!(target: "jaunt::recordings", error = %remote.scrub(&other.to_string()), "the recording object store failed");
            RecordingStoreError::Unavailable
        }
    }
}

#[cfg(feature = "testing")]
fn take_fault(counter: &AtomicU64) -> bool {
    loop {
        let left = counter.load(Ordering::SeqCst);
        if left == 0 {
            return false;
        }
        if counter
            .compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return true;
        }
    }
}

fn keep_after(key: &RecordingKey, error: RecordingStoreError) -> RecordingStoreError {
    if !error.is_local_fault() {
        return error;
    }
    tracing::warn!(target: "jaunt::recordings", session_id = key.session_id(), error = %error, "a staged recording cannot be read or written now: the files are kept and the attempt is repeated later");
    RecordingStoreError::Unavailable
}

fn publish(
    remote: &Remote,
    layout: &Layout,
    key: &RecordingKey,
    cast: Option<&CastSource<'_>>,
    manifest: &[u8],
) -> Result<(), RecordingStoreError> {
    let paths = layout.paths(key)?;
    remote
        .run(remote.guarded(async {
            let start = remote.started();
            if let Some(cast) = cast {
                remote.ensure_cast(start, &paths, cast).await?;
            }
            remote
                .ensure_manifest(start, &paths.manifest, manifest)
                .await
        }))
        .map_err(unavailable(remote))
}

impl RecordingSink for S3Sink {
    fn begin(&self, key: &RecordingKey) -> Result<Box<dyn StagedRecording>, RecordingStoreError> {
        let inner = self.staging.begin_staged(key)?;
        Ok(Box::new(self.staged(key, inner)))
    }

    fn resume(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn StagedRecording>>, RecordingStoreError> {
        Ok(self
            .staging
            .resume_staged(key, raw_bytes, prefix_sha256)?
            .map(|inner| Box::new(self.staged(key, inner)) as Box<dyn StagedRecording>))
    }

    fn holds_staged_manifest(&self, key: &RecordingKey) -> bool {
        self.staging.pending_exists(key).unwrap_or(true)
    }

    fn holds_staged_part(&self, key: &RecordingKey) -> bool {
        self.staging
            .open_staged_cast(key)
            .map_or(true, |opened| opened.is_some())
    }

    fn open(&self, key: &RecordingKey) -> Result<Option<StoredRecording>, RecordingStoreError> {
        let paths = self.layout.paths(key)?;
        let remote = &self.remote;
        let (manifest, cast) = remote
            .run(remote.guarded_read(async {
                let start = remote.started();
                let manifest = remote
                    .retry(start, || async {
                        remote.get_manifest(&paths.manifest).await
                    })
                    .await?;
                let Some(manifest) = manifest else {
                    return Ok::<_, RemoteError>((None, None));
                };
                let cast = remote
                    .retry(start, || async { remote.stat(&paths.cast).await })
                    .await?;
                Ok((Some(manifest), cast))
            }))
            .map_err(unavailable(remote))?;
        let Some(bytes) = manifest else {
            return Ok(None);
        };
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RecordingStoreError::InvalidManifest);
        }
        let parsed: SessionManifest =
            serde_json::from_slice(&bytes).map_err(|_| RecordingStoreError::InvalidManifest)?;
        if parsed.session_id != key.session_id() {
            return Err(RecordingStoreError::InvalidManifest);
        }
        let cast = cast.map(|stat| {
            Box::new(CastReader::new(
                self.remote.clone(),
                paths.cast.clone(),
                &stat,
            )) as Box<dyn Read + Send>
        });
        Ok(Some(StoredRecording {
            manifest: parsed,
            manifest_sha256: sha256_hex(&bytes),
            cast,
        }))
    }
}

impl S3Sink {
    fn staged(&self, key: &RecordingKey, inner: DirectoryStaged) -> S3Staged {
        self.live.register(key.session_id());
        S3Staged {
            live: self.live.clone(),
            remote: self.remote.clone(),
            layout: self.layout.clone(),
            staging: self.staging.clone(),
            key: key.clone(),
            inner: Some(inner),
            stashed: None,
            sealed: false,
            #[cfg(feature = "testing")]
            open_faults: self.open_faults.clone(),
        }
    }
}

pub struct S3Staged {
    live: Arc<LiveKeys>,
    remote: Arc<Remote>,
    layout: Layout,
    staging: Arc<DirectorySink>,
    key: RecordingKey,
    inner: Option<DirectoryStaged>,
    stashed: Option<Vec<u8>>,
    sealed: bool,
    #[cfg(feature = "testing")]
    open_faults: Arc<AtomicU64>,
}

impl S3Staged {
    fn staged_mut(&mut self) -> Result<&mut DirectoryStaged, RecordingStoreError> {
        self.inner.as_mut().ok_or(RecordingStoreError::Finished)
    }
}

impl StagedRecording for S3Staged {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), RecordingStoreError> {
        if self.sealed {
            return Err(RecordingStoreError::Finished);
        }
        self.staged_mut()?.write(seq, raw)
    }

    fn written(&self) -> u64 {
        self.inner.as_ref().map_or(0, StagedRecording::written)
    }

    fn prefix_sha256(&self) -> String {
        self.inner
            .as_ref()
            .map(StagedRecording::prefix_sha256)
            .unwrap_or_default()
    }

    fn commit(&mut self, manifest: &SessionManifest) -> Result<Committed, RecordingStoreError> {
        let bytes = manifest_bytes(manifest)?;
        let stash_needed = self.stashed.as_deref() != Some(bytes.as_slice());
        self.sealed = true;
        let inner = self.inner.as_mut().ok_or(RecordingStoreError::Finished)?;
        if stash_needed {
            inner
                .stash_manifest(&bytes)
                .map_err(|err| keep_after(&self.key, err))?;
            self.stashed = Some(bytes.clone());
        }
        let has_cast = inner
            .cast_for_upload()
            .map_err(|err| keep_after(&self.key, err))?
            .is_some();
        let cast_bytes = StagedRecording::written(inner);
        let cast_sha256 = StagedRecording::prefix_sha256(inner);
        let staging = self.staging.clone();
        let key = self.key.clone();
        #[cfg(feature = "testing")]
        let faults = self.open_faults.clone();
        let open = move || {
            #[cfg(feature = "testing")]
            if take_fault(&faults) {
                return Err(RecordingStoreError::Io {
                    operation: "open a staged recording",
                    source: std::io::Error::from_raw_os_error(24),
                });
            }
            staging
                .open_staged_cast(&key)?
                .ok_or(RecordingStoreError::Finished)
        };
        let source = has_cast.then_some(CastSource {
            open: &open,
            len: cast_bytes,
            sha256: &cast_sha256,
        });
        let published = publish(
            &self.remote,
            &self.layout,
            &self.key,
            source.as_ref(),
            &bytes,
        );
        match published {
            Ok(()) => {
                if let Some(mut inner) = self.inner.take()
                    && let Err(err) = inner.discard()
                {
                    tracing::warn!(target: "jaunt::recordings", error = %err, "the staged files of a stored recording could not be removed: the next start removes them");
                }
                Ok(Committed {
                    location: self.key.location(),
                    cast_sha256: has_cast.then_some(cast_sha256),
                    cast_bytes,
                    manifest_sha256: sha256_hex(&bytes),
                })
            }
            Err(RecordingStoreError::Unavailable) => Err(RecordingStoreError::Unavailable),
            Err(RecordingStoreError::Exists) => Err(RecordingStoreError::Exists),
            Err(local) if local.is_local_fault() => Err(keep_after(&self.key, local)),
            Err(other) => {
                if let Some(mut inner) = self.inner.take()
                    && let Err(err) = inner.discard()
                {
                    tracing::warn!(target: "jaunt::recordings", error = %err, "removing a failed recording left files behind");
                }
                Err(other)
            }
        }
    }

    fn keep_files(&mut self) {
        self.sealed = true;
    }

    fn abort(mut self: Box<Self>) -> Result<(), RecordingStoreError> {
        match self.inner.take() {
            Some(mut inner) => inner.discard(),
            None => Ok(()),
        }
    }
}

impl Drop for S3Staged {
    fn drop(&mut self) {
        self.live.unregister(self.key.session_id());
        if self.sealed
            && let Some(inner) = self.inner.as_mut()
        {
            inner.release();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{SinkOptions, request_timeout};
    use crate::retry::RetryPolicy;

    #[test]
    fn the_request_timeout_grows_with_the_part_size() {
        let cases: [(usize, u64); 4] = [
            (1024, 30),
            (5 * 1024 * 1024, 30),
            (8 * 1024 * 1024, 32),
            (128 * 1024 * 1024, 512),
        ];
        for (part, secs) in cases {
            assert_eq!(request_timeout(part).as_secs(), secs, "{part}");
        }
    }

    #[test]
    fn the_options_never_show_the_credentials_they_scrub_from_errors() {
        let options = SinkOptions {
            prefix: "recordings/".to_owned(),
            part_size: 1,
            conditional_put: true,
            retry: RetryPolicy::new(Duration::from_secs(1)),
            secrets: vec!["AKIDVALUE".to_owned(), "secret-value-42".to_owned()],
            breaker_window: Duration::from_secs(15),
        };
        let shown = format!("{options:?}");
        assert!(
            !shown.contains("AKIDVALUE") && !shown.contains("secret-value-42"),
            "{shown}"
        );
    }
}
