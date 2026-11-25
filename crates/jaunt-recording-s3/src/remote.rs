use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::stream::BoxStream;
use jaunt_audit::{MAX_MANIFEST_BYTES, RecordingKey, RecordingStoreError};
use object_store::path::Path;
use object_store::{
    Attribute, AttributeValue, Attributes, GetOptions, GetRange, ObjectMeta, ObjectStore,
    ObjectStoreExt, PutMode, PutMultipartOptions, PutOptions, PutPayload,
};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

use crate::breaker::{Admission, Breaker};
use crate::retry::{RemoteError, RetryPolicy, Timer, retrying};

pub const CAST_CONTENT_TYPE: &str = "application/x-asciicast";
pub const MANIFEST_CONTENT_TYPE: &str = "application/json";
pub const SHA256_METADATA: &str = "sha256";
pub const READ_CHUNK: u64 = 1024 * 1024;
const CAST_SUFFIX: &str = ".cast";
const MANIFEST_SUFFIX: &str = ".manifest.json";
const PROBE_NAME: &str = ".jaunt-probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Cast,
    Manifest,
}

#[derive(Debug, Clone)]
pub struct Layout {
    prefix: String,
}

#[derive(Debug, Clone)]
pub struct Paths {
    pub cast: Path,
    pub manifest: Path,
}

impl Layout {
    pub fn new(prefix: &str) -> Layout {
        Layout {
            prefix: prefix.to_owned(),
        }
    }

    pub fn paths(&self, key: &RecordingKey) -> Result<Paths, RecordingStoreError> {
        let base = format!("{}{}", self.prefix, key.location());
        let parse = |suffix: &str| {
            Path::parse(format!("{base}{suffix}")).map_err(|_| RecordingStoreError::UnsafePath)
        };
        Ok(Paths {
            cast: parse(CAST_SUFFIX)?,
            manifest: parse(MANIFEST_SUFFIX)?,
        })
    }

    pub fn directory(&self, year_month: &str) -> Result<Path, RecordingStoreError> {
        Path::parse(format!("{}{}", self.prefix, year_month))
            .map_err(|_| RecordingStoreError::UnsafePath)
    }

    pub fn probe(&self) -> Result<Path, RecordingStoreError> {
        Path::parse(format!("{}{PROBE_NAME}", self.prefix))
            .map_err(|_| RecordingStoreError::UnsafePath)
    }

    pub fn root(&self) -> Result<Option<Path>, RecordingStoreError> {
        if self.prefix.is_empty() {
            return Ok(None);
        }
        Path::parse(&self.prefix)
            .map(Some)
            .map_err(|_| RecordingStoreError::UnsafePath)
    }

    pub fn classify(&self, path: &Path) -> Option<(RecordingKey, ObjectKind)> {
        let text = path.as_ref();
        let relative = text.strip_prefix(self.prefix.as_str())?;
        if let Some(location) = relative.strip_suffix(CAST_SUFFIX) {
            return RecordingKey::from_location(location)
                .ok()
                .map(|key| (key, ObjectKind::Cast));
        }
        let location = relative.strip_suffix(MANIFEST_SUFFIX)?;
        RecordingKey::from_location(location)
            .ok()
            .map(|key| (key, ObjectKind::Manifest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub sha256: Option<String>,
    pub etag: Option<String>,
}

pub struct CastSource<'a> {
    pub open: &'a (dyn Fn() -> Result<File, RecordingStoreError> + Send + Sync),
    pub len: u64,
    pub sha256: &'a str,
}

impl Stat {
    fn is(&self, source: &CastSource<'_>) -> bool {
        self.size == source.len && self.sha256.as_deref() == Some(source.sha256)
    }
}

struct Turn<'a>(&'a Breaker, bool);

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        if self.1 {
            self.0.release();
        }
    }
}

pub struct Remote {
    store: Arc<dyn ObjectStore>,
    handle: Handle,
    timer: Arc<dyn Timer>,
    policy: RetryPolicy,
    part_size: usize,
    conditional_put: bool,
    secrets: Vec<String>,
    breaker_window: Duration,
    breaker: Breaker,
    permanent_logged_at: Mutex<Option<Duration>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

pub struct RemoteSettings {
    pub policy: RetryPolicy,
    pub part_size: usize,
    pub conditional_put: bool,
    pub secrets: Vec<String>,
    pub breaker_window: Duration,
}

pub const PERMANENT_WINDOW_FACTOR: u32 = 8;
pub const PERMANENT_LOG_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_BODY: &[u8] = b"jaunt recording store probe\n";

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn attributes(content_type: &'static str, sha256: &str) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, AttributeValue::from(content_type));
    attributes.insert(
        Attribute::Metadata(SHA256_METADATA.into()),
        AttributeValue::from(sha256.to_owned()),
    );
    attributes
}

fn read_full(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

pub fn scrub_text(text: &str, secrets: &[String]) -> String {
    let mut shown = text.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            shown = shown.replace(secret.as_str(), "[redacted]");
        }
    }
    shown.chars().take(240).collect()
}

pub fn is_permanent_status(status: u16) -> bool {
    matches!(status, 400 | 405 | 415 | 501 | 301 | 302 | 307 | 308)
}

fn status_in(text: &str) -> Option<u16> {
    const MARKER: &str = "status code: ";
    let start = text.find(MARKER)? + MARKER.len();
    text.get(start..start + 3)?.parse().ok()
}

fn local_io(operation: &'static str) -> impl FnOnce(io::Error) -> RecordingStoreError {
    move |source| RecordingStoreError::Io { operation, source }
}

fn changed() -> RecordingStoreError {
    RecordingStoreError::PrefixMismatch
}

impl Remote {
    pub fn new(
        store: Arc<dyn ObjectStore>,
        handle: Handle,
        timer: Arc<dyn Timer>,
        settings: RemoteSettings,
    ) -> Remote {
        Remote {
            store,
            handle,
            timer,
            policy: settings.policy,
            part_size: settings.part_size,
            conditional_put: settings.conditional_put,
            secrets: settings.secrets,
            breaker_window: settings.breaker_window,
            breaker: Breaker::new(),
            permanent_logged_at: Mutex::new(None),
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.breaker.is_open(self.timer.elapsed())
    }

    pub async fn guarded<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, RemoteError>>,
    ) -> Result<T, RemoteError> {
        self.guarded_for(Access::Write, operation).await
    }

    pub async fn guarded_read<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, RemoteError>>,
    ) -> Result<T, RemoteError> {
        self.guarded_for(Access::Read, operation).await
    }

    async fn guarded_for<T>(
        &self,
        access: Access,
        operation: impl std::future::Future<Output = Result<T, RemoteError>>,
    ) -> Result<T, RemoteError> {
        let admission = self.breaker.admit(self.timer.elapsed());
        if admission == Admission::Wait {
            return Err(RemoteError::Waiting);
        }
        let turn = Turn(&self.breaker, admission == Admission::Probe);
        let outcome = operation.await;
        self.note(access, &outcome);
        drop(turn);
        outcome
    }

    fn note<T>(&self, access: Access, outcome: &Result<T, RemoteError>) {
        let now = self.timer.elapsed();
        match outcome {
            Ok(_) => self.breaker.close(),
            Err(RemoteError::Transient(_)) => {
                self.breaker.trip(now.saturating_add(self.breaker_window))
            }
            Err(RemoteError::Denied(_) | RemoteError::Missing(_)) if access == Access::Write => {
                self.breaker.trip(now.saturating_add(self.breaker_window));
            }
            Err(RemoteError::Permanent(detail)) => {
                self.breaker.trip(
                    now.saturating_add(self.breaker_window.saturating_mul(PERMANENT_WINDOW_FACTOR)),
                );
                self.log_permanent(now, detail);
            }
            Err(_) => self.breaker.release(),
        }
    }

    fn log_permanent(&self, now: Duration, detail: &str) {
        let mut logged = self
            .permanent_logged_at
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if logged.is_some_and(|at| now.saturating_sub(at) < PERMANENT_LOG_INTERVAL) {
            return;
        }
        *logged = Some(now);
        tracing::error!(target: "jaunt::recordings", detail, "the recording object store rejects requests for good: check the endpoint, the bucket and the encryption settings");
    }

    pub fn run<T>(&self, future: impl std::future::Future<Output = T>) -> T {
        self.handle.block_on(future)
    }

    pub fn started(&self) -> Duration {
        self.timer.elapsed()
    }

    pub fn policy(&self) -> RetryPolicy {
        self.policy
    }

    pub fn scrub(&self, text: &str) -> String {
        scrub_text(text, &self.secrets)
    }

    pub fn classify(&self, error: object_store::Error) -> RemoteError {
        use object_store::Error;
        match error {
            Error::AlreadyExists { .. }
            | Error::Precondition { .. }
            | Error::NotModified { .. } => RemoteError::Conflict,
            Error::PermissionDenied { .. } | Error::Unauthenticated { .. } => {
                RemoteError::Denied(self.scrub(&error.to_string()))
            }
            Error::NotFound { .. } => RemoteError::Missing(self.scrub(&error.to_string())),
            Error::NotImplemented { .. }
            | Error::NotSupported { .. }
            | Error::InvalidPath { .. }
            | Error::UnknownConfigurationKey { .. } => {
                RemoteError::Permanent(self.scrub(&error.to_string()))
            }
            other => {
                let text = other.to_string();
                match status_in(&text) {
                    Some(401 | 403) => RemoteError::Denied(self.scrub(&text)),
                    Some(404) => RemoteError::Missing(self.scrub(&text)),
                    Some(status) if is_permanent_status(status) => {
                        RemoteError::Permanent(self.scrub(&text))
                    }
                    _ => RemoteError::Transient(self.scrub(&text)),
                }
            }
        }
    }

    pub async fn retry<T, F, Fut>(&self, start: Duration, operation: F) -> Result<T, RemoteError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, RemoteError>>,
    {
        self.retry_with(&self.policy, start, operation).await
    }

    pub async fn retry_with<T, F, Fut>(
        &self,
        policy: &RetryPolicy,
        start: Duration,
        operation: F,
    ) -> Result<T, RemoteError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, RemoteError>>,
    {
        retrying(self.timer.as_ref(), policy, start, operation).await
    }

    pub async fn stat(&self, path: &Path) -> Result<Option<Stat>, RemoteError> {
        let options = GetOptions {
            head: true,
            ..GetOptions::default()
        };
        match self.store.get_opts(path, options).await {
            Ok(found) => Ok(Some(Stat {
                size: found.meta.size,
                sha256: found
                    .attributes
                    .get(&Attribute::Metadata(SHA256_METADATA.into()))
                    .map(|value| value.as_ref().to_owned()),
                etag: found.meta.e_tag.clone(),
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(error) => Err(self.classify(error)),
        }
    }

    pub async fn get_manifest(&self, path: &Path) -> Result<Option<Bytes>, RemoteError> {
        let found = match self.store.get_opts(path, GetOptions::default()).await {
            Ok(found) => found,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(self.classify(error)),
        };
        let limit = u64::try_from(MAX_MANIFEST_BYTES).unwrap_or(u64::MAX);
        if found.meta.size > limit {
            return Err(RemoteError::Local(RecordingStoreError::InvalidManifest));
        }
        found
            .bytes()
            .await
            .map(Some)
            .map_err(|error| self.classify(error))
    }

    pub async fn delete(&self, path: &Path) -> Result<(), RemoteError> {
        match self.store.delete(path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(error) => Err(self.classify(error)),
        }
    }

    pub async fn put_new(
        &self,
        path: &Path,
        bytes: Bytes,
        sha256: &str,
        content_type: &'static str,
    ) -> Result<(), RemoteError> {
        let mode = if self.conditional_put {
            PutMode::Create
        } else {
            if self.stat(path).await?.is_some() {
                return Err(RemoteError::Conflict);
            }
            PutMode::Overwrite
        };
        let options = PutOptions {
            mode,
            attributes: attributes(content_type, sha256),
            ..PutOptions::default()
        };
        self.store
            .put_opts(path, PutPayload::from_bytes(bytes), options)
            .await
            .map(|_| ())
            .map_err(|error| self.classify(error))
    }

    pub async fn ensure_cast(
        &self,
        start: Duration,
        paths: &Paths,
        source: &CastSource<'_>,
    ) -> Result<(), RemoteError> {
        self.retry(start, || async move {
            match self.stat(&paths.cast).await? {
                Some(found) if found.is(source) => return Ok(()),
                Some(_) => {
                    if self.stat(&paths.manifest).await?.is_some() {
                        return Err(RemoteError::Conflict);
                    }
                    self.delete(&paths.cast).await?;
                }
                None => {}
            }
            match self.upload_cast(paths, source).await {
                Ok(()) => {}
                Err(RemoteError::Conflict) => {
                    return match self.stat(&paths.cast).await? {
                        Some(found) if found.is(source) => Ok(()),
                        _ => Err(RemoteError::Conflict),
                    };
                }
                Err(other) => return Err(other),
            }
            match self.stat(&paths.cast).await? {
                Some(found) if found.is(source) => Ok(()),
                _ => Err(RemoteError::Transient(
                    "the uploaded cast does not match what was sent".to_owned(),
                )),
            }
        })
        .await
    }

    async fn upload_cast(&self, paths: &Paths, source: &CastSource<'_>) -> Result<(), RemoteError> {
        let mut file = (source.open)()?;
        file.seek(SeekFrom::Start(0))
            .map_err(local_io("rewind the staged recording"))?;
        let part = u64::try_from(self.part_size).unwrap_or(u64::MAX);
        if source.len <= part {
            let mut buffer = vec![0u8; usize::try_from(source.len).unwrap_or(0)];
            let filled =
                read_full(&mut file, &mut buffer).map_err(local_io("read the staged recording"))?;
            let mut extra = [0u8; 1];
            let more =
                read_full(&mut file, &mut extra).map_err(local_io("read the staged recording"))?;
            if filled != buffer.len() || more != 0 || sha256_hex(&buffer) != source.sha256 {
                return Err(changed().into());
            }
            return self
                .put_new(
                    &paths.cast,
                    Bytes::from(buffer),
                    source.sha256,
                    CAST_CONTENT_TYPE,
                )
                .await;
        }
        self.upload_multipart(paths, source, file).await
    }

    async fn upload_multipart(
        &self,
        paths: &Paths,
        source: &CastSource<'_>,
        mut file: File,
    ) -> Result<(), RemoteError> {
        let options = PutMultipartOptions {
            attributes: attributes(CAST_CONTENT_TYPE, source.sha256),
            ..PutMultipartOptions::default()
        };
        let mut upload = self
            .store
            .put_multipart_opts(&paths.cast, options)
            .await
            .map_err(|error| self.classify(error))?;
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let outcome: Result<(), RemoteError> = async {
            loop {
                let mut buffer = vec![0u8; self.part_size];
                let filled = read_full(&mut file, &mut buffer)
                    .map_err(local_io("read the staged recording"))?;
                if filled == 0 {
                    break;
                }
                buffer.truncate(filled);
                hasher.update(&buffer);
                total = total.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
                upload
                    .put_part(PutPayload::from_bytes(Bytes::from(buffer)))
                    .await
                    .map_err(|error| self.classify(error))?;
            }
            if total != source.len || hex(&hasher.clone().finalize()) != source.sha256 {
                return Err(changed().into());
            }
            if self.stat(&paths.cast).await?.is_some() {
                return Err(RemoteError::Conflict);
            }
            Ok(())
        }
        .await;
        let outcome = match outcome {
            Ok(()) => upload
                .complete()
                .await
                .map(|_| ())
                .map_err(|error| self.classify(error)),
            Err(error) => Err(error),
        };
        if outcome.is_err()
            && let Err(error) = upload.abort().await
        {
            tracing::debug!(target: "jaunt::recordings", error = %self.scrub(&error.to_string()), "aborting a multipart upload did not succeed");
        }
        outcome
    }

    pub async fn ensure_manifest(
        &self,
        start: Duration,
        path: &Path,
        manifest: &[u8],
    ) -> Result<(), RemoteError> {
        let sha256 = sha256_hex(manifest);
        let bytes = Bytes::copy_from_slice(manifest);
        let (bytes, sha256) = (&bytes, &sha256);
        self.retry(start, || async move {
            match self
                .put_new(path, bytes.clone(), sha256, MANIFEST_CONTENT_TYPE)
                .await
            {
                Err(RemoteError::Conflict) => match self.get_manifest(path).await? {
                    Some(existing) if existing == *bytes => Ok(()),
                    Some(_) => Err(RemoteError::Conflict),
                    None => Err(RemoteError::Transient(
                        "the manifest disappeared while it was checked".to_owned(),
                    )),
                },
                other => other,
            }
        })
        .await
    }

    pub async fn read_range(
        &self,
        path: &Path,
        range: Range<u64>,
        etag: Option<String>,
    ) -> Result<Bytes, RemoteError> {
        let start = self.timer.elapsed();
        let (range, etag) = (&range, &etag);
        self.guarded_read(self.retry(start, || async move {
            let options = GetOptions {
                range: Some(GetRange::Bounded(range.clone())),
                if_match: etag.clone(),
                ..GetOptions::default()
            };
            let found = self
                .store
                .get_opts(path, options)
                .await
                .map_err(|error| self.classify(error))?;
            found.bytes().await.map_err(|error| self.classify(error))
        }))
        .await
    }

    pub fn list_stream(
        &self,
        prefix: Option<&Path>,
    ) -> BoxStream<'static, object_store::Result<ObjectMeta>> {
        self.store.list(prefix)
    }

    pub async fn probe_write(&self, path: &Path) -> Result<(), RemoteError> {
        let options = PutOptions {
            mode: PutMode::Overwrite,
            attributes: attributes("text/plain", &sha256_hex(PROBE_BODY)),
            ..PutOptions::default()
        };
        self.store
            .put_opts(path, PutPayload::from_static(PROBE_BODY), options)
            .await
            .map_err(|error| self.classify(error))?;
        self.delete(path).await
    }

    pub async fn probe_listing(&self, prefix: Option<&Path>) -> Result<(), RemoteError> {
        self.store
            .list_with_delimiter(prefix)
            .await
            .map(|_| ())
            .map_err(|error| self.classify(error))
    }
}

fn read_failure(error: RemoteError) -> io::Error {
    let kind = match &error {
        RemoteError::Transient(_) | RemoteError::Waiting => io::ErrorKind::TimedOut,
        RemoteError::Denied(_) => io::ErrorKind::PermissionDenied,
        RemoteError::Missing(_) => io::ErrorKind::NotFound,
        RemoteError::Permanent(_) | RemoteError::Conflict | RemoteError::Local(_) => {
            io::ErrorKind::Other
        }
    };
    io::Error::new(kind, error)
}

pub struct CastReader {
    remote: Arc<Remote>,
    path: Path,
    size: u64,
    etag: Option<String>,
    position: u64,
    buffer: Bytes,
}

impl CastReader {
    pub fn new(remote: Arc<Remote>, path: Path, stat: &Stat) -> CastReader {
        CastReader {
            remote,
            path,
            size: stat.size,
            etag: stat.etag.clone(),
            position: 0,
            buffer: Bytes::new(),
        }
    }
}

impl Read for CastReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.buffer.is_empty() {
            if self.position >= self.size {
                return Ok(0);
            }
            let end = self.position.saturating_add(READ_CHUNK).min(self.size);
            let wanted = end - self.position;
            let fetched = self
                .remote
                .run(
                    self.remote
                        .read_range(&self.path, self.position..end, self.etag.clone()),
                )
                .map_err(read_failure)?;
            if u64::try_from(fetched.len()).ok() != Some(wanted) {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the object store returned a short range",
                ));
            }
            self.buffer = fetched;
            self.position = end;
        }
        let count = out.len().min(self.buffer.len());
        out[..count].copy_from_slice(&self.buffer[..count]);
        self.buffer.advance(count);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use jaunt_audit::RecordingKey;

    use super::{Layout, ObjectKind, scrub_text, status_in};

    #[test]
    fn secrets_are_replaced_before_the_text_is_cut_and_never_survive_the_cut() {
        let secret = "s3cr3t-value";
        let text = format!("{}{secret} tail", "x".repeat(236));
        let shown = scrub_text(&text, &[secret.to_owned()]);
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(shown.chars().count() <= 240);
        let split = format!("{}{secret}", "y".repeat(238));
        assert!(!scrub_text(&split, &[secret.to_owned()]).contains("s3"));
        assert_eq!(scrub_text("plain", &[String::new()]), "plain");
    }

    #[test]
    fn permanent_statuses_are_those_a_retry_can_never_cure() {
        for status in [400, 405, 415, 501, 301, 302, 307, 308] {
            assert!(super::is_permanent_status(status), "{status}");
        }
        for status in [401, 403, 404, 408, 409, 429, 500, 502, 503, 504] {
            assert!(!super::is_permanent_status(status), "{status}");
        }
    }

    #[test]
    fn the_status_of_a_listing_error_is_read_from_its_text() {
        let cases = [
            (
                "Error performing list request: Server returned non-2xx status code: 403 Forbidden: <x>",
                Some(403),
            ),
            (
                "Server returned non-2xx status code: 404 Not Found: ",
                Some(404),
            ),
            (
                "Server returned non-2xx status code: 503 Service Unavailable",
                Some(503),
            ),
            ("error sending request for url", None),
            ("status code: 4", None),
        ];
        for (text, status) in cases {
            assert_eq!(status_in(text), status, "{text}");
        }
    }

    const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

    #[test]
    fn keys_are_built_only_from_the_prefix_the_date_and_a_valid_id() {
        let key = RecordingKey::new(ID, 1_764_028_800).unwrap();
        let cases = [
            ("recordings/", format!("recordings/2025/11/{ID}")),
            ("", format!("2025/11/{ID}")),
            ("a/b-c/", format!("a/b-c/2025/11/{ID}")),
        ];
        for (prefix, base) in cases {
            let layout = Layout::new(prefix);
            let paths = layout.paths(&key).unwrap();
            assert_eq!(paths.cast.as_ref(), format!("{base}.cast"));
            assert_eq!(paths.manifest.as_ref(), format!("{base}.manifest.json"));
            assert_eq!(
                layout.classify(&paths.cast),
                Some((key.clone(), ObjectKind::Cast))
            );
            assert_eq!(
                layout.classify(&paths.manifest),
                Some((key.clone(), ObjectKind::Manifest))
            );
        }
        let layout = Layout::new("recordings/");
        for foreign in [
            "other/2025/11/5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11.cast".to_owned(),
            "recordings/2025/11/not-an-id.cast".to_owned(),
            format!("recordings/2025/13/{ID}.cast"),
            format!("recordings/2025/11/sub/{ID}.cast"),
        ] {
            let path = object_store::path::Path::parse(&foreign).unwrap();
            assert_eq!(layout.classify(&path), None, "{foreign}");
        }
    }
}
