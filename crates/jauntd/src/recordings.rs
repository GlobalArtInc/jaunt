use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use jaunt_audit::{
    DEFAULT_MIN_FREE_BYTES, DirectoryLimits, DirectorySink, RecordingKey, RecordingStoreError,
    verify_stored,
};
use jaunt_control::{
    Control, ControlError, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_CHUNKS, DEFAULT_MAX_UPLOADS_PER_NODE,
    DEFAULT_MAX_UPLOADS_TOTAL, DEFAULT_PENDING_BYTES_PER_NODE, DEFAULT_PENDING_BYTES_TOTAL,
    DEFAULT_SESSION_PENDING_BYTES, RecordingLimits, RecordingSettings,
};
use jaunt_record::Limits;
use jaunt_store::{Store, StoreError, is_session_id};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use serde::Deserialize;

use crate::config;

const DATABASE_FILE: &str = "jaunt.db";
const MAX_UPLOADS_LIMIT: u64 = 65_536;
const MIN_IDLE_TIMEOUT_SECS: u64 = 60;
const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;
const MAX_CHUNK_COMPRESSED_LIMIT: u64 = 16 * 1024 * 1024;
const MAX_CHUNK_RAW_LIMIT: u64 = 64 * 1024 * 1024;
const EXIT_OK: u8 = 0;
const EXIT_FAILED: u8 = 1;
const EXIT_USAGE: u8 = 2;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingsSection {
    pub dir: Option<PathBuf>,
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
    #[serde(default = "default_max_chunk_compressed")]
    pub max_chunk_compressed: u64,
    #[serde(default = "default_max_chunk_raw")]
    pub max_chunk_raw: u64,
    #[serde(default = "default_max_chunks")]
    pub max_chunks: u64,
    #[serde(default = "default_max_total_raw")]
    pub max_total_raw: u64,
}

impl Default for RecordingsSection {
    fn default() -> RecordingsSection {
        RecordingsSection {
            dir: None,
            min_free_bytes: default_min_free_bytes(),
            max_uploads_per_node: default_max_uploads_per_node(),
            max_uploads_total: default_max_uploads_total(),
            max_pending_bytes_per_node: default_max_pending_bytes_per_node(),
            max_pending_bytes_total: default_max_pending_bytes_total(),
            max_pending_bytes: default_max_pending_bytes(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_chunk_compressed: default_max_chunk_compressed(),
            max_chunk_raw: default_max_chunk_raw(),
            max_chunks: default_max_chunks(),
            max_total_raw: default_max_total_raw(),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingsSettings {
    pub dir: PathBuf,
    pub min_free_bytes: u64,
    pub limits: RecordingLimits,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecordingsConfigError {
    #[error("recordings.dir must be an absolute path")]
    RelativeDir,
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

impl RecordingsSection {
    pub fn into_settings(self) -> Result<Option<RecordingsSettings>, RecordingsConfigError> {
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
        let max_chunk_compressed = narrow(
            "max_chunk_compressed",
            self.max_chunk_compressed,
            1,
            MAX_CHUNK_COMPRESSED_LIMIT,
        )?;
        let max_chunk_raw = bounded("max_chunk_raw", self.max_chunk_raw, 1, MAX_CHUNK_RAW_LIMIT)?;
        let max_chunks = bounded("max_chunks", self.max_chunks, 1, u64::MAX)?;
        let max_total_raw = bounded("max_total_raw", self.max_total_raw, 1, u64::MAX)?;
        let Some(dir) = self.dir else {
            return Ok(None);
        };
        if !dir.is_absolute() {
            return Err(RecordingsConfigError::RelativeDir);
        }
        Ok(Some(RecordingsSettings {
            dir,
            min_free_bytes: self.min_free_bytes,
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
    #[error(transparent)]
    Recover(#[from] ControlError),
}

pub struct PreparedRecordings {
    pub settings: RecordingSettings,
    directory: Arc<DirectorySink>,
    path: PathBuf,
}

pub fn prepare(settings: &RecordingsSettings) -> Result<PreparedRecordings, RecordingsStartError> {
    let directory =
        DirectorySink::create(&settings.dir, settings.directory_limits()).map_err(|source| {
            RecordingsStartError::Directory {
                path: settings.dir.clone(),
                source,
            }
        })?;
    let directory = Arc::new(directory);
    Ok(PreparedRecordings {
        settings: RecordingSettings {
            sink: directory.clone(),
            limits: settings.limits,
        },
        directory,
        path: settings.dir.clone(),
    })
}

pub async fn recover(
    prepared: &PreparedRecordings,
    control: &Control,
) -> Result<(), RecordingsStartError> {
    let recovered = control.recover_recordings().await?;
    let leftovers = prepared.directory.remove_leftovers().map_err(|source| {
        RecordingsStartError::Directory {
            path: prepared.path.clone(),
            source,
        }
    })?;
    if recovered.salvaged > 0
        || recovered.failed > 0
        || leftovers.parts > 0
        || leftovers.orphan_casts > 0
    {
        tracing::warn!(
            target: "jaunt::daemon",
            salvaged = recovered.salvaged,
            failed = recovered.failed,
            parts = leftovers.parts,
            orphan_casts = leftovers.orphan_casts,
            "recordings interrupted by the last stop were stored as incomplete or discarded"
        );
    }
    Ok(())
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
    #[error("recordings.dir is not set: recording is disabled")]
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
        .into_settings()
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
    let sink = DirectorySink::open_existing(&settings.dir, settings.directory_limits())
        .map_err(VerifyCommandError::Directory)?;
    let verified =
        verify_stored(&sink, &key, &row).map_err(|failure| VerifyCommandError::Failed {
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
    use std::path::Path;

    use jaunt_audit::{DirectoryLimits, DirectorySink, RecordingKey, RecordingSink};
    use jaunt_control::RecordingLimits;
    use jaunt_record::{MANIFEST_VERSION, SessionKind, SessionManifest};
    use jaunt_store::{
        ActivateSession, NewCertificate, NewSession, NewUser, Store, StoredRecording,
    };
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqliteConnectOptions;

    use super::{RecordingsConfigError, RecordingsSection, open_files_target, prepare, verify};

    const NOW: i64 = 1_764_028_800;
    const NODE: &str = "node-a";

    fn section(text: &str) -> Result<RecordingsSection, String> {
        serde_saphyr::from_str(text).map_err(|err| err.to_string())
    }

    #[test]
    fn the_section_is_off_without_a_directory_and_takes_the_documented_defaults() {
        assert_eq!(RecordingsSection::default().into_settings(), Ok(None));
        let settings = section("dir: /var/lib/jaunt/recordings\n")
            .unwrap()
            .into_settings()
            .unwrap()
            .unwrap();
        assert_eq!(settings.limits, RecordingLimits::default());
        assert_eq!(settings.min_free_bytes, 1024 * 1024 * 1024);
        assert_eq!(settings.limits.chunk.max_pending_bytes, 64 * 1024 * 1024);
        assert_eq!(settings.limits.max_uploads_per_node, 64);
        assert_eq!(settings.limits.max_uploads_total, 1024);
        assert_eq!(settings.limits.idle_timeout.as_secs(), 7200);
        assert_eq!(settings.limits.chunk.max_chunks, 200_000);
    }

    #[test]
    fn the_section_is_strict_and_bounded() {
        assert!(section("dir: /r\nextra: 1\n").is_err());
        assert_eq!(
            section("dir: recordings\n").unwrap().into_settings(),
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
            ("max_chunk_compressed: 16777217\n", "max_chunk_compressed"),
            ("max_chunk_raw: 0\n", "max_chunk_raw"),
            ("max_chunks: 0\n", "max_chunks"),
            ("max_total_raw: 0\n", "max_total_raw"),
        ] {
            let err = section(&format!("dir: /r\n{text}"))
                .unwrap()
                .into_settings()
                .err()
                .unwrap();
            assert!(
                matches!(err, RecordingsConfigError::OutOfRange { field: found, .. } if found == field),
                "{text}: {err}"
            );
        }
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
            .into_settings()
            .unwrap()
            .unwrap();
        let prepared = prepare(&settings).unwrap();
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
