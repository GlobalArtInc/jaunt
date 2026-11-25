mod directory;
mod resolve;
mod verify;

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read};

use jaunt_record::{SessionManifest, Sink, SinkError};
use jaunt_store::is_session_id;
use sha2::{Digest, Sha256};

use crate::time::{SECONDS_PER_DAY, civil_from_days};

pub use directory::{
    DEFAULT_MIN_FREE_BYTES, DirectoryLimits, DirectorySink, DirectoryStaged, FILE_MODE, FreeSpace,
    Leftovers, PendingManifest, ROOT_MODE,
};
pub use resolve::{
    CAST_CONFLICT, CastProof, IDENTITY_CONFLICT, Identity, LENGTH_CONFLICT, LocalProof,
    MANIFEST_CONFLICT, Resolution, STRUCTURE_CONFLICT, StoreProof, UNREADABLE_CONFLICT,
    read_store_proof, resolve_existing,
};
pub use verify::{VerifiedRecording, VerifyFailure, cast_sha256, verify_stored};

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const CAST_SUFFIX: &str = ".cast";
pub const MANIFEST_SUFFIX: &str = ".manifest.json";
pub const PART_SUFFIX: &str = ".part";
pub const PENDING_SUFFIX: &str = ".manifest.pending";

const MAX_YEAR: i64 = 9999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingKey {
    session_id: String,
    year: i64,
    month: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecordingKeyError {
    #[error("the session id is not in the stored session id format")]
    SessionId,
    #[error("the session start is outside the supported date range")]
    Date,
}

impl RecordingKey {
    pub fn new(session_id: &str, started_at: i64) -> Result<RecordingKey, RecordingKeyError> {
        if !is_session_id(session_id) {
            return Err(RecordingKeyError::SessionId);
        }
        if started_at < 0 {
            return Err(RecordingKeyError::Date);
        }
        let (year, month, _) = civil_from_days(started_at.div_euclid(SECONDS_PER_DAY));
        if year > MAX_YEAR {
            return Err(RecordingKeyError::Date);
        }
        Ok(RecordingKey {
            session_id: session_id.to_owned(),
            year,
            month,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn location(&self) -> String {
        format!(
            "{}/{}/{}",
            self.year_dir(),
            self.month_dir(),
            self.session_id
        )
    }

    pub fn from_location(location: &str) -> Result<RecordingKey, RecordingKeyError> {
        let mut parts = location.split('/');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(year), Some(month), Some(id), None) => {
                RecordingKey::from_directories(id, year, month)
            }
            _ => Err(RecordingKeyError::Date),
        }
    }

    pub(crate) fn from_directories(
        session_id: &str,
        year: &str,
        month: &str,
    ) -> Result<RecordingKey, RecordingKeyError> {
        if !is_session_id(session_id) {
            return Err(RecordingKeyError::SessionId);
        }
        let digits = |text: &str, len: usize| {
            (text.len() == len && text.bytes().all(|b| b.is_ascii_digit()))
                .then(|| text.parse::<i64>().ok())
                .flatten()
        };
        match (digits(year, 4), digits(month, 2)) {
            (Some(year), Some(month)) if (1..=12).contains(&month) => Ok(RecordingKey {
                session_id: session_id.to_owned(),
                year,
                month,
            }),
            _ => Err(RecordingKeyError::Date),
        }
    }

    pub(crate) fn year_dir(&self) -> String {
        format!("{:04}", self.year)
    }

    pub(crate) fn month_dir(&self) -> String {
        format!("{:02}", self.month)
    }

    pub(crate) fn cast_name(&self) -> String {
        format!("{}{CAST_SUFFIX}", self.session_id)
    }

    pub(crate) fn manifest_name(&self) -> String {
        format!("{}{MANIFEST_SUFFIX}", self.session_id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecordingStoreError {
    #[error("the recording storage is below its free space reserve")]
    DiskFull,
    #[error("the recording exceeds its total size limit")]
    TooLarge,
    #[error("the recording sink received chunk {seq} out of order")]
    OutOfOrder { seq: u64 },
    #[error("a file already exists where the recording would be written")]
    Exists,
    #[error("a path of the recording storage is a symbolic link or not a directory")]
    UnsafePath,
    #[error("the recording object store is unavailable")]
    Unavailable,
    #[error("the stored manifest is invalid")]
    InvalidManifest,
    #[error("the recording was already committed or aborted")]
    Finished,
    #[error("the recording file system cannot rename without replacing an existing file")]
    NoReplaceUnsupported,
    #[error("the staged recording does not match the digest of its delivered prefix")]
    PrefixMismatch,
    #[error("recording storage could not {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

impl RecordingStoreError {
    pub fn is_local_fault(&self) -> bool {
        match self {
            RecordingStoreError::UnsafePath => true,
            RecordingStoreError::Io { source, .. } => source.kind() != io::ErrorKind::NotFound,
            _ => false,
        }
    }

    pub(crate) fn io(operation: &'static str) -> impl FnOnce(io::Error) -> RecordingStoreError {
        move |source| RecordingStoreError::Io { operation, source }
    }
}

pub struct Committed {
    pub location: String,
    pub cast_sha256: Option<String>,
    pub cast_bytes: u64,
    pub manifest_sha256: String,
}

impl fmt::Debug for Committed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Committed")
            .field("location", &self.location)
            .field("cast_sha256", &self.cast_sha256)
            .field("cast_bytes", &self.cast_bytes)
            .field("manifest_sha256", &self.manifest_sha256)
            .finish()
    }
}

pub struct StoredRecording {
    pub manifest: SessionManifest,
    pub manifest_sha256: String,
    pub cast: Option<Box<dyn Read + Send>>,
}

impl fmt::Debug for StoredRecording {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredRecording")
            .field("manifest", &self.manifest)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("cast", &self.cast.is_some())
            .finish()
    }
}

pub trait RecordingSink: Send + Sync {
    fn begin(&self, key: &RecordingKey) -> Result<Box<dyn StagedRecording>, RecordingStoreError>;

    fn open(&self, key: &RecordingKey) -> Result<Option<StoredRecording>, RecordingStoreError>;

    fn resume(
        &self,
        key: &RecordingKey,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<Option<Box<dyn StagedRecording>>, RecordingStoreError>;

    fn holds_staged_manifest(&self, key: &RecordingKey) -> bool {
        let _ = key;
        false
    }

    fn holds_staged_part(&self, key: &RecordingKey) -> bool {
        let _ = key;
        false
    }
}

pub trait StagedRecording: Send {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), RecordingStoreError>;

    fn written(&self) -> u64;

    fn prefix_sha256(&self) -> String;

    fn commit(&mut self, manifest: &SessionManifest) -> Result<Committed, RecordingStoreError>;

    fn abort(self: Box<Self>) -> Result<(), RecordingStoreError>;

    fn keep_files(&mut self) {}
}

pub struct StagedSink<'a>(pub &'a mut dyn StagedRecording);

impl Sink for StagedSink<'_> {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), SinkError> {
        self.0.write(seq, raw).map_err(SinkError::new)
    }
}

pub fn store_error_of(error: &SinkError) -> Option<&RecordingStoreError> {
    error
        .source()
        .and_then(|source| source.downcast_ref::<RecordingStoreError>())
}

pub fn manifest_bytes(manifest: &SessionManifest) -> Result<Vec<u8>, RecordingStoreError> {
    serde_json::to_vec(manifest).map_err(|_| RecordingStoreError::InvalidManifest)
}

pub fn manifest_sha256(manifest: &SessionManifest) -> Result<String, RecordingStoreError> {
    manifest_bytes(manifest).map(|bytes| sha256_hex(&bytes))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{RecordingKey, RecordingKeyError};

    const ID: &str = "5f0c3a52-8a8e-4c55-9a51-2f6f0d1b8c11";

    #[test]
    fn the_key_takes_its_directories_from_the_utc_start_date_and_a_valid_id_only() {
        let cases = [
            (0, "1970/01"),
            (1_764_028_800, "2025/11"),
            (1_767_225_599, "2025/12"),
            (1_767_225_600, "2026/01"),
            (253_402_300_799, "9999/12"),
        ];
        for (secs, prefix) in cases {
            let key = RecordingKey::new(ID, secs).unwrap();
            assert_eq!(key.location(), format!("{prefix}/{ID}"));
            assert_eq!(RecordingKey::from_location(&key.location()), Ok(key));
        }
        for bad in [
            format!("2025/13/{ID}"),
            format!("2025/00/{ID}"),
            format!("25/11/{ID}"),
            format!("2025/11/{ID}/x"),
            format!("2025/11/../{ID}"),
            "2025/11/id".to_owned(),
            "2025/11".to_owned(),
        ] {
            assert!(RecordingKey::from_location(&bad).is_err(), "{bad}");
        }
        assert_eq!(
            RecordingKey::new(ID, 253_402_300_800),
            Err(RecordingKeyError::Date)
        );
        assert_eq!(RecordingKey::new(ID, -1), Err(RecordingKeyError::Date));
        for bad in [
            "../../etc/passwd",
            "",
            "5F0C3A52-8A8E-4C55-9A51-2F6F0D1B8C11",
        ] {
            assert_eq!(
                RecordingKey::new(bad, 0),
                Err(RecordingKeyError::SessionId),
                "{bad}"
            );
        }
    }
}
