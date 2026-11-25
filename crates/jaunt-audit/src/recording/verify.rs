use std::io::Read;

use jaunt_store::Recording;
use sha2::{Digest, Sha256};

use super::{RecordingKey, RecordingSink, RecordingStoreError, hex};

const READ_BUFFER: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRecording {
    pub chunks: u64,
    pub raw_bytes: u64,
    pub incomplete: bool,
    pub cast_sha256: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyFailure {
    #[error("the recording was never stored")]
    NotStored,
    #[error("the stored location does not match the session")]
    LocationMismatch,
    #[error("the stored manifest is missing")]
    ManifestMissing,
    #[error("a complete recording with chunks has no digest")]
    DigestMissing,
    #[error("the stored manifest differs from the one that was accepted")]
    ManifestChanged,
    #[error("the stored manifest disagrees with the recording table on {0}")]
    ManifestDisagrees(&'static str),
    #[error("the cast file is missing")]
    CastMissing,
    #[error("a cast file exists for a recording without one")]
    CastUnexpected,
    #[error("the cast file has {actual} bytes but {expected} were stored")]
    CastLength { expected: u64, actual: u64 },
    #[error("the cast file content does not match its stored sha256")]
    CastChanged,
    #[error(transparent)]
    Storage(#[from] RecordingStoreError),
}

pub fn verify_stored(
    sink: &dyn RecordingSink,
    key: &RecordingKey,
    row: &Recording,
) -> Result<VerifiedRecording, VerifyFailure> {
    if !row.state.is_stored() {
        return Err(VerifyFailure::NotStored);
    }
    if row.session_id != key.session_id() || row.location.as_deref() != Some(&key.location()) {
        return Err(VerifyFailure::LocationMismatch);
    }
    if row.digest.is_none() && !row.incomplete && row.chunks > 0 {
        return Err(VerifyFailure::DigestMissing);
    }
    let stored = sink.open(key)?.ok_or(VerifyFailure::ManifestMissing)?;
    if row.manifest_sha256.as_deref() != Some(stored.manifest_sha256.as_str()) {
        return Err(VerifyFailure::ManifestChanged);
    }
    let manifest = &stored.manifest;
    let checks = [
        ("digest", manifest.digest == row.digest),
        (
            "input_recorded",
            manifest.input_recorded == row.input_recorded,
        ),
        (
            "dropped_chunks",
            manifest.dropped_chunks == row.dropped_chunks,
        ),
        ("incomplete", !manifest.incomplete || row.incomplete),
        (
            "chunks",
            row.incomplete
                || (manifest.chunks == row.chunks && manifest.raw_bytes == row.raw_bytes),
        ),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, holds)| !holds) {
        return Err(VerifyFailure::ManifestDisagrees(field));
    }
    let cast_sha256 = match (stored.cast, row.cast_sha256.as_deref()) {
        (None, None) => {
            if row.raw_bytes != 0 {
                return Err(VerifyFailure::CastMissing);
            }
            None
        }
        (None, Some(_)) => return Err(VerifyFailure::CastMissing),
        (Some(_), None) => return Err(VerifyFailure::CastUnexpected),
        (Some(mut cast), Some(expected)) => {
            let (actual_bytes, actual_sha256) = cast_sha256(&mut cast)?;
            if actual_bytes != row.raw_bytes {
                return Err(VerifyFailure::CastLength {
                    expected: row.raw_bytes,
                    actual: actual_bytes,
                });
            }
            if actual_sha256 != expected {
                return Err(VerifyFailure::CastChanged);
            }
            Some(actual_sha256)
        }
    };
    Ok(VerifiedRecording {
        chunks: row.chunks,
        raw_bytes: row.raw_bytes,
        incomplete: row.incomplete,
        cast_sha256,
    })
}

pub fn cast_sha256(reader: &mut impl Read) -> Result<(u64, String), RecordingStoreError> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; READ_BUFFER];
    let mut total: u64 = 0;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(RecordingStoreError::io("read a stored cast"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    Ok((total, hex(&hasher.finalize())))
}
