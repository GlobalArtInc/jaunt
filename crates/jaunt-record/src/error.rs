use std::error::Error as StdError;
use std::fmt;

use thiserror::Error;

pub struct SinkError {
    payload: Box<dyn StdError + Send + Sync>,
}

impl SinkError {
    pub fn new(payload: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            payload: payload.into(),
        }
    }
}

impl fmt::Display for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sink write failed")
    }
}

impl fmt::Debug for SinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SinkError")
    }
}

impl StdError for SinkError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.payload.as_ref())
    }
}

impl PartialEq for SinkError {
    fn eq(&self, other: &Self) -> bool {
        self.payload.to_string() == other.payload.to_string()
    }
}

impl Eq for SinkError {}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordError {
    #[error("recording is already finished")]
    Finished,
    #[error("sftp sessions have no terminal and cannot be cast-recorded")]
    SftpHasNoCast,
    #[error("shell sessions need a terminal and cannot be metadata-only")]
    ShellNeedsTerminal,
    #[error("a command is only allowed for exec sessions")]
    CommandNotAllowed,
    #[error("marker text exceeds the maximum length")]
    MarkerTooLong,
    #[error("chunk compression failed")]
    Compress,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssembleError {
    #[error("chunk belongs to a different session")]
    SessionMismatch,
    #[error("compressed chunk exceeds the limit")]
    CompressedTooLarge,
    #[error("declared raw length exceeds the limit")]
    RawTooLarge,
    #[error("chunk sequence number exceeds the chunk count limit")]
    SeqLimit,
    #[error("total raw size exceeds the limit")]
    TotalRawLimit,
    #[error("reorder buffer exceeds the limit")]
    PendingLimit,
    #[error("chunk checksum does not match its content")]
    ChecksumMismatch,
    #[error("chunk decompression failed")]
    Decompress,
    #[error("decompressed length does not match the declared raw length")]
    RawLenMismatch,
    #[error("chunk {seq} conflicts with a previously accepted chunk of the same number")]
    Conflict { seq: u64 },
    #[error("chunk {seq} arrived after the last chunk")]
    AfterLast { seq: u64 },
    #[error("chunk {seq} is marked last but a later chunk was already seen")]
    LastNotFinal { seq: u64 },
    #[error("a different chunk is already marked last")]
    ConflictingLast,
    #[error("delivering the chunk to the sink failed")]
    Sink(#[source] SinkError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("unsupported manifest version {0}")]
    UnsupportedVersion(u32),
    #[error("manifest belongs to a different session")]
    SessionMismatch,
    #[error(
        "recording has {missing} missing chunks but the manifest does not say it is incomplete"
    )]
    Gap { missing: u64 },
    #[error("the last chunk was never received")]
    MissingLast,
    #[error("manifest says complete but reports dropped chunks")]
    InconsistentManifest,
    #[error("manifest chunk count does not match the received chunks")]
    ChunkCountMismatch,
    #[error("manifest raw size does not match the received chunks")]
    RawBytesMismatch,
    #[error("manifest digest does not match the received chunks")]
    DigestMismatch,
    #[error("chunk decompression failed")]
    Decompress,
    #[error("a terminal session was expected but no recording was received")]
    NoRecording,
    #[error("a session without a terminal reports recording data")]
    MetadataOnlyMismatch,
    #[error("delivering a chunk to the sink failed")]
    Sink(#[source] SinkError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AckError {
    #[error("ack {seq} is above the highest queued chunk")]
    AboveHighest { seq: u64 },
}
