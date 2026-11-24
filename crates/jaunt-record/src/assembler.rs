use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

use crate::chunk::{Chunk, digest_over, sha256_of, to_hex};
use crate::error::{AssembleError, SinkError, VerifyError};
use crate::manifest::{MANIFEST_VERSION, SessionManifest};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_chunk_compressed: usize,
    pub max_chunk_raw: u64,
    pub max_chunks: u64,
    pub max_total_raw: u64,
    pub max_pending_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_chunk_compressed: 1024 * 1024,
            max_chunk_raw: 8 * 1024 * 1024,
            max_chunks: 1_000_000,
            max_total_raw: 4 * 1024 * 1024 * 1024,
            max_pending_bytes: 256 * 1024 * 1024,
        }
    }
}

pub trait Sink {
    fn write(&mut self, seq: u64, raw: &[u8]) -> Result<(), SinkError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    New,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub session_id: String,
    pub received_chunks: u64,
    pub missing_chunks: u64,
    pub raw_bytes: u64,
    pub digest: Option<String>,
    pub incomplete: bool,
    pub dropped_chunks: u64,
}

#[derive(Debug, Clone, Copy)]
struct ChunkMeta {
    sha256: [u8; 32],
    raw_len: u64,
    is_last: bool,
}

pub struct Assembler {
    limits: Limits,
    session_id: String,
    metas: BTreeMap<u64, ChunkMeta>,
    next_deliver: u64,
    reordered: BTreeMap<u64, Vec<u8>>,
    reordered_bytes: usize,
    total_raw: u64,
    last_seq: Option<u64>,
}

impl fmt::Debug for Assembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assembler")
            .field("received_chunks", &self.metas.len())
            .field("reordered_chunks", &self.reordered.len())
            .field("reordered_bytes", &self.reordered_bytes)
            .field("next_deliver", &self.next_deliver)
            .field("last_seq", &self.last_seq)
            .finish()
    }
}

impl Assembler {
    pub fn new(expected_session_id: impl Into<String>, limits: Limits) -> Self {
        Self {
            limits,
            session_id: expected_session_id.into(),
            metas: BTreeMap::new(),
            next_deliver: 0,
            reordered: BTreeMap::new(),
            reordered_bytes: 0,
            total_raw: 0,
            last_seq: None,
        }
    }

    pub fn accept(
        &mut self,
        chunk: &Chunk,
        sink: &mut dyn Sink,
    ) -> Result<Accepted, AssembleError> {
        if chunk.session_id != self.session_id {
            return Err(AssembleError::SessionMismatch);
        }
        if chunk.compressed.len() > self.limits.max_chunk_compressed {
            return Err(AssembleError::CompressedTooLarge);
        }
        if chunk.raw_len > self.limits.max_chunk_raw {
            return Err(AssembleError::RawTooLarge);
        }
        if chunk.seq >= self.limits.max_chunks {
            return Err(AssembleError::SeqLimit);
        }
        let digest = sha256_of(&chunk.compressed);
        if to_hex(&digest) != chunk.sha256 {
            return Err(AssembleError::ChecksumMismatch);
        }
        let meta = ChunkMeta {
            sha256: digest,
            raw_len: chunk.raw_len,
            is_last: chunk.is_last,
        };
        if let Some(known) = self.metas.get(&chunk.seq) {
            return if known.sha256 == meta.sha256
                && known.raw_len == meta.raw_len
                && known.is_last == meta.is_last
            {
                self.drain_reordered(sink)?;
                Ok(Accepted::Duplicate)
            } else {
                Err(AssembleError::Conflict { seq: chunk.seq })
            };
        }
        self.check_last_marker(chunk)?;
        if self.total_raw.saturating_add(chunk.raw_len) > self.limits.max_total_raw {
            return Err(AssembleError::TotalRawLimit);
        }
        let in_order = chunk.seq == self.next_deliver;
        if !in_order
            && self.reordered_bytes.saturating_add(chunk.compressed.len())
                > self.limits.max_pending_bytes
        {
            return Err(AssembleError::PendingLimit);
        }
        let raw = inflate(&chunk.compressed, chunk.raw_len)?;
        if in_order {
            sink.write(chunk.seq, &raw).map_err(AssembleError::Sink)?;
            self.commit(chunk, meta);
            self.next_deliver += 1;
            self.drain_reordered(sink)?;
        } else {
            self.commit(chunk, meta);
            self.reordered_bytes += chunk.compressed.len();
            self.reordered.insert(chunk.seq, chunk.compressed.clone());
        }
        Ok(Accepted::New)
    }

    pub fn complete(
        &mut self,
        manifest: &SessionManifest,
        expects_cast: bool,
        sink: &mut dyn Sink,
    ) -> Result<Verified, VerifyError> {
        if manifest.version != MANIFEST_VERSION {
            return Err(VerifyError::UnsupportedVersion(manifest.version));
        }
        if manifest.session_id != self.session_id {
            return Err(VerifyError::SessionMismatch);
        }
        if !manifest.incomplete && manifest.dropped_chunks != 0 {
            return Err(VerifyError::InconsistentManifest);
        }
        let received = len_u64(self.metas.len());
        let Some(highest) = self.metas.keys().next_back().copied() else {
            if expects_cast {
                return Err(VerifyError::NoRecording);
            }
            if manifest.chunks != 0
                || manifest.raw_bytes != 0
                || manifest.dropped_chunks != 0
                || manifest.digest.is_some()
            {
                return Err(VerifyError::MetadataOnlyMismatch);
            }
            return Ok(self.verified(manifest, 0, false));
        };
        let expected = self.last_seq.unwrap_or(highest) + 1;
        let missing = expected - received;
        let full_set = self.last_seq.is_some() && missing == 0;
        if full_set {
            self.verify_full_set(manifest)?;
        } else if !manifest.incomplete {
            return if missing > 0 {
                Err(VerifyError::Gap { missing })
            } else {
                Err(VerifyError::MissingLast)
            };
        } else {
            self.verify_incomplete_set(manifest, highest)?;
            self.deliver_remaining(sink)?;
        }
        Ok(self.verified(manifest, missing, full_set))
    }

    fn check_last_marker(&self, chunk: &Chunk) -> Result<(), AssembleError> {
        if let Some(last) = self.last_seq {
            if chunk.seq > last {
                return Err(AssembleError::AfterLast { seq: chunk.seq });
            }
            if chunk.is_last {
                return Err(AssembleError::ConflictingLast);
            }
        }
        if chunk.is_last
            && self
                .metas
                .keys()
                .next_back()
                .is_some_and(|highest| *highest > chunk.seq)
        {
            return Err(AssembleError::LastNotFinal { seq: chunk.seq });
        }
        Ok(())
    }

    fn commit(&mut self, chunk: &Chunk, meta: ChunkMeta) {
        self.metas.insert(chunk.seq, meta);
        self.total_raw += chunk.raw_len;
        if chunk.is_last {
            self.last_seq = Some(chunk.seq);
        }
    }

    fn deliver_reordered(&mut self, seq: u64, sink: &mut dyn Sink) -> Result<(), AssembleError> {
        let Some(compressed) = self.reordered.get(&seq) else {
            return Ok(());
        };
        let raw_len = self.metas.get(&seq).map_or(0, |meta| meta.raw_len);
        let raw = inflate(compressed, raw_len)?;
        sink.write(seq, &raw).map_err(AssembleError::Sink)?;
        if let Some(done) = self.reordered.remove(&seq) {
            self.reordered_bytes -= done.len();
        }
        Ok(())
    }

    fn drain_reordered(&mut self, sink: &mut dyn Sink) -> Result<(), AssembleError> {
        while self.reordered.contains_key(&self.next_deliver) {
            self.deliver_reordered(self.next_deliver, sink)?;
            self.next_deliver += 1;
        }
        Ok(())
    }

    fn deliver_remaining(&mut self, sink: &mut dyn Sink) -> Result<(), VerifyError> {
        while let Some(seq) = self.reordered.keys().next().copied() {
            self.deliver_reordered(seq, sink)
                .map_err(|error| match error {
                    AssembleError::Sink(sink_error) => VerifyError::Sink(sink_error),
                    _ => VerifyError::Decompress,
                })?;
        }
        Ok(())
    }

    fn verify_full_set(&self, manifest: &SessionManifest) -> Result<(), VerifyError> {
        if manifest.dropped_chunks != 0 {
            return Err(VerifyError::InconsistentManifest);
        }
        if manifest.chunks != len_u64(self.metas.len()) {
            return Err(VerifyError::ChunkCountMismatch);
        }
        if manifest.raw_bytes != self.total_raw {
            return Err(VerifyError::RawBytesMismatch);
        }
        let recomputed = digest_over(self.metas.values().map(|meta| &meta.sha256));
        if manifest.digest.as_deref() != Some(recomputed.as_str()) {
            return Err(VerifyError::DigestMismatch);
        }
        Ok(())
    }

    fn verify_incomplete_set(
        &self,
        manifest: &SessionManifest,
        highest: u64,
    ) -> Result<(), VerifyError> {
        if let Some(last) = self.last_seq
            && manifest.chunks != last + 1
        {
            return Err(VerifyError::ChunkCountMismatch);
        }
        let counted = len_u64(self.metas.len()).checked_add(manifest.dropped_chunks);
        if highest >= manifest.chunks || counted != Some(manifest.chunks) {
            return Err(VerifyError::ChunkCountMismatch);
        }
        if manifest.raw_bytes < self.total_raw {
            return Err(VerifyError::RawBytesMismatch);
        }
        Ok(())
    }

    fn verified(&self, manifest: &SessionManifest, missing: u64, full_set: bool) -> Verified {
        let digest = if full_set {
            Some(digest_over(self.metas.values().map(|meta| &meta.sha256)))
        } else {
            None
        };
        Verified {
            session_id: self.session_id.clone(),
            received_chunks: len_u64(self.metas.len()),
            missing_chunks: missing,
            raw_bytes: self.total_raw,
            digest,
            incomplete: manifest.incomplete,
            dropped_chunks: manifest.dropped_chunks,
        }
    }
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

pub(crate) fn inflate(compressed: &[u8], raw_len: u64) -> Result<Vec<u8>, AssembleError> {
    let decoder =
        zstd::stream::read::Decoder::new(compressed).map_err(|_| AssembleError::Decompress)?;
    read_bounded(decoder, raw_len)
}

pub(crate) fn read_bounded(reader: impl Read, raw_len: u64) -> Result<Vec<u8>, AssembleError> {
    let mut out = Vec::new();
    let read = reader
        .take(raw_len.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| AssembleError::Decompress)?;
    if u64::try_from(read).ok() != Some(raw_len) {
        return Err(AssembleError::RawLenMismatch);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Read;

    use super::*;

    const READER_CAP: u64 = 4 * 1024 * 1024;

    struct CappedZeros<'a> {
        produced: &'a Cell<u64>,
    }

    impl Read for CappedZeros<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let room = READER_CAP.saturating_sub(self.produced.get());
            let len = buf.len().min(usize::try_from(room).unwrap_or(usize::MAX));
            buf[..len].fill(0);
            self.produced.set(self.produced.get() + len as u64);
            Ok(len)
        }
    }

    #[test]
    fn bounded_reading_stops_at_the_declared_length_plus_one() {
        let produced = Cell::new(0);
        let result = read_bounded(
            CappedZeros {
                produced: &produced,
            },
            1000,
        );
        assert_eq!(result, Err(AssembleError::RawLenMismatch));
        assert_eq!(produced.get(), 1001);
    }
}
