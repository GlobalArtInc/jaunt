use std::fmt;

use sha2::{Digest, Sha256};

pub const CHUNK_TARGET_BYTES: usize = 64 * 1024;
pub const ZSTD_LEVEL: i32 = 3;

#[derive(Clone, PartialEq, Eq)]
pub struct Chunk {
    pub session_id: String,
    pub seq: u64,
    pub raw_len: u64,
    pub compressed: Vec<u8>,
    pub sha256: String,
    pub is_last: bool,
}

impl fmt::Debug for Chunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("session_id", &self.session_id)
            .field("seq", &self.seq)
            .field("raw_len", &self.raw_len)
            .field("compressed_len", &self.compressed.len())
            .field("sha256", &self.sha256)
            .field("is_last", &self.is_last)
            .finish()
    }
}

pub(crate) fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn digest_over<'a>(chunk_digests: impl Iterator<Item = &'a [u8; 32]>) -> String {
    let mut hasher = Sha256::new();
    for digest in chunk_digests {
        hasher.update(digest);
    }
    to_hex(&hasher.finalize())
}
