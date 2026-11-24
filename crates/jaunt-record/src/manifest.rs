use std::fmt;

use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionKind {
    Shell,
    Exec,
    Sftp,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionManifest {
    pub version: u32,
    pub session_id: String,
    pub kind: SessionKind,
    pub node: String,
    pub user: String,
    pub login: String,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub exit_status: Option<i32>,
    pub command: Option<String>,
    pub bytes_out: u64,
    pub bytes_in: u64,
    pub input_recorded: bool,
    pub chunks: u64,
    pub raw_bytes: u64,
    pub incomplete: bool,
    pub dropped_chunks: u64,
    pub digest: Option<String>,
}

pub(crate) fn redacted_command(command: &Option<String>) -> Option<&'static str> {
    command.as_ref().map(|_| "<redacted>")
}

impl fmt::Debug for SessionManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManifest")
            .field("version", &self.version)
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("node", &self.node)
            .field("user", &self.user)
            .field("login", &self.login)
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("exit_status", &self.exit_status)
            .field("command", &redacted_command(&self.command))
            .field("bytes_out", &self.bytes_out)
            .field("bytes_in", &self.bytes_in)
            .field("input_recorded", &self.input_recorded)
            .field("chunks", &self.chunks)
            .field("raw_bytes", &self.raw_bytes)
            .field("incomplete", &self.incomplete)
            .field("dropped_chunks", &self.dropped_chunks)
            .field("digest", &self.digest)
            .finish()
    }
}
