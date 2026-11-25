use std::fmt;

use serde::{Deserialize, Serialize};

pub const RECORDING_CHUNKS_SUFFIX: &str = "chunks";
pub const RECORDING_COMPLETE_SUFFIX: &str = "complete";
pub const RECORDINGS_PATH_PREFIX: &str = "/v1/agent/recordings/";

pub fn recording_chunks_path(session_id: &str) -> String {
    format!("{RECORDINGS_PATH_PREFIX}{session_id}/{RECORDING_CHUNKS_SUFFIX}")
}

pub fn recording_complete_path(session_id: &str) -> String {
    format!("{RECORDINGS_PATH_PREFIX}{session_id}/{RECORDING_COMPLETE_SUFFIX}")
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingChunk {
    pub seq: u64,
    pub raw_len: u64,
    pub sha256: String,
    pub is_last: bool,
    pub data: String,
}

impl fmt::Debug for RecordingChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingChunk")
            .field("seq", &self.seq)
            .field("raw_len", &self.raw_len)
            .field("sha256", &self.sha256)
            .field("is_last", &self.is_last)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingAck {
    pub acked_through: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordingKind {
    Shell,
    Exec,
    Sftp,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingManifest {
    pub version: u32,
    pub session_id: String,
    pub kind: RecordingKind,
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

impl fmt::Debug for RecordingManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordingManifest")
            .field("version", &self.version)
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("node", &self.node)
            .field("user", &self.user)
            .field("login", &self.login)
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("exit_status", &self.exit_status)
            .field("command", &self.command.as_ref().map(|_| "[redacted]"))
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingComplete {
    pub manifest: RecordingManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordingState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordingReceipt {
    pub state: RecordingState,
    pub chunks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordingRefusal {
    Disabled,
    SessionUnknown,
    NotRecordable,
    BadChunk,
    TooLarge,
    Conflict,
    Closed,
    TooMany,
    InsufficientStorage,
}

impl RecordingRefusal {
    pub const ALL: [RecordingRefusal; 9] = [
        RecordingRefusal::Disabled,
        RecordingRefusal::SessionUnknown,
        RecordingRefusal::NotRecordable,
        RecordingRefusal::BadChunk,
        RecordingRefusal::TooLarge,
        RecordingRefusal::Conflict,
        RecordingRefusal::Closed,
        RecordingRefusal::TooMany,
        RecordingRefusal::InsufficientStorage,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            RecordingRefusal::Disabled => "recording_disabled",
            RecordingRefusal::SessionUnknown => "session_unknown",
            RecordingRefusal::NotRecordable => "session_not_recordable",
            RecordingRefusal::BadChunk => "bad_chunk",
            RecordingRefusal::TooLarge => "recording_too_large",
            RecordingRefusal::Conflict => "conflict",
            RecordingRefusal::Closed => "recording_closed",
            RecordingRefusal::TooMany => "too_many_recordings",
            RecordingRefusal::InsufficientStorage => "insufficient_storage",
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            RecordingRefusal::Disabled | RecordingRefusal::SessionUnknown => 404,
            RecordingRefusal::NotRecordable
            | RecordingRefusal::Conflict
            | RecordingRefusal::Closed => 409,
            RecordingRefusal::BadChunk => 422,
            RecordingRefusal::TooLarge => 413,
            RecordingRefusal::TooMany => 429,
            RecordingRefusal::InsufficientStorage => 507,
        }
    }

    pub const fn retry_later(self) -> bool {
        matches!(
            self,
            RecordingRefusal::TooMany | RecordingRefusal::InsufficientStorage
        )
    }

    pub fn from_code(code: &str) -> Option<RecordingRefusal> {
        RecordingRefusal::ALL
            .into_iter()
            .find(|refusal| refusal.code() == code)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        RecordingAck, RecordingChunk, RecordingComplete, RecordingManifest, RecordingReceipt,
        RecordingRefusal, RecordingState, recording_chunks_path, recording_complete_path,
    };

    fn manifest() -> serde_json::Value {
        json!({
            "version": 1, "session_id": "s", "kind": "exec", "node": "n", "user": "u",
            "login": "deploy", "started_at": 1, "ended_at": 2, "exit_status": 0,
            "command": "secret-command --token abc", "bytes_out": 3, "bytes_in": 4,
            "input_recorded": false, "chunks": 0, "raw_bytes": 0, "incomplete": false,
            "dropped_chunks": 0, "digest": null,
        })
    }

    #[test]
    fn recording_bodies_are_strict_and_round_trip() {
        let chunk = json!({
            "seq": 0, "raw_len": 5, "sha256": "ab", "is_last": true, "data": "AAAA",
        });
        let parsed: RecordingChunk = serde_json::from_value(chunk.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), chunk);
        for extra in ["session_id", "node_id", "compressed"] {
            let mut with_extra = chunk.clone();
            with_extra[extra] = json!("x");
            assert!(serde_json::from_value::<RecordingChunk>(with_extra).is_err());
        }

        let complete = json!({"manifest": manifest()});
        let parsed: RecordingComplete = serde_json::from_value(complete.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), complete);
        let mut nested = complete;
        nested["manifest"]["extra"] = json!(1);
        assert!(serde_json::from_value::<RecordingComplete>(nested).is_err());

        assert_eq!(
            serde_json::to_value(RecordingAck {
                acked_through: None
            })
            .unwrap(),
            json!({"acked_through": null})
        );
        assert_eq!(
            serde_json::to_value(RecordingReceipt {
                state: RecordingState::Incomplete,
                chunks: 3
            })
            .unwrap(),
            json!({"state": "incomplete", "chunks": 3})
        );
    }

    #[test]
    fn debug_output_hides_the_chunk_data_and_the_command() {
        let chunk = RecordingChunk {
            seq: 1,
            raw_len: 2,
            sha256: "ab".to_owned(),
            is_last: false,
            data: "cmVjb3JkZWQtc2VjcmV0".to_owned(),
        };
        let manifest: RecordingManifest = serde_json::from_value(manifest()).unwrap();
        let shown = format!("{chunk:?} {manifest:?}");
        assert!(!shown.contains("cmVjb3JkZWQtc2VjcmV0"), "{shown}");
        assert!(!shown.contains("secret-command"), "{shown}");
        assert!(
            shown.contains("data_len") && shown.contains("deploy"),
            "{shown}"
        );
    }

    #[test]
    fn refusal_codes_are_stable_and_parse_back() {
        let codes: Vec<(&str, u16)> = RecordingRefusal::ALL
            .iter()
            .map(|refusal| (refusal.code(), refusal.status()))
            .collect();
        assert_eq!(
            codes,
            [
                ("recording_disabled", 404),
                ("session_unknown", 404),
                ("session_not_recordable", 409),
                ("bad_chunk", 422),
                ("recording_too_large", 413),
                ("conflict", 409),
                ("recording_closed", 409),
                ("too_many_recordings", 429),
                ("insufficient_storage", 507),
            ]
        );
        for refusal in RecordingRefusal::ALL {
            assert_eq!(RecordingRefusal::from_code(refusal.code()), Some(refusal));
        }
        assert_eq!(RecordingRefusal::from_code("server_error"), None);
        assert_eq!(
            recording_chunks_path("abc"),
            "/v1/agent/recordings/abc/chunks"
        );
        assert_eq!(
            recording_complete_path("abc"),
            "/v1/agent/recordings/abc/complete"
        );
    }
}
