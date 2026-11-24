use std::fmt;

use sha2::{Digest, Sha256};

use crate::chunk::{CHUNK_TARGET_BYTES, Chunk, ZSTD_LEVEL, sha256_of, to_hex};
use crate::clock::Clock;
use crate::error::RecordError;
use crate::manifest::{MANIFEST_VERSION, SessionKind, SessionManifest, redacted_command};
use crate::utf8::{Utf8Stream, split_at_char_boundary};

pub const MAX_EVENT_TEXT_BYTES: usize = 16 * 1024;
pub const MAX_MARKER_BYTES: usize = 4 * 1024;

#[derive(Clone)]
pub struct RecorderConfig {
    pub session_id: String,
    pub kind: SessionKind,
    pub node: String,
    pub user: String,
    pub login: String,
    pub command: Option<String>,
    pub started_at: u64,
    pub width: u16,
    pub height: u16,
    pub shell: String,
    pub term: String,
    pub record_input: bool,
}

#[derive(Clone)]
pub struct MetadataOnly {
    pub session_id: String,
    pub kind: SessionKind,
    pub node: String,
    pub user: String,
    pub login: String,
    pub command: Option<String>,
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub exit_status: Option<i32>,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

impl fmt::Debug for RecorderConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecorderConfig")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("node", &self.node)
            .field("user", &self.user)
            .field("login", &self.login)
            .field("command", &redacted_command(&self.command))
            .field("started_at", &self.started_at)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("shell", &self.shell)
            .field("term", &self.term)
            .field("record_input", &self.record_input)
            .finish()
    }
}

impl fmt::Debug for MetadataOnly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataOnly")
            .field("session_id", &self.session_id)
            .field("kind", &self.kind)
            .field("node", &self.node)
            .field("user", &self.user)
            .field("login", &self.login)
            .field("command", &redacted_command(&self.command))
            .field("started_at", &self.started_at)
            .field("ended_at", &self.ended_at)
            .field("exit_status", &self.exit_status)
            .field("bytes_out", &self.bytes_out)
            .field("bytes_in", &self.bytes_in)
            .finish()
    }
}

type Compressor = fn(&[u8]) -> Result<Vec<u8>, RecordError>;

fn compress_zstd(raw: &[u8]) -> Result<Vec<u8>, RecordError> {
    zstd::bulk::compress(raw, ZSTD_LEVEL).map_err(|_| RecordError::Compress)
}

pub struct Recorder {
    session_id: String,
    kind: SessionKind,
    node: String,
    user: String,
    login: String,
    command: Option<String>,
    started_at: u64,
    record_input: bool,
    clock: Box<dyn Clock>,
    last_micros: u64,
    pending: String,
    output: Utf8Stream,
    input: Utf8Stream,
    ready: Vec<Chunk>,
    next_seq: u64,
    raw_bytes: u64,
    chunk_digests: Sha256,
    bytes_out: u64,
    bytes_in: u64,
    finished: bool,
    compressor: Compressor,
}

impl Recorder {
    pub fn new(config: RecorderConfig, clock: Box<dyn Clock>) -> Result<Self, RecordError> {
        match config.kind {
            SessionKind::Sftp => return Err(RecordError::SftpHasNoCast),
            SessionKind::Shell | SessionKind::Exec => {}
        }
        check_command(config.kind, config.command.as_deref())?;
        let mut pending = String::with_capacity(CHUNK_TARGET_BYTES + MAX_EVENT_TEXT_BYTES);
        write_header(&mut pending, &config);
        Ok(Self {
            session_id: config.session_id,
            kind: config.kind,
            node: config.node,
            user: config.user,
            login: config.login,
            command: config.command,
            started_at: config.started_at,
            record_input: config.record_input,
            clock,
            last_micros: 0,
            pending,
            output: Utf8Stream::default(),
            input: Utf8Stream::default(),
            ready: Vec::new(),
            next_seq: 0,
            raw_bytes: 0,
            chunk_digests: Sha256::new(),
            bytes_out: 0,
            bytes_in: 0,
            finished: false,
            compressor: compress_zstd,
        })
    }

    pub fn metadata_only(meta: MetadataOnly) -> Result<SessionManifest, RecordError> {
        if meta.kind == SessionKind::Shell {
            return Err(RecordError::ShellNeedsTerminal);
        }
        check_command(meta.kind, meta.command.as_deref())?;
        Ok(SessionManifest {
            version: MANIFEST_VERSION,
            session_id: meta.session_id,
            kind: meta.kind,
            node: meta.node,
            user: meta.user,
            login: meta.login,
            started_at: meta.started_at,
            ended_at: meta.ended_at,
            exit_status: meta.exit_status,
            command: meta.command,
            bytes_out: meta.bytes_out,
            bytes_in: meta.bytes_in,
            input_recorded: false,
            chunks: 0,
            raw_bytes: 0,
            incomplete: false,
            dropped_chunks: 0,
            digest: None,
        })
    }

    pub fn push_output(&mut self, data: &[u8]) -> Result<(), RecordError> {
        self.ensure_open()?;
        self.bytes_out = self.bytes_out.saturating_add(len_u64(data.len()));
        let text = self.output.decode(data, false);
        self.emit_text("o", &text)
    }

    pub fn push_input(&mut self, data: &[u8]) -> Result<bool, RecordError> {
        self.ensure_open()?;
        self.bytes_in = self.bytes_in.saturating_add(len_u64(data.len()));
        if !self.record_input {
            return Ok(false);
        }
        let text = self.input.decode(data, false);
        self.emit_text("i", &text)?;
        Ok(true)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), RecordError> {
        self.ensure_open()?;
        self.emit_text("r", &format!("{cols}x{rows}"))
    }

    pub fn marker(&mut self, text: &str) -> Result<(), RecordError> {
        self.ensure_open()?;
        if text.len() > MAX_MARKER_BYTES {
            return Err(RecordError::MarkerTooLong);
        }
        self.emit_text("m", text)
    }

    pub fn flush(&mut self) -> Result<(), RecordError> {
        self.ensure_open()?;
        if self.pending.is_empty() {
            return Ok(());
        }
        self.cut(false)
    }

    pub fn take_chunks(&mut self) -> Vec<Chunk> {
        std::mem::take(&mut self.ready)
    }

    pub fn finish(
        &mut self,
        exit_status: Option<i32>,
        ended_at: u64,
    ) -> Result<SessionManifest, RecordError> {
        self.ensure_open()?;
        let output_tail = self.output.decode(&[], true);
        self.emit_text("o", &output_tail)?;
        if self.record_input {
            let input_tail = self.input.decode(&[], true);
            self.emit_text("i", &input_tail)?;
        }
        self.cut(true)?;
        self.finished = true;
        let digest = to_hex(&self.chunk_digests.clone().finalize());
        Ok(SessionManifest {
            version: MANIFEST_VERSION,
            session_id: self.session_id.clone(),
            kind: self.kind,
            node: self.node.clone(),
            user: self.user.clone(),
            login: self.login.clone(),
            started_at: self.started_at,
            ended_at: Some(ended_at),
            exit_status,
            command: self.command.clone(),
            bytes_out: self.bytes_out,
            bytes_in: self.bytes_in,
            input_recorded: self.record_input,
            chunks: self.next_seq,
            raw_bytes: self.raw_bytes,
            incomplete: false,
            dropped_chunks: 0,
            digest: Some(digest),
        })
    }

    fn ensure_open(&self) -> Result<(), RecordError> {
        if self.finished {
            return Err(RecordError::Finished);
        }
        Ok(())
    }

    fn next_time(&mut self) -> u64 {
        let now = u64::try_from(self.clock.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.last_micros = self.last_micros.max(now);
        self.last_micros
    }

    fn emit_text(&mut self, kind: &str, text: &str) -> Result<(), RecordError> {
        let mut rest = text;
        while !rest.is_empty() {
            let (piece, tail) = split_at_char_boundary(rest, MAX_EVENT_TEXT_BYTES);
            rest = tail;
            let micros = self.next_time();
            write_event(&mut self.pending, micros, kind, piece);
            if self.pending.len() >= CHUNK_TARGET_BYTES {
                self.cut(false)?;
            }
        }
        Ok(())
    }

    fn cut(&mut self, is_last: bool) -> Result<(), RecordError> {
        let raw = self.pending.as_bytes();
        let compressed = (self.compressor)(raw)?;
        let digest = sha256_of(&compressed);
        let raw_len = len_u64(raw.len());
        self.chunk_digests.update(digest);
        self.raw_bytes = self.raw_bytes.saturating_add(raw_len);
        self.ready.push(Chunk {
            session_id: self.session_id.clone(),
            seq: self.next_seq,
            raw_len,
            compressed,
            sha256: to_hex(&digest),
            is_last,
        });
        self.next_seq += 1;
        self.pending.clear();
        Ok(())
    }
}

#[cfg(test)]
impl Recorder {
    pub(crate) fn retained_input_bytes(&self) -> usize {
        self.input.carried()
    }

    pub(crate) fn pending_text(&self) -> &str {
        &self.pending
    }

    pub(crate) fn set_compressor(&mut self, compressor: Compressor) {
        self.compressor = compressor;
    }
}

fn check_command(kind: SessionKind, command: Option<&str>) -> Result<(), RecordError> {
    if kind != SessionKind::Exec && command.is_some() {
        return Err(RecordError::CommandNotAllowed);
    }
    Ok(())
}

fn len_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn push_json_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            control if u32::from(control) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(control)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

fn push_time(out: &mut String, micros: u64) {
    let secs = micros / 1_000_000;
    let frac = micros % 1_000_000;
    if frac == 0 {
        out.push_str(&format!("{secs}.0"));
    } else {
        let digits = format!("{frac:06}");
        out.push_str(&format!("{secs}.{}", digits.trim_end_matches('0')));
    }
}

fn write_header(out: &mut String, config: &RecorderConfig) {
    out.push_str(&format!(
        "{{\"version\":2,\"width\":{},\"height\":{},\"timestamp\":{},\"env\":{{\"SHELL\":",
        config.width, config.height, config.started_at
    ));
    push_json_string(out, &config.shell);
    out.push_str(",\"TERM\":");
    push_json_string(out, &config.term);
    out.push_str("}}\n");
}

fn write_event(out: &mut String, micros: u64, kind: &str, data: &str) {
    out.push('[');
    push_time(out, micros);
    out.push_str(", \"");
    out.push_str(kind);
    out.push_str("\", ");
    push_json_string(out, data);
    out.push_str("]\n");
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    struct FixedClock;

    impl Clock for FixedClock {
        fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }

    fn config(record_input: bool) -> RecorderConfig {
        RecorderConfig {
            session_id: "s".to_owned(),
            kind: SessionKind::Shell,
            node: "n".to_owned(),
            user: "u".to_owned(),
            login: "l".to_owned(),
            command: None,
            started_at: 0,
            width: 80,
            height: 24,
            shell: "sh".to_owned(),
            term: "xterm".to_owned(),
            record_input,
        }
    }

    fn recorder(record_input: bool) -> Recorder {
        Recorder::new(config(record_input), Box::new(FixedClock)).unwrap()
    }

    fn failing_compressor(_: &[u8]) -> Result<Vec<u8>, RecordError> {
        Err(RecordError::Compress)
    }

    #[test]
    fn unrecorded_input_is_not_retained_anywhere() {
        let mut recorder = recorder(false);
        let header_len = recorder.pending_text().len();
        assert_eq!(recorder.push_input(b"secret\xe2\x82"), Ok(false));
        assert_eq!(recorder.retained_input_bytes(), 0);
        assert_eq!(recorder.pending_text().len(), header_len);
        assert!(recorder.take_chunks().is_empty());
        assert_eq!(recorder.bytes_in, 8);
    }

    #[test]
    fn recorded_input_keeps_an_incomplete_sequence_until_the_next_push() {
        let mut recorder = recorder(true);
        assert_eq!(recorder.push_input(&[0xe2, 0x82]), Ok(true));
        assert_eq!(recorder.retained_input_bytes(), 2);
    }

    #[test]
    fn a_failed_final_cut_leaves_the_recorder_retryable() {
        let mut recorder = recorder(false);
        recorder.push_output(b"abc").unwrap();
        recorder.set_compressor(failing_compressor);
        assert_eq!(
            recorder.finish(Some(0), 5).err(),
            Some(RecordError::Compress)
        );
        assert!(recorder.take_chunks().is_empty());
        recorder.push_output(b"def").unwrap();
        recorder.set_compressor(compress_zstd);
        let manifest = recorder.finish(Some(0), 6).unwrap();
        let chunks = recorder.take_chunks();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_last);
        assert_eq!(chunks[0].seq, 0);
        assert_eq!(manifest.chunks, 1);
        let cast = String::from_utf8(zstd::stream::decode_all(&chunks[0].compressed[..]).unwrap())
            .unwrap();
        assert!(cast.contains("\"abc\"") && cast.contains("\"def\""));
        assert_eq!(recorder.push_output(b"x"), Err(RecordError::Finished));
    }

    #[test]
    fn debug_output_redacts_the_command() {
        let mut config = config(false);
        config.kind = SessionKind::Exec;
        config.command = Some("mysql --password=hunter2".to_owned());
        let shown = format!("{config:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("<redacted>"));

        let meta = MetadataOnly {
            session_id: "s".to_owned(),
            kind: SessionKind::Exec,
            node: "n".to_owned(),
            user: "u".to_owned(),
            login: "l".to_owned(),
            command: Some("mysql --password=hunter2".to_owned()),
            started_at: 0,
            ended_at: None,
            exit_status: None,
            bytes_out: 0,
            bytes_in: 0,
        };
        assert!(!format!("{meta:?}").contains("hunter2"));
        let manifest = Recorder::metadata_only(meta).unwrap();
        let shown = format!("{manifest:?}");
        assert!(!shown.contains("hunter2"));
        assert!(shown.contains("<redacted>"));
        assert!(format!("{:?}", config.command).contains("hunter2"));
    }
}
