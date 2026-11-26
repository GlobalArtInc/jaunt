use std::fmt;

use jaunt_record::{RecordError, Recorder, SessionManifest};
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use thiserror::Error;

use crate::channel::{
    ChannelError, ChannelFrame, ChannelProtocol, RESIZE, STATUS, STDERR, STDIN, STDOUT,
    parse_channel_message,
};

pub const MAX_STATUS_BYTES: usize = 64 * 1024;
pub const MAX_RESIZE_PENDING_BYTES: usize = 4 * 1024;
pub const EXEC_CHANNELS: u8 = 5;

const STATUS_SUCCESS: &str = "Success";
const STATUS_FAILURE: &str = "Failure";
const NON_ZERO_EXIT_CODE: &str = "NonZeroExitCode";
const EXIT_CODE_CAUSE: &str = "ExitCode";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    Exited(u8),
    Failed,
    Malformed,
    Missing,
}

impl ExecStatus {
    pub fn exit_code(self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(i32::from(code)),
            Self::Failed | Self::Malformed | Self::Missing => None,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecCastError {
    #[error("exec channel message is not valid")]
    Channel(#[from] ChannelError),
    #[error("terminal resize stream is not valid")]
    InvalidResize,
    #[error("exec status exceeds {MAX_STATUS_BYTES} bytes")]
    StatusTooLarge,
    #[error("close signal names channel {channel}, which exec does not have")]
    UnknownChannelClosed { channel: u8 },
    #[error("recording the exec session failed")]
    Record(#[from] RecordError),
}

#[derive(Debug)]
pub struct ExecOutcome {
    pub manifest: SessionManifest,
    pub status: ExecStatus,
}

pub struct ExecCast {
    protocol: ChannelProtocol,
    stdout_tail: Vec<u8>,
    stderr_tail: Vec<u8>,
    status: Vec<u8>,
    status_overflow: bool,
    stdin_enabled: bool,
    stdin_closed: bool,
    resize_pending: Vec<u8>,
    resize_closed: bool,
    resize_broken: bool,
    client_broken: Option<u8>,
}

impl fmt::Debug for ExecCast {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExecCast")
            .field("protocol", &self.protocol)
            .field("stdout_tail_bytes", &self.stdout_tail.len())
            .field("stderr_tail_bytes", &self.stderr_tail.len())
            .field("status_bytes", &self.status.len())
            .field("status_overflow", &self.status_overflow)
            .field("stdin_enabled", &self.stdin_enabled)
            .field("stdin_closed", &self.stdin_closed)
            .field("resize_pending_bytes", &self.resize_pending.len())
            .field("resize_closed", &self.resize_closed)
            .field("resize_broken", &self.resize_broken)
            .field("client_broken", &self.client_broken)
            .finish()
    }
}

impl ExecCast {
    pub fn new(protocol: ChannelProtocol, stdin_enabled: bool) -> Self {
        Self {
            protocol,
            stdout_tail: Vec::new(),
            stderr_tail: Vec::new(),
            status: Vec::new(),
            status_overflow: false,
            stdin_enabled,
            stdin_closed: false,
            resize_pending: Vec::new(),
            resize_closed: false,
            resize_broken: false,
            client_broken: None,
        }
    }

    pub fn client_message(
        &mut self,
        recorder: &mut Recorder,
        message: &[u8],
    ) -> Result<(), ExecCastError> {
        if let Some(channel) = self.client_broken {
            return Err(ExecCastError::UnknownChannelClosed { channel });
        }
        let frame = match parse_channel_message(self.protocol, message) {
            Err(ChannelError::Empty) => return Ok(()),
            other => other?,
        };
        match frame {
            ChannelFrame::Close { channel } if channel >= EXEC_CHANNELS => {
                self.client_broken = Some(channel);
                return Err(ExecCastError::UnknownChannelClosed { channel });
            }
            ChannelFrame::Close { channel: STDIN } => self.stdin_closed = true,
            ChannelFrame::Close { channel: RESIZE } => {
                self.resize_closed = true;
                self.resize_pending = Vec::new();
            }
            ChannelFrame::Close { .. } => {}
            ChannelFrame::Data {
                channel: STDIN,
                payload,
            } => {
                if self.stdin_enabled && !self.stdin_closed {
                    recorder.push_input(payload)?;
                }
            }
            ChannelFrame::Data {
                channel: RESIZE,
                payload,
            } => self.resize(recorder, payload)?,
            ChannelFrame::Data { .. } => {}
        }
        Ok(())
    }

    pub fn server_message(
        &mut self,
        recorder: &mut Recorder,
        message: &[u8],
    ) -> Result<(), ExecCastError> {
        let frame = match parse_channel_message(self.protocol, message) {
            Err(ChannelError::Empty) => return Ok(()),
            other => other?,
        };
        match frame {
            ChannelFrame::Data {
                channel: STDOUT,
                payload,
            } => push_output(recorder, &mut self.stdout_tail, payload)?,
            ChannelFrame::Data {
                channel: STDERR,
                payload,
            } => push_output(recorder, &mut self.stderr_tail, payload)?,
            ChannelFrame::Data {
                channel: STATUS,
                payload,
            } => self.append_status(payload)?,
            ChannelFrame::Data { .. } | ChannelFrame::Close { .. } => {}
        }
        Ok(())
    }

    pub fn status(&self) -> ExecStatus {
        if self.status_overflow {
            return ExecStatus::Malformed;
        }
        if self.status.is_empty() {
            return ExecStatus::Missing;
        }
        decode_status(&self.status)
    }

    pub fn finish(
        &mut self,
        recorder: &mut Recorder,
        ended_at: u64,
    ) -> Result<ExecOutcome, ExecCastError> {
        for tail in [
            std::mem::take(&mut self.stdout_tail),
            std::mem::take(&mut self.stderr_tail),
        ] {
            if !tail.is_empty() {
                recorder.push_output(String::from_utf8_lossy(&tail).as_bytes())?;
            }
        }
        let status = self.status();
        let manifest = recorder.finish(status.exit_code(), ended_at)?;
        Ok(ExecOutcome { manifest, status })
    }

    fn resize(&mut self, recorder: &mut Recorder, payload: &[u8]) -> Result<(), ExecCastError> {
        if self.resize_closed || self.resize_broken {
            return Ok(());
        }
        if payload.len() > MAX_RESIZE_PENDING_BYTES.saturating_sub(self.resize_pending.len()) {
            return Err(self.break_resize());
        }
        self.resize_pending.extend_from_slice(payload);
        let pending = std::mem::take(&mut self.resize_pending);
        let mut sizes =
            serde_json::Deserializer::from_slice(&pending).into_iter::<Option<TerminalSize>>();
        let mut failed = false;
        for size in sizes.by_ref() {
            match size {
                Ok(size) => {
                    let size = size.unwrap_or_default();
                    recorder.resize(size.width, size.height)?;
                }
                Err(error) => {
                    failed = !error.is_eof();
                    break;
                }
            }
        }
        if failed {
            return Err(self.break_resize());
        }
        let consumed = sizes.byte_offset();
        self.resize_pending = pending.get(consumed..).unwrap_or_default().to_vec();
        Ok(())
    }

    fn break_resize(&mut self) -> ExecCastError {
        self.resize_broken = true;
        self.resize_pending = Vec::new();
        ExecCastError::InvalidResize
    }

    fn append_status(&mut self, payload: &[u8]) -> Result<(), ExecCastError> {
        if self.status_overflow
            || payload.len() > MAX_STATUS_BYTES.saturating_sub(self.status.len())
        {
            self.status_overflow = true;
            self.status = Vec::new();
            return Err(ExecCastError::StatusTooLarge);
        }
        self.status.extend_from_slice(payload);
        Ok(())
    }
}

fn push_output(
    recorder: &mut Recorder,
    tail: &mut Vec<u8>,
    payload: &[u8],
) -> Result<(), RecordError> {
    let mut pending = std::mem::take(tail);
    pending.extend_from_slice(payload);
    let complete = complete_utf8_prefix(&pending);
    *tail = pending.split_off(complete);
    if pending.is_empty() {
        return Ok(());
    }
    recorder.push_output(&pending)
}

fn complete_utf8_prefix(bytes: &[u8]) -> usize {
    let len = bytes.len();
    for back in 1..=len.min(3) {
        let start = len - back;
        let Some(&byte) = bytes.get(start) else {
            return len;
        };
        if byte & 0b1100_0000 == 0b1000_0000 {
            continue;
        }
        let needed = match byte {
            0xC2..=0xDF => 2,
            0xE0..=0xEF => 3,
            0xF0..=0xF4 => 4,
            _ => return len,
        };
        return if back < needed { start } else { len };
    }
    len
}

#[derive(Debug, Default, Clone, Copy)]
struct TerminalSize {
    width: u16,
    height: u16,
}

impl<'de> Deserialize<'de> for TerminalSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(TerminalSizeVisitor)
    }
}

struct TerminalSizeVisitor;

impl<'de> Visitor<'de> for TerminalSizeVisitor {
    type Value = TerminalSize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a terminal size object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<TerminalSize, A::Error> {
        let mut size = TerminalSize::default();
        while let Some(key) = map.next_key::<String>()? {
            let target = if key.eq_ignore_ascii_case("width") {
                &mut size.width
            } else if key.eq_ignore_ascii_case("height") {
                &mut size.height
            } else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            if let Some(value) = map.next_value::<Option<u16>>()? {
                *target = value;
            }
        }
        Ok(size)
    }
}

#[derive(Deserialize)]
struct WireStatus {
    status: Option<String>,
    reason: Option<String>,
    details: Option<WireDetails>,
}

#[derive(Deserialize)]
struct WireDetails {
    causes: Option<Vec<WireCause>>,
}

#[derive(Deserialize)]
struct WireCause {
    reason: Option<String>,
    message: Option<String>,
}

fn decode_status(bytes: &[u8]) -> ExecStatus {
    let Ok(status) = serde_json::from_slice::<WireStatus>(bytes) else {
        return ExecStatus::Malformed;
    };
    match status.status.as_deref() {
        Some(STATUS_SUCCESS) => ExecStatus::Exited(0),
        Some(STATUS_FAILURE) if status.reason.as_deref() == Some(NON_ZERO_EXIT_CODE) => {
            let code = status
                .details
                .and_then(|details| details.causes)
                .unwrap_or_default()
                .into_iter()
                .find(|cause| cause.reason.as_deref() == Some(EXIT_CODE_CAUSE))
                .and_then(|cause| parse_exit_code(cause.message.as_deref().unwrap_or("")));
            code.map_or(ExecStatus::Malformed, ExecStatus::Exited)
        }
        Some(STATUS_FAILURE) => ExecStatus::Failed,
        _ => ExecStatus::Malformed,
    }
}

fn parse_exit_code(text: &str) -> Option<u8> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}
