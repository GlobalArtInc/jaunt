use std::fmt;

use bytes::Bytes;

use crate::error::{DecodeError, Problem};
use crate::frame::{Event, Frame, Stream};
use crate::limits::{Limits, LimitsError};
use crate::reader::{Reader, length_field, lossy};
use crate::startup::{MAX_CANCEL_KEY_BYTES, MIN_CANCEL_KEY_BYTES, ProtocolVersion};

const MESSAGE: &str = "message";
const AUTHENTICATION: &str = "Authentication";
const BACKEND_KEY_DATA: &str = "BackendKeyData";
const PARAMETER_STATUS: &str = "ParameterStatus";
const READY_FOR_QUERY: &str = "ReadyForQuery";
const ERROR_RESPONSE: &str = "ErrorResponse";
const NOTICE_RESPONSE: &str = "NoticeResponse";
const COMMAND_COMPLETE: &str = "CommandComplete";
const COPY_IN_RESPONSE: &str = "CopyInResponse";
const COPY_OUT_RESPONSE: &str = "CopyOutResponse";
const COPY_BOTH_RESPONSE: &str = "CopyBothResponse";
const NEGOTIATE_PROTOCOL_VERSION: &str = "NegotiateProtocolVersion";
const DATA_ROW: &str = "DataRow";
const COPY_DATA: &str = "CopyData";
const OTHER: &str = "backend message";

const HEADER: usize = 5;
const ROW_COUNT_COMMANDS: &[&str] = &[
    "INSERT", "DELETE", "UPDATE", "MERGE", "SELECT", "MOVE", "FETCH", "COPY",
];

#[derive(Debug, Clone)]
pub enum BackendMessage {
    Authentication(Authentication),
    BackendKeyData(BackendKeyData),
    ParameterStatus(ParameterStatus),
    ReadyForQuery(TransactionStatus),
    ErrorResponse(Notice),
    NoticeResponse(Notice),
    CommandComplete(CommandComplete),
    CopyInResponse(CopyResponse),
    CopyOutResponse(CopyResponse),
    CopyBothResponse(CopyResponse),
    NegotiateProtocolVersion(NegotiateProtocolVersion),
    DataRow { length: usize },
    CopyData { length: usize },
    Other { tag: u8, length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    Ok,
    KerberosV5,
    CleartextPassword,
    Md5Password,
    Gss,
    GssContinue,
    Sspi,
    Sasl { mechanisms: Vec<String> },
    SaslContinue,
    SaslFinal,
}

impl Authentication {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[derive(Clone)]
pub struct BackendKeyData {
    process_id: i32,
    secret_key: Bytes,
}

impl BackendKeyData {
    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

impl fmt::Debug for BackendKeyData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendKeyData")
            .field("process_id", &self.process_id)
            .field("secret_key", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterStatus {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Idle,
    InTransaction,
    Failed,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Notice {
    pub severity: String,
    pub code: String,
    pub message: String,
}

impl fmt::Debug for Notice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notice")
            .field("severity", &self.severity)
            .field("code", &self.code)
            .field("message_length", &self.message.len())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandComplete {
    pub command: String,
    pub rows: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyFormat {
    Text,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyResponse {
    pub format: CopyFormat,
    pub column_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateProtocolVersion {
    pub newest_version: ProtocolVersion,
    pub unrecognized_options: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Fixed,
    Buffered(&'static str),
    Streamed(&'static str),
}

pub struct BackendDecoder {
    limits: Limits,
    stream: Stream,
}

impl BackendDecoder {
    pub fn new(limits: Limits) -> Result<Self, LimitsError> {
        limits.validate()?;
        Ok(Self {
            limits,
            stream: Stream::new(limits.max_pending),
        })
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        self.stream.push(input)
    }

    pub fn next_event(&mut self) -> Result<Option<Event<BackendMessage>>, DecodeError> {
        if self.stream.is_poisoned() {
            return Err(DecodeError::Poisoned);
        }
        let result = self.decode();
        if result.is_err() {
            self.stream.poison();
        }
        result
    }

    pub fn is_poisoned(&self) -> bool {
        self.stream.is_poisoned()
    }

    pub fn pending(&self) -> usize {
        self.stream.pending()
    }

    fn decode(&mut self) -> Result<Option<Event<BackendMessage>>, DecodeError> {
        if let Some(chunk) = self.stream.continuation() {
            return Ok(Some(Event::Continuation(chunk)));
        }
        if self.stream.in_continuation() {
            return Ok(None);
        }
        let buffered = self.stream.buffered();
        let Some(&tag) = buffered.first() else {
            return Ok(None);
        };
        let class = classify(tag)?;
        if buffered.len() < HEADER {
            return Ok(None);
        }
        let length = length_field(&buffered[1..])
            .filter(|length| *length >= 4)
            .ok_or(DecodeError::Malformed {
                message: MESSAGE,
                problem: Problem::InvalidLength,
            })?;
        let body_length = length - 4;
        match class {
            Class::Fixed => {
                if body_length != 0 {
                    return Err(DecodeError::Malformed {
                        message: OTHER,
                        problem: Problem::InvalidLength,
                    });
                }
                let raw = self.stream.split(HEADER, 0);
                let message = BackendMessage::Other { tag, length: 0 };
                Ok(Some(Event::Frame(Frame::new(message, raw, 0))))
            }
            Class::Buffered(name) => {
                if length > self.limits.max_statement_message {
                    return Err(DecodeError::TooLarge {
                        message: name,
                        length,
                        limit: self.limits.max_statement_message,
                    });
                }
                if buffered.len() < HEADER + body_length {
                    return Ok(None);
                }
                let raw = self.stream.split(HEADER + body_length, 0);
                let message = buffered_message(tag, raw.slice(HEADER..))?;
                Ok(Some(Event::Frame(Frame::new(message, raw, 0))))
            }
            Class::Streamed(name) => {
                if length > self.limits.max_data_message {
                    return Err(DecodeError::TooLarge {
                        message: name,
                        length,
                        limit: self.limits.max_data_message,
                    });
                }
                let raw = self.stream.split(HEADER, body_length);
                let message = match tag {
                    b'D' => BackendMessage::DataRow {
                        length: body_length,
                    },
                    b'd' => BackendMessage::CopyData {
                        length: body_length,
                    },
                    tag => BackendMessage::Other {
                        tag,
                        length: body_length,
                    },
                };
                Ok(Some(Event::Frame(Frame::new(message, raw, body_length))))
            }
        }
    }
}

fn classify(tag: u8) -> Result<Class, DecodeError> {
    Ok(match tag {
        b'R' => Class::Buffered(AUTHENTICATION),
        b'K' => Class::Buffered(BACKEND_KEY_DATA),
        b'S' => Class::Buffered(PARAMETER_STATUS),
        b'Z' => Class::Buffered(READY_FOR_QUERY),
        b'E' => Class::Buffered(ERROR_RESPONSE),
        b'N' => Class::Buffered(NOTICE_RESPONSE),
        b'C' => Class::Buffered(COMMAND_COMPLETE),
        b'G' => Class::Buffered(COPY_IN_RESPONSE),
        b'H' => Class::Buffered(COPY_OUT_RESPONSE),
        b'W' => Class::Buffered(COPY_BOTH_RESPONSE),
        b'v' => Class::Buffered(NEGOTIATE_PROTOCOL_VERSION),
        b'D' => Class::Streamed(DATA_ROW),
        b'd' => Class::Streamed(COPY_DATA),
        b'T' | b't' | b'A' => Class::Streamed(OTHER),
        b'1' | b'2' | b'3' | b'n' | b's' | b'I' | b'c' => Class::Fixed,
        tag => return Err(DecodeError::UnknownMessage { tag }),
    })
}

fn buffered_message(tag: u8, body: Bytes) -> Result<BackendMessage, DecodeError> {
    match tag {
        b'R' => authentication(&body).map(BackendMessage::Authentication),
        b'K' => backend_key_data(&body).map(BackendMessage::BackendKeyData),
        b'S' => parameter_status(&body).map(BackendMessage::ParameterStatus),
        b'Z' => ready_for_query(&body).map(BackendMessage::ReadyForQuery),
        b'E' => notice(ERROR_RESPONSE, &body).map(BackendMessage::ErrorResponse),
        b'N' => notice(NOTICE_RESPONSE, &body).map(BackendMessage::NoticeResponse),
        b'C' => command_complete(&body).map(BackendMessage::CommandComplete),
        b'G' => copy_response(COPY_IN_RESPONSE, &body).map(BackendMessage::CopyInResponse),
        b'H' => copy_response(COPY_OUT_RESPONSE, &body).map(BackendMessage::CopyOutResponse),
        b'W' => copy_response(COPY_BOTH_RESPONSE, &body).map(BackendMessage::CopyBothResponse),
        b'v' => negotiate(&body).map(BackendMessage::NegotiateProtocolVersion),
        tag => Err(DecodeError::UnknownMessage { tag }),
    }
}

fn authentication(body: &[u8]) -> Result<Authentication, DecodeError> {
    let malformed = DecodeError::malformed(AUTHENTICATION);
    let mut reader = Reader::new(body);
    let code = reader.i32().map_err(&malformed)?;
    let request = match code {
        0 => Authentication::Ok,
        2 => Authentication::KerberosV5,
        3 => Authentication::CleartextPassword,
        5 => {
            reader.take(4).map_err(&malformed)?;
            Authentication::Md5Password
        }
        7 => Authentication::Gss,
        8 => {
            reader.rest();
            Authentication::GssContinue
        }
        9 => Authentication::Sspi,
        10 => {
            let mut mechanisms = Vec::new();
            loop {
                let mechanism = reader.cstr().map_err(&malformed)?;
                if mechanism.is_empty() {
                    break;
                }
                mechanisms.push(lossy(mechanism));
            }
            Authentication::Sasl { mechanisms }
        }
        11 => {
            reader.rest();
            Authentication::SaslContinue
        }
        12 => {
            reader.rest();
            Authentication::SaslFinal
        }
        code => return Err(DecodeError::UnknownAuthentication { code }),
    };
    reader.finish().map_err(&malformed)?;
    Ok(request)
}

fn backend_key_data(body: &[u8]) -> Result<BackendKeyData, DecodeError> {
    let malformed = DecodeError::malformed(BACKEND_KEY_DATA);
    let mut reader = Reader::new(body);
    let process_id = reader.i32().map_err(&malformed)?;
    let key_start = reader.position();
    if !(MIN_CANCEL_KEY_BYTES..=MAX_CANCEL_KEY_BYTES).contains(&reader.remaining()) {
        return Err(malformed(Problem::InvalidLength));
    }
    Ok(BackendKeyData {
        process_id,
        secret_key: Bytes::copy_from_slice(&body[key_start..]),
    })
}

fn parameter_status(body: &[u8]) -> Result<ParameterStatus, DecodeError> {
    let malformed = DecodeError::malformed(PARAMETER_STATUS);
    let mut reader = Reader::new(body);
    let name = lossy(reader.cstr().map_err(&malformed)?);
    let value = lossy(reader.cstr().map_err(&malformed)?);
    reader.finish().map_err(&malformed)?;
    Ok(ParameterStatus { name, value })
}

fn ready_for_query(body: &[u8]) -> Result<TransactionStatus, DecodeError> {
    let malformed = DecodeError::malformed(READY_FOR_QUERY);
    let mut reader = Reader::new(body);
    let status = match reader.u8().map_err(&malformed)? {
        b'I' => TransactionStatus::Idle,
        b'T' => TransactionStatus::InTransaction,
        b'E' => TransactionStatus::Failed,
        _ => return Err(malformed(Problem::InvalidValue)),
    };
    reader.finish().map_err(&malformed)?;
    Ok(status)
}

fn notice(message: &'static str, body: &[u8]) -> Result<Notice, DecodeError> {
    let malformed = DecodeError::malformed(message);
    let mut reader = Reader::new(body);
    let (mut localized, mut severity, mut code, mut text) = (None, None, None, None);
    loop {
        let field = reader.u8().map_err(&malformed)?;
        if field == 0 {
            break;
        }
        let value = reader.cstr().map_err(&malformed)?;
        match field {
            b'S' => localized = Some(value),
            b'V' => severity = Some(value),
            b'C' => code = Some(value),
            b'M' => text = Some(value),
            _ => {}
        }
    }
    reader.finish().map_err(&malformed)?;
    let (Some(severity), Some(code), Some(text)) = (severity.or(localized), code, text) else {
        return Err(malformed(Problem::MissingField));
    };
    Ok(Notice {
        severity: lossy(severity),
        code: lossy(code),
        message: lossy(text),
    })
}

fn command_complete(body: &[u8]) -> Result<CommandComplete, DecodeError> {
    let malformed = DecodeError::malformed(COMMAND_COMPLETE);
    let mut reader = Reader::new(body);
    let tag = lossy(reader.cstr().map_err(&malformed)?);
    reader.finish().map_err(&malformed)?;
    let mut words = tag.split(' ');
    let first = words.next().unwrap_or_default();
    let rows = words
        .next_back()
        .filter(|_| ROW_COUNT_COMMANDS.contains(&first))
        .and_then(|last| last.parse::<u64>().ok());
    let command = if rows.is_some() {
        first.to_owned()
    } else {
        tag.clone()
    };
    Ok(CommandComplete { command, rows })
}

fn copy_response(message: &'static str, body: &[u8]) -> Result<CopyResponse, DecodeError> {
    let malformed = DecodeError::malformed(message);
    let mut reader = Reader::new(body);
    let format = copy_format(reader.u8().map_err(&malformed)?).ok_or(Problem::InvalidValue);
    let format = format.map_err(&malformed)?;
    let column_count = reader.count().map_err(&malformed)?;
    for _ in 0..column_count {
        let column = reader.i16().map_err(&malformed)?;
        let valid = u8::try_from(column).ok().and_then(copy_format).is_some();
        if !valid {
            return Err(malformed(Problem::InvalidValue));
        }
    }
    reader.finish().map_err(&malformed)?;
    Ok(CopyResponse {
        format,
        column_count,
    })
}

fn copy_format(code: u8) -> Option<CopyFormat> {
    match code {
        0 => Some(CopyFormat::Text),
        1 => Some(CopyFormat::Binary),
        _ => None,
    }
}

fn negotiate(body: &[u8]) -> Result<NegotiateProtocolVersion, DecodeError> {
    let malformed = DecodeError::malformed(NEGOTIATE_PROTOCOL_VERSION);
    let mut reader = Reader::new(body);
    let newest_version = ProtocolVersion::from_code(reader.u32().map_err(&malformed)?);
    let count = usize::try_from(reader.i32().map_err(&malformed)?)
        .map_err(|_| malformed(Problem::NegativeCount))?;
    let mut unrecognized_options = Vec::new();
    for _ in 0..count {
        unrecognized_options.push(lossy(reader.cstr().map_err(&malformed)?));
    }
    reader.finish().map_err(&malformed)?;
    Ok(NegotiateProtocolVersion {
        newest_version,
        unrecognized_options,
    })
}
