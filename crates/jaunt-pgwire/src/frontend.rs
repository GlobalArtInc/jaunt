use std::fmt;

use bytes::Bytes;

use crate::error::{DecodeError, Problem};
use crate::frame::{Event, Frame, Stream};
use crate::limits::{Limits, LimitsError};
use crate::reader::{Reader, length_field, lossy};
use crate::startup::{
    CANCEL_REQUEST_CODE, CancelRequest, GSSENC_REQUEST_CODE, ProtocolVersion, SSL_REQUEST_CODE,
    StartupMessage,
};
use crate::statement::Statement;

const STARTUP_PACKET: &str = "startup packet";
const SSL_REQUEST: &str = "SSLRequest";
const GSSENC_REQUEST: &str = "GSSENCRequest";
const MESSAGE: &str = "message";
const QUERY: &str = "Query";
const PARSE: &str = "Parse";
const BIND: &str = "Bind";
const EXECUTE: &str = "Execute";
const DESCRIBE: &str = "Describe";
const CLOSE: &str = "Close";
const SYNC: &str = "Sync";
const FLUSH: &str = "Flush";
const TERMINATE: &str = "Terminate";
const COPY_DATA: &str = "CopyData";
const COPY_DONE: &str = "CopyDone";
const COPY_FAIL: &str = "CopyFail";
const PASSWORD: &str = "password response";

const HEADER: usize = 5;
const NEGOTIATION_LENGTH: usize = 8;
const SUPPORTED_MAJOR: u16 = 3;

#[derive(Debug, Clone)]
pub enum FrontendMessage {
    SslRequest,
    GssEncRequest,
    Cancel(CancelRequest),
    Startup(StartupMessage),
    Query(Statement),
    QueryText { length: usize },
    Parse(Parse),
    Bind(Bind),
    Execute(Execute),
    Describe(Target),
    Close(Target),
    Sync,
    Flush,
    Terminate,
    CopyData { length: usize },
    CopyDone,
    CopyFail(CopyFail),
    Password(PasswordResponse),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parse {
    pub name: String,
    pub statement: Statement,
    pub parameter_type_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bind {
    pub portal: String,
    pub statement: String,
    pub parameter_format_count: usize,
    pub parameter_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Execute {
    pub portal: String,
    pub max_rows: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Statement,
    Portal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub kind: TargetKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyFail {
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordKind {
    Password,
    SaslInitial,
    Sasl,
    Gss,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordVariant {
    Password,
    SaslInitial {
        mechanism: String,
        data_length: Option<usize>,
    },
    Sasl {
        data_length: usize,
    },
    Gss {
        data_length: usize,
    },
}

#[derive(Clone, PartialEq, Eq)]
pub struct PasswordResponse {
    body: Bytes,
}

impl PasswordResponse {
    pub fn length(&self) -> usize {
        self.body.len()
    }

    pub fn interpret(&self, kind: PasswordKind) -> Result<PasswordVariant, DecodeError> {
        let malformed = DecodeError::malformed(PASSWORD);
        let mut reader = Reader::new(&self.body);
        let variant = match kind {
            PasswordKind::Password => {
                reader.cstr().map_err(&malformed)?;
                PasswordVariant::Password
            }
            PasswordKind::SaslInitial => {
                let mechanism = lossy(reader.cstr().map_err(&malformed)?);
                let declared = reader.i32().map_err(&malformed)?;
                let data_length = match declared {
                    -1 => None,
                    length => {
                        let length = usize::try_from(length)
                            .map_err(|_| malformed(Problem::InvalidLength))?;
                        reader.take(length).map_err(&malformed)?;
                        Some(length)
                    }
                };
                PasswordVariant::SaslInitial {
                    mechanism,
                    data_length,
                }
            }
            PasswordKind::Sasl => PasswordVariant::Sasl {
                data_length: reader.rest().len(),
            },
            PasswordKind::Gss => PasswordVariant::Gss {
                data_length: reader.rest().len(),
            },
        };
        reader.finish().map_err(&malformed)?;
        Ok(variant)
    }
}

impl fmt::Debug for PasswordResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordResponse")
            .field("length", &self.body.len())
            .field("body", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Startup { ssl: bool, gss: bool },
    Regular,
    Ended,
}

#[derive(Debug, Clone, Copy)]
enum Class {
    Empty(&'static str, EmptyMessage),
    Buffered(&'static str),
    Streamed,
    StreamedQuery,
    Bind,
}

#[derive(Debug, Clone, Copy)]
enum EmptyMessage {
    Sync,
    Flush,
    Terminate,
    CopyDone,
}

#[derive(Debug, Default)]
struct BindScan {
    searched: usize,
    portal_end: Option<usize>,
    statement_end: Option<usize>,
}

#[derive(Debug)]
struct QueryScan {
    remaining: usize,
}

impl QueryScan {
    fn check(&mut self, chunk: &[u8]) -> Result<(), DecodeError> {
        self.remaining = self.remaining.saturating_sub(chunk.len());
        let last = self.remaining == 0;
        if let Some(position) = chunk.iter().position(|byte| *byte == 0)
            && !(last && position + 1 == chunk.len())
        {
            return Err(DecodeError::Malformed {
                message: QUERY,
                problem: Problem::TrailingBytes,
            });
        }
        if last && chunk.last() != Some(&0) {
            return Err(DecodeError::Malformed {
                message: QUERY,
                problem: Problem::MissingTerminator,
            });
        }
        Ok(())
    }
}

pub struct FrontendDecoder {
    limits: Limits,
    stream: Stream,
    phase: Phase,
    bind: Option<BindScan>,
    streamed_queries: bool,
    query: Option<QueryScan>,
}

impl FrontendDecoder {
    pub fn new(limits: Limits) -> Result<Self, LimitsError> {
        limits.validate()?;
        Ok(Self {
            limits,
            stream: Stream::new(limits.max_pending),
            phase: Phase::Startup {
                ssl: false,
                gss: false,
            },
            bind: None,
            streamed_queries: false,
            query: None,
        })
    }

    pub fn with_streamed_queries(limits: Limits) -> Result<Self, LimitsError> {
        let mut decoder = Self::new(limits)?;
        decoder.streamed_queries = true;
        Ok(decoder)
    }

    pub fn push(&mut self, input: &[u8]) -> Result<(), DecodeError> {
        self.stream.push(input)
    }

    pub fn next_event(&mut self) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        if self.stream.is_poisoned() {
            return Err(DecodeError::Poisoned);
        }
        let result = self.decode();
        if result.is_err() {
            self.stream.poison();
            self.bind = None;
            self.query = None;
        }
        result
    }

    pub fn is_poisoned(&self) -> bool {
        self.stream.is_poisoned()
    }

    pub fn pending(&self) -> usize {
        self.stream.pending()
    }

    fn decode(&mut self) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        if let Some(chunk) = self.stream.continuation() {
            if let Some(scan) = &mut self.query {
                scan.check(chunk.bytes())?;
                if scan.remaining == 0 {
                    self.query = None;
                }
            }
            return Ok(Some(Event::Continuation(chunk)));
        }
        if self.stream.in_continuation() {
            return Ok(None);
        }
        match self.phase {
            Phase::Startup { ssl, gss } => self.startup(ssl, gss),
            Phase::Regular => self.regular(),
            Phase::Ended if self.stream.pending() == 0 => Ok(None),
            Phase::Ended => Err(DecodeError::DataAfterEnd),
        }
    }

    fn startup(
        &mut self,
        ssl: bool,
        gss: bool,
    ) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        let buffered = self.stream.buffered();
        if buffered.len() < 4 {
            return Ok(None);
        }
        let length = length_field(buffered)
            .filter(|length| *length >= NEGOTIATION_LENGTH)
            .ok_or(DecodeError::Malformed {
                message: STARTUP_PACKET,
                problem: Problem::InvalidLength,
            })?;
        if length > self.limits.max_startup_message {
            return Err(DecodeError::TooLarge {
                message: STARTUP_PACKET,
                length,
                limit: self.limits.max_startup_message,
            });
        }
        if buffered.len() < length {
            return Ok(None);
        }
        let raw = self.stream.split(length, 0);
        let code = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let message = match code {
            SSL_REQUEST_CODE => {
                negotiation(SSL_REQUEST, length, ssl)?;
                self.phase = Phase::Startup { ssl: true, gss };
                FrontendMessage::SslRequest
            }
            GSSENC_REQUEST_CODE => {
                negotiation(GSSENC_REQUEST, length, gss)?;
                self.phase = Phase::Startup { ssl, gss: true };
                FrontendMessage::GssEncRequest
            }
            CANCEL_REQUEST_CODE => {
                let cancel = CancelRequest::decode(&raw[NEGOTIATION_LENGTH..])?;
                self.phase = Phase::Ended;
                FrontendMessage::Cancel(cancel)
            }
            code => {
                let version = ProtocolVersion::from_code(code);
                if version.major != SUPPORTED_MAJOR {
                    return Err(DecodeError::UnsupportedProtocol {
                        major: version.major,
                        minor: version.minor,
                    });
                }
                let startup = StartupMessage::decode(
                    version,
                    &raw[NEGOTIATION_LENGTH..],
                    self.limits.max_startup_parameters,
                )?;
                self.phase = Phase::Regular;
                FrontendMessage::Startup(startup)
            }
        };
        Ok(Some(Event::Frame(Frame::new(message, raw, 0))))
    }

    fn regular(&mut self) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        let buffered = self.stream.buffered();
        let Some(&tag) = buffered.first() else {
            return Ok(None);
        };
        let class = if tag == b'Q' && self.streamed_queries {
            Class::StreamedQuery
        } else {
            classify(tag)?
        };
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
            Class::Empty(name, kind) => {
                if body_length != 0 {
                    return Err(DecodeError::Malformed {
                        message: name,
                        problem: Problem::InvalidLength,
                    });
                }
                if matches!(kind, EmptyMessage::Terminate) {
                    self.phase = Phase::Ended;
                }
                let raw = self.stream.split(HEADER, 0);
                Ok(Some(Event::Frame(Frame::new(kind.message(), raw, 0))))
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
            Class::Streamed => {
                self.check_data(COPY_DATA, length)?;
                let raw = self.stream.split(HEADER, body_length);
                let message = FrontendMessage::CopyData {
                    length: body_length,
                };
                Ok(Some(Event::Frame(Frame::new(message, raw, body_length))))
            }
            Class::StreamedQuery => {
                self.check_data(QUERY, length)?;
                if body_length == 0 {
                    return Err(DecodeError::Malformed {
                        message: QUERY,
                        problem: Problem::MissingTerminator,
                    });
                }
                self.query = Some(QueryScan {
                    remaining: body_length,
                });
                let raw = self.stream.split(HEADER, body_length);
                let message = FrontendMessage::QueryText {
                    length: body_length,
                };
                Ok(Some(Event::Frame(Frame::new(message, raw, body_length))))
            }
            Class::Bind => {
                self.check_data(BIND, length)?;
                self.bind(body_length)
            }
        }
    }

    fn check_data(&self, message: &'static str, length: usize) -> Result<(), DecodeError> {
        if length > self.limits.max_data_message {
            return Err(DecodeError::TooLarge {
                message,
                length,
                limit: self.limits.max_data_message,
            });
        }
        Ok(())
    }

    fn bind(&mut self, body_length: usize) -> Result<Option<Event<FrontendMessage>>, DecodeError> {
        let limit = self.limits.max_statement_message;
        let buffered = self.stream.buffered();
        let available = (buffered.len() - HEADER).min(body_length);
        let window = available.min(limit);
        let body = &buffered[HEADER..HEADER + window];
        let scan = self.bind.get_or_insert_with(BindScan::default);
        while scan.statement_end.is_none() {
            match body[scan.searched..].iter().position(|byte| *byte == 0) {
                Some(offset) => {
                    let end = scan.searched + offset;
                    scan.searched = end + 1;
                    if scan.portal_end.is_none() {
                        scan.portal_end = Some(end);
                    } else {
                        scan.statement_end = Some(end);
                    }
                }
                None => {
                    scan.searched = window;
                    break;
                }
            }
        }
        let (Some(portal_end), Some(statement_end)) = (scan.portal_end, scan.statement_end) else {
            return if window == limit {
                Err(DecodeError::BindPrefixTooLarge { limit })
            } else if available == body_length {
                Err(DecodeError::Malformed {
                    message: BIND,
                    problem: Problem::MissingTerminator,
                })
            } else {
                Ok(None)
            };
        };
        let formats_at = statement_end + 1;
        let Some(format_count) = read_count(body_length, available, limit, body, formats_at)?
        else {
            return Ok(None);
        };
        let parameters_at = formats_at + 2 + 2 * format_count;
        let Some(parameter_count) = read_count(body_length, available, limit, body, parameters_at)?
        else {
            return Ok(None);
        };
        let prefix = parameters_at + 2;
        let message = Bind {
            portal: lossy(&body[..portal_end]),
            statement: lossy(&body[portal_end + 1..statement_end]),
            parameter_format_count: format_count,
            parameter_count,
        };
        self.bind = None;
        let raw = self.stream.split(HEADER + prefix, body_length - prefix);
        Ok(Some(Event::Frame(Frame::new(
            FrontendMessage::Bind(message),
            raw,
            body_length - prefix,
        ))))
    }
}

fn read_count(
    body_length: usize,
    available: usize,
    limit: usize,
    window: &[u8],
    at: usize,
) -> Result<Option<usize>, DecodeError> {
    let end = at + 2;
    if end > limit {
        return Err(DecodeError::BindPrefixTooLarge { limit });
    }
    if end > body_length {
        return Err(DecodeError::Malformed {
            message: BIND,
            problem: Problem::Truncated,
        });
    }
    if end > available {
        return Ok(None);
    }
    let count = i16::from_be_bytes([window[at], window[at + 1]]);
    usize::try_from(count)
        .map(Some)
        .map_err(|_| DecodeError::Malformed {
            message: BIND,
            problem: Problem::NegativeCount,
        })
}

fn negotiation(message: &'static str, length: usize, seen: bool) -> Result<(), DecodeError> {
    if length != NEGOTIATION_LENGTH {
        return Err(DecodeError::Malformed {
            message,
            problem: Problem::InvalidLength,
        });
    }
    if seen {
        return Err(DecodeError::RepeatedNegotiation { message });
    }
    Ok(())
}

impl EmptyMessage {
    fn message(self) -> FrontendMessage {
        match self {
            Self::Sync => FrontendMessage::Sync,
            Self::Flush => FrontendMessage::Flush,
            Self::Terminate => FrontendMessage::Terminate,
            Self::CopyDone => FrontendMessage::CopyDone,
        }
    }
}

fn classify(tag: u8) -> Result<Class, DecodeError> {
    Ok(match tag {
        b'Q' => Class::Buffered(QUERY),
        b'P' => Class::Buffered(PARSE),
        b'E' => Class::Buffered(EXECUTE),
        b'D' => Class::Buffered(DESCRIBE),
        b'C' => Class::Buffered(CLOSE),
        b'f' => Class::Buffered(COPY_FAIL),
        b'p' => Class::Buffered(PASSWORD),
        b'B' => Class::Bind,
        b'd' => Class::Streamed,
        b'S' => Class::Empty(SYNC, EmptyMessage::Sync),
        b'H' => Class::Empty(FLUSH, EmptyMessage::Flush),
        b'X' => Class::Empty(TERMINATE, EmptyMessage::Terminate),
        b'c' => Class::Empty(COPY_DONE, EmptyMessage::CopyDone),
        b'F' => return Err(DecodeError::FunctionCallRefused),
        tag => return Err(DecodeError::UnknownMessage { tag }),
    })
}

fn buffered_message(tag: u8, body: Bytes) -> Result<FrontendMessage, DecodeError> {
    match tag {
        b'Q' => statement_text(QUERY, &body).map(FrontendMessage::Query),
        b'P' => parse(&body).map(FrontendMessage::Parse),
        b'E' => execute(&body).map(FrontendMessage::Execute),
        b'D' => target(DESCRIBE, &body).map(FrontendMessage::Describe),
        b'C' => target(CLOSE, &body).map(FrontendMessage::Close),
        b'f' => copy_fail(&body).map(FrontendMessage::CopyFail),
        b'p' => Ok(FrontendMessage::Password(PasswordResponse { body })),
        tag => Err(DecodeError::UnknownMessage { tag }),
    }
}

fn statement_text(message: &'static str, body: &[u8]) -> Result<Statement, DecodeError> {
    let malformed = DecodeError::malformed(message);
    let mut reader = Reader::new(body);
    let text = reader.cstr().map_err(&malformed)?;
    reader.finish().map_err(&malformed)?;
    Ok(Statement::new(text))
}

fn parse(body: &[u8]) -> Result<Parse, DecodeError> {
    let malformed = DecodeError::malformed(PARSE);
    let mut reader = Reader::new(body);
    let name = lossy(reader.cstr().map_err(&malformed)?);
    let statement = Statement::new(reader.cstr().map_err(&malformed)?);
    let parameter_type_count = reader.count().map_err(&malformed)?;
    reader.take(4 * parameter_type_count).map_err(&malformed)?;
    reader.finish().map_err(&malformed)?;
    Ok(Parse {
        name,
        statement,
        parameter_type_count,
    })
}

fn execute(body: &[u8]) -> Result<Execute, DecodeError> {
    let malformed = DecodeError::malformed(EXECUTE);
    let mut reader = Reader::new(body);
    let portal = lossy(reader.cstr().map_err(&malformed)?);
    let max_rows = reader.i32().map_err(&malformed)?;
    reader.finish().map_err(&malformed)?;
    Ok(Execute { portal, max_rows })
}

fn target(message: &'static str, body: &[u8]) -> Result<Target, DecodeError> {
    let malformed = DecodeError::malformed(message);
    let mut reader = Reader::new(body);
    let kind = match reader.u8().map_err(&malformed)? {
        b'S' => TargetKind::Statement,
        b'P' => TargetKind::Portal,
        _ => return Err(malformed(Problem::InvalidValue)),
    };
    let name = lossy(reader.cstr().map_err(&malformed)?);
    reader.finish().map_err(&malformed)?;
    Ok(Target { kind, name })
}

fn copy_fail(body: &[u8]) -> Result<CopyFail, DecodeError> {
    let malformed = DecodeError::malformed(COPY_FAIL);
    let mut reader = Reader::new(body);
    let message = lossy(reader.cstr().map_err(&malformed)?);
    reader.finish().map_err(&malformed)?;
    Ok(CopyFail { message })
}
