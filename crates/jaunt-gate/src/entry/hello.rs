use std::fmt;
use std::io;

use rustls::server::{Accepted, Acceptor};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{Instant, timeout_at};

use super::{ALPN_SSH, ALPN_SVC};

pub const MAX_CLIENT_HELLO_BYTES: usize = 16 * 1024;
const RECORD_HEADER_LEN: usize = 5;
const MAX_RECORD_BODY: usize = 1 << 14;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const RECORD_VERSION_MAJOR: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HelloError {
    #[error("the client hello is longer than {MAX_CLIENT_HELLO_BYTES} bytes")]
    TooLarge,
    #[error("the client hello did not arrive in time")]
    Timeout,
    #[error("the connection does not carry a tls client hello")]
    Malformed,
    #[error("the connection ended before the client hello was complete")]
    Truncated,
    #[error("reading the client hello failed: {0:?}")]
    Io(io::ErrorKind),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HelloInfo {
    server_name: Option<String>,
    offers_ssh: bool,
    offers_svc: bool,
}

impl HelloInfo {
    fn of(accepted: &Accepted) -> Self {
        let hello = accepted.client_hello();
        let mut info = Self {
            server_name: hello.server_name().map(str::to_owned),
            offers_ssh: false,
            offers_svc: false,
        };
        for offered in hello.alpn().into_iter().flatten() {
            info.offers_ssh |= offered == ALPN_SSH;
            info.offers_svc |= offered == ALPN_SVC;
        }
        info
    }

    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    pub fn offers_ssh(&self) -> bool {
        self.offers_ssh
    }

    pub fn offers_svc(&self) -> bool {
        self.offers_svc
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CapturedHello {
    bytes: Vec<u8>,
    info: HelloInfo,
}

impl CapturedHello {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn info(&self) -> &HelloInfo {
        &self.info
    }

    pub fn into_parts(self) -> (Vec<u8>, HelloInfo) {
        (self.bytes, self.info)
    }
}

impl fmt::Debug for CapturedHello {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedHello")
            .field("len", &self.bytes.len())
            .field("info", &self.info)
            .finish()
    }
}

pub async fn capture_client_hello<R>(
    io: &mut R,
    deadline: Instant,
) -> Result<CapturedHello, HelloError>
where
    R: AsyncRead + Unpin,
{
    timeout_at(deadline, read_client_hello(io))
        .await
        .unwrap_or(Err(HelloError::Timeout))
}

pub fn parse_client_hello(bytes: &[u8]) -> Result<CapturedHello, HelloError> {
    let mut reader = HelloReader::new();
    let mut source = bytes;
    loop {
        let slot = reader.reserve()?;
        let (chunk, rest) = source
            .split_at_checked(slot.len())
            .ok_or(HelloError::Truncated)?;
        slot.copy_from_slice(chunk);
        source = rest;
        if let Some(info) = reader.advance()? {
            return Ok(reader.finish(info));
        }
    }
}

async fn read_client_hello<R>(io: &mut R) -> Result<CapturedHello, HelloError>
where
    R: AsyncRead + Unpin,
{
    let mut reader = HelloReader::new();
    loop {
        let slot = reader.reserve()?;
        match io.read_exact(slot).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(HelloError::Truncated);
            }
            Err(error) => return Err(HelloError::Io(error.kind())),
        }
        if let Some(info) = reader.advance()? {
            return Ok(reader.finish(info));
        }
    }
}

struct HelloReader {
    captured: Vec<u8>,
    record_start: usize,
    body: Option<usize>,
    acceptor: Acceptor,
}

impl HelloReader {
    fn new() -> Self {
        Self {
            captured: Vec::new(),
            record_start: 0,
            body: None,
            acceptor: Acceptor::default(),
        }
    }

    fn reserve(&mut self) -> Result<&mut [u8], HelloError> {
        let start = self.captured.len();
        let end = start + self.body.unwrap_or(RECORD_HEADER_LEN);
        if end > MAX_CLIENT_HELLO_BYTES {
            return Err(HelloError::TooLarge);
        }
        self.captured.resize(end, 0);
        self.captured.get_mut(start..).ok_or(HelloError::Malformed)
    }

    fn advance(&mut self) -> Result<Option<HelloInfo>, HelloError> {
        let record = self
            .captured
            .get(self.record_start..)
            .ok_or(HelloError::Malformed)?;
        if self.body.is_none() {
            self.body = Some(record_body_len(record)?);
            return Ok(None);
        }
        let mut unread = record;
        while !unread.is_empty() {
            match self.acceptor.read_tls(&mut unread) {
                Ok(0) | Err(_) => return Err(HelloError::Malformed),
                Ok(_) => {}
            }
        }
        self.body = None;
        self.record_start = self.captured.len();
        match self.acceptor.accept() {
            Ok(Some(accepted)) => Ok(Some(HelloInfo::of(&accepted))),
            Ok(None) => Ok(None),
            Err(_) => Err(HelloError::Malformed),
        }
    }

    fn finish(self, info: HelloInfo) -> CapturedHello {
        CapturedHello {
            bytes: self.captured,
            info,
        }
    }
}

fn record_body_len(header: &[u8]) -> Result<usize, HelloError> {
    let Some(&[content_type, major, _, len_hi, len_lo]) = header.first_chunk::<RECORD_HEADER_LEN>()
    else {
        return Err(HelloError::Malformed);
    };
    if content_type != CONTENT_TYPE_HANDSHAKE || major != RECORD_VERSION_MAJOR {
        return Err(HelloError::Malformed);
    }
    let len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if len == 0 || len > MAX_RECORD_BODY {
        return Err(HelloError::Malformed);
    }
    Ok(len)
}
