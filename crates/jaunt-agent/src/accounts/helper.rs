use std::io;
use std::path::Path;
use std::time::Duration;

use jaunt_host_users::{
    EnsureRequest, MAX_RESPONSE_BYTES, ProtocolError, Response, encode_request, parse_response,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub const HELPER_BUDGET: Duration = Duration::from_secs(10);
pub const HELPER_WAIT: Duration = HELPER_BUDGET.saturating_add(Duration::from_secs(1));

const CHUNK_BYTES: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    #[error("cannot connect to the account helper: {0}")]
    Connect(#[source] io::Error),
    #[error("cannot send the request to the account helper: {0}")]
    Send(#[source] io::Error),
    #[error("reading the answer of the account helper failed: {0}")]
    Receive(#[source] io::Error),
    #[error("the account helper closed the connection without an answer")]
    Closed,
    #[error("the answer of the account helper is longer than {MAX_RESPONSE_BYTES} bytes")]
    TooLong,
    #[error("the account helper exchange is not valid: {0}")]
    Protocol(#[source] ProtocolError),
}

impl HelperError {
    pub fn cause(&self) -> &'static str {
        match self {
            Self::Connect(_) => "connect",
            Self::Send(_) => "send",
            Self::Receive(_) => "receive",
            Self::Closed => "closed",
            Self::TooLong => "too_long",
            Self::Protocol(_) => "malformed",
        }
    }
}

pub async fn ask_helper(socket: &Path, request: &EnsureRequest) -> Result<Response, HelperError> {
    let line = encode_request(request).map_err(HelperError::Protocol)?;
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(HelperError::Connect)?;
    stream.write_all(&line).await.map_err(HelperError::Send)?;
    let answer = read_answer(&mut stream).await?;
    parse_response(&answer).map_err(HelperError::Protocol)
}

async fn read_answer<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, HelperError> {
    let mut line = Vec::new();
    let mut chunk = [0_u8; CHUNK_BYTES];
    loop {
        let read = reader
            .read(&mut chunk)
            .await
            .map_err(HelperError::Receive)?;
        if read == 0 {
            return Err(HelperError::Closed);
        }
        let received = chunk.get(..read).unwrap_or_default();
        let end = received.iter().position(|byte| *byte == b'\n');
        line.extend_from_slice(received.get(..end.unwrap_or(read)).unwrap_or_default());
        if line.len() > MAX_RESPONSE_BYTES {
            return Err(HelperError::TooLong);
        }
        if end.is_some() {
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use jaunt_host_users::MAX_RESPONSE_BYTES;

    use super::{HelperError, read_answer};

    async fn read(bytes: &[u8]) -> Result<Vec<u8>, HelperError> {
        let mut reader = bytes;
        read_answer(&mut reader).await
    }

    #[tokio::test]
    async fn an_answer_is_one_bounded_line() {
        assert_eq!(read(b"{\"v\":1}\nrest").await.unwrap(), b"{\"v\":1}");
        let exact = [vec![b'a'; MAX_RESPONSE_BYTES], b"\n".to_vec()].concat();
        assert_eq!(read(&exact).await.unwrap().len(), MAX_RESPONSE_BYTES);
        let over = [vec![b'a'; MAX_RESPONSE_BYTES + 1], b"\n".to_vec()].concat();
        assert!(matches!(read(&over).await, Err(HelperError::TooLong)));
        assert!(matches!(read(b"{\"v\":1}").await, Err(HelperError::Closed)));
        assert!(matches!(read(b"").await, Err(HelperError::Closed)));
    }
}
