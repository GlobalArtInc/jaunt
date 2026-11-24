use std::fmt;

use http::header::HeaderMap;
use http::{Method, Request};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ALPN_TUNNEL: &[u8] = b"jaunt-tunnel/1";
pub const ALPN_AGENT_API: &[u8] = b"jaunt-agent/1";
pub const CONTROL_VERSION: u32 = 1;
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_SESSION_ID_LEN: usize = 64;
pub const MAX_CLIENT_ADDRESS_LEN: usize = 128;
pub const MAX_NODE_ID_LEN: usize = 128;

pub(crate) const PATH_STREAM: &str = "/v1/stream";
pub(crate) const PATH_CONTROL: &str = "/v1/control";
const REQUEST_URI_STREAM: &str = "https://jaunt.internal/v1/stream";
const REQUEST_URI_CONTROL: &str = "https://jaunt.internal/v1/control";

pub const HEADER_SESSION: &str = "x-jaunt-session";
pub const HEADER_KIND: &str = "x-jaunt-kind";
pub const HEADER_CLIENT: &str = "x-jaunt-client";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MetaError {
    #[error("missing header {0}")]
    Missing(&'static str),
    #[error("header {0} is present more than once")]
    Duplicate(&'static str),
    #[error("header {0} has an invalid value")]
    Invalid(&'static str),
    #[error("header {0} is too long")]
    TooLong(&'static str),
    #[error("unknown stream kind")]
    UnknownKind,
    #[error("request could not be built")]
    RequestBuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid node id")]
pub struct InvalidNodeId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidNodeId> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_NODE_ID_LEN
            && value.bytes().all(|byte| byte.is_ascii_graphic());
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidNodeId)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> Result<Self, MetaError> {
        let value = value.into();
        if value.len() > MAX_SESSION_ID_LEN {
            return Err(MetaError::TooLong(HEADER_SESSION));
        }
        let valid = !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(value))
        } else {
            Err(MetaError::Invalid(HEADER_SESSION))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for SessionId {
    type Error = MetaError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SessionId> for String {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Ssh,
}

impl StreamKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
        }
    }

    fn parse(value: &str) -> Result<Self, MetaError> {
        match value {
            "ssh" => Ok(Self::Ssh),
            _ => Err(MetaError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMeta {
    session: SessionId,
    kind: StreamKind,
    client: String,
}

impl StreamMeta {
    pub fn new(
        session: SessionId,
        kind: StreamKind,
        client: impl Into<String>,
    ) -> Result<Self, MetaError> {
        let client = client.into();
        if client.len() > MAX_CLIENT_ADDRESS_LEN {
            return Err(MetaError::TooLong(HEADER_CLIENT));
        }
        if client.is_empty() || !client.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(MetaError::Invalid(HEADER_CLIENT));
        }
        Ok(Self {
            session,
            kind,
            client,
        })
    }

    pub fn session(&self) -> &SessionId {
        &self.session
    }

    pub fn kind(&self) -> StreamKind {
        self.kind
    }

    pub fn client(&self) -> &str {
        &self.client
    }

    pub fn from_headers(headers: &HeaderMap) -> Result<Self, MetaError> {
        let session = SessionId::new(single_header(headers, HEADER_SESSION)?)?;
        let kind = StreamKind::parse(&single_header(headers, HEADER_KIND)?)?;
        let client = single_header(headers, HEADER_CLIENT)?;
        Self::new(session, kind, client)
    }

    pub(crate) fn to_request(&self) -> Result<Request<()>, MetaError> {
        Request::builder()
            .method(Method::POST)
            .uri(REQUEST_URI_STREAM)
            .header(HEADER_SESSION, self.session.as_str())
            .header(HEADER_KIND, self.kind.as_str())
            .header(HEADER_CLIENT, self.client.as_str())
            .body(())
            .map_err(|_| MetaError::RequestBuild)
    }
}

pub(crate) fn control_request() -> Result<Request<()>, http::Error> {
    Request::builder()
        .method(Method::POST)
        .uri(REQUEST_URI_CONTROL)
        .body(())
}

fn single_header(headers: &HeaderMap, name: &'static str) -> Result<String, MetaError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(MetaError::Missing(name))?;
    if values.next().is_some() {
        return Err(MetaError::Duplicate(name));
    }
    let text = value.to_str().map_err(|_| MetaError::Invalid(name))?;
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HeaderValue;

    fn headers(session: &str, kind: &str, client: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(HEADER_SESSION, HeaderValue::from_str(session).unwrap());
        map.insert(HEADER_KIND, HeaderValue::from_str(kind).unwrap());
        map.insert(HEADER_CLIENT, HeaderValue::from_str(client).unwrap());
        map
    }

    #[test]
    fn session_id_rules() {
        let long = "a".repeat(MAX_SESSION_ID_LEN);
        let too_long = "a".repeat(MAX_SESSION_ID_LEN + 1);
        let cases: [(&str, Result<(), MetaError>); 8] = [
            ("abc-DEF_1.2", Ok(())),
            (long.as_str(), Ok(())),
            ("", Err(MetaError::Invalid(HEADER_SESSION))),
            (too_long.as_str(), Err(MetaError::TooLong(HEADER_SESSION))),
            ("has space", Err(MetaError::Invalid(HEADER_SESSION))),
            ("slash/", Err(MetaError::Invalid(HEADER_SESSION))),
            ("new\nline", Err(MetaError::Invalid(HEADER_SESSION))),
            ("caf\u{e9}", Err(MetaError::Invalid(HEADER_SESSION))),
        ];
        for (input, expected) in cases {
            assert_eq!(SessionId::new(input).map(|_| ()), expected, "{input:?}");
        }
    }

    #[test]
    fn client_address_rules() {
        let session = SessionId::new("s1").unwrap();
        let max = "1".repeat(MAX_CLIENT_ADDRESS_LEN);
        let too_long = "1".repeat(MAX_CLIENT_ADDRESS_LEN + 1);
        let cases: [(&str, Result<(), MetaError>); 5] = [
            ("203.0.113.7:51514", Ok(())),
            (max.as_str(), Ok(())),
            ("", Err(MetaError::Invalid(HEADER_CLIENT))),
            (too_long.as_str(), Err(MetaError::TooLong(HEADER_CLIENT))),
            ("a b", Err(MetaError::Invalid(HEADER_CLIENT))),
        ];
        for (input, expected) in cases {
            let result = StreamMeta::new(session.clone(), StreamKind::Ssh, input).map(|_| ());
            assert_eq!(result, expected, "{input:?}");
        }
    }

    #[test]
    fn meta_round_trips_through_request_headers() {
        let meta = StreamMeta::new(
            SessionId::new("sess-1").unwrap(),
            StreamKind::Ssh,
            "[::1]:2222",
        )
        .unwrap();
        let request = meta.to_request().unwrap();
        assert_eq!(request.method(), Method::POST);
        assert_eq!(request.uri().path(), PATH_STREAM);
        assert_eq!(StreamMeta::from_headers(request.headers()), Ok(meta));
    }

    #[test]
    fn header_parsing_rejects_bad_input() {
        let mut duplicated = headers("s1", "ssh", "1.2.3.4:5");
        duplicated.append(HEADER_SESSION, HeaderValue::from_static("s2"));
        let mut missing = headers("s1", "ssh", "1.2.3.4:5");
        missing.remove(HEADER_KIND);
        let mut non_ascii = headers("s1", "ssh", "1.2.3.4:5");
        non_ascii.insert(HEADER_CLIENT, HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        let cases = [
            (duplicated, MetaError::Duplicate(HEADER_SESSION)),
            (missing, MetaError::Missing(HEADER_KIND)),
            (non_ascii, MetaError::Invalid(HEADER_CLIENT)),
            (headers("s1", "tcp", "1.2.3.4:5"), MetaError::UnknownKind),
            (
                headers("bad id", "ssh", "1.2.3.4:5"),
                MetaError::Invalid(HEADER_SESSION),
            ),
        ];
        for (map, expected) in cases {
            assert_eq!(StreamMeta::from_headers(&map), Err(expected));
        }
    }

    #[test]
    fn node_id_rules() {
        let max = "n".repeat(MAX_NODE_ID_LEN);
        let too_long = "n".repeat(MAX_NODE_ID_LEN + 1);
        assert!(NodeId::new("web-01.prod").is_ok());
        assert!(NodeId::new(max).is_ok());
        for bad in ["", "has space", "line\nbreak", too_long.as_str()] {
            assert_eq!(NodeId::new(bad), Err(InvalidNodeId), "{bad:?}");
        }
    }
}
