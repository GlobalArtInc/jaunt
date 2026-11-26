use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use subtle::ConstantTimeEq;

use crate::backend::BackendKeyData;

use crate::error::{DecodeError, EncodeError, Problem};
use crate::reader::Reader;

pub const MIN_CANCEL_KEY_BYTES: usize = 4;
pub const MAX_CANCEL_KEY_BYTES: usize = 256;

pub(crate) const CANCEL_REQUEST_CODE: u32 = (1234 << 16) | 5678;
pub(crate) const SSL_REQUEST_CODE: u32 = (1234 << 16) | 5679;
pub(crate) const GSSENC_REQUEST_CODE: u32 = (1234 << 16) | 5680;

const STARTUP_MESSAGE: &str = "StartupMessage";
const CANCEL_REQUEST: &str = "CancelRequest";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const V3_0: Self = Self { major: 3, minor: 0 };
    pub const V3_2: Self = Self { major: 3, minor: 2 };

    pub(crate) fn from_code(code: u32) -> Self {
        Self {
            major: (code >> 16) as u16,
            minor: (code & 0xffff) as u16,
        }
    }

    fn code(self) -> u32 {
        (u32::from(self.major) << 16) | u32::from(self.minor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMessage {
    version: ProtocolVersion,
    parameters: Vec<(String, String)>,
}

impl StartupMessage {
    pub(crate) fn from_parts(version: ProtocolVersion, parameters: Vec<(String, String)>) -> Self {
        Self {
            version,
            parameters,
        }
    }

    pub(crate) fn decode(
        version: ProtocolVersion,
        body: &[u8],
        max_parameters: usize,
    ) -> Result<Self, DecodeError> {
        let malformed = DecodeError::malformed(STARTUP_MESSAGE);
        let mut reader = Reader::new(body);
        let mut parameters: Vec<(String, String)> = Vec::new();
        loop {
            let name = reader.cstr().map_err(&malformed)?;
            if name.is_empty() {
                break;
            }
            let value = reader.cstr().map_err(&malformed)?;
            if parameters.len() == max_parameters {
                return Err(DecodeError::TooManyStartupParameters {
                    limit: max_parameters,
                });
            }
            let name = utf8(name).map_err(&malformed)?;
            let value = utf8(value).map_err(&malformed)?;
            if parameters
                .iter()
                .any(|(existing, _)| existing.eq_ignore_ascii_case(&name))
            {
                return Err(DecodeError::DuplicateStartupParameter);
            }
            parameters.push((name, value));
        }
        reader.finish().map_err(&malformed)?;
        Ok(Self {
            version,
            parameters,
        })
    }

    pub fn version(&self) -> ProtocolVersion {
        self.version
    }

    pub fn parameters(&self) -> impl Iterator<Item = (&str, &str)> {
        self.parameters
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(existing, _)| existing == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn encode(&self) -> Result<Bytes, EncodeError> {
        let body: usize = self
            .parameters
            .iter()
            .map(|(name, value)| name.len() + value.len() + 2)
            .sum();
        let length = body + 9;
        let field = i32::try_from(length).map_err(|_| EncodeError::TooLong)?;
        let mut out = BytesMut::with_capacity(length);
        out.put_i32(field);
        out.put_u32(self.version.code());
        for (name, value) in &self.parameters {
            out.put_slice(name.as_bytes());
            out.put_u8(0);
            out.put_slice(value.as_bytes());
            out.put_u8(0);
        }
        out.put_u8(0);
        Ok(out.freeze())
    }
}

#[derive(Clone)]
pub struct CancelRequest {
    process_id: i32,
    secret_key: Bytes,
}

impl CancelRequest {
    pub(crate) fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let malformed = DecodeError::malformed(CANCEL_REQUEST);
        let mut reader = Reader::new(body);
        let process_id = reader.i32().map_err(&malformed)?;
        let key_start = reader.position();
        let key_length = reader.remaining();
        if !(MIN_CANCEL_KEY_BYTES..=MAX_CANCEL_KEY_BYTES).contains(&key_length) {
            return Err(malformed(Problem::InvalidLength));
        }
        Ok(Self {
            process_id,
            secret_key: Bytes::copy_from_slice(&body[key_start..]),
        })
    }

    pub fn process_id(&self) -> i32 {
        self.process_id
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    pub fn matches(&self, key_data: &BackendKeyData) -> bool {
        let same_key: bool = self.secret_key.ct_eq(key_data.secret_key()).into();
        same_key & (self.process_id == key_data.process_id())
    }
}

impl fmt::Debug for CancelRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelRequest")
            .field("process_id", &self.process_id)
            .field("secret_key", &"[redacted]")
            .finish()
    }
}

fn utf8(bytes: &[u8]) -> Result<String, Problem> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Problem::InvalidUtf8)
}
