use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Problem {
    #[error("the message ends early")]
    Truncated,
    #[error("a string is not terminated")]
    MissingTerminator,
    #[error("bytes follow the end of the message")]
    TrailingBytes,
    #[error("the length field is invalid")]
    InvalidLength,
    #[error("a count is negative")]
    NegativeCount,
    #[error("a string is not valid UTF-8")]
    InvalidUtf8,
    #[error("a field has an invalid value")]
    InvalidValue,
    #[error("a required field is missing")]
    MissingField,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("the decoder is poisoned by an earlier error")]
    Poisoned,
    #[error("pending input of {length} bytes exceeds the limit of {limit} bytes")]
    PendingTooLarge { length: usize, limit: usize },
    #[error("{message} of {length} bytes exceeds the limit of {limit} bytes")]
    TooLarge {
        message: &'static str,
        length: usize,
        limit: usize,
    },
    #[error("the Bind header exceeds the limit of {limit} bytes")]
    BindPrefixTooLarge { limit: usize },
    #[error("unknown message type {tag:#04x}")]
    UnknownMessage { tag: u8 },
    #[error("function calls are refused")]
    FunctionCallRefused,
    #[error("unsupported protocol version {major}.{minor}")]
    UnsupportedProtocol { major: u16, minor: u16 },
    #[error("malformed {message}: {problem}")]
    Malformed {
        message: &'static str,
        problem: Problem,
    },
    #[error("the startup message has more than {limit} parameters")]
    TooManyStartupParameters { limit: usize },
    #[error("a startup parameter is repeated")]
    DuplicateStartupParameter,
    #[error("{message} was sent twice during startup")]
    RepeatedNegotiation { message: &'static str },
    #[error("unknown authentication request {code}")]
    UnknownAuthentication { code: i32 },
    #[error("data follows the end of the conversation")]
    DataAfterEnd,
}

impl DecodeError {
    pub(crate) fn malformed(message: &'static str) -> impl Fn(Problem) -> Self {
        move |problem| Self::Malformed { message, problem }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("the message is too long to encode")]
    TooLong,
}
