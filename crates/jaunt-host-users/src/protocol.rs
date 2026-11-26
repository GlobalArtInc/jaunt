use std::fmt;

use serde::{Deserialize, Serialize};

use crate::config::{MAX_GROUPS, MAX_HOME_BYTES};
use crate::line::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES};
use crate::names::Name;
use crate::paths::is_clean_absolute_path;
use crate::rules::Reason;

pub const PROTOCOL_VERSION: u64 = 1;

const REFERENCE_PREFIX: &str = "H-";
const REFERENCE_DIGITS: usize = 8;
const MAX_SESSION_BYTES: usize = 64;
const MAX_CREATED_GROUPS: usize = MAX_GROUPS + 1;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Reference(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a reference is H- followed by 8 upper-case hexadecimal digits")]
pub struct InvalidReference;

impl Reference {
    pub fn parse(value: &str) -> Result<Self, InvalidReference> {
        let digits = value
            .strip_prefix(REFERENCE_PREFIX)
            .ok_or(InvalidReference)?;
        let valid = digits.len() == REFERENCE_DIGITS
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidReference)
        }
    }

    pub fn from_random(bits: u32) -> Self {
        Self(format!("{REFERENCE_PREFIX}{bits:08X}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Reference {
    type Error = InvalidReference;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Reference> for String {
    fn from(reference: Reference) -> Self {
        reference.0
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SessionLabel(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a session label is 1 to 64 letters, digits, dots, dashes or underscores")]
pub struct InvalidSessionLabel;

impl SessionLabel {
    pub fn parse(value: &str) -> Result<Self, InvalidSessionLabel> {
        let valid = !value.is_empty()
            && value.len() <= MAX_SESSION_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidSessionLabel)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SessionLabel {
    type Error = InvalidSessionLabel;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<SessionLabel> for String {
    fn from(label: SessionLabel) -> Self {
        label.0
    }
}

impl fmt::Display for SessionLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureRequest {
    pub login: String,
    pub reference: Reference,
    pub session: SessionLabel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedStage {
    Busy,
    Request,
    State,
    Lookup,
    Tool,
    Useradd,
    Verify,
    Partial,
}

impl FailedStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Request => "request",
            Self::State => "state",
            Self::Lookup => "lookup",
            Self::Tool => "tool",
            Self::Useradd => "useradd",
            Self::Verify => "verify",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Exists,
    Created {
        uid: u32,
        home: String,
        groups: Vec<Name>,
    },
    Refused {
        reason: Reason,
    },
    Failed {
        stage: FailedStage,
        exit_code: Option<i32>,
    },
    Disabled,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("the message is longer than {limit} bytes")]
    TooLong { limit: usize },
    #[error("the message is not JSON of the expected shape")]
    Malformed,
    #[error("the message uses an unsupported protocol version")]
    Version,
    #[error(transparent)]
    Reference(#[from] InvalidReference),
    #[error(transparent)]
    Session(#[from] InvalidSessionLabel),
    #[error("the response fields do not match its result")]
    Inconsistent,
    #[error("the message could not be encoded")]
    Encode,
}

#[derive(Deserialize)]
struct VersionProbe {
    v: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Ensure,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    v: u64,
    op: Operation,
    login: String,
    #[serde(rename = "ref")]
    reference: String,
    session: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Exists,
    Created,
    Refused,
    Failed,
    Disabled,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    v: u64,
    result: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<Name>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stage: Option<FailedStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

fn check_version(line: &[u8]) -> Result<(), ProtocolError> {
    let probe: VersionProbe = serde_json::from_slice(line).map_err(|_| ProtocolError::Malformed)?;
    if probe.v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::Version)
    }
}

fn to_line<T: Serialize>(message: &T, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut line = serde_json::to_vec(message).map_err(|_| ProtocolError::Encode)?;
    if line.len() > limit {
        return Err(ProtocolError::TooLong { limit });
    }
    line.push(b'\n');
    Ok(line)
}

pub fn parse_request(line: &[u8]) -> Result<EnsureRequest, ProtocolError> {
    if line.len() > MAX_REQUEST_BYTES {
        return Err(ProtocolError::TooLong {
            limit: MAX_REQUEST_BYTES,
        });
    }
    check_version(line)?;
    let wire: WireRequest = serde_json::from_slice(line).map_err(|_| ProtocolError::Malformed)?;
    let Operation::Ensure = wire.op;
    Ok(EnsureRequest {
        login: wire.login,
        reference: Reference::parse(&wire.reference)?,
        session: SessionLabel::parse(&wire.session)?,
    })
}

pub fn encode_request(request: &EnsureRequest) -> Result<Vec<u8>, ProtocolError> {
    let wire = WireRequest {
        v: PROTOCOL_VERSION,
        op: Operation::Ensure,
        login: request.login.clone(),
        reference: request.reference.as_str().to_owned(),
        session: request.session.as_str().to_owned(),
    };
    to_line(&wire, MAX_REQUEST_BYTES)
}

pub fn parse_response(line: &[u8]) -> Result<Response, ProtocolError> {
    if line.len() > MAX_RESPONSE_BYTES {
        return Err(ProtocolError::TooLong {
            limit: MAX_RESPONSE_BYTES,
        });
    }
    check_version(line)?;
    let wire: WireResponse = serde_json::from_slice(line).map_err(|_| ProtocolError::Malformed)?;
    let WireResponse {
        v: _,
        result,
        uid,
        home,
        groups,
        reason,
        stage,
        exit_code,
    } = wire;
    let response = match (result, uid, home, groups, reason, stage, exit_code) {
        (Outcome::Exists, None, None, None, None, None, None) => Response::Exists,
        (Outcome::Disabled, None, None, None, None, None, None) => Response::Disabled,
        (Outcome::Refused, None, None, None, Some(reason), None, None) => {
            Response::Refused { reason }
        }
        (Outcome::Failed, None, None, None, None, Some(stage), exit_code) => {
            Response::Failed { stage, exit_code }
        }
        (Outcome::Created, Some(uid), Some(home), Some(groups), None, None, None)
            if created_fields_fit(&home, &groups) =>
        {
            Response::Created { uid, home, groups }
        }
        _ => return Err(ProtocolError::Inconsistent),
    };
    Ok(response)
}

fn created_fields_fit(home: &str, groups: &[Name]) -> bool {
    is_clean_absolute_path(home, MAX_HOME_BYTES) && groups.len() <= MAX_CREATED_GROUPS
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, ProtocolError> {
    let empty = |result| WireResponse {
        v: PROTOCOL_VERSION,
        result,
        uid: None,
        home: None,
        groups: None,
        reason: None,
        stage: None,
        exit_code: None,
    };
    let wire = match response {
        Response::Exists => empty(Outcome::Exists),
        Response::Disabled => empty(Outcome::Disabled),
        Response::Refused { reason } => WireResponse {
            reason: Some(*reason),
            ..empty(Outcome::Refused)
        },
        Response::Failed { stage, exit_code } => WireResponse {
            stage: Some(*stage),
            exit_code: *exit_code,
            ..empty(Outcome::Failed)
        },
        Response::Created { uid, home, groups } if created_fields_fit(home, groups) => {
            WireResponse {
                uid: Some(*uid),
                home: Some(home.clone()),
                groups: Some(groups.clone()),
                ..empty(Outcome::Created)
            }
        }
        Response::Created { .. } => return Err(ProtocolError::Inconsistent),
    };
    to_line(&wire, MAX_RESPONSE_BYTES)
}

#[cfg(test)]
mod tests;
