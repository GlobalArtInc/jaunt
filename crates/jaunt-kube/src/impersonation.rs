use http::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use thiserror::Error;

pub const IMPERSONATE_USER: &str = "impersonate-user";
pub const IMPERSONATE_GROUP: &str = "impersonate-group";
pub const IMPERSONATE_UID: &str = "impersonate-uid";
pub const IMPERSONATE_EXTRA_PREFIX: &str = "impersonate-extra-";
pub const IMPERSONATE_SESSION: &str = "impersonate-extra-jaunt-session-id";
pub const MAX_SUBJECT_NAME_BYTES: usize = 253;
pub const MAX_SESSION_TAG_BYTES: usize = 64;
pub const MAX_IMPERSONATION_GROUPS: usize = 64;
pub const REMOTE_HEADER_PREFIX: &str = "x-remote-";

const IMPERSONATE_PREFIX: &str = "impersonate-";
const SYSTEM_PREFIX: &[u8] = b"system:";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ImpersonationError {
    #[error("kubernetes user name is not valid")]
    InvalidUser,
    #[error("kubernetes group name is not valid")]
    InvalidGroup,
    #[error("session id is not valid for an impersonation header")]
    InvalidSession,
    #[error("impersonating a system user is not allowed")]
    SystemUser,
    #[error("impersonating a system group is not allowed")]
    SystemGroup,
    #[error("more than {MAX_IMPERSONATION_GROUPS} groups to impersonate")]
    TooManyGroups,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemNames {
    Refuse,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KubeUser(String);

impl KubeUser {
    pub fn new(value: impl Into<String>) -> Result<Self, ImpersonationError> {
        let value = value.into();
        if is_subject_name(&value) {
            Ok(Self(value))
        } else {
            Err(ImpersonationError::InvalidUser)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KubeGroup(String);

impl KubeGroup {
    pub fn new(value: impl Into<String>) -> Result<Self, ImpersonationError> {
        let value = value.into();
        if is_subject_name(&value) {
            Ok(Self(value))
        } else {
            Err(ImpersonationError::InvalidGroup)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionTag(String);

impl SessionTag {
    pub fn new(value: impl Into<String>) -> Result<Self, ImpersonationError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_SESSION_TAG_BYTES
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if valid {
            Ok(Self(value))
        } else {
            Err(ImpersonationError::InvalidSession)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn is_subject_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SUBJECT_NAME_BYTES
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'@' | b':' | b'+' | b'=' | b'-')
        })
}

pub fn has_system_prefix(value: &str) -> bool {
    value
        .as_bytes()
        .get(..SYSTEM_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(SYSTEM_PREFIX))
}

pub fn impersonation_headers(
    user: &KubeUser,
    groups: &[KubeGroup],
    session: &SessionTag,
    system: SystemNames,
) -> Result<HeaderMap, ImpersonationError> {
    if system == SystemNames::Refuse {
        if has_system_prefix(user.as_str()) {
            return Err(ImpersonationError::SystemUser);
        }
        if groups.iter().any(|group| has_system_prefix(group.as_str())) {
            return Err(ImpersonationError::SystemGroup);
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(IMPERSONATE_USER),
        header_value(user.as_str(), ImpersonationError::InvalidUser)?,
    );
    let mut seen: Vec<&str> = Vec::with_capacity(groups.len());
    for group in groups {
        if seen.contains(&group.as_str()) {
            continue;
        }
        if seen.len() == MAX_IMPERSONATION_GROUPS {
            return Err(ImpersonationError::TooManyGroups);
        }
        seen.push(group.as_str());
        headers.append(
            HeaderName::from_static(IMPERSONATE_GROUP),
            header_value(group.as_str(), ImpersonationError::InvalidGroup)?,
        );
    }
    headers.insert(
        HeaderName::from_static(IMPERSONATE_SESSION),
        header_value(session.as_str(), ImpersonationError::InvalidSession)?,
    );
    Ok(headers)
}

fn header_value(value: &str, error: ImpersonationError) -> Result<HeaderValue, ImpersonationError> {
    HeaderValue::from_str(value).map_err(|_| error)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefusedHeader {
    Uid,
    Extra,
    Other,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StrippedHeaders {
    authorization: bool,
    requested_users: Vec<String>,
    requested_groups: Vec<String>,
    refused: Vec<RefusedHeader>,
    unreadable: bool,
    remote_identity: bool,
}

impl StrippedHeaders {
    pub fn had_authorization(&self) -> bool {
        self.authorization
    }

    pub fn requested_users(&self) -> &[String] {
        &self.requested_users
    }

    pub fn requested_groups(&self) -> &[String] {
        &self.requested_groups
    }

    pub fn refused(&self) -> &[RefusedHeader] {
        &self.refused
    }

    pub fn had_remote_identity(&self) -> bool {
        self.remote_identity
    }

    pub fn had_unreadable_value(&self) -> bool {
        self.unreadable
    }

    pub fn must_refuse(&self) -> bool {
        !self.refused.is_empty() || self.unreadable
    }

    pub fn is_empty(&self) -> bool {
        !self.authorization
            && self.requested_users.is_empty()
            && self.requested_groups.is_empty()
            && self.refused.is_empty()
            && !self.unreadable
            && !self.remote_identity
    }
}

pub fn strip_client_headers(headers: &mut HeaderMap) -> StrippedHeaders {
    let mut stripped = StrippedHeaders::default();
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            *name == AUTHORIZATION
                || name.as_str().starts_with(IMPERSONATE_PREFIX)
                || name.as_str().starts_with(REMOTE_HEADER_PREFIX)
        })
        .cloned()
        .collect();
    for name in names {
        if name.as_str().starts_with(REMOTE_HEADER_PREFIX) {
            headers.remove(&name);
            stripped.remote_identity = true;
            continue;
        }
        let values: Vec<HeaderValue> = headers.get_all(&name).iter().cloned().collect();
        headers.remove(&name);
        let target = match name.as_str() {
            "authorization" => {
                stripped.authorization = true;
                continue;
            }
            IMPERSONATE_USER => &mut stripped.requested_users,
            IMPERSONATE_GROUP => &mut stripped.requested_groups,
            other => {
                let refused = if other == IMPERSONATE_UID {
                    RefusedHeader::Uid
                } else if other.starts_with(IMPERSONATE_EXTRA_PREFIX) {
                    RefusedHeader::Extra
                } else {
                    RefusedHeader::Other
                };
                if !stripped.refused.contains(&refused) {
                    stripped.refused.push(refused);
                }
                continue;
            }
        };
        for value in values {
            match value.to_str() {
                Ok(text) => target.push(text.to_owned()),
                Err(_) => stripped.unreadable = true,
            }
        }
    }
    stripped
}
