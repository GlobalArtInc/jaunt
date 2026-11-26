use serde::{Deserialize, Serialize};

use crate::ssh_login::is_portable_login;

pub const AGENT_CAPABILITIES_PATH: &str = "/v1/agent/capabilities";
pub const AGENT_SESSION_ACCOUNT_PATH: &str = "/v1/agent/session/account";
pub const MAX_ACCOUNT_HOME_BYTES: usize = 128;
pub const MAX_ACCOUNT_GROUPS: usize = 33;

const REFERENCE_PREFIX: &str = "H-";
const REFERENCE_DIGITS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentCapabilities {
    pub creates_accounts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AccountReference(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an account reference is H- followed by 8 upper-case hexadecimal digits")]
pub struct InvalidAccountReference;

impl AccountReference {
    pub fn parse(value: &str) -> Result<Self, InvalidAccountReference> {
        let digits = value
            .strip_prefix(REFERENCE_PREFIX)
            .ok_or(InvalidAccountReference)?;
        let valid = digits.len() == REFERENCE_DIGITS
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte));
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidAccountReference)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AccountReference {
    type Error = InvalidAccountReference;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<AccountReference> for String {
    fn from(reference: AccountReference) -> Self {
        reference.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountEventKind {
    Creating,
    Created,
    Refused,
    Failed,
    Missing,
}

impl AccountEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRefusal {
    NameRule,
    ReservedName,
    MaxUsers,
    GroupCollision,
    UidRange,
    HomeExists,
    RateLimit,
}

impl AccountRefusal {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NameRule => "name_rule",
            Self::ReservedName => "reserved_name",
            Self::MaxUsers => "max_users",
            Self::GroupCollision => "group_collision",
            Self::UidRange => "uid_range",
            Self::HomeExists => "home_exists",
            Self::RateLimit => "rate_limit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStage {
    Busy,
    Tool,
    Partial,
    Request,
    State,
    Lookup,
    Useradd,
    Verify,
}

impl AccountStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Tool => "tool",
            Self::Partial => "partial",
            Self::Request => "request",
            Self::State => "state",
            Self::Lookup => "lookup",
            Self::Useradd => "useradd",
            Self::Verify => "verify",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountReport {
    pub session_id: String,
    pub login: String,
    pub event: AccountEventKind,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<AccountReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AccountRefusal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<AccountStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEvent {
    Creating {
        reference: AccountReference,
    },
    Created {
        reference: AccountReference,
        uid: u32,
        home: String,
        groups: Vec<String>,
    },
    Refused {
        reference: AccountReference,
        reason: AccountRefusal,
    },
    Failed {
        reference: AccountReference,
        stage: AccountStage,
        exit_code: Option<i32>,
    },
    Missing {
        reference: AccountReference,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAccountReport {
    #[error("the account report fields do not match its event")]
    Inconsistent,
    #[error("the uid of a created account is zero")]
    Uid,
    #[error("the home directory of an account report is not a plain absolute path")]
    Home,
    #[error("the groups of an account report are not a short list of portable names")]
    Groups,
}

fn is_clean_home(home: &str) -> bool {
    let Some(rest) = home.strip_prefix('/') else {
        return false;
    };
    home.len() <= MAX_ACCOUNT_HOME_BYTES
        && !rest.is_empty()
        && rest.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                })
        })
}

fn are_portable_groups(groups: &[String]) -> bool {
    groups.len() <= MAX_ACCOUNT_GROUPS && groups.iter().all(|group| is_portable_login(group))
}

impl AccountEvent {
    pub const fn kind(&self) -> AccountEventKind {
        match self {
            Self::Creating { .. } => AccountEventKind::Creating,
            Self::Created { .. } => AccountEventKind::Created,
            Self::Refused { .. } => AccountEventKind::Refused,
            Self::Failed { .. } => AccountEventKind::Failed,
            Self::Missing { .. } => AccountEventKind::Missing,
        }
    }

    pub const fn reference(&self) -> &AccountReference {
        match self {
            Self::Creating { reference }
            | Self::Created { reference, .. }
            | Self::Refused { reference, .. }
            | Self::Failed { reference, .. }
            | Self::Missing { reference } => reference,
        }
    }

    pub const fn is_outcome(&self) -> bool {
        !matches!(self, Self::Creating { .. })
    }
}

impl AccountReport {
    pub fn new(session_id: String, login: String, event: AccountEvent) -> Self {
        let mut report = Self {
            session_id,
            login,
            event: event.kind(),
            reference: Some(event.reference().clone()),
            reason: None,
            stage: None,
            exit_code: None,
            uid: None,
            home: None,
            groups: None,
        };
        match event {
            AccountEvent::Creating { .. } | AccountEvent::Missing { .. } => {}
            AccountEvent::Created {
                uid, home, groups, ..
            } => {
                report.uid = Some(uid);
                report.home = Some(home);
                report.groups = Some(groups);
            }
            AccountEvent::Refused { reason, .. } => report.reason = Some(reason),
            AccountEvent::Failed {
                stage, exit_code, ..
            } => {
                report.stage = Some(stage);
                report.exit_code = exit_code;
            }
        }
        report
    }

    pub fn event(&self) -> Result<AccountEvent, InvalidAccountReport> {
        let inconsistent = InvalidAccountReport::Inconsistent;
        let reference = self.reference.clone();
        let detail = (
            self.reason,
            self.stage,
            self.exit_code,
            self.uid,
            self.home.as_deref(),
            self.groups.as_deref(),
        );
        match (self.event, reference, detail) {
            (AccountEventKind::Creating, Some(reference), (None, None, None, None, None, None)) => {
                Ok(AccountEvent::Creating { reference })
            }
            (
                AccountEventKind::Created,
                Some(reference),
                (None, None, None, Some(uid), Some(home), Some(groups)),
            ) => {
                if uid == 0 {
                    return Err(InvalidAccountReport::Uid);
                }
                if !is_clean_home(home) {
                    return Err(InvalidAccountReport::Home);
                }
                if !are_portable_groups(groups) {
                    return Err(InvalidAccountReport::Groups);
                }
                Ok(AccountEvent::Created {
                    reference,
                    uid,
                    home: home.to_owned(),
                    groups: groups.to_vec(),
                })
            }
            (
                AccountEventKind::Refused,
                Some(reference),
                (Some(reason), None, None, None, None, None),
            ) => Ok(AccountEvent::Refused { reference, reason }),
            (
                AccountEventKind::Failed,
                Some(reference),
                (None, Some(stage), exit_code, None, None, None),
            ) => Ok(AccountEvent::Failed {
                reference,
                stage,
                exit_code,
            }),
            (AccountEventKind::Missing, Some(reference), (None, None, None, None, None, None)) => {
                Ok(AccountEvent::Missing { reference })
            }
            _ => Err(inconsistent),
        }
    }
}

#[cfg(test)]
mod tests;
