use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use jaunt_proto::is_portable_login;
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshDecision {
    pub allowed: bool,
    pub port_forwarding: bool,
    pub record_input: bool,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAccess {
    pub role: String,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub logins: Vec<String>,
    pub port_forwarding: bool,
    pub record_input: bool,
    pub admin: Vec<AdminPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub enum AdminPermission {
    NodesApprove,
    SessionsRead,
    RecordingsRead,
    RevocationsWrite,
    AuditRead,
}

impl AdminPermission {
    pub const ALL: [AdminPermission; 5] = [
        AdminPermission::NodesApprove,
        AdminPermission::SessionsRead,
        AdminPermission::RecordingsRead,
        AdminPermission::RevocationsWrite,
        AdminPermission::AuditRead,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            AdminPermission::NodesApprove => "nodes.approve",
            AdminPermission::SessionsRead => "sessions.read",
            AdminPermission::RecordingsRead => "recordings.read",
            AdminPermission::RevocationsWrite => "revocations.write",
            AdminPermission::AuditRead => "audit.read",
        }
    }
}

impl fmt::Display for AdminPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAdminPermission(pub String);

impl fmt::Display for UnknownAdminPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown admin permission `{}`", self.0)
    }
}

impl std::error::Error for UnknownAdminPermission {}

impl FromStr for AdminPermission {
    type Err = UnknownAdminPermission;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        AdminPermission::ALL
            .into_iter()
            .find(|permission| permission.as_str() == value)
            .ok_or_else(|| UnknownAdminPermission(value.to_owned()))
    }
}

impl TryFrom<String> for AdminPermission {
    type Error = UnknownAdminPermission;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

const FORBIDDEN_SUBSTITUTED_LOGIN: &str = "root";

pub(crate) fn is_valid_substituted_login(login: &str) -> bool {
    is_portable_login(login) && login != FORBIDDEN_SUBSTITUTED_LOGIN
}
