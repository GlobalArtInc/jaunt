use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

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

pub type ResourceInfo = NodeInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Node,
    KubernetesCluster,
    DatabaseServer,
    TcpService,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshDecision {
    pub allowed: bool,
    pub port_forwarding: bool,
    pub record_input: bool,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KubeDecision {
    pub allowed: bool,
    pub roles: Vec<String>,
    pub denied_by: Vec<String>,
    pub subtracted_by: Vec<String>,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub record_exec: bool,
    pub record_input: bool,
    pub trait_not_valid: bool,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DbDecision {
    pub allowed: bool,
    pub roles: Vec<String>,
    pub denied_by: Vec<String>,
    pub users: Vec<String>,
    pub names: Vec<String>,
    pub trait_not_valid: bool,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpDecision {
    pub allowed: bool,
    pub roles: Vec<String>,
    pub denied_by: Vec<String>,
    pub policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantPrincipals {
    Ssh {
        logins: Vec<String>,
        port_forwarding: bool,
        record_input: bool,
    },
    Kubernetes {
        users: Vec<String>,
        groups: Vec<String>,
        record_exec: bool,
        record_input: bool,
    },
    Database {
        users: Vec<String>,
        names: Vec<String>,
    },
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedSet {
    Absent,
    Any,
    Listed(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedPrincipals {
    Ssh {
        logins: Option<Vec<String>>,
    },
    Kubernetes {
        users: DeniedSet,
        groups: DeniedSet,
    },
    Database {
        users: Option<Vec<String>>,
        names: Option<Vec<String>>,
    },
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleGrant {
    pub role: String,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub admin: Vec<AdminPermission>,
    pub principals: GrantPrincipals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleDenial {
    pub role: String,
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub principals: DeniedPrincipals,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResourceReach {
    pub allows: Vec<RoleGrant>,
    pub denies: Vec<RoleDenial>,
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
    TokensWrite,
}

impl AdminPermission {
    pub const ALL: [AdminPermission; 6] = [
        AdminPermission::NodesApprove,
        AdminPermission::SessionsRead,
        AdminPermission::RecordingsRead,
        AdminPermission::RevocationsWrite,
        AdminPermission::AuditRead,
        AdminPermission::TokensWrite,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            AdminPermission::NodesApprove => "nodes.approve",
            AdminPermission::SessionsRead => "sessions.read",
            AdminPermission::RecordingsRead => "recordings.read",
            AdminPermission::RevocationsWrite => "revocations.write",
            AdminPermission::AuditRead => "audit.read",
            AdminPermission::TokensWrite => "tokens.write",
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWarning {
    pub role: String,
    pub field: &'static str,
    pub value: String,
}

impl fmt::Display for PolicyWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "role {:?}: {} grants the privileged literal {:?}; keep it only as a deliberate choice",
            self.role, self.field, self.value
        )
    }
}
