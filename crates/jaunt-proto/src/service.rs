use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

pub const AGENT_SERVICES_PATH: &str = "/v1/agent/services";
pub const SERVICES_PATH: &str = "/v1/services";
pub const MAX_SERVICES_PER_AGENT: usize = 64;
pub const MAX_SERVICE_PATH_BYTES: usize = 1024;
pub const MAX_QUERY_BYTES: u32 = 8 * 1024;
pub const DEFAULT_MAX_QUERY_BYTES: u32 = 4096;
pub const MAX_TCP_IDLE_TIMEOUT_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_TCP_IDLE_TIMEOUT_SECS: u64 = 60 * 60;

const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceKind {
    Kubernetes,
    Postgres,
    Tcp,
}

impl ServiceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kubernetes => "kubernetes",
            Self::Postgres => "postgres",
            Self::Tcp => "tcp",
        }
    }
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KubernetesApi {
    #[default]
    InCluster,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KubernetesAudit {
    #[default]
    Mutating,
    All,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesSettings {
    #[serde(default)]
    pub api: KubernetesApi,
    #[serde(default)]
    pub audit: KubernetesAudit,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryAudit {
    #[default]
    Text,
    Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresAudit {
    #[serde(default)]
    pub queries: QueryAudit,
    #[serde(default = "default_max_query_bytes")]
    pub max_query_bytes: u32,
}

impl Default for PostgresAudit {
    fn default() -> Self {
        Self {
            queries: QueryAudit::default(),
            max_query_bytes: DEFAULT_MAX_QUERY_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresSettings {
    pub tls: PostgresTls,
    #[serde(default)]
    pub audit: PostgresAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpSettings {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
}

impl Default for TcpSettings {
    fn default() -> Self {
        Self {
            idle_timeout_secs: DEFAULT_TCP_IDLE_TIMEOUT_SECS,
        }
    }
}

fn default_max_query_bytes() -> u32 {
    DEFAULT_MAX_QUERY_BYTES
}

fn default_idle_timeout_secs() -> u64 {
    DEFAULT_TCP_IDLE_TIMEOUT_SECS
}

fn ssh_enabled_by_default() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnouncedService {
    pub kind: ServiceKind,
    pub name: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postgres: Option<PostgresSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAnnouncement {
    #[serde(default = "ssh_enabled_by_default")]
    pub ssh_enabled: bool,
    pub services: Vec<AnnouncedService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ServiceSettings {
    Kubernetes(KubernetesSettings),
    Postgres(PostgresSettings),
    Tcp(TcpSettings),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceProblem {
    #[error("at most {MAX_SERVICES_PER_AGENT} services may be declared")]
    TooMany,
    #[error("the {kind} service {name:?} is declared more than once")]
    Duplicate { kind: ServiceKind, name: String },
    #[error("a {kind} service cannot carry a {block} block")]
    ForeignBlock {
        kind: ServiceKind,
        block: ServiceKind,
    },
    #[error("a {0} service needs an address written as host:port")]
    AddressRequired(ServiceKind),
    #[error("a kubernetes service takes no address")]
    AddressNotAllowed,
    #[error(
        "the address must be host:port with a DNS name or an IP address (IPv6 in brackets) and a port from 1 to 65535"
    )]
    InvalidAddress,
    #[error("a postgres service needs a postgres block whose tls names a ca_file")]
    PostgresTlsMissing,
    #[error(
        "postgres.tls.ca_file must be an absolute path of at most {MAX_SERVICE_PATH_BYTES} bytes without control characters"
    )]
    InvalidCaFile,
    #[error("postgres.tls.server_name must be a DNS name or an IP address")]
    InvalidServerName,
    #[error("postgres.audit.max_query_bytes must be between 1 and {MAX_QUERY_BYTES}")]
    InvalidMaxQueryBytes,
    #[error("tcp.idle_timeout_secs must be between 1 and {MAX_TCP_IDLE_TIMEOUT_SECS}")]
    InvalidIdleTimeout,
}

impl ServiceAnnouncement {
    pub fn check_set(&self) -> Result<(), ServiceProblem> {
        if self.services.len() > MAX_SERVICES_PER_AGENT {
            return Err(ServiceProblem::TooMany);
        }
        let mut seen = BTreeSet::new();
        for service in &self.services {
            if !seen.insert((service.kind, service.name.as_str())) {
                return Err(ServiceProblem::Duplicate {
                    kind: service.kind,
                    name: service.name.clone(),
                });
            }
        }
        Ok(())
    }
}

impl AnnouncedService {
    pub fn settings(&self) -> Result<ServiceSettings, ServiceProblem> {
        for (block, present) in [
            (ServiceKind::Kubernetes, self.kubernetes.is_some()),
            (ServiceKind::Postgres, self.postgres.is_some()),
            (ServiceKind::Tcp, self.tcp.is_some()),
        ] {
            if present && block != self.kind {
                return Err(ServiceProblem::ForeignBlock {
                    kind: self.kind,
                    block,
                });
            }
        }
        match (self.kind, self.address.as_deref()) {
            (ServiceKind::Kubernetes, Some(_)) => return Err(ServiceProblem::AddressNotAllowed),
            (ServiceKind::Kubernetes, None) => {}
            (kind, None) => return Err(ServiceProblem::AddressRequired(kind)),
            (_, Some(address)) if !is_host_port(address) => {
                return Err(ServiceProblem::InvalidAddress);
            }
            (_, Some(_)) => {}
        }
        match self.kind {
            ServiceKind::Kubernetes => Ok(ServiceSettings::Kubernetes(
                self.kubernetes.unwrap_or_default(),
            )),
            ServiceKind::Postgres => {
                let settings = self
                    .postgres
                    .clone()
                    .ok_or(ServiceProblem::PostgresTlsMissing)?;
                check_postgres(&settings)?;
                Ok(ServiceSettings::Postgres(settings))
            }
            ServiceKind::Tcp => {
                let settings = self.tcp.unwrap_or_default();
                if !(1..=MAX_TCP_IDLE_TIMEOUT_SECS).contains(&settings.idle_timeout_secs) {
                    return Err(ServiceProblem::InvalidIdleTimeout);
                }
                Ok(ServiceSettings::Tcp(settings))
            }
        }
    }
}

fn check_postgres(settings: &PostgresSettings) -> Result<(), ServiceProblem> {
    let tls = &settings.tls;
    if tls.ca_file.is_none() {
        return Err(ServiceProblem::PostgresTlsMissing);
    }
    if tls
        .ca_file
        .as_deref()
        .is_some_and(|path| !is_absolute_path(path))
    {
        return Err(ServiceProblem::InvalidCaFile);
    }
    if tls
        .server_name
        .as_deref()
        .is_some_and(|name| !is_host(name))
    {
        return Err(ServiceProblem::InvalidServerName);
    }
    if !(1..=MAX_QUERY_BYTES).contains(&settings.audit.max_query_bytes) {
        return Err(ServiceProblem::InvalidMaxQueryBytes);
    }
    Ok(())
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= MAX_SERVICE_PATH_BYTES
        && !path.chars().any(char::is_control)
}

fn is_dns_name(name: &str) -> bool {
    name.len() <= MAX_DNS_NAME_BYTES
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
                return false;
            };
            bytes.len() <= MAX_DNS_LABEL_BYTES
                && first.is_ascii_alphanumeric()
                && last.is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

fn is_host(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() || is_dns_name(host)
}

fn is_host_port(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|port| port > 0);
    let host_ok = match host.strip_prefix('[') {
        Some(rest) => rest
            .strip_suffix(']')
            .is_some_and(|inner| inner.parse::<Ipv6Addr>().is_ok()),
        None => host.parse::<Ipv4Addr>().is_ok() || is_dns_name(host),
    };
    port_ok && host_ok
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSummary {
    pub kind: ServiceKind,
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceList {
    pub services: Vec<ServiceSummary>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeService {
    pub id: String,
    pub kind: ServiceKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeServices {
    pub services: Vec<NodeService>,
}

#[cfg(test)]
mod tests;
