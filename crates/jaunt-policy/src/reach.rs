use crate::model::{
    DeniedPrincipals, DeniedSet, GrantPrincipals, ResourceInfo, ResourceKind, ResourceReach,
    RoleDenial, RoleGrant,
};
use crate::policy::{DeniedValues, PolicySet, Role};
use crate::template::ValueSpec;

fn denied_set(values: Option<&DeniedValues>) -> DeniedSet {
    match values {
        None => DeniedSet::Absent,
        Some(DeniedValues::Any) => DeniedSet::Any,
        Some(DeniedValues::Listed(values)) => DeniedSet::Listed(values.iter().cloned().collect()),
    }
}

fn written(specs: &[ValueSpec]) -> Vec<String> {
    specs.iter().map(ValueSpec::as_written).collect()
}

fn grant_principals(
    role: &Role,
    kind: ResourceKind,
    resource: &ResourceInfo,
) -> Option<GrantPrincipals> {
    match kind {
        ResourceKind::Node => role
            .ssh
            .as_ref()
            .filter(|rule| rule.matches_node(resource))
            .map(|rule| GrantPrincipals::Ssh {
                logins: written(&rule.logins),
                port_forwarding: rule.port_forwarding,
                record_input: rule.record_input,
            }),
        ResourceKind::KubernetesCluster => role
            .kubernetes
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|rule| GrantPrincipals::Kubernetes {
                users: written(&rule.users),
                groups: written(&rule.groups),
                record_exec: rule.record_exec,
                record_input: rule.record_input,
            }),
        ResourceKind::DatabaseServer => role
            .databases
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|rule| GrantPrincipals::Database {
                users: written(&rule.users),
                names: rule.names.iter().map(|name| name.as_written()).collect(),
            }),
        ResourceKind::TcpService => role
            .tcp
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|_| GrantPrincipals::Tcp),
    }
}

fn denied_principals(
    role: &Role,
    kind: ResourceKind,
    resource: &ResourceInfo,
) -> Option<DeniedPrincipals> {
    let deny = &role.deny;
    match kind {
        ResourceKind::Node => deny
            .ssh
            .as_ref()
            .filter(|rule| rule.matches_node(resource))
            .map(|rule| DeniedPrincipals::Ssh {
                logins: rule.logins.listed(),
            }),
        ResourceKind::KubernetesCluster => deny
            .kubernetes
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|rule| DeniedPrincipals::Kubernetes {
                users: denied_set(rule.users.as_ref()),
                groups: denied_set(rule.groups.as_ref()),
            }),
        ResourceKind::DatabaseServer => deny
            .databases
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|rule| DeniedPrincipals::Database {
                users: rule.users.listed(),
                names: rule.names.listed(),
            }),
        ResourceKind::TcpService => deny
            .tcp
            .as_ref()
            .filter(|rule| rule.matches(resource))
            .map(|_| DeniedPrincipals::Tcp),
    }
}

impl PolicySet {
    pub fn roles_reaching_resource(
        &self,
        kind: ResourceKind,
        resource: &ResourceInfo,
    ) -> ResourceReach {
        let mut allows: Vec<RoleGrant> = self
            .roles
            .iter()
            .filter_map(|role| {
                grant_principals(role, kind, resource).map(|principals| RoleGrant {
                    role: role.name.clone(),
                    users: role.users.iter().cloned().collect(),
                    groups: role.groups.iter().cloned().collect(),
                    admin: role.admin.iter().copied().collect(),
                    principals,
                })
            })
            .collect();
        allows.sort_by(|left, right| left.role.cmp(&right.role));
        let mut denies: Vec<RoleDenial> = self
            .roles
            .iter()
            .filter_map(|role| {
                denied_principals(role, kind, resource).map(|principals| RoleDenial {
                    role: role.name.clone(),
                    users: role.users.iter().cloned().collect(),
                    groups: role.groups.iter().cloned().collect(),
                    principals,
                })
            })
            .collect();
        denies.sort_by(|left, right| left.role.cmp(&right.role));
        ResourceReach { allows, denies }
    }
}
