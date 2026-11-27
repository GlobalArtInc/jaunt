use std::borrow::Cow;
use std::collections::BTreeSet;

use jaunt_proto::{is_portable_login, is_valid_substituted_login};

use crate::access_test::AccessTest;
use crate::model::{
    AdminPermission, GrantPrincipals, Identity, NodeInfo, PolicyWarning, ResourceKind, RoleAccess,
    SshDecision,
};
use crate::services::{DbDenyRule, DbRule, KubeDenyRule, KubeRule, TcpDenyRule, TcpRule};
use crate::template::{Target, ValueSpec};

pub(crate) const ANY_VALUE: &str = "*";
pub(crate) const NAME_PSEUDO_LABEL: &str = "name";
const SSH_LOGINS_FIELD: &str = "spec.ssh.logins";
const KUBE_GROUPS_FIELD: &str = "spec.kubernetes.groups";
const DB_USERS_FIELD: &str = "spec.databases.users";
const PRIVILEGED_SSH_LOGINS: [&str; 1] = ["root"];
const PRIVILEGED_KUBE_GROUPS: [&str; 3] =
    ["system:masters", "system:authenticated", "system:nodes"];
const PRIVILEGED_DB_USERS: [&str; 1] = ["postgres"];

fn privileged<'a>(
    specs: &'a [ValueSpec],
    reserved: &'a [&'a str],
) -> impl Iterator<Item = &'a str> + 'a {
    specs
        .iter()
        .filter_map(ValueSpec::as_literal)
        .filter(move |value| reserved.contains(value))
}

fn is_login_prefix(prefix: &str) -> bool {
    is_portable_login(&format!("{prefix}a"))
}

pub(crate) const SSH_LOGIN: Target = Target {
    literal: is_portable_login,
    prefix: is_login_prefix,
    substituted: is_valid_substituted_login,
};

#[derive(Debug, Clone)]
pub(crate) enum SelectorKey {
    Name,
    Label(String),
}

#[derive(Debug, Clone)]
pub(crate) struct LabelRequirement {
    pub(crate) key: SelectorKey,
    pub(crate) values: Vec<String>,
}

impl LabelRequirement {
    fn matches(&self, node: &NodeInfo) -> bool {
        let actual = match &self.key {
            SelectorKey::Name => Some(&node.name),
            SelectorKey::Label(key) => node.labels.get(key),
        };
        actual.is_some_and(|actual| {
            self.values
                .iter()
                .any(|expected| expected == ANY_VALUE || expected == actual)
        })
    }
}

pub(crate) fn selector_matches(selector: &[LabelRequirement], node: &NodeInfo) -> bool {
    !selector.is_empty() && selector.iter().all(|req| req.matches(node))
}

#[derive(Debug, Clone)]
pub(crate) struct SshRule {
    pub(crate) nodes: Vec<LabelRequirement>,
    pub(crate) logins: Vec<ValueSpec>,
    pub(crate) port_forwarding: bool,
    pub(crate) record_input: bool,
}

impl SshRule {
    pub(crate) fn matches_node(&self, node: &NodeInfo) -> bool {
        selector_matches(&self.nodes, node)
    }

    fn resolved_logins<'a>(
        &'a self,
        identity: &'a Identity,
    ) -> impl Iterator<Item = Cow<'a, str>> + 'a {
        self.logins
            .iter()
            .flat_map(move |spec| spec.resolve(identity, SSH_LOGIN))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum DeniedValues {
    Any,
    Listed(BTreeSet<String>),
}

impl DeniedValues {
    pub(crate) fn covers(&self, value: &str) -> bool {
        match self {
            DeniedValues::Any => true,
            DeniedValues::Listed(values) => values.contains(value),
        }
    }

    pub(crate) fn listed(&self) -> Option<Vec<String>> {
        match self {
            DeniedValues::Any => None,
            DeniedValues::Listed(values) => Some(values.iter().cloned().collect()),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SshDenyRule {
    pub(crate) nodes: Vec<LabelRequirement>,
    pub(crate) logins: DeniedValues,
}

impl SshDenyRule {
    pub(crate) fn matches_node(&self, node: &NodeInfo) -> bool {
        selector_matches(&self.nodes, node)
    }

    fn covers(&self, login: &str) -> bool {
        self.logins.covers(login)
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RoleDeny {
    pub(crate) ssh: Option<SshDenyRule>,
    pub(crate) kubernetes: Option<KubeDenyRule>,
    pub(crate) databases: Option<DbDenyRule>,
    pub(crate) tcp: Option<TcpDenyRule>,
}

struct SshDenials<'a>(Vec<&'a SshDenyRule>);

impl SshDenials<'_> {
    fn covers(&self, login: &str) -> bool {
        self.0.iter().any(|rule| rule.covers(login))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Role {
    pub(crate) name: String,
    pub(crate) users: BTreeSet<String>,
    pub(crate) groups: BTreeSet<String>,
    pub(crate) ssh: Option<SshRule>,
    pub(crate) kubernetes: Option<KubeRule>,
    pub(crate) databases: Option<DbRule>,
    pub(crate) tcp: Option<TcpRule>,
    pub(crate) deny: RoleDeny,
    pub(crate) admin: BTreeSet<AdminPermission>,
}

impl Role {
    fn applies_to(&self, identity: &Identity) -> bool {
        self.users.contains(&identity.email)
            || identity
                .groups
                .iter()
                .any(|group| self.groups.contains(group))
    }
}

#[derive(Debug, Clone)]
pub struct PolicySet {
    pub(crate) roles: Vec<Role>,
    pub(crate) tests: Vec<AccessTest>,
    pub(crate) hash: String,
}

impl PolicySet {
    pub fn empty() -> Self {
        PolicySet {
            roles: Vec::new(),
            tests: Vec::new(),
            hash: crate::loader::hash_files(&[]),
        }
    }

    pub(crate) fn applicable_roles<'a>(
        &'a self,
        identity: &'a Identity,
    ) -> impl Iterator<Item = &'a Role> {
        self.roles.iter().filter(|role| role.applies_to(identity))
    }

    fn ssh_rules_reaching<'a>(
        &'a self,
        identity: &'a Identity,
        node: &'a NodeInfo,
    ) -> impl Iterator<Item = (&'a Role, &'a SshRule)> {
        self.applicable_roles(identity).filter_map(|role| {
            role.ssh
                .as_ref()
                .filter(|rule| rule.matches_node(node))
                .map(|rule| (role, rule))
        })
    }

    fn ssh_denials<'a>(&'a self, identity: &'a Identity, node: &NodeInfo) -> SshDenials<'a> {
        SshDenials(
            self.applicable_roles(identity)
                .filter_map(|role| role.deny.ssh.as_ref())
                .filter(|rule| rule.matches_node(node))
                .collect(),
        )
    }

    pub fn route(&self, identity: &Identity, node: &NodeInfo) -> bool {
        let denials = self.ssh_denials(identity, node);
        self.ssh_rules_reaching(identity, node).any(|(_, rule)| {
            rule.resolved_logins(identity)
                .any(|login| !denials.covers(&login))
        })
    }

    pub fn authorize_ssh(&self, identity: &Identity, node: &NodeInfo, login: &str) -> SshDecision {
        let mut decision = SshDecision::default();
        if !is_portable_login(login) || self.ssh_denials(identity, node).covers(login) {
            return decision;
        }
        for (role, rule) in self.ssh_rules_reaching(identity, node) {
            if !rule
                .resolved_logins(identity)
                .any(|candidate| candidate == login)
            {
                continue;
            }
            decision.allowed = true;
            decision.port_forwarding |= rule.port_forwarding;
            decision.record_input |= rule.record_input;
            decision.roles.push(role.name.clone());
        }
        decision.roles.sort();
        decision
    }

    pub fn ssh_logins(&self, identity: &Identity, node: &NodeInfo) -> Vec<String> {
        let denials = self.ssh_denials(identity, node);
        let mut logins: Vec<String> = self
            .ssh_rules_reaching(identity, node)
            .flat_map(|(_, rule)| rule.resolved_logins(identity))
            .filter(|login| !denials.covers(login))
            .map(Cow::into_owned)
            .collect();
        logins.sort();
        logins.dedup();
        logins
    }

    pub fn ssh_hidden_logins(&self, identity: &Identity, node: &NodeInfo) -> Vec<String> {
        let mut hidden: Vec<String> = self
            .ssh_rules_reaching(identity, node)
            .flat_map(|(_, rule)| rule.logins.iter())
            .flat_map(|spec| spec.dropped(identity, SSH_LOGIN))
            .filter(|login| !is_portable_login(login))
            .collect();
        hidden.sort();
        hidden.dedup();
        hidden
    }

    pub fn roles_reaching(&self, node: &NodeInfo) -> Vec<RoleAccess> {
        self.roles_reaching_resource(ResourceKind::Node, node)
            .allows
            .into_iter()
            .filter_map(|grant| match grant.principals {
                GrantPrincipals::Ssh {
                    logins,
                    port_forwarding,
                    record_input,
                } => Some(RoleAccess {
                    role: grant.role,
                    users: grant.users,
                    groups: grant.groups,
                    logins,
                    port_forwarding,
                    record_input,
                    admin: grant.admin,
                }),
                _ => None,
            })
            .collect()
    }

    pub fn admin_can(&self, identity: &Identity, permission: AdminPermission) -> bool {
        self.roles
            .iter()
            .any(|role| role.applies_to(identity) && role.admin.contains(&permission))
    }

    pub fn warnings(&self) -> Vec<PolicyWarning> {
        self.roles
            .iter()
            .flat_map(|role| {
                let ssh = role
                    .ssh
                    .iter()
                    .flat_map(|rule| privileged(&rule.logins, &PRIVILEGED_SSH_LOGINS))
                    .map(|value| (SSH_LOGINS_FIELD, value));
                let kube = role
                    .kubernetes
                    .iter()
                    .flat_map(|rule| privileged(&rule.groups, &PRIVILEGED_KUBE_GROUPS))
                    .map(|value| (KUBE_GROUPS_FIELD, value));
                let db = role
                    .databases
                    .iter()
                    .flat_map(|rule| privileged(&rule.users, &PRIVILEGED_DB_USERS))
                    .map(|value| (DB_USERS_FIELD, value));
                ssh.chain(kube)
                    .chain(db)
                    .map(|(field, value)| PolicyWarning {
                        role: role.name.clone(),
                        field,
                        value: value.to_owned(),
                    })
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.roles.is_empty() && self.tests.is_empty()
    }

    pub fn role_count(&self) -> usize {
        self.roles.len()
    }

    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn tests(&self) -> &[AccessTest] {
        &self.tests
    }
}

impl Default for PolicySet {
    fn default() -> Self {
        PolicySet::empty()
    }
}
