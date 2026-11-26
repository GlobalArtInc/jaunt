use std::borrow::Cow;
use std::collections::BTreeSet;

use jaunt_proto::{is_portable_login, is_valid_substituted_login};

use crate::access_test::AccessTest;
use crate::model::{AdminPermission, Identity, NodeInfo, PolicyWarning, RoleAccess, SshDecision};
use crate::template::{Target, ValueSpec};

pub(crate) const ANY_VALUE: &str = "*";
pub(crate) const NAME_PSEUDO_LABEL: &str = "name";
const SSH_LOGINS_FIELD: &str = "spec.ssh.logins";
const PRIVILEGED_SSH_LOGINS: [&str; 1] = ["root"];

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

fn selector_matches(selector: &[LabelRequirement], node: &NodeInfo) -> bool {
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
    fn matches_node(&self, node: &NodeInfo) -> bool {
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
pub(crate) enum DeniedLogins {
    Any,
    Listed(BTreeSet<String>),
}

#[derive(Debug, Clone)]
pub(crate) struct SshDenyRule {
    pub(crate) nodes: Vec<LabelRequirement>,
    pub(crate) logins: DeniedLogins,
}

impl SshDenyRule {
    fn matches_node(&self, node: &NodeInfo) -> bool {
        selector_matches(&self.nodes, node)
    }

    fn covers(&self, login: &str) -> bool {
        match &self.logins {
            DeniedLogins::Any => true,
            DeniedLogins::Listed(logins) => logins.contains(login),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RoleDeny {
    pub(crate) ssh: Option<SshDenyRule>,
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

    fn applicable_roles<'a>(&'a self, identity: &'a Identity) -> impl Iterator<Item = &'a Role> {
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

    pub fn roles_reaching(&self, node: &NodeInfo) -> Vec<RoleAccess> {
        let mut reaching: Vec<RoleAccess> = self
            .roles
            .iter()
            .filter_map(|role| {
                let rule = role.ssh.as_ref().filter(|rule| rule.matches_node(node))?;
                Some(RoleAccess {
                    role: role.name.clone(),
                    users: role.users.iter().cloned().collect(),
                    groups: role.groups.iter().cloned().collect(),
                    logins: rule.logins.iter().map(ValueSpec::as_written).collect(),
                    port_forwarding: rule.port_forwarding,
                    record_input: rule.record_input,
                    admin: role.admin.iter().copied().collect(),
                })
            })
            .collect();
        reaching.sort_by(|left, right| left.role.cmp(&right.role));
        reaching
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
                role.ssh
                    .iter()
                    .flat_map(|rule| rule.logins.iter().filter_map(ValueSpec::as_literal))
                    .filter(|login| PRIVILEGED_SSH_LOGINS.contains(login))
                    .map(|login| PolicyWarning {
                        role: role.name.clone(),
                        field: SSH_LOGINS_FIELD,
                        value: login.to_owned(),
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
