use std::collections::BTreeSet;

use crate::access_test::AccessTest;
use crate::model::{
    AdminPermission, Identity, NodeInfo, RoleAccess, SshDecision, is_valid_login,
    is_valid_substituted_login,
};
use crate::raw::USERNAME_PLACEHOLDER;

pub(crate) const ANY_VALUE: &str = "*";

#[derive(Debug, Clone)]
pub(crate) struct LabelRequirement {
    pub(crate) key: String,
    pub(crate) values: Vec<String>,
}

impl LabelRequirement {
    fn matches(&self, node: &NodeInfo) -> bool {
        match node.labels.get(&self.key) {
            Some(actual) => self
                .values
                .iter()
                .any(|expected| expected == ANY_VALUE || expected == actual),
            None => false,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum LoginSpec {
    Literal(String),
    Username,
}

#[derive(Debug, Clone)]
pub(crate) struct SshRule {
    pub(crate) nodes: Vec<LabelRequirement>,
    pub(crate) logins: Vec<LoginSpec>,
    pub(crate) port_forwarding: bool,
    pub(crate) record_input: bool,
}

impl SshRule {
    fn matches_node(&self, node: &NodeInfo) -> bool {
        !self.nodes.is_empty() && self.nodes.iter().all(|req| req.matches(node))
    }

    fn resolved_logins<'a>(&'a self, identity: &'a Identity) -> impl Iterator<Item = &'a str> {
        self.logins.iter().filter_map(move |spec| match spec {
            LoginSpec::Literal(login) => Some(login.as_str()).filter(|l| is_valid_login(l)),
            LoginSpec::Username => {
                Some(identity.username.as_str()).filter(|l| is_valid_substituted_login(l))
            }
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Role {
    pub(crate) name: String,
    pub(crate) users: BTreeSet<String>,
    pub(crate) groups: BTreeSet<String>,
    pub(crate) ssh: Option<SshRule>,
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

    pub fn route(&self, identity: &Identity, node: &NodeInfo) -> bool {
        self.roles.iter().any(|role| {
            role.applies_to(identity)
                && role.ssh.as_ref().is_some_and(|rule| {
                    rule.matches_node(node) && rule.resolved_logins(identity).next().is_some()
                })
        })
    }

    pub fn authorize_ssh(&self, identity: &Identity, node: &NodeInfo, login: &str) -> SshDecision {
        let mut decision = SshDecision::default();
        if !is_valid_login(login) {
            return decision;
        }
        for role in &self.roles {
            if !role.applies_to(identity) {
                continue;
            }
            let Some(rule) = role.ssh.as_ref() else {
                continue;
            };
            if !rule.matches_node(node) {
                continue;
            }
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
                    logins: rule
                        .logins
                        .iter()
                        .map(|spec| match spec {
                            LoginSpec::Literal(login) => login.clone(),
                            LoginSpec::Username => USERNAME_PLACEHOLDER.to_owned(),
                        })
                        .collect(),
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
