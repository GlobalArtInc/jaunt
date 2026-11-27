use std::borrow::Cow;
use std::collections::BTreeSet;

use jaunt_proto::{
    is_db_name, is_db_user, is_kube_principal, is_valid_substituted_db_name,
    is_valid_substituted_db_user, is_valid_substituted_kube_principal,
};

use crate::model::{DbDecision, Identity, KubeDecision, ResourceInfo, TcpDecision};
use crate::policy::{ANY_VALUE, DeniedValues, LabelRequirement, PolicySet, Role, selector_matches};
use crate::template::{Target, ValueSpec};

fn is_kube_prefix(prefix: &str) -> bool {
    is_valid_substituted_kube_principal(&format!("{prefix}a"))
}

fn is_db_user_prefix(prefix: &str) -> bool {
    is_valid_substituted_db_user(&format!("{prefix}a"))
}

fn is_db_name_prefix(prefix: &str) -> bool {
    is_valid_substituted_db_name(&format!("{prefix}a"))
}

pub(crate) const KUBE_PRINCIPAL: Target = Target {
    literal: is_kube_principal,
    prefix: is_kube_prefix,
    substituted: is_valid_substituted_kube_principal,
};

pub(crate) const DB_USER: Target = Target {
    literal: is_db_user,
    prefix: is_db_user_prefix,
    substituted: is_valid_substituted_db_user,
};

pub(crate) const DB_NAME: Target = Target {
    literal: is_db_name,
    prefix: is_db_name_prefix,
    substituted: is_valid_substituted_db_name,
};

fn resolve_all<'a>(
    specs: &'a [ValueSpec],
    identity: &'a Identity,
    target: Target,
) -> impl Iterator<Item = Cow<'a, str>> + 'a {
    specs
        .iter()
        .flat_map(move |spec| spec.resolve(identity, target))
}

fn any_dropped(specs: &[ValueSpec], identity: &Identity, target: Target) -> bool {
    specs
        .iter()
        .any(|spec| spec.drops_invalid(identity, target))
}

fn subtract<'a>(
    granted: &BTreeSet<String>,
    denials: &[(&'a Role, &KubeDenyRule)],
    removing: &mut BTreeSet<&'a str>,
    covers: impl Fn(&KubeDenyRule, &str) -> bool,
) -> BTreeSet<String> {
    let mut kept = BTreeSet::new();
    for value in granted {
        let mut removed = false;
        for (role, deny) in denials {
            if covers(deny, value) {
                removing.insert(role.name.as_str());
                removed = true;
            }
        }
        if !removed {
            kept.insert(value.clone());
        }
    }
    kept
}

fn sorted_names<'a>(roles: impl Iterator<Item = &'a Role>) -> Vec<String> {
    let names: BTreeSet<&str> = roles.map(|role| role.name.as_str()).collect();
    names.into_iter().map(str::to_owned).collect()
}

#[derive(Debug, Clone)]
pub(crate) struct KubeRule {
    pub(crate) clusters: Vec<LabelRequirement>,
    pub(crate) groups: Vec<ValueSpec>,
    pub(crate) users: Vec<ValueSpec>,
    pub(crate) record_exec: bool,
    pub(crate) record_input: bool,
}

impl KubeRule {
    pub(crate) fn matches(&self, cluster: &ResourceInfo) -> bool {
        selector_matches(&self.clusters, cluster)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct KubeDenyRule {
    pub(crate) clusters: Vec<LabelRequirement>,
    pub(crate) groups: Option<DeniedValues>,
    pub(crate) users: Option<DeniedValues>,
}

impl KubeDenyRule {
    pub(crate) fn matches(&self, cluster: &ResourceInfo) -> bool {
        selector_matches(&self.clusters, cluster)
    }

    fn denies_cluster(&self) -> bool {
        self.groups.is_none() && self.users.is_none()
    }

    fn covers_user(&self, user: &str) -> bool {
        self.users.as_ref().is_some_and(|users| users.covers(user))
    }

    fn covers_group(&self, group: &str) -> bool {
        self.groups
            .as_ref()
            .is_some_and(|groups| groups.covers(group))
    }
}

#[derive(Debug, Clone)]
pub(crate) enum DbNameSpec {
    Any,
    Value(ValueSpec),
}

impl DbNameSpec {
    pub(crate) fn as_written(&self) -> String {
        match self {
            DbNameSpec::Any => ANY_VALUE.to_owned(),
            DbNameSpec::Value(spec) => spec.as_written(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DbRule {
    pub(crate) servers: Vec<LabelRequirement>,
    pub(crate) users: Vec<ValueSpec>,
    pub(crate) names: Vec<DbNameSpec>,
}

impl DbRule {
    pub(crate) fn matches(&self, server: &ResourceInfo) -> bool {
        selector_matches(&self.servers, server)
    }

    fn resolved_users<'a>(
        &'a self,
        identity: &'a Identity,
    ) -> impl Iterator<Item = Cow<'a, str>> + 'a {
        resolve_all(&self.users, identity, DB_USER)
    }

    fn resolved_names<'a>(
        &'a self,
        identity: &'a Identity,
    ) -> impl Iterator<Item = Cow<'a, str>> + 'a {
        self.names.iter().flat_map(move |spec| {
            let (any, value) = match spec {
                DbNameSpec::Any => (Some(Cow::Borrowed(ANY_VALUE)), None),
                DbNameSpec::Value(value) => (None, Some(value)),
            };
            any.into_iter().chain(
                value
                    .into_iter()
                    .flat_map(move |value| value.resolve(identity, DB_NAME)),
            )
        })
    }

    fn grants(&self, identity: &Identity, user: &str, name: &str) -> bool {
        self.resolved_users(identity)
            .any(|candidate| candidate == user)
            && self
                .resolved_names(identity)
                .any(|candidate| candidate == ANY_VALUE || candidate == name)
    }

    fn drops_invalid(&self, identity: &Identity) -> bool {
        any_dropped(&self.users, identity, DB_USER)
            || self.names.iter().any(|spec| match spec {
                DbNameSpec::Any => false,
                DbNameSpec::Value(value) => value.drops_invalid(identity, DB_NAME),
            })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DbDenyRule {
    pub(crate) servers: Vec<LabelRequirement>,
    pub(crate) users: DeniedValues,
    pub(crate) names: DeniedValues,
}

impl DbDenyRule {
    pub(crate) fn matches(&self, server: &ResourceInfo) -> bool {
        selector_matches(&self.servers, server)
    }

    fn covers(&self, user: &str, name: &str) -> bool {
        self.users.covers(user) && self.names.covers(name)
    }

    fn removes_user(&self, user: &str) -> bool {
        matches!(self.names, DeniedValues::Any) && self.users.covers(user)
    }

    fn removes_name(&self, name: &str) -> bool {
        matches!(self.users, DeniedValues::Any) && self.names.covers(name)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TcpRule {
    pub(crate) services: Vec<LabelRequirement>,
}

impl TcpRule {
    pub(crate) fn matches(&self, service: &ResourceInfo) -> bool {
        selector_matches(&self.services, service)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TcpDenyRule {
    pub(crate) services: Vec<LabelRequirement>,
}

impl TcpDenyRule {
    pub(crate) fn matches(&self, service: &ResourceInfo) -> bool {
        selector_matches(&self.services, service)
    }
}

impl PolicySet {
    pub fn authorize_kube(&self, identity: &Identity, cluster: &ResourceInfo) -> KubeDecision {
        let mut decision = KubeDecision {
            policy_hash: self.hash.clone(),
            ..KubeDecision::default()
        };
        let denials: Vec<(&Role, &KubeDenyRule)> = self
            .applicable_roles(identity)
            .filter_map(|role| {
                role.deny
                    .kubernetes
                    .as_ref()
                    .filter(|rule| rule.matches(cluster))
                    .map(|rule| (role, rule))
            })
            .collect();
        let cluster_deniers = sorted_names(
            denials
                .iter()
                .filter(|(_, rule)| rule.denies_cluster())
                .map(|(role, _)| *role),
        );

        let mut granting = Vec::new();
        let mut removing = BTreeSet::new();
        let mut users = BTreeSet::new();
        let mut groups = BTreeSet::new();
        let mut record_exec = false;
        let mut record_input = false;
        for (role, rule) in self.applicable_roles(identity).filter_map(|role| {
            role.kubernetes
                .as_ref()
                .filter(|rule| rule.matches(cluster))
                .map(|rule| (role, rule))
        }) {
            record_exec |= rule.record_exec;
            record_input |= rule.record_input;
            decision.trait_not_valid |= any_dropped(&rule.users, identity, KUBE_PRINCIPAL)
                || any_dropped(&rule.groups, identity, KUBE_PRINCIPAL);
            let granted_users: BTreeSet<String> =
                resolve_all(&rule.users, identity, KUBE_PRINCIPAL)
                    .map(Cow::into_owned)
                    .collect();
            let granted_groups: BTreeSet<String> =
                resolve_all(&rule.groups, identity, KUBE_PRINCIPAL)
                    .map(Cow::into_owned)
                    .collect();
            let kept_users = subtract(&granted_users, &denials, &mut removing, |deny, user| {
                deny.covers_user(user)
            });
            let kept_groups = subtract(&granted_groups, &denials, &mut removing, |deny, group| {
                deny.covers_group(group)
            });
            if kept_users.is_empty() || (!granted_groups.is_empty() && kept_groups.is_empty()) {
                continue;
            }
            granting.push(role);
            users.extend(kept_users);
            groups.extend(kept_groups);
        }

        if !cluster_deniers.is_empty() {
            decision.denied_by = cluster_deniers;
            return decision;
        }
        if granting.is_empty() {
            decision.denied_by = removing.into_iter().map(str::to_owned).collect();
            return decision;
        }

        decision.allowed = true;
        decision.roles = sorted_names(granting.into_iter());
        decision.subtracted_by = removing.into_iter().map(str::to_owned).collect();
        decision.users = users.into_iter().collect();
        decision.groups = groups.into_iter().collect();
        decision.record_exec = record_exec;
        decision.record_input = record_input;
        decision
    }

    pub fn authorize_db(
        &self,
        identity: &Identity,
        server: &ResourceInfo,
        user: &str,
        name: &str,
    ) -> DbDecision {
        let mut decision = DbDecision {
            policy_hash: self.hash.clone(),
            ..DbDecision::default()
        };
        let denials: Vec<(&Role, &DbDenyRule)> = self
            .applicable_roles(identity)
            .filter_map(|role| {
                role.deny
                    .databases
                    .as_ref()
                    .filter(|rule| rule.matches(server))
                    .map(|rule| (role, rule))
            })
            .collect();
        let rules: Vec<(&Role, &DbRule)> = self
            .applicable_roles(identity)
            .filter_map(|role| {
                role.databases
                    .as_ref()
                    .filter(|rule| rule.matches(server))
                    .map(|rule| (role, rule))
            })
            .collect();

        decision.trait_not_valid = rules.iter().any(|(_, rule)| rule.drops_invalid(identity));
        if !is_db_user(user) || !is_db_name(name) {
            return decision;
        }
        decision.denied_by = sorted_names(
            denials
                .iter()
                .filter(|(_, rule)| rule.covers(user, name))
                .map(|(role, _)| *role),
        );
        if !decision.denied_by.is_empty() {
            return decision;
        }
        let granting: Vec<(&Role, &DbRule)> = rules
            .into_iter()
            .filter(|(_, rule)| rule.grants(identity, user, name))
            .collect();
        if granting.is_empty() {
            return decision;
        }

        decision.allowed = true;
        decision.roles = sorted_names(granting.iter().map(|(role, _)| *role));
        decision.users = granting
            .iter()
            .flat_map(|(_, rule)| rule.resolved_users(identity))
            .filter(|user| !denials.iter().any(|(_, rule)| rule.removes_user(user)))
            .map(Cow::into_owned)
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        decision.names = granting
            .iter()
            .flat_map(|(_, rule)| rule.resolved_names(identity))
            .filter(|name| !denials.iter().any(|(_, rule)| rule.removes_name(name)))
            .map(Cow::into_owned)
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        decision
    }

    pub fn authorize_tcp(&self, identity: &Identity, service: &ResourceInfo) -> TcpDecision {
        let mut decision = TcpDecision {
            policy_hash: self.hash.clone(),
            ..TcpDecision::default()
        };
        decision.denied_by = sorted_names(self.applicable_roles(identity).filter(|role| {
            role.deny
                .tcp
                .as_ref()
                .is_some_and(|rule| rule.matches(service))
        }));
        if !decision.denied_by.is_empty() {
            return decision;
        }
        decision.roles = sorted_names(
            self.applicable_roles(identity)
                .filter(|role| role.tcp.as_ref().is_some_and(|rule| rule.matches(service))),
        );
        decision.allowed = !decision.roles.is_empty();
        decision
    }
}
