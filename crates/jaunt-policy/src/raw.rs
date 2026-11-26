use std::collections::{BTreeMap, BTreeSet};

use jaunt_proto::is_portable_login;
use serde::Deserialize;

use crate::access_test::{AccessTest, Expect};
use crate::model::{AdminPermission, NodeInfo};
use crate::policy::{
    ANY_VALUE, DeniedLogins, LabelRequirement, NAME_PSEUDO_LABEL, Role, RoleDeny, SSH_LOGIN,
    SelectorKey, SshDenyRule, SshRule,
};
use crate::template::{Parsed, TRAIT_FORMS, ValueSpec};

pub(crate) const API_VERSION: &str = "jaunt/v1";

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "PolicyDocument"))]
#[serde(
    tag = "kind",
    expecting = "a mapping with `kind` set to Role or AccessTest"
)]
pub(crate) enum RawDocument {
    Role(RawRole),
    AccessTest(RawAccessTests),
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "Role"))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RawRole {
    #[cfg_attr(feature = "schema", schemars(extend("const" = "jaunt/v1")))]
    api_version: String,
    metadata: RawMetadata,
    spec: RawRoleSpec,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleMetadata"))]
#[serde(deny_unknown_fields)]
struct RawMetadata {
    name: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleSpec"))]
#[serde(deny_unknown_fields)]
struct RawRoleSpec {
    members: Option<RawMembers>,
    ssh: Option<RawSsh>,
    deny: Option<RawDeny>,
    admin: Option<Vec<AdminPermission>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleMembers"))]
#[serde(deny_unknown_fields)]
struct RawMembers {
    groups: Option<Vec<String>>,
    users: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleSsh"))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawSsh {
    nodes: Option<BTreeMap<String, Vec<String>>>,
    logins: Option<Vec<String>>,
    #[serde(default)]
    port_forwarding: bool,
    #[serde(default)]
    record_input: bool,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleDeny"))]
#[serde(deny_unknown_fields)]
struct RawDeny {
    ssh: Option<RawDenySsh>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleDenySsh"))]
#[serde(deny_unknown_fields)]
struct RawDenySsh {
    nodes: Option<BTreeMap<String, Vec<String>>>,
    logins: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessTest"))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RawAccessTests {
    #[cfg_attr(feature = "schema", schemars(extend("const" = "jaunt/v1")))]
    api_version: String,
    spec: Vec<RawAccessTest>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessTestCase"))]
#[serde(deny_unknown_fields)]
struct RawAccessTest {
    user: String,
    #[serde(default)]
    groups: Vec<String>,
    username: Option<String>,
    node: BTreeMap<String, String>,
    login: String,
    expect: Expect,
}

pub(crate) enum Compiled {
    Role(Box<Role>),
    Tests(Vec<AccessTest>),
}

impl RawDocument {
    pub(crate) fn compile(self, source: &str) -> Result<Compiled, Vec<String>> {
        let mut errors = Vec::new();
        let compiled = match self {
            RawDocument::Role(raw) => {
                check_api_version(&raw.api_version, &mut errors);
                Compiled::Role(Box::new(compile_role(raw, &mut errors)))
            }
            RawDocument::AccessTest(raw) => {
                check_api_version(&raw.api_version, &mut errors);
                Compiled::Tests(compile_tests(raw.spec, source))
            }
        };
        if errors.is_empty() {
            Ok(compiled)
        } else {
            Err(errors)
        }
    }
}

fn check_api_version(api_version: &str, errors: &mut Vec<String>) {
    if api_version != API_VERSION {
        errors.push(format!(
            "unsupported apiVersion {api_version:?}, expected {API_VERSION:?}"
        ));
    }
}

fn compile_role(raw: RawRole, errors: &mut Vec<String>) -> Role {
    let name = raw.metadata.name;
    if name.is_empty() || name.chars().any(char::is_control) {
        errors.push(format!(
            "metadata.name {name:?} must be non-empty and free of control characters"
        ));
    }

    let (users, groups) = match raw.spec.members {
        Some(members) => (
            non_empty_set(members.users, "spec.members.users", errors),
            non_empty_set(members.groups, "spec.members.groups", errors),
        ),
        None => (BTreeSet::new(), BTreeSet::new()),
    };

    let ssh = raw.spec.ssh.and_then(|ssh| compile_ssh(&name, ssh, errors));
    let deny = raw
        .spec
        .deny
        .map(|deny| compile_deny(&name, deny, errors))
        .unwrap_or_default();
    let admin = raw.spec.admin.unwrap_or_default().into_iter().collect();

    Role {
        name,
        users,
        groups,
        ssh,
        deny,
        admin,
    }
}

fn non_empty_set(
    values: Option<Vec<String>>,
    path: &str,
    errors: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for (index, value) in values.unwrap_or_default().into_iter().enumerate() {
        if value.is_empty() {
            errors.push(format!("{path}[{index}] must not be empty"));
        } else {
            set.insert(value);
        }
    }
    set
}

fn compile_selector(
    context: &str,
    block: &str,
    raw: Option<BTreeMap<String, Vec<String>>>,
    errors: &mut Vec<String>,
) -> Vec<LabelRequirement> {
    let path = format!("{context}{block}.nodes");
    let mut nodes = Vec::new();
    match raw {
        None => errors.push(format!("{path} is required when {block} is set")),
        Some(selector) => {
            if selector.is_empty() {
                errors.push(format!("{path} selector must not be empty"));
            }
            for (key, values) in selector {
                if key.is_empty() {
                    errors.push(format!("{path} label key must not be empty"));
                }
                if values.is_empty() {
                    errors.push(format!("{path}.{key} must list at least one value"));
                }
                if values.iter().any(String::is_empty) {
                    errors.push(format!("{path}.{key} values must not be empty"));
                }
                let key = if key == NAME_PSEUDO_LABEL {
                    SelectorKey::Name
                } else {
                    SelectorKey::Label(key)
                };
                nodes.push(LabelRequirement { key, values });
            }
        }
    }
    nodes
}

fn compile_ssh(role: &str, raw: RawSsh, errors: &mut Vec<String>) -> Option<SshRule> {
    let nodes = compile_selector("", "spec.ssh", raw.nodes, errors);

    let mut logins = Vec::new();
    let raw_logins = raw.logins.unwrap_or_default();
    if raw_logins.is_empty() {
        errors.push("spec.ssh.logins must list at least one login".to_owned());
    }
    for (index, login) in raw_logins.into_iter().enumerate() {
        let path = format!("role {role:?}: spec.ssh.logins[{index}] {login:?}");
        match ValueSpec::parse(&login, SSH_LOGIN) {
            Parsed::Valid(spec) => logins.push(spec),
            Parsed::InvalidLiteral => errors.push(format!("{path} is not a valid login")),
            Parsed::MalformedTemplate => errors.push(format!("{path}: {TRAIT_FORMS}")),
            Parsed::InvalidPrefix => errors.push(format!(
                "{path}: the literal prefix cannot start a valid login"
            )),
        }
    }

    if nodes.is_empty() || logins.is_empty() {
        return None;
    }
    Some(SshRule {
        nodes,
        logins,
        port_forwarding: raw.port_forwarding,
        record_input: raw.record_input,
    })
}

fn compile_deny(role: &str, raw: RawDeny, errors: &mut Vec<String>) -> RoleDeny {
    RoleDeny {
        ssh: raw.ssh.and_then(|ssh| compile_deny_ssh(role, ssh, errors)),
    }
}

fn compile_deny_ssh(role: &str, raw: RawDenySsh, errors: &mut Vec<String>) -> Option<SshDenyRule> {
    let context = format!("role {role:?}: ");
    let nodes = compile_selector(&context, "spec.deny.ssh", raw.nodes, errors);
    let logins = match raw.logins {
        None => DeniedLogins::Any,
        Some(raw_logins) => {
            if raw_logins.is_empty() {
                errors.push(format!(
                    "{context}spec.deny.ssh.logins must list at least one login; omit it to deny every login"
                ));
            }
            let mut any = false;
            let mut listed = BTreeSet::new();
            for (index, login) in raw_logins.into_iter().enumerate() {
                let path = format!("{context}spec.deny.ssh.logins[{index}] {login:?}");
                if login == ANY_VALUE {
                    any = true;
                } else if login.contains(['{', '}']) {
                    errors.push(format!(
                        "{path}: a deny rule lists literal logins or \"*\", not traits"
                    ));
                } else if !is_portable_login(&login) {
                    errors.push(format!("{path} is not a valid login"));
                } else {
                    listed.insert(login);
                }
            }
            if any {
                DeniedLogins::Any
            } else {
                DeniedLogins::Listed(listed)
            }
        }
    };

    if nodes.is_empty() {
        return None;
    }
    Some(SshDenyRule { nodes, logins })
}

fn compile_tests(raw: Vec<RawAccessTest>, source: &str) -> Vec<AccessTest> {
    raw.into_iter()
        .enumerate()
        .map(|(index, case)| {
            let mut labels = case.node;
            let name = labels.remove(NAME_PSEUDO_LABEL).unwrap_or_default();
            let username = case.username.unwrap_or_else(|| {
                case.user
                    .split_once('@')
                    .map(|(local, _)| local.to_owned())
                    .unwrap_or_default()
            });
            AccessTest {
                source: format!("{source} entry {}", index + 1),
                user: case.user,
                groups: case.groups,
                username,
                node: NodeInfo { name, labels },
                login: case.login,
                expect: case.expect,
            }
        })
        .collect()
}
