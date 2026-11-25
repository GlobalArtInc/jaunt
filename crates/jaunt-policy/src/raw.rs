use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::access_test::{AccessTest, Expect};
use crate::model::{AdminPermission, NodeInfo, is_valid_login};
use crate::policy::{LabelRequirement, LoginSpec, Role, SshRule};

pub(crate) const API_VERSION: &str = "jaunt/v1";
pub(crate) const USERNAME_PLACEHOLDER: &str = "{username}";
const NODE_NAME_KEY: &str = "name";

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

    let ssh = raw.spec.ssh.and_then(|ssh| compile_ssh(ssh, errors));
    let admin = raw.spec.admin.unwrap_or_default().into_iter().collect();

    Role {
        name,
        users,
        groups,
        ssh,
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

fn compile_ssh(raw: RawSsh, errors: &mut Vec<String>) -> Option<SshRule> {
    let mut nodes = Vec::new();
    match raw.nodes {
        None => errors.push("spec.ssh.nodes is required when spec.ssh is set".to_owned()),
        Some(selector) => {
            if selector.is_empty() {
                errors.push("spec.ssh.nodes selector must not be empty".to_owned());
            }
            for (key, values) in selector {
                if key.is_empty() {
                    errors.push("spec.ssh.nodes label key must not be empty".to_owned());
                }
                if values.is_empty() {
                    errors.push(format!("spec.ssh.nodes.{key} must list at least one value"));
                }
                if values.iter().any(String::is_empty) {
                    errors.push(format!("spec.ssh.nodes.{key} values must not be empty"));
                }
                nodes.push(LabelRequirement { key, values });
            }
        }
    }

    let mut logins = Vec::new();
    let raw_logins = raw.logins.unwrap_or_default();
    if raw_logins.is_empty() {
        errors.push("spec.ssh.logins must list at least one login".to_owned());
    }
    for (index, login) in raw_logins.into_iter().enumerate() {
        if login == USERNAME_PLACEHOLDER {
            logins.push(LoginSpec::Username);
        } else if login.contains('{') || login.contains('}') {
            errors.push(format!(
                "spec.ssh.logins[{index}] {login:?}: only a standalone {USERNAME_PLACEHOLDER} placeholder is supported"
            ));
        } else if !is_valid_login(&login) {
            errors.push(format!(
                "spec.ssh.logins[{index}] {login:?} is not a valid login"
            ));
        } else {
            logins.push(LoginSpec::Literal(login));
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

fn compile_tests(raw: Vec<RawAccessTest>, source: &str) -> Vec<AccessTest> {
    raw.into_iter()
        .enumerate()
        .map(|(index, case)| {
            let mut labels = case.node;
            let name = labels.remove(NODE_NAME_KEY).unwrap_or_default();
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
