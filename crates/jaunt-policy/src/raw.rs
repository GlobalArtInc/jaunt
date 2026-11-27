use std::collections::{BTreeMap, BTreeSet};

use jaunt_proto::{is_db_name, is_db_user, is_kube_principal, is_portable_login};
use serde::Deserialize;

use crate::access_test::{AccessTarget, AccessTest, Expect};
use crate::model::{AdminPermission, NodeInfo};
use crate::policy::{
    ANY_VALUE, DeniedValues, LabelRequirement, NAME_PSEUDO_LABEL, Role, RoleDeny, SSH_LOGIN,
    SelectorKey, SshDenyRule, SshRule,
};
use crate::services::{
    DB_NAME, DB_USER, DbDenyRule, DbNameSpec, DbRule, KUBE_PRINCIPAL, KubeDenyRule, KubeRule,
    TcpDenyRule, TcpRule,
};
use crate::template::{Parsed, TRAIT_FORMS, Target, ValueSpec};

pub(crate) const API_VERSION: &str = "jaunt/v1";

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "PolicyDocument"))]
#[serde(
    tag = "kind",
    expecting = "a mapping with `kind` set to Role or AccessTest"
)]
pub(crate) enum RawDocument {
    Role(Box<RawRole>),
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
    kubernetes: Option<RawKubernetes>,
    databases: Option<RawDatabases>,
    tcp: Option<RawTcp>,
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
    kubernetes: Option<RawDenyKubernetes>,
    databases: Option<RawDenyDatabases>,
    tcp: Option<RawTcp>,
}

type RawSelector = BTreeMap<String, Vec<String>>;

fn record_exec_default() -> bool {
    true
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleKubernetes"))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RawKubernetes {
    clusters: Option<RawSelector>,
    groups: Option<Vec<String>>,
    users: Option<Vec<String>>,
    #[serde(default = "record_exec_default")]
    record_exec: bool,
    #[serde(default)]
    record_input: bool,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleDatabases"))]
#[serde(deny_unknown_fields)]
struct RawDatabases {
    servers: Option<RawSelector>,
    users: Option<Vec<String>>,
    names: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleTcp"))]
#[serde(deny_unknown_fields)]
struct RawTcp {
    services: Option<RawSelector>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleDenyKubernetes"))]
#[serde(deny_unknown_fields)]
struct RawDenyKubernetes {
    clusters: Option<RawSelector>,
    groups: Option<Vec<String>>,
    users: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "RoleDenyDatabases"))]
#[serde(deny_unknown_fields)]
struct RawDenyDatabases {
    servers: Option<RawSelector>,
    users: Option<Vec<String>>,
    names: Option<Vec<String>>,
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
#[cfg_attr(
    feature = "schema",
    schemars(extend("oneOf" = [
        { "required": ["node", "login"], "properties": { "kubernetes": false, "database": false, "tcp": false } },
        { "required": ["kubernetes"], "properties": { "node": false, "login": false, "database": false, "tcp": false } },
        { "required": ["database"], "properties": { "node": false, "login": false, "kubernetes": false, "tcp": false } },
        { "required": ["tcp"], "properties": { "node": false, "login": false, "kubernetes": false, "database": false } }
    ]))
)]
#[serde(deny_unknown_fields)]
struct RawAccessTest {
    user: String,
    #[serde(default)]
    groups: Vec<String>,
    username: Option<String>,
    node: Option<BTreeMap<String, String>>,
    login: Option<String>,
    kubernetes: Option<RawKubernetesTarget>,
    database: Option<RawDatabaseTarget>,
    tcp: Option<RawTcpTarget>,
    #[cfg_attr(feature = "schema", schemars(length(max = 0)))]
    grants: Option<Vec<String>>,
    expect: Expect,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessTestKubernetes"))]
#[serde(deny_unknown_fields)]
struct RawKubernetesTarget {
    cluster: BTreeMap<String, String>,
    user: Option<String>,
    groups: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessTestDatabase"))]
#[serde(deny_unknown_fields)]
struct RawDatabaseTarget {
    server: BTreeMap<String, String>,
    user: String,
    name: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "AccessTestTcp"))]
#[serde(deny_unknown_fields)]
struct RawTcpTarget {
    service: BTreeMap<String, String>,
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
                Compiled::Role(Box::new(compile_role(*raw, &mut errors)))
            }
            RawDocument::AccessTest(raw) => {
                check_api_version(&raw.api_version, &mut errors);
                Compiled::Tests(compile_tests(raw.spec, source, &mut errors))
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
    let kubernetes = raw
        .spec
        .kubernetes
        .and_then(|block| compile_kubernetes(&name, block, errors));
    let databases = raw
        .spec
        .databases
        .and_then(|block| compile_databases(&name, block, errors));
    let tcp = raw
        .spec
        .tcp
        .and_then(|block| compile_tcp(&name, block, errors));
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
        kubernetes,
        databases,
        tcp,
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
    field: &str,
    raw: Option<RawSelector>,
    errors: &mut Vec<String>,
) -> Vec<LabelRequirement> {
    let path = format!("{context}{block}.{field}");
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
    let nodes = compile_selector("", "spec.ssh", "nodes", raw.nodes, errors);

    let raw_logins = raw.logins.unwrap_or_default();
    if raw_logins.is_empty() {
        errors.push("spec.ssh.logins must list at least one login".to_owned());
    }
    let logins = compile_values(
        &format!("role {role:?}: spec.ssh.logins"),
        raw_logins,
        SSH_LOGIN,
        "login",
        errors,
    );

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

fn compile_values(
    path: &str,
    raw: Vec<String>,
    target: Target,
    noun: &str,
    errors: &mut Vec<String>,
) -> Vec<ValueSpec> {
    raw.into_iter()
        .enumerate()
        .filter_map(|(index, value)| {
            compile_value(&format!("{path}[{index}]"), &value, target, noun, errors)
        })
        .collect()
}

fn compile_value(
    path: &str,
    value: &str,
    target: Target,
    noun: &str,
    errors: &mut Vec<String>,
) -> Option<ValueSpec> {
    let path = format!("{path} {value:?}");
    match ValueSpec::parse(value, target) {
        Parsed::Valid(spec) => return Some(spec),
        Parsed::InvalidLiteral => errors.push(format!("{path} is not a valid {noun}")),
        Parsed::MalformedTemplate => errors.push(format!("{path}: {TRAIT_FORMS}")),
        Parsed::InvalidPrefix => errors.push(format!(
            "{path}: the literal prefix cannot start a valid {noun}"
        )),
    }
    None
}

fn compile_required_values(
    path: &str,
    raw: Option<Vec<String>>,
    target: Target,
    noun: &str,
    errors: &mut Vec<String>,
) -> Vec<ValueSpec> {
    let raw = raw.unwrap_or_default();
    if raw.is_empty() {
        errors.push(format!("{path} must list at least one {noun}"));
    }
    compile_values(path, raw, target, noun, errors)
}

fn compile_optional_values(
    path: &str,
    raw: Option<Vec<String>>,
    target: Target,
    noun: &str,
    errors: &mut Vec<String>,
) -> Option<Vec<ValueSpec>> {
    raw.map(|raw| compile_required_values(path, Some(raw), target, noun, errors))
}

fn compile_kubernetes(
    role: &str,
    raw: RawKubernetes,
    errors: &mut Vec<String>,
) -> Option<KubeRule> {
    let context = format!("role {role:?}: ");
    let block = "spec.kubernetes";
    let before = errors.len();
    let clusters = compile_selector(&context, block, "clusters", raw.clusters, errors);
    let groups = compile_optional_values(
        &format!("{context}{block}.groups"),
        raw.groups,
        KUBE_PRINCIPAL,
        "Kubernetes group",
        errors,
    )
    .unwrap_or_default();
    let users = compile_optional_values(
        &format!("{context}{block}.users"),
        raw.users,
        KUBE_PRINCIPAL,
        "Kubernetes user",
        errors,
    )
    .unwrap_or_else(|| vec![ValueSpec::email()]);
    if errors.len() != before {
        return None;
    }
    Some(KubeRule {
        clusters,
        groups,
        users,
        record_exec: raw.record_exec,
        record_input: raw.record_input,
    })
}

fn compile_databases(role: &str, raw: RawDatabases, errors: &mut Vec<String>) -> Option<DbRule> {
    let context = format!("role {role:?}: ");
    let block = "spec.databases";
    let before = errors.len();
    let servers = compile_selector(&context, block, "servers", raw.servers, errors);
    let users = compile_required_values(
        &format!("{context}{block}.users"),
        raw.users,
        DB_USER,
        "database user",
        errors,
    );
    let names_path = format!("{context}{block}.names");
    let raw_names = raw.names.unwrap_or_default();
    if raw_names.is_empty() {
        errors.push(format!(
            "{names_path} must list at least one database name or \"*\""
        ));
    }
    let names: Vec<DbNameSpec> = raw_names
        .into_iter()
        .enumerate()
        .filter_map(|(index, name)| {
            if name == ANY_VALUE {
                return Some(DbNameSpec::Any);
            }
            let path = format!("{names_path}[{index}]");
            compile_value(&path, &name, DB_NAME, "database name", errors).map(DbNameSpec::Value)
        })
        .collect();
    if errors.len() != before {
        return None;
    }
    Some(DbRule {
        servers,
        users,
        names,
    })
}

fn compile_tcp(role: &str, raw: RawTcp, errors: &mut Vec<String>) -> Option<TcpRule> {
    let context = format!("role {role:?}: ");
    let before = errors.len();
    let services = compile_selector(&context, "spec.tcp", "services", raw.services, errors);
    (errors.len() == before).then_some(TcpRule { services })
}

fn compile_denied_values(
    path: &str,
    raw: Option<Vec<String>>,
    valid: fn(&str) -> bool,
    noun: &str,
    errors: &mut Vec<String>,
) -> Option<DeniedValues> {
    let raw = raw?;
    if raw.is_empty() {
        errors.push(format!(
            "{path} must list at least one {noun} or \"*\"; omit the key instead of an empty list"
        ));
    }
    let mut any = false;
    let mut listed = BTreeSet::new();
    for (index, value) in raw.into_iter().enumerate() {
        let item = format!("{path}[{index}] {value:?}");
        if value == ANY_VALUE {
            any = true;
        } else if value.contains(['{', '}']) {
            errors.push(format!(
                "{item}: a deny rule lists literal values or \"*\", not traits"
            ));
        } else if !valid(&value) {
            errors.push(format!("{item} is not a valid {noun}"));
        } else {
            listed.insert(value);
        }
    }
    Some(if any {
        DeniedValues::Any
    } else {
        DeniedValues::Listed(listed)
    })
}

fn compile_deny(role: &str, raw: RawDeny, errors: &mut Vec<String>) -> RoleDeny {
    RoleDeny {
        ssh: raw.ssh.and_then(|ssh| compile_deny_ssh(role, ssh, errors)),
        kubernetes: raw
            .kubernetes
            .and_then(|block| compile_deny_kubernetes(role, block, errors)),
        databases: raw
            .databases
            .and_then(|block| compile_deny_databases(role, block, errors)),
        tcp: raw
            .tcp
            .and_then(|block| compile_deny_tcp(role, block, errors)),
    }
}

fn compile_deny_kubernetes(
    role: &str,
    raw: RawDenyKubernetes,
    errors: &mut Vec<String>,
) -> Option<KubeDenyRule> {
    let context = format!("role {role:?}: ");
    let block = "spec.deny.kubernetes";
    let before = errors.len();
    let clusters = compile_selector(&context, block, "clusters", raw.clusters, errors);
    let groups = compile_denied_values(
        &format!("{context}{block}.groups"),
        raw.groups,
        is_kube_principal,
        "Kubernetes group",
        errors,
    );
    let users = compile_denied_values(
        &format!("{context}{block}.users"),
        raw.users,
        is_kube_principal,
        "Kubernetes user",
        errors,
    );
    (errors.len() == before).then_some(KubeDenyRule {
        clusters,
        groups,
        users,
    })
}

fn compile_deny_databases(
    role: &str,
    raw: RawDenyDatabases,
    errors: &mut Vec<String>,
) -> Option<DbDenyRule> {
    let context = format!("role {role:?}: ");
    let block = "spec.deny.databases";
    let before = errors.len();
    let servers = compile_selector(&context, block, "servers", raw.servers, errors);
    let users = compile_denied_values(
        &format!("{context}{block}.users"),
        raw.users,
        is_db_user,
        "database user",
        errors,
    );
    let names = compile_denied_values(
        &format!("{context}{block}.names"),
        raw.names,
        is_db_name,
        "database name",
        errors,
    );
    (errors.len() == before).then_some(DbDenyRule {
        servers,
        users: users.unwrap_or(DeniedValues::Any),
        names: names.unwrap_or(DeniedValues::Any),
    })
}

fn compile_deny_tcp(role: &str, raw: RawTcp, errors: &mut Vec<String>) -> Option<TcpDenyRule> {
    let context = format!("role {role:?}: ");
    let before = errors.len();
    let services = compile_selector(&context, "spec.deny.tcp", "services", raw.services, errors);
    (errors.len() == before).then_some(TcpDenyRule { services })
}

fn compile_deny_ssh(role: &str, raw: RawDenySsh, errors: &mut Vec<String>) -> Option<SshDenyRule> {
    let context = format!("role {role:?}: ");
    let nodes = compile_selector(&context, "spec.deny.ssh", "nodes", raw.nodes, errors);
    let logins = match raw.logins {
        None => DeniedValues::Any,
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
                DeniedValues::Any
            } else {
                DeniedValues::Listed(listed)
            }
        }
    };

    if nodes.is_empty() {
        return None;
    }
    Some(SshDenyRule { nodes, logins })
}

fn resource(mut labels: BTreeMap<String, String>) -> NodeInfo {
    let name = labels.remove(NAME_PSEUDO_LABEL).unwrap_or_default();
    NodeInfo { name, labels }
}

const ONE_TARGET: &str =
    "an access test needs exactly one target: node with login, kubernetes, database or tcp";

fn compile_target(
    case: &mut RawAccessTest,
    path: &str,
    errors: &mut Vec<String>,
) -> Option<AccessTarget> {
    let mut targets = Vec::new();
    match (case.node.take(), case.login.take()) {
        (Some(node), Some(login)) => targets.push(AccessTarget::Ssh {
            node: resource(node),
            login,
        }),
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            errors.push(format!("{path}: node and login must be given together"));
            return None;
        }
    }
    if let Some(target) = case.kubernetes.take() {
        targets.push(AccessTarget::Kubernetes {
            cluster: resource(target.cluster),
            user: target.user,
            groups: target.groups.map(|groups| groups.into_iter().collect()),
        });
    }
    if let Some(target) = case.database.take() {
        targets.push(AccessTarget::Database {
            server: resource(target.server),
            user: target.user,
            name: target.name,
        });
    }
    if let Some(target) = case.tcp.take() {
        targets.push(AccessTarget::Tcp {
            service: resource(target.service),
        });
    }
    if targets.len() != 1 {
        errors.push(format!("{path}: {ONE_TARGET}"));
        return None;
    }
    targets.pop()
}

fn compile_tests(
    raw: Vec<RawAccessTest>,
    source: &str,
    errors: &mut Vec<String>,
) -> Vec<AccessTest> {
    let mut tests = Vec::new();
    for (index, mut case) in raw.into_iter().enumerate() {
        let path = format!("spec[{index}]");
        if case
            .grants
            .as_ref()
            .is_some_and(|grants| !grants.is_empty())
        {
            errors.push(format!(
                "{path}: grants is reserved for temporary role grants and must be empty or absent"
            ));
        }
        let Some(target) = compile_target(&mut case, &path, errors) else {
            continue;
        };
        let username = case.username.unwrap_or_else(|| {
            case.user
                .split_once('@')
                .map(|(local, _)| local.to_owned())
                .unwrap_or_default()
        });
        tests.push(AccessTest {
            source: format!("{source} entry {}", index + 1),
            user: case.user,
            groups: case.groups,
            username,
            target,
            expect: case.expect,
        });
    }
    tests
}
