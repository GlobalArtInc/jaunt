#![cfg(feature = "schema")]

use std::fs;
use std::path::Path;

use jaunt_policy::{policy_schema, policy_schema_pretty};
use serde_json::Value;

const ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: ops }\nspec:\n  members: { users: [alice@example.com], groups: [ops] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy, '{username}'], portForwarding: true, recordInput: false }\n  admin: [nodes.approve, sessions.read]\n";
const TESTS: &str = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: alice@example.com, groups: [ops], username: alice, node: { env: prod, name: web-1 }, login: deploy, expect: allow }\n";

fn instance(yaml: &str) -> Value {
    serde_saphyr::from_str(yaml).expect("example document must parse")
}

fn valid(validator: &jsonschema::Validator, yaml: &str) -> bool {
    validator.is_valid(&instance(yaml))
}

#[test]
fn schema_accepts_valid_documents_and_rejects_deviations() {
    let schema = policy_schema();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    let validator = jsonschema::validator_for(&schema).expect("schema must compile");

    assert!(valid(&validator, ROLE));
    assert!(valid(&validator, TESTS));
    assert!(valid(
        &validator,
        &ROLE.replace("sessions.read", "audit.read")
    ));
    let with_deny =
        format!("{ROLE}  deny: {{ ssh: {{ nodes: {{ name: [db-1] }}, logins: [root, '*'] }} }}\n");
    assert!(valid(&validator, &with_deny));
    assert!(valid(
        &validator,
        &ROLE.replace("'{username}'", "'u-{groups}'")
    ));

    let rejected = [
        ("unknown field", ROLE.replace("members:", "memberz:")),
        (
            "unknown nested field",
            ROLE.replace("portForwarding", "portForwardin"),
        ),
        (
            "unsupported apiVersion in a role",
            ROLE.replace("jaunt/v1", "jaunt/v2"),
        ),
        (
            "unsupported apiVersion in tests",
            TESTS.replace("jaunt/v1", "jaunt/v2"),
        ),
        ("unknown kind", ROLE.replace("kind: Role", "kind: Nope")),
        ("missing kind", ROLE.replace("kind: Role\n", "")),
        (
            "unknown admin permission",
            ROLE.replace("sessions.read", "sessions.write"),
        ),
        (
            "deny of an unknown kind",
            format!("{ROLE}  deny: {{ http: {{ services: {{ env: [prod] }} }} }}\n"),
        ),
        (
            "deny with an allow-only field",
            format!(
                "{ROLE}  deny: {{ ssh: {{ nodes: {{ env: [prod] }}, portForwarding: true }} }}\n"
            ),
        ),
        ("bad expectation", TESTS.replace("allow", "maybe")),
        (
            "test extra field",
            TESTS.replace("login:", "note: n, login:"),
        ),
    ];
    for (label, document) in rejected {
        assert!(!valid(&validator, &document), "{label} must be rejected");
    }
}

#[test]
fn schema_discriminates_by_kind_and_forbids_unknown_fields() {
    let schema = policy_schema();
    let one_of = schema["oneOf"].as_array().expect("oneOf over the kinds");
    assert_eq!(one_of.len(), 2);
    let text = schema.to_string();
    assert!(text.contains("\"additionalProperties\":false"));
}

#[test]
fn schema_output_is_deterministic_and_pretty() {
    let first = policy_schema_pretty();
    let second = policy_schema_pretty();
    assert_eq!(first, second);
    assert!(first.contains("\n  "));
    let parsed: Value = serde_json::from_str(&first).expect("output must be JSON");
    assert_eq!(parsed, policy_schema());
}

#[test]
fn schema_definitions_have_public_names() {
    let schema = policy_schema();
    let definitions = schema["$defs"].as_object().expect("definitions");
    assert!(definitions.keys().all(|name| !name.starts_with("Raw")));
    for name in [
        "RoleSpec",
        "RoleDeny",
        "RoleDenySsh",
        "RoleKubernetes",
        "RoleDatabases",
        "RoleTcp",
        "RoleDenyKubernetes",
        "RoleDenyDatabases",
        "AccessTestCase",
        "AccessTestKubernetes",
        "AccessTestDatabase",
        "AccessTestTcp",
        "AdminPermission",
    ] {
        assert!(definitions.contains_key(name), "{name} is missing");
    }
}

const SERVICES_ROLE: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: platform }\nspec:\n  members: { groups: [platform] }\n  kubernetes: { clusters: { env: [prod] }, groups: [view, 'oidc:{groups}'], users: ['{email}'], recordExec: true, recordInput: false }\n  databases: { servers: { env: [prod] }, users: [readonly, '{username}'], names: ['*'] }\n  tcp: { services: { team: [ops] } }\n  deny:\n    kubernetes: { clusters: { name: [prod-ru] }, groups: ['system:masters'] }\n    databases: { servers: { env: [prod] }, users: [postgres] }\n    tcp: { services: { name: [vault] } }\n";
const SERVICE_TESTS: &str = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  - { user: a@b.c, kubernetes: { cluster: { name: prod-eu, env: prod }, user: a@b.c, groups: [view] }, expect: allow }\n  - { user: a@b.c, database: { server: { name: lk, env: prod }, user: readonly, name: app }, grants: [], expect: allow }\n  - { user: a@b.c, tcp: { service: { name: grafana, team: ops } }, expect: allow }\n";

#[test]
fn schema_covers_the_service_blocks_and_one_target_per_access_test() {
    let validator = jsonschema::validator_for(&policy_schema()).expect("schema must compile");
    assert!(valid(&validator, SERVICES_ROLE));
    assert!(valid(&validator, SERVICE_TESTS));

    let tcp_case = "{ user: a@b.c, tcp: { service: { name: grafana, team: ops } }, expect: allow }";
    let rejected = [
        (
            "unknown kubernetes field",
            SERVICES_ROLE.replace("recordInput: false", "resources: [pods]"),
        ),
        (
            "deny with an allow-only kubernetes field",
            SERVICES_ROLE.replace(
                "groups: ['system:masters']",
                "groups: ['system:masters'], recordExec: false",
            ),
        ),
        (
            "non-empty grants",
            SERVICE_TESTS.replace("grants: []", "grants: [dba]"),
        ),
        (
            "two targets in one case",
            SERVICE_TESTS.replace(
                tcp_case,
                "{ user: a@b.c, tcp: { service: { name: g } }, node: { env: prod }, login: deploy, expect: allow }",
            ),
        ),
        (
            "node without login",
            SERVICE_TESTS.replace(tcp_case, "{ user: a@b.c, node: { env: prod }, expect: allow }"),
        ),
        (
            "no target",
            SERVICE_TESTS.replace(tcp_case, "{ user: a@b.c, expect: allow }"),
        ),
        (
            "database case without a name",
            SERVICE_TESTS.replace(", name: app }", " }"),
        ),
    ];
    for (label, document) in rejected {
        assert!(!valid(&validator, &document), "{label} must be rejected");
    }
}

fn yaml_documents(text: &str) -> Vec<Value> {
    serde_saphyr::from_multiple(text).expect("example file must parse")
}

#[test]
fn repository_example_policy_files_validate_against_the_schema() {
    let validator = jsonschema::validator_for(&policy_schema()).expect("schema must compile");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let files = [
        "deploy/policy/roles.example.yaml",
        "e2e/fixtures/policy/roles.yaml",
        "e2e/fixtures/policy/access-tests.yaml",
    ];
    for file in files {
        let text = fs::read_to_string(root.join(file)).expect("example file must exist");
        let documents = yaml_documents(&text);
        assert!(!documents.is_empty(), "{file} has no documents");
        for (index, document) in documents.iter().enumerate() {
            let errors: Vec<String> = validator
                .iter_errors(document)
                .map(|error| error.to_string())
                .collect();
            assert!(
                errors.is_empty(),
                "{file} document {}: {errors:?}",
                index + 1
            );
        }
    }
}
