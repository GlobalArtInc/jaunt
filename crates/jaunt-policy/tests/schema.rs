#![cfg(feature = "schema")]

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
    for name in ["RoleSpec", "AccessTestCase", "AdminPermission"] {
        assert!(definitions.contains_key(name), "{name} is missing");
    }
}
