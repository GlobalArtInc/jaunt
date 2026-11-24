mod common;

use common::{load_err, load_ok};

const HEAD: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: r }\n";
const TESTS_HEAD: &str = "apiVersion: jaunt/v1\nkind: AccessTest\n";

fn role(spec: &str) -> String {
    format!("{HEAD}{spec}")
}

#[test]
fn baseline_documents_load() {
    let valid_role = role(
        "spec:\n  members: { users: [a@b.c] }\n  ssh: { nodes: { env: [prod] }, logins: [deploy] }\n",
    );
    let valid_tests = format!("{TESTS_HEAD}spec: []\n");
    let set = load_ok(&[("a.yaml", &valid_role), ("b.yaml", &valid_tests)]);
    assert!(set.tests().is_empty());
}

#[test]
fn structural_deviations_are_rejected_in_document_one() {
    let cases: Vec<(&str, String, &str)> = vec![
        (
            "members extra field",
            role("spec:\n  members: { users: [a@b.c], extra: 1 }\n"),
            "unknown field `extra`",
        ),
        (
            "metadata extra field",
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: r, labels: {} }\nspec: {}\n"
                .to_owned(),
            "unknown field `labels`",
        ),
        (
            "access test extra field next to spec",
            format!("{TESTS_HEAD}spec: []\nextra: 1\n"),
            "unknown field `extra`",
        ),
        (
            "access test metadata",
            format!("{TESTS_HEAD}metadata: {{ name: t }}\nspec: []\n"),
            "unknown field `metadata`",
        ),
        (
            "access test apiVersion",
            "apiVersion: jaunt/v2\nkind: AccessTest\nspec: []\n".to_owned(),
            "unsupported apiVersion",
        ),
        (
            "empty user",
            role("spec:\n  members: { users: [''] }\n"),
            "spec.members.users[0] must not be empty",
        ),
        (
            "empty group",
            role("spec:\n  members: { groups: [ops, ''] }\n"),
            "spec.members.groups[1] must not be empty",
        ),
        (
            "empty role name",
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: '' }\nspec: {}\n".to_owned(),
            "metadata.name",
        ),
        (
            "role name with a control character",
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: \"a\\nb\" }\nspec: {}\n"
                .to_owned(),
            "metadata.name",
        ),
        (
            "merge key",
            role("spec:\n  <<: { members: { users: [a@b.c] } }\n"),
            "merge keys",
        ),
        (
            "include tag",
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: !include other.yaml }\nspec: {}\n"
                .to_owned(),
            "unsupported tag",
        ),
        (
            "python object tag",
            "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: !!python/object r }\nspec: {}\n"
                .to_owned(),
            "unsupported tag",
        ),
        (
            "ssh without nodes",
            role("spec:\n  ssh: { logins: [deploy] }\n"),
            "spec.ssh.nodes is required",
        ),
        (
            "ssh with null nodes",
            role("spec:\n  ssh: { nodes: ~, logins: [deploy] }\n"),
            "spec.ssh.nodes is required",
        ),
        (
            "ssh without logins",
            role("spec:\n  ssh: { nodes: { env: [prod] } }\n"),
            "spec.ssh.logins must list at least one login",
        ),
        (
            "ssh with null logins",
            role("spec:\n  ssh: { nodes: { env: [prod] }, logins: ~ }\n"),
            "spec.ssh.logins must list at least one login",
        ),
        (
            "ssh with empty logins",
            role("spec:\n  ssh: { nodes: { env: [prod] }, logins: [] }\n"),
            "spec.ssh.logins must list at least one login",
        ),
        (
            "empty ssh block",
            role("spec:\n  ssh: {}\n"),
            "spec.ssh.nodes is required",
        ),
    ];
    for (label, content, fragment) in cases {
        let errors = load_err(&[("a.yaml", &content)]);
        let found = errors.errors().iter().any(|error| {
            error.file == "a.yaml" && error.document == Some(1) && error.message.contains(fragment)
        });
        assert!(found, "{label}: expected {fragment:?} in\n{errors}");
    }
}
