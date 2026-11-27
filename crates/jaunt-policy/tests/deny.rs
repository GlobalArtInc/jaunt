mod common;

use common::{load_err, load_ok};
use jaunt_policy::{Identity, NodeInfo, PolicySet, SshDecision, run_access_tests};

const LOGINS: [&str; 4] = ["deploy", "root", "alice", "app"];

fn role(name: &str, members: &str, body: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  members: {members}\n{body}"
    )
}

fn alice() -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: "alice".to_owned(),
        groups: vec!["ops".to_owned()],
    }
}

fn node(name: &str, env: &str) -> NodeInfo {
    NodeInfo {
        name: name.to_owned(),
        labels: [("env".to_owned(), env.to_owned())].into(),
    }
}

const WIDE_ALLOW: &str =
    "  ssh: { nodes: { env: ['*'] }, logins: [deploy, root, '{username}', app] }\n";

fn with_deny(deny: &str) -> PolicySet {
    load_ok(&[(
        "roles.yaml",
        &[
            role("wide", "{ groups: [ops] }", WIDE_ALLOW),
            role("limits", "{ groups: [ops] }", &format!("  deny: {deny}\n")),
        ]
        .join("---\n"),
    )])
}

fn allowed_logins(set: &PolicySet, target: &NodeInfo) -> Vec<&'static str> {
    LOGINS
        .into_iter()
        .filter(|login| set.authorize_ssh(&alice(), target, login).allowed)
        .collect()
}

#[test]
fn an_ssh_deny_matches_the_node_selector_and_the_listed_logins() {
    let prod = node("web-1", "prod");
    let dev = node("dev-1", "dev");
    let cases: [(&str, &str, &[&str], &[&str]); 7] = [
        (
            "no logins key denies every login",
            "{ ssh: { nodes: { env: [prod] } } }",
            &[],
            &["deploy", "root", "alice", "app"],
        ),
        (
            "listed login",
            "{ ssh: { nodes: { env: [prod] }, logins: [root] } }",
            &["deploy", "alice", "app"],
            &["deploy", "root", "alice", "app"],
        ),
        (
            "several listed logins",
            "{ ssh: { nodes: { env: [prod] }, logins: [root, alice] } }",
            &["deploy", "app"],
            &["deploy", "root", "alice", "app"],
        ),
        (
            "star denies every login",
            "{ ssh: { nodes: { env: [prod] }, logins: ['*'] } }",
            &[],
            &["deploy", "root", "alice", "app"],
        ),
        (
            "star next to a login",
            "{ ssh: { nodes: { env: [prod] }, logins: [root, '*'] } }",
            &[],
            &["deploy", "root", "alice", "app"],
        ),
        (
            "wildcard selector",
            "{ ssh: { nodes: { env: ['*'] }, logins: [root] } }",
            &["deploy", "alice", "app"],
            &["deploy", "alice", "app"],
        ),
        (
            "selector on a missing label",
            "{ ssh: { nodes: { team: ['*'] } } }",
            &["deploy", "root", "alice", "app"],
            &["deploy", "root", "alice", "app"],
        ),
    ];
    for (label, deny, on_prod, on_dev) in cases {
        let set = with_deny(deny);
        assert_eq!(allowed_logins(&set, &prod), on_prod, "{label}: prod");
        assert_eq!(allowed_logins(&set, &dev), on_dev, "{label}: dev");
        for target in [&prod, &dev] {
            let offered = set.ssh_logins(&alice(), target);
            let expected: Vec<&str> = {
                let mut logins = allowed_logins(&set, target);
                logins.sort_unstable();
                logins
            };
            assert_eq!(offered, expected, "{label}: terminal logins");
            assert_eq!(
                set.route(&alice(), target),
                !expected.is_empty(),
                "{label}: route"
            );
        }
    }
}

#[test]
fn a_denied_login_yields_the_empty_decision() {
    let set = with_deny("{ ssh: { nodes: { env: [prod] }, logins: [root] } }");
    let decision = set.authorize_ssh(&alice(), &node("web-1", "prod"), "root");
    assert_eq!(decision, SshDecision::default());
}

#[test]
fn deny_beats_allow_regardless_of_role_order_and_file() {
    let allow = role("allow", "{ groups: [ops] }", WIDE_ALLOW);
    let deny = role(
        "deny",
        "{ users: [alice@example.com] }",
        "  deny: { ssh: { nodes: { env: [prod] }, logins: [root] } }\n",
    );
    let same_role = role(
        "both",
        "{ groups: [ops] }",
        &format!("{WIDE_ALLOW}  deny: {{ ssh: {{ nodes: {{ env: [prod] }}, logins: [root] }} }}\n"),
    );
    let layouts: Vec<Vec<(&str, String)>> = vec![
        vec![("a.yaml", format!("{allow}---\n{deny}"))],
        vec![("a.yaml", format!("{deny}---\n{allow}"))],
        vec![("a.yaml", allow.clone()), ("b.yaml", deny.clone())],
        vec![("a.yaml", deny.clone()), ("b.yaml", allow.clone())],
        vec![("a.yaml", same_role)],
    ];
    for (index, files) in layouts.iter().enumerate() {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, content)| (*name, content.as_str()))
            .collect();
        let set = load_ok(&files);
        let prod = node("web-1", "prod");
        assert!(
            !set.authorize_ssh(&alice(), &prod, "root").allowed,
            "{index}"
        );
        assert!(
            set.authorize_ssh(&alice(), &prod, "deploy").allowed,
            "{index}"
        );
        assert!(
            set.authorize_ssh(&alice(), &node("dev-1", "dev"), "root")
                .allowed,
            "{index}"
        );
        assert!(
            !set.ssh_logins(&alice(), &prod).contains(&"root".to_owned()),
            "{index}"
        );
    }
}

#[test]
fn deny_rules_of_several_roles_add_up_in_any_order_and_file() {
    let allow = role("wide", "{ groups: [ops] }", WIDE_ALLOW);
    let deny_root = role(
        "a",
        "{ groups: [ops] }",
        "  deny: { ssh: { nodes: { env: [prod] }, logins: [root] } }\n",
    );
    let deny_alice = role(
        "b",
        "{ users: [alice@example.com] }",
        "  deny: { ssh: { nodes: { env: [prod] }, logins: [alice] } }\n",
    );
    let joined = |parts: [&String; 3]| {
        parts
            .iter()
            .map(|part| part.as_str())
            .collect::<Vec<_>>()
            .join("---\n")
    };
    let layouts: Vec<Vec<(&str, String)>> = vec![
        vec![("a.yaml", joined([&allow, &deny_root, &deny_alice]))],
        vec![("a.yaml", joined([&deny_alice, &deny_root, &allow]))],
        vec![("a.yaml", joined([&deny_root, &allow, &deny_alice]))],
        vec![
            ("a.yaml", deny_root.clone()),
            ("b.yaml", deny_alice.clone()),
            ("c.yaml", allow.clone()),
        ],
        vec![
            ("a.yaml", deny_alice.clone()),
            ("b.yaml", allow.clone()),
            ("c.yaml", deny_root.clone()),
        ],
    ];
    let prod = node("web-1", "prod");
    let dev = node("dev-1", "dev");
    for (index, files) in layouts.iter().enumerate() {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, content)| (*name, content.as_str()))
            .collect();
        let set = load_ok(&files);
        assert_eq!(allowed_logins(&set, &prod), ["deploy", "app"], "{index}");
        assert_eq!(
            set.ssh_logins(&alice(), &prod),
            ["app", "deploy"],
            "{index}"
        );
        assert!(set.route(&alice(), &prod), "{index}");
        assert_eq!(allowed_logins(&set, &dev), LOGINS, "{index}");
    }
}

#[test]
fn a_deny_applies_only_to_members_of_its_role() {
    let set = load_ok(&[(
        "roles.yaml",
        &[
            role("wide", "{ groups: [ops, dev] }", WIDE_ALLOW),
            role(
                "ops-limits",
                "{ groups: [ops] }",
                "  deny: { ssh: { nodes: { env: [prod] } } }\n",
            ),
            role(
                "orphan-limits",
                "{}",
                "  deny: { ssh: { nodes: { env: ['*'] } } }\n",
            ),
        ]
        .join("---\n"),
    )]);
    let prod = node("web-1", "prod");
    let developer = Identity {
        email: "bob@example.com".to_owned(),
        username: "bob".to_owned(),
        groups: vec!["dev".to_owned()],
    };
    assert!(!set.route(&alice(), &prod));
    assert!(set.route(&developer, &prod));
    assert!(set.authorize_ssh(&developer, &prod, "deploy").allowed);
}

#[test]
fn ssh_deny_rules_are_validated_and_unknown_kinds_are_rejected() {
    let cases = [
        (
            "{ ssh: { logins: [root] } }",
            "role \"r\": spec.deny.ssh.nodes is required when spec.deny.ssh is set",
        ),
        (
            "{ ssh: { nodes: {}, logins: [root] } }",
            "role \"r\": spec.deny.ssh.nodes selector must not be empty",
        ),
        (
            "{ ssh: { nodes: { env: [] } } }",
            "role \"r\": spec.deny.ssh.nodes.env must list at least one value",
        ),
        (
            "{ ssh: { nodes: { env: [prod] }, logins: [] } }",
            "role \"r\": spec.deny.ssh.logins must list at least one login",
        ),
        (
            "{ ssh: { nodes: { env: [prod] }, logins: ['{username}'] } }",
            "not traits",
        ),
        (
            "{ ssh: { nodes: { env: [prod] }, logins: ['x{groups}'] } }",
            "not traits",
        ),
        (
            "{ ssh: { nodes: { env: [prod] }, logins: [Root] } }",
            "role \"r\": spec.deny.ssh.logins[0] \"Root\" is not a valid login",
        ),
        (
            "{ ssh: { nodes: { env: [prod] }, logins: [root], portForwarding: true } }",
            "unknown field `portForwarding`",
        ),
        (
            "{ http: { services: { env: [prod] } } }",
            "unknown field `http`",
        ),
    ];
    for (deny, fragment) in cases {
        let content = role("r", "{ groups: [ops] }", &format!("  deny: {deny}\n"));
        let errors = load_err(&[("a.yaml", &content)]);
        let found = errors.errors().iter().any(|error| {
            error.file == "a.yaml" && error.document == Some(1) && error.message.contains(fragment)
        });
        assert!(found, "{deny}: expected {fragment:?} in\n{errors}");
    }
}

#[test]
fn access_tests_see_deny_rules() {
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  \
        - { user: alice@example.com, groups: [ops], node: { name: web-1, env: prod }, login: root, expect: deny }\n  \
        - { user: alice@example.com, groups: [ops], node: { name: web-1, env: prod }, login: deploy, expect: allow }\n  \
        - { user: alice@example.com, groups: [ops], node: { name: dev-1, env: dev }, login: root, expect: allow }\n";
    let set = load_ok(&[
        (
            "a.yaml",
            &[
                role("wide", "{ groups: [ops] }", WIDE_ALLOW),
                role(
                    "limits",
                    "{ groups: [ops] }",
                    "  deny: { ssh: { nodes: { env: [prod] }, logins: [root] } }\n",
                ),
            ]
            .join("---\n"),
        ),
        ("b.yaml", tests),
    ]);
    let results = run_access_tests(&set);
    assert_eq!(results.len(), 3);
    for result in results {
        assert!(result.passed, "{}", result.description);
    }
}
