mod common;

use common::{load_err, load_ok};
use jaunt_policy::{AdminPermission, Identity, NodeInfo, PolicySet, SshDecision};

fn identity(email: &str, groups: &[&str]) -> Identity {
    let username = email.split('@').next().unwrap_or_default();
    identity_named(email, username, groups)
}

fn identity_named(email: &str, username: &str, groups: &[&str]) -> Identity {
    Identity {
        email: email.to_owned(),
        username: username.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

fn node(labels: &[(&str, &str)]) -> NodeInfo {
    NodeInfo {
        name: "node-1".to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn role(name: &str, members: Option<&str>, ssh: &str, admin: &str) -> String {
    let members = members.map_or(String::new(), |m| format!("  members: {m}\n"));
    let ssh = if ssh.is_empty() {
        String::new()
    } else {
        format!("  ssh: {ssh}\n")
    };
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n{members}{ssh}  admin: {admin}\n"
    )
}

fn load_roles(roles: &[String]) -> PolicySet {
    load_ok(&[("roles.yaml", &roles.join("---\n"))])
}

fn allowed(set: &PolicySet, who: &Identity, target: &NodeInfo, login: &str) -> bool {
    set.authorize_ssh(who, target, login).allowed
}

const ALICE: &str = "alice@example.com";

fn alice_role(ssh: &str) -> PolicySet {
    load_roles(&[role("r", Some("{ users: [alice@example.com] }"), ssh, "[]")])
}

#[test]
fn everything_is_denied_by_default() {
    let populated = load_roles(&[role(
        "ops",
        Some("{ users: [alice@example.com] }"),
        "{ nodes: { env: [prod] }, logins: [deploy] }",
        "[sessions.read]",
    )]);
    let without_members = load_roles(&[role(
        "orphan",
        None,
        "{ nodes: { env: [prod] }, logins: [deploy] }",
        "[sessions.read]",
    )]);
    let sets = [
        ("empty", load_ok(&[])),
        ("populated", populated.clone()),
        ("without members", without_members),
    ];
    let target = node(&[("env", "prod")]);
    let outsider = identity("mallory@example.com", &["nobody"]);
    let member = identity(ALICE, &[]);
    for (label, set) in &sets {
        assert!(!set.route(&outsider, &target), "{label}: route");
        assert_eq!(
            set.authorize_ssh(&outsider, &target, "deploy"),
            SshDecision::default(),
            "{label}: authorize"
        );
        for permission in AdminPermission::ALL {
            assert!(!set.admin_can(&outsider, permission), "{label}: admin");
        }
    }
    assert!(populated.route(&member, &target));
    assert!(!sets[0].1.route(&member, &target));
    assert!(!sets[2].1.route(&member, &target));
}

#[test]
fn selector_requires_every_key() {
    let set = alice_role("{ nodes: { env: [prod], team: [core] }, logins: [deploy] }");
    let who = identity(ALICE, &[]);
    let cases = [
        (vec![("env", "prod"), ("team", "core")], true),
        (
            vec![("env", "prod"), ("team", "core"), ("extra", "x")],
            true,
        ),
        (vec![("env", "prod")], false),
        (vec![("env", "prod"), ("team", "other")], false),
        (vec![("env", "staging"), ("team", "core")], false),
        (vec![], false),
    ];
    for (labels, expected) in cases {
        let target = node(&labels);
        assert_eq!(
            allowed(&set, &who, &target, "deploy"),
            expected,
            "{labels:?}"
        );
    }
}

#[test]
fn selector_accepts_any_listed_value() {
    let set = alice_role("{ nodes: { env: [prod, staging] }, logins: [deploy] }");
    let who = identity(ALICE, &[]);
    let cases = [
        ("prod", true),
        ("staging", true),
        ("dev", false),
        ("production", false),
        ("prod-eu", false),
        ("pro", false),
        ("Prod", false),
        ("", false),
    ];
    for (value, expected) in cases {
        let target = node(&[("env", value)]);
        assert_eq!(
            allowed(&set, &who, &target, "deploy"),
            expected,
            "{value:?}"
        );
    }
}

#[test]
fn wildcard_requires_the_label_to_exist() {
    let set = alice_role("{ nodes: { team: ['*'] }, logins: [deploy] }");
    let who = identity(ALICE, &[]);
    let cases = [
        (vec![("team", "core")], true),
        (vec![("team", "")], true),
        (vec![("team", "*")], true),
        (vec![("env", "prod")], false),
        (vec![], false),
    ];
    for (labels, expected) in cases {
        let target = node(&labels);
        assert_eq!(
            allowed(&set, &who, &target, "deploy"),
            expected,
            "{labels:?}"
        );
        assert_eq!(set.route(&who, &target), expected, "route {labels:?}");
    }
}

#[test]
fn node_without_the_labelled_key_never_matches() {
    let set = alice_role("{ nodes: { env: [prod], team: ['*'] }, logins: [deploy] }");
    let who = identity(ALICE, &[]);
    let cases = [
        (vec![("env", "prod")], false),
        (vec![("team", "core")], false),
        (vec![("env", "prod"), ("team", "core")], true),
    ];
    for (labels, expected) in cases {
        let target = node(&labels);
        assert_eq!(
            allowed(&set, &who, &target, "deploy"),
            expected,
            "{labels:?}"
        );
    }
}

#[test]
fn membership_by_group_or_email_is_exact() {
    let set = load_roles(&[role(
        "r",
        Some("{ groups: [infra-admins], users: [alice@example.com] }"),
        "{ nodes: { env: ['*'] }, logins: [deploy] }",
        "[]",
    )]);
    let target = node(&[("env", "prod")]);
    let cases = [
        (identity("alice@example.com", &[]), true),
        (identity("bob@example.com", &["infra-admins"]), true),
        (identity("bob@example.com", &["dev", "infra-admins"]), true),
        (identity("Alice@example.com", &[]), false),
        (identity("alice@example.com.evil", &[]), false),
        (identity("bob@example.com", &["Infra-Admins"]), false),
        (identity("bob@example.com", &["infra-admin"]), false),
        (identity("bob@example.com", &[]), false),
        (identity("", &[""]), false),
    ];
    for (who, expected) in cases {
        assert_eq!(allowed(&set, &who, &target, "deploy"), expected, "{who:?}");
    }
}

#[test]
fn logins_are_literal_or_the_username_placeholder() {
    let set = alice_role("{ nodes: { env: [prod] }, logins: [deploy, '{username}'] }");
    let target = node(&[("env", "prod")]);
    let alice = identity(ALICE, &[]);
    let cases = [
        ("deploy", true),
        ("alice", true),
        ("root", false),
        ("Deploy", false),
        ("", false),
        ("{username}", false),
    ];
    for (login, expected) in cases {
        assert_eq!(allowed(&set, &alice, &target, login), expected, "{login:?}");
    }
    let renamed = identity_named(ALICE, "ally", &[]);
    assert!(allowed(&set, &renamed, &target, "ally"));
    assert!(!allowed(&set, &renamed, &target, "alice"));
}

#[test]
fn invalid_substituted_login_is_ignored() {
    let only_username = alice_role("{ nodes: { env: [prod] }, logins: ['{username}'] }");
    let with_literal = alice_role("{ nodes: { env: [prod] }, logins: ['{username}', deploy] }");
    let target = node(&[("env", "prod")]);
    for bad in ["", "a b", "a:b", "a/b", "a\tb", "a\nb", "a\u{0}b", " "] {
        let who = identity_named(ALICE, bad, &[]);
        assert!(!allowed(&only_username, &who, &target, bad), "{bad:?}");
        assert!(!only_username.route(&who, &target), "route {bad:?}");
        assert!(!allowed(&with_literal, &who, &target, bad), "{bad:?}");
        assert!(with_literal.route(&who, &target), "route literal {bad:?}");
        assert!(allowed(&with_literal, &who, &target, "deploy"), "{bad:?}");
    }
}

#[test]
fn roles_do_not_combine_node_and_login() {
    let set = load_roles(&[
        role(
            "prod-deploy",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [prod] }, logins: [deploy] }",
            "[]",
        ),
        role(
            "staging-root",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [staging] }, logins: [root] }",
            "[]",
        ),
    ]);
    let who = identity(ALICE, &[]);
    let prod = node(&[("env", "prod")]);
    let staging = node(&[("env", "staging")]);
    let cases = [
        (&prod, "deploy", Some("prod-deploy")),
        (&staging, "root", Some("staging-root")),
        (&prod, "root", None),
        (&staging, "deploy", None),
    ];
    for (target, login, expected_role) in cases {
        let decision = set.authorize_ssh(&who, target, login);
        assert_eq!(decision.allowed, expected_role.is_some(), "{login}");
        let roles: Vec<&str> = decision.roles.iter().map(String::as_str).collect();
        assert_eq!(
            roles,
            expected_role.into_iter().collect::<Vec<_>>(),
            "{login}"
        );
    }
}

#[test]
fn port_forwarding_and_input_recording_need_one_matching_role() {
    let set = load_roles(&[
        role(
            "b-forward",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [prod] }, logins: [deploy], portForwarding: true }",
            "[]",
        ),
        role(
            "a-record",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [prod] }, logins: [deploy], recordInput: true }",
            "[]",
        ),
        role(
            "c-plain",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [prod] }, logins: [deploy] }",
            "[]",
        ),
        role(
            "d-elsewhere",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [dev] }, logins: [deploy], portForwarding: true, recordInput: true }",
            "[]",
        ),
        role(
            "e-other-user",
            Some("{ users: [bob@example.com] }"),
            "{ nodes: { env: [dev] }, logins: [root], portForwarding: true, recordInput: true }",
            "[]",
        ),
    ]);
    let alice = identity(ALICE, &[]);

    let all = set.authorize_ssh(&alice, &node(&[("env", "prod")]), "deploy");
    assert!(all.allowed && all.port_forwarding && all.record_input);
    assert_eq!(all.roles, ["a-record", "b-forward", "c-plain"]);

    let dev = set.authorize_ssh(&alice, &node(&[("env", "dev")]), "deploy");
    assert!(dev.allowed && dev.port_forwarding && dev.record_input);
    assert_eq!(dev.roles, ["d-elsewhere"]);

    let plain_only = load_roles(&[role(
        "c-plain",
        Some("{ users: [alice@example.com] }"),
        "{ nodes: { env: [prod] }, logins: [deploy] }",
        "[]",
    )]);
    let decision = plain_only.authorize_ssh(&alice, &node(&[("env", "prod")]), "deploy");
    assert!(decision.allowed && !decision.port_forwarding && !decision.record_input);

    let denied = set.authorize_ssh(&alice, &node(&[("env", "prod")]), "root");
    assert_eq!(denied, SshDecision::default());
}

#[test]
fn admin_permissions_are_the_union_of_applicable_roles() {
    let set = load_roles(&[
        role(
            "readers",
            Some("{ groups: [readers] }"),
            "",
            "[sessions.read, recordings.read]",
        ),
        role(
            "approvers",
            Some("{ users: [alice@example.com] }"),
            "",
            "[nodes.approve]",
        ),
        role("nobody", None, "", "[revocations.write]"),
        role(
            "auditors",
            Some("{ groups: [auditors] }"),
            "",
            "[audit.read]",
        ),
    ]);
    let cases = [
        (
            identity(ALICE, &["readers"]),
            [true, true, true, false, false],
        ),
        (identity(ALICE, &[]), [true, false, false, false, false]),
        (
            identity("bob@example.com", &["readers"]),
            [false, true, true, false, false],
        ),
        (
            identity("bob@example.com", &[]),
            [false, false, false, false, false],
        ),
        (
            identity("bob@example.com", &["auditors"]),
            [false, false, false, false, true],
        ),
    ];
    for (who, expected) in cases {
        let actual = AdminPermission::ALL.map(|permission| set.admin_can(&who, permission));
        assert_eq!(actual, expected, "{who:?}");
    }
}

#[test]
fn admin_permission_round_trips_and_rejects_unknown_values() {
    for permission in AdminPermission::ALL {
        assert_eq!(
            permission.as_str().parse::<AdminPermission>(),
            Ok(permission)
        );
        assert_eq!(permission.to_string(), permission.as_str());
    }
    for bad in [
        "",
        "nodes.delete",
        "Nodes.Approve",
        " sessions.read",
        "sessions.*",
        "admin",
    ] {
        assert!(bad.parse::<AdminPermission>().is_err(), "{bad:?}");
    }
    let rejected = load_err(&[(
        "roles.yaml",
        &role(
            "r",
            Some("{ users: [alice@example.com] }"),
            "",
            "[sessions.read, nodes.delete]",
        ),
    )]);
    assert!(
        rejected
            .to_string()
            .contains("unknown admin permission `nodes.delete`"),
        "{rejected}"
    );
}

#[test]
fn route_agrees_with_authorize_ssh() {
    let set = load_roles(&[
        role(
            "wide",
            Some("{ groups: [ops] }"),
            "{ nodes: { env: [prod, staging] }, logins: [deploy, '{username}'] }",
            "[]",
        ),
        role(
            "narrow",
            Some("{ users: [carol@example.com] }"),
            "{ nodes: { env: [prod], team: ['*'] }, logins: ['{username}'] }",
            "[]",
        ),
        role("silent", Some("{ groups: [ops] }"), "", "[sessions.read]"),
    ]);
    let identities = [
        identity("alice@example.com", &["ops"]),
        identity("carol@example.com", &[]),
        identity_named("carol@example.com", "a b", &[]),
        identity_named("dave@example.com", "", &["ops"]),
        identity("eve@example.com", &[]),
    ];
    let nodes = [
        node(&[("env", "prod")]),
        node(&[("env", "prod"), ("team", "core")]),
        node(&[("env", "staging")]),
        node(&[("env", "dev")]),
        node(&[]),
    ];
    let logins = ["deploy", "alice", "carol", "dave", "root", "a b", ""];
    for who in &identities {
        for target in &nodes {
            let any_login = logins
                .iter()
                .any(|login| set.authorize_ssh(who, target, login).allowed);
            assert_eq!(set.route(who, target), any_login, "{who:?} {target:?}");
        }
    }
}
