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

fn named(name: &str, labels: &[(&str, &str)]) -> NodeInfo {
    NodeInfo {
        name: name.to_owned(),
        ..node(labels)
    }
}

#[test]
fn the_name_pseudo_label_matches_the_node_name_and_a_real_label_cannot_forge_it() {
    let set = alice_role("{ nodes: { name: [web-1, web-2], env: [prod] }, logins: [deploy] }");
    let any_name = alice_role("{ nodes: { name: ['*'] }, logins: [deploy] }");
    let who = identity(ALICE, &[]);
    let cases = [
        (named("web-1", &[("env", "prod")]), true),
        (named("web-2", &[("env", "prod")]), true),
        (named("web-3", &[("env", "prod")]), false),
        (named("Web-1", &[("env", "prod")]), false),
        (named("web-1", &[]), false),
        (named("web-3", &[("env", "prod"), ("name", "web-1")]), false),
        (named("web-1", &[("env", "prod"), ("name", "web-3")]), true),
    ];
    for (target, expected) in cases {
        assert_eq!(
            allowed(&set, &who, &target, "deploy"),
            expected,
            "{target:?}"
        );
        assert_eq!(set.route(&who, &target), expected, "route {target:?}");
        assert!(allowed(&any_name, &who, &target, "deploy"), "{target:?}");
    }

    let denied_by_name = load_roles(&[
        role(
            "wide",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: ['*'] }, logins: [deploy] }",
            "[]",
        ),
        format!(
            "{}  deny: {{ ssh: {{ nodes: {{ name: [db-1] }} }} }}\n",
            role("limits", Some("{ users: [alice@example.com] }"), "", "[]")
        ),
    ]);
    for (target, expected) in [
        (named("db-1", &[("env", "prod")]), false),
        (named("db-1", &[("env", "prod"), ("name", "web-1")]), false),
        (named("web-1", &[("env", "prod"), ("name", "db-1")]), true),
    ] {
        assert_eq!(
            allowed(&denied_by_name, &who, &target, "deploy"),
            expected,
            "{target:?}"
        );
    }
}

#[test]
fn access_tests_use_the_name_key_as_the_node_name() {
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  \
        - { user: alice@example.com, node: { name: web-1, env: prod }, login: deploy, expect: allow }\n  \
        - { user: alice@example.com, node: { name: web-2, env: prod }, login: deploy, expect: deny }\n  \
        - { user: alice@example.com, node: { env: prod }, login: deploy, expect: deny }\n";
    let set = load_ok(&[
        (
            "a.yaml",
            &role(
                "r",
                Some("{ users: [alice@example.com] }"),
                "{ nodes: { name: [web-1] }, logins: [deploy] }",
                "[]",
            ),
        ),
        ("b.yaml", tests),
    ]);
    let results = jaunt_policy::run_access_tests(&set);
    assert_eq!(results.len(), 3);
    for result in results {
        assert!(result.passed, "{}", result.description);
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

#[test]
fn roles_reaching_a_node_are_listed_with_their_subjects_logins_and_flags() {
    let set = load_ok(&[(
        "roles.yaml",
        &[
            role(
                "prod-ops",
                Some("{ users: [alice@example.com], groups: [infra] }"),
                "{ nodes: { env: [prod], team: [\"*\"] }, logins: [deploy, \"{username}\"], portForwarding: true }",
                "[nodes.approve]",
            ),
            role(
                "web-deploy",
                Some("{ groups: [web] }"),
                "{ nodes: { env: [prod, staging] }, logins: [deploy], recordInput: true }",
                "[]",
            ),
            role(
                "dev-only",
                Some("{ groups: [dev] }"),
                "{ nodes: { env: [dev] }, logins: [dev] }",
                "[]",
            ),
            role(
                "auditors",
                Some("{ groups: [audit] }"),
                "",
                "[audit.read]",
            ),
        ]
        .join("---\n"),
    )]);

    let reaching = set.roles_reaching(&node(&[("env", "prod"), ("team", "web")]));

    let names: Vec<&str> = reaching.iter().map(|role| role.role.as_str()).collect();
    assert_eq!(names, ["prod-ops", "web-deploy"]);
    assert_eq!(reaching[0].users, ["alice@example.com"]);
    assert_eq!(reaching[0].groups, ["infra"]);
    assert_eq!(reaching[0].logins, ["deploy", "{username}"]);
    assert!(reaching[0].port_forwarding && !reaching[0].record_input);
    assert_eq!(reaching[0].admin, [AdminPermission::NodesApprove]);
    assert!(reaching[1].users.is_empty());
    assert_eq!(reaching[1].groups, ["web"]);
    assert!(!reaching[1].port_forwarding && reaching[1].record_input);
    assert!(reaching[1].admin.is_empty());

    assert!(set.roles_reaching(&node(&[("env", "qa")])).is_empty());
    assert!(set.roles_reaching(&node(&[("env", "prod")])).len() == 1);
}

fn terminal_policy() -> PolicySet {
    load_roles(&[
        role(
            "ops",
            Some("{ groups: [ops] }"),
            "{ nodes: { env: [prod] }, logins: [deploy, \"{username}\"] }",
            "[]",
        ),
        role(
            "dev",
            Some("{ users: [alice@example.com] }"),
            "{ nodes: { env: [prod, dev] }, logins: [deploy, app] }",
            "[]",
        ),
        role(
            "admins",
            Some("{ users: [alice@example.com] }"),
            "",
            "[nodes.approve]",
        ),
    ])
}

#[test]
fn terminal_logins_of_every_role_reaching_a_node_are_merged_sorted_and_unique() {
    let alice = identity_named(ALICE, "alice", &["ops"]);
    let set = terminal_policy();
    assert_eq!(
        set.ssh_logins(&alice, &node(&[("env", "prod")])),
        ["alice", "app", "deploy"]
    );
    assert_eq!(
        set.ssh_logins(&alice, &node(&[("env", "dev")])),
        ["app", "deploy"]
    );
}

#[test]
fn terminal_logins_expand_the_username_and_never_offer_a_root_username() {
    let set = terminal_policy();
    let bob = identity_named("bob@example.com", "bob", &["ops"]);
    assert_eq!(
        set.ssh_logins(&bob, &node(&[("env", "prod")])),
        ["bob", "deploy"]
    );
    let root = identity_named("root@example.com", "root", &["ops"]);
    assert_eq!(set.ssh_logins(&root, &node(&[("env", "prod")])), ["deploy"]);
}

#[test]
fn a_role_without_an_ssh_block_offers_no_terminal_and_every_ssh_role_offers_a_pty() {
    let admins_only = load_roles(&[role(
        "admins",
        Some("{ users: [alice@example.com] }"),
        "",
        "[nodes.approve]",
    )]);
    let alice = identity_named(ALICE, "alice", &[]);
    assert!(
        admins_only
            .ssh_logins(&alice, &node(&[("env", "prod")]))
            .is_empty()
    );
    assert!(
        !terminal_policy()
            .ssh_logins(&alice, &node(&[("env", "dev")]))
            .is_empty()
    );
}

#[test]
fn no_role_means_no_terminal_login_and_unmatched_nodes_offer_nothing() {
    let set = terminal_policy();
    let carol = identity_named("carol@example.com", "carol", &[]);
    assert!(set.ssh_logins(&carol, &node(&[("env", "prod")])).is_empty());
    let bob = identity_named("bob@example.com", "bob", &["ops"]);
    assert!(set.ssh_logins(&bob, &node(&[("env", "dev")])).is_empty());
    assert!(
        PolicySet::empty()
            .ssh_logins(&bob, &node(&[("env", "prod")]))
            .is_empty()
    );
}

#[test]
fn every_terminal_login_is_one_authorize_allows_and_route_agrees() {
    let set = terminal_policy();
    for who in [
        identity_named(ALICE, "alice", &["ops"]),
        identity_named("bob@example.com", "bob", &["ops"]),
        identity_named("carol@example.com", "carol", &[]),
    ] {
        for target in [node(&[("env", "prod")]), node(&[("env", "dev")])] {
            let logins = set.ssh_logins(&who, &target);
            assert_eq!(set.route(&who, &target), !logins.is_empty());
            for login in &logins {
                assert!(allowed(&set, &who, &target, login), "{login}");
            }
            for other in ["root", "nobody", "carol"] {
                if !logins.iter().any(|login| login == other) {
                    assert!(!allowed(&set, &who, &target, other), "{other}");
                }
            }
        }
    }
}
