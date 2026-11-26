mod common;

use common::{load_err, load_ok};
use jaunt_policy::{Identity, NodeInfo, PolicySet, run_access_tests};

fn role_with_logins(logins: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: r }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{logins}] }}\n"
    )
}

fn load_logins(logins: &str) -> PolicySet {
    load_ok(&[("a.yaml", &role_with_logins(logins))])
}

fn who(username: &str, groups: &[&str]) -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: username.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

fn prod() -> NodeInfo {
    NodeInfo {
        name: "web-1".to_owned(),
        labels: [("env".to_owned(), "prod".to_owned())].into(),
    }
}

fn assert_logins(set: &PolicySet, identity: &Identity, expected: &[&str]) {
    let offered = set.ssh_logins(identity, &prod());
    assert_eq!(offered, expected, "{identity:?}");
    assert_eq!(set.route(identity, &prod()), !expected.is_empty());
    for login in expected {
        assert!(
            set.authorize_ssh(identity, &prod(), login).allowed,
            "{login}"
        );
    }
}

#[test]
fn groups_expand_to_one_login_per_valid_group() {
    let set = load_logins("'{groups}'");
    let cases: [(&[&str], &[&str]); 5] = [
        (&[], &[]),
        (&["ops"], &["ops"]),
        (&["ops", "dev", "web"], &["dev", "ops", "web"]),
        (&["ops", "Admins", "a b", "", "root", "/team"], &["ops"]),
        (&["ops", "ops"], &["ops"]),
    ];
    for (groups, expected) in cases {
        assert_logins(&set, &who("alice", groups), expected);
    }
}

#[test]
fn a_literal_prefix_is_kept_and_the_whole_value_is_checked() {
    let set = load_logins("'u-{username}', 'g.{groups}', 'r{username}'");
    let fits = "a".repeat(30);
    let fits_prefixed = [format!("r{fits}"), format!("u-{fits}")];
    let overflows = "a".repeat(32);
    let cases: [(&str, &[&str], Vec<&str>); 7] = [
        ("alice", &["ops"], vec!["g.ops", "ralice", "u-alice"]),
        ("oot", &[], vec!["u-oot"]),
        ("Alice", &["Ops"], vec![]),
        ("", &[""], vec![]),
        ("a b", &["x/y"], vec![]),
        (
            &fits,
            &[],
            fits_prefixed.iter().map(String::as_str).collect(),
        ),
        (&overflows, &[], vec![]),
    ];
    for (username, groups, expected) in cases {
        assert_logins(&set, &who(username, groups), &expected);
    }
}

#[test]
fn an_empty_trait_value_never_yields_the_bare_prefix() {
    let set = load_logins("'deploy{username}', 'deploy{groups}'");
    assert_logins(&set, &who("", &[""]), &[]);
    assert!(
        !set.authorize_ssh(&who("", &[""]), &prod(), "deploy")
            .allowed
    );
}

#[test]
fn the_email_trait_never_forms_a_login_and_traits_are_not_case_folded() {
    let email = load_logins("'{email}'");
    assert_logins(&email, &who("alice", &["ops"]), &[]);

    let username = load_logins("'{username}'");
    for (name, expected) in [
        ("alice", &["alice"][..]),
        ("ALICE", &[][..]),
        ("root", &[][..]),
    ] {
        assert_logins(&username, &who(name, &[]), expected);
    }
    assert!(
        !username
            .authorize_ssh(&who("ALICE", &[]), &prod(), "alice")
            .allowed
    );
}

#[test]
fn malformed_trait_forms_and_prefixes_are_rejected() {
    let too_long_prefix = format!("'{}{{username}}'", "a".repeat(32));
    let cases = [
        ("'{username}-x'", "a trait must be"),
        ("'{user}'", "a trait must be"),
        ("'{Username}'", "a trait must be"),
        ("'{username}{groups}'", "a trait must be"),
        ("'a{groups}b'", "a trait must be"),
        ("'{username'", "a trait must be"),
        ("'username}'", "a trait must be"),
        ("'{}'", "a trait must be"),
        ("'{ username }'", "a trait must be"),
        (
            "'U-{username}'",
            "the literal prefix cannot start a valid login",
        ),
        (
            "'1{username}'",
            "the literal prefix cannot start a valid login",
        ),
        (
            "'a b{username}'",
            "the literal prefix cannot start a valid login",
        ),
        (
            too_long_prefix.as_str(),
            "the literal prefix cannot start a valid login",
        ),
    ];
    for (logins, fragment) in cases {
        let errors = load_err(&[("a.yaml", &role_with_logins(logins))]);
        let found = errors.errors().iter().any(|error| {
            error.document == Some(1)
                && error.message.contains("spec.ssh.logins[0]")
                && error.message.contains(fragment)
        });
        assert!(found, "{logins}: expected {fragment:?} in\n{errors}");
    }
    let longest_prefix = format!("'{}{{username}}'", "a".repeat(31));
    load_logins(&longest_prefix);
}

#[test]
fn roles_reaching_show_traits_as_written() {
    let set = load_logins("deploy, '{username}', 'u-{email}', 'g_{groups}'");
    let reaching = set.roles_reaching(&prod());
    assert_eq!(reaching.len(), 1);
    assert_eq!(
        reaching[0].logins,
        ["deploy", "{username}", "u-{email}", "g_{groups}"]
    );
}

#[test]
fn access_tests_expand_traits_from_the_case_identity() {
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  \
        - { user: alice@example.com, groups: [ops, dev, web], node: { env: prod }, login: team-dev, expect: allow }\n  \
        - { user: alice@example.com, groups: [], node: { env: prod }, login: team-dev, expect: deny }\n  \
        - { user: alice@example.com, groups: [Dev], node: { env: prod }, login: team-dev, expect: deny }\n  \
        - { user: alice@example.com, username: carol, node: { env: prod }, login: u-carol, expect: allow }\n";
    let set = load_ok(&[
        (
            "a.yaml",
            &role_with_logins("'team-{groups}', 'u-{username}'"),
        ),
        ("b.yaml", tests),
    ]);
    let results = run_access_tests(&set);
    assert_eq!(results.len(), 4);
    for result in results {
        assert!(result.passed, "{}", result.description);
    }
}
