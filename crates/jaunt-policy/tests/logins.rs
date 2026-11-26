mod common;

use std::fs;

use common::{load_err, load_ok, write_dir};
use jaunt_policy::{Expect, Identity, NodeInfo, PolicyHandle, PolicySet, run_access_tests};

const VALID: [&str; 10] = [
    "a",
    "_a",
    "a9",
    "a.b",
    "a-b",
    "a_b",
    "deploy",
    "svc.build-01",
    "alice",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
];

const INVALID: [&str; 27] = [
    "",
    "A9",
    "0abc",
    "Rozmarin",
    "aliCe",
    "ro\u{200b}ot",
    "\u{202e}toor",
    "-oProxyCommand=x",
    "-a",
    ".",
    "..",
    ".hidden",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "a@b",
    "\u{a0}",
    "a b",
    "a/b",
    "a:b",
    "a;b",
    "a'b",
    "a\"b",
    "\u{e9}",
    "a\n",
    "a\u{0}b",
    "a\\b",
    "a$b",
    "\u{ff21}",
];

fn yaml_quote(value: &str) -> String {
    let mut quoted = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ';' | ' ') => {
                quoted.push(c);
            }
            c => quoted.push_str(&format!("\\U{:08x}", u32::from(c))),
        }
    }
    quoted.push('"');
    quoted
}

fn role_with_logins(logins: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: r }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{logins}] }}\n"
    )
}

fn load_logins(logins: &str) -> PolicySet {
    load_ok(&[("a.yaml", &role_with_logins(logins))])
}

fn who(username: &str) -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: username.to_owned(),
        groups: Vec::new(),
    }
}

fn prod() -> NodeInfo {
    NodeInfo {
        name: "web-1".to_owned(),
        labels: [("env".to_owned(), "prod".to_owned())].into(),
    }
}

#[test]
fn policy_literals_must_match_the_login_grammar() {
    for login in VALID {
        let set = load_logins(&yaml_quote(login));
        assert!(
            set.authorize_ssh(&who("someone"), &prod(), login).allowed,
            "{login:?}"
        );
    }
    for login in INVALID {
        let errors = load_err(&[("a.yaml", &role_with_logins(&yaml_quote(login)))]);
        let rejected = errors.errors().iter().any(|e| {
            e.file == "a.yaml" && e.document == Some(1) && e.message.contains("not a valid login")
        });
        assert!(rejected, "{login:?}: {errors}");
    }
}

#[test]
fn substituted_usernames_must_match_the_login_grammar() {
    let set = load_logins("'{username}'");
    for login in VALID {
        let allowed = set.authorize_ssh(&who(login), &prod(), login).allowed;
        assert!(allowed, "{login:?}");
        assert!(set.route(&who(login), &prod()), "route {login:?}");
    }
    for login in INVALID {
        assert!(
            !set.authorize_ssh(&who(login), &prod(), login).allowed,
            "{login:?}"
        );
        assert!(!set.route(&who(login), &prod()), "route {login:?}");
    }
}

#[test]
fn substituted_root_is_ignored_while_a_literal_root_works() {
    let placeholder_only = load_logins("'{username}'");
    let root = who("root");
    assert!(
        !placeholder_only
            .authorize_ssh(&root, &prod(), "root")
            .allowed
    );
    assert!(!placeholder_only.route(&root, &prod()));
    assert!(
        placeholder_only
            .authorize_ssh(&who("alice"), &prod(), "alice")
            .allowed
    );

    let with_literal = load_logins("'{username}', root");
    assert!(with_literal.authorize_ssh(&root, &prod(), "root").allowed);
    assert!(with_literal.route(&root, &prod()));
    assert!(
        with_literal
            .authorize_ssh(&who("alice"), &prod(), "root")
            .allowed
    );
    assert!(
        with_literal
            .authorize_ssh(&who("alice"), &prod(), "alice")
            .allowed
    );

    let literal_only = load_logins("root");
    assert!(
        literal_only
            .authorize_ssh(&who("alice"), &prod(), "root")
            .allowed
    );
}

#[test]
fn a_role_with_a_literal_login_outside_the_grammar_is_refused_and_the_last_good_set_stays() {
    let dir = write_dir(&[("a.yaml", &role_with_logins("deploy"))]);
    let handle = PolicyHandle::empty();
    assert!(handle.reload(dir.path()).applied);
    let good_hash = handle.snapshot().hash().to_owned();

    fs::write(
        dir.path().join("a.yaml"),
        role_with_logins("deploy, Deploy"),
    )
    .unwrap();
    let rejected = handle.reload(dir.path());
    assert!(!rejected.applied);
    assert_eq!(
        rejected.errors,
        ["a.yaml: document 1: role \"r\": spec.ssh.logins[1] \"Deploy\" is not a valid login"]
    );
    let active = handle.snapshot();
    assert_eq!(active.hash(), good_hash);
    assert!(
        active
            .authorize_ssh(&who("alice"), &prod(), "deploy")
            .allowed
    );
    assert!(
        !active
            .authorize_ssh(&who("alice"), &prod(), "Deploy")
            .allowed
    );
}

#[test]
fn a_username_outside_the_grammar_yields_no_login_and_is_never_folded() {
    let set = load_logins("deploy, '{username}'");
    for (username, logins) in [
        ("alice", vec!["alice", "deploy"]),
        ("Alice", vec!["deploy"]),
        ("9lives", vec!["deploy"]),
    ] {
        assert_eq!(
            set.ssh_logins(&who(username), &prod()),
            logins,
            "{username:?}"
        );
    }

    let upper = who("Alice");
    for (login, allowed) in [("Alice", false), ("alice", false), ("deploy", true)] {
        assert_eq!(
            set.authorize_ssh(&upper, &prod(), login).allowed,
            allowed,
            "{login:?}"
        );
    }
    assert!(set.authorize_ssh(&who("alice"), &prod(), "alice").allowed);
}

#[test]
fn access_tests_see_the_same_rule_for_substituted_usernames() {
    let tests = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n  \
        - { user: alice@example.com, username: Alice, node: { env: prod }, login: Alice, expect: deny }\n  \
        - { user: alice@example.com, username: Alice, node: { env: prod }, login: alice, expect: deny }\n  \
        - { user: alice@example.com, username: alice, node: { env: prod }, login: alice, expect: allow }\n";
    let set = load_ok(&[
        ("a.yaml", &role_with_logins("'{username}'")),
        ("b.yaml", tests),
    ]);
    let expected = [Expect::Deny, Expect::Deny, Expect::Allow];
    assert_eq!(
        set.tests()
            .iter()
            .map(|case| case.expect)
            .collect::<Vec<_>>(),
        expected
    );
    let results = run_access_tests(&set);
    assert_eq!(results.len(), 3);
    for result in results {
        assert!(result.passed, "{}", result.description);
    }
}
