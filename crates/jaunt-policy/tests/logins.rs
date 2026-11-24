mod common;

use common::{load_err, load_ok};
use jaunt_policy::{Identity, NodeInfo, PolicySet};

const VALID: [&str; 11] = [
    "a",
    "_a",
    "A9",
    "0abc",
    "a.b",
    "a-b",
    "a_b",
    "deploy",
    "svc.build-01",
    "alice",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
];

const INVALID: [&str; 23] = [
    "",
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
