mod common;

use common::{load_err, load_ok};
use jaunt_policy::{DbDecision, Identity, PolicySet, ResourceInfo};

type GrammarCase = (
    &'static str,
    &'static [&'static str],
    &'static str,
    &'static str,
    bool,
    bool,
);
type DenyCase = (
    &'static str,
    [bool; 4],
    &'static [&'static str],
    &'static [&'static str],
);

fn role(name: &str, members: &str, body: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  members: {members}\n{body}"
    )
}

fn roles(parts: &[String]) -> PolicySet {
    load_ok(&[("roles.yaml", &parts.join("---\n"))])
}

fn person(username: &str, groups: &[&str]) -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: username.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

fn alice() -> Identity {
    person("alice", &["ops"])
}

fn server(name: &str, env: &str) -> ResourceInfo {
    ResourceInfo {
        name: name.to_owned(),
        labels: [("env".to_owned(), env.to_owned())].into(),
    }
}

fn lk() -> ResourceInfo {
    server("lk-ru-prod", "prod")
}

fn databases(name: &str, body: &str) -> String {
    role(name, "{ groups: [ops] }", &format!("  databases: {body}\n"))
}

fn allowed(set: &PolicySet, who: &Identity, target: &ResourceInfo, user: &str, name: &str) -> bool {
    set.authorize_db(who, target, user, name).allowed
}

#[test]
fn a_role_grants_its_users_on_its_names_and_roles_do_not_mix() {
    let set = roles(&[
        databases(
            "reader",
            "{ servers: { env: [prod] }, users: [readonly], names: [app, billing] }",
        ),
        databases(
            "owner",
            "{ servers: { name: [lk-ru-prod] }, users: [app_owner], names: [app] }",
        ),
        databases(
            "everything",
            "{ servers: { env: [dev] }, users: [dev], names: ['*'] }",
        ),
    ]);
    let cases: [(&str, ResourceInfo, &str, &str, bool); 9] = [
        ("listed pair", lk(), "readonly", "billing", true),
        ("pair from another role", lk(), "app_owner", "app", true),
        (
            "user of one role, name of another",
            lk(),
            "app_owner",
            "billing",
            false,
        ),
        ("unknown name", lk(), "readonly", "secrets", false),
        ("unknown user", lk(), "postgres", "app", false),
        (
            "name selector",
            server("lk-eu-prod", "prod"),
            "app_owner",
            "app",
            false,
        ),
        ("any name", server("x", "dev"), "dev", "whatever", true),
        (
            "star is not a requested name",
            server("x", "dev"),
            "dev",
            "*",
            false,
        ),
        (
            "invalid requested user",
            server("x", "dev"),
            "de v",
            "app",
            false,
        ),
    ];
    for (label, target, user, name, expected) in cases {
        assert_eq!(
            allowed(&set, &alice(), &target, user, name),
            expected,
            "{label}"
        );
    }
    let decision = set.authorize_db(&alice(), &lk(), "app_owner", "app");
    assert_eq!(decision.roles, ["owner"]);
    assert_eq!(decision.users, ["app_owner"]);
    assert_eq!(decision.names, ["app"]);
    assert_eq!(decision.policy_hash, set.hash());
}

#[test]
fn an_allowed_decision_lists_only_what_the_granting_roles_give() {
    let set = roles(&[
        databases(
            "a",
            "{ servers: { env: [prod] }, users: [app], names: [shop] }",
        ),
        databases(
            "b",
            "{ servers: { env: [prod] }, users: [admin], names: [ledger] }",
        ),
    ]);
    let decision = set.authorize_db(&alice(), &lk(), "app", "shop");
    assert!(decision.allowed);
    assert_eq!(decision.roles, ["a"]);
    assert_eq!(decision.users, ["app"]);
    assert_eq!(decision.names, ["shop"]);
    let admin = set.authorize_db(&alice(), &lk(), "admin", "ledger");
    assert_eq!(admin.roles, ["b"]);
    assert_eq!(
        (admin.users, admin.names),
        (vec!["admin".to_owned()], vec!["ledger".to_owned()])
    );
}

#[test]
fn substituted_database_users_and_names_follow_the_stricter_grammar() {
    let set = roles(&[databases(
        "personal",
        "{ servers: { env: [prod] }, users: ['{username}', 'g_{groups}'], names: ['{username}', 'team-{groups}'] }",
    )]);
    let cases: [GrammarCase; 7] = [
        ("alice", &["ops"], "alice", "alice", true, false),
        ("alice", &["ops"], "g_ops", "team-ops", true, false),
        ("Alice", &["ops"], "Alice", "team-ops", false, true),
        ("postgres", &["ops"], "postgres", "team-ops", false, true),
        (
            "pg_monitor",
            &["ops"],
            "pg_monitor",
            "team-ops",
            false,
            true,
        ),
        ("alice", &["ops", "Dev"], "g_Dev", "team-ops", false, true),
        (
            "alice",
            &["ops", "dev", "web"],
            "g_web",
            "team-dev",
            true,
            false,
        ),
    ];
    for (username, groups, user, name, expected, invalid) in cases {
        let decision = set.authorize_db(&person(username, groups), &lk(), user, name);
        assert_eq!(
            decision.allowed, expected,
            "{username} {groups:?} {user} {name}"
        );
        assert_eq!(decision.trait_not_valid, invalid, "{username} {groups:?}");
    }
}

#[test]
fn a_database_deny_matches_the_server_and_the_listed_users_and_names() {
    let wide = databases(
        "wide",
        "{ servers: { env: ['*'] }, users: [readonly, postgres, app], names: ['*'] }",
    );
    let pairs = [
        ("readonly", "app"),
        ("readonly", "secrets"),
        ("postgres", "app"),
        ("app", "secrets"),
    ];
    let cases: [DenyCase; 5] = [
        ("{ servers: { env: [prod] } }", [false; 4], &[], &[]),
        (
            "{ servers: { env: [prod] }, users: [postgres] }",
            [true, true, false, true],
            &["app", "readonly"],
            &["*"],
        ),
        (
            "{ servers: { env: [prod] }, names: [secrets] }",
            [true, false, true, false],
            &["app", "postgres", "readonly"],
            &["*"],
        ),
        (
            "{ servers: { env: [prod] }, users: [app], names: [secrets] }",
            [true, true, true, false],
            &["app", "postgres", "readonly"],
            &["*"],
        ),
        (
            "{ servers: { name: [lk-ru-prod] }, users: ['*'], names: ['*'] }",
            [false; 4],
            &[],
            &[],
        ),
    ];
    for (deny, expected, users, names) in cases {
        let set = roles(&[
            wide.clone(),
            role(
                "limits",
                "{ groups: [ops] }",
                &format!("  deny: {{ databases: {deny} }}\n"),
            ),
        ]);
        for ((user, name), allowed_pair) in pairs.iter().zip(expected) {
            let decision = set.authorize_db(&alice(), &lk(), user, name);
            assert_eq!(decision.allowed, allowed_pair, "{deny}: {user} {name}");
            let denied_by: &[&str] = if allowed_pair { &[] } else { &["limits"] };
            assert_eq!(decision.denied_by, denied_by, "{deny}: {user} {name}");
            let (users, names): (&[&str], &[&str]) = if allowed_pair {
                (users, names)
            } else {
                (&[], &[])
            };
            assert_eq!(decision.users, users, "{deny}: {user} {name}");
            assert_eq!(decision.names, names, "{deny}: {user} {name}");
        }
        assert!(
            allowed(
                &set,
                &alice(),
                &server("dev-1", "dev"),
                "postgres",
                "secrets"
            ),
            "{deny}: dev"
        );
    }
}

#[test]
fn a_database_deny_wins_regardless_of_order_and_file_and_only_for_members() {
    let allow_role = databases(
        "allow",
        "{ servers: { env: [prod] }, users: [postgres], names: ['*'] }",
    );
    let deny_role = role(
        "deny",
        "{ users: [alice@example.com] }",
        "  deny: { databases: { servers: { env: [prod] }, users: [postgres] } }\n",
    );
    let layouts: Vec<Vec<(&str, String)>> = vec![
        vec![("a.yaml", format!("{allow_role}---\n{deny_role}"))],
        vec![("a.yaml", format!("{deny_role}---\n{allow_role}"))],
        vec![
            ("a.yaml", allow_role.clone()),
            ("b.yaml", deny_role.clone()),
        ],
        vec![
            ("a.yaml", deny_role.clone()),
            ("b.yaml", allow_role.clone()),
        ],
    ];
    let bob = Identity {
        email: "bob@example.com".to_owned(),
        username: "bob".to_owned(),
        groups: vec!["ops".to_owned()],
    };
    let carol = Identity {
        email: "carol@example.com".to_owned(),
        username: "carol".to_owned(),
        groups: vec!["dev".to_owned()],
    };
    for (index, files) in layouts.iter().enumerate() {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, content)| (*name, content.as_str()))
            .collect();
        let set = load_ok(&files);
        assert_eq!(
            set.authorize_db(&alice(), &lk(), "postgres", "app"),
            DbDecision {
                denied_by: vec!["deny".to_owned()],
                policy_hash: set.hash().to_owned(),
                ..DbDecision::default()
            },
            "{index}"
        );
        assert!(allowed(&set, &bob, &lk(), "postgres", "app"), "{index}");
        assert_eq!(
            set.authorize_db(&carol, &lk(), "postgres", "app"),
            DbDecision {
                policy_hash: set.hash().to_owned(),
                ..DbDecision::default()
            },
            "{index}: not a member"
        );
    }
}

#[test]
fn a_template_prefix_leaves_room_for_one_character() {
    let prefix = "u".repeat(62);
    let set = roles(&[databases(
        "personal",
        &format!("{{ servers: {{ env: [prod] }}, users: ['{prefix}{{username}}'], names: ['*'] }}"),
    )]);
    assert!(allowed(
        &set,
        &person("x", &["ops"]),
        &lk(),
        &format!("{prefix}x"),
        "app"
    ));
    let decision = set.authorize_db(
        &person("xy", &["ops"]),
        &lk(),
        &format!("{prefix}xy"),
        "app",
    );
    assert!(!decision.allowed && decision.trait_not_valid);
    let errors = load_err(&[(
        "a.yaml",
        &databases(
            "personal",
            &format!(
                "{{ servers: {{ env: [prod] }}, users: ['{prefix}u{{username}}'], names: ['*'] }}"
            ),
        ),
    )]);
    assert!(
        errors
            .to_string()
            .contains("the literal prefix cannot start a valid database user"),
        "{errors}"
    );
}

#[test]
fn database_blocks_are_validated() {
    let cases = [
        (
            "  databases: { users: [a], names: [b] }\n",
            "role \"r\": spec.databases.servers is required when spec.databases is set",
        ),
        (
            "  databases: { servers: { env: [prod] }, names: [b] }\n",
            "role \"r\": spec.databases.users must list at least one database user",
        ),
        (
            "  databases: { servers: { env: [prod] }, users: [a] }\n",
            "role \"r\": spec.databases.names must list at least one database name",
        ),
        (
            "  databases: { servers: { env: [prod] }, users: [1app], names: [b] }\n",
            "role \"r\": spec.databases.users[0] \"1app\" is not a valid database user",
        ),
        (
            "  databases: { servers: { env: [prod] }, users: [a], names: ['*', 'a/b'] }\n",
            "role \"r\": spec.databases.names[1] \"a/b\" is not a valid database name",
        ),
        (
            "  databases: { servers: { env: [prod] }, users: ['pg_{username}'], names: [b] }\n",
            "the literal prefix cannot start a valid database user",
        ),
        (
            "  databases: { servers: { env: [prod] }, users: [a], names: ['App{username}'] }\n",
            "the literal prefix cannot start a valid database name",
        ),
        (
            "  deny: { databases: { servers: { env: [prod] }, users: [] } }\n",
            "role \"r\": spec.deny.databases.users must list at least one database user",
        ),
        (
            "  deny: { databases: { servers: { env: [prod] }, names: ['{username}'] } }\n",
            "not traits",
        ),
        (
            "  deny: { databases: { servers: { env: [prod] }, users: ['a-b'] } }\n",
            "role \"r\": spec.deny.databases.users[0] \"a-b\" is not a valid database user",
        ),
    ];
    for (body, fragment) in cases {
        let errors = load_err(&[("a.yaml", &role("r", "{ groups: [ops] }", body))]);
        assert!(
            errors
                .errors()
                .iter()
                .any(|error| error.document == Some(1) && error.message.contains(fragment)),
            "{body}: expected {fragment:?} in\n{errors}"
        );
    }
}
