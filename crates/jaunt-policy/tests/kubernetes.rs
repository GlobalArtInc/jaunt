mod common;

use common::{load_err, load_ok};
use jaunt_policy::{Identity, KubeDecision, PolicySet, ResourceInfo};

type SubtractionCase<'a> = (
    &'a [String],
    bool,
    &'static [&'static str],
    &'static [&'static str],
    &'static [&'static str],
);

type AttributionCase = (
    Vec<String>,
    bool,
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

fn person(email: &str, groups: &[&str]) -> Identity {
    Identity {
        email: email.to_owned(),
        username: "alice".to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    }
}

fn alice() -> Identity {
    person("alice@example.com", &["ops"])
}

fn cluster(name: &str, labels: &[(&str, &str)]) -> ResourceInfo {
    ResourceInfo {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn prod_eu() -> ResourceInfo {
    cluster("prod-eu", &[("env", "prod"), ("region", "eu")])
}

fn allow(body: &str) -> String {
    role(
        "allow",
        "{ groups: [ops] }",
        &format!("  kubernetes: {body}\n"),
    )
}

#[test]
fn cluster_selectors_work_like_node_selectors() {
    let cases: [(&str, ResourceInfo, bool); 9] = [
        ("{ env: [prod] }", prod_eu(), true),
        ("{ env: [stage, prod] }", prod_eu(), true),
        ("{ env: [prod], region: [us] }", prod_eu(), false),
        ("{ env: ['*'] }", prod_eu(), true),
        ("{ team: ['*'] }", prod_eu(), false),
        ("{ name: [prod-eu] }", prod_eu(), true),
        ("{ name: [prod-ru] }", prod_eu(), false),
        (
            "{ name: [prod-ru] }",
            cluster("prod-eu", &[("name", "prod-ru")]),
            false,
        ),
        ("{ name: ['*'], env: [prod] }", prod_eu(), true),
    ];
    for (selector, target, expected) in cases {
        let set = roles(&[allow(&format!("{{ clusters: {selector} }}"))]);
        let decision = set.authorize_kube(&alice(), &target);
        assert_eq!(decision.allowed, expected, "{selector} on {target:?}");
    }
}

#[test]
fn users_default_to_the_email_and_groups_expand_per_identity_group() {
    let set = roles(&[role(
        "allow",
        "{ users: [alice@example.com] }",
        "  kubernetes: { clusters: { env: [prod] }, groups: [view, 'oidc:{groups}'] }\n",
    )]);
    let cases: [(&[&str], &[&str]); 3] = [
        (&[], &["view"]),
        (&["dev"], &["oidc:dev", "view"]),
        (
            &["dev", "ops", "web"],
            &["oidc:dev", "oidc:ops", "oidc:web", "view"],
        ),
    ];
    for (groups, expected) in cases {
        let decision = set.authorize_kube(&person("alice@example.com", groups), &prod_eu());
        assert!(decision.allowed, "{groups:?}");
        assert_eq!(decision.users, ["alice@example.com"], "{groups:?}");
        assert_eq!(decision.groups, expected, "{groups:?}");
        assert!(!decision.trait_not_valid, "{groups:?}");
    }
}

#[test]
fn substituted_values_that_fail_the_predicate_are_absent_and_flagged() {
    let set = roles(&[allow(
        "{ clusters: { env: [prod] }, users: ['{email}', 'u:{username}'], groups: ['{groups}'] }",
    )]);
    let decision = set.authorize_kube(
        &person(
            "alice@example.com",
            &["ops", "system:masters", "SYSTEM:nodes", "a b"],
        ),
        &prod_eu(),
    );
    assert!(decision.allowed);
    assert_eq!(decision.users, ["alice@example.com", "u:alice"]);
    assert_eq!(decision.groups, ["ops"]);
    assert!(decision.trait_not_valid);

    let email_only = roles(&[allow("{ clusters: { env: [prod] } }")]);
    let unicode = email_only.authorize_kube(&person("al\u{e9}@example.com", &["ops"]), &prod_eu());
    assert!(!unicode.allowed);
    assert!(unicode.users.is_empty());
    assert!(unicode.trait_not_valid);
    let system = email_only.authorize_kube(&person("system:admin", &["ops"]), &prod_eu());
    assert!(!system.allowed);
    assert!(system.trait_not_valid);

    let literal = roles(&[allow(
        "{ clusters: { env: [prod] }, users: [admin], groups: ['system:masters'] }",
    )]);
    let decision = literal.authorize_kube(&alice(), &prod_eu());
    assert!(decision.allowed && !decision.trait_not_valid);
    assert_eq!(decision.users, ["admin"]);
    assert_eq!(decision.groups, ["system:masters"]);
}

#[test]
fn a_kubernetes_deny_blocks_the_cluster_or_subtracts_principals() {
    let wide = allow(
        "{ clusters: { env: ['*'] }, users: ['{email}', admin], groups: [view, edit, 'system:masters'] }",
    );
    let cases: [(&str, bool, &[&str], &[&str]); 9] = [
        ("{ clusters: { env: [prod] } }", false, &[], &[]),
        ("{ clusters: { name: [prod-eu] } }", false, &[], &[]),
        (
            "{ clusters: { env: [prod] }, groups: ['system:masters'] }",
            true,
            &["admin", "alice@example.com"],
            &["edit", "view"],
        ),
        (
            "{ clusters: { env: [prod] }, users: [admin] }",
            true,
            &["alice@example.com"],
            &["edit", "system:masters", "view"],
        ),
        (
            "{ clusters: { env: [prod] }, users: [admin, alice@example.com] }",
            false,
            &[],
            &[],
        ),
        (
            "{ clusters: { env: [prod] }, users: ['*'], groups: [view] }",
            false,
            &[],
            &[],
        ),
        (
            "{ clusters: { env: [prod] }, groups: ['*'] }",
            false,
            &[],
            &[],
        ),
        (
            "{ clusters: { env: [prod] }, groups: [view, edit, 'system:masters'] }",
            false,
            &[],
            &[],
        ),
        (
            "{ clusters: { env: [prod] }, users: [admin], groups: [view, edit] }",
            true,
            &["alice@example.com"],
            &["system:masters"],
        ),
    ];
    for (deny, allowed, users, groups) in cases {
        let set = roles(&[
            wide.clone(),
            role(
                "limits",
                "{ groups: [ops] }",
                &format!("  deny: {{ kubernetes: {deny} }}\n"),
            ),
        ]);
        let decision = set.authorize_kube(&alice(), &prod_eu());
        assert_eq!(decision.allowed, allowed, "{deny}");
        assert_eq!(decision.users, users, "{deny}");
        assert_eq!(decision.groups, groups, "{deny}");
        let (refused_by, narrowed_by): (&[&str], &[&str]) = if allowed {
            (&[], &["limits"])
        } else {
            (&["limits"], &[])
        };
        assert_eq!(decision.denied_by, refused_by, "{deny}");
        assert_eq!(decision.subtracted_by, narrowed_by, "{deny}");
        let roles_granting: &[&str] = if allowed { &["allow"] } else { &[] };
        assert_eq!(decision.roles, roles_granting, "{deny}");
        let other = set.authorize_kube(&alice(), &cluster("stage-1", &[("env", "stage")]));
        assert!(
            other.allowed && other.denied_by.is_empty() && other.subtracted_by.is_empty(),
            "{deny}: stage"
        );
        assert_eq!(
            other.groups,
            ["edit", "system:masters", "view"],
            "{deny}: stage"
        );
    }
}

#[test]
fn a_role_whose_groups_are_all_subtracted_grants_nothing() {
    let deny_admins = role(
        "limits",
        "{ groups: [ops] }",
        "  deny: { kubernetes: { clusters: { env: [prod] }, groups: [cluster-admins] } }\n",
    );
    let cases: [SubtractionCase; 4] = [
        (
            &[allow(
                "{ clusters: { env: [prod] }, groups: [cluster-admins] }",
            )],
            false,
            &[],
            &[],
            &[],
        ),
        (
            &[allow(
                "{ clusters: { env: [prod] }, groups: [a, b, cluster-admins] }",
            )],
            true,
            &["allow"],
            &["alice@example.com"],
            &["a", "b"],
        ),
        (
            &[allow("{ clusters: { env: [prod] } }")],
            true,
            &["allow"],
            &["alice@example.com"],
            &[],
        ),
        (
            &[
                role(
                    "admins",
                    "{ groups: [ops] }",
                    "  kubernetes: { clusters: { env: [prod] }, users: [admin-sa], groups: [cluster-admins], recordInput: true }\n",
                ),
                allow("{ clusters: { env: [prod] } }"),
            ],
            true,
            &["allow"],
            &["alice@example.com"],
            &[],
        ),
    ];
    for (index, (grants, allowed, granting, users, groups)) in cases.into_iter().enumerate() {
        let mut parts = grants.to_vec();
        parts.push(deny_admins.clone());
        let decision = roles(&parts).authorize_kube(&alice(), &prod_eu());
        assert_eq!(decision.allowed, allowed, "{index}");
        assert_eq!(decision.roles, granting, "{index}");
        assert_eq!(decision.users, users, "{index}");
        assert_eq!(decision.groups, groups, "{index}");
    }

    let flags = roles(&[
        role(
            "disabled",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { env: [prod] }, groups: [cluster-admins], recordInput: true }\n",
        ),
        allow("{ clusters: { env: [prod] }, recordExec: false }"),
        deny_admins.clone(),
    ])
    .authorize_kube(&alice(), &prod_eu());
    assert!(flags.allowed);
    assert_eq!(flags.roles, ["allow"]);
    assert!(flags.record_exec && flags.record_input);

    let disabled_by_users = roles(&[
        role(
            "x",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { env: [prod] }, users: [x-user], groups: [gx] }\n",
        ),
        role(
            "y",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { env: [prod] }, groups: [gy] }\n",
        ),
        role(
            "dusers",
            "{ groups: [ops] }",
            "  deny: { kubernetes: { clusters: { env: [prod] }, users: [x-user] } }\n",
        ),
    ])
    .authorize_kube(&alice(), &prod_eu());
    assert!(disabled_by_users.allowed);
    assert_eq!(disabled_by_users.roles, ["y"]);
    assert_eq!(disabled_by_users.users, ["alice@example.com"]);
    assert_eq!(disabled_by_users.groups, ["gy"]);
    assert_eq!(disabled_by_users.subtracted_by, ["dusers"]);

    let substituted = roles(&[
        role(
            "oidc",
            "{ users: [alice@example.com] }",
            "  kubernetes: { clusters: { env: [prod] }, groups: ['oidc:{groups}'] }\n",
        ),
        role(
            "limits",
            "{ users: [alice@example.com] }",
            "  deny: { kubernetes: { clusters: { env: [prod] }, groups: ['oidc:a'] } }\n",
        ),
    ])
    .authorize_kube(&person("alice@example.com", &["a", "b"]), &prod_eu());
    assert!(substituted.allowed);
    assert_eq!(substituted.groups, ["oidc:b"]);
    assert_eq!(substituted.subtracted_by, ["limits"]);

    let unrelated = roles(&[
        allow("{ clusters: { env: [prod] }, groups: [a, b] }"),
        role(
            "limits",
            "{ groups: [ops] }",
            "  deny: { kubernetes: { clusters: { env: [prod] }, groups: [a] } }\n",
        ),
    ])
    .authorize_kube(&alice(), &prod_eu());
    assert!(unrelated.allowed);
    assert_eq!(unrelated.groups, ["b"]);
}

#[test]
fn a_decision_names_only_the_denies_that_refused_or_subtracted() {
    let grant = allow("{ clusters: { env: [prod] }, groups: [view, edit] }");
    let whole = role(
        "whole",
        "{ groups: [ops] }",
        "  deny: { kubernetes: { clusters: { env: [prod] } } }\n",
    );
    let narrow = |group: &str| {
        role(
            "narrow",
            "{ groups: [ops] }",
            &format!(
                "  deny: {{ kubernetes: {{ clusters: {{ env: [prod] }}, groups: [{group}] }} }}\n"
            ),
        )
    };
    let idle = role(
        "idle",
        "{ groups: [ops] }",
        "  deny: { kubernetes: { clusters: { env: [prod] }, users: [nobody] } }\n",
    );
    let only_edit = allow("{ clusters: { env: [prod] }, groups: [edit] }");
    let cases: [AttributionCase; 5] = [
        (
            vec![grant.clone(), whole.clone(), narrow("edit")],
            false,
            &["whole"],
            &[],
        ),
        (
            vec![grant.clone(), narrow("edit"), idle.clone()],
            true,
            &[],
            &["narrow"],
        ),
        (vec![grant.clone(), narrow("other")], true, &[], &[]),
        (
            vec![only_edit.clone(), narrow("edit"), idle.clone()],
            false,
            &["narrow"],
            &[],
        ),
        (vec![whole.clone(), idle.clone()], false, &["whole"], &[]),
    ];
    for (index, (parts, allowed, denied_by, subtracted_by)) in cases.into_iter().enumerate() {
        let decision = roles(&parts).authorize_kube(&alice(), &prod_eu());
        assert_eq!(decision.allowed, allowed, "{index}");
        assert_eq!(decision.denied_by, denied_by, "{index}");
        assert_eq!(decision.subtracted_by, subtracted_by, "{index}");
    }
}

#[test]
fn a_kubernetes_deny_wins_regardless_of_order_and_only_for_members() {
    let allow_role = allow("{ clusters: { env: [prod] } }");
    let deny_role = role(
        "deny",
        "{ users: [alice@example.com] }",
        "  deny: { kubernetes: { clusters: { env: [prod] } } }\n",
    );
    let both = role(
        "both",
        "{ groups: [ops] }",
        "  kubernetes: { clusters: { env: [prod] } }\n  deny: { kubernetes: { clusters: { env: [prod] } } }\n",
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
        vec![("a.yaml", both)],
    ];
    for (index, files) in layouts.iter().enumerate() {
        let files: Vec<(&str, &str)> = files
            .iter()
            .map(|(name, content)| (*name, content.as_str()))
            .collect();
        let decision = load_ok(&files).authorize_kube(&alice(), &prod_eu());
        assert!(!decision.allowed, "{index}");
        assert!(
            decision.roles.is_empty() && decision.users.is_empty(),
            "{index}"
        );
    }

    let set = roles(&[allow_role, deny_role]);
    assert!(
        set.authorize_kube(&person("bob@example.com", &["ops"]), &prod_eu())
            .allowed
    );
}

#[test]
fn roles_add_up_and_the_strictest_recording_flags_win() {
    let set = roles(&[
        role(
            "viewer",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { env: [prod] }, users: [viewer], groups: [view], recordExec: false }\n",
        ),
        role(
            "editor",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { region: [eu] }, groups: [edit] }\n",
        ),
        role(
            "elsewhere",
            "{ groups: [ops] }",
            "  kubernetes: { clusters: { env: [stage] }, recordExec: true, recordInput: true }\n",
        ),
    ]);
    let decision = set.authorize_kube(&alice(), &prod_eu());
    assert_eq!(
        decision,
        KubeDecision {
            allowed: true,
            roles: vec!["editor".to_owned(), "viewer".to_owned()],
            denied_by: Vec::new(),
            subtracted_by: Vec::new(),
            users: vec!["alice@example.com".to_owned(), "viewer".to_owned()],
            groups: vec!["edit".to_owned(), "view".to_owned()],
            record_exec: true,
            record_input: false,
            trait_not_valid: false,
            policy_hash: set.hash().to_owned(),
        }
    );

    let flags = |body: &str| {
        roles(&[allow(&format!("{{ clusters: {{ env: [prod] }}{body} }}"))])
            .authorize_kube(&alice(), &prod_eu())
    };
    let defaults = flags("");
    assert!(defaults.record_exec && !defaults.record_input);
    let relaxed = flags(", recordExec: false, recordInput: true");
    assert!(!relaxed.record_exec && relaxed.record_input);

    let strict = role(
        "strict",
        "{ groups: [ops] }",
        "  kubernetes: { clusters: { env: [prod] }, recordInput: true }\n",
    );
    let relaxed_role = role(
        "relaxed",
        "{ groups: [ops] }",
        "  kubernetes: { clusters: { env: [prod] }, recordExec: false, recordInput: false }\n",
    );
    let plain = role(
        "plain",
        "{ groups: [ops] }",
        "  kubernetes: { clusters: { env: [prod] } }\n",
    );
    for parts in [
        [relaxed_role.clone(), plain.clone()],
        [plain.clone(), relaxed_role.clone()],
    ] {
        let decision = roles(&parts).authorize_kube(&alice(), &prod_eu());
        assert!(decision.record_exec && !decision.record_input, "exec");
    }
    for parts in [
        [strict.clone(), relaxed_role.clone()],
        [relaxed_role.clone(), strict.clone()],
    ] {
        let decision = roles(&parts).authorize_kube(&alice(), &prod_eu());
        assert!(decision.record_exec && decision.record_input, "input");
    }

    let none = set.authorize_kube(&person("bob@example.com", &["dev"]), &prod_eu());
    assert_eq!(
        none,
        KubeDecision {
            policy_hash: set.hash().to_owned(),
            ..KubeDecision::default()
        }
    );
}

#[test]
fn a_template_prefix_may_leave_room_for_one_character() {
    let prefix = "p".repeat(252);
    let set = roles(&[allow(&format!(
        "{{ clusters: {{ env: [prod] }}, groups: ['{prefix}{{groups}}'] }}"
    ))]);
    let decision = set.authorize_kube(&person("alice@example.com", &["ops", "x"]), &prod_eu());
    assert!(decision.allowed);
    assert_eq!(decision.groups, [format!("{prefix}x")]);
    assert!(decision.trait_not_valid);

    let errors = load_err(&[(
        "a.yaml",
        &allow(&format!(
            "{{ clusters: {{ env: [prod] }}, groups: ['{prefix}p{{groups}}'] }}"
        )),
    )]);
    assert!(
        errors
            .to_string()
            .contains("the literal prefix cannot start a valid Kubernetes group"),
        "{errors}"
    );
}

#[test]
fn kubernetes_blocks_are_validated() {
    let cases = [
        (
            "  kubernetes: { groups: [view] }\n",
            "role \"r\": spec.kubernetes.clusters is required when spec.kubernetes is set",
        ),
        (
            "  kubernetes: { clusters: {} }\n",
            "role \"r\": spec.kubernetes.clusters selector must not be empty",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, users: [] }\n",
            "role \"r\": spec.kubernetes.users must list at least one Kubernetes user",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, groups: [] }\n",
            "role \"r\": spec.kubernetes.groups must list at least one Kubernetes group",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, groups: ['-view'] }\n",
            "role \"r\": spec.kubernetes.groups[0] \"-view\" is not a valid Kubernetes group",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, users: [ok, 'a b'] }\n",
            "role \"r\": spec.kubernetes.users[1] \"a b\" is not a valid Kubernetes user",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, groups: ['system:{groups}'] }\n",
            "the literal prefix cannot start a valid Kubernetes group",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, groups: ['{group}'] }\n",
            "a trait must be",
        ),
        (
            "  kubernetes: { clusters: { env: [prod] }, resources: [pods] }\n",
            "unknown field `resources`",
        ),
        (
            "  deny: { kubernetes: { groups: [view] } }\n",
            "role \"r\": spec.deny.kubernetes.clusters is required",
        ),
        (
            "  deny: { kubernetes: { clusters: { env: [prod] }, groups: [] } }\n",
            "role \"r\": spec.deny.kubernetes.groups must list at least one Kubernetes group",
        ),
        (
            "  deny: { kubernetes: { clusters: { env: [prod] }, users: ['{email}'] } }\n",
            "role \"r\": spec.deny.kubernetes.users[0] \"{email}\": a deny rule lists literal values",
        ),
        (
            "  deny: { kubernetes: { clusters: { env: [prod] }, groups: ['a,b'] } }\n",
            "role \"r\": spec.deny.kubernetes.groups[0] \"a,b\" is not a valid Kubernetes group",
        ),
        (
            "  deny: { kubernetes: { clusters: { env: [prod] }, recordExec: false } }\n",
            "unknown field `recordExec`",
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
