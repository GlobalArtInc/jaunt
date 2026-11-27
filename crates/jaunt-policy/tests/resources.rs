mod common;

use common::{load_err, load_ok};
use jaunt_policy::{
    AdminPermission, DeniedPrincipals, DeniedSet, GrantPrincipals, Identity, PolicySet,
    ResourceInfo, ResourceKind, RoleDenial, RoleGrant, TcpDecision,
};

fn role(name: &str, members: &str, body: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  members: {members}\n{body}"
    )
}

fn roles(parts: &[String]) -> PolicySet {
    load_ok(&[("roles.yaml", &parts.join("---\n"))])
}

fn alice() -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: "alice".to_owned(),
        groups: vec!["ops".to_owned()],
    }
}

fn resource(name: &str, labels: &[(&str, &str)]) -> ResourceInfo {
    ResourceInfo {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn tcp_services_follow_the_selector_and_a_deny_wins() {
    let grafana = resource("grafana", &[("team", "ops")]);
    let vault = resource("vault", &[("team", "ops")]);
    let cases: [(&str, &str, bool, bool); 6] = [
        ("{ team: [ops] }", "", true, true),
        ("{ team: ['*'] }", "", true, true),
        ("{ name: [grafana] }", "", true, false),
        ("{ team: [dev] }", "", false, false),
        (
            "{ team: [ops] }",
            "{ services: { name: [vault] } }",
            true,
            false,
        ),
        (
            "{ team: [ops] }",
            "{ services: { team: ['*'] } }",
            false,
            false,
        ),
    ];
    for (selector, deny, on_grafana, on_vault) in cases {
        let mut body = format!("  tcp: {{ services: {selector} }}\n");
        if !deny.is_empty() {
            body.push_str(&format!("  deny: {{ tcp: {deny} }}\n"));
        }
        let set = roles(&[role("r", "{ groups: [ops] }", &body)]);
        assert_eq!(
            set.authorize_tcp(&alice(), &grafana).allowed,
            on_grafana,
            "{selector} {deny}"
        );
        assert_eq!(
            set.authorize_tcp(&alice(), &vault).allowed,
            on_vault,
            "{selector} {deny}"
        );
    }

    let allow = role(
        "allow",
        "{ groups: [ops] }",
        "  tcp: { services: { team: [ops] } }\n",
    );
    let deny = role(
        "deny",
        "{ users: [alice@example.com] }",
        "  deny: { tcp: { services: { name: [vault] } } }\n",
    );
    let foreign_deny = role(
        "foreign",
        "{ users: [bob@example.com] }",
        "  deny: { tcp: { services: { team: ['*'] } } }\n",
    );
    let layouts: Vec<Vec<(&str, String)>> = vec![
        vec![("a.yaml", format!("{allow}---\n{deny}---\n{foreign_deny}"))],
        vec![("a.yaml", format!("{foreign_deny}---\n{deny}---\n{allow}"))],
        vec![
            ("a.yaml", allow.clone()),
            ("b.yaml", deny.clone()),
            ("c.yaml", foreign_deny.clone()),
        ],
        vec![
            ("a.yaml", deny.clone()),
            ("b.yaml", foreign_deny.clone()),
            ("c.yaml", allow.clone()),
        ],
    ];
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
            set.authorize_tcp(&alice(), &vault),
            TcpDecision {
                allowed: false,
                roles: Vec::new(),
                denied_by: strings(&["deny"]),
                policy_hash: set.hash().to_owned(),
            },
            "{index}"
        );
        let open = set.authorize_tcp(&alice(), &grafana);
        assert!(open.allowed && open.denied_by.is_empty(), "{index}");
        assert_eq!(open.roles, ["allow"], "{index}");
        assert_eq!(
            set.authorize_tcp(&carol, &grafana),
            TcpDecision {
                policy_hash: set.hash().to_owned(),
                ..TcpDecision::default()
            },
            "{index}: not a member"
        );
    }

    for (body, fragment) in [
        (
            "  tcp: {}\n",
            "role \"r\": spec.tcp.services is required when spec.tcp is set",
        ),
        (
            "  tcp: { services: { team: [] } }\n",
            "role \"r\": spec.tcp.services.team must list at least one value",
        ),
        (
            "  deny: { tcp: { services: {} } }\n",
            "role \"r\": spec.deny.tcp.services selector must not be empty",
        ),
        (
            "  tcp: { services: { team: [ops] }, address: x }\n",
            "unknown field `address`",
        ),
    ] {
        let errors = load_err(&[("a.yaml", &role("r", "{ groups: [ops] }", body))]);
        assert!(
            errors
                .errors()
                .iter()
                .any(|error| error.message.contains(fragment)),
            "{body}: expected {fragment:?} in\n{errors}"
        );
    }
}

fn reach_policy() -> PolicySet {
    roles(&[
        role(
            "platform",
            "{ users: [alice@example.com], groups: [platform] }",
            "  ssh: { nodes: { env: [prod] }, logins: [deploy, '{username}'] }\n  kubernetes: { clusters: { env: [prod] }, groups: [view, 'oidc:{groups}'] }\n  databases: { servers: { env: [prod] }, users: [readonly, '{username}'], names: ['*'] }\n  tcp: { services: { env: [prod] } }\n  admin: [audit.read]\n",
        ),
        role(
            "limits",
            "{ groups: [contractors] }",
            "  deny:\n    ssh: { nodes: { env: [prod] }, logins: [root] }\n    kubernetes: { clusters: { name: [prod-eu] }, groups: ['system:masters'] }\n    databases: { servers: { env: [prod] }, names: [secrets] }\n    tcp: { services: { env: [prod] } }\n",
        ),
        role(
            "stage",
            "{ groups: [dev] }",
            "  kubernetes: { clusters: { env: [stage] }, users: [dev], recordExec: false, recordInput: true }\n  deny: { kubernetes: { clusters: { env: [stage] } } }\n",
        ),
    ])
}

#[test]
fn roles_reaching_a_resource_list_grants_with_principals_and_denies_apart() {
    let set = reach_policy();
    let prod = resource("prod-eu", &[("env", "prod")]);
    let members = (strings(&["alice@example.com"]), strings(&["platform"]));
    let grant = |principals| RoleGrant {
        role: "platform".to_owned(),
        users: members.0.clone(),
        groups: members.1.clone(),
        admin: vec![AdminPermission::AuditRead],
        principals,
    };
    let denial = |principals| RoleDenial {
        role: "limits".to_owned(),
        users: Vec::new(),
        groups: strings(&["contractors"]),
        principals,
    };
    let cases = [
        (
            ResourceKind::Node,
            GrantPrincipals::Ssh {
                logins: strings(&["deploy", "{username}"]),
                port_forwarding: false,
                record_input: false,
            },
            DeniedPrincipals::Ssh {
                logins: Some(strings(&["root"])),
            },
        ),
        (
            ResourceKind::KubernetesCluster,
            GrantPrincipals::Kubernetes {
                users: strings(&["{email}"]),
                groups: strings(&["view", "oidc:{groups}"]),
                record_exec: true,
                record_input: false,
            },
            DeniedPrincipals::Kubernetes {
                users: DeniedSet::Absent,
                groups: DeniedSet::Listed(strings(&["system:masters"])),
            },
        ),
        (
            ResourceKind::DatabaseServer,
            GrantPrincipals::Database {
                users: strings(&["readonly", "{username}"]),
                names: strings(&["*"]),
            },
            DeniedPrincipals::Database {
                users: None,
                names: Some(strings(&["secrets"])),
            },
        ),
        (
            ResourceKind::TcpService,
            GrantPrincipals::Tcp,
            DeniedPrincipals::Tcp,
        ),
    ];
    for (kind, granted, denied) in cases {
        let reach = set.roles_reaching_resource(kind, &prod);
        assert_eq!(reach.allows, [grant(granted)], "{kind:?}");
        assert_eq!(reach.denies, [denial(denied)], "{kind:?}");
    }

    let stage = set.roles_reaching_resource(
        ResourceKind::KubernetesCluster,
        &resource("stage-1", &[("env", "stage")]),
    );
    assert_eq!(stage.allows.len(), 1);
    assert_eq!(stage.allows[0].role, "stage");
    assert_eq!(
        stage.allows[0].principals,
        GrantPrincipals::Kubernetes {
            users: strings(&["dev"]),
            groups: Vec::new(),
            record_exec: false,
            record_input: true,
        }
    );
    assert_eq!(
        stage.denies[0].principals,
        DeniedPrincipals::Kubernetes {
            users: DeniedSet::Absent,
            groups: DeniedSet::Absent,
        }
    );

    for (deny, users, groups) in [
        (
            "{ clusters: { env: [qa] }, groups: ['*'] }",
            DeniedSet::Absent,
            DeniedSet::Any,
        ),
        (
            "{ clusters: { env: [qa] }, users: ['*'], groups: [view] }",
            DeniedSet::Any,
            DeniedSet::Listed(strings(&["view"])),
        ),
        (
            "{ clusters: { env: [qa] }, users: [admin, '*'] }",
            DeniedSet::Any,
            DeniedSet::Absent,
        ),
    ] {
        let set = roles(&[role(
            "limits",
            "{ groups: [ops] }",
            &format!("  deny: {{ kubernetes: {deny} }}\n"),
        )]);
        let reach = set.roles_reaching_resource(
            ResourceKind::KubernetesCluster,
            &resource("qa-1", &[("env", "qa")]),
        );
        assert_eq!(
            reach.denies[0].principals,
            DeniedPrincipals::Kubernetes { users, groups },
            "{deny}"
        );
    }

    let elsewhere = resource("prod-ru", &[("env", "qa")]);
    let empty = set.roles_reaching_resource(ResourceKind::DatabaseServer, &elsewhere);
    assert!(empty.allows.is_empty() && empty.denies.is_empty());

    let nodes = set.roles_reaching(&prod);
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].role, "platform");
    assert_eq!(nodes[0].logins, ["deploy", "{username}"]);
    assert_eq!(nodes[0].admin, [AdminPermission::AuditRead]);
}

#[test]
fn privileged_literals_of_every_kind_are_warnings() {
    let set = roles(&[role(
        "wide",
        "{ groups: [ops] }",
        "  ssh: { nodes: { env: [prod] }, logins: [root, deploy] }\n  kubernetes: { clusters: { env: [prod] }, users: ['system:masters'], groups: [view, 'system:masters', 'oidc:{groups}', 'system:authenticated', 'system:nodes', 'system:bootstrappers'] }\n  databases: { servers: { env: [prod] }, users: [postgres, '{username}', Postgres], names: [postgres] }\n",
    )]);
    let warnings: Vec<(String, &str, String)> = set
        .warnings()
        .into_iter()
        .map(|warning| (warning.role, warning.field, warning.value))
        .collect();
    assert_eq!(
        warnings,
        [
            ("wide".to_owned(), "spec.ssh.logins", "root".to_owned()),
            (
                "wide".to_owned(),
                "spec.kubernetes.groups",
                "system:masters".to_owned()
            ),
            (
                "wide".to_owned(),
                "spec.kubernetes.groups",
                "system:authenticated".to_owned()
            ),
            (
                "wide".to_owned(),
                "spec.kubernetes.groups",
                "system:nodes".to_owned()
            ),
            (
                "wide".to_owned(),
                "spec.databases.users",
                "postgres".to_owned()
            ),
        ]
    );
    let quiet = roles(&[role(
        "deny-only",
        "{ groups: [ops] }",
        "  deny: { kubernetes: { clusters: { env: [prod] }, groups: ['system:masters'] }, databases: { servers: { env: [prod] }, users: [postgres] } }\n",
    )]);
    assert!(quiet.warnings().is_empty());
}
