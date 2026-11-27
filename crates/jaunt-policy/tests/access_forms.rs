mod common;

use common::{load_err, load_ok};
use jaunt_policy::{AccessTarget, run_access_tests};

const ROLES: &str = "apiVersion: jaunt/v1
kind: Role
metadata: { name: platform }
spec:
  members: { groups: [platform] }
  ssh: { nodes: { env: [prod] }, logins: [deploy] }
  kubernetes: { clusters: { env: [prod] }, users: ['{email}', admin], groups: [view, 'oidc:{groups}'] }
  databases: { servers: { env: [prod] }, users: [readonly], names: [app] }
  tcp: { services: { team: [ops] } }
  deny:
    kubernetes: { clusters: { name: [prod-ru] } }
    tcp: { services: { name: [vault] } }
";

fn tests_file(cases: &[&str]) -> String {
    let mut text = "apiVersion: jaunt/v1\nkind: AccessTest\nspec:\n".to_owned();
    for case in cases {
        text.push_str(&format!(
            "  - {{ user: a@example.com, groups: [platform], {case} }}\n"
        ));
    }
    text
}

#[test]
fn every_target_form_runs_against_its_decision() {
    let cases = [
        ("node: { env: prod }, login: deploy, expect: allow", true),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod } }, expect: allow",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, user: admin }, expect: allow",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, user: root }, expect: deny",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-ru, env: prod } }, expect: deny",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, groups: [oidc:platform, view] }, expect: allow",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, groups: [view, view, oidc:platform] }, expect: allow",
            true,
        ),
        (
            "kubernetes: { cluster: { name: prod-ru, env: prod }, groups: [] }, expect: deny",
            true,
        ),
        (
            "database: { server: { name: lk, env: prod }, user: readonly, name: app }, expect: allow",
            true,
        ),
        (
            "database: { server: { name: lk, env: prod }, user: readonly, name: other }, expect: deny",
            true,
        ),
        (
            "tcp: { service: { name: grafana, team: ops } }, expect: allow",
            true,
        ),
        (
            "tcp: { service: { name: vault, team: ops } }, expect: deny",
            true,
        ),
        (
            "tcp: { service: { name: vault, team: ops } }, grants: [], expect: deny",
            true,
        ),
        (
            "tcp: { service: { name: vault, team: ops } }, expect: allow",
            false,
        ),
        (
            "database: { server: { env: prod }, user: readonly, name: app }, expect: deny",
            false,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, groups: [view] }, expect: allow",
            false,
        ),
        (
            "kubernetes: { cluster: { name: prod-eu, env: prod }, groups: [view, oidc:platform, edit] }, expect: allow",
            false,
        ),
    ];
    let lines: Vec<&str> = cases.iter().map(|(case, _)| *case).collect();
    let set = load_ok(&[("roles.yaml", ROLES), ("tests.yaml", &tests_file(&lines))]);
    let results = run_access_tests(&set);
    assert_eq!(results.len(), cases.len());
    for ((case, passes), result) in cases.iter().zip(&results) {
        assert_eq!(result.passed, *passes, "{case}: {}", result.description);
    }
    assert!(
        results[15].description.contains(
            "expected allow got allow; groups expected {\"view\"} got {\"oidc:platform\", \"view\"}"
        ),
        "{}",
        results[15].description
    );
    assert!(
        results[13].description.contains("tcp service=\"vault\"")
            && results[13].description.contains("expected allow got deny"),
        "{}",
        results[13].description
    );

    let AccessTarget::Kubernetes {
        cluster,
        user,
        groups,
    } = &set.tests()[2].target
    else {
        panic!("the third case targets a cluster");
    };
    assert_eq!(cluster.name, "prod-eu");
    assert!(!cluster.labels.contains_key("name"));
    assert_eq!(user.as_deref(), Some("admin"));
    assert!(groups.is_none());
}

#[test]
fn a_case_needs_exactly_one_target_and_grants_stay_reserved() {
    let cases = [
        (
            "expect: allow",
            "spec[0]: an access test needs exactly one target",
        ),
        (
            "node: { env: prod }, expect: allow",
            "spec[0]: node and login must be given together",
        ),
        (
            "login: deploy, expect: allow",
            "spec[0]: node and login must be given together",
        ),
        (
            "node: { env: prod }, login: deploy, tcp: { service: { team: ops } }, expect: allow",
            "spec[0]: an access test needs exactly one target",
        ),
        (
            "kubernetes: { cluster: { env: prod } }, database: { server: { env: prod }, user: a, name: b }, expect: allow",
            "spec[0]: an access test needs exactly one target",
        ),
        (
            "tcp: { service: { team: ops } }, grants: [dba], expect: allow",
            "spec[0]: grants is reserved for temporary role grants and must be empty or absent",
        ),
        (
            "database: { server: { env: prod }, user: a }, expect: allow",
            "missing field `name`",
        ),
        (
            "kubernetes: { cluster: { env: prod }, login: x }, expect: allow",
            "unknown field `login`",
        ),
    ];
    for (case, fragment) in cases {
        let errors = load_err(&[("tests.yaml", &tests_file(&[case]))]);
        assert!(
            errors
                .errors()
                .iter()
                .any(|error| error.document == Some(1) && error.message.contains(fragment)),
            "{case}: expected {fragment:?} in\n{errors}"
        );
    }
}
