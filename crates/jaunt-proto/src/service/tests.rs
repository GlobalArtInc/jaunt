use serde_json::{Value, json};

use super::{
    AnnouncedService, KubernetesAudit, MAX_SERVICES_PER_AGENT, NodeServices, QueryAudit,
    ServiceAnnouncement, ServiceKind, ServiceList, ServiceProblem, ServiceSettings,
};

fn service(value: Value) -> AnnouncedService {
    serde_json::from_value(value).unwrap()
}

fn problem(value: Value) -> Option<ServiceProblem> {
    service(value).settings().err()
}

#[test]
fn every_kind_has_documented_defaults_and_its_own_block() {
    let kube = service(json!({"kind": "kubernetes", "name": "prod-eu"}))
        .settings()
        .unwrap();
    let ServiceSettings::Kubernetes(kube) = kube else {
        panic!("kubernetes settings");
    };
    assert_eq!(kube.audit, KubernetesAudit::Mutating);
    assert_eq!(
        serde_json::to_value(ServiceSettings::Kubernetes(kube)).unwrap(),
        json!({"api": "in-cluster", "audit": "mutating"})
    );

    let tcp = service(json!({"kind": "tcp", "name": "grafana", "address": "10.0.0.5:3000"}))
        .settings()
        .unwrap();
    assert_eq!(
        serde_json::to_value(&tcp).unwrap(),
        json!({"idle_timeout_secs": 3600})
    );

    let pg = service(json!({
        "kind": "postgres", "name": "lk", "address": "db.internal:5432",
        "postgres": {"tls": {"server_name": "lk-01"}}
    }))
    .settings()
    .unwrap();
    let ServiceSettings::Postgres(pg) = pg else {
        panic!("postgres settings");
    };
    assert_eq!(pg.audit.queries, QueryAudit::Text);
    assert_eq!(pg.audit.max_query_bytes, 4096);
}

#[test]
fn settings_are_refused_by_rule() {
    let pg = |extra: Value| {
        let mut base = json!({"kind": "postgres", "name": "lk", "address": "127.0.0.1:5432",
                              "postgres": {"tls": {"ca_file": "/etc/jaunt/pg-ca.pem"}}});
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base
    };
    let long_path = format!("/{}", "a".repeat(1024));
    let cases: Vec<(Value, Option<ServiceProblem>)> = vec![
        (pg(json!({})), None),
        (pg(json!({"address": "[::1]:5432"})), None),
        (
            pg(
                json!({"postgres": {"tls": {"ca_file": "/x", "server_name": "10.0.0.1"},
                                   "audit": {"queries": "digest", "max_query_bytes": 65536}}}),
            ),
            None,
        ),
        (
            json!({"kind": "kubernetes", "name": "k", "address": "1.2.3.4:6443"}),
            Some(ServiceProblem::AddressNotAllowed),
        ),
        (
            json!({"kind": "tcp", "name": "t"}),
            Some(ServiceProblem::AddressRequired(ServiceKind::Tcp)),
        ),
        (
            json!({"kind": "postgres", "name": "p", "postgres": {"tls": {"server_name": "x"}}}),
            Some(ServiceProblem::AddressRequired(ServiceKind::Postgres)),
        ),
        (
            json!({"kind": "tcp", "name": "t", "address": "1.2.3.4:1", "postgres": {"tls": {}}}),
            Some(ServiceProblem::ForeignBlock {
                kind: ServiceKind::Tcp,
                block: ServiceKind::Postgres,
            }),
        ),
        (
            json!({"kind": "kubernetes", "name": "k", "tcp": {}}),
            Some(ServiceProblem::ForeignBlock {
                kind: ServiceKind::Kubernetes,
                block: ServiceKind::Tcp,
            }),
        ),
        (
            json!({"kind": "postgres", "name": "p", "address": "h:1"}),
            Some(ServiceProblem::PostgresTlsMissing),
        ),
        (
            pg(json!({"postgres": {"tls": {}}})),
            Some(ServiceProblem::PostgresTlsMissing),
        ),
        (
            pg(json!({"postgres": {"tls": {"ca_file": "relative.pem"}}})),
            Some(ServiceProblem::InvalidCaFile),
        ),
        (
            pg(json!({"postgres": {"tls": {"ca_file": long_path}}})),
            Some(ServiceProblem::InvalidCaFile),
        ),
        (
            pg(json!({"postgres": {"tls": {"ca_file": "/etc/jaunt/ca\n.pem"}}})),
            Some(ServiceProblem::InvalidCaFile),
        ),
        (
            pg(json!({"postgres": {"tls": {"ca_file": "/etc/jaunt/\u{7f}.pem"}}})),
            Some(ServiceProblem::InvalidCaFile),
        ),
        (
            pg(json!({"postgres": {"tls": {"server_name": "bad name"}}})),
            Some(ServiceProblem::InvalidServerName),
        ),
        (
            pg(json!({"postgres": {"tls": {"server_name": "x"}, "audit": {"max_query_bytes": 0}}})),
            Some(ServiceProblem::InvalidMaxQueryBytes),
        ),
        (
            pg(
                json!({"postgres": {"tls": {"server_name": "x"}, "audit": {"max_query_bytes": 65537}}}),
            ),
            Some(ServiceProblem::InvalidMaxQueryBytes),
        ),
        (
            json!({"kind": "tcp", "name": "t", "address": "h:1", "tcp": {"idle_timeout_secs": 0}}),
            Some(ServiceProblem::InvalidIdleTimeout),
        ),
        (
            json!({"kind": "tcp", "name": "t", "address": "h:1", "tcp": {"idle_timeout_secs": 86401}}),
            Some(ServiceProblem::InvalidIdleTimeout),
        ),
        (
            json!({"kind": "tcp", "name": "t", "address": "h:1", "tcp": {"idle_timeout_secs": 86400}}),
            None,
        ),
    ];
    for (value, expected) in cases {
        assert_eq!(problem(value.clone()), expected, "{value}");
    }
}

#[test]
fn addresses_are_host_and_port() {
    for (address, ok) in [
        ("10.0.0.5:3000", true),
        ("db-01.internal:5432", true),
        ("[2001:db8::1]:443", true),
        ("h:65535", true),
        ("h:0", false),
        ("h:65536", false),
        ("h:+80", false),
        ("h:", false),
        ("h", false),
        (":80", false),
        ("2001:db8::1:443", false),
        ("[2001:db8::1:443", false),
        ("-bad.example:80", false),
        ("a b:80", false),
        ("http://h:80", false),
    ] {
        let parsed = service(json!({"kind": "tcp", "name": "t", "address": address})).settings();
        assert_eq!(parsed.is_ok(), ok, "{address}");
    }
}

#[test]
fn the_set_is_bounded_and_names_are_unique_per_kind() {
    let item = |kind: &str, name: &str| json!({"kind": kind, "name": name});
    let parse = |items: Vec<Value>| -> ServiceAnnouncement {
        serde_json::from_value(json!({"services": items})).unwrap()
    };
    let full: Vec<Value> = (0..MAX_SERVICES_PER_AGENT)
        .map(|index| item("kubernetes", &format!("k{index}")))
        .collect();
    let announcement = parse(full.clone());
    assert!(announcement.ssh_enabled);
    assert_eq!(announcement.check_set(), Ok(()));
    let mut over = full;
    over.push(item("kubernetes", "extra"));
    assert_eq!(parse(over).check_set(), Err(ServiceProblem::TooMany));
    assert_eq!(
        parse(vec![item("tcp", "x"), item("kubernetes", "x")]).check_set(),
        Ok(())
    );
    assert_eq!(
        parse(vec![item("tcp", "x"), item("tcp", "x")]).check_set(),
        Err(ServiceProblem::Duplicate {
            kind: ServiceKind::Tcp,
            name: "x".to_owned()
        })
    );
}

#[test]
fn wire_types_reject_unknown_fields_and_kinds() {
    for value in [
        json!({"services": [], "extra": 1}),
        json!({"services": [{"kind": "ssh", "name": "x"}]}),
        json!({"services": [{"kind": "tcp", "name": "x", "port": 1}]}),
        json!({"services": [{"kind": "tcp", "name": "x", "tcp": {"idle": 1}}]}),
        json!({"services": [{"kind": "kubernetes", "name": "x", "kubernetes": {"api": "kubeconfig"}}]}),
        json!({"services": [{"kind": "kubernetes", "name": "x", "kubernetes": {"audit": "none"}}]}),
        json!({"services": [{"kind": "postgres", "name": "x", "postgres": {}}]}),
        json!({"ssh_enabled": false}),
    ] {
        assert!(
            serde_json::from_value::<ServiceAnnouncement>(value.clone()).is_err(),
            "{value}"
        );
    }
    let off: ServiceAnnouncement =
        serde_json::from_value(json!({"ssh_enabled": false, "services": []})).unwrap();
    assert!(!off.ssh_enabled);

    let list = json!({"services": [{"kind": "tcp", "name": "grafana", "labels": {"team": "ops"},
                                    "connected": true}], "truncated": false});
    let parsed: ServiceList = serde_json::from_value(list.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), list);
    let mut extra = list;
    extra["services"][0]["address"] = json!("10.0.0.5:3000");
    assert!(serde_json::from_value::<ServiceList>(extra).is_err());
}

#[test]
fn the_node_service_list_carries_only_id_kind_and_name() {
    let wire = json!({"services": [
        {"id": "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11", "kind": "postgres", "name": "billing"}
    ]});
    let parsed: NodeServices = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(parsed.services[0].kind, ServiceKind::Postgres);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    for (path, value) in [
        ("/services/0/labels", json!({"env": "prod"})),
        ("/services/0/address", json!("10.0.0.5:5432")),
        ("/truncated", json!(false)),
    ] {
        let mut extra = wire.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        extra
            .pointer_mut(if parent.is_empty() { "" } else { parent })
            .unwrap()[key] = value;
        assert!(
            serde_json::from_value::<NodeServices>(extra).is_err(),
            "{path}"
        );
    }
    let mut unknown_kind = wire;
    unknown_kind["services"][0]["kind"] = json!("ssh");
    assert!(serde_json::from_value::<NodeServices>(unknown_kind).is_err());
}
