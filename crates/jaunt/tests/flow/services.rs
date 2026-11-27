use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::lock::ProfileLock;
use jaunt::profile::ProfileName;
use jaunt::store::ProfileStore;
use jaunt::user_x509::{IssuedError, UserCertificate, X509Error, ensure_x509};
use jaunt_proto::{
    NodeList, NodeSummary, ServiceKind, ServiceList, ServiceSummary, X509CertificateRequest,
};
use serde_json::Value;

use crate::cli::{jaunt, stderr, stdout, write_profile};
use crate::support::{
    API_TOKEN, Behavior, CertSpec, FakeServer, X509Reply, ca_key, new_key_data, now_secs,
    serial_section, sign,
};

fn service(
    kind: ServiceKind,
    name: &str,
    labels: &[(&str, &str)],
    connected: bool,
) -> ServiceSummary {
    ServiceSummary {
        kind,
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        connected,
    }
}

fn listing_server(services: Option<Vec<ServiceSummary>>) -> FakeServer {
    FakeServer::start(Behavior {
        nodes: vec![NodeSummary {
            name: "web-01".to_owned(),
            labels: [("env".to_owned(), "prod".to_owned())].into(),
            hostname: "web-01.internal".to_owned(),
            connected: true,
        }],
        services,
        ..Behavior::default()
    })
}

fn signed_in(server: &FakeServer) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    write_profile(
        &home,
        &server.url(),
        i64::try_from(now_secs() + 3600).unwrap(),
    );
    (root, home)
}

#[test]
fn each_kind_is_listed_as_a_table_or_as_the_server_json() {
    let _serial = serial_section();
    let server = listing_server(Some(vec![
        service(ServiceKind::Kubernetes, "prod-eu", &[], true),
        service(ServiceKind::Postgres, "orders", &[("team", "shop")], false),
        service(ServiceKind::Tcp, "grafana", &[], true),
    ]));
    let (_root, home) = signed_in(&server);
    let texts = [
        (
            "kube",
            "KIND  NAME     LABELS  CONNECTED\nkube  prod-eu  -       yes\n",
        ),
        (
            "db",
            "KIND  NAME    LABELS     CONNECTED\ndb    orders  team=shop  no\n",
        ),
        (
            "tcp",
            "KIND  NAME     LABELS  CONNECTED\ntcp   grafana  -       yes\n",
        ),
        (
            "all",
            "KIND  NAME     LABELS     CONNECTED\nssh   web-01   env=prod   yes\nkube  prod-eu  -          yes\ndb    orders   team=shop  no\ntcp   grafana  -          yes\n",
        ),
    ];
    for (kind, expected) in texts {
        let listed = jaunt(&home, &["ls", "--kind", kind]);
        assert_eq!(listed.status.code(), Some(0), "{kind}: {}", stderr(&listed));
        assert_eq!(stdout(&listed), expected, "{kind}");
    }
    for (kind, names) in [
        ("kube", ["prod-eu"]),
        ("db", ["orders"]),
        ("tcp", ["grafana"]),
    ] {
        let listed = jaunt(&home, &["ls", "--kind", kind, "--format", "json"]);
        assert_eq!(listed.status.code(), Some(0), "{kind}: {}", stderr(&listed));
        let parsed: ServiceList = serde_json::from_str(&stdout(&listed)).unwrap();
        let found: Vec<&str> = parsed.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(found, names, "{kind}");
    }
    let everything = jaunt(&home, &["ls", "--kind", "all", "--format", "json"]);
    let parsed: Value = serde_json::from_str(&stdout(&everything)).unwrap();
    let nodes: NodeList = serde_json::from_value(parsed["nodes"].clone()).unwrap();
    let services: ServiceList = serde_json::from_value(parsed["services"].clone()).unwrap();
    assert_eq!(nodes.nodes.len(), 1);
    assert_eq!(services.services.len(), 3);
}

#[test]
fn a_server_without_the_service_list_is_named_in_one_line() {
    let _serial = serial_section();
    let server = listing_server(None);
    let (_root, home) = signed_in(&server);
    let message = "this server does not list Kubernetes clusters, databases or TCP services";

    for kind in ["kube", "db", "tcp"] {
        let listed = jaunt(&home, &["ls", "--kind", kind]);
        assert_eq!(listed.status.code(), Some(1), "{kind}");
        assert_eq!(stdout(&listed), "", "{kind}");
        assert_eq!(stderr(&listed), format!("jaunt: {message}\n"), "{kind}");
    }
    let everything = jaunt(&home, &["ls", "--kind", "all"]);
    assert_eq!(everything.status.code(), Some(0), "{}", stderr(&everything));
    assert!(
        stderr(&everything).starts_with(&format!("jaunt: note: {message}; only hosts are shown\n")),
        "{}",
        stderr(&everything)
    );
    assert_eq!(
        stdout(&everything),
        "KIND  NAME    LABELS    CONNECTED\nssh   web-01  env=prod  yes\n"
    );
}

fn x509_profile(server: &FakeServer, home: &Path) -> (ProfileStore, i64) {
    let valid_before = now_secs() + 3600;
    write_profile(home, &server.url(), i64::try_from(valid_before).unwrap());
    let mut spec = CertSpec::user(new_key_data(), 3600);
    spec.valid_before = valid_before;
    let certificate = sign(&ca_key(), &spec).to_openssh().unwrap();
    fs::write(home.join("default/id_ed25519-cert.pub"), certificate).unwrap();
    (
        ProfileStore::new(home, &ProfileName::default_name()),
        i64::try_from(valid_before).unwrap(),
    )
}

fn lock(store: &ProfileStore) -> ProfileLock {
    ProfileLock::acquire(
        store.home(),
        &store.lock_path(),
        Instant::now() + Duration::from_secs(5),
        &mut || {},
    )
    .unwrap()
}

#[test]
fn x509_issuance_over_http_carries_the_token_and_names_a_server_that_does_not_issue() {
    let now = i64::try_from(now_secs()).unwrap();
    type Expected = fn(&Result<UserCertificate, X509Error>) -> bool;
    let cases: [(X509Reply, Expected); 3] = [
        (X509Reply::Missing, |outcome| {
            matches!(outcome, Err(X509Error::NotOffered))
        }),
        (X509Reply::NotConfigured, |outcome| {
            matches!(outcome, Err(X509Error::NotOffered))
        }),
        (X509Reply::Garbage, |outcome| {
            matches!(outcome, Err(X509Error::Refused(IssuedError::Unreadable)))
        }),
    ];
    for (reply, expected) in cases {
        let server = FakeServer::start(Behavior {
            x509: reply,
            ..Behavior::default()
        });
        let root = tempfile::tempdir().unwrap();
        let (store, _) = x509_profile(&server, &root.path().join("state"));

        let outcome = ensure_x509(&store, &lock(&store), now);

        assert!(expected(&outcome), "{outcome:?}");
        assert!(!store.x509_dir().join("cert.pem").exists());
        assert_eq!(server.seen(|seen| seen.x509_requests.len()), 1);
    }

    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let ssh_end = now + 3600;
    let server = FakeServer::start(Behavior {
        x509: X509Reply::Issue {
            valid_before: ssh_end,
        },
        ..Behavior::default()
    });
    let (store, ssh_valid_before) = x509_profile(&server, &home);

    let issued = ensure_x509(&store, &lock(&store), now).unwrap();

    assert_eq!(issued.valid_before, ssh_valid_before.min(ssh_end));
    for path in [&issued.key_path, &issued.certificate_path] {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let request = server.seen(|seen| seen.x509_requests[0].clone());
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/v1/certificates/x509");
    assert_eq!(
        request.header("authorization"),
        Some(format!("Bearer {API_TOKEN}").as_str())
    );
    let body: X509CertificateRequest = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(STANDARD.decode(body.public_key).unwrap().len(), 44);
}
