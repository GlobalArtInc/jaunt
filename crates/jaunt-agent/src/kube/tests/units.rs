use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, Version};
use jaunt_kube::{MAX_IMPERSONATION_GROUPS, classify};
use jaunt_proto::{AgentEventValue, KubeAccess, KubernetesAudit};

use super::support::{DNS_NAME, SESSION};
use crate::kube::audit::{Class, cut, describe};
use crate::kube::policy::{
    Decision, DecisionError, MAX_DECISION_USERS, Refused, client_ip, upstream_headers,
};
use crate::kube::request::{
    ExpectedHost, PathProblem, authority_matches, check_path, framing_supported,
};

fn access(users: &[&str], groups: &[&str]) -> KubeAccess {
    KubeAccess {
        users: users.iter().map(|user| (*user).to_owned()).collect(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
        record_exec: true,
        record_input: false,
    }
}

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn values(map: &HeaderMap, name: &str) -> Vec<String> {
    map.get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_host_must_be_the_cluster_name_with_at_most_the_default_port() {
    let expected = ExpectedHost::new(DNS_NAME);
    for (value, matches) in [
        ("prod-eu.kube.svc.test", true),
        ("PROD-EU.Kube.SVC.test", true),
        ("prod-eu.kube.svc.test:443", true),
        ("prod-eu.kube.svc.test:8443", false),
        ("prod-eu.kube.svc.test:", false),
        ("prod-eu.kube.svc.test:0443", false),
        ("prod-eu.kube.svc.test.", false),
        ("staging.kube.svc.test", false),
        ("user@prod-eu.kube.svc.test", false),
        ("prod-eu.kube.svc.test:443:443", false),
        ("", false),
    ] {
        assert_eq!(expected.matches(value), matches, "{value:?}");
    }
    assert!(!ExpectedHost::new("").matches(""));
}

#[test]
fn every_host_and_authority_of_a_request_must_match() {
    let expected = ExpectedHost::new(DNS_NAME);
    let request = |version: Version, uri: &str, hosts: &[&str]| {
        let mut request = Request::new(());
        *request.version_mut() = version;
        *request.uri_mut() = uri.parse().unwrap();
        for host in hosts {
            request
                .headers_mut()
                .append("host", HeaderValue::from_str(host).unwrap());
        }
        authority_matches(&request, &expected)
    };
    let own = "https://prod-eu.kube.svc.test/api";
    let other = "https://staging.kube.svc.test/api";
    for (version, uri, hosts, matches) in [
        (Version::HTTP_11, "/api", &[DNS_NAME][..], true),
        (Version::HTTP_11, "/api", &[][..], false),
        (Version::HTTP_11, "/api", &[DNS_NAME, DNS_NAME][..], false),
        (Version::HTTP_11, own, &[DNS_NAME][..], true),
        (Version::HTTP_11, own, &[][..], false),
        (Version::HTTP_11, other, &[DNS_NAME][..], false),
        (Version::HTTP_2, own, &[][..], true),
        (Version::HTTP_2, own, &[DNS_NAME][..], true),
        (Version::HTTP_2, own, &["staging.kube.svc.test"][..], false),
        (Version::HTTP_2, other, &[][..], false),
        (Version::HTTP_2, "/api", &[DNS_NAME][..], true),
        (Version::HTTP_2, "/api", &[][..], false),
    ] {
        assert_eq!(
            request(version, uri, hosts),
            matches,
            "{version:?} {uri} {hosts:?}"
        );
    }
}

#[test]
fn only_canonical_paths_pass() {
    for (path, expected) in [
        ("/", Ok(())),
        ("/api/v1/namespaces/default/pods", Ok(())),
        ("/api/v1/namespaces/default/configmaps/a%20b", Ok(())),
        ("/apis/apps/v1/deployments", Ok(())),
        ("/api/v1/namespaces/default/configmaps/%C3%A9", Ok(())),
        ("*", Err(PathProblem::NotOrigin)),
        ("", Err(PathProblem::NotOrigin)),
        ("/api/v1/pods/../secrets", Err(PathProblem::DotSegment)),
        ("/api/v1/./pods", Err(PathProblem::DotSegment)),
        ("/api/v1/pods/%2e%2e/secrets", Err(PathProblem::DotSegment)),
        ("/api/v1/pods/%2E", Err(PathProblem::DotSegment)),
        ("/api//v1/pods", Err(PathProblem::EmptySegment)),
        ("//api/v1/pods", Err(PathProblem::EmptySegment)),
        ("/api/v1/pods/", Err(PathProblem::EmptySegment)),
        ("/api/v1/pods/a%2fb", Err(PathProblem::EncodedSlash)),
        ("/api/v1/pods/a%2Fb", Err(PathProblem::EncodedSlash)),
        ("/api/v1/pods/a%00b", Err(PathProblem::EncodedNul)),
        ("/api/v1/pods/a%5cb", Err(PathProblem::Backslash)),
        ("/api/v1/pods/a\\b", Err(PathProblem::Backslash)),
        ("/api/v1/pods/a%ffb", Err(PathProblem::NotUtf8)),
        ("/api/v1/pods/a%0ab", Err(PathProblem::Control)),
        ("/api/v1/pods/a%C2%85b", Err(PathProblem::Control)),
        ("/api/v1/pods/a%zzb", Err(PathProblem::BadEscape)),
        ("/api/v1/pods/a%2", Err(PathProblem::BadEscape)),
        ("/api/v1/pods/a b", Err(PathProblem::Byte)),
        ("/api/v1/pods/\u{e9}", Err(PathProblem::Byte)),
    ] {
        assert_eq!(check_path(path), expected, "{path:?}");
    }
}

#[test]
fn transfer_codings_other_than_one_chunked_are_refused() {
    for (codings, supported) in [
        (&[][..], true),
        (&["chunked"][..], true),
        (&["Chunked"][..], true),
        (&["gzip, chunked"][..], false),
        (&["chunked, chunked"][..], false),
        (&["chunked", "chunked"][..], false),
        (&["identity"][..], false),
    ] {
        let mut map = HeaderMap::new();
        for coding in codings {
            map.append("transfer-encoding", HeaderValue::from_str(coding).unwrap());
        }
        assert_eq!(framing_supported(&map), supported, "{codings:?}");
    }
}

#[test]
fn the_classes_and_the_audit_rule_follow_the_classifier() {
    let mutating = KubernetesAudit::Mutating;
    for (method, path, query, class, audited) in [
        (
            Method::GET,
            "/api/v1/namespaces/a/pods",
            None,
            Class::Read,
            false,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods/web",
            None,
            Class::Read,
            false,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods/web/log",
            None,
            Class::Read,
            false,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods",
            Some("watch=1"),
            Class::Watch,
            false,
        ),
        (Method::GET, "/api", None, Class::Read, false),
        (Method::GET, "/version", None, Class::Read, false),
        (
            Method::GET,
            "/api/v1/namespaces/a/secrets",
            None,
            Class::Read,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/secrets/token",
            None,
            Class::Read,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/secrets",
            Some("watch=1"),
            Class::Watch,
            true,
        ),
        (
            Method::POST,
            "/api/v1/namespaces/a/configmaps",
            None,
            Class::Write,
            true,
        ),
        (
            Method::PUT,
            "/api/v1/namespaces/a/configmaps/c",
            None,
            Class::Write,
            true,
        ),
        (
            Method::PATCH,
            "/api/v1/namespaces/a/configmaps/c",
            None,
            Class::Write,
            true,
        ),
        (
            Method::DELETE,
            "/api/v1/namespaces/a/configmaps/c",
            None,
            Class::Write,
            true,
        ),
        (
            Method::DELETE,
            "/api/v1/namespaces/a/configmaps",
            None,
            Class::Write,
            true,
        ),
        (
            Method::POST,
            "/api/v1/namespaces/a/pods/web/exec",
            None,
            Class::Exec,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods/web/attach",
            None,
            Class::Exec,
            true,
        ),
        (
            Method::POST,
            "/api/v1/namespaces/a/pods/web/portforward",
            None,
            Class::Exec,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods/web/proxy/metrics",
            None,
            Class::Exec,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/services/s/proxy",
            None,
            Class::Exec,
            true,
        ),
        (
            Method::GET,
            "/api/v1/proxy/namespaces/a/pods/web",
            None,
            Class::Write,
            true,
        ),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods/../secrets",
            None,
            Class::Write,
            true,
        ),
        (Method::GET, "/totally/unknown", None, Class::Write, true),
        (Method::POST, "/version", None, Class::Write, true),
        (
            Method::OPTIONS,
            "/api/v1/namespaces/a/pods",
            None,
            Class::Write,
            true,
        ),
    ] {
        let classified = classify(&method, path, query);
        let described = describe(&classified, mutating);
        assert_eq!(
            (described.class, described.audited),
            (class, audited),
            "{method} {path} {query:?}"
        );
        let all = describe(&classified, KubernetesAudit::All);
        assert!(all.audited, "{method} {path} {query:?}");
        assert_eq!(all.class, class, "{method} {path} {query:?}");
    }
}

#[test]
fn request_fields_are_the_classified_shape_cut_at_the_spec_limits() {
    let text =
        |described: &crate::kube::audit::Described, name: &str| match described.fields.get(name) {
            Some(AgentEventValue::Text(text)) => Some(text.clone()),
            _ => None,
        };
    let classified = classify(
        &Method::PATCH,
        "/apis/apps/v1/namespaces/team/deployments/web/scale",
        Some("fieldManager=kubectl&labelSelector=app%3Dsecret"),
    );
    let described = describe(&classified, KubernetesAudit::Mutating);
    for (field, value) in [
        ("verb", Some("patch")),
        ("api_group", Some("apps")),
        ("api_version", Some("v1")),
        ("resource", Some("deployments")),
        ("subresource", Some("scale")),
        ("namespace", Some("team")),
        ("name", Some("web")),
    ] {
        assert_eq!(text(&described, field).as_deref(), value, "{field}");
    }
    assert_eq!(described.fields.get("status"), None);

    let core = describe(
        &classify(&Method::POST, "/api/v1/namespaces/a/configmaps", None),
        KubernetesAudit::Mutating,
    );
    assert_eq!(text(&core, "api_group"), None);
    assert_eq!(text(&core, "name"), None);

    let unknown = describe(
        &classify(&Method::GET, "/a/b?x=1", None),
        KubernetesAudit::Mutating,
    );
    assert_eq!(text(&unknown, "verb").as_deref(), Some("unknown"));
    assert_eq!(unknown.fields.get("resource"), None);

    let long = "%C3%A9".repeat(200);
    let classified = classify(
        &Method::DELETE,
        &format!("/api/v1/namespaces/{long}/configmaps/{long}"),
        None,
    );
    let described = describe(&classified, KubernetesAudit::Mutating);
    let name = text(&described, "name").unwrap();
    let namespace = text(&described, "namespace").unwrap();
    assert_eq!((name.len(), namespace.len()), (254, 128));
    assert!(name.chars().all(|ch| ch == '\u{e9}'));

    for (input, max, expected) in [
        ("abcdef", 3, "abc"),
        ("ab\u{e9}", 3, "ab"),
        ("\u{e9}\u{e9}", 3, "\u{e9}"),
        ("short", 64, "short"),
        ("", 4, ""),
    ] {
        assert_eq!(cut(input, max), expected, "{input:?} {max}");
    }
}

#[test]
fn a_decision_is_usable_only_when_every_value_is_a_plain_kubernetes_name() {
    let many: Vec<String> = (0..=MAX_IMPERSONATION_GROUPS)
        .map(|index| format!("group-{index}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let duplicated = vec!["view"; MAX_IMPERSONATION_GROUPS + 1];
    let users_over: Vec<String> = (0..=MAX_DECISION_USERS)
        .map(|index| format!("user-{index}"))
        .collect();
    let users_over: Vec<&str> = users_over.iter().map(String::as_str).collect();
    for (users, groups, session, expected) in [
        (&["alice@example.com"][..], &["view"][..], SESSION, Ok(())),
        (
            &["alice", "alice"][..],
            &["view", "view"][..],
            SESSION,
            Ok(()),
        ),
        (&[][..], &["view"][..], SESSION, Err(DecisionError::NoUser)),
        (
            &["alice", "system:admin"][..],
            &[][..],
            SESSION,
            Err(DecisionError::SystemUser),
        ),
        (
            &["alice"][..],
            &duplicated[..],
            SESSION,
            Err(DecisionError::TooManyGroups),
        ),
        (
            &users_over[..],
            &[][..],
            SESSION,
            Err(DecisionError::TooManyUsers),
        ),
        (&users_over[..MAX_DECISION_USERS], &[][..], SESSION, Ok(())),
        (
            &["system:admin"][..],
            &[][..],
            SESSION,
            Err(DecisionError::SystemUser),
        ),
        (
            &["SYSTEM:admin"][..],
            &[][..],
            SESSION,
            Err(DecisionError::SystemUser),
        ),
        (
            &["alice"][..],
            &["system:masters"][..],
            SESSION,
            Err(DecisionError::SystemGroup),
        ),
        (
            &["alice"][..],
            &["System:Masters"][..],
            SESSION,
            Err(DecisionError::SystemGroup),
        ),
        (
            &["alice\r\nImpersonate-Group: x"][..],
            &[][..],
            SESSION,
            Err(DecisionError::User),
        ),
        (
            &["alice"][..],
            &["view\nx"][..],
            SESSION,
            Err(DecisionError::Group),
        ),
        (
            &["alice", "bob\u{0}"][..],
            &[][..],
            SESSION,
            Err(DecisionError::User),
        ),
        (
            &["alice"][..],
            &many[..MAX_IMPERSONATION_GROUPS],
            SESSION,
            Ok(()),
        ),
        (
            &["alice"][..],
            &many[..],
            SESSION,
            Err(DecisionError::TooManyGroups),
        ),
        (
            &["alice"][..],
            &[][..],
            "k-bad session",
            Err(DecisionError::Session),
        ),
    ] {
        let decided = Decision::from_access(&access(users, groups), session).map(|_| ());
        assert_eq!(decided, expected, "{users:?} {groups:?} {session:?}");
    }
}

#[test]
fn the_headers_to_the_api_follow_the_impersonation_table() {
    let one = Decision::from_access(&access(&["alice"], &["view", "dev"]), SESSION).unwrap();
    let several =
        Decision::from_access(&access(&["alice", "bob"], &["view", "dev"]), SESSION).unwrap();
    let applied = |decision: &Decision, pairs: &[(&str, &str)]| {
        upstream_headers(headers(pairs), decision, None).map(|map| {
            (
                values(&map, "impersonate-user"),
                values(&map, "impersonate-group"),
            )
        })
    };
    let both = vec!["view".to_owned(), "dev".to_owned()];
    let user = |name: &str| vec![name.to_owned()];
    assert_eq!(applied(&one, &[]), Ok((user("alice"), both.clone())));
    assert_eq!(
        applied(&one, &[("impersonate-user", "alice")]),
        Ok((user("alice"), both.clone()))
    );
    assert_eq!(
        applied(&one, &[("impersonate-user", "bob")]),
        Err(Refused::UserNotAllowed)
    );
    assert_eq!(applied(&several, &[]), Err(Refused::ChooseUser));
    assert_eq!(
        applied(&several, &[("impersonate-user", "bob")]),
        Ok((user("bob"), both.clone()))
    );
    assert_eq!(
        applied(&several, &[("impersonate-user", "carol")]),
        Err(Refused::UserNotAllowed)
    );
    assert_eq!(
        applied(
            &several,
            &[("impersonate-user", "alice"), ("impersonate-user", "bob")]
        ),
        Err(Refused::SeveralUsers)
    );
    assert_eq!(
        applied(
            &one,
            &[("impersonate-group", "dev"), ("impersonate-group", "dev")]
        ),
        Ok((user("alice"), vec!["dev".to_owned()]))
    );
    assert_eq!(
        applied(&one, &[("impersonate-group", "admin")]),
        Err(Refused::GroupNotAllowed)
    );
    assert_eq!(
        applied(&one, &[("impersonate-group", "system:masters")]),
        Err(Refused::GroupNotAllowed)
    );
    for refused in [
        "impersonate-uid",
        "impersonate-extra-scopes",
        "impersonate-extra-jaunt-session-id",
        "impersonate-future",
    ] {
        assert_eq!(
            applied(&one, &[(refused, "x")]),
            Err(Refused::Header),
            "{refused}"
        );
    }
    for lookalike in [
        "impersonate_user",
        "Impersonate_Group",
        "impersonate_extra_x",
        "authorization_",
        "x_remote_user",
    ] {
        let expected = if lookalike == "authorization_" {
            Ok((user("alice"), both.clone()))
        } else {
            Err(Refused::LookalikeHeader)
        };
        assert_eq!(applied(&one, &[(lookalike, "x")]), expected, "{lookalike}");
    }
}

#[test]
fn client_identity_and_hop_by_hop_headers_never_reach_the_api() {
    let decision = Decision::from_access(&access(&["alice"], &["view"]), SESSION).unwrap();
    let forwarded = upstream_headers(
        headers(&[
            ("authorization", "Bearer client-token"),
            ("impersonate-user", "alice"),
            ("x-remote-user", "admin"),
            ("x-remote-group", "system:masters"),
            ("connection", "keep-alive, impersonate-user, x-custom-hop"),
            ("x-custom-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic x"),
            ("proxy-connection", "keep-alive"),
            ("te", "trailers"),
            ("trailer", "x-checksum"),
            ("transfer-encoding", "chunked"),
            ("upgrade", "h2c"),
            ("host", DNS_NAME),
            ("content-length", "5"),
            ("expect", "100-continue"),
            ("accept", "application/json"),
            ("user-agent", "kubectl/v1.31"),
        ]),
        &decision,
        None,
    )
    .unwrap();
    let mut names: Vec<&str> = forwarded.keys().map(HeaderName::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "accept",
            "impersonate-extra-jaunt-session-id",
            "impersonate-group",
            "impersonate-user",
            "user-agent"
        ]
    );
    let mut odd = headers(&[("x-listed", "1"), ("accept", "*/*")]);
    odd.append(
        "connection",
        HeaderValue::from_bytes(b"x-unreadable\xff, x-listed").unwrap(),
    );
    let forwarded_odd = upstream_headers(odd, &decision, None).unwrap();
    assert!(!forwarded_odd.contains_key("x-listed"));
    assert!(!forwarded_odd.contains_key("connection"));
    assert!(forwarded_odd.contains_key("accept"));
    assert_eq!(values(&forwarded, "impersonate-user"), ["alice"]);
    assert_eq!(
        values(&forwarded, "impersonate-extra-jaunt-session-id"),
        [SESSION]
    );
}

#[test]
fn the_documented_limits_are_the_built_in_ones() {
    use std::time::Duration;

    use crate::kube::{KUBE_LIMITS, KubernetesUpstream};

    assert_eq!(KUBE_LIMITS.max_header_bytes, 64 * 1024);
    assert_eq!(KUBE_LIMITS.max_concurrent_streams, 128);
    assert_eq!(KUBE_LIMITS.idle_keep_alive, Duration::from_secs(60));
    assert_eq!(
        (KUBE_LIMITS.ping_interval, KUBE_LIMITS.ping_timeout),
        (Duration::from_secs(30), Duration::from_secs(20))
    );
    assert_eq!(KUBE_LIMITS.head_timeout, Duration::from_secs(60));
    assert_eq!(KUBE_LIMITS.connect_timeout, Duration::from_secs(10));
    assert!(KUBE_LIMITS.shutdown_grace < Duration::from_secs(1));
    assert_eq!(KUBE_LIMITS.token_reread, Duration::from_secs(60));
    assert_eq!(
        (
            KUBE_LIMITS.api_connections,
            KUBE_LIMITS.api_streams_per_connection
        ),
        (16, 100)
    );
    assert_eq!(KUBE_LIMITS.stream_window, 128 * 1024);
    assert_eq!(KUBE_LIMITS.progress_timeout, Duration::from_secs(60));
    assert_eq!(KUBE_LIMITS.token_check_every, Duration::from_secs(1));
    assert_eq!(
        (KUBE_LIMITS.slots_per_user, KUBE_LIMITS.slots_per_connection),
        (256, 128)
    );
    assert_eq!(KUBE_LIMITS.slot_wait, Duration::from_secs(60));
    assert_eq!(KUBE_LIMITS.api_connection_window(), 100 * 128 * 1024);
    for (streams, window) in [
        (100, 128 * 1024),
        (1, 65_535),
        (2, 16 * 1024),
        (100_000, 1 << 20),
    ] {
        let limits = crate::kube::KubeLimits {
            api_streams_per_connection: streams,
            stream_window: window,
            ..KUBE_LIMITS
        };
        let connection = u64::from(limits.api_connection_window());
        assert!(
            connection >= (streams as u64 * u64::from(window)).min((1 << 31) - 1),
            "{streams} x {window}"
        );
        assert!(connection < 1 << 31);
    }
    let in_cluster = KubernetesUpstream::default();
    assert_eq!(in_cluster.base_url, "https://kubernetes.default.svc");
    assert_eq!(
        in_cluster.ca_file.to_str(),
        Some("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
    );
    assert_eq!(
        in_cluster.token_file.to_str(),
        Some("/var/run/secrets/kubernetes.io/serviceaccount/token")
    );
}

#[test]
fn only_an_https_origin_is_accepted_as_the_api_server() {
    use std::time::SystemTime;

    use crate::kube::upstream::Upstream;
    use crate::kube::{KUBE_LIMITS, KubernetesUpstream};
    use crate::testkit::ManualClock;

    for (base_url, accepted) in [
        ("https://kubernetes.default.svc", true),
        ("https://kubernetes.default.svc/", true),
        ("https://10.96.0.1:443", true),
        ("https://[fd00::1]:6443", true),
        ("http://kubernetes.default.svc", false),
        ("https://kubernetes.default.svc/prefix", false),
        ("https://kubernetes.default.svc/?x=1", false),
        ("https://user@kubernetes.default.svc", false),
        ("kubernetes.default.svc", false),
        ("", false),
    ] {
        let settings = KubernetesUpstream {
            base_url: base_url.to_owned(),
            ..KubernetesUpstream::default()
        };
        let built = Upstream::new(&settings, ManualClock::new(SystemTime::now()), KUBE_LIMITS);
        assert_eq!(built.is_ok(), accepted, "{base_url:?}");
    }
}

#[test]
fn origin_headers_are_replaced_by_the_tunnel_address_only() {
    let decision = Decision::from_access(&access(&["alice"], &["view"]), SESSION).unwrap();
    let client = headers(&[
        ("x-forwarded-for", "1.2.3.4"),
        ("X-Forwarded-Host", "evil.example"),
        ("x-forwarded-proto", "http"),
        ("x-forwarded-port", "80"),
        ("x-forwarded-anything", "1"),
        ("forwarded", "for=1.2.3.4"),
        ("x-real-ip", "1.2.3.4"),
        ("via", "1.1 evil"),
        ("audit-id", "00000000-aaaa"),
        ("keep-alive", "timeout=5"),
        ("accept", "*/*"),
    ]);
    for (addr, expected) in [
        ("203.0.113.5:40000", Some("203.0.113.5")),
        ("[2001:db8::7]:40000", Some("2001:db8::7")),
        ("198.51.100.9", Some("198.51.100.9")),
        ("2001:db8::8", Some("2001:db8::8")),
        ("gate.example:443", None),
        ("", None),
        ("203.0.113.5:40000, 1.2.3.4", None),
    ] {
        let forwarded = upstream_headers(client.clone(), &decision, client_ip(addr)).unwrap();
        let mut names: Vec<&str> = forwarded.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        let mut wanted = vec![
            "accept",
            "impersonate-extra-jaunt-session-id",
            "impersonate-group",
            "impersonate-user",
        ];
        if expected.is_some() {
            wanted.push("x-forwarded-for");
        }
        wanted.sort_unstable();
        assert_eq!(names, wanted, "{addr:?}");
        let set = values(&forwarded, "x-forwarded-for");
        assert_eq!(set, expected.into_iter().collect::<Vec<_>>(), "{addr:?}");
    }
}

#[test]
fn only_watches_and_followed_logs_wait_for_their_head_without_a_limit() {
    use crate::kube::request::answers_late;
    let log = "/api/v1/namespaces/a/pods/web/log";
    for (method, path, query, late) in [
        (
            Method::GET,
            "/api/v1/namespaces/a/pods",
            Some("watch=1"),
            true,
        ),
        (Method::GET, "/api/v1/watch/namespaces/a/pods", None, true),
        (Method::GET, log, Some("follow=true"), true),
        (Method::GET, log, Some("container=c&follow=1"), true),
        (Method::GET, log, Some("follow=%74rue"), true),
        (Method::GET, log, Some("follow"), true),
        (Method::GET, log, Some("follow=f"), true),
        (Method::GET, log, Some("follow=fAlSe"), false),
        (Method::GET, log, Some("follow=false&follow=true"), false),
        (Method::GET, log, Some("follow=false"), false),
        (Method::GET, log, Some("follow=0"), false),
        (Method::GET, log, Some("follow=true;x=1"), false),
        (Method::GET, log, None, false),
        (
            Method::GET,
            "/api/v1/namespaces/a/pods",
            Some("follow=true"),
            false,
        ),
        (Method::GET, "/api/v1/namespaces/a/pods", None, false),
        (Method::POST, "/api/v1/namespaces/a/configmaps", None, false),
    ] {
        let classified = classify(&method, path, query);
        assert_eq!(
            answers_late(&classified, query),
            late,
            "{method} {path} {query:?}"
        );
    }
}

#[tokio::test]
async fn nothing_is_counted_or_audited_after_the_session_ended() {
    use std::sync::Arc;
    use std::time::SystemTime;

    use jaunt_proto::ServiceOutcome;

    use crate::kube::audit::SessionAudit;
    use crate::kube::tests::support::CapturedEvents;
    use crate::runtime::events::{EventSink, SINK_LIMITS};
    use crate::testkit::ManualClock;

    let clock = ManualClock::new(SystemTime::now());
    let sink = EventSink::new(
        Arc::new(CapturedEvents::default()),
        clock.clone(),
        Arc::new(|| 1.0),
        SINK_LIMITS,
    );
    let audit = Arc::new(SessionAudit::new(
        sink.session(SESSION),
        clock,
        KubernetesAudit::Mutating,
    ));
    let write = || {
        describe(
            &classify(&Method::POST, "/api/v1/namespaces/a/configmaps", None),
            KubernetesAudit::Mutating,
        )
    };
    assert!(audit.begin(write()).is_some());
    audit.end(ServiceOutcome::Closed, 0, 0);
    assert!(audit.begin(write()).is_none());
    assert_eq!(sink.counters().emitted, 2);
}

#[test]
fn the_bearer_token_is_a_sensitive_header() {
    use std::time::SystemTime;

    use crate::kube::KUBE_LIMITS;
    use crate::kube::token::TokenSource;
    use crate::testkit::ManualClock;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    std::fs::write(&path, "abc.def\n").unwrap();
    let source = TokenSource::new(path, ManualClock::new(SystemTime::now()), KUBE_LIMITS);
    let bearer = source.bearer().unwrap();
    assert!(bearer.is_sensitive());
    assert_eq!(bearer.to_str().unwrap(), "Bearer abc.def");
    assert!(!format!("{bearer:?}").contains("abc.def"));
}
