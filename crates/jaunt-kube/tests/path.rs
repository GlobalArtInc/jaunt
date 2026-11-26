use http::Method;
use jaunt_kube::{ApiRequest, MAX_QUERY_PARAMETERS, classify};

fn describe(request: &ApiRequest) -> String {
    match request {
        ApiRequest::Resource(resource) => {
            let mut text = format!(
                "{} {}/{}/{}",
                resource.verb().as_str(),
                resource.group(),
                resource.version(),
                resource.resource()
            );
            if let Some(subresource) = resource.subresource() {
                text.push('/');
                text.push_str(subresource);
            }
            text.push_str(&format!(
                " ns={} name={}",
                resource.namespace().unwrap_or("-"),
                resource.name().unwrap_or("-")
            ));
            if resource.is_watch() {
                text.push_str(" watch");
            }
            if resource.is_upgrade_candidate() {
                text.push_str(" upgrade");
            }
            text
        }
        ApiRequest::NonResource(kind) => format!("{kind:?}"),
        ApiRequest::Unknown => "unknown".to_owned(),
    }
}

fn method(name: &str) -> Method {
    Method::from_bytes(name.as_bytes()).unwrap()
}

#[test]
fn classifies_the_request_table() {
    let rows: &[(&str, &str, &str)] = &[
        ("GET", "/api/v1/pods", "list /v1/pods ns=- name=-"),
        (
            "GET",
            "/api/v1/namespaces/default/pods",
            "list /v1/pods ns=default name=-",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web",
            "get /v1/pods ns=default name=web",
        ),
        (
            "HEAD",
            "/api/v1/namespaces/default/pods/web",
            "get /v1/pods ns=default name=web",
        ),
        (
            "POST",
            "/api/v1/namespaces/default/pods",
            "create /v1/pods ns=default name=-",
        ),
        (
            "PUT",
            "/api/v1/namespaces/default/pods/web",
            "update /v1/pods ns=default name=web",
        ),
        (
            "PATCH",
            "/api/v1/namespaces/default/pods/web",
            "patch /v1/pods ns=default name=web",
        ),
        (
            "DELETE",
            "/api/v1/namespaces/default/pods/web",
            "delete /v1/pods ns=default name=web",
        ),
        (
            "DELETE",
            "/api/v1/namespaces/default/pods",
            "deletecollection /v1/pods ns=default name=-",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?watch=true",
            "watch /v1/pods ns=default name=- watch",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?resourceVersion=10&watch=1",
            "watch /v1/pods ns=default name=- watch",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?watch=false",
            "list /v1/pods ns=default name=-",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?watch=true&watch=false",
            "watch /v1/pods ns=default name=- watch",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web?watch=true",
            "get /v1/pods ns=default name=web",
        ),
        (
            "GET",
            "/api/v1/watch/namespaces/default/pods",
            "watch /v1/pods ns=default name=- watch",
        ),
        (
            "GET",
            "/api/v1/watch/namespaces/default/pods/web",
            "watch /v1/pods ns=default name=web watch",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?watch=1&fieldSelector=metadata.name%3Dweb",
            "watch /v1/pods ns=default name=web watch",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3D..",
            "list /v1/pods ns=default name=-",
        ),
        (
            "GET",
            "/api/v1/namespaces",
            "list /v1/namespaces ns=- name=-",
        ),
        (
            "GET",
            "/api/v1/namespaces/default",
            "get /v1/namespaces ns=default name=default",
        ),
        (
            "PUT",
            "/api/v1/namespaces/default/finalize",
            "update /v1/namespaces/finalize ns=default name=default",
        ),
        (
            "PUT",
            "/api/v1/namespaces/default/status",
            "update /v1/namespaces/status ns=default name=default",
        ),
        (
            "GET",
            "/api/v1/nodes/node-1",
            "get /v1/nodes ns=- name=node-1",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/",
            "list /v1/pods ns=default name=-",
        ),
        (
            "GET",
            "/apis/apps/v1/namespaces/prod/deployments",
            "list apps/v1/deployments ns=prod name=-",
        ),
        (
            "GET",
            "/apis/apps/v1/namespaces/prod/deployments?fieldSelector=metadata.name%3Dapi",
            "list apps/v1/deployments ns=prod name=api",
        ),
        (
            "PATCH",
            "/apis/apps/v1/namespaces/prod/deployments/api/scale",
            "patch apps/v1/deployments/scale ns=prod name=api",
        ),
        (
            "PUT",
            "/apis/apps/v1/namespaces/prod/deployments/api/status",
            "update apps/v1/deployments/status ns=prod name=api",
        ),
        (
            "GET",
            "/apis/rbac.authorization.k8s.io/v1/clusterroles/system:aggregate-to-admin",
            "get rbac.authorization.k8s.io/v1/clusterroles ns=- name=system:aggregate-to-admin",
        ),
        (
            "GET",
            "/apis/apps/v1/watch/deployments",
            "watch apps/v1/deployments ns=- name=- watch",
        ),
        (
            "POST",
            "/api/v1/namespaces/default/pods/web/exec?command=sh&stdin=true&tty=true",
            "exec /v1/pods/exec ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web/exec?command=sh",
            "exec /v1/pods/exec ns=default name=web upgrade",
        ),
        (
            "POST",
            "/api/v1/namespaces/default/pods/web/attach",
            "attach /v1/pods/attach ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web/portforward?ports=8080",
            "portforward /v1/pods/portforward ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web/log?follow=true",
            "log /v1/pods/log ns=default name=web",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web%2Fexec",
            "exec /v1/pods/exec ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web/exe%63",
            "exec /v1/pods/exec ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/services/web:80/proxy/healthz",
            "get /v1/services/proxy ns=default name=web:80 upgrade",
        ),
        (
            "POST",
            "/api/v1/namespaces/default/pods/web/proxy",
            "create /v1/pods/proxy ns=default name=web upgrade",
        ),
        (
            "GET",
            "/api/v1/nodes/node-1/proxy/metrics",
            "get /v1/nodes/proxy ns=- name=node-1 upgrade",
        ),
        (
            "POST",
            "/api/v1/namespaces/default/pods/web/eviction",
            "create /v1/pods/eviction ns=default name=web",
        ),
        (
            "GET",
            "/apis/subresources.example.io/v1/namespaces/vm/machines/m1/console",
            "get subresources.example.io/v1/machines/console ns=vm name=m1",
        ),
        (
            "DELETE",
            "/api/v1/namespaces/default/pods/web/exec",
            "unknown",
        ),
        ("POST", "/api/v1/namespaces/default/pods/web/log", "unknown"),
        ("GET", "/api/v1/pods/web/exec", "unknown"),
        (
            "GET",
            "/api/v1/namespaces/default/pods/web/exec/extra",
            "unknown",
        ),
        (
            "GET",
            "/api/v1/watch/namespaces/default/pods/web/log",
            "unknown",
        ),
        ("POST", "/api/v1/watch/namespaces/default/pods", "unknown"),
        ("GET", "/api/v1/watch", "unknown"),
        (
            "GET",
            "/api/v1/proxy/namespaces/default/pods/web",
            "unknown",
        ),
        ("OPTIONS", "/api/v1/pods", "unknown"),
        ("BREW", "/api/v1/pods", "unknown"),
        ("GET", "/api/v1/namespaces/%zz/pods", "unknown"),
        ("GET", "/api/v1/namespaces/de%00fault/pods", "unknown"),
        ("GET", "/api/v1/namespaces/de%0Afault/pods", "unknown"),
        ("GET", "/api/v1/namespaces/%FF/pods", "unknown"),
        ("GET", "/api/v1/namespaces/../pods", "unknown"),
        ("GET", "/api/v1/namespaces/a%2525b/pods", "unknown"),
        ("GET", "/api/v1//pods", "unknown"),
        ("GET", "/apis//v1/pods", "unknown"),
        ("GET", "/apis/Apps/v1/deployments", "unknown"),
        ("GET", "/api/V1/pods", "unknown"),
        ("GET", "/api/v1/Pods", "unknown"),
        (
            "GET",
            "/apis/example.com/v1-beta/widgets",
            "list example.com/v1-beta/widgets ns=- name=-",
        ),
        ("GET", "/apis/example.com/v1-/widgets", "unknown"),
        ("GET", "/apis/example.com/-v1/widgets", "unknown"),
        ("GET", "/apis/example.com/1v/widgets", "unknown"),
        (
            "GET",
            "/apis/example.com/v1-beta",
            "Discovery(GroupResources { group: \"example.com\", version: \"v1-beta\" })",
        ),
        (
            "GET",
            "/apis/apps/v1/watch/namespaces/x/deployments/d/status",
            "unknown",
        ),
        (
            "GET",
            "/api/v1/namespaces/default/pods/a+b",
            "get /v1/pods ns=default name=a+b",
        ),
        (
            "GET",
            "/apis/foo/v1/namespaces/x/pods/y/exec",
            "get foo/v1/pods/exec ns=x name=y upgrade",
        ),
        ("GET", "/version", "Version"),
        ("GET", "/healthz", "Healthz"),
        ("GET", "/livez/ping", "Livez"),
        ("GET", "/readyz?verbose", "Readyz"),
        ("GET", "/openapi/v2", "OpenApi"),
        ("GET", "/openapi/v3/apis/apps/v1", "OpenApi"),
        ("GET", "/api", "Discovery(CoreVersions)"),
        (
            "GET",
            "/api/v1",
            "Discovery(CoreResources { version: \"v1\" })",
        ),
        ("GET", "/apis", "Discovery(Groups)"),
        (
            "GET",
            "/apis/apps",
            "Discovery(GroupVersions { group: \"apps\" })",
        ),
        (
            "GET",
            "/apis/apps/v1/",
            "Discovery(GroupResources { group: \"apps\", version: \"v1\" })",
        ),
        ("POST", "/version", "unknown"),
        ("GET", "/openapi/v4", "unknown"),
        ("GET", "/metrics", "unknown"),
        ("GET", "/", "unknown"),
        ("GET", "", "unknown"),
        ("GET", "api/v1/pods", "unknown"),
    ];
    for (name, target, expected) in rows {
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (*target, None),
        };
        let request = classify(&method(name), path, query);
        assert_eq!(describe(&request), *expected, "{name} {target}");
    }
}

#[test]
fn a_version_may_be_at_most_sixty_three_bytes() {
    let longest = format!("v{}", "a".repeat(62));
    let too_long = format!("v{}", "a".repeat(63));
    let longest_path = format!("/apis/example.com/{longest}/widgets");
    let too_long_path = format!("/apis/example.com/{too_long}/widgets");
    assert_eq!(
        describe(&classify(&Method::GET, &longest_path, None)),
        format!("list example.com/{longest}/widgets ns=- name=-")
    );
    assert_eq!(
        classify(&Method::GET, &too_long_path, None),
        ApiRequest::Unknown
    );
}

#[test]
fn a_query_with_too_many_parameters_is_unknown() {
    let at_limit = vec!["limit=1"; MAX_QUERY_PARAMETERS].join("&");
    let over_limit = vec!["limit=1"; MAX_QUERY_PARAMETERS + 1].join("&");
    assert_ne!(
        classify(&Method::GET, "/api/v1/pods", Some(&at_limit)),
        ApiRequest::Unknown
    );
    assert_eq!(
        classify(&Method::GET, "/api/v1/pods", Some(&over_limit)),
        ApiRequest::Unknown
    );
}
