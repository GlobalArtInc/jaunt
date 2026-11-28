use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use jaunt_proto::KubernetesAudit;

use super::support::{
    Alpn, CLIENT_ADDR, CONFIGMAPS, H2, Kube, Options, PODS, TestBody, alice, body_text, h2,
    h2_request, int, kube, text,
};
use crate::kube::audit::{REQUEST, SESSION_END, SESSION_START};
use crate::runtime::events::{SINK_LIMITS, SinkLimits};
use crate::testkit::eventually;

type Shape = (String, Option<String>, Option<String>, Option<i64>);

async fn send(client: &mut H2, method: Method, path: &str, body: TestBody) -> StatusCode {
    let mut request = h2_request(method, path, body);
    request
        .headers_mut()
        .insert("x-custom", HeaderValue::from_static("HEADER-SECRET"));
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_static("Bearer CLIENT-SECRET"),
    );
    body_text(client.send_request(request).await.unwrap())
        .await
        .0
}

#[tokio::test]
async fn a_session_reports_its_identity_counts_its_classes_and_audits_only_what_the_rules_name() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let exec = format!("{PODS}/web/exec?command=QUERY-SECRET");
    for (method, path, status) in [
        (
            Method::GET,
            format!("{PODS}?labelSelector=QUERY-SECRET"),
            StatusCode::OK,
        ),
        (Method::GET, format!("{PODS}/web/log"), StatusCode::OK),
        (
            Method::GET,
            "/api/v1/namespaces/default/secrets/db".to_owned(),
            StatusCode::OK,
        ),
        (
            Method::POST,
            format!("{CONFIGMAPS}?fieldManager=QUERY-SECRET"),
            StatusCode::OK,
        ),
        (Method::DELETE, format!("{CONFIGMAPS}/old"), StatusCode::OK),
        (
            Method::GET,
            "/api/v1/namespaces/default/pods/../secrets".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            Method::GET,
            "/not/a/kubernetes/path".to_owned(),
            StatusCode::OK,
        ),
        (Method::POST, exec.clone(), StatusCode::FORBIDDEN),
    ] {
        let body = TestBody::text("{\"data\":\"BODY-SECRET\"}");
        assert_eq!(
            send(&mut client, method.clone(), &path, body).await,
            status,
            "{method} {path}"
        );
    }
    let watch = client
        .send_request(h2_request(
            Method::GET,
            &format!("{PODS}?watch=1"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(watch.status(), StatusCode::OK);
    session.cancel.cancel();
    session.finished().await;
    drop(watch);

    let start = kube_api.events_settled(SESSION_START, 1).await;
    assert_eq!(start.len(), 1);
    assert_eq!(
        text(&start[0], "user").as_deref(),
        Some("alice@example.com")
    );
    assert_eq!(text(&start[0], "groups").as_deref(), Some("view,dev"));
    assert_eq!(text(&start[0], "client_addr").as_deref(), Some(CLIENT_ADDR));
    assert!(!start[0].fields.contains_key("service"));

    let end = kube_api.events_settled(SESSION_END, 1).await;
    assert_eq!(end.len(), 1);
    for (field, expected) in [
        ("requests_read", 3),
        ("requests_watch", 1),
        ("requests_write", 4),
        ("requests_exec", 1),
    ] {
        assert_eq!(int(&end[0], field), Some(expected), "{field}");
    }
    assert!(int(&end[0], "bytes_up").unwrap() > 0);
    assert!(int(&end[0], "bytes_down").unwrap() > 0);
    assert_eq!(text(&end[0], "reason").as_deref(), Some("closed"));

    let requests = kube_api.captured.named(REQUEST);
    let mut shapes: Vec<Shape> = requests
        .iter()
        .map(|event| {
            (
                text(event, "verb").unwrap(),
                text(event, "resource"),
                text(event, "name"),
                int(event, "status"),
            )
        })
        .collect();
    shapes.sort();
    let owned = |verb: &str, resource: Option<&str>, name: Option<&str>, status: i64| {
        (
            verb.to_owned(),
            resource.map(str::to_owned),
            name.map(str::to_owned),
            Some(status),
        )
    };
    assert_eq!(
        shapes,
        [
            owned("create", Some("configmaps"), None, 200),
            owned("delete", Some("configmaps"), Some("old"), 200),
            owned("exec", Some("pods"), Some("web"), 403),
            owned("get", Some("secrets"), Some("db"), 200),
            owned("unknown", None, None, 200),
            owned("unknown", None, None, 400),
        ]
    );
    for event in &requests {
        assert!(int(event, "duration_ms").is_some(), "{event:?}");
        assert!(!event.fields.contains_key("observed_at"));
    }
    let everything = serde_json::to_string(&kube_api.captured.events()).unwrap();
    for secret in [
        "QUERY-SECRET",
        "BODY-SECRET",
        "HEADER-SECRET",
        "CLIENT-SECRET",
        "sa-token",
    ] {
        assert!(
            !everything.contains(secret),
            "{secret} leaked: {everything}"
        );
    }
}

#[tokio::test]
async fn audit_all_writes_every_request_and_a_hostile_decision_still_starts_and_ends() {
    let kube_api = Kube::with(Options {
        mode: KubernetesAudit::All,
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    for path in [
        PODS.to_owned(),
        format!("{PODS}/web"),
        "/version".to_owned(),
        "/api".to_owned(),
    ] {
        assert_eq!(
            send(&mut client, Method::GET, &path, TestBody::empty()).await,
            StatusCode::OK
        );
    }
    session.cancel.cancel();
    session.finished().await;
    let requests = kube_api.events_settled(REQUEST, 4).await;
    let mut verbs: Vec<String> = requests
        .iter()
        .map(|event| text(event, "verb").unwrap())
        .collect();
    verbs.sort();
    assert_eq!(verbs, ["get", "get", "get", "list"]);

    let mut hostile = kube_api
        .open(kube(&["alice@example.com"], &["system:masters"]), Alpn::H2)
        .await;
    let mut client = h2(hostile.take()).await;
    assert_eq!(
        send(&mut client, Method::GET, PODS, TestBody::empty()).await,
        StatusCode::FORBIDDEN
    );
    hostile.cancel.cancel();
    hostile.finished().await;
    let starts = kube_api.events_settled(SESSION_START, 2).await;
    let last = starts.last().unwrap();
    assert_eq!(text(last, "user"), None);
    assert_eq!(text(last, "groups"), None);
    assert_eq!(text(last, "client_addr").as_deref(), Some(CLIENT_ADDR));
    kube_api.events_settled(SESSION_END, 2).await;
    assert_eq!(kube_api.api.seen().len(), 4);
}

#[tokio::test]
async fn a_request_still_waiting_for_its_answer_is_audited_when_the_session_ends() {
    for aborted in [false, true] {
        let kube_api = Kube::new().await;
        let mut session = kube_api.open(alice(), Alpn::H2).await;
        let client = h2(session.take()).await;
        let pending = tokio::spawn({
            let mut client = client.clone();
            async move {
                drop(
                    client
                        .send_request(h2_request(
                            Method::POST,
                            &format!("{CONFIGMAPS}/slow"),
                            TestBody::empty(),
                        ))
                        .await,
                );
            }
        });
        eventually("the slow request to reach the API", || {
            kube_api.api.seen().len() == 1
        })
        .await;
        if aborted {
            session.serving.abort();
        } else {
            session.cancel.cancel();
            session.finished().await;
        }
        pending.abort();
        kube_api.events_settled(SESSION_END, 1).await;
        let requests = kube_api.events_settled(REQUEST, 1).await;
        assert_eq!(requests.len(), 1, "aborted {aborted}");
        assert_eq!(text(&requests[0], "verb").as_deref(), Some("create"));
        assert_eq!(text(&requests[0], "name").as_deref(), Some("slow"));
        let status = (!aborted).then_some(503);
        assert_eq!(int(&requests[0], "status"), status, "aborted {aborted}");
        assert!(int(&requests[0], "duration_ms").is_some());
    }
}

#[tokio::test]
async fn events_the_sink_cannot_queue_are_counted_as_dropped() {
    let kube_api = Kube::with(Options {
        sink: SinkLimits {
            queue_events: 3,
            ..SINK_LIMITS
        },
        ..Options::default()
    })
    .await;
    kube_api.captured.hold();
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    for index in 0..8 {
        let path = format!("{CONFIGMAPS}/c-{index}");
        assert_eq!(
            send(&mut client, Method::DELETE, &path, TestBody::empty()).await,
            StatusCode::OK
        );
    }
    session.cancel.cancel();
    session.finished().await;
    let counters = kube_api.sink.counters();
    assert_eq!(counters.emitted, 10);
    assert!(counters.dropped >= 6, "{counters:?}");
}

#[tokio::test]
async fn the_start_lists_every_allowed_user_and_the_end_counts_bytes_by_direction() {
    let kube_api = Kube::new().await;
    let produced = kube_api.api.serve_download(512 * 1024);
    let mut session = kube_api
        .open(
            kube(&["alice@example.com", "bob@example.com"], &["view"]),
            Alpn::H2,
        )
        .await;
    let mut client = h2(session.take()).await;
    let mut request = h2_request(Method::GET, &format!("{CONFIGMAPS}/big"), TestBody::empty());
    request.headers_mut().insert(
        "impersonate-user",
        HeaderValue::from_static("bob@example.com"),
    );
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = crate::testkit::soon("the download", response.into_body().collect())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(body.len(), 512 * 1024);
    assert_eq!(
        produced.load(std::sync::atomic::Ordering::SeqCst),
        512 * 1024
    );
    session.cancel.cancel();
    session.finished().await;
    let start = kube_api.events_settled(SESSION_START, 1).await;
    assert_eq!(
        text(&start[0], "user").as_deref(),
        Some("alice@example.com,bob@example.com")
    );
    let end = kube_api.events_settled(SESSION_END, 1).await;
    let (up, down) = (
        int(&end[0], "bytes_up").unwrap(),
        int(&end[0], "bytes_down").unwrap(),
    );
    assert!(up > 0 && up < 64 * 1024, "{up}");
    assert!(down > 512 * 1024, "{down}");
}
