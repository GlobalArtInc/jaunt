use std::pin::pin;

use http::{HeaderValue, Method, StatusCode};

use super::support::{
    Alpn, CONFIGMAPS, DNS_NAME, Kube, PODS, TestBody, alice, body_text, h2, h2_request, message,
    raw_exchange,
};

fn get(path: &str, headers: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\n{headers}\r\n").into_bytes()
}

fn host() -> String {
    format!("Host: {DNS_NAME}\r\n")
}

#[tokio::test]
async fn a_request_for_another_host_is_misdirected_before_any_upstream_traffic() {
    let kube_api = Kube::new().await;
    let own = format!("{CONFIGMAPS}/c");
    let absolute_other = format!("https://staging.kube.svc.test{own}");
    let absolute_own = format!("https://{DNS_NAME}{own}");
    for (request, status) in [
        (get(&own, "Host: staging.kube.svc.test\r\n"), 421),
        (get(&own, ""), 421),
        (get(&own, &format!("{}{}", host(), host())), 421),
        (get(&absolute_other, &host()), 421),
        (get(&own, &format!("Host: {DNS_NAME}:8443\r\n")), 421),
        (get(&own, "Host: PROD-EU.KUBE.SVC.TEST:443\r\n"), 200),
        (get(&absolute_own, &host()), 200),
    ] {
        let mut session = kube_api.open(alice(), Alpn::Http11).await;
        let mut tls = session.take();
        let before = kube_api.api.seen().len();
        let (got, body) = raw_exchange(&mut tls, &request).await;
        let shown = String::from_utf8_lossy(&request).into_owned();
        assert_eq!(got, status, "{shown}: {body}");
        let reached = kube_api.api.seen().len() - before;
        if status == 421 {
            assert_eq!(reached, 0, "{shown}");
            assert!(
                message(&body).contains("another Kubernetes cluster"),
                "{body}"
            );
        } else {
            assert_eq!(reached, 1, "{shown}");
        }
        session.cancel.cancel();
        session.finished().await;
    }

    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let mut request = h2_request(Method::GET, &own, TestBody::empty());
    *request.uri_mut() = absolute_other.parse().unwrap();
    let (status, _) = body_text(client.send_request(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    let mut request = h2_request(Method::GET, &own, TestBody::empty());
    request
        .headers_mut()
        .insert("host", HeaderValue::from_static("staging.kube.svc.test"));
    let (status, _) = body_text(client.send_request(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert_eq!(kube_api.api.seen().len(), 2);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn paths_that_another_parser_could_read_differently_are_refused() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    for path in [
        "/api/v1/namespaces/default/pods/../secrets",
        "/api/v1/namespaces/default/secrets/%2e%2e",
        "/api//v1/namespaces/default/pods",
        "/api/v1/namespaces/default/pods/",
        "/api/v1/namespaces/default/configmaps/a%2fb",
        "/api/v1/namespaces/default/configmaps/a%2Fb",
        "/api/v1/namespaces/default/configmaps/a%00b",
        "/api/v1/namespaces/default/configmaps/a%5cb",
        "/api/v1/namespaces/default/configmaps/a%ffb",
        "/api/v1/namespaces/default/configmaps/a%0db",
        "/api/v1/namespaces/default/configmaps/a%zz",
    ] {
        let (status, body) = raw_exchange(&mut tls, &get(path, &host())).await;
        assert_eq!(status, 400, "{path}: {body}");
        assert!(message(&body).contains("canonical"), "{path}: {body}");
    }
    let (status, _) = raw_exchange(&mut tls, &get("/api/v1/pods/a\\b", &host())).await;
    assert_eq!(status, 400);
    assert!(kube_api.api.seen().is_empty());
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn framing_tricks_are_refused_or_reframed_and_connection_tokens_cannot_drop_our_headers() {
    let kube_api = Kube::new().await;
    let post = |extra: &str, body: &str| {
        format!(
            "POST {CONFIGMAPS} HTTP/1.1\r\nHost: {DNS_NAME}\r\nContent-Type: application/json\r\n{extra}\r\n{body}"
        )
        .into_bytes()
    };
    let smuggled = format!("GET {CONFIGMAPS}/smuggled HTTP/1.1\r\nHost: {DNS_NAME}\r\n\r\n");
    let chunked = format!("{:x}\r\n{smuggled}\r\n0\r\n\r\n", smuggled.len());
    for (request, status, received) in [
        (
            post("Content-Length: 4\r\nContent-Length: 5\r\n", "abcd"),
            400,
            None,
        ),
        (
            post("Content-Length: 4\r\nContent-Length: 4\r\n", "abcd"),
            200,
            Some(4),
        ),
        (
            post(
                "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n",
                &chunked,
            ),
            200,
            Some(smuggled.len()),
        ),
        (
            post(
                "Transfer-Encoding: chunked\r\nContent-Length: 4\r\n",
                &chunked,
            ),
            200,
            Some(smuggled.len()),
        ),
        (
            post("Transfer-Encoding: gzip, chunked\r\n", &chunked),
            400,
            None,
        ),
        (
            post("Transfer-Encoding: chunked, chunked\r\n", &chunked),
            400,
            None,
        ),
        (
            post(
                "Transfer-Encoding: identity\r\nContent-Length: 4\r\n",
                "abcd",
            ),
            400,
            None,
        ),
    ] {
        let mut session = kube_api.open(alice(), Alpn::Http11).await;
        let mut tls = session.take();
        let before = kube_api.api.seen().len();
        let shown = String::from_utf8_lossy(&request).into_owned();
        let (got, body) = raw_exchange(&mut tls, &request).await;
        assert_eq!(got, status, "{shown}: {body}");
        let seen = kube_api.api.seen();
        let reached: Vec<_> = seen[before..].to_vec();
        match received {
            Some(length) => {
                assert_eq!(reached.len(), 1, "{shown}");
                assert!(body.contains(&format!("\"received\":{length}")), "{body}");
                assert!(reached[0].values("transfer-encoding").is_empty());
            }
            None => assert!(reached.is_empty(), "{shown}"),
        }
        assert!(
            seen.iter().all(|seen| !seen.path.contains("smuggled")),
            "{shown}"
        );
        session.cancel.cancel();
        session.finished().await;
    }

    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    let request = get(
        &format!("{CONFIGMAPS}/c"),
        &format!(
            "{}Connection: Impersonate-User, Impersonate-Group, Authorization, Impersonate-Extra-Jaunt-Session-Id\r\nImpersonate-User: alice@example.com\r\nIMPERSONATE-GROUP: dev\r\n",
            host()
        ),
    );
    let (status, body) = raw_exchange(&mut tls, &request).await;
    assert_eq!(status, 200, "{body}");
    let last = kube_api.api.seen().pop().unwrap();
    assert_eq!(last.values("impersonate-user"), ["alice@example.com"]);
    assert_eq!(last.values("impersonate-group"), ["dev"]);
    assert_eq!(last.values("authorization").len(), 1);
    assert_eq!(last.values("impersonate-extra-jaunt-session-id").len(), 1);
    assert!(last.values("connection").is_empty());
    for lookalike in [
        "Impersonate_User: system:admin",
        "X_Remote_Group: system:masters",
    ] {
        let before = kube_api.api.seen().len();
        let request = get(
            &format!("{CONFIGMAPS}/c"),
            &format!("{}{lookalike}\r\n", host()),
        );
        let (status, body) = raw_exchange(&mut tls, &request).await;
        assert_eq!(status, 403, "{lookalike}: {body}");
        assert_eq!(kube_api.api.seen().len(), before, "{lookalike}");
    }
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn upgrades_and_other_methods_get_a_status_and_never_reach_the_api() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    let exec = format!("{PODS}/web/exec?command=sh&stdin=true&tty=true");
    for (request, status, says) in [
        (
            get(
                &exec,
                &format!("{}Connection: Upgrade\r\nUpgrade: SPDY/3.1\r\n", host()),
            ),
            403,
            "not available yet",
        ),
        (
            get(
                &exec,
                &format!(
                    "{}Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                    host()
                ),
            ),
            403,
            "not available yet",
        ),
        (
            get(
                &format!("{PODS}?watch=1"),
                &format!("{}Connection: Upgrade\r\nUpgrade: websocket\r\n", host()),
            ),
            403,
            "not available yet",
        ),
        (
            format!("OPTIONS {PODS} HTTP/1.1\r\n{}\r\n", host()).into_bytes(),
            405,
            "method",
        ),
        (
            format!("TRACE {PODS} HTTP/1.1\r\n{}\r\n", host()).into_bytes(),
            405,
            "method",
        ),
    ] {
        let shown = String::from_utf8_lossy(&request).into_owned();
        let (got, body) = raw_exchange(&mut tls, &request).await;
        assert_eq!(got, status, "{shown}: {body}");
        assert!(message(&body).contains(says), "{shown}: {body}");
    }

    let mut h2_session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(h2_session.take()).await;
    let request = h2_request(Method::POST, &exec, TestBody::empty());
    let (status, body) = body_text(client.send_request(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(kube_api.api.seen().is_empty());
    for session in [session, h2_session] {
        session.cancel.cancel();
        session.finished().await;
    }
}

#[tokio::test]
async fn header_blocks_and_concurrent_streams_are_limited() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    let filler = |bytes: usize| format!("X-Filler: {}\r\n", "a".repeat(bytes));
    let (status, _) = raw_exchange(
        &mut tls,
        &get(
            &format!("{CONFIGMAPS}/c"),
            &format!("{}{}", host(), filler(60 * 1024)),
        ),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = raw_exchange(
        &mut tls,
        &get(
            &format!("{CONFIGMAPS}/c"),
            &format!("{}{}", host(), filler(65 * 1024)),
        ),
    )
    .await;
    assert_eq!(status, 431);
    assert_eq!(kube_api.api.seen().len(), 1);
    session.cancel.cancel();
    session.finished().await;

    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let (mut client, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(session.take()),
    )
    .await
    .unwrap();
    let mut connection = pin!(connection);
    let mut small = h2_request(Method::GET, &format!("{CONFIGMAPS}/c"), TestBody::empty());
    small.headers_mut().insert(
        "x-filler",
        HeaderValue::from_str(&"a".repeat(30 * 1024)).unwrap(),
    );
    let response = tokio::select! {
        response = client.send_request(small) => response.unwrap(),
        _ = connection.as_mut() => panic!("the connection ended"),
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(connection.current_max_send_streams(), 128);
    let mut large = h2_request(Method::GET, &format!("{CONFIGMAPS}/c"), TestBody::empty());
    large.headers_mut().insert(
        "x-filler",
        HeaderValue::from_str(&"a".repeat(70 * 1024)).unwrap(),
    );
    let refused = tokio::select! {
        response = client.send_request(large) => response.map(|response| response.status()),
        _ = connection.as_mut() => Ok(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE),
    };
    assert!(
        refused.is_err() || refused.as_ref().is_ok_and(|status| *status == 431),
        "{refused:?}"
    );
    assert_eq!(kube_api.api.seen().len(), 2);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn redirects_and_api_errors_pass_through_unchanged() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let response = client
        .send_request(h2_request(
            Method::GET,
            &format!("{CONFIGMAPS}/redirect"),
            TestBody::empty(),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()["location"],
        "https://elsewhere.example/api"
    );
    for code in [401_u16, 403, 429, 500, 503] {
        let response = client
            .send_request(h2_request(
                Method::GET,
                &format!("{CONFIGMAPS}/status-{code}"),
                TestBody::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.headers()["retry-after"], "7", "{code}");
        let (status, body) = body_text(response).await;
        assert_eq!(status.as_u16(), code);
        assert_eq!(body, "{\"from\":\"api\"}", "{code}");
    }
    assert_eq!(kube_api.api.seen().len(), 6);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn origin_headers_of_the_client_are_replaced_by_its_tunnel_address() {
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    let request = get(
        &format!("{CONFIGMAPS}/c"),
        &format!(
            "{}X-Forwarded-For: 1.2.3.4\r\nForwarded: for=1.2.3.4\r\nX-Real-IP: 1.2.3.4\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: http\r\nX-Forwarded-Port: 80\r\nX-Forwarded-Client-Cert: x\r\nVia: 1.1 evil\r\nAudit-ID: 00000000-aaaa\r\n",
            host()
        ),
    );
    let (status, body) = raw_exchange(&mut tls, &request).await;
    assert_eq!(status, 200, "{body}");
    let seen = kube_api.api.seen().pop().unwrap();
    assert_eq!(seen.values("x-forwarded-for"), ["203.0.113.5"]);
    for name in [
        "forwarded",
        "x-real-ip",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-client-cert",
        "via",
        "audit-id",
    ] {
        assert!(seen.values(name).is_empty(), "{name}");
    }
    session.cancel.cancel();
    session.finished().await;
}
