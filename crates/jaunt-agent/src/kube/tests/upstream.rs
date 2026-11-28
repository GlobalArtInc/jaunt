use std::fs::File;

use http::{HeaderMap, HeaderValue, Method, StatusCode};

use super::support::{
    Alpn, CONFIGMAPS, FakeApi, FakeOptions, H2, Kube, Options, SilentListener, TOKEN, TestBody,
    alice, body_text, h2, h2_request, message, pem,
};
use crate::clock::Clock;
use crate::kube::{KUBE_LIMITS, KubernetesUpstream};
use crate::testkit::{LogCapture, TestPki, eventually, soon};

const UNREACHABLE: &str = "the Kubernetes API server cannot be reached through the Jaunt agent";

async fn fetch(client: &mut H2, name: &str) -> (StatusCode, String) {
    let request = h2_request(
        Method::GET,
        &format!("{CONFIGMAPS}/{name}"),
        TestBody::empty(),
    );
    body_text(client.send_request(request).await.unwrap()).await
}

fn last_authorization(kube_api: &Kube) -> String {
    kube_api.api.seen().last().unwrap().values("authorization")[0].clone()
}

#[tokio::test]
async fn a_rotated_token_is_used_without_restart_and_a_failed_read_keeps_the_old_one() {
    let log = LogCapture::default();
    let _guard = log.install();
    let kube_api = Kube::new().await;
    let check = KUBE_LIMITS.token_check_every;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(last_authorization(&kube_api), format!("Bearer {TOKEN}"));

    let rotated = "sa-token-two-after-rotation";
    std::fs::write(&kube_api.api.token_file, rotated).unwrap();
    kube_api.api.accept_token(rotated);
    kube_api.clock.advance(check);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(last_authorization(&kube_api), format!("Bearer {rotated}"));

    std::fs::remove_file(&kube_api.api.token_file).unwrap();
    kube_api.clock.advance(check);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(last_authorization(&kube_api), format!("Bearer {rotated}"));
    std::fs::write(&kube_api.api.token_file, "  \n").unwrap();
    kube_api.clock.advance(check);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(last_authorization(&kube_api), format!("Bearer {rotated}"));
    let logged = log.text();
    assert!(
        logged.contains("reading the service account token for the Kubernetes API server failed"),
        "{logged}"
    );
    assert_eq!(
        logged.matches("reading the service account token").count(),
        1
    );
    assert!(
        !logged.contains(rotated) && !logged.contains(TOKEN),
        "{logged}"
    );

    let same_size = "sa-token-2-after-rotation-x";
    assert_eq!(same_size.len(), rotated.len());
    std::fs::write(&kube_api.api.token_file, rotated).unwrap();
    kube_api.clock.advance(check);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    let stamped = File::open(&kube_api.api.token_file)
        .unwrap()
        .metadata()
        .unwrap()
        .modified()
        .unwrap();
    std::fs::write(&kube_api.api.token_file, same_size).unwrap();
    File::options()
        .write(true)
        .open(&kube_api.api.token_file)
        .unwrap()
        .set_modified(stamped)
        .unwrap();
    kube_api.api.accept_token(same_size);
    kube_api.clock.advance(KUBE_LIMITS.token_reread);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(last_authorization(&kube_api), format!("Bearer {same_size}"));
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn an_unusable_api_gives_502_without_details() {
    let log = LogCapture::default();
    let _guard = log.install();
    let reference = FakeApi::start().await;
    let closing = SilentListener::start(true).await;
    let untrusted = FakeApi::start_with(&TestPki::new(), &TestPki::new()).await;
    let pki = TestPki::new();
    let http1_only = FakeApi::start_options(FakeOptions {
        serving: &pki,
        trusted: &pki,
        alpn: &[b"http/1.1"],
        tls12_only: false,
        resumption: false,
    })
    .await;
    let no_alpn = FakeApi::start_options(FakeOptions {
        serving: &pki,
        trusted: &pki,
        alpn: &[],
        tls12_only: false,
        resumption: false,
    })
    .await;
    for (upstream, kind) in [
        (
            KubernetesUpstream {
                base_url: format!("https://{}", closing.addr),
                ..reference.upstream()
            },
            "handshake",
        ),
        (untrusted.upstream(), "handshake"),
        (http1_only.upstream(), "handshake"),
        (no_alpn.upstream(), "not_http2"),
        (
            KubernetesUpstream {
                ca_file: reference.ca_file.with_file_name("missing.crt"),
                ..reference.upstream()
            },
            "ca_read",
        ),
    ] {
        let kube_api = Kube::with(Options {
            upstream: Some(upstream.clone()),
            ..Options::default()
        })
        .await;
        let mut session = kube_api.open(alice(), Alpn::H2).await;
        let mut client = h2(session.take()).await;
        let (status, body) = fetch(&mut client, "c").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{upstream:?}");
        assert_eq!(message(&body), UNREACHABLE);
        let field = format!("\"kind\":\"{kind}\"");
        assert!(log.text().contains(&field), "{kind}: {}", log.text());
        session.cancel.cancel();
        session.finished().await;
    }
    assert!(untrusted.seen().is_empty());
    assert!(http1_only.seen().is_empty());
    assert!(no_alpn.seen().is_empty());
    assert!(!log.text().contains(TOKEN));
}

#[tokio::test]
async fn an_api_that_accepts_and_stays_silent_gives_502_after_the_connect_timeout() {
    let log = LogCapture::default();
    let _guard = log.install();
    let silent = SilentListener::start(false).await;
    let reference = FakeApi::start().await;
    let kube_api = Kube::with(Options {
        upstream: Some(KubernetesUpstream {
            base_url: format!("https://{}", silent.addr),
            ..reference.upstream()
        }),
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let asked_at = kube_api.clock.now();
    let answer = tokio::spawn(async move { fetch(&mut client, "c").await });
    kube_api
        .clock
        .wait_for_sleeper(asked_at + KUBE_LIMITS.connect_timeout)
        .await;
    kube_api.clock.advance(KUBE_LIMITS.connect_timeout);
    let (status, body) = soon("the connect timeout", answer).await.unwrap();
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(message(&body), UNREACHABLE);
    assert!(
        log.text().contains("\"kind\":\"connect_timeout\""),
        "{}",
        log.text()
    );
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn an_api_that_speaks_only_tls_1_2_is_reached() {
    let pki = TestPki::new();
    let api = FakeApi::start_options(FakeOptions {
        serving: &pki,
        trusted: &pki,
        alpn: &[b"h2"],
        tls12_only: true,
        resumption: false,
    })
    .await;
    let kube_api = Kube::with(Options {
        upstream: Some(api.upstream()),
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(api.seen().len(), 1);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn a_dropped_connection_is_replaced_and_a_new_ca_applies_to_new_connections() {
    let log = LogCapture::default();
    let _guard = log.install();
    let kube_api = Kube::new().await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(kube_api.handler.open_upstream_connections(), 1);

    kube_api.api.drop_connections();
    eventually("the agent to see the dropped connection", || {
        kube_api.handler.open_upstream_connections() == 0
    })
    .await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(kube_api.handler.open_upstream_connections(), 1);

    let rotated = TestPki::new();
    let other = TestPki::new();
    std::fs::write(
        &kube_api.api.ca_file,
        format!(
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n{}",
            pem(rotated.root_der())
        ),
    )
    .unwrap();
    kube_api.api.swap_certificate(&rotated);
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    kube_api.api.drop_connections();
    eventually("the agent to see the dropped connection", || {
        kube_api.handler.open_upstream_connections() == 0
    })
    .await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);

    std::fs::write(&kube_api.api.ca_file, "not pem at all").unwrap();
    kube_api.api.drop_connections();
    eventually("the agent to see the dropped connection", || {
        kube_api.handler.open_upstream_connections() == 0
    })
    .await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert!(
        log.text()
            .contains("reading the CA file of the Kubernetes API server failed"),
        "{}",
        log.text()
    );

    kube_api.api.swap_certificate(&other);
    kube_api.api.drop_connections();
    eventually("the agent to see the dropped connection", || {
        kube_api.handler.open_upstream_connections() == 0
    })
    .await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::BAD_GATEWAY);
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn client_trailers_never_reach_the_api() {
    let kube_api = Kube::new().await;
    let mut trailers = HeaderMap::new();
    trailers.insert("impersonate-user", HeaderValue::from_static("system:admin"));
    trailers.insert("x-trailer", HeaderValue::from_static("1"));
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    let request = h2_request(Method::POST, CONFIGMAPS, TestBody::Trailing(0, trailers));
    let (status, body) = body_text(client.send_request(request).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"received\":4"), "{body}");
    session.cancel.cancel();
    session.finished().await;

    let mut session = kube_api.open(alice(), Alpn::Http11).await;
    let mut tls = session.take();
    let request = format!(
        "POST {CONFIGMAPS} HTTP/1.1\r\nHost: {}\r\nTransfer-Encoding: chunked\r\nTrailer: Impersonate-User\r\n\r\n4\r\nabcd\r\n0\r\nImpersonate-User: system:admin\r\nX-Trailer: 1\r\n\r\n",
        super::support::DNS_NAME
    );
    let (status, body) = super::support::raw_exchange(&mut tls, request.as_bytes()).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"received\":4"), "{body}");
    assert_eq!(kube_api.api.seen().len(), 2);
    assert!(
        kube_api.api.trailers().is_empty(),
        "{:?}",
        kube_api.api.trailers()
    );
    session.cancel.cancel();
    session.finished().await;
}

#[tokio::test]
async fn every_new_connection_to_the_api_does_a_full_handshake() {
    let pki = TestPki::new();
    let api = FakeApi::start_options(FakeOptions {
        serving: &pki,
        trusted: &pki,
        alpn: &[b"h2"],
        tls12_only: false,
        resumption: true,
    })
    .await;
    let kube_api = Kube::with(Options {
        upstream: Some(api.upstream()),
        ..Options::default()
    })
    .await;
    let mut session = kube_api.open(alice(), Alpn::H2).await;
    let mut client = h2(session.take()).await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    api.drop_connections();
    eventually("the agent to see the dropped connection", || {
        kube_api.handler.open_upstream_connections() == 0
    })
    .await;
    assert_eq!(fetch(&mut client, "c").await.0, StatusCode::OK);
    assert_eq!(
        api.handshakes(),
        [rustls::HandshakeKind::Full, rustls::HandshakeKind::Full]
    );
    session.cancel.cancel();
    session.finished().await;
}
