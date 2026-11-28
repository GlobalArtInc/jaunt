use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::{DbAccessRequest, KubeAccess, ServiceAccess, ServiceKind, ServiceOutcome};
use jaunt_tunnel::StreamKind;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::support::{
    AuthorizeStep, Behaviour, CLIENT, DAY, Harness, HarnessOptions, Preparing, TCP_ADDRESS,
    USER_ID, UserSpec, closed_without_data, dns_name, handshake, hello_then_read, later,
    service_id, wait_until,
};
use crate::clock::Clock;
use crate::keys::TlsKey;
use crate::runtime::MAX_GRANT_DURATION;
use crate::runtime::events::{SINK_LIMITS, SessionEvent};
use crate::runtime::limits::{SERVICE_LIMITS, ServiceLimits};
use crate::testkit::{LogCapture, NODE_ID};

const TCP: StreamKind = StreamKind::Tcp;

fn refusals(log: &LogCapture, needle: &str) -> Vec<String> {
    let session = format!("\"session_id\":\"{needle}\"");
    let reason = format!("\"reason\":\"{needle}\"");
    log.text()
        .lines()
        .filter(|line| line.contains("tls.refused"))
        .filter(|line| line.contains(&session) || line.contains(&reason))
        .map(str::to_owned)
        .collect()
}

enum Presented {
    Foreign,
    Spec(fn(&mut UserSpec, i64)),
    Node,
    Nothing,
}

#[tokio::test]
async fn certificates_outside_the_user_profile_are_refused_before_control_is_asked() {
    let harness = Harness::new();
    let log = LogCapture::default();
    let _guard = log.install();
    let cases: Vec<(&str, Presented, &str)> = vec![
        ("foreign CA", Presented::Foreign, "untrusted"),
        ("node certificate", Presented::Node, "untrusted"),
        (
            "expired",
            Presented::Spec(|spec, now| spec.not_after = now - 1),
            "expired",
        ),
        (
            "not yet valid",
            Presented::Spec(|spec, now| spec.not_before = now + 120),
            "not_yet_valid",
        ),
        (
            "wrong SAN",
            Presented::Spec(|spec, _| spec.sans = Vec::new()),
            "user_uri",
        ),
        (
            "wrong key type, which the client cannot even present",
            Presented::Spec(|spec, _| spec.ed25519 = false),
            "no_certificate",
        ),
        ("no certificate", Presented::Nothing, "no_certificate"),
    ];
    for (index, (name, presented, reason)) in cases.into_iter().enumerate() {
        harness.clock.advance(SERVICE_LIMITS.refusal_log_every);
        let now = crate::clock::unix_secs(crate::clock::Clock::now(harness.clock.as_ref()));
        let config = match presented {
            Presented::Foreign => {
                let foreign = super::support::UserCa::new(now).issue(&UserSpec::valid(now));
                harness.client_config(Some(&foreign), &[])
            }
            Presented::Spec(adjust) => {
                let mut spec = UserSpec::valid(now);
                adjust(&mut spec, now);
                harness.client_config(Some(&harness.ca.issue(&spec)), &[])
            }
            Presented::Node => node_config(&harness, now),
            Presented::Nothing => harness.client_config(None, &[]),
        };
        let session = format!("s-{index}");
        let mut opened = harness.open(TCP, "grafana", &session);
        let outcome = handshake(opened.take(), &dns_name(TCP, "grafana"), config).await;
        if let Ok(mut stream) = outcome {
            assert!(closed_without_data(&mut stream).await, "{name}");
        }
        opened.finished().await;
        let lines = refusals(&log, &session);
        assert_eq!(lines.len(), 1, "{name}: {lines:?}");
        assert!(lines[0].contains("tcp.tls.refused"), "{name}: {lines:?}");
        assert!(lines[0].contains(reason), "{name}: {lines:?}");
    }
    assert!(harness.control.authorizations().is_empty());
    assert!(harness.control.ends().is_empty());
}

fn node_config(harness: &Harness, now: i64) -> std::sync::Arc<rustls::ClientConfig> {
    let node_key = TlsKey::generate().unwrap();
    let node_der = STANDARD
        .decode(
            harness
                .pki
                .node_x509(node_key.spki_der(), NODE_ID, now - 60, now + DAY),
        )
        .unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(harness.pki.roots());
    std::sync::Arc::new(
        builder
            .with_client_auth_cert(
                vec![CertificateDer::from(node_der)],
                PrivateKeyDer::Pkcs8(node_key.pkcs8_der().to_vec().into()),
            )
            .unwrap(),
    )
}

#[tokio::test]
async fn an_empty_trust_set_refuses_every_certificate_without_asking_control() {
    let harness = Harness::with(HarnessOptions {
        trusted: false,
        ..HarnessOptions::default()
    });
    let log = LogCapture::default();
    let _guard = log.install();
    let mut opened = harness.open(TCP, "grafana", "s-empty");
    let config = harness.client_config(Some(&harness.user()), &[]);
    if let Ok(mut stream) = handshake(opened.take(), &dns_name(TCP, "grafana"), config).await {
        assert!(closed_without_data(&mut stream).await);
    }
    opened.finished().await;
    assert!(refusals(&log, "s-empty")[0].contains("no_trust"));
    assert!(log.text().contains("no user X.509 roots are loaded"));
    assert!(harness.control.authorizations().is_empty());
}

#[tokio::test]
async fn a_stream_that_does_not_match_its_service_is_closed_before_any_handshake_output() {
    let harness = Harness::new();
    let log = LogCapture::default();
    let _guard = log.install();
    let config = harness.client_config(Some(&harness.user()), &[]);
    let cases = [
        (
            "s-other",
            TCP,
            "grafana",
            "loki.tcp.svc.test",
            "sni_mismatch",
            0,
        ),
        (
            "s-kind",
            TCP,
            "grafana",
            "grafana.db.svc.test",
            "sni_mismatch",
            0,
        ),
        ("s-bare", TCP, "grafana", "grafana.tcp", "sni_mismatch", 0),
        (
            "s-unknown",
            TCP,
            "loki",
            "loki.tcp.svc.test",
            "unknown_service",
            0,
        ),
        (
            "s-unserved",
            StreamKind::Db,
            "billing",
            "billing.db.svc.test",
            "not_served",
            0,
        ),
        (
            "s-domain",
            TCP,
            "grafana",
            "grafana.tcp.evil.test",
            "sni_mismatch",
            1,
        ),
    ];
    for (session, kind, service, sni, reason, certificate_calls) in cases {
        harness.clock.advance(SERVICE_LIMITS.refusal_log_every);
        let mut opened = harness.open(kind, service, session);
        let received = hello_then_read(opened.take(), sni, config.clone()).await;
        assert!(received.is_empty(), "{session}: {} bytes", received.len());
        opened.finished().await;
        let lines = refusals(&log, session);
        assert_eq!(lines.len(), 1, "{session}: {lines:?}");
        assert!(lines[0].contains(reason), "{session}: {lines:?}");
        assert_eq!(
            harness.control.certificate_calls(),
            certificate_calls,
            "{session}"
        );
    }
    assert_eq!(harness.control.certificate_calls(), 1);
    assert!(harness.control.authorizations().is_empty());
}

#[tokio::test]
async fn a_valid_certificate_asks_control_once_and_the_handler_gets_the_grant_and_the_bytes() {
    let harness = Harness::new();
    let user = harness.user();
    let mut opened = harness.open(TCP, "grafana", "s-allow");
    let config = harness.client_config(Some(&user), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    stream.write_all(b"ping over tls").await.unwrap();
    let mut echoed = [0_u8; 13];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping over tls");
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    drop(stream.read_to_end(&mut rest).await);
    opened.finished().await;

    let asked = harness.control.authorizations();
    assert_eq!(asked.len(), 1);
    let request = &asked[0];
    assert_eq!(request.session_id, "s-allow");
    assert_eq!(request.kind, ServiceKind::Tcp);
    assert_eq!(request.service, "grafana");
    assert_eq!(request.client_addr, CLIENT);
    assert_eq!(request.identity.user_id, USER_ID);
    assert_eq!(request.identity.serial, 4242);
    assert_eq!(
        request.identity.subject_fingerprint,
        user.subject_fingerprint()
    );
    assert_eq!(
        request.identity.issuer_fingerprint,
        harness.ca.fingerprint()
    );
    assert_eq!(request.db, None);
    let served = harness.handler.served();
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].grant.access, ServiceAccess::Tcp);
    assert_eq!(served[0].grant.max_duration, Duration::from_secs(3600));
    assert_eq!(served[0].grant.target.as_deref(), Some(TCP_ADDRESS));
    assert_eq!(served[0].session_id, "s-allow");
    assert_eq!(served[0].service, "grafana");
    assert_eq!(served[0].client_addr, CLIENT);
    assert_eq!(served[0].user.user_id, USER_ID);
    let ends = harness.control.ends();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].session_id, "s-allow");
    assert_eq!(ends[0].outcome, ServiceOutcome::Closed);
    assert_eq!((ends[0].bytes_in, ends[0].bytes_out), (13, 13));
}

#[tokio::test]
async fn a_kubernetes_stream_negotiates_its_protocol_and_carries_the_kube_grant() {
    let harness = Harness::new();
    let access = ServiceAccess::Kube(KubeAccess {
        users: vec!["alice@example.com".to_owned()],
        groups: vec!["view".to_owned()],
        record_exec: true,
        record_input: false,
    });
    harness.control.allow_by_default(access.clone(), 600);
    let mut opened = harness.open(
        StreamKind::Kube,
        "prod-eu",
        "k-0123456789abcdef0123456789abcdef",
    );
    let config = harness.client_config(Some(&harness.user()), &[b"h2"]);
    let mut stream = handshake(
        opened.take(),
        &dns_name(StreamKind::Kube, "prod-eu"),
        config,
    )
    .await
    .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    stream.shutdown().await.unwrap();
    opened.finished().await;
    let served = harness.handler.served();
    assert_eq!(served[0].grant.access, access);
    assert_eq!(served[0].grant.target, None);
    assert_eq!(served[0].alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(
        harness.control.authorizations()[0].kind,
        ServiceKind::Kubernetes
    );
}

#[tokio::test]
async fn a_deny_closes_the_connection_without_detail_and_without_an_end_report() {
    let harness = Harness::new();
    harness.control.script(AuthorizeStep::Deny);
    let mut opened = harness.open(TCP, "grafana", "s-deny");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    assert_eq!(harness.control.authorizations().len(), 1);
    assert!(harness.handler.served().is_empty());
    assert!(harness.control.ends().is_empty());
}

#[tokio::test]
async fn access_of_another_kind_is_not_served_and_the_session_is_ended() {
    let harness = Harness::new();
    harness.control.script(AuthorizeStep::Allow(
        ServiceAccess::Kube(KubeAccess {
            users: Vec::new(),
            groups: Vec::new(),
            record_exec: true,
            record_input: false,
        }),
        60,
    ));
    let mut opened = harness.open(TCP, "grafana", "s-mixed");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    assert!(harness.handler.served().is_empty());
    let ends = harness.control.ends();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].outcome, ServiceOutcome::UpstreamError);
}

async fn ended_once_with(behaviour: Behaviour, expected: ServiceOutcome) {
    let harness = Harness::with(HarnessOptions {
        behaviour,
        ..HarnessOptions::default()
    });
    let mut opened = harness.open(TCP, "grafana", "s-fails");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    let ends = harness.control.ends();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].session_id, "s-fails");
    assert_eq!(ends[0].outcome, expected);
}

#[tokio::test]
async fn a_handler_panic_ends_the_session_once_as_an_upstream_error() {
    ended_once_with(Behaviour::Panic, ServiceOutcome::UpstreamError).await;
}

#[tokio::test]
async fn a_handler_failure_ends_the_session_once_as_an_upstream_error() {
    ended_once_with(Behaviour::Fail, ServiceOutcome::UpstreamError).await;
}

#[tokio::test]
async fn an_unanswered_authorization_is_ended_once_so_control_can_free_the_slot() {
    let harness = Harness::new();
    harness.control.script(AuthorizeStep::Hold);
    let mut opened = harness.open(TCP, "grafana", "s-lost");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    wait_until("the authorization to be asked", || {
        harness.control.authorizations().len() == 1
    })
    .await;
    let deadline = later(&harness.clock, SERVICE_LIMITS.authorize_timeout);
    harness.clock.wait_for_sleeper(deadline).await;
    assert!(harness.control.ends().is_empty());
    harness.clock.advance(SERVICE_LIMITS.authorize_timeout);
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    let ends = harness.control.ends();
    assert_eq!(ends.len(), 1);
    assert_eq!(ends[0].session_id, "s-lost");
    assert_eq!(ends[0].outcome, ServiceOutcome::UpstreamError);
    assert_eq!((ends[0].bytes_in, ends[0].bytes_out), (0, 0));
    assert!(harness.handler.served().is_empty());
}

#[tokio::test]
async fn an_ambiguous_control_failure_is_ended_and_a_clear_refusal_is_not() {
    for (status, ended) in [(503, 1), (403, 0)] {
        let harness = Harness::new();
        harness.control.script(AuthorizeStep::Fail(status));
        let mut opened = harness.open(TCP, "grafana", "s-failed");
        let config = harness.client_config(Some(&harness.user()), &[]);
        let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
            .await
            .unwrap();
        assert!(closed_without_data(&mut stream).await);
        opened.finished().await;
        assert_eq!(harness.control.ends().len(), ended, "{status}");
    }
}

#[tokio::test]
async fn sixty_four_unfinished_handshakes_fill_a_service_and_each_lasts_ten_seconds() {
    let harness = Harness::new();
    let log = LogCapture::default();
    let _guard = log.install();
    let id = service_id("grafana");
    let mut pending = Vec::new();
    for index in 0..SERVICE_LIMITS.handshakes_per_service {
        pending.push(harness.open(TCP, "grafana", &format!("s-wait-{index}")));
    }
    wait_until("every handshake to hold a slot", || {
        harness.runtime.gauges().handshakes_held(&id) == SERVICE_LIMITS.handshakes_per_service
    })
    .await;
    let mut extra = harness.open(TCP, "grafana", "s-extra");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let received = hello_then_read(extra.take(), &dns_name(TCP, "grafana"), config).await;
    assert!(received.is_empty());
    extra.finished().await;
    assert!(refusals(&log, "s-extra")[0].contains("handshake_limit"));
    let deadline = later(&harness.clock, SERVICE_LIMITS.handshake_timeout);
    wait_until("every handshake to wait for its deadline", || {
        harness
            .clock
            .sleepers()
            .iter()
            .filter(|at| **at == deadline)
            .count()
            == SERVICE_LIMITS.handshakes_per_service
    })
    .await;
    harness
        .clock
        .advance(SERVICE_LIMITS.handshake_timeout - Duration::from_secs(1));
    tokio::task::yield_now().await;
    assert_eq!(
        harness.runtime.gauges().handshakes_held(&id),
        SERVICE_LIMITS.handshakes_per_service
    );
    harness.clock.advance(Duration::from_secs(1));
    for opened in pending {
        opened.finished().await;
    }
    assert_eq!(harness.runtime.gauges().handshakes_held(&id), 0);
    assert_eq!(harness.runtime.gauges().connections_held(&id), 0);
    let timeouts = refusals(&log, "handshake_timeout");
    assert_eq!(timeouts.len(), 1, "{timeouts:?}");
    assert!(timeouts[0].contains("\"suppressed\":0"), "{timeouts:?}");
    assert!(harness.control.authorizations().is_empty());
}

#[tokio::test]
async fn one_user_holds_at_most_thirty_two_connections_to_a_service() {
    let limits = ServiceLimits {
        connections_per_user: 32,
        ..SERVICE_LIMITS
    };
    let harness = Harness::with(HarnessOptions {
        behaviour: Behaviour::Hold,
        limits,
        ..HarnessOptions::default()
    });
    let log = LogCapture::default();
    let _guard = log.install();
    let user = harness.user();
    let config = harness.client_config(Some(&user), &[]);
    let mut held = Vec::new();
    for index in 0..limits.connections_per_user {
        let mut opened = harness.open(TCP, "grafana", &format!("s-held-{index}"));
        let stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config.clone())
            .await
            .unwrap();
        held.push((opened, stream));
    }
    wait_until("every connection to reach the handler", || {
        harness.handler.served().len() == limits.connections_per_user
    })
    .await;
    let mut opened = harness.open(TCP, "grafana", "s-one-more");
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config.clone())
        .await
        .unwrap();
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    assert!(refusals(&log, "s-one-more")[0].contains("user_limit"));
    assert_eq!(
        harness.control.authorizations().len(),
        limits.connections_per_user
    );
    let other = {
        let mut spec = UserSpec::valid(harness.now);
        spec.sans = vec![super::support::user_uri(
            "0f8fad5b-d9cb-469f-a165-70867728950e",
        )];
        harness.ca.issue(&spec)
    };
    let mut opened = harness.open(TCP, "grafana", "s-other-user");
    let other_config = harness.client_config(Some(&other), &[]);
    drop(
        handshake(opened.take(), &dns_name(TCP, "grafana"), other_config)
            .await
            .unwrap(),
    );
    wait_until("the other user to be asked about", || {
        harness.control.authorizations().len() == limits.connections_per_user + 1
    })
    .await;
    opened.cancel.cancel();
    opened.finished().await;
    let (first, _stream) = held.remove(0);
    first.cancel.cancel();
    first.finished().await;
    let mut opened = harness.open(TCP, "grafana", "s-freed");
    drop(
        handshake(opened.take(), &dns_name(TCP, "grafana"), config)
            .await
            .unwrap(),
    );
    wait_until("the freed slot to be used", || {
        harness.control.authorizations().len() == limits.connections_per_user + 2
    })
    .await;
    opened.cancel.cancel();
    opened.finished().await;
    for (opened, _stream) in held {
        opened.cancel.cancel();
        opened.finished().await;
    }
}

#[tokio::test]
async fn a_session_longer_than_its_grant_is_ended_at_the_deadline() {
    let harness = Harness::with(HarnessOptions {
        behaviour: Behaviour::Hold,
        ..HarnessOptions::default()
    });
    harness.control.allow_by_default(ServiceAccess::Tcp, 90);
    let mut opened = harness.open(TCP, "grafana", "s-long");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    wait_until("the session to start", || {
        harness.handler.served().len() == 1
    })
    .await;
    let deadline = later(&harness.clock, Duration::from_secs(90));
    harness.clock.wait_for_sleeper(deadline).await;
    harness.clock.advance(Duration::from_secs(90));
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    assert_eq!(
        harness.control.ends()[0].outcome,
        ServiceOutcome::MaxDuration
    );
}

#[tokio::test]
async fn every_grant_is_cut_at_twenty_four_hours() {
    for granted in [u64::MAX, 25 * 3600] {
        let harness = Harness::with(HarnessOptions {
            behaviour: Behaviour::Hold,
            ..HarnessOptions::default()
        });
        harness
            .control
            .allow_by_default(ServiceAccess::Tcp, granted);
        let mut opened = harness.open(TCP, "grafana", "s-long-grant");
        let config = harness.client_config(Some(&harness.user()), &[]);
        let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
            .await
            .unwrap();
        wait_until("the session to start", || {
            harness.handler.served().len() == 1
        })
        .await;
        assert_eq!(
            harness.handler.served()[0].grant.max_duration,
            MAX_GRANT_DURATION,
            "{granted}"
        );
        let deadline = later(&harness.clock, MAX_GRANT_DURATION);
        harness.clock.wait_for_sleeper(deadline).await;
        harness
            .clock
            .advance(MAX_GRANT_DURATION - Duration::from_secs(1));
        tokio::task::yield_now().await;
        assert!(harness.control.ends().is_empty(), "{granted}");
        harness.clock.advance(Duration::from_secs(1));
        assert!(closed_without_data(&mut stream).await);
        opened.finished().await;
        assert_eq!(
            harness.control.ends()[0].outcome,
            ServiceOutcome::MaxDuration,
            "{granted}"
        );
    }
}

#[test]
fn the_documented_limits_are_the_built_in_ones() {
    assert_eq!(SERVICE_LIMITS.handshakes_per_service, 64);
    assert_eq!(SERVICE_LIMITS.handshake_timeout, Duration::from_secs(10));
    assert_eq!(SERVICE_LIMITS.connections_per_user, 32);
    assert_eq!(SERVICE_LIMITS.connections_per_service, 512);
    assert_eq!(SERVICE_LIMITS.authorize_timeout, Duration::from_secs(10));
    assert_eq!(MAX_GRANT_DURATION, Duration::from_secs(24 * 3600));
    assert_eq!(SERVICE_LIMITS.event_flush_timeout, Duration::from_secs(2));
    assert_eq!(
        (SINK_LIMITS.queue_events, SINK_LIMITS.queue_bytes),
        (4096, 4 * 1024 * 1024)
    );
    assert_eq!(
        (
            SINK_LIMITS.batch_events,
            SINK_LIMITS.batch_bytes,
            SINK_LIMITS.batch_wait
        ),
        (256, 256 * 1024, Duration::from_secs(1))
    );
    assert_eq!(
        (SINK_LIMITS.first_retry, SINK_LIMITS.max_retry),
        (Duration::from_secs(1), Duration::from_secs(30))
    );
    let docs = include_str!("../../../../../docs/operations.md");
    for documented in [
        "4096 events or 4 MiB",
        "256 events, 256 KiB or 1 s",
        "from 1 s to 30 s",
        "2 s for the audit events of a session",
        "64 unfinished TLS handshakes per service",
        "10 s for the handshake and 10 s more for the first protocol step",
        "32 connections per user and service",
        "512 connections per service",
        "10 s for the answer of control",
        "at most 24 hours",
    ] {
        assert!(docs.contains(documented), "{documented}");
    }
}

#[tokio::test]
async fn a_service_holds_at_most_five_hundred_twelve_connections() {
    let limits = ServiceLimits {
        connections_per_user: 1024,
        ..SERVICE_LIMITS
    };
    let harness = Harness::with(HarnessOptions {
        behaviour: Behaviour::Hold,
        limits,
        ..HarnessOptions::default()
    });
    let log = LogCapture::default();
    let _guard = log.install();
    let id = service_id("grafana");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut held = Vec::new();
    for index in 0..SERVICE_LIMITS.connections_per_service {
        let mut opened = harness.open(TCP, "grafana", &format!("s-many-{index}"));
        let stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config.clone())
            .await
            .unwrap();
        held.push((opened, stream));
        if index == 0 {
            wait_until("the first session", || harness.handler.served().len() == 1).await;
            assert_eq!(harness.runtime.gauges().handshakes_held(&id), 0);
            assert_eq!(harness.runtime.gauges().connections_held(&id), 1);
        }
    }
    wait_until("every session to start", || {
        harness.handler.served().len() == SERVICE_LIMITS.connections_per_service
    })
    .await;
    let mut extra = harness.open(TCP, "grafana", "s-many-extra");
    let received = hello_then_read(extra.take(), &dns_name(TCP, "grafana"), config).await;
    assert!(received.is_empty());
    extra.finished().await;
    assert!(refusals(&log, "s-many-extra")[0].contains("service_limit"));
    assert_eq!(
        harness.control.authorizations().len(),
        SERVICE_LIMITS.connections_per_service
    );
    for (opened, _stream) in held {
        opened.cancel.cancel();
        opened.finished().await;
    }
    assert_eq!(harness.runtime.gauges().connections_held(&id), 0);
}

#[tokio::test]
async fn a_handler_that_never_starts_its_protocol_is_cut_before_control_is_asked() {
    let harness = Harness::new();
    harness.handler.prepare_with(Preparing::Hang);
    let id = service_id("grafana");
    let mut opened = harness.open(TCP, "grafana", "s-silent");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    wait_until("the handshake to finish on the agent", || {
        harness.runtime.gauges().handshakes_held(&id) == 0
    })
    .await;
    let deadline = later(&harness.clock, SERVICE_LIMITS.handshake_timeout);
    harness.clock.wait_for_sleeper(deadline).await;
    harness
        .clock
        .advance(SERVICE_LIMITS.handshake_timeout - Duration::from_secs(1));
    tokio::task::yield_now().await;
    assert_eq!(harness.runtime.gauges().connections_held(&id), 1);
    harness.clock.advance(Duration::from_secs(1));
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    assert!(harness.control.authorizations().is_empty());
    assert!(harness.control.ends().is_empty());
    assert_eq!(harness.runtime.gauges().connections_held(&id), 0);
}

#[tokio::test]
async fn the_database_fields_of_the_handler_reach_the_authorization() {
    let harness = Harness::with(HarnessOptions {
        handled: vec![StreamKind::Db],
        ..HarnessOptions::default()
    });
    let asked = DbAccessRequest {
        user: "app".to_owned(),
        name: "main".to_owned(),
        agent_key: "MCowBQYDK2VwAyEA".to_owned(),
    };
    harness.handler.prepare_with(Preparing::Db(asked.clone()));
    harness.control.script(AuthorizeStep::Deny);
    let mut opened = harness.open(StreamKind::Db, "billing", "s-db");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(StreamKind::Db, "billing"), config)
        .await
        .unwrap();
    assert!(closed_without_data(&mut stream).await);
    opened.finished().await;
    let requests = harness.control.authorizations();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].kind, ServiceKind::Postgres);
    assert_eq!(requests[0].service, "billing");
    assert_eq!(requests[0].db, Some(asked));
}

#[tokio::test]
async fn a_handler_that_fails_before_it_returns_a_future_ends_the_session_once() {
    ended_once_with(Behaviour::PanicAtOnce, ServiceOutcome::UpstreamError).await;
}

#[tokio::test]
async fn every_connection_is_a_full_handshake_that_is_checked_again() {
    let harness = Harness::new();
    let config = harness.client_config(Some(&harness.user()), &[]);
    for session in ["s-first", "s-second"] {
        let mut opened = harness.open(TCP, "grafana", session);
        let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config.clone())
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut echoed = [0_u8; 1];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(
            stream.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "{session}"
        );
        stream.shutdown().await.unwrap();
        drop(stream);
        opened.finished().await;
    }
    assert_eq!(harness.control.authorizations().len(), 2);
}

#[tokio::test]
async fn a_client_that_speaks_only_tls_1_2_is_refused() {
    let harness = Harness::new();
    let user = harness.user();
    let (chain, key) = user.client_auth();
    let config = std::sync::Arc::new(
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(harness.pki.roots())
        .with_client_auth_cert(chain, key)
        .unwrap(),
    );
    let mut opened = harness.open(TCP, "grafana", "s-old-tls");
    let refused = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            refused
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(
                rustls::AlertDescription::ProtocolVersion
            ))
        ),
        "{refused:?}"
    );
    opened.finished().await;
    assert!(harness.control.authorizations().is_empty());
}

#[tokio::test]
async fn the_events_of_a_session_reach_control_before_its_end_is_reported() {
    let harness = Harness::new();
    let start = SessionEvent {
        name: "tcp.session.start",
        fields: [(
            "client_addr".to_owned(),
            jaunt_proto::AgentEventValue::Text(CLIENT.to_owned()),
        )]
        .into_iter()
        .collect(),
    };
    harness.handler.emit_on_serve(vec![start]);
    let mut opened = harness.open(TCP, "grafana", "s-events");
    let config = harness.client_config(Some(&harness.user()), &[]);
    let mut stream = handshake(opened.take(), &dns_name(TCP, "grafana"), config)
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    drop(stream.read_to_end(&mut rest).await);
    opened.finished().await;

    assert_eq!(harness.control.calls(), ["events", "end"]);
    let batches = harness.control.batches();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].events.len(), 1);
    assert_eq!(batches[0].events[0].session_id, "s-events");
    assert_eq!(batches[0].events[0].name, "tcp.session.start");
    let started = harness
        .clock
        .now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert_eq!(u128::from(batches[0].events[0].seq), started * 1000 + 1);
    assert_eq!(harness.events.queue_len(), 0);
}
