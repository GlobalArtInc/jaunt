mod support;

#[allow(dead_code)]
#[path = "services/fixture.rs"]
mod fixture;

#[allow(dead_code)]
#[path = "ssh/fixture.rs"]
mod ssh_fixture;

use std::sync::Arc;
use std::time::Duration;

use fixture::{
    AgentEvent, CLUSTER, DOMAIN, Fixture, NODE, OTHER_USER, Options, Reply, RouteAnswer, SESSION,
    TestClock, TestIssuer, USER, agent_tls, closed_without_bytes, gate_with, hello, noise,
    read_all,
};
use jaunt_gate::{
    DEFAULT_KUBE_STREAMS_PER_ADDRESS, DEFAULT_KUBE_STREAMS_PER_CLUSTER,
    DEFAULT_SVC_STREAMS_PER_ADDRESS, DEFAULT_SVC_STREAMS_PER_USER, GateCertificateError,
    ServiceGateConfig, ServiceGateError, ServicesEntry, StreamRefusal, TlsRefusal,
};
use jaunt_proto::{GateTlsIssueError, ServiceKind, is_kube_session_id};
use jaunt_tunnel::StreamKind;
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData};
use russh::keys::{HashAlg, PublicKey};
use rustls::pki_types::ServerName;
use support::{HubOptions, Pki, Verdicts, audited, eventually, field, start_hub, within};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const LOCAL: [u8; 4] = [127, 0, 0, 1];

fn ssh_fingerprint(raw: [u8; 32]) -> String {
    PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(raw)))
        .fingerprint(HashAlg::Sha256)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn kube_name(cluster: &str) -> String {
    format!("{cluster}.kube.{DOMAIN}")
}

async fn write_bytewise(tcp: &mut TcpStream, bytes: &[u8]) {
    for byte in bytes {
        tcp.write_all(std::slice::from_ref(byte)).await.unwrap();
    }
}

#[tokio::test]
async fn kube_bytes_pass_unchanged_both_ways_with_a_byte_split_hello_and_early_data() {
    let reply = noise(7, 200_000);
    let mut fixture = Fixture::start(Options {
        reply: Reply::AfterEnd(Arc::new(reply.clone())),
        ..Options::default()
    })
    .await;
    let hello = hello(Some(&kube_name(CLUSTER)));
    let trailing = noise(11, 300_000);
    let mut tcp = fixture.tcp(LOCAL).await;
    let client_addr = tcp.local_addr().unwrap();
    write_bytewise(&mut tcp, &hello).await;
    let mut offset = 0;
    let mut sizes = noise(3, 4096)
        .into_iter()
        .map(|size| usize::from(size) * 37 + 1);
    while offset < trailing.len() {
        let end = (offset + sizes.next().unwrap()).min(trailing.len());
        tcp.write_all(&trailing[offset..end]).await.unwrap();
        offset = end;
    }
    tcp.shutdown().await.unwrap();

    let AgentEvent::Opened(meta) = fixture.next_event().await else {
        panic!("the stream did not open first");
    };
    assert_eq!(meta.kind(), StreamKind::Kube);
    assert_eq!(meta.service().map(|name| name.as_str()), Some(CLUSTER));
    assert!(is_kube_session_id(meta.session().as_str()));
    assert_eq!(meta.client(), client_addr.to_string());
    let AgentEvent::Received(received) = fixture.next_event().await else {
        panic!("the agent did not report the bytes");
    };
    assert_eq!(received.len(), hello.len() + trailing.len());
    assert!(received == [hello.as_slice(), trailing.as_slice()].concat());
    let back = read_all(&mut tcp).await.unwrap();
    assert!(back == reply, "{} bytes came back", back.len());

    let ended = audited("the kube stream end", |event| {
        field(event, "event") == "gate.kube.stream" && field(event, "outcome") == "closed"
    })
    .await;
    assert_eq!(field(&ended, "service"), CLUSTER);
    assert_eq!(field(&ended, "reason"), "closed");
    assert_eq!(field(&ended, "node_id"), NODE);
    assert_eq!(field(&ended, "session_id"), meta.session().as_str());
    assert_eq!(field(&ended, "client_addr"), client_addr.to_string());
    assert_eq!(
        field(&ended, "bytes_up"),
        (hello.len() + trailing.len()).to_string()
    );
    assert_eq!(field(&ended, "bytes_down"), reply.len().to_string());
    assert!(field(&ended, "duration_ms").parse::<u64>().is_ok());
    assert_eq!(fixture.control.locates(), 1);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn kube_mutual_tls_completes_end_to_end_without_any_gate_key() {
    let agent = agent_tls(&kube_name(CLUSTER), b"h2");
    let mut fixture = Fixture::start(Options {
        reply: Reply::Tls(agent.acceptor.clone()),
        ..Options::default()
    })
    .await;
    let tcp = fixture.tcp(LOCAL).await;
    let name = ServerName::try_from(kube_name(CLUSTER)).unwrap();
    let mut tls = within(
        "the handshake with the cluster agent",
        TlsConnector::from(agent.client.clone()).connect(name, tcp),
    )
    .await
    .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    tls.write_all(b"ping").await.unwrap();
    let mut pong = [0_u8; 4];
    within("the answer", tls.read_exact(&mut pong))
        .await
        .unwrap();
    assert_eq!(&pong, b"pong");
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the stream did not open");
    };
    let AgentEvent::Received(ping) = fixture.next_event().await else {
        panic!("the agent did not decrypt the request");
    };
    assert_eq!(ping, b"ping");
    drop(tls);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn kube_refusals_close_without_a_byte_and_name_the_reason() {
    let fixture = Fixture::start(Options {
        served: vec![StreamKind::Db],
        ..Options::default()
    })
    .await;
    let cases = [
        ("ghost", StreamRefusal::UnknownCluster),
        ("orphan", StreamRefusal::NodeNotConnected),
        (CLUSTER, StreamRefusal::KindNotServed),
    ];
    for (cluster, reason) in cases {
        let mut tcp = fixture.tcp(LOCAL).await;
        tcp.write_all(&hello(Some(&kube_name(cluster))))
            .await
            .unwrap();
        assert!(closed_without_bytes(&mut tcp).await, "{cluster}");
        assert_eq!(fixture.gate.kube_refused(reason), 1, "{cluster}");
        let event = audited(reason.as_str(), |event| {
            field(event, "event") == "gate.kube.stream" && field(event, "reason") == reason.as_str()
        })
        .await;
        assert_eq!(field(&event, "outcome"), "refused");
        assert_eq!(field(&event, "service"), cluster);
        assert_eq!(field(&event, "suppressed"), "0");
    }
    assert_eq!(fixture.control.locates_of("orphan"), 1);
    let mut again = fixture.tcp(LOCAL).await;
    again
        .write_all(&hello(Some(&kube_name("orphan"))))
        .await
        .unwrap();
    assert!(closed_without_bytes(&mut again).await);
    assert_eq!(fixture.control.locates_of("orphan"), 2);
    assert_eq!(fixture.control.locates_of("ghost"), 1);
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::UnsupportedClass), 0);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn a_flood_of_one_unknown_cluster_reaches_control_once() {
    let fixture = Fixture::start(Options::default()).await;
    let before = support::audit_events().len();
    for _ in 0..20 {
        let mut tcp = fixture.tcp(LOCAL).await;
        tcp.write_all(&hello(Some(&kube_name("ghost"))))
            .await
            .unwrap();
        assert!(closed_without_bytes(&mut tcp).await);
    }
    assert_eq!(fixture.control.locates(), 1);
    assert_eq!(fixture.gate.kube_refused(StreamRefusal::UnknownCluster), 20);
    let refusals: Vec<_> = support::audit_events()
        .into_iter()
        .skip(before)
        .filter(|event| field(event, "event") == "gate.kube.stream")
        .collect();
    assert_eq!(refusals.len(), 1, "{refusals:?}");
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn kube_streams_stop_at_the_per_address_and_per_cluster_limits() {
    assert_eq!(DEFAULT_KUBE_STREAMS_PER_ADDRESS, 32);
    assert_eq!(DEFAULT_KUBE_STREAMS_PER_CLUSTER, 512);
    let mut fixture = Fixture::start(Options {
        proxied: true,
        configure: |config| {
            config.kube_streams_per_address = 2;
            config.kube_streams_per_cluster = 3;
        },
        ..Options::default()
    })
    .await;
    let mut held = Vec::new();
    for client in [[192, 0, 2, 1], [192, 0, 2, 1], [192, 0, 2, 2]] {
        let mut tcp = fixture.tcp(client).await;
        tcp.write_all(&hello(Some(&kube_name(CLUSTER))))
            .await
            .unwrap();
        let AgentEvent::Opened(_) = fixture.next_event().await else {
            panic!("a stream within the limits did not open");
        };
        held.push(tcp);
    }
    for (client, reason) in [
        ([192, 0, 2, 1], StreamRefusal::AddressLimit),
        ([192, 0, 2, 3], StreamRefusal::ClusterLimit),
    ] {
        let mut tcp = fixture.tcp(client).await;
        tcp.write_all(&hello(Some(&kube_name(CLUSTER))))
            .await
            .unwrap();
        assert!(closed_without_bytes(&mut tcp).await, "{reason:?}");
        assert_eq!(fixture.gate.kube_refused(reason), 1);
    }
    eventually("three spliced kube streams", || {
        let stats = fixture.gate.stats();
        (
            stats.kube_streams,
            stats.kube_addresses,
            stats.kube_clusters,
        ) == (3, 2, 1)
    })
    .await;
    let mut first = held.remove(0);
    first.shutdown().await.unwrap();
    read_all(&mut first).await.unwrap();
    eventually("a closed stream to return its slots", || {
        fixture.gate.stats().kube_streams == 2
    })
    .await;
    let mut again = fixture.tcp([192, 0, 2, 3]).await;
    again
        .write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    while let AgentEvent::Received(..) = fixture.next_event().await {}
    drop((held, again));
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn the_entry_kube_slot_is_held_for_as_long_as_the_stream_is_open() {
    let mut fixture = Fixture::start(Options {
        entry_kube_per_address: Some(1),
        ..Options::default()
    })
    .await;
    let mut open = fixture.tcp(LOCAL).await;
    open.write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the first stream did not open");
    };
    let mut second = fixture.tcp(LOCAL).await;
    second
        .write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    assert!(closed_without_bytes(&mut second).await);
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::Limit), 1);
    open.shutdown().await.unwrap();
    assert_eq!(read_all(&mut open).await.unwrap(), b"from the agent");
    let AgentEvent::Received(_) = fixture.next_event().await else {
        panic!("the agent did not see the end of the first stream");
    };
    fixture.idle().await;
    let mut third = fixture.tcp(LOCAL).await;
    third
        .write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("a stream after the release did not open");
    };
    drop(third);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn svc_refuses_every_client_certificate_that_is_not_a_current_user_certificate() {
    let fixture = Fixture::start(Options::default()).await;
    let foreign = fixture::UserCa::new();
    let now = fixture::unix(std::time::SystemTime::now());
    let expired = fixture.users.user_valid(USER, 9, now - 7200, now - 3600);
    let stranger = foreign.user(USER, 9);
    let node_leaf = fixture.pki.client_leaf(NODE);
    let node_config = {
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(fixture.issuer.roots())
        .with_client_auth_cert(node_leaf.chain.clone(), node_leaf.key())
        .unwrap();
        config.alpn_protocols = vec![fixture::ALPN_SVC.to_vec()];
        Arc::new(config)
    };
    let configs = [
        ("none", fixture.outer_config(None)),
        ("foreign chain", fixture.outer_config(Some(&stranger))),
        ("expired", fixture.outer_config(Some(&expired))),
        ("node certificate", node_config),
    ];
    for (count, (case, config)) in (1_u64..).zip(configs) {
        let alerted = match fixture.svc_with(LOCAL, config).await {
            Err(_) => true,
            Ok(mut tls) => {
                drop(
                    tls.write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
                        .await,
                );
                let mut buffer = [0_u8; 64];
                within(case, tls.read(&mut buffer)).await.is_err()
            }
        };
        assert!(alerted, "{case} was not refused by the tls handshake");
        eventually(case, || {
            fixture.hub.hub.tls_refused(TlsRefusal::ClientCertificate) == count
        })
        .await;
    }
    *fixture.roots.0.lock().unwrap() = None;
    let valid = fixture.users.user(USER, 9);
    assert!(fixture.svc(LOCAL, Some(&valid)).await.is_err());
    assert_eq!(
        fixture.hub.hub.tls_refused(TlsRefusal::ClientCertificate),
        5
    );
    assert!(fixture.control.routes().is_empty());
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn svc_allow_opens_one_stream_with_the_routed_identity_and_replays_the_inner_hello() {
    let mut fixture = Fixture::start(Options::default()).await;
    for (sni, kind, stream_kind, name) in [
        (
            format!("lk.db.{DOMAIN}"),
            ServiceKind::Postgres,
            StreamKind::Db,
            "lk",
        ),
        (
            format!("Grafana.TCP.{DOMAIN}"),
            ServiceKind::Tcp,
            StreamKind::Tcp,
            "grafana",
        ),
    ] {
        let user = fixture.users.user(USER, 4242);
        let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
        let client_addr = tls.get_ref().0.local_addr().unwrap();
        let inner = hello(Some(&sni));
        let trailing = noise(5, 70_000);
        tls.write_all(&inner).await.unwrap();
        tls.write_all(&trailing).await.unwrap();
        tls.shutdown().await.unwrap();
        let AgentEvent::Opened(meta) = fixture.next_event().await else {
            panic!("no stream opened for {sni}");
        };
        assert_eq!(meta.kind(), stream_kind);
        assert_eq!(meta.service().map(|service| service.as_str()), Some(name));
        assert_eq!(meta.client(), client_addr.to_string());
        let AgentEvent::Received(received) = fixture.next_event().await else {
            panic!("the agent did not report the bytes");
        };
        assert!(
            received == [inner.as_slice(), trailing.as_slice()].concat(),
            "{sni}"
        );
        assert_eq!(read_all(&mut tls).await.unwrap(), b"from the agent");
        let routes = fixture.control.routes();
        let route = routes.last().unwrap();
        assert_eq!(route.identity.user_id, USER);
        assert_eq!(route.identity.serial, 4242);
        assert_eq!(
            route.identity.subject_fingerprint,
            ssh_fingerprint(user.raw_key())
        );
        assert_eq!(
            route.identity.issuer_fingerprint,
            ssh_fingerprint(fixture.users.raw_key())
        );
        assert_eq!(route.kind, kind);
        assert_eq!(route.service, name);
        assert_eq!(route.client_addr, client_addr.to_string());
        if kind == ServiceKind::Postgres {
            assert_eq!(meta.session().as_str(), SESSION);
        }
        let ended = audited("the svc stream end", |event| {
            field(event, "event") == "gate.svc.stream"
                && field(event, "outcome") == "closed"
                && field(event, "service") == name
        })
        .await;
        assert_eq!(field(&ended, "user_id"), USER);
        assert_eq!(field(&ended, "serial"), "4242");
        assert_eq!(field(&ended, "kind"), stream_kind.as_str());
        assert_eq!(field(&ended, "session_id"), meta.session().as_str());
        assert_eq!(field(&ended, "node_id"), NODE);
        assert_eq!(
            field(&ended, "bytes_up"),
            (inner.len() + trailing.len()).to_string()
        );
        assert_eq!(field(&ended, "bytes_down"), "14");
    }
    assert_eq!(fixture.control.routes().len(), 2);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn svc_inner_tls_runs_end_to_end_between_the_client_and_the_agent() {
    let agent = agent_tls(&format!("lk.db.{DOMAIN}"), b"postgresql");
    let mut fixture = Fixture::start(Options {
        reply: Reply::Tls(agent.acceptor.clone()),
        ..Options::default()
    })
    .await;
    let user = fixture.users.user(USER, 7);
    let outer = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    let name = ServerName::try_from(format!("lk.db.{DOMAIN}")).unwrap();
    let mut inner = within(
        "the inner handshake",
        TlsConnector::from(agent.client.clone()).connect(name, outer),
    )
    .await
    .unwrap();
    inner.write_all(b"ping").await.unwrap();
    let mut pong = [0_u8; 4];
    within("the inner answer", inner.read_exact(&mut pong))
        .await
        .unwrap();
    assert_eq!(&pong, b"pong");
    let AgentEvent::Opened(meta) = fixture.next_event().await else {
        panic!("no stream opened");
    };
    assert_eq!(meta.kind(), StreamKind::Db);
    drop(inner);
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn svc_deny_a_failing_control_and_bad_service_names_close_without_a_stream() {
    let fixture = Fixture::start(Options::default()).await;
    let user = fixture.users.user(USER, 7);
    let mut expected_routes = 0;
    for (answer, sni, reason) in [
        (
            RouteAnswer::Deny,
            Some(format!("lk.db.{DOMAIN}")),
            StreamRefusal::Denied,
        ),
        (
            RouteAnswer::Fail,
            Some(format!("lk.tcp.{DOMAIN}")),
            StreamRefusal::ControlUnavailable,
        ),
        (
            RouteAnswer::Allow,
            Some(format!("lk.kube.{DOMAIN}")),
            StreamRefusal::ServiceName,
        ),
        (
            RouteAnswer::Allow,
            Some(format!("a.b.db.{DOMAIN}")),
            StreamRefusal::ServiceName,
        ),
        (
            RouteAnswer::Allow,
            Some(DOMAIN.to_owned()),
            StreamRefusal::ServiceName,
        ),
        (
            RouteAnswer::Allow,
            Some(format!("lk.db.evil{DOMAIN}")),
            StreamRefusal::ServiceName,
        ),
        (RouteAnswer::Allow, None, StreamRefusal::ServiceName),
    ] {
        fixture.control.answer(answer.clone());
        let before = fixture.gate.svc_refused(reason);
        let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
        tls.write_all(&hello(sni.as_deref())).await.unwrap();
        assert!(closed_without_bytes(&mut tls).await, "{sni:?}");
        assert_eq!(fixture.gate.svc_refused(reason), before + 1, "{sni:?}");
        if matches!(
            reason,
            StreamRefusal::Denied | StreamRefusal::ControlUnavailable
        ) {
            expected_routes += 1;
        }
        assert_eq!(fixture.control.routes().len(), expected_routes, "{sni:?}");
    }
    let mut tls = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    tls.write_all(b"\x16\x03\x01\x00\x05hello").await.unwrap();
    assert!(closed_without_bytes(&mut tls).await);
    assert_eq!(fixture.gate.svc_refused(StreamRefusal::InnerHello), 1);
    let denied = audited("the denied stream", |event| {
        field(event, "event") == "gate.svc.stream" && field(event, "reason") == "denied"
    })
    .await;
    assert_eq!(field(&denied, "outcome"), "refused");
    assert_eq!(field(&denied, "user_id"), USER);
    assert_eq!(field(&denied, "service"), "lk");
    assert!(!format!("{denied:?}").contains("policy"));
    assert_eq!(
        fixture.hub.hub.tls_refused(TlsRefusal::ClientCertificate),
        0
    );
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn svc_streams_stop_at_the_per_address_and_per_user_limits() {
    assert_eq!(DEFAULT_SVC_STREAMS_PER_ADDRESS, 32);
    assert_eq!(DEFAULT_SVC_STREAMS_PER_USER, 32);
    let mut fixture = Fixture::start(Options {
        proxied: true,
        configure: |config| {
            config.svc_streams_per_address = 1;
            config.svc_streams_per_user = 1;
        },
        ..Options::default()
    })
    .await;
    let alice = fixture.users.user(USER, 1);
    let bob = fixture.users.user(OTHER_USER, 2);
    let mut held = fixture.svc([192, 0, 2, 1], Some(&alice)).await.unwrap();
    held.write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the first stream did not open");
    };

    let same_address = fixture.svc([192, 0, 2, 1], Some(&bob)).await;
    let refused = match same_address {
        Err(_) => true,
        Ok(mut tls) => closed_without_bytes(&mut tls).await,
    };
    assert!(refused);
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::Limit), 1);

    let mut same_user = fixture.svc([192, 0, 2, 2], Some(&alice)).await.unwrap();
    same_user
        .write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
        .await
        .unwrap();
    assert!(closed_without_bytes(&mut same_user).await);
    assert_eq!(fixture.gate.svc_refused(StreamRefusal::UserLimit), 1);
    assert_eq!(fixture.control.routes().len(), 1);

    eventually("one spliced svc stream", || {
        let stats = fixture.gate.stats();
        (stats.svc_streams, stats.svc_addresses, stats.svc_users) == (1, 1, 1)
    })
    .await;
    held.shutdown().await.unwrap();
    read_all(&mut held).await.unwrap();
    fixture.idle().await;
    let mut later = fixture.svc([192, 0, 2, 2], Some(&alice)).await.unwrap();
    later
        .write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
        .await
        .unwrap();
    later.shutdown().await.unwrap();
    assert_eq!(read_all(&mut later).await.unwrap(), b"from the agent");
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn stopping_the_entry_ends_open_streams_and_frees_every_slot() {
    let mut fixture = Fixture::start(Options::default()).await;
    let mut kube = fixture.tcp(LOCAL).await;
    kube.write_all(&hello(Some(&kube_name(CLUSTER))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the kube stream did not open");
    };
    let user = fixture.users.user(USER, 7);
    let mut svc = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    svc.write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
        .await
        .unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the svc stream did not open");
    };
    eventually("both streams to be spliced", || {
        let stats = fixture.gate.stats();
        (stats.kube_streams, stats.svc_streams) == (1, 1)
    })
    .await;
    let gate = within("the entry to stop", fixture.stop_entry()).await;
    eventually("the slots of stopped streams", || {
        gate.stats() == jaunt_gate::ServiceGateStats::default()
    })
    .await;
    for kind in ["gate.kube.stream", "gate.svc.stream"] {
        audited(kind, |event| {
            field(event, "event") == kind
                && field(event, "outcome") == "closed"
                && ["aborted", "shutdown"].contains(&field(event, "reason"))
        })
        .await;
    }
    assert!(closed_without_bytes(&mut kube).await);
    assert!(closed_without_bytes(&mut svc).await);
}

#[tokio::test]
async fn the_gate_class_has_its_own_handshake_budget() {
    let mut fixture = Fixture::start(Options {
        configure: |config| config.max_handshaking = 1,
        ..Options::default()
    })
    .await;
    let user = fixture.users.user(USER, 7);
    let config = fixture.outer_config(Some(&user));
    let mut client =
        rustls::ClientConnection::new(config.clone(), ServerName::try_from(DOMAIN).unwrap())
            .unwrap();
    let mut client_hello = Vec::new();
    client.write_tls(&mut client_hello).unwrap();
    let mut stalled = fixture.tcp(LOCAL).await;
    stalled.write_all(&client_hello).await.unwrap();
    eventually("the stalled handshake to hold the budget", || {
        fixture.gate.stats().handshaking == 1
    })
    .await;
    assert_eq!(fixture.hub.hub.entry_handshaking(), 0);
    let refused = match fixture.svc_with(LOCAL, config).await {
        Err(_) => true,
        Ok(mut tls) => closed_without_bytes(&mut tls).await,
    };
    assert!(refused);
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::Limit), 1);
    drop(stalled);
    eventually("the abandoned handshake to free the budget", || {
        fixture.gate.stats().handshaking == 0
    })
    .await;
    assert_eq!(fixture.hub.hub.tls_refused(TlsRefusal::TlsHandshake), 1);
    let mut later = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    later
        .write_all(&hello(Some(&format!("lk.db.{DOMAIN}"))))
        .await
        .unwrap();
    later.shutdown().await.unwrap();
    assert_eq!(read_all(&mut later).await.unwrap(), b"from the agent");
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the stream after the budget was freed did not open");
    };
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn the_gate_certificate_is_renewed_at_half_life_and_open_connections_keep_going() {
    let mut fixture = Fixture::start(Options::default()).await;
    let first_serial = fixture.gate.certificate_serial();
    let first = fixture.issuer.last_issued();
    let user = fixture.users.user(USER, 7);
    let mut open = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    assert_eq!(open.get_ref().1.peer_certificates().unwrap()[0], first);
    let inner = hello(Some(&format!("lk.db.{DOMAIN}")));
    open.write_all(&inner).await.unwrap();
    let AgentEvent::Opened(_) = fixture.next_event().await else {
        panic!("the stream did not open");
    };

    fixture.clock.advance(Duration::from_secs(3 * 24 * 3600));
    assert!(!fixture.gate.renew_if_due().await.unwrap());
    fixture.clock.advance(Duration::from_secs(12 * 3600));
    assert!(fixture.gate.renew_if_due().await.unwrap());
    assert_ne!(fixture.gate.certificate_serial(), first_serial);
    let renewed = fixture.issuer.last_issued();
    assert_ne!(renewed, first);

    let fresh = fixture.svc(LOCAL, Some(&user)).await.unwrap();
    assert_eq!(fresh.get_ref().1.peer_certificates().unwrap()[0], renewed);
    drop(fresh);
    open.write_all(b"after the renewal").await.unwrap();
    open.shutdown().await.unwrap();
    let AgentEvent::Received(received) = fixture.next_event().await else {
        panic!("the agent did not report the bytes");
    };
    assert_eq!(received, [inner.as_slice(), b"after the renewal"].concat());
    assert_eq!(read_all(&mut open).await.unwrap(), b"from the agent");
    assert_eq!(
        fixture.issuer.asked.lock().unwrap().as_slice(),
        [DOMAIN, DOMAIN]
    );
    fixture.idle().await;
    fixture.stop().await;
}

#[tokio::test]
async fn the_gate_asks_the_issuer_for_exactly_the_services_domain_and_stops_on_a_refusal() {
    let clock = TestClock::new();
    let issuer = TestIssuer::new(DOMAIN, clock.clone());
    let normalized = gate_with(issuer.clone(), ServiceGateConfig::new("SVC.Test."), &clock).await;
    assert!(normalized.is_ok());
    let refused = gate_with(issuer.clone(), ServiceGateConfig::new("other.test"), &clock).await;
    assert!(matches!(
        refused,
        Err(ServiceGateError::Certificate(GateCertificateError::Issue(
            GateTlsIssueError::NameRefused
        )))
    ));
    assert_eq!(
        issuer.asked.lock().unwrap().as_slice(),
        [DOMAIN, "other.test"]
    );
    for invalid in ["", "*.svc.test", "192.0.2.7"] {
        assert!(matches!(
            gate_with(issuer.clone(), ServiceGateConfig::new(invalid), &clock).await,
            Err(ServiceGateError::Domain(_))
        ));
    }
    let mut zero = ServiceGateConfig::new(DOMAIN);
    zero.svc_streams_per_user = 0;
    assert!(matches!(
        gate_with(issuer.clone(), zero, &clock).await,
        Err(ServiceGateError::StreamLimits)
    ));
    assert_eq!(issuer.asked.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn ssh_through_443_is_the_same_session_as_through_2222() {
    let ssh = ssh_fixture::Fixture::start(|_| {}).await;
    let tunnel = Pki::new("entry ca");
    let entry = start_hub(
        &tunnel,
        Arc::new(Verdicts::default()),
        HubOptions {
            services: Some(ServicesEntry::new(DOMAIN)),
            ..HubOptions::default()
        },
    )
    .await;
    let clock = TestClock::new();
    let issuer = TestIssuer::new(DOMAIN, clock.clone());
    let gate = jaunt_gate::ServiceGate::new(jaunt_gate::ServiceGateParts {
        config: ServiceGateConfig::new(DOMAIN),
        issuer: issuer.clone(),
        user_x509: Arc::new(fixture::FixedRoots(std::sync::Mutex::new(None))),
        control: fixture::FakeControl::new(),
        registry: entry.hub.registry().clone(),
        ssh: Some(Arc::clone(&ssh.gate)),
        clock: clock.clock(),
    })
    .await
    .unwrap();
    assert!(entry.hub.install_class_handlers(gate.handlers()));

    let plain = ssh.connect().await;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(issuer.roots())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"jaunt-ssh/1".to_vec()];
    let tcp = TcpStream::connect(entry.addr).await.unwrap();
    let client_addr = tcp.local_addr().unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(DOMAIN).unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"jaunt-ssh/1"[..]));
    let mut through_tls = ssh_fixture::Client::over(tls).await.unwrap();
    assert_eq!(through_tls.host_certificate(), plain.host_certificate());
    assert!(through_tls.login(&ssh.user_ca).await);
    let mut channel = through_tls.open_node().await.unwrap();
    ssh_fixture::echo_once(&mut channel, b"over 443").await;

    let connected = audited("the ssh connect over tls", |event| {
        field(event, "event") == "gate.ssh.connect"
            && field(event, "client_addr") == client_addr.to_string()
    })
    .await;
    assert_eq!(field(&connected, "peer_addr"), client_addr.to_string());
    assert_eq!(field(&connected, "proxied"), "false");
    audited("the ssh login over tls", |event| {
        field(event, "event") == "gate.ssh.auth"
            && field(event, "outcome") == "ok"
            && field(event, "client_addr") == client_addr.to_string()
    })
    .await;
    audited("the forward over tls", |event| {
        field(event, "event") == "gate.ssh.forward"
            && field(event, "outcome") == "allowed"
            && field(event, "client_addr") == client_addr.to_string()
    })
    .await;
    assert_eq!(ssh.control.seen().len(), 1);
    assert_eq!(ssh.gate.authenticated(), 1);
    drop((channel, through_tls, plain));
    eventually("the ssh connections to end", || {
        ssh.gate.authenticated() == 0
    })
    .await;
    eventually("the gate slots to be released", || {
        gate.stats() == jaunt_gate::ServiceGateStats::default()
    })
    .await;
    ssh.stop().await;
}

#[tokio::test]
async fn ssh_through_443_shares_the_ssh_limits_of_2222() {
    let ssh = ssh_fixture::Fixture::start(|config| {
        config.client_limits = jaunt_limits::AddressLimits {
            rate: jaunt_limits::Rate::clamped(1000, 1000),
            concurrent: 1,
            tracked: 16,
        };
    })
    .await;
    let entry = start_hub(
        &Pki::new("entry ca"),
        Arc::new(Verdicts::default()),
        HubOptions {
            services: Some(ServicesEntry::new(DOMAIN)),
            ..HubOptions::default()
        },
    )
    .await;
    let clock = TestClock::new();
    let issuer = TestIssuer::new(DOMAIN, clock.clone());
    let gate = jaunt_gate::ServiceGate::new(jaunt_gate::ServiceGateParts {
        config: ServiceGateConfig::new(DOMAIN),
        issuer: issuer.clone(),
        user_x509: Arc::new(fixture::FixedRoots(std::sync::Mutex::new(None))),
        control: fixture::FakeControl::new(),
        registry: entry.hub.registry().clone(),
        ssh: Some(Arc::clone(&ssh.gate)),
        clock: clock.clock(),
    })
    .await
    .unwrap();
    entry.hub.install_class_handlers(gate.handlers());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(issuer.roots())
    .with_no_client_auth();
    config.alpn_protocols = vec![b"jaunt-ssh/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let dial = || async {
        let tcp = TcpStream::connect(entry.addr).await.unwrap();
        connector
            .connect(ServerName::try_from(DOMAIN).unwrap(), tcp)
            .await
    };

    let waiting = ssh.connect().await;
    let refused = match dial().await {
        Err(_) => true,
        Ok(mut tls) => closed_without_bytes(&mut tls).await,
    };
    assert!(refused);
    audited("the ssh limit over tls", |event| {
        field(event, "event") == "gate.ssh.limited" && field(event, "reason") == "concurrent"
    })
    .await;
    assert_eq!(gate.stats().handshaking, 0);

    let mut first = waiting;
    assert!(first.login(&ssh.user_ca).await);
    let mut over_tls = ssh_fixture::Client::over(dial().await.unwrap())
        .await
        .unwrap();
    assert!(over_tls.login(&ssh.user_ca).await);
    drop((first, over_tls));
    eventually("the ssh connections to end", || {
        ssh.gate.authenticated() == 0
    })
    .await;
    ssh.stop().await;
}
