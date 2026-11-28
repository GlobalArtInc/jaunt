use std::time::Duration;

use axum::http::StatusCode;
use jaunt_ca::ROOT_VALIDITY;
use jaunt_control::ControlError;
use jaunt_proto::{
    ClientConfigV2, ClientTransport, GATE_ALPN_SSH, GATE_ALPN_SVC, GateTlsIssueError, GateTlsIssuer,
};
use jaunt_store::{ServiceApproval, ServiceQuery, ServiceState};
use serde_json::{Value, json};

use crate::audit::{Captured, start_recording, take_recording};
use crate::issuance_support::{
    DAY, DOMAIN, HOUR, P256_SPKI, client_verifies, der_of, eight_hour_session, get,
    openssl_verifies, parsed, server_verifies, spki,
};
use crate::session_support::{audit_events, node};
use crate::support::{APPROVER, Harness, Options, Reply};
use crate::sweep::{DEADLINE, POLL_EVERY, serve_sweeping_often};

const PATH: &str = "/v1/agent/service-certificate";
const ANNOUNCE: &str = "/v1/agent/services";

async fn services_harness(internal_root_age: Duration) -> Harness {
    Harness::with(Options {
        services_domain: Some(DOMAIN),
        internal_root_age,
        gate_endpoint: Some("gate.example.com:2222"),
        ..Options::default()
    })
    .await
}

fn tcp(name: &str) -> Value {
    json!({"kind": "tcp", "name": name, "labels": {"team": "ops"}, "address": "10.0.0.5:3000"})
}

async fn announce(harness: &Harness, node_id: &str, services: &[Value]) {
    let reply = crate::support::send(
        harness.agent_router.clone(),
        crate::support::request(
            ANNOUNCE,
            &json!({ "services": services }),
            None,
            Some(node_id),
        ),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{}", reply.text());
}

async fn service_id(harness: &Harness, node_id: &str, name: &str, state: ServiceState) -> String {
    let page = harness
        .store
        .services()
        .page(&ServiceQuery {
            state: Some(state),
            node_id: Some(node_id.to_owned()),
            after: None,
            limit: 100,
        })
        .await
        .unwrap();
    page.services
        .into_iter()
        .find(|service| service.name == name)
        .unwrap_or_else(|| panic!("no {name} in state {state:?}"))
        .id
}

async fn approved(harness: &Harness, node_id: &str, name: &str) -> String {
    let id = service_id(harness, node_id, name, ServiceState::Pending).await;
    harness
        .store
        .services()
        .approve(&ServiceApproval {
            id: &id,
            approver: APPROVER,
            labels_override: None,
            now: harness.clock.now_secs(),
        })
        .await
        .unwrap();
    id
}

async fn ask(harness: &Harness, node_id: &str, service_id: &str, key: &str) -> Reply {
    let request = crate::support::request(
        PATH,
        &json!({ "service_id": service_id, "public_key": key }),
        None,
        Some(node_id),
    );
    crate::support::send(harness.agent_router.clone(), request).await
}

async fn issued(harness: &Harness, node_id: &str, service_id: &str) -> Value {
    let (key, _) = spki();
    let reply = ask(harness, node_id, service_id, &key).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()
}

async fn config(harness: &Harness) -> ClientConfigV2 {
    let alice = eight_hour_session(harness, "alice").await;
    let reply = get(
        &harness.router,
        "/v2/client/config",
        Some(&alice.token),
        None,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    serde_json::from_slice(&reply.body).unwrap()
}

async fn pinned_roots(harness: &Harness) -> Vec<Vec<u8>> {
    config(harness)
        .await
        .services
        .unwrap()
        .roots
        .iter()
        .map(|root| der_of(&json!(root.certificate_der)))
        .collect()
}

fn refusals(recorded: Vec<Captured>) -> Vec<String> {
    audit_events(recorded)
        .into_iter()
        .filter(|event| event["event"] == "cert.service.refused")
        .map(|event| event["reason"].clone())
        .collect()
}

#[tokio::test]
async fn an_approved_service_of_the_node_gets_a_server_certificate_named_from_its_row() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    announce(
        &harness,
        &node_id,
        &[
            tcp("grafana"),
            json!({"kind": "kubernetes", "name": "prod-eu", "labels": {"env": "prod"}}),
            json!({"kind": "postgres", "name": "lk", "labels": {"env": "prod"},
                   "address": "127.0.0.1:5432", "postgres": {"tls": {"ca_file": "/etc/jaunt/pg-ca.pem", "server_name": "db-01"}}}),
        ],
    )
    .await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let cluster = approved(&harness, &node_id, "prod-eu").await;
    let database = approved(&harness, &node_id, "lk").await;
    let now = harness.clock.now_secs();
    start_recording();

    let body = issued(&harness, &node_id, &grafana).await;

    let name = format!("grafana.tcp.{DOMAIN}");
    assert_eq!(body["dns_name"], json!(name));
    let der = der_of(&body["certificate_der"]);
    let leaf = parsed(&der);
    assert!(leaf.common_names.is_empty());
    assert_eq!(leaf.sans, [format!("DNSName(\"{name}\")")]);
    assert!(leaf.server_auth && !leaf.client_auth);
    let serial = body["serial"].as_i64().unwrap();
    assert_eq!(leaf.serial, u128::try_from(serial).unwrap());
    assert_eq!(
        (leaf.not_before, leaf.not_after),
        (now - 120, now + 7 * DAY)
    );
    let roots = pinned_roots(&harness).await;
    assert!(server_verifies(&roots, &der, &name, now));
    assert!(!server_verifies(
        &roots,
        &der,
        &format!("grafana.db.{DOMAIN}"),
        now
    ));
    assert!(!client_verifies(&roots, &der, now));
    if let Some(accepted) = openssl_verifies(&roots, &der, "sslserver", now, Some(&name)) {
        assert!(accepted);
        assert_eq!(
            openssl_verifies(&roots, &der, "sslclient", now, Some(&name)),
            Some(false)
        );
    }
    let row = harness
        .store
        .service_certificates()
        .get(serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            row.node_id.as_str(),
            row.service_id.as_str(),
            row.dns_name.as_str()
        ),
        (node_id.as_str(), grafana.as_str(), name.as_str())
    );
    let event = audit_events(take_recording())
        .into_iter()
        .find(|event| event["event"] == "cert.service.issued")
        .unwrap();
    assert_eq!(event["node_id"], node_id);
    assert_eq!(event["service_id"], grafana);
    assert_eq!(event["kind"], "tcp");
    assert_eq!(event["name"], "grafana");
    assert_eq!(event["serial"], serial.to_string());
    assert_eq!(event["valid_before"], (now + 7 * DAY).to_string());

    for (id, expected) in [
        (&cluster, format!("prod-eu.kube.{DOMAIN}")),
        (&database, format!("lk.db.{DOMAIN}")),
    ] {
        let body = issued(&harness, &node_id, id).await;
        assert_eq!(body["dns_name"], json!(expected));
        assert!(server_verifies(
            &roots,
            &der_of(&body["certificate_der"]),
            &expected,
            now
        ));
    }

    announce(
        &harness,
        &node_id,
        &[json!({"kind": "tcp", "name": "grafana", "labels": {"team": "dev"}, "address": "10.0.0.5:3000"})],
    )
    .await;
    let pending = service_id(&harness, &node_id, "grafana", ServiceState::Pending).await;
    assert_ne!(pending, grafana);
    let still = issued(&harness, &node_id, &grafana).await;
    assert_eq!(still["dns_name"], json!(name));

    let (key, _) = spki();
    let named = crate::support::send(
        harness.agent_router.clone(),
        crate::support::request(
            PATH,
            &json!({"service_id": grafana, "public_key": key, "name": "evil"}),
            None,
            Some(&node_id),
        ),
    )
    .await;
    assert_eq!(named.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn certificates_are_refused_for_anything_but_an_approved_announced_service_of_the_caller() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    let other = node(&harness, "web-02").await;
    let gone = node(&harness, "web-03").await;
    announce(&harness, &node_id, &[tcp("grafana"), tcp("pending")]).await;
    announce(&harness, &other, &[tcp("theirs")]).await;
    announce(&harness, &gone, &[tcp("orphan")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let pending = service_id(&harness, &node_id, "pending", ServiceState::Pending).await;
    let theirs = approved(&harness, &other, "theirs").await;
    let orphan = approved(&harness, &gone, "orphan").await;
    harness.admin.remove_node("web-03", APPROVER).await.unwrap();
    let (key, _) = spki();
    start_recording();

    for (label, caller, id, status, code) in [
        (
            "another node",
            node_id.as_str(),
            theirs.as_str(),
            StatusCode::NOT_FOUND,
            "unknown_service",
        ),
        (
            "pending",
            node_id.as_str(),
            pending.as_str(),
            StatusCode::NOT_FOUND,
            "unknown_service",
        ),
        (
            "unknown",
            node_id.as_str(),
            "6f1c2a52-6d1e-4d0f-9e43-2f1d7f1d9a10",
            StatusCode::NOT_FOUND,
            "unknown_service",
        ),
        (
            "not an id",
            node_id.as_str(),
            "../grafana",
            StatusCode::NOT_FOUND,
            "unknown_service",
        ),
        (
            "removed node",
            gone.as_str(),
            orphan.as_str(),
            StatusCode::FORBIDDEN,
            "node_removed",
        ),
    ] {
        let reply = ask(&harness, caller, id, &key).await;
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (status, code),
            "{label}"
        );
    }
    announce(&harness, &node_id, &[tcp("pending")]).await;
    let withdrawn = ask(&harness, &node_id, &grafana, &key).await;
    assert_eq!(
        (withdrawn.status, withdrawn.error_code().as_str()),
        (StatusCode::NOT_FOUND, "unknown_service")
    );
    assert_eq!(
        refusals(take_recording()),
        [
            "other_node",
            "not_approved",
            "unknown_service",
            "invalid_service_id",
            "node_removed",
            "not_announced"
        ]
    );

    let unauthenticated = crate::support::send(
        harness.agent_router.clone(),
        crate::support::request(
            PATH,
            &json!({"service_id": grafana, "public_key": key}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let without_domain = Harness::new().await;
    let lone = node(&without_domain, "web-01").await;
    announce(&without_domain, &lone, &[tcp("grafana")]).await;
    let lone_service = approved(&without_domain, &lone, "grafana").await;
    start_recording();
    let reply = ask(&without_domain, &lone, &lone_service, &key).await;
    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (StatusCode::NOT_FOUND, "not_configured")
    );
    assert_eq!(refusals(take_recording()), ["not_configured"]);
}

#[tokio::test]
async fn only_an_ed25519_spki_is_certified_for_a_service() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    announce(&harness, &node_id, &[tcp("grafana")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let (_, der) = spki();
    start_recording();
    for (label, key) in [
        ("p-256", P256_SPKI.to_owned()),
        (
            "ssh line",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".to_owned(),
        ),
        ("raw key", base64(&der[12..])),
        ("garbage", "%%".to_owned()),
        ("the authority key", base64(&root_spki(&harness.root_der))),
    ] {
        let reply = ask(&harness, &node_id, &grafana, &key).await;
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (StatusCode::BAD_REQUEST, "invalid_public_key"),
            "{label}"
        );
    }
    assert_eq!(refusals(take_recording()), ["invalid_public_key"; 5]);
}

fn root_spki(der: &[u8]) -> Vec<u8> {
    let (_, root) = x509_parser::parse_x509_certificate(der).unwrap();
    root.public_key().raw.to_vec()
}

fn root_not_after(der: &[u8]) -> i64 {
    let (_, root) = x509_parser::parse_x509_certificate(der).unwrap();
    root.validity().not_after.timestamp()
}

fn base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn a_service_certificate_ends_with_the_internal_root() {
    let root_left = Duration::from_secs(u64::try_from(7 * DAY + HOUR).unwrap());
    let harness = services_harness(ROOT_VALIDITY - root_left).await;
    let node_id = node(&harness, "web-01").await;
    announce(&harness, &node_id, &[tcp("grafana")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let root_end = root_not_after(&harness.root_der);
    harness.clock.advance(u64::try_from(2 * HOUR).unwrap());
    let now = harness.clock.now_secs();
    assert!(root_end < now + 7 * DAY && root_end > now);

    let first = issued(&harness, &node_id, &grafana).await;
    assert_eq!(first["valid_before"], json!(root_end));
    assert_eq!(
        parsed(&der_of(&first["certificate_der"])).not_after,
        root_end
    );
}

#[tokio::test]
async fn purging_drops_service_certificates_only_thirty_days_after_they_expire() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    announce(&harness, &node_id, &[tcp("grafana")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let serial = issued(&harness, &node_id, &grafana).await["serial"]
        .as_i64()
        .unwrap();
    let stored = |harness: &Harness| {
        let store = harness.store.clone();
        async move {
            store
                .service_certificates()
                .get(serial)
                .await
                .unwrap()
                .is_some()
        }
    };

    harness.clock.advance(u64::try_from(37 * DAY).unwrap());
    assert_eq!(
        harness.control.purge_service_certificates().await.unwrap(),
        0
    );
    assert!(stored(&harness).await);
    harness.clock.advance(1);
    assert_eq!(
        harness.control.purge_service_certificates().await.unwrap(),
        1
    );
    assert!(!stored(&harness).await);
}

#[tokio::test]
async fn the_background_sweeper_drops_service_certificates_thirty_days_after_they_expire() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    announce(&harness, &node_id, &[tcp("grafana")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let expired = issued(&harness, &node_id, &grafana).await["serial"]
        .as_i64()
        .unwrap();
    harness.clock.advance(u64::try_from(37 * DAY + 1).unwrap());
    let fresh = issued(&harness, &node_id, &grafana).await["serial"]
        .as_i64()
        .unwrap();
    let stored = |serial: i64| {
        let store = harness.store.clone();
        async move {
            store
                .service_certificates()
                .get(serial)
                .await
                .unwrap()
                .is_some()
        }
    };
    assert!(stored(expired).await && stored(fresh).await);

    let running = serve_sweeping_often(&harness).await;
    let started = std::time::Instant::now();
    while stored(expired).await {
        assert!(
            started.elapsed() < DEADLINE,
            "the expired service certificate was not purged"
        );
        tokio::time::sleep(POLL_EVERY).await;
    }
    running.shut_down().await;

    assert!(stored(fresh).await);
}

#[tokio::test]
async fn each_node_gets_a_burst_of_sixty_four_then_six_service_certificates_a_minute() {
    let harness = services_harness(Duration::ZERO).await;
    let node_id = node(&harness, "web-01").await;
    let other = node(&harness, "web-02").await;
    announce(&harness, &node_id, &[tcp("grafana")]).await;
    announce(&harness, &other, &[tcp("loki")]).await;
    let grafana = approved(&harness, &node_id, "grafana").await;
    let loki = approved(&harness, &other, "loki").await;
    let (key, _) = spki();

    for call in 1..=64 {
        let reply = ask(&harness, &node_id, &grafana, &key).await;
        assert_eq!(reply.status, StatusCode::OK, "call {call}");
    }
    let limited = ask(&harness, &node_id, &grafana, &key).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = limited.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=10).contains(&retry), "{retry}");
    assert_eq!(
        ask(&harness, &other, &loki, &key).await.status,
        StatusCode::OK
    );

    harness.clock.advance(60);
    for call in 1..=6 {
        let reply = ask(&harness, &node_id, &grafana, &key).await;
        assert_eq!(reply.status, StatusCode::OK, "call {call} after a minute");
    }
    assert_eq!(
        ask(&harness, &node_id, &grafana, &key).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn a_node_client_certificate_is_not_a_server_certificate_under_the_pinned_root() {
    let harness = services_harness(Duration::ZERO).await;
    let (_, delivered) = harness.enrolled_node("web-01").await;
    let node_der = der_of(&delivered["x509_certificate_der"]);
    let roots = pinned_roots(&harness).await;
    let now = harness.clock.now_secs();

    assert!(client_verifies(&roots, &node_der, now));
    for name in [
        DOMAIN.to_owned(),
        "web-01".to_owned(),
        format!("web-01.tcp.{DOMAIN}"),
        format!("web-01.kube.{DOMAIN}"),
    ] {
        assert!(!server_verifies(&roots, &node_der, &name, now), "{name}");
    }
}

#[tokio::test]
async fn client_config_v2_adds_the_services_entry_and_the_transport_defaults_to_tls_with_it() {
    let harness = services_harness(Duration::ZERO).await;
    let anonymous = get(&harness.router, "/v2/client/config", None, None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);

    let alice = eight_hour_session(&harness, "alice").await;
    let raw = get(
        &harness.router,
        "/v2/client/config",
        Some(&alice.token),
        None,
    )
    .await
    .json();
    let v1 = get(&harness.router, "/v1/client-config", None, None)
        .await
        .json();
    for field in ["ssh_suffix", "gate", "host_ca_keys"] {
        assert_eq!(raw[field], v1[field], "{field}");
    }
    let mut v1_fields: Vec<&String> = v1.as_object().unwrap().keys().collect();
    v1_fields.sort();
    assert_eq!(v1_fields, ["gate", "host_ca_keys", "ssh_suffix"]);
    let parsed: ClientConfigV2 = serde_json::from_value(raw).unwrap();
    assert_eq!(parsed.ssh_gate.client_transport, ClientTransport::Tls);
    let services = parsed.services.unwrap();
    assert_eq!(services.domain, DOMAIN);
    assert_eq!(services.gate_tls_name, DOMAIN);
    assert_eq!(services.port, 443);
    assert_eq!(services.alpn, [GATE_ALPN_SSH, GATE_ALPN_SVC]);
    assert_eq!(
        (GATE_ALPN_SSH.as_bytes(), GATE_ALPN_SVC.as_bytes()),
        (jaunt_gate::ALPN_SSH, jaunt_gate::ALPN_SVC)
    );
    assert_eq!(services.roots.len(), 1);
    assert_eq!(
        der_of(&json!(services.roots[0].certificate_der)),
        harness.root_der
    );
    assert_eq!(
        services.roots[0].sha256,
        crate::support::sha256_hex_of_bytes(&harness.root_der)
    );

    for (domain, transport, expected) in [
        (None, None, ClientTransport::Tcp),
        (
            Some(DOMAIN),
            Some(ClientTransport::Tcp),
            ClientTransport::Tcp,
        ),
    ] {
        let harness = Harness::with(Options {
            services_domain: domain,
            client_transport: transport,
            gate_endpoint: Some("gate.example.com:2222"),
            ..Options::default()
        })
        .await;
        let chosen = config(&harness).await;
        assert_eq!(chosen.ssh_gate.client_transport, expected);
        assert_eq!(chosen.services.is_some(), domain.is_some());
    }
    let refused = Harness::try_with(Options {
        client_transport: Some(ClientTransport::Tls),
        ..Options::default()
    })
    .await;
    assert!(matches!(
        refused.err(),
        Some(ControlError::TlsTransportWithoutServicesDomain)
    ));
    let no_gate = Harness::with(Options {
        services_domain: Some(DOMAIN),
        ..Options::default()
    })
    .await;
    let bob = eight_hour_session(&no_gate, "bob").await;
    let reply = get(&no_gate.router, "/v2/client/config", Some(&bob.token), None).await;
    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (StatusCode::NOT_FOUND, "not_configured")
    );
}

#[tokio::test]
async fn the_gate_issuer_certifies_only_the_services_domain() {
    let harness = services_harness(Duration::ZERO).await;
    let (_, der) = spki();
    let now = harness.clock.now_secs();
    for name in [
        "other.example.com",
        "grafana.tcp.svc.example.com",
        "x.kube.svc.example.com",
        "SVC.example.com",
        "svc.example.com.",
        "example.com",
        "",
    ] {
        assert_eq!(
            harness.control.issue(&der, name).await.err(),
            Some(GateTlsIssueError::NameRefused),
            "{name:?}"
        );
    }
    let p256 = base64_decode(P256_SPKI);
    let authority = root_spki(&harness.root_der);
    for key in [p256.as_slice(), &der[12..], &[], authority.as_slice()] {
        assert_eq!(
            harness.control.issue(key, DOMAIN).await.err(),
            Some(GateTlsIssueError::InvalidKey)
        );
    }

    start_recording();
    let issued = harness.control.issue(&der, DOMAIN).await.unwrap();
    let events: Vec<Captured> = audit_events(take_recording())
        .into_iter()
        .filter(|event| event["event"] == "cert.gate.issued")
        .collect();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["serial"], issued.serial.to_string());
    assert_eq!(events[0]["valid_before"], issued.valid_before.to_string());
    let leaf = parsed(&issued.certificate_der);
    assert_eq!(leaf.sans, [format!("DNSName(\"{DOMAIN}\")")]);
    assert!(leaf.server_auth && !leaf.client_auth);
    assert_eq!(leaf.serial, u128::from(issued.serial));
    assert_eq!(
        (issued.valid_after, issued.valid_before),
        (
            u64::try_from(now - 120).unwrap(),
            u64::try_from(now + 7 * DAY).unwrap()
        )
    );
    let roots = pinned_roots(&harness).await;
    assert!(server_verifies(
        &roots,
        &issued.certificate_der,
        DOMAIN,
        now
    ));
    assert!(!server_verifies(
        &roots,
        &issued.certificate_der,
        &format!("x.kube.{DOMAIN}"),
        now
    ));
    assert!(!client_verifies(&roots, &issued.certificate_der, now));

    let without_domain = Harness::new().await;
    assert_eq!(
        without_domain.control.issue(&der, DOMAIN).await.err(),
        Some(GateTlsIssueError::NotConfigured)
    );
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}
