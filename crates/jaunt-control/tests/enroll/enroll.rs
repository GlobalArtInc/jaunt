use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_control::{ApproveError, ControlError};
use jaunt_store::{CreateOutcome, EnrollmentLimits, EnrollmentState, NewEnrollment};
use serde_json::{Map, Value, json};

use crate::support::{
    DEFAULT_PEER, Harness, HostAuthority, Options, new_agent, request_raw, send, sha256_hex,
};

const RSA_SPKI_PREFIX: [u8; 24] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
];
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

#[tokio::test]
async fn enrolling_returns_a_handle_a_code_and_the_expiry_and_stores_only_hashes() {
    let harness = Harness::new().await;
    let agent = new_agent();

    let reply = harness.enroll_body(&agent.enroll_body("web-01")).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.headers["cache-control"], "no-store");
    let body = reply.json();
    let handle = body["handle"].as_str().unwrap();
    let code = body["code"].as_str().unwrap();
    assert_eq!(handle.len(), 43);
    assert_eq!(code.len(), 9);
    assert_eq!(&code[4..5], "-");
    assert_eq!(body["expires_at"], harness.clock.now_secs() + 900);
    assert_eq!(body["poll_interval"], 3);

    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&sha256_hex(handle))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, EnrollmentState::Pending);
    assert_eq!(stored.code_hash, sha256_hex(&code.replace('-', "")));
    assert_eq!(stored.source_ip, DEFAULT_PEER);
    assert_eq!(stored.peer_addr, DEFAULT_PEER);
    assert_eq!(stored.name, "web-01");
    assert_eq!(stored.labels["env"], "prod");
    assert_eq!(stored.tls_public_key, agent.tls_public_key);
    assert!(!stored.ssh_host_public_key.contains("root@agent"));
    assert!(agent.ssh_line.starts_with(&stored.ssh_host_public_key));
    assert_eq!(harness.poll(handle).await.state(), "pending");
}

#[tokio::test]
async fn invalid_requests_are_refused_with_the_field_that_failed() {
    let harness = Harness::new().await;
    let agent = new_agent();
    let base = agent.enroll_body("web-01");
    let with = |field: &str, value: Value| {
        let mut body = base.clone();
        body[field] = value;
        body
    };
    let many_labels: Map<String, Value> = (0..17).map(|n| (format!("k{n}"), json!("v"))).collect();
    let rsa = STANDARD.encode([RSA_SPKI_PREFIX.as_slice(), &[1_u8; 270]].concat());
    let p256 = STANDARD.encode([P256_SPKI_PREFIX.as_slice(), &[2_u8; 64]].concat());
    let weak = STANDARD.encode([&agent.tls_der[..12], &[0_u8; 32]].concat());

    let mut cases: Vec<(&str, Value, &str)> = Vec::new();
    for name in [
        "Web-01",
        "web_01",
        "-web",
        "web-",
        "",
        "we.b",
        &"a".repeat(64),
    ] {
        cases.push(("name", with("name", json!(name)), "invalid_name"));
    }
    for labels in [
        Value::Object(many_labels),
        json!({"Bad": "x"}),
        json!({"env": "a b"}),
        json!({"1env": "x"}),
        json!({"env": "x".repeat(64)}),
    ] {
        cases.push(("labels", with("labels", labels), "invalid_labels"));
    }
    for hostname in ["", &"h".repeat(254), "web\u{7}01", "wéb", "web 01", " web"] {
        cases.push((
            "hostname",
            with("hostname", json!(hostname)),
            "invalid_hostname",
        ));
    }
    for key in ["garbage", "", rsa.as_str(), p256.as_str(), weak.as_str()] {
        cases.push((
            "tls_public_key",
            with("tls_public_key", json!(key)),
            "invalid_tls_public_key",
        ));
    }
    for key in [
        "garbage",
        "",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA",
    ] {
        cases.push((
            "ssh_host_public_key",
            with("ssh_host_public_key", json!(key)),
            "invalid_ssh_host_public_key",
        ));
    }
    for version in ["v".repeat(65), "1.0\u{7}".to_owned(), "1.0 beta".to_owned()] {
        cases.push((
            "agent_version",
            with("agent_version", json!(version)),
            "invalid_agent_version",
        ));
    }
    cases.push(("extra", with("extra", json!(1)), "invalid_request"));
    cases.push(("labels type", with("labels", json!([1])), "invalid_request"));

    for (field, body, code) in cases {
        let reply = harness.enroll_body(&body).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{field}: {}",
            reply.text()
        );
        assert_eq!(reply.error_code(), code, "{field}");
    }
}

#[tokio::test]
async fn malformed_oversized_and_unaddressed_requests_are_refused() {
    let harness = Harness::new().await;
    let body = serde_json::to_vec(&new_agent().enroll_body("web-01")).unwrap();
    let path = "/v1/agent/enroll";

    let wrong_type = send(
        harness.router.clone(),
        request_raw(path, "text/plain", body.clone(), Some(DEFAULT_PEER), None),
    )
    .await;
    assert_eq!(
        (wrong_type.status, wrong_type.error_code()),
        (StatusCode::BAD_REQUEST, "invalid_request".to_owned())
    );

    let oversized = send(
        harness.router.clone(),
        request_raw(
            path,
            "application/json",
            vec![b' '; 16 * 1024 + 1],
            Some(DEFAULT_PEER),
            None,
        ),
    )
    .await;
    assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(oversized.error_code(), "payload_too_large");

    let unaddressed = send(
        harness.router.clone(),
        request_raw(path, "application/json", body, None, None),
    )
    .await;
    assert_eq!(unaddressed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(unaddressed.error_code(), "server_error");
}

#[tokio::test]
async fn a_name_held_by_an_active_node_needs_replace_and_pending_requests_may_share_a_name() {
    let harness = Harness::new().await;
    let first = harness.enroll("web-01").await;
    let second = harness.enroll("web-01").await;
    harness.approve(&first).await;

    let agent = new_agent();
    let refused = harness.enroll_body(&agent.enroll_body("web-01")).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.error_code(), "name_taken");

    let mut replacing = agent.enroll_body("web-01");
    replacing["replace"] = json!(true);
    let accepted = harness.enroll_body(&replacing).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());
    let replacement_code = accepted.json()["code"].as_str().unwrap().to_owned();

    let late = harness
        .admin
        .approve(&second.code, "cli:tester", None)
        .await;
    assert!(matches!(late, Err(ApproveError::NameTaken(name)) if name == "web-01"));

    let approved = harness
        .admin
        .approve(&replacement_code, "cli:tester", None)
        .await
        .unwrap();
    assert_eq!(
        approved.replaced.as_ref().map(|node| node.name.as_str()),
        Some("web-01")
    );
    assert_eq!(harness.poll(&first.handle).await.state(), "rejected");
    assert_eq!(
        harness
            .store
            .nodes()
            .get_active_by_name("web-01")
            .await
            .unwrap()
            .unwrap()
            .id,
        approved.node.id
    );
}

#[tokio::test]
async fn pending_requests_are_capped_per_source_address() {
    let harness = Harness::new().await;
    let busy = "198.51.100.7";
    for n in 0..20 {
        let body = new_agent().enroll_body(&format!("web-{n}"));
        let reply = harness.enroll_from(busy, &body).await;
        assert_eq!(reply.status, StatusCode::OK, "{n}: {}", reply.text());
    }

    let over = harness
        .enroll_from(busy, &new_agent().enroll_body("web-x"))
        .await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(over.error_code(), "too_many_requests");
    let elsewhere = harness
        .enroll_from("198.51.100.8", &new_agent().enroll_body("web-x"))
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK);

    harness.clock.advance(900);
    let later = harness
        .enroll_from(busy, &new_agent().enroll_body("web-x"))
        .await;
    assert_eq!(
        later.status,
        StatusCode::OK,
        "expired requests stop counting"
    );
}

#[tokio::test]
async fn pending_requests_are_capped_in_total() {
    let harness = Harness::new().await;
    let now = harness.clock.now_secs();
    let unlimited = EnrollmentLimits {
        max_pending: i64::MAX,
        max_pending_per_ip: i64::MAX,
    };
    for n in 0..999 {
        let outcome = harness
            .store
            .enrollments()
            .create(
                &NewEnrollment {
                    handle_hash: format!("handle-{n}"),
                    code_hash: format!("code-{n}"),
                    name: format!("filler-{n}"),
                    labels: Default::default(),
                    hostname: "filler".to_owned(),
                    source_ip: format!("192.0.2.{}", n % 200),
                    peer_addr: format!("192.0.2.{}", n % 200),
                    tls_public_key: "tls".to_owned(),
                    ssh_host_public_key: "ssh".to_owned(),
                    replace_existing: false,
                    agent_version: "0".to_owned(),
                    ttl_secs: 900,
                },
                unlimited,
                now,
            )
            .await
            .unwrap();
        assert!(matches!(outcome, CreateOutcome::Created(_)));
    }

    let last = harness
        .enroll_from("203.0.113.99", &new_agent().enroll_body("web-1000"))
        .await;
    assert_eq!(last.status, StatusCode::OK, "{}", last.text());
    let over = harness
        .enroll_from("203.0.113.98", &new_agent().enroll_body("web-1001"))
        .await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(over.error_code(), "too_many_requests");
}

#[tokio::test]
async fn only_a_host_authority_that_matches_the_trust_set_is_accepted() {
    for (host_authority, expected) in [
        (HostAuthority::Matching, None),
        (HostAuthority::WrongKind, Some("NotHostAuthority")),
        (
            HostAuthority::NotTheTrustedKey,
            Some("HostAuthorityNotTrusted"),
        ),
    ] {
        let built = Harness::try_with(Options {
            host_authority,
            ..Options::default()
        })
        .await;
        let outcome = match built {
            Ok(_) => None,
            Err(ControlError::NotHostAuthority) => Some("NotHostAuthority"),
            Err(ControlError::HostAuthorityNotTrusted) => Some("HostAuthorityNotTrusted"),
            Err(other) => panic!("unexpected {other}"),
        };
        assert_eq!(outcome, expected);
    }
}

#[tokio::test]
async fn the_per_address_cap_applies_to_the_whole_64_bit_prefix_of_an_ipv6_source() {
    let harness = Harness::new().await;
    let mut replies = Vec::new();
    for n in 1..=20 {
        let peer = format!("2001:db8:1:2::{n:x}");
        let reply = harness
            .enroll_from(&peer, &new_agent().enroll_body(&format!("web-{n}")))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{peer}: {}", reply.text());
        replies.push(reply.json());
    }
    let mut stored = Vec::new();
    for reply in &replies[..2] {
        let handle = reply["handle"].as_str().unwrap();
        stored.push(
            harness
                .store
                .enrollments()
                .get_by_handle_hash(&sha256_hex(handle))
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert_eq!(stored[0].peer_addr, "2001:db8:1:2::1");
    assert_eq!(stored[1].peer_addr, "2001:db8:1:2::2");
    assert_eq!(stored[0].source_ip, "2001:db8:1:2::/64");
    assert_eq!(stored[1].source_ip, "2001:db8:1:2::/64");
    let first = harness
        .admin
        .pending(replies[0]["code"].as_str().unwrap())
        .await
        .unwrap();
    let second = harness
        .admin
        .pending(replies[1]["code"].as_str().unwrap())
        .await
        .unwrap();
    assert_ne!(first.peer_addr, second.peer_addr);
    assert_eq!(first.source_network, second.source_network);

    let same_prefix = harness
        .enroll_from("2001:db8:1:2:ffff::1", &new_agent().enroll_body("web-21"))
        .await;
    assert_eq!(same_prefix.status, StatusCode::TOO_MANY_REQUESTS);
    let other_prefix = harness
        .enroll_from("2001:db8:1:3::1", &new_agent().enroll_body("web-22"))
        .await;
    assert_eq!(other_prefix.status, StatusCode::OK);
    let mapped = harness
        .enroll_from("::ffff:203.0.113.77", &new_agent().enroll_body("web-23"))
        .await;
    assert_eq!(mapped.status, StatusCode::OK);
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&sha256_hex(mapped.json()["handle"].as_str().unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.source_ip, "203.0.113.77");
    assert_eq!(stored.peer_addr, "203.0.113.77");
}

#[tokio::test]
async fn every_enrollment_attempt_counts_against_a_per_source_limit_whatever_its_outcome() {
    let harness = Harness::new().await;
    harness.approve(&harness.enroll("web-01").await).await;
    let taken = new_agent().enroll_body("web-01");
    let invalid = new_agent().enroll_body("Bad_Name");
    for n in 1..60 {
        let (body, status) = if n % 2 == 0 {
            (&taken, StatusCode::CONFLICT)
        } else {
            (&invalid, StatusCode::BAD_REQUEST)
        };
        let reply = harness.enroll_body(body).await;
        assert_eq!(reply.status, status, "attempt {n}: {}", reply.text());
    }

    for body in [&taken, &invalid, &new_agent().enroll_body("web-02")] {
        let limited = harness.enroll_body(body).await;
        assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.error_code(), "too_many_requests");
    }
    let elsewhere = harness
        .enroll_from("198.51.100.1", &new_agent().enroll_body("web-02"))
        .await;
    assert_eq!(elsewhere.status, StatusCode::OK);

    harness.clock.advance(600);
    let later = harness.enroll_body(&taken).await;
    assert_eq!(later.status, StatusCode::CONFLICT);
}
