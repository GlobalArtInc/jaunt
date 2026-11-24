use std::future::Future;
use std::task::Poll;
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_ca::parse_node_identity;
use jaunt_ca::ssh_key::certificate::CertType;
use jaunt_store::{EnrollmentState, NodeCertificateKind};
use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Row, SqlitePool};

use crate::support::{
    Enrolled, Harness, host_certificate_is_valid, new_agent, request, send, verify_node_certificate,
};

const FAIL_RECORDING: &str = "CREATE TRIGGER fail_certificate_insert BEFORE INSERT ON \
    node_certificates BEGIN SELECT RAISE(ABORT, 'forced'); END";

pub async fn raw_pool(harness: &Harness) -> SqlitePool {
    SqlitePool::connect_with(SqliteConnectOptions::new().filename(&harness.db_path))
        .await
        .unwrap()
}

#[tokio::test]
async fn an_approved_node_receives_verifiable_certificates_exactly_once_and_they_are_recorded() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "pending");
    let approved = harness.approve(&enrolled).await;

    let reply = harness.poll(&enrolled.handle).await;

    assert_eq!(reply.state(), "approved", "{}", reply.text());
    let body = reply.json();
    let now = harness.clock.now_secs();
    assert_eq!(body["node_id"], approved.node.id);
    assert_eq!(body["agent_endpoint"], "agents.example.com:443");
    assert_eq!(
        STANDARD
            .decode(body["internal_ca_root_der"].as_str().unwrap())
            .unwrap(),
        harness.root_der
    );

    let der = STANDARD
        .decode(body["x509_certificate_der"].as_str().unwrap())
        .unwrap();
    verify_node_certificate(&harness.root_der, &der, now).unwrap();
    verify_node_certificate(&harness.root_der, &der, now + 7 * 86_400 - 1).unwrap();
    assert!(verify_node_certificate(&harness.root_der, &der, now + 7 * 86_400 + 1).is_err());
    assert_eq!(
        parse_node_identity(&der).unwrap().node_id.to_string(),
        approved.node.id
    );
    assert_eq!(body["x509_not_after"], now + 7 * 86_400);

    let host = host_certificate_is_valid(
        body["ssh_host_certificate"].as_str().unwrap(),
        &harness.host_ca,
        now,
    );
    assert_eq!(host.cert_type(), CertType::Host);
    assert_eq!(host.valid_principals(), ["web-01.jaunt.test", "web-01"]);
    assert_eq!(host.public_key(), enrolled.agent.ssh_public_key.key_data());
    assert_eq!(body["ssh_not_after"], now + 7 * 86_400);

    let records = harness
        .store
        .nodes()
        .certificates(&approved.node.id)
        .await
        .unwrap();
    let kinds: Vec<_> = records.iter().map(|record| record.kind).collect();
    assert_eq!(kinds.len(), 2);
    assert!(
        kinds.contains(&NodeCertificateKind::X509) && kinds.contains(&NodeCertificateKind::SshHost)
    );
    let ssh_record = records
        .iter()
        .find(|record| record.kind == NodeCertificateKind::SshHost)
        .unwrap();
    assert_eq!(ssh_record.serial, format!("{:x}", host.serial()));
    assert_eq!(ssh_record.not_after, body["ssh_not_after"]);
    let x509_record = records
        .iter()
        .find(|record| record.kind == NodeCertificateKind::X509)
        .unwrap();
    assert_eq!(x509_record.not_after, body["x509_not_after"]);

    let again = harness.poll(&enrolled.handle).await;
    assert_eq!(again.state(), "already_delivered");
    assert!(again.json().get("x509_certificate_der").is_none());
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn unknown_and_malformed_handles_get_the_same_not_found_answer() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let flipped = format!(
        "{}{}",
        &enrolled.handle[..42],
        if enrolled.handle.ends_with('A') {
            'B'
        } else {
            'A'
        }
    );

    for handle in [
        flipped.as_str(),
        "short",
        "",
        &"!".repeat(43),
        &"A".repeat(43),
    ] {
        let reply = harness.poll(handle).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{handle:?}");
        assert_eq!(reply.json(), json!({"error": "not_found"}), "{handle:?}");
    }
    let wrong_shape = send(
        harness.router.clone(),
        request(
            "/v1/agent/enroll/poll",
            &json!({"handle": enrolled.handle, "x": 1}),
            None,
            None,
        ),
    )
    .await;
    assert_eq!(wrong_shape.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unapproved_request_expires_and_so_does_an_approved_one_nobody_collected() {
    let harness = Harness::new().await;
    let silent = harness.enroll("web-01").await;
    let late = harness.enroll("web-02").await;
    harness.approve(&late).await;

    harness.clock.advance(899);
    assert_eq!(harness.poll(&silent.handle).await.state(), "pending");
    harness.clock.advance(1);

    for enrolled in [&silent, &late] {
        let reply = harness.poll(&enrolled.handle).await;
        assert_eq!(reply.state(), "expired");
        assert!(reply.json().get("x509_certificate_der").is_none());
    }
    assert!(
        harness
            .admin
            .approve(&silent.code, "cli:tester", None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_rejected_request_never_receives_certificates() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    harness
        .admin
        .reject(&enrolled.code, "cli:tester")
        .await
        .unwrap();

    assert_eq!(harness.poll(&enrolled.handle).await.state(), "rejected");
    assert!(
        harness
            .admin
            .approve(&enrolled.code, "cli:tester", None)
            .await
            .is_err()
    );
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "rejected");
}

#[tokio::test]
async fn removing_the_node_before_collection_turns_the_delivery_into_a_rejection() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let approved = harness.approve(&enrolled).await;
    harness
        .admin
        .remove_node("web-01", "cli:tester")
        .await
        .unwrap();

    assert_eq!(harness.poll(&enrolled.handle).await.state(), "rejected");
    assert!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn polling_faster_than_the_limit_is_answered_with_429_until_the_window_passes() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    for n in 0..20 {
        assert_eq!(
            harness.poll(&enrolled.handle).await.state(),
            "pending",
            "{n}"
        );
    }

    let limited = harness.poll(&enrolled.handle).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.error_code(), "too_many_requests");
    let other = harness.enroll("web-02").await;
    assert_eq!(harness.poll(&other.handle).await.state(), "pending");

    harness.clock.advance(10);
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "pending");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exactly_one_of_sixteen_concurrent_polls_receives_the_certificates() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let approved = harness.approve(&enrolled).await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let router = harness.router.clone();
        let handle = enrolled.handle.clone();
        tasks.push(tokio::spawn(async move {
            send(
                router,
                request(
                    "/v1/agent/enroll/poll",
                    &json!({"handle": handle}),
                    None,
                    None,
                ),
            )
            .await
        }));
    }

    let mut winners = 0;
    for task in tasks {
        let reply = task.await.unwrap();
        let body = reply.json();
        match body["state"].as_str().unwrap() {
            "approved" => {
                winners += 1;
                assert!(body.get("x509_certificate_der").is_some());
            }
            "pending" | "already_delivered" => {
                assert!(body.get("x509_certificate_der").is_none());
                assert!(body.get("ssh_host_certificate").is_none());
            }
            other => panic!("unexpected state {other}: {body}"),
        }
    }

    assert_eq!(winners, 1);
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        harness.poll(&enrolled.handle).await.state(),
        "already_delivered"
    );
}

#[tokio::test]
async fn nothing_is_delivered_when_recording_fails_and_a_later_poll_still_delivers_once() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let approved = harness.approve(&enrolled).await;
    let pool = raw_pool(&harness).await;
    sqlx::query(FAIL_RECORDING).execute(&pool).await.unwrap();

    let failed = harness.poll(&enrolled.handle).await;

    assert_eq!(failed.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(failed.json(), json!({"error": "server_error"}));
    assert!(!failed.text().contains("forced"));
    assert!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .is_empty()
    );
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, EnrollmentState::Approved);

    sqlx::query("DROP TRIGGER fail_certificate_insert")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(harness.poll(&enrolled.handle).await.state(), "approved");
    assert_eq!(
        harness.poll(&enrolled.handle).await.state(),
        "already_delivered"
    );
    assert_eq!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn the_agent_routes_are_not_served_by_the_public_router() {
    let harness = Harness::new().await;
    let (_enrolled, body) = harness.enrolled_node("web-01").await;
    let node_id = body["node_id"].as_str().unwrap();

    let on_public = send(
        harness.router.clone(),
        request("/v1/agent/renew", &json!({}), None, Some(node_id)),
    )
    .await;
    assert_eq!(on_public.status, StatusCode::NOT_FOUND);

    let on_agent = send(
        harness.agent_router.clone(),
        request(
            "/v1/agent/enroll",
            &new_agent().enroll_body("web-02"),
            Some("203.0.113.1"),
            None,
        ),
    )
    .await;
    assert_eq!(on_agent.status, StatusCode::NOT_FOUND);
}

async fn drive_then_drop(router: Router, handle: &str, polls: usize) {
    let mut poll = Box::pin(send(
        router,
        request(
            "/v1/agent/enroll/poll",
            &json!({"handle": handle}),
            None,
            None,
        ),
    ));
    for _ in 0..polls {
        let finished =
            std::future::poll_fn(|cx| Poll::Ready(poll.as_mut().poll(cx).is_ready())).await;
        if finished {
            return;
        }
        tokio::task::yield_now().await;
    }
}

const SNAPSHOT: &str = "SELECT e.state AS state, \
    (SELECT COUNT(*) FROM node_certificates c WHERE c.node_id = e.node_id) AS certificates \
    FROM enrollments e WHERE e.id = ?";

pub async fn settled_snapshot(
    pool: &SqlitePool,
    harness: &Harness,
    enrolled: &Enrolled,
) -> (String, i64) {
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let row = sqlx::query(SNAPSHOT)
            .bind(&stored.id)
            .fetch_one(pool)
            .await
            .unwrap();
        let state: String = row.get("state");
        let certificates: i64 = row.get("certificates");
        if state != "delivering" {
            return (state, certificates);
        }
        assert!(
            Instant::now() < deadline,
            "an enrollment stayed in delivering"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub fn assert_consistent(snapshot: &(String, i64), context: &str) {
    match (snapshot.0.as_str(), snapshot.1) {
        ("delivered", 2) | ("approved", 0) => {}
        other => panic!("{context}: the enrollment ended as {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_dropped_at_any_point_of_the_delivery_never_leaves_it_stuck() {
    let harness = Harness::new().await;
    let pool = raw_pool(&harness).await;
    for polls in 0..120 {
        let peer = format!("10.1.{}.{}", polls / 200, polls % 200 + 1);
        let enrolled = harness
            .enroll_from_peer(&peer, &format!("web-{polls}"))
            .await;
        harness.approve(&enrolled).await;

        drive_then_drop(harness.router.clone(), &enrolled.handle, polls).await;

        let snapshot = settled_snapshot(&pool, &harness, &enrolled).await;
        assert_consistent(&snapshot, &format!("{polls} polls"));
    }
}

#[tokio::test]
async fn an_unclaimed_delivery_answers_pending_until_the_enrollment_expires_and_then_expired() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    harness.approve(&enrolled).await;
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap();
    let now = harness.clock.now_secs();
    harness
        .store
        .enrollments()
        .begin_delivery(&stored.id, now)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(harness.poll(&enrolled.handle).await.state(), "pending");
    harness.clock.advance(900);

    assert_eq!(harness.poll(&enrolled.handle).await.state(), "expired");
}

#[tokio::test]
async fn removing_the_node_while_its_certificates_are_being_issued_ends_the_delivery() {
    let harness = Harness::new().await;
    let enrolled = harness.enroll("web-01").await;
    let approved = harness.approve(&enrolled).await;
    let stored = harness
        .store
        .enrollments()
        .get_by_handle_hash(&enrolled.handle_hash())
        .await
        .unwrap()
        .unwrap();
    harness
        .store
        .enrollments()
        .begin_delivery(&stored.id, harness.clock.now_secs())
        .await
        .unwrap()
        .unwrap();

    harness
        .admin
        .remove_node("web-01", "cli:tester")
        .await
        .unwrap();

    assert_eq!(harness.poll(&enrolled.handle).await.state(), "rejected");
    assert!(
        harness
            .store
            .nodes()
            .certificates(&approved.node.id)
            .await
            .unwrap()
            .is_empty()
    );
}
