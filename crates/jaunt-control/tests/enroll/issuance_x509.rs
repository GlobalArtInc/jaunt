use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use jaunt_ca::ssh_key::HashAlg;
use jaunt_ca::{CLIENT_ROOT_VALIDITY, CaKind, CaLock, ClientCa, FileBackend};
use jaunt_control::{KillScope, RevokeRequest};
use jaunt_proto::{AgentTrustV2, AgentTrustV3, TrustRole};
use jaunt_store::{NewApiToken, NewRevocation, NewSession, RevocationKind, SessionState, Subjects};
use serde_json::{Value, json};

use crate::audit::{start_recording, take_recording};
use crate::issuance_support::{
    DAY, HOUR, RecordingKiller, Session, client_verifies, der_of, eight_hour_session, get,
    openssl_verifies, parsed, post_json, server_verifies, session, spki,
};
use crate::session_support::{NODE_NAME, audit_events, node, raw_pool};
use crate::support::{Harness, Options, Reply};

const PATH: &str = "/v1/certificates/x509";

async fn x509_harness(root_age: Duration) -> Harness {
    Harness::with(Options {
        user_x509_root_age: Some(root_age),
        ..Options::default()
    })
    .await
}

async fn request(harness: &Harness, session: &Session) -> Reply {
    let (key, _) = spki();
    post_json(
        &harness.router,
        PATH,
        Some(&session.token),
        &json!({ "public_key": key }),
    )
    .await
}

async fn issued(harness: &Harness, session: &Session) -> Value {
    let reply = request(harness, session).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    reply.json()
}

async fn trust_v3(harness: &Harness, node_id: &str) -> AgentTrustV3 {
    let reply = get(
        &harness.agent_router,
        "/v3/agent/trust",
        None,
        Some(node_id),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    serde_json::from_slice(&reply.body).unwrap()
}

fn served_roots(trust: &AgentTrustV3) -> Vec<Vec<u8>> {
    trust
        .user_x509_roots
        .iter()
        .map(|root| der_of(&json!(root.certificate_der)))
        .collect()
}

#[tokio::test]
async fn the_certificate_names_the_user_for_client_auth_and_ends_with_its_parent() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let now = harness.clock.now_secs();
    start_recording();

    let body = issued(&harness, &alice).await;

    let der = der_of(&body["certificate_der"]);
    let leaf = parsed(&der);
    let serial = body["serial"].as_i64().unwrap();
    assert_eq!(body["parent_serial"], json!(alice.parent));
    assert_eq!(leaf.serial, u128::try_from(serial).unwrap());
    assert!(serial > alice.parent);
    assert_eq!(leaf.common_names, std::slice::from_ref(&alice.email));
    assert_eq!(
        leaf.sans,
        [format!("URI(\"urn:jaunt:user:{}\")", alice.user_id)]
    );
    assert!(leaf.client_auth && !leaf.server_auth);
    assert_eq!(
        (leaf.not_before, leaf.not_after),
        (now - 120, now + 8 * HOUR)
    );
    assert_eq!(
        (body["valid_after"].as_i64(), body["valid_before"].as_i64()),
        (Some(now - 120), Some(now + 8 * HOUR))
    );

    let row = harness
        .store
        .certificates()
        .get(serial)
        .await
        .unwrap()
        .unwrap();
    let slot = harness.control.user_x509().unwrap();
    assert_eq!(row.kind, "x509");
    assert_eq!(row.user_id, alice.user_id);
    assert_eq!(row.parent_serial, Some(alice.parent));
    assert_eq!(row.valid_before, now + 8 * HOUR);
    assert_eq!(
        row.ca_fingerprint.as_deref(),
        Some(jaunt_ca::fingerprint_hex(slot.trust.active()).as_str())
    );
    assert_eq!(row.host_trust_id, None);
    assert_eq!(row.subject_fingerprint.as_ref().map(String::len), Some(64));

    let events: Vec<_> = audit_events(take_recording())
        .into_iter()
        .filter(|event| event["event"] == "cert.x509.issued")
        .collect();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event["user_id"], alice.user_id);
    assert_eq!(event["serial"], serial.to_string());
    assert_eq!(event["parent_serial"], alice.parent.to_string());
    assert_eq!(event["valid_before"], (now + 8 * HOUR).to_string());
    assert_eq!(event["client_addr"], crate::support::DEFAULT_PEER);
    for value in event.values() {
        assert!(!value.contains(&alice.token), "{event:?}");
        assert!(!value.contains("BEGIN"), "{event:?}");
    }
}

#[tokio::test]
async fn the_lifetime_never_passes_the_parent_or_the_root() {
    let harness = x509_harness(Duration::ZERO).await;
    let now = harness.clock.now_secs();
    let late_token = now + 30 * HOUR;
    let short = session(&harness, "short", (now - 120, now + HOUR), late_token).await;
    let long = session(&harness, "long", (now - 120, now + 24 * HOUR), late_token).await;
    let future = session(&harness, "future", (now + 60, now + HOUR), late_token).await;

    assert_eq!(
        issued(&harness, &short).await["valid_before"],
        json!(now + HOUR)
    );
    assert_eq!(
        issued(&harness, &long).await["valid_before"],
        json!(now + 24 * HOUR)
    );
    assert_eq!(
        request(&harness, &future).await.status,
        StatusCode::UNAUTHORIZED
    );

    harness.clock.advance(u64::try_from(HOUR - 1).unwrap());
    let last_second = issued(&harness, &short).await;
    assert_eq!(last_second["valid_before"], json!(now + HOUR));
    let leaf = parsed(&der_of(&last_second["certificate_der"]));
    assert_eq!(leaf.not_after, now + HOUR);
    harness.clock.advance(1);
    let expired = request(&harness, &short).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED);
    assert_eq!(expired.headers["www-authenticate"], "Bearer");
}

#[tokio::test]
async fn the_lifetime_stops_at_the_end_of_the_root_and_an_expired_root_issues_nothing() {
    let root_left = Duration::from_secs(u64::try_from(HOUR).unwrap());
    let harness = x509_harness(CLIENT_ROOT_VALIDITY - root_left).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let root_end = jaunt_control_root_end(&harness);
    let now = harness.clock.now_secs();
    assert!(root_end < now + 8 * HOUR && root_end > now);

    let body = issued(&harness, &alice).await;
    assert_eq!(body["valid_before"], json!(root_end));
    assert_eq!(
        parsed(&der_of(&body["certificate_der"])).not_after,
        root_end
    );

    let old = x509_harness(CLIENT_ROOT_VALIDITY + Duration::from_secs(60)).await;
    let bob = eight_hour_session(&old, "bob").await;
    assert_eq!(
        request(&old, &bob).await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
}

fn jaunt_control_root_end(harness: &Harness) -> i64 {
    let slot = harness.control.user_x509().unwrap();
    let end = slot
        .ca
        .root_not_after()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    i64::try_from(end).unwrap()
}

#[tokio::test]
async fn only_an_ed25519_spki_from_an_authenticated_session_is_accepted() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let (good, der) = spki();
    let p256 = crate::issuance_support::P256_SPKI;
    let mut trailing = der.clone();
    trailing.push(0);
    for (label, key) in [
        ("p-256", p256.to_owned()),
        (
            "ssh line",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA".to_owned(),
        ),
        ("raw key", base64_of(&der[12..])),
        ("trailing byte", base64_of(&trailing)),
        ("garbage", "!!".to_owned()),
    ] {
        let reply = post_json(
            &harness.router,
            PATH,
            Some(&alice.token),
            &json!({ "public_key": key }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{label}");
        assert_eq!(reply.error_code(), "invalid_public_key", "{label}");
    }
    let named = post_json(
        &harness.router,
        PATH,
        Some(&alice.token),
        &json!({ "public_key": good, "email": "root@example.com" }),
    )
    .await;
    assert_eq!(named.status, StatusCode::BAD_REQUEST);
    for bearer in [None, Some("jt_notavalidtoken")] {
        let reply = post_json(
            &harness.router,
            PATH,
            bearer,
            &json!({ "public_key": good }),
        )
        .await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    let without_slot = Harness::new().await;
    let bob = eight_hour_session(&without_slot, "bob").await;
    let reply = request(&without_slot, &bob).await;
    assert_eq!(
        (reply.status, reply.error_code().as_str()),
        (StatusCode::NOT_FOUND, "not_configured")
    );
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[tokio::test]
async fn each_user_may_take_ten_certificates_a_minute() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let bob = eight_hour_session(&harness, "bob").await;
    for _ in 0..10 {
        assert_eq!(request(&harness, &alice).await.status, StatusCode::OK);
    }
    let limited = request(&harness, &alice).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = limited.headers["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=6).contains(&retry), "{retry}");
    assert_eq!(request(&harness, &bob).await.status, StatusCode::OK);
    harness.clock.advance(6);
    assert_eq!(request(&harness, &alice).await.status, StatusCode::OK);
    assert_eq!(
        request(&harness, &alice).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn revoking_the_parent_revokes_the_child_everywhere_revocation_is_read() {
    let harness = x509_harness(Duration::ZERO).await;
    let node_id = node(&harness, NODE_NAME).await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let alice = eight_hour_session(&harness, "alice").await;
    let child = issued(&harness, &alice).await["serial"].as_i64().unwrap();
    let now = harness.clock.now_secs();
    let sessions = harness.store.sessions();
    let on_child = sessions
        .create(
            &NewSession {
                user_id: alice.user_id.clone(),
                serial: child,
                node_id: node_id.clone(),
                ttl_secs: 60,
            },
            now,
        )
        .await
        .unwrap();
    let revoked = |serial: i64| {
        let store = harness.store.clone();
        let user_id = alice.user_id.clone();
        async move {
            store
                .revocations()
                .any_matches(Subjects {
                    user_id: &user_id,
                    serial: Some(serial),
                    node_id: None,
                })
                .await
                .unwrap()
        }
    };
    assert!(!revoked(child).await);

    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::Serial,
                subject: alice.parent.to_string(),
                reason: "lost laptop".to_owned(),
            },
            "cli:tester",
        )
        .await
        .unwrap();

    assert!(revoked(child).await);
    let closed = sessions.get(&on_child.id).await.unwrap().unwrap();
    assert_eq!(closed.state, SessionState::Ended);
    let scopes: Vec<KillScope> = killer
        .orders()
        .into_iter()
        .map(|order| order.scope)
        .collect();
    for serial in [alice.parent, child] {
        assert!(
            scopes.contains(&KillScope::Certificate {
                user_id: alice.user_id.clone(),
                serial: u64::try_from(serial).unwrap(),
            }),
            "{serial}: {scopes:?}"
        );
    }
    assert_eq!(
        request(&harness, &alice).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_parent_revoked_by_another_process_reaches_the_child_through_the_watch() {
    let harness = x509_harness(Duration::ZERO).await;
    let killer = Arc::new(RecordingKiller::default());
    harness.control.install_session_killer(killer.clone());
    let alice = eight_hour_session(&harness, "alice").await;
    let child = issued(&harness, &alice).await["serial"].as_i64().unwrap();
    let second_child = issued(&harness, &alice).await["serial"].as_i64().unwrap();
    harness
        .store
        .revocations()
        .insert(
            &NewRevocation {
                kind: RevocationKind::Serial,
                subject: alice.parent.to_string(),
                reason: "lost laptop".to_owned(),
                created_by: "cli:root".to_owned(),
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();

    harness.control.check_revocations().await.unwrap();

    let children: Vec<u64> = killer
        .orders()
        .into_iter()
        .filter_map(|order| match order.scope {
            KillScope::Certificate { serial, .. } => Some(serial),
            _ => None,
        })
        .collect();
    for serial in [alice.parent, child, second_child] {
        assert!(
            children.contains(&u64::try_from(serial).unwrap()),
            "{serial}: {children:?}"
        );
    }
}

#[tokio::test]
async fn trust_v3_is_the_s30_set_plus_the_user_x509_roots_and_a_previous_root_still_validates() {
    let harness = x509_harness(Duration::ZERO).await;
    let node_id = node(&harness, NODE_NAME).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let first = issued(&harness, &alice).await;
    let first_der = der_of(&first["certificate_der"]);
    let now = harness.clock.now_secs();

    let v2: AgentTrustV2 = serde_json::from_slice(
        &get(
            &harness.agent_router,
            "/v2/agent/trust",
            None,
            Some(&node_id),
        )
        .await
        .body,
    )
    .unwrap();
    let before = trust_v3(&harness, &node_id).await;
    assert_eq!(
        (&before.user_ca_keys, &before.host_ca_active),
        (&v2.user_ca_keys, &v2.host_ca_active)
    );
    let raw = get(
        &harness.agent_router,
        "/v3/agent/trust",
        None,
        Some(&node_id),
    )
    .await
    .json();
    let mut fields: Vec<&String> = raw.as_object().unwrap().keys().collect();
    fields.sort();
    assert_eq!(
        fields,
        [
            "host_ca_active",
            "trust_id",
            "user_ca_keys",
            "user_x509_roots"
        ]
    );
    assert_eq!(before.user_x509_roots.len(), 1);
    let active = &before.user_x509_roots[0];
    let slot = harness.control.user_x509().unwrap();
    assert_eq!(active.role, TrustRole::Active);
    assert_eq!(
        active.fingerprint,
        jaunt_ca::fingerprint_hex(slot.trust.active())
    );
    assert_eq!(der_of(&json!(active.certificate_der)), slot.ca.root_der());
    assert!(active.not_before <= now && active.not_after > now + 4 * 365 * DAY);
    assert!(client_verifies(&served_roots(&before), &first_der, now));
    assert!(!server_verifies(
        &served_roots(&before),
        &first_der,
        "alice",
        now
    ));

    let lock = CaLock::acquire(&harness.ca_root).unwrap();
    let added = ClientCa::add_next(
        &lock,
        CaKind::UserX509,
        &harness.identity,
        std::time::SystemTime::now(),
    )
    .unwrap();
    FileBackend::promote(
        &lock,
        CaKind::UserX509,
        &harness.identity,
        &added.public_key.fingerprint(HashAlg::Sha256),
    )
    .unwrap();
    drop(lock);
    let stale = request(&harness, &alice).await;
    assert_eq!(
        (stale.status, stale.error_code().as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable")
    );
    let rotated = ClientCa::load(&harness.ca_root, CaKind::UserX509, &harness.identity).unwrap();
    harness.control.replace_user_x509(rotated).unwrap();

    let after = trust_v3(&harness, &node_id).await;
    let v2_after: AgentTrustV2 = serde_json::from_slice(
        &get(
            &harness.agent_router,
            "/v2/agent/trust",
            None,
            Some(&node_id),
        )
        .await
        .body,
    )
    .unwrap();
    assert_eq!(v2_after.trust_id, v2.trust_id);
    assert_ne!(after.trust_id, before.trust_id);
    assert_ne!(before.trust_id, v2.trust_id);
    let roles: Vec<TrustRole> = after.user_x509_roots.iter().map(|root| root.role).collect();
    assert_eq!(roles, [TrustRole::Active, TrustRole::Previous]);
    assert_eq!(after.user_x509_roots[1].fingerprint, active.fingerprint);
    let second = issued(&harness, &alice).await;
    let second_der = der_of(&second["certificate_der"]);
    let roots = served_roots(&after);
    assert!(client_verifies(&roots, &first_der, now));
    assert!(client_verifies(&roots, &second_der, now));
    assert!(!client_verifies(&served_roots(&before), &second_der, now));
    let second_row = harness
        .store
        .certificates()
        .get(second["serial"].as_i64().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        second_row.ca_fingerprint,
        Some(after.user_x509_roots[0].fingerprint.clone())
    );
    for (der, expected) in [(&first_der, true), (&second_der, true)] {
        if let Some(accepted) = openssl_verifies(&roots, der, "sslclient", now, None) {
            assert_eq!(accepted, expected);
            assert_eq!(
                openssl_verifies(&roots, der, "sslserver", now, None),
                Some(false)
            );
        }
    }

    let without_slot = Harness::new().await;
    let other = node(&without_slot, NODE_NAME).await;
    assert!(
        trust_v3(&without_slot, &other)
            .await
            .user_x509_roots
            .is_empty()
    );
    assert_eq!(
        get(&harness.agent_router, "/v3/agent/trust", None, None)
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
}

async fn x509_rows(harness: &Harness) -> i64 {
    let pool = raw_pool(harness).await;
    sqlx::query_scalar("SELECT COUNT(*) FROM certificates WHERE kind = 'x509'")
        .fetch_one(&pool)
        .await
        .unwrap()
}

async fn token_for(harness: &Harness, holder: &Session, serial: i64) -> Session {
    let now = harness.clock.now_secs();
    let token = format!("jt_{:B>43}", serial);
    harness
        .store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: crate::support::sha256_hex(&token),
            user_id: holder.user_id.clone(),
            cert_serial: serial,
            created_at: now,
            expires_at: now + 8 * HOUR,
        })
        .await
        .unwrap();
    Session {
        user_id: holder.user_id.clone(),
        email: holder.email.clone(),
        parent: serial,
        token,
    }
}

fn refused_like_an_unknown_token(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.headers["www-authenticate"], "Bearer");
    assert!(reply.body.is_empty(), "{}", reply.text());
}

#[tokio::test]
async fn a_token_bound_to_another_users_certificate_or_to_a_child_gets_nothing() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let bob = eight_hour_session(&harness, "bob").await;
    let unknown = post_json(
        &harness.router,
        PATH,
        Some(&format!("jt_{:C>43}", 1)),
        &json!({ "public_key": spki().0 }),
    )
    .await;
    refused_like_an_unknown_token(&unknown);

    let borrowed = token_for(&harness, &alice, bob.parent).await;
    start_recording();
    refused_like_an_unknown_token(&request(&harness, &borrowed).await);
    assert_eq!(foreign_parent_warnings(take_recording()), 1);
    assert_eq!(x509_rows(&harness).await, 0);

    let child = issued(&harness, &alice).await["serial"].as_i64().unwrap();
    assert_eq!(x509_rows(&harness).await, 1);
    let grandchild = token_for(&harness, &alice, child).await;
    start_recording();
    refused_like_an_unknown_token(&request(&harness, &grandchild).await);
    assert_eq!(foreign_parent_warnings(take_recording()), 1);
    assert_eq!(x509_rows(&harness).await, 1);
}

fn foreign_parent_warnings(recorded: Vec<crate::audit::Captured>) -> usize {
    recorded
        .iter()
        .filter(|event| {
            event["target"] == "jaunt::control"
                && event.get("message").is_some_and(|message| {
                    message.contains("bound to a record that is not a user certificate")
                })
        })
        .count()
}

#[tokio::test]
async fn a_child_the_store_did_not_record_is_never_handed_out() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let pool = raw_pool(&harness).await;
    sqlx::query(
        "CREATE TRIGGER drop_x509 BEFORE INSERT ON certificates WHEN NEW.kind = 'x509' \
         BEGIN SELECT RAISE(IGNORE); END",
    )
    .execute(&pool)
    .await
    .unwrap();
    start_recording();

    let reply = request(&harness, &alice).await;

    refused_like_an_unknown_token(&reply);
    assert_eq!(x509_rows(&harness).await, 0);
    assert!(
        audit_events(take_recording())
            .iter()
            .all(|event| event["event"] != "cert.x509.issued")
    );
}

enum ActiveDamage {
    Missing,
    Directory,
    Garbage,
    ForeignFingerprint,
    Oversized,
    Unreadable,
}

fn damage(active: &std::path::Path, how: &ActiveDamage) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::remove_file(active).unwrap();
    match how {
        ActiveDamage::Missing => {}
        ActiveDamage::Directory => std::fs::create_dir(active).unwrap(),
        ActiveDamage::Garbage => std::fs::write(active, b"not a fingerprint\n").unwrap(),
        ActiveDamage::ForeignFingerprint => {
            std::fs::write(active, format!("{}\n", "ab".repeat(32))).unwrap();
        }
        ActiveDamage::Oversized => std::fs::write(active, vec![b'a'; 64 * 1024]).unwrap(),
        ActiveDamage::Unreadable => {
            std::fs::write(active, b"placeholder\n").unwrap();
            std::fs::set_permissions(active, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(active).is_ok() {
                eprintln!(
                    "skipped: the active file stays readable at mode 000, as it does for root"
                );
                return false;
            }
        }
    }
    true
}

fn restore(active: &std::path::Path, original: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::symlink_metadata(active) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir(active).unwrap(),
        Ok(_) => {
            std::fs::set_permissions(active, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::remove_file(active).unwrap();
        }
        Err(_) => {}
    }
    std::fs::write(active, original).unwrap();
    std::fs::set_permissions(active, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[tokio::test]
async fn issuance_fails_closed_whenever_the_active_key_on_disk_cannot_be_confirmed() {
    let harness = x509_harness(Duration::ZERO).await;
    let alice = eight_hour_session(&harness, "alice").await;
    let active = harness.ca_root.join("user-x509").join("active");
    let original = std::fs::read(&active).unwrap();
    assert_eq!(request(&harness, &alice).await.status, StatusCode::OK);

    for (label, how) in [
        ("missing", ActiveDamage::Missing),
        ("a directory", ActiveDamage::Directory),
        ("garbage", ActiveDamage::Garbage),
        ("a foreign fingerprint", ActiveDamage::ForeignFingerprint),
        ("oversized", ActiveDamage::Oversized),
        ("mode 000", ActiveDamage::Unreadable),
    ] {
        let applies = damage(&active, &how);
        if applies {
            start_recording();
            let refused = request(&harness, &alice).await;
            assert_eq!(
                (refused.status, refused.error_code().as_str()),
                (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
                "{label}"
            );
            assert!(
                audit_events(take_recording())
                    .iter()
                    .all(|event| event["event"] != "cert.x509.issued"),
                "{label}"
            );
        }
        restore(&active, &original);
        harness.clock.advance(60);
        assert_eq!(
            request(&harness, &alice).await.status,
            StatusCode::OK,
            "{label} restored"
        );
    }
    assert_eq!(x509_rows(&harness).await, 7);
}
