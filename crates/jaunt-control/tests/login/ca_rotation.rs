use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use jaunt_ca::ssh_key::{Certificate, PublicKey};
use jaunt_ca::{AgeIdentity, CaKind, CaLock, FileBackend, fingerprint_hex};
use jaunt_control::CaSnapshot;
use jaunt_control::ca_rotation::{read_listings, reports, status_json};
use serde_json::{Value, json};

use crate::sign_hook::SignHook;
use crate::support::{Harness, Options, ed25519_public_key_line};
use crate::web_support::{APPROVER_AND_OPS_ROLES, bob, carol};

const CA_STATUS: &str = "/v1/admin/ca";

fn fresh_snapshot() -> CaSnapshot {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    for kind in [CaKind::User, CaKind::Host] {
        FileBackend::init(dir.path(), kind, &identity.recipient()).unwrap();
    }
    let (user_trust, user) = FileBackend::load(dir.path(), CaKind::User, &identity).unwrap();
    let (host_trust, host) = FileBackend::load(dir.path(), CaKind::Host, &identity).unwrap();
    CaSnapshot::new(Arc::new(user), user_trust, Arc::new(host), host_trust).unwrap()
}

fn host_lines(snapshot: &CaSnapshot) -> Value {
    json!(snapshot.host_trust().to_authorized_lines().unwrap())
}

async fn issued(harness: &Harness, body: &Value) -> (Certificate, jaunt_store::Certificate) {
    let certificate = Certificate::from_openssh(body["certificate"].as_str().unwrap()).unwrap();
    let serial = body["serial"].as_i64().unwrap();
    let row = harness
        .store
        .certificates()
        .get(serial)
        .await
        .unwrap()
        .unwrap();
    (certificate, row)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_records_the_key_that_signed_it_the_host_set_sent_with_it_and_its_subject_key()
 {
    let harness = Harness::new().await;
    let snapshot = harness.control.ca_snapshot();
    let subject_line = ed25519_public_key_line("alice@laptop");
    let subject = PublicKey::from_openssh(&subject_line).unwrap();
    let session = harness.begin().await;
    harness.approve(&session).await;

    let reply = harness.finish(&session, &subject_line).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    let (certificate, row) = issued(&harness, &body).await;
    assert_eq!(
        certificate.signature_key(),
        snapshot.user_trust().active().key_data()
    );
    assert_eq!(
        row.ca_fingerprint.as_deref(),
        Some(fingerprint_hex(snapshot.user_trust().active()).as_str())
    );
    assert_eq!(row.host_trust_id.as_deref(), Some(snapshot.host_trust_id()));
    assert_eq!(
        row.subject_fingerprint.as_deref(),
        Some(fingerprint_hex(&subject).as_str())
    );
    assert_eq!(body["host_ca_keys"], host_lines(&snapshot));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_snapshot_swapped_while_a_certificate_is_signed_does_not_split_that_issuance() {
    let hook = SignHook::default();
    let harness = Harness::with(Options {
        sign_hook: Some(hook.clone()),
        ..Options::default()
    })
    .await;
    let before = harness.control.ca_snapshot();
    let after = fresh_snapshot();
    let after_user = after.user_trust().active().clone();
    let after_host_id = after.host_trust_id().to_owned();
    let after_host_lines = host_lines(&after);
    let control = harness.control.clone();
    let replaced = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&replaced);
    hook.arm(move || {
        let previous = control.replace_snapshot(after);
        *seen.lock().unwrap() = Some(previous.user_trust_id().to_owned());
    });

    let first = harness.login().await;

    assert!(hook.fired());
    assert_eq!(
        replaced.lock().unwrap().as_deref(),
        Some(before.user_trust_id())
    );
    assert_eq!(
        harness
            .control
            .ca_snapshot()
            .user_trust()
            .active()
            .key_data(),
        after_user.key_data()
    );
    let (certificate, row) = issued(&harness, &first).await;
    assert_eq!(
        certificate.signature_key(),
        before.user_trust().active().key_data()
    );
    assert_eq!(
        row.ca_fingerprint.as_deref(),
        Some(fingerprint_hex(before.user_trust().active()).as_str())
    );
    assert_eq!(row.host_trust_id.as_deref(), Some(before.host_trust_id()));
    assert_eq!(first["host_ca_keys"], host_lines(&before));

    let second = harness.login().await;

    let (certificate, row) = issued(&harness, &second).await;
    assert_eq!(certificate.signature_key(), after_user.key_data());
    assert_eq!(
        row.ca_fingerprint.as_deref(),
        Some(fingerprint_hex(&after_user).as_str())
    );
    assert_eq!(row.host_trust_id.as_deref(), Some(after_host_id.as_str()));
    assert_eq!(second["host_ca_keys"], after_host_lines);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ca_status_needs_a_session_and_the_audit_read_permission() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let allowed = harness.web_sign_in().await;
    let without = harness.web_sign_in_with("", bob()).await;
    let approver_only = harness.web_sign_in_with("", carol()).await;

    let anonymous = harness.web_get(CA_STATUS, None).await;
    let refused = harness.web_get(CA_STATUS, Some(&without.cookie())).await;
    let approver = harness
        .web_get(CA_STATUS, Some(&approver_only.cookie()))
        .await;
    let granted = harness.web_get(CA_STATUS, Some(&allowed.cookie())).await;

    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.json(), json!({ "error": "forbidden" }));
    assert_eq!(approver.status, StatusCode::FORBIDDEN);
    assert!(!approver.text().contains("fingerprint"));
    assert_eq!(granted.status, StatusCode::OK, "{}", granted.text());
    assert_eq!(granted.header("cache-control"), "no-store");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ca_status_is_the_report_the_cli_prints() {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    harness.login().await;
    let lock = CaLock::acquire(&harness.ca_root).unwrap();
    let next = FileBackend::add_next(&lock, CaKind::User, &harness.identity).unwrap();
    drop(lock);
    let cookie = harness.web_sign_in().await.cookie();

    let reply = harness.web_get(CA_STATUS, Some(&cookie)).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let now = harness.clock.now_secs();
    let expected = status_json(
        &reports(
            &harness.store,
            read_listings(&harness.ca_root).unwrap(),
            now,
        )
        .await
        .unwrap(),
    );
    assert_eq!(reply.json(), expected);
    assert_eq!(
        reply.json()["user"]["keys"][1],
        json!({ "state": "next", "fingerprint": fingerprint_hex(&next) })
    );
    assert_eq!(reply.json()["user"]["steps"][0]["line"], "promote: ready");
    assert!(!reply.text().contains("AGE-SECRET-KEY"));
}
