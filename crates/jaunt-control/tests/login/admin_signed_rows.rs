use axum::http::{Method, StatusCode};
use jaunt_ca::fingerprint_hex;
use jaunt_ca::ssh_key::certificate::{Builder, CertType};
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Certificate, PublicKey};
use jaunt_control::RevokeRequest;
use jaunt_store::{NewCertificate, RevocationKind};

use crate::audit::{start_recording, take_recording};
use crate::provider::Identity;
use crate::signed_support::{
    Holder, LOOKUP, NOISE_GAP_SECS, WHOAMI, accepted, admin_harness, assert_unauthorized,
    cli_login, event, genuine_certificate, key_file, new_key, outcomes, refused, send, sign,
    sign_for, unproven,
};
use crate::support::{Harness, PUBLIC_ORIGIN};
use crate::web_support::bob;

fn foreign_certificate(holder: &Holder, now: i64) -> String {
    let issued = Certificate::from_openssh(&holder.certificate).unwrap();
    let foreign_ca = new_key();
    let now = u64::try_from(now).unwrap();
    let mut builder = Builder::new_with_random_nonce(
        &mut OsRng,
        holder.key.public_key().key_data().clone(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    builder.serial(issued.serial()).unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.key_id(issued.key_id()).unwrap();
    builder.valid_principal(holder.user_id()).unwrap();
    builder.sign(&foreign_ca).unwrap().to_openssh().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_unissued_web_revoked_and_expired_certificates_are_refused() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let later = cli_login(&harness, Identity::alice()).await;
    let target = format!("{PUBLIC_ORIGIN}{WHOAMI}");
    let alice_serial = u64::try_from(alice.serial).unwrap();
    let other_key = new_key();
    let line = |certificate: Certificate| certificate.to_openssh().unwrap();
    let cases = [
        (
            foreign_certificate(&alice, harness.clock.now_secs()),
            &alice.key,
        ),
        (
            line(genuine_certificate(
                &harness,
                &alice,
                &alice.key,
                alice_serial,
                true,
            )),
            &alice.key,
        ),
        (
            line(genuine_certificate(
                &harness, &alice, &alice.key, 999_999, false,
            )),
            &alice.key,
        ),
        (
            line(genuine_certificate(
                &harness,
                &alice,
                &other_key,
                alice_serial,
                false,
            )),
            &other_key,
        ),
    ];
    start_recording();

    for (certificate, key) in &cases {
        harness.clock.advance(NOISE_GAP_SECS);
        let now = harness.clock.now_secs();
        let signed = sign_for(certificate, &key_file(key), "GET", &target, b"", now);
        assert_unauthorized(&send(&harness, Method::GET, WHOAMI, &signed, b"").await);
    }
    harness
        .control
        .revocations()
        .revoke(
            &RevokeRequest {
                kind: RevocationKind::Serial,
                subject: alice.serial.to_string(),
                reason: "test".to_owned(),
            },
            "cli:test",
        )
        .await
        .unwrap();
    let now = harness.clock.now_secs();
    let revoked = sign(&alice, "GET", WHOAMI, b"", now);
    assert_unauthorized(&send(&harness, Method::GET, WHOAMI, &revoked, b"").await);
    let fresh = sign(&later, "GET", WHOAMI, b"", now);
    assert_eq!(
        send(&harness, Method::GET, WHOAMI, &fresh, b"")
            .await
            .status,
        StatusCode::OK
    );
    harness.clock.advance(8 * 60 * 60 + 1);
    let expired = sign(&later, "GET", WHOAMI, b"", harness.clock.now_secs());
    assert_unauthorized(&send(&harness, Method::GET, WHOAMI, &expired, b"").await);

    let events = take_recording();
    assert_eq!(
        outcomes(&events),
        [
            unproven("untrusted_ca"),
            unproven("web_origin"),
            refused("unknown_serial"),
            refused("serial_mismatch"),
            refused("revoked"),
            accepted(),
            refused("expired"),
        ]
    );
    let revocation_denials = event(&events, "authz.deny");
    assert_eq!(revocation_denials.len(), 1);
    assert_eq!(revocation_denials[0]["phase"], "signed_admin");
}

struct RowEdit {
    user_id: Option<String>,
    key_id: Option<String>,
    kind: Option<&'static str>,
    ca_fingerprint: Option<String>,
}

async fn record_row(harness: &Harness, certificate: &Certificate, edit: RowEdit) {
    let user_id = certificate.valid_principals()[0].clone();
    harness
        .store
        .certificates()
        .record(&NewCertificate {
            serial: i64::try_from(certificate.serial()).unwrap(),
            user_id: edit.user_id.unwrap_or(user_id),
            kind: edit.kind.unwrap_or("user").to_owned(),
            key_id: edit
                .key_id
                .unwrap_or_else(|| certificate.key_id().to_owned()),
            valid_after: i64::try_from(certificate.valid_after()).unwrap(),
            valid_before: i64::try_from(certificate.valid_before()).unwrap(),
            issued_at: harness.clock.now_secs(),
            ca_fingerprint: Some(edit.ca_fingerprint.unwrap_or_else(|| {
                fingerprint_hex(&PublicKey::from(certificate.signature_key().clone()))
            })),
            host_trust_id: None,
            subject_fingerprint: Some(fingerprint_hex(&PublicKey::from(
                certificate.public_key().clone(),
            ))),
        })
        .await
        .unwrap();
}

const UNCHANGED: RowEdit = RowEdit {
    user_id: None,
    key_id: None,
    kind: None,
    ca_fingerprint: None,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_serial_row_that_differs_in_user_key_id_kind_or_authority_is_refused() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let bob_id = cli_login(&harness, bob()).await.user_id();
    let target = format!("{PUBLIC_ORIGIN}{WHOAMI}");
    let edits = [
        UNCHANGED,
        RowEdit {
            user_id: Some(bob_id),
            ..UNCHANGED
        },
        RowEdit {
            key_id: Some("jaunt:other@example.com:1".to_owned()),
            ..UNCHANGED
        },
        RowEdit {
            kind: Some("host"),
            ..UNCHANGED
        },
        RowEdit {
            ca_fingerprint: Some("00".repeat(32)),
            ..UNCHANGED
        },
    ];
    start_recording();

    let mut statuses = Vec::new();
    for edit in edits {
        let serial = harness
            .store
            .certificates()
            .allocate_serial()
            .await
            .unwrap();
        let certificate = genuine_certificate(
            &harness,
            &alice,
            &alice.key,
            u64::try_from(serial).unwrap(),
            false,
        );
        record_row(&harness, &certificate, edit).await;
        let signed = sign_for(
            &certificate.to_openssh().unwrap(),
            &alice.key_file(),
            "GET",
            &target,
            b"",
            harness.clock.now_secs(),
        );
        statuses.push(
            send(&harness, Method::GET, WHOAMI, &signed, b"")
                .await
                .status,
        );
    }

    assert_eq!(statuses[0], StatusCode::OK);
    assert!(
        statuses[1..]
            .iter()
            .all(|status| *status == StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        outcomes(&take_recording()),
        [
            accepted(),
            refused("serial_mismatch"),
            refused("serial_mismatch"),
            refused("serial_mismatch"),
            refused("serial_mismatch"),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signed_body_one_byte_over_the_cap_is_refused_with_413() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let body = vec![b' '; 16 * 1024 + 1];
    let signed = sign(&alice, "POST", LOOKUP, &body, harness.clock.now_secs());
    start_recording();

    let reply = send(&harness, Method::POST, LOOKUP, &signed, &body).await;

    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.error_code(), "payload_too_large");
    let events = take_recording();
    assert_eq!(outcomes(&events), [unproven("body_too_large")]);
    assert!(event(&events, "admin.signed_request").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_that_fills_its_nonce_share_gets_429_with_a_retry_after() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let now = harness.clock.now_secs();
    for _ in 0..256 {
        let signed = sign(&alice, "GET", WHOAMI, b"", now);
        assert_eq!(
            send(&harness, Method::GET, WHOAMI, &signed, b"")
                .await
                .status,
            StatusCode::OK
        );
    }
    let signed = sign(&alice, "GET", WHOAMI, b"", now);
    start_recording();

    let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reply.header("retry-after"), "121");
    assert_eq!(reply.error_code(), "too_many_requests");
    assert_eq!(outcomes(&take_recording()), [refused("nonce_key_full")]);
}
