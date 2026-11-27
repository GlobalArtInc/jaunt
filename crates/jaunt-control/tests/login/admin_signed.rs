use std::time::Duration;

use axum::http::{Method, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::admin_signature::{AgentSigner, SignedHeaders, new_nonce};
use jaunt::agent::SshAgent;
use jaunt::secret::Secret;
use jaunt_ca::ssh_key::{HashAlg, LineEnding, PrivateKey};
use jaunt_control::RevokeRequest;
use jaunt_proto::{admin_signature_base, admin_signature_params};
use jaunt_store::RevocationKind;
use ssh_encoding::Encode;

use crate::audit::{start_recording, take_recording};
use crate::provider::Identity;
use crate::signed_support::{
    LOOKUP, LOOKUP_BODY, NOISE_GAP_SECS, RealAgent, WHOAMI, accepted, admin_harness,
    assert_unauthorized, cli_login, event, new_key, outcomes, pairs, send, send_pairs, sign,
    sign_for, unproven,
};
use crate::support::{DEFAULT_PEER, Harness, Options, PUBLIC_ORIGIN};
use crate::web_support::{APPROVER_AND_OPS_ROLES, bob};

const NAMESPACE: &str = "jaunt-admin@1";

#[tokio::test(flavor = "multi_thread")]
async fn a_request_signed_with_the_profile_key_file_reaches_the_admin_route_and_is_audited() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    start_recording();

    let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    let events = take_recording();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["email"], "alice@example.com");
    assert_eq!(outcomes(&events), [accepted()]);
    let audited = event(&events, "admin.signed_request")[0];
    assert_eq!(audited["serial"], alice.serial.to_string());
    assert_eq!(audited["user_id"], alice.user_id());
    assert_eq!(audited["path"], WHOAMI);
    assert_eq!(
        audited["client_addr"],
        DEFAULT_PEER.split(':').next().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_signed_through_a_real_ssh_agent_is_accepted() {
    let Some(agent) = RealAgent::start().await else {
        return;
    };
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let pem = alice.key.to_openssh(LineEnding::LF).unwrap();
    SshAgent::new(Some(agent.socket.clone().into_os_string()))
        .add(&Secret::new(pem.to_string()), 300)
        .unwrap();
    let signer = AgentSigner::new(agent.socket.clone(), Duration::from_secs(10));

    let signed = sign_for(
        &alice.certificate,
        &signer,
        "GET",
        &format!("{PUBLIC_ORIGIN}{WHOAMI}"),
        b"",
        harness.clock.now_secs(),
    );
    let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.json()["email"], "alice@example.com");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_request_is_refused_with_a_generic_401() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    start_recording();

    let first = send(&harness, Method::GET, WHOAMI, &signed, b"").await;
    harness.clock.advance(5);
    let replay = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(first.status, StatusCode::OK);
    assert_unauthorized(&replay);
    assert_eq!(
        outcomes(&take_recording()),
        [accepted(), unproven("replayed_nonce")]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn created_beyond_the_window_is_refused_and_the_edges_pass() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    harness.clock.advance(200);
    start_recording();

    for (offset, status) in [
        (-120, StatusCode::OK),
        (120, StatusCode::OK),
        (-121, StatusCode::UNAUTHORIZED),
        (121, StatusCode::UNAUTHORIZED),
    ] {
        harness.clock.advance(NOISE_GAP_SECS);
        let now = harness.clock.now_secs();
        let signed = sign(&alice, "GET", WHOAMI, b"", now + offset);
        let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;
        assert_eq!(reply.status, status, "{offset}");
    }

    assert_eq!(
        outcomes(&take_recording()),
        [
            accepted(),
            accepted(),
            unproven("created_skew"),
            unproven("created_skew")
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_signed_before_control_started_is_refused_even_inside_the_window() {
    let harness = admin_harness().await;
    let started = harness.clock.now_secs();
    let alice = cli_login(&harness, Identity::alice()).await;
    harness.clock.advance(60);
    start_recording();

    let before = sign(&alice, "GET", WHOAMI, b"", started - 1);
    let at_start = sign(&alice, "GET", WHOAMI, b"", started);
    let after = sign(&alice, "GET", WHOAMI, b"", started + 1);
    let refused_reply = send(&harness, Method::GET, WHOAMI, &before, b"").await;
    let at_start_reply = send(&harness, Method::GET, WHOAMI, &at_start, b"").await;
    let after_reply = send(&harness, Method::GET, WHOAMI, &after, b"").await;

    assert_unauthorized(&refused_reply);
    assert_eq!(at_start_reply.status, StatusCode::OK);
    assert_eq!(after_reply.status, StatusCode::OK);
    assert_eq!(
        outcomes(&take_recording()),
        [unproven("before_start"), accepted(), accepted()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tampered_body_does_not_burn_the_nonce_and_the_honest_body_needs_no_csrf() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(
        &alice,
        "POST",
        LOOKUP,
        LOOKUP_BODY,
        harness.clock.now_secs(),
    );
    start_recording();

    let tampered = send(
        &harness,
        Method::POST,
        LOOKUP,
        &signed,
        br#"{"code":"ZZZZ-ZZZZ-ZZZZ"}"#,
    )
    .await;
    let honest = send(&harness, Method::POST, LOOKUP, &signed, LOOKUP_BODY).await;

    assert_unauthorized(&tampered);
    assert_eq!(
        honest.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        honest.text()
    );
    assert_eq!(honest.error_code(), "no_pending_enrolment");
    assert_eq!(
        outcomes(&take_recording()),
        [unproven("digest_mismatch"), accepted()]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn another_method_path_or_origin_than_the_signed_one_is_refused_before_any_lookup() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let now = harness.clock.now_secs();
    let signed = sign(&alice, "GET", WHOAMI, b"", now);
    let elsewhere = sign_for(
        &alice.certificate,
        &alice.key_file(),
        "GET",
        &format!("https://other.example{WHOAMI}"),
        b"",
        now,
    );
    start_recording();

    for (method, path, headers) in [
        (Method::POST, WHOAMI, &signed),
        (Method::GET, "/v1/admin/nodes", &signed),
        (Method::GET, WHOAMI, &elsewhere),
    ] {
        harness.clock.advance(NOISE_GAP_SECS);
        assert_unauthorized(&send(&harness, method, path, headers, b"").await);
    }
    let original = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(original.status, StatusCode::OK);
    let events = take_recording();
    assert_eq!(
        outcomes(&events),
        [
            unproven("bad_signature"),
            unproven("bad_signature"),
            unproven("bad_signature"),
            accepted()
        ]
    );
    assert!(event(&events, "authz.deny").is_empty());
}

fn with_signature(
    signed: &SignedHeaders,
    target: &str,
    key: &PrivateKey,
    namespace: &str,
    hash: HashAlg,
) -> SignedHeaders {
    let params = signed.signature_input.strip_prefix("jaunt=").unwrap();
    let base = admin_signature_base(
        ["GET", target, &signed.content_digest, &signed.certificate],
        params,
    );
    let sshsig = key.sign(namespace, hash, base.as_bytes()).unwrap();
    let mut bytes = Vec::new();
    sshsig.encode(&mut bytes).unwrap();
    SignedHeaders {
        signature: format!("jaunt=:{}:", STANDARD.encode(bytes)),
        ..signed.clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_signature_by_another_key_namespace_or_hash_is_refused() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    let target = format!("{PUBLIC_ORIGIN}{WHOAMI}");
    let stranger = new_key();
    start_recording();

    for (key, namespace, hash) in [
        (&stranger, NAMESPACE, HashAlg::Sha512),
        (&alice.key, "file", HashAlg::Sha512),
        (&alice.key, NAMESPACE, HashAlg::Sha256),
    ] {
        harness.clock.advance(NOISE_GAP_SECS);
        let forged = with_signature(&signed, &target, key, namespace, hash);
        assert_unauthorized(&send(&harness, Method::GET, WHOAMI, &forged, b"").await);
    }
    let rebuilt = with_signature(&signed, &target, &alice.key, NAMESPACE, HashAlg::Sha512);
    let reply = send(&harness, Method::GET, WHOAMI, &rebuilt, b"").await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(
        outcomes(&take_recording()),
        [
            unproven("bad_signature"),
            unproven("bad_signature"),
            unproven("bad_signature"),
            accepted()
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_headers_and_changed_covered_components_are_refused() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    let without_digest: Vec<(&str, String)> = pairs(&signed)
        .into_iter()
        .filter(|(name, _)| *name != "content-digest")
        .collect();
    let mut extra_component = pairs(&signed);
    extra_component[2].1 = signed.signature_input.replacen(
        "\"jaunt-certificate\")",
        "\"jaunt-certificate\" \"host\")",
        1,
    );
    let mut missing_component = pairs(&signed);
    missing_component[2].1 = signed
        .signature_input
        .replacen(" \"content-digest\"", "", 1);
    start_recording();

    for headers in [&without_digest, &extra_component, &missing_component] {
        harness.clock.advance(NOISE_GAP_SECS);
        assert_unauthorized(&send_pairs(&harness, Method::GET, WHOAMI, headers, b"").await);
    }

    assert_eq!(
        outcomes(&take_recording()),
        [
            unproven("missing_header"),
            unproven("covered_components"),
            unproven("covered_components")
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unproven_refusals_are_noisy_anonymous_and_counted_when_held_back() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let mut broken = pairs(&sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs()));
    broken[3].1 = "jaunt=:AAAA:".to_owned();
    start_recording();

    for _ in 0..3 {
        assert_unauthorized(&send_pairs(&harness, Method::GET, WHOAMI, &broken, b"").await);
    }
    harness.clock.advance(NOISE_GAP_SECS);
    assert_unauthorized(&send_pairs(&harness, Method::GET, WHOAMI, &broken, b"").await);

    let events = take_recording();
    let noisy = event(&events, "admin.signed_request_refused");
    assert_eq!(noisy.len(), 2);
    assert_eq!(noisy[0]["suppressed"], "0");
    assert_eq!(noisy[1]["suppressed"], "2");
    for refusal in noisy {
        assert_eq!(refusal["reason"], "bad_signature");
        assert_eq!(
            refusal["client_addr"],
            DEFAULT_PEER.split(':').next().unwrap()
        );
        assert!(refusal.get("user_id").is_none());
        assert!(refusal.get("serial").is_none());
    }
    assert!(event(&events, "admin.signed_request").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_signed_identity_wins_over_a_cookie_and_csrf_is_not_asked_for() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let bob_signed = cli_login(&harness, bob()).await;
    let alice_cookie = harness.web_sign_in().await.cookie();
    let bob_cookie = harness.web_sign_in_with("", bob()).await.cookie();
    let now = harness.clock.now_secs();

    let mut alice_with_bob_cookie = pairs(&sign(&alice, "GET", WHOAMI, b"", now));
    alice_with_bob_cookie.push(("cookie", bob_cookie.clone()));
    let mut bob_with_alice_cookie = pairs(&sign(&bob_signed, "GET", WHOAMI, b"", now));
    bob_with_alice_cookie.push(("cookie", alice_cookie.clone()));
    let mut post_with_cookie = pairs(&sign(&alice, "POST", LOOKUP, LOOKUP_BODY, now));
    post_with_cookie.push(("cookie", bob_cookie));
    let mut broken_with_cookie = pairs(&sign(&alice, "GET", WHOAMI, b"", now));
    broken_with_cookie[3].1 = "jaunt=:AAAA:".to_owned();
    broken_with_cookie.push(("cookie", alice_cookie));

    let as_alice = send_pairs(&harness, Method::GET, WHOAMI, &alice_with_bob_cookie, b"").await;
    let as_bob = send_pairs(&harness, Method::GET, WHOAMI, &bob_with_alice_cookie, b"").await;
    let posted = send_pairs(
        &harness,
        Method::POST,
        LOOKUP,
        &post_with_cookie,
        LOOKUP_BODY,
    )
    .await;
    let broken = send_pairs(&harness, Method::GET, WHOAMI, &broken_with_cookie, b"").await;

    assert_eq!(as_alice.status, StatusCode::OK, "{}", as_alice.text());
    assert_eq!(as_alice.json()["email"], "alice@example.com");
    assert_eq!(as_bob.status, StatusCode::FORBIDDEN);
    assert_eq!(
        posted.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        posted.text()
    );
    assert_unauthorized(&broken);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_admin_right_gives_a_generic_403() {
    let harness = admin_harness().await;
    let bob = cli_login(&harness, bob()).await;
    let signed = sign(&bob, "GET", WHOAMI, b"", harness.clock.now_secs());
    start_recording();

    let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    let events = take_recording();
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(reply.json(), serde_json::json!({ "error": "forbidden" }));
    let denied = event(&events, "authz.deny")[0];
    assert_eq!(denied["reason"], "policy_denied");
    assert_eq!(denied["serial"], bob.serial.to_string());
    assert_eq!(outcomes(&events), [accepted()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_captured_request_replayed_reads_no_database_and_writes_no_critical_event() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    start_recording();

    let first = send(&harness, Method::GET, WHOAMI, &signed, b"").await;
    let in_window = send(&harness, Method::GET, WHOAMI, &signed, b"").await;
    harness.clock.advance(130);
    let after_window = send(&harness, Method::GET, WHOAMI, &signed, b"").await;
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
    harness.clock.advance(NOISE_GAP_SECS);
    let after_revocation = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(first.status, StatusCode::OK);
    for reply in [&in_window, &after_window, &after_revocation] {
        assert_unauthorized(reply);
    }
    let events = take_recording();
    assert_eq!(
        outcomes(&events),
        [
            accepted(),
            unproven("replayed_nonce"),
            unproven("created_skew"),
            unproven("created_skew")
        ]
    );
    assert_eq!(event(&events, "admin.signed_request").len(), 1);
    assert!(event(&events, "authz.deny").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_signature_naming_another_serial_as_keyid_is_refused() {
    let harness = admin_harness().await;
    let alice = cli_login(&harness, Identity::alice()).await;
    let now = harness.clock.now_secs();
    let signed = sign(&alice, "GET", WHOAMI, b"", now);
    let other_serial = u64::try_from(alice.serial).unwrap() + 1;
    let params = admin_signature_params(now, &new_nonce().unwrap(), other_serial);
    let renamed = SignedHeaders {
        signature_input: format!("jaunt={params}"),
        ..signed.clone()
    };
    let target = format!("{PUBLIC_ORIGIN}{WHOAMI}");
    let forged = with_signature(&renamed, &target, &alice.key, NAMESPACE, HashAlg::Sha512);
    start_recording();

    let reply = send(&harness, Method::GET, WHOAMI, &forged, b"").await;

    assert_unauthorized(&reply);
    assert_eq!(outcomes(&take_recording()), [unproven("keyid_mismatch")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_started_with_a_clock_before_1970_answers_proven_requests_with_500() {
    let harness = Harness::with(Options {
        web: true,
        clock_before_epoch_at_start: true,
        ..Options::default()
    })
    .await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    let alice = cli_login(&harness, Identity::alice()).await;
    let signed = sign(&alice, "GET", WHOAMI, b"", harness.clock.now_secs());
    start_recording();

    let reply = send(&harness, Method::GET, WHOAMI, &signed, b"").await;

    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(outcomes(&take_recording()), [unproven("unavailable")]);
}
