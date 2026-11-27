use std::time::{Duration, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use jaunt::admin_signature::{KeyFileSigner, RequestToSign, new_nonce, sign_request};
use jaunt::secret::Secret;
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use jaunt_ca::{CaKind, FileBackend, UserCertParams, Uuid, fingerprint_hex, sign_user_certificate};
use jaunt_store::NewCertificate;
use serde_json::{Value, json};

use crate::audit::{Captured, start_recording, take_recording};
use crate::session_support::user;
use crate::support::{Harness, PUBLIC_ORIGIN, Reply, send};
use crate::web_support::web_harness;

const REVOKERS: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: revokers }\nspec:\n  \
     members: { users: [approver@example.com] }\n  admin: [revocations.write]\n";

struct Signer {
    key: PrivateKey,
    certificate: String,
}

async fn issue(harness: &Harness, user_id: &str) -> Signer {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let serial = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    let (_, authority) =
        FileBackend::load(&harness.ca_root, CaKind::User, &harness.identity).unwrap();
    let now = UNIX_EPOCH + Duration::from_secs(u64::try_from(harness.clock.now_secs()).unwrap());
    let certificate = sign_user_certificate(
        &authority,
        UserCertParams {
            subject_public_key: key.public_key().clone(),
            user_id: Uuid::parse_str(user_id).unwrap(),
            email: "approver@example.com".to_owned(),
            serial: u64::try_from(serial).unwrap(),
            validity: Duration::from_secs(3600),
        },
        now,
    )
    .unwrap();
    harness
        .store
        .certificates()
        .record(&NewCertificate {
            serial,
            user_id: user_id.to_owned(),
            kind: "user".to_owned(),
            key_id: certificate.key_id().to_owned(),
            valid_after: i64::try_from(certificate.valid_after()).unwrap(),
            valid_before: i64::try_from(certificate.valid_before()).unwrap(),
            issued_at: harness.clock.now_secs(),
            ca_fingerprint: Some(fingerprint_hex(&PublicKey::from(
                certificate.signature_key().clone(),
            ))),
            host_trust_id: None,
            subject_fingerprint: Some(fingerprint_hex(key.public_key())),
        })
        .await
        .unwrap();
    Signer {
        key,
        certificate: certificate.to_openssh().unwrap(),
    }
}

async fn signed(
    harness: &Harness,
    signer: &Signer,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Reply {
    let bytes = body.map_or_else(Vec::new, |body| serde_json::to_vec(body).unwrap());
    let pem = signer.key.to_openssh(LineEnding::LF).unwrap();
    let key_file = KeyFileSigner::from_openssh(&Secret::new(pem.to_string())).unwrap();
    let target = format!("{PUBLIC_ORIGIN}{path}");
    let headers = sign_request(
        &key_file,
        &signer.certificate,
        RequestToSign {
            method: method.as_str(),
            target_uri: &target,
            body: &bytes,
        },
        harness.clock.now_secs(),
        &new_nonce().unwrap(),
    )
    .unwrap();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("jaunt-certificate", headers.certificate)
        .header("content-digest", headers.content_digest)
        .header("signature-input", headers.signature_input)
        .header("signature", headers.signature)
        .body(Body::from(bytes))
        .unwrap();
    send(harness.router.clone(), request).await
}

fn actor_of(events: &[Captured], name: &str, field: &str) -> String {
    events
        .iter()
        .find(|event| event.get("event").map(String::as_str) == Some(name))
        .unwrap_or_else(|| panic!("no {name} event"))[field]
        .clone()
}

#[tokio::test]
async fn an_intent_is_bound_to_its_certificate_and_signed_decisions_name_the_signed_actor() {
    let harness = web_harness(&[]).await;
    let approver = user(&harness, "approver", &[]).await;
    let first = issue(&harness, &approver).await;
    let second = issue(&harness, &approver).await;
    let enrolled = harness.enroll("web-01").await;
    let expected = format!("signed:{approver}");
    start_recording();

    let looked = signed(
        &harness,
        &first,
        Method::POST,
        "/v1/admin/enrolments/lookup",
        Some(&json!({ "code": enrolled.code })),
    )
    .await;
    assert_eq!(looked.status, StatusCode::OK, "{}", looked.text());
    let enrolment_id = looked.json()["enrolment"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let approve_path = format!("/v1/admin/enrolments/{enrolment_id}/approve");
    let intent = json!({ "intent": looked.json()["intent"] });
    let crossed = signed(
        &harness,
        &second,
        Method::POST,
        &approve_path,
        Some(&intent),
    )
    .await;
    let approved = signed(&harness, &first, Method::POST, &approve_path, Some(&intent)).await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.text());
    let node_id = approved.json()["node"]["id"].as_str().unwrap().to_owned();
    let removed = signed(
        &harness,
        &first,
        Method::DELETE,
        &format!("/v1/admin/nodes/{node_id}"),
        Some(&json!({ "confirm_name": "web-01" })),
    )
    .await;

    let events = take_recording();
    assert_eq!(
        (crossed.status, crossed.error_code().as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, "invalid_intent")
    );
    assert_eq!(removed.status, StatusCode::OK, "{}", removed.text());
    assert_eq!(
        actor_of(&events, "admin.enrolment.looked_up", "looked_up_by"),
        expected
    );
    assert_eq!(
        actor_of(&events, "node.enroll.approved", "approved_by"),
        expected
    );
    assert_eq!(actor_of(&events, "node.removed", "removed_by"), expected);
    let stored = harness.store.nodes().get(&node_id).await.unwrap().unwrap();
    assert_eq!(stored.approved_by, expected);
}

#[tokio::test]
async fn revocations_made_and_lifted_by_a_signed_request_name_the_signed_actor() {
    let harness = web_harness(&[REVOKERS.to_owned()]).await;
    let approver = user(&harness, "approver", &[]).await;
    let target = user(&harness, "target", &[]).await;
    let signer = issue(&harness, &approver).await;
    let expected = format!("signed:{approver}");
    start_recording();

    let created = signed(
        &harness,
        &signer,
        Method::POST,
        "/v1/admin/revocations",
        Some(&json!({ "kind": "user", "subject": target, "reason": "left" })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    let revocation = created.json()["revocation"].clone();
    let lifted = signed(
        &harness,
        &signer,
        Method::DELETE,
        &format!(
            "/v1/admin/revocations/{}",
            revocation["id"].as_str().unwrap()
        ),
        None,
    )
    .await;

    let events = take_recording();
    assert_eq!(revocation["created_by"], expected);
    assert_eq!(lifted.status, StatusCode::NO_CONTENT, "{}", lifted.text());
    assert_eq!(actor_of(&events, "revoke.created", "created_by"), expected);
    assert_eq!(actor_of(&events, "revoke.removed", "removed_by"), expected);
}
