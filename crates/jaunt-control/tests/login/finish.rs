use std::process::Command;

use axum::http::StatusCode;
use jaunt_ca::Uuid;
use jaunt_ca::ssh_key::certificate::CertType;
use jaunt_ca::ssh_key::public::{KeyData, SkEd25519};
use jaunt_ca::ssh_key::{Certificate, PublicKey};
use serde_json::{Value, json};

use crate::support::{
    DEFAULT_CERT_TTL_SECS, Harness, LOGIN_TTL_SECS, Options, UNISSUED_CODE,
    ed25519_public_key_line, sha256_hex,
};

const RSA_PUBLIC_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbq8RTZjt4CE3S8rO3jTGFkWZNb/VU4RKaU7as+YNXyAP7sB2MGZBYgM/zsaJM4QJqOyiIWaXGKaSV2jPK0zjEZ+G1yAGKKutJuHInAw+zZYCdcZsKMPyENxGarTBfziudWiQVVdjf0QBuWDF0UOFgwRe2JMWgP8fz/9Gin3ZdLIIZGiCdZbwLmGMHEy8WIwV+PtdJ2xy2uP+5+bAcoP/TTg4i3yvmrf/POnL5GoXimJYc/1X3YXCc2KmO/wJBeoyVc2FbScDpGQJRZN8feRqzTeevM/vT9D2P86z7JKNgDgH0wDXIOKDnkPzjegvTMrf/6Vc9fczxZpPElguEAQyN";
const ECDSA_PUBLIC_KEY: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIXyZONjjt2pzRYePwe5K3V8M7ZUC3D4ojb+J69S2a6G5qgmn4ClOqI1PHn33Dtgrv3kGFUhwYjnV45peLMoBEc=";

fn security_key_line() -> String {
    let line = ed25519_public_key_line("");
    let key = PublicKey::from_openssh(&line).unwrap();
    let ed25519 = *key.key_data().ed25519().unwrap();
    PublicKey::from(KeyData::SkEd25519(SkEd25519::new(ed25519, "ssh:")))
        .to_openssh()
        .unwrap()
}

fn str_field<'a>(body: &'a Value, name: &str) -> &'a str {
    body[name].as_str().unwrap()
}

fn int_field(body: &Value, name: &str) -> i64 {
    body[name].as_i64().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn full_login_issues_a_certificate_a_token_and_the_host_keys() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let public_key = ed25519_public_key_line("alice@laptop");

    let reply = harness.finish(&session, &public_key).await;

    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    assert_eq!(reply.header("content-type"), "application/json");
    assert_eq!(reply.header("cache-control"), "no-store");
    assert_eq!(reply.header("referrer-policy"), "no-referrer");
    let body = reply.json();

    let certificate = Certificate::from_openssh(str_field(&body, "certificate")).unwrap();
    let user_id = str_field(&body, "user_id");
    assert!(Uuid::parse_str(user_id).is_ok());
    assert_eq!(certificate.cert_type(), CertType::User);
    assert_eq!(certificate.valid_principals(), [user_id]);
    let serial = int_field(&body, "serial");
    assert_eq!(certificate.serial(), u64::try_from(serial).unwrap());
    let expected_key_id = format!("jaunt:alice@example.com:{serial}");
    assert_eq!(certificate.key_id(), expected_key_id);
    assert_eq!(str_field(&body, "key_id"), expected_key_id);
    assert_eq!(str_field(&body, "email"), "alice@example.com");
    let subject = PublicKey::from_openssh(&public_key).unwrap();
    assert_eq!(certificate.public_key(), subject.key_data());

    let now = harness.clock.now_secs();
    let ttl = i64::try_from(DEFAULT_CERT_TTL_SECS).unwrap();
    assert_eq!(int_field(&body, "valid_after"), now - 120);
    assert_eq!(int_field(&body, "valid_before"), now + ttl);
    assert_eq!(int_field(&body, "token_expires_at"), now + ttl);
    assert_eq!(
        certificate.valid_before(),
        u64::try_from(now + ttl).unwrap()
    );

    let host_keys: Vec<&str> = body["host_ca_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap())
        .collect();
    assert_eq!(host_keys, harness.host_keys);

    let stored = harness
        .store
        .certificates()
        .get(serial)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.user_id, user_id);
    assert_eq!(stored.kind, "user");
    assert_eq!(stored.key_id, expected_key_id);
    assert_eq!(stored.valid_before, now + ttl);
    assert_eq!(stored.issued_at, now);

    let token = str_field(&body, "api_token");
    assert!(token.starts_with("jt_"));
    let whoami = harness.whoami(token).await;
    assert_eq!(whoami.status, StatusCode::OK);
    assert_eq!(whoami.json()["user_id"], user_id);
    assert_eq!(whoami.json()["cert_serial"], serial);
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_lifetime_is_clamped_to_the_maximum_user_validity() {
    for (configured, expected) in [(3600, 3600), (2 * 86_400, 86_400)] {
        let harness = Harness::with(Options {
            cert_ttl_secs: configured,
            ..Options::default()
        })
        .await;

        let body = harness.login().await;

        let now = harness.clock.now_secs();
        assert_eq!(int_field(&body, "valid_before"), now + expected);
        assert_eq!(int_field(&body, "token_expires_at"), now + expected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn issued_certificate_is_readable_by_ssh_keygen() {
    let harness = Harness::new().await;
    let body = harness.login().await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("user-cert.pub");
    std::fs::write(&path, str_field(&body, "certificate")).unwrap();

    let output = match Command::new("ssh-keygen")
        .args(["-L", "-f"])
        .arg(&path)
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: ssh-keygen is not installed");
            return;
        }
        Err(err) => panic!("ssh-keygen failed to start: {err}"),
    };

    assert!(output.status.success());
    let listing = String::from_utf8(output.stdout).unwrap();
    let serial = int_field(&body, "serial");
    assert!(listing.contains("user certificate"));
    assert!(listing.contains(&format!("Key ID: \"jaunt:alice@example.com:{serial}\"")));
    assert!(listing.contains(&format!("Serial: {serial}")));
    assert!(listing.contains(str_field(&body, "user_id")));
}

#[tokio::test(flavor = "multi_thread")]
async fn second_finish_after_success_is_invalid_grant() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let public_key = ed25519_public_key_line("alice");
    assert_eq!(
        harness.finish(&session, &public_key).await.status,
        StatusCode::OK
    );

    let again = harness.finish(&session, &public_key).await;

    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.error_code(), "invalid_grant");
    assert!(harness.store.certificates().get(2).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_verifier_is_refused_and_does_not_burn_the_request() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let public_key = ed25519_public_key_line("alice");

    let wrong = harness
        .finish_raw(
            &session.login_id,
            &harness.next_verifier(),
            session.completion_code(),
            &public_key,
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.error_code(), "invalid_grant");

    let right = harness.finish(&session, &public_key).await;
    assert_eq!(right.status, StatusCode::OK, "{}", right.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_before_the_callback_is_invalid_grant() {
    let harness = Harness::new().await;
    let session = harness.begin().await;

    let early = harness
        .finish(&session, &ed25519_public_key_line("alice"))
        .await;

    assert_eq!(early.status, StatusCode::BAD_REQUEST);
    assert_eq!(early.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_for_an_unknown_or_foreign_kind_request_is_invalid_grant() {
    let harness = Harness::new().await;
    let unknown = harness
        .finish_raw(
            "0b1f2a3c-4d5e-4f60-8a7b-9c8d7e6f5a4b",
            &harness.next_verifier(),
            UNISSUED_CODE,
            &ed25519_public_key_line("alice"),
        )
        .await;
    assert_eq!(unknown.error_code(), "invalid_grant");

    let verifier = harness.next_verifier();
    let web = harness
        .store
        .login_requests()
        .create(
            &jaunt_store::NewLoginRequest {
                kind: "web".to_owned(),
                pkce_challenge: crate::support::challenge_for(&verifier),
                client_label: None,
                ttl_secs: 300,
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    let user = harness
        .store
        .users()
        .upsert(
            &jaunt_store::NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "web-user".to_owned(),
                email: "web@example.com".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            harness.clock.now_secs(),
        )
        .await
        .unwrap();
    assert!(
        harness
            .store
            .login_requests()
            .approve(
                &web.id,
                &user.id,
                Some(&sha256_hex(UNISSUED_CODE)),
                harness.clock.now_secs(),
            )
            .await
            .unwrap()
    );

    let foreign = harness
        .finish_raw(
            &web.id,
            &verifier,
            UNISSUED_CODE,
            &ed25519_public_key_line("alice"),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::BAD_REQUEST);
    assert_eq!(foreign.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_after_the_request_expired_is_invalid_grant() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    harness.clock.advance(LOGIN_TTL_SECS + 1);

    let late = harness
        .finish(&session, &ed25519_public_key_line("alice"))
        .await;

    assert_eq!(late.status, StatusCode::BAD_REQUEST);
    assert_eq!(late.error_code(), "invalid_grant");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_finish_calls_issue_exactly_one_certificate() {
    let harness = std::sync::Arc::new(Harness::new().await);
    let session = harness.begin().await;
    harness.approve(&session).await;

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let harness = harness.clone();
        let login_id = session.login_id.clone();
        let verifier = session.verifier.clone();
        let completion = session.completion_code().to_owned();
        tasks.push(tokio::spawn(async move {
            harness
                .finish_raw(
                    &login_id,
                    &verifier,
                    &completion,
                    &ed25519_public_key_line("alice"),
                )
                .await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        let reply = task.await.unwrap();
        match reply.status {
            StatusCode::OK => winners += 1,
            StatusCode::BAD_REQUEST => assert_eq!(reply.error_code(), "invalid_grant"),
            other => panic!("unexpected status {other}"),
        }
    }

    assert_eq!(winners, 1);
    let certificates = harness.store.certificates();
    assert!(certificates.get(1).await.unwrap().is_some());
    assert!(certificates.get(2).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_accepts_only_plain_ed25519_public_keys() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let good = ed25519_public_key_line("alice@laptop");
    let unsupported = [
        ("rsa", RSA_PUBLIC_KEY.to_owned()),
        ("ecdsa", ECDSA_PUBLIC_KEY.to_owned()),
        ("security key", security_key_line()),
        ("options prefix", format!("no-pty,command=\"id\" {good}")),
        ("two lines", format!("{good}\n{good}")),
        ("garbage", "not a key".to_owned()),
        ("empty", String::new()),
    ];

    for (name, key) in unsupported {
        let reply = harness.finish(&session, &key).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(reply.error_code(), "invalid_grant", "{name}");
    }

    let accepted = harness.finish(&session, &format!("{good}\n")).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn finish_rejects_malformed_requests() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let key = ed25519_public_key_line("alice");
    let valid = json!({
        "login_id": session.login_id,
        "code_verifier": session.verifier,
        "completion_code": session.completion_code(),
        "public_key": key,
    });
    let with = |name: &str, value: Value| {
        let mut body = valid.clone();
        body[name] = value;
        body
    };
    let without = |name: &str| {
        let mut body = valid.clone();
        body.as_object_mut().unwrap().remove(name);
        body
    };
    let cases = [
        (
            "unknown field",
            with("redirect_host", json!("evil.example")),
        ),
        ("missing verifier", without("code_verifier")),
        ("missing key", without("public_key")),
        ("numeric completion code", with("completion_code", json!(7))),
        ("numeric login id", with("login_id", json!(7))),
        ("login id not a uuid", with("login_id", json!("not-a-uuid"))),
        (
            "uppercase login id",
            with("login_id", json!(session.login_id.to_uppercase())),
        ),
        (
            "short verifier",
            with("code_verifier", json!("a".repeat(42))),
        ),
        (
            "long verifier",
            with("code_verifier", json!("a".repeat(129))),
        ),
        (
            "verifier charset",
            with("code_verifier", json!(format!("{}+", "a".repeat(42)))),
        ),
    ];
    for (name, body) in cases {
        let reply = harness.post_json("/v1/login/finish", &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(reply.error_code(), "invalid_request", "{name}");
    }

    let not_json = harness
        .post_raw("/v1/login/finish", Some("application/json"), b"[".to_vec())
        .await;
    assert_eq!(not_json.error_code(), "invalid_request");
    let wrong_type = harness
        .post_raw(
            "/v1/login/finish",
            Some("text/plain"),
            serde_json::to_vec(&valid).unwrap(),
        )
        .await;
    assert_eq!(wrong_type.error_code(), "invalid_request");
    let no_type = harness
        .post_raw(
            "/v1/login/finish",
            None,
            serde_json::to_vec(&valid).unwrap(),
        )
        .await;
    assert_eq!(no_type.error_code(), "invalid_request");

    let still_valid = harness.post_json("/v1/login/finish", &valid).await;
    assert_eq!(still_valid.status, StatusCode::OK, "{}", still_valid.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_bodies_are_refused_with_payload_too_large() {
    let harness = Harness::new().await;
    for path in ["/v1/login/start", "/v1/login/finish"] {
        let padding = "x".repeat(16 * 1024 + 1);
        let body = serde_json::to_vec(&json!({ "padding": padding })).unwrap();

        let reply = harness.post_raw(path, Some("application/json"), body).await;

        assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(reply.error_code(), "payload_too_large", "{path}");
        assert_eq!(reply.header("cache-control"), "no-store");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_wrong_completion_code_is_refused_and_does_not_burn_the_request() {
    let harness = Harness::new().await;
    let session = harness.begin().await;
    harness.approve(&session).await;
    let key = ed25519_public_key_line("alice");
    let valid = json!({
        "login_id": session.login_id,
        "code_verifier": session.verifier,
        "completion_code": session.completion_code(),
        "public_key": key,
    });
    let with = |value: Value| {
        let mut body = valid.clone();
        body["completion_code"] = value;
        body
    };
    let mut absent = valid.clone();
    absent.as_object_mut().unwrap().remove("completion_code");
    let cases = [
        ("field absent", absent),
        ("null", with(Value::Null)),
        ("empty", with(json!(""))),
        ("too short", with(json!("short"))),
        (
            "too long",
            with(json!(format!("{}A", session.completion_code()))),
        ),
        ("never issued", with(json!(UNISSUED_CODE))),
        ("the verifier", with(json!(session.verifier))),
        ("the login id", with(json!(session.login_id))),
        ("the provider state", with(json!(session.state))),
        (
            "the stored hash",
            with(json!(sha256_hex(session.completion_code()))),
        ),
    ];
    for (name, body) in cases {
        let reply = harness.post_json("/v1/login/finish", &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(reply.error_code(), "invalid_grant", "{name}");
    }

    let wrong_verifier = harness
        .finish_raw(
            &session.login_id,
            &harness.next_verifier(),
            session.completion_code(),
            &key,
        )
        .await;
    assert_eq!(wrong_verifier.error_code(), "invalid_grant");

    let stored = harness
        .store
        .login_requests()
        .get(&session.login_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, jaunt_store::LoginRequestState::Approved);
    assert!(harness.store.certificates().get(1).await.unwrap().is_none());
    let right = harness.post_json("/v1/login/finish", &valid).await;
    assert_eq!(right.status, StatusCode::OK, "{}", right.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_party_that_never_saw_the_completion_code_cannot_finish_the_login() {
    let harness = Harness::new().await;
    let attacker_verifier = harness.next_verifier();
    let started = harness
        .start_body(&json!({
            "code_challenge": crate::support::challenge_for(&attacker_verifier),
            "code_challenge_method": "S256",
            "redirect_port": 45123,
        }))
        .await
        .json();
    let login_id = started["login_id"].as_str().unwrap().to_owned();
    let authorize_url = started["authorize_url"].as_str().unwrap().to_owned();
    let state =
        crate::provider::form_pairs(authorize_url.split_once('?').unwrap().1)["state"].clone();
    let victim_code = harness
        .provider
        .grant(&authorize_url, crate::provider::Identity::alice());
    let victim_redirect = harness
        .callback(&format!("code={victim_code}&state={state}"))
        .await;
    assert_eq!(victim_redirect.status, StatusCode::FOUND);
    let completion = victim_redirect
        .location()
        .split_once("&code=")
        .unwrap()
        .1
        .to_owned();
    let attacker_key = ed25519_public_key_line("mallory");

    let guesses = [
        login_id.as_str(),
        attacker_verifier.as_str(),
        state.as_str(),
        UNISSUED_CODE,
    ];
    for guess in guesses {
        let reply = harness
            .finish_raw(&login_id, &attacker_verifier, guess, &attacker_key)
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{guess}");
        assert_eq!(reply.error_code(), "invalid_grant", "{guess}");
    }
    let bare = harness
        .post_json(
            "/v1/login/finish",
            &json!({
                "login_id": login_id,
                "code_verifier": attacker_verifier,
                "public_key": attacker_key,
            }),
        )
        .await;
    assert_eq!(bare.error_code(), "invalid_grant");
    let victim_side = harness
        .finish_raw(
            &login_id,
            &harness.next_verifier(),
            &completion,
            &ed25519_public_key_line("alice"),
        )
        .await;
    assert_eq!(victim_side.error_code(), "invalid_grant");
    assert!(harness.store.certificates().get(1).await.unwrap().is_none());

    let legitimate = harness
        .finish_raw(&login_id, &attacker_verifier, &completion, &attacker_key)
        .await;
    assert_eq!(legitimate.status, StatusCode::OK, "{}", legitimate.text());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_approved_loopback_request_without_a_completion_hash_is_a_server_error() {
    let harness = Harness::new().await;
    let verifier = harness.next_verifier();
    let requests = harness.store.login_requests();
    let now = harness.clock.now_secs();
    let request = requests
        .create(
            &jaunt_store::NewLoginRequest {
                kind: "loopback".to_owned(),
                pkce_challenge: crate::support::challenge_for(&verifier),
                client_label: None,
                ttl_secs: 300,
            },
            now,
        )
        .await
        .unwrap();
    let user = harness
        .store
        .users()
        .upsert(
            &jaunt_store::NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: "unbound".to_owned(),
                email: "unbound@example.com".to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            now,
        )
        .await
        .unwrap();
    assert!(
        requests
            .approve(&request.id, &user.id, None, now)
            .await
            .unwrap()
    );

    let reply = harness
        .finish_raw(
            &request.id,
            &verifier,
            UNISSUED_CODE,
            &ed25519_public_key_line("alice"),
        )
        .await;

    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.error_code(), "server_error");
    let stored = requests.get(&request.id).await.unwrap().unwrap();
    assert_eq!(stored.state, jaunt_store::LoginRequestState::Approved);
}
