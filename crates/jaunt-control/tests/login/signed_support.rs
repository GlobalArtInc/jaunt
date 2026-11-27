use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use jaunt::admin_signature::{
    KeyFileSigner, RequestToSign, SignedHeaders, SshSigner, new_nonce, sign_request,
};
use jaunt::secret::Secret;
use jaunt_ca::ssh_key::rand_core::OsRng;
use jaunt_ca::ssh_key::{Algorithm, Certificate, LineEnding, PrivateKey};
use jaunt_ca::{
    CaKind, FileBackend, UserCertParams, Uuid, sign_user_certificate, sign_web_user_certificate,
};
use tempfile::TempDir;

use crate::audit::Captured;
use crate::provider::Identity;
use crate::support::{Harness, PUBLIC_ORIGIN, Reply};
use crate::web_support::APPROVER_AND_OPS_ROLES;

pub const WHOAMI: &str = "/v1/admin/whoami";
pub const LOOKUP: &str = "/v1/admin/enrolments/lookup";
pub const LOOKUP_BODY: &[u8] = br#"{"code":"ABCD-EFGH-IJKL"}"#;
pub const NOISE_GAP_SECS: u64 = 10;

pub struct Holder {
    pub key: PrivateKey,
    pub certificate: String,
    pub serial: i64,
}

impl Holder {
    pub fn key_file(&self) -> KeyFileSigner {
        key_file(&self.key)
    }

    pub fn user_id(&self) -> String {
        Certificate::from_openssh(&self.certificate)
            .unwrap()
            .valid_principals()[0]
            .clone()
    }
}

pub fn key_file(key: &PrivateKey) -> KeyFileSigner {
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    KeyFileSigner::from_openssh(&Secret::new(pem.to_string())).unwrap()
}

pub fn new_key() -> PrivateKey {
    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
}

pub async fn admin_harness() -> Harness {
    let harness = Harness::with_web().await;
    harness.load_policy(APPROVER_AND_OPS_ROLES);
    harness
}

pub async fn cli_login(harness: &Harness, identity: Identity) -> Holder {
    let key = new_key();
    let session = harness.begin().await;
    let code = harness.provider.grant(&session.authorize_url, identity);
    let approved = harness
        .callback(&format!("code={code}&state={}", session.state))
        .await;
    session.record_completion(approved.location());
    let reply = harness
        .finish(&session, &key.public_key().to_openssh().unwrap())
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    Holder {
        key,
        certificate: body["certificate"].as_str().unwrap().to_owned(),
        serial: body["serial"].as_i64().unwrap(),
    }
}

pub fn sign_for(
    certificate: &str,
    signer: &dyn SshSigner,
    method: &str,
    target: &str,
    body: &[u8],
    created: i64,
) -> SignedHeaders {
    let request = RequestToSign {
        method,
        target_uri: target,
        body,
    };
    sign_request(signer, certificate, request, created, &new_nonce().unwrap()).unwrap()
}

pub fn sign(holder: &Holder, method: &str, path: &str, body: &[u8], created: i64) -> SignedHeaders {
    sign_for(
        &holder.certificate,
        &holder.key_file(),
        method,
        &format!("{PUBLIC_ORIGIN}{path}"),
        body,
        created,
    )
}

pub fn pairs(signed: &SignedHeaders) -> Vec<(&'static str, String)> {
    vec![
        ("jaunt-certificate", signed.certificate.clone()),
        ("content-digest", signed.content_digest.clone()),
        ("signature-input", signed.signature_input.clone()),
        ("signature", signed.signature.clone()),
    ]
}

pub async fn send_pairs(
    harness: &Harness,
    method: Method,
    path: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> Reply {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    harness
        .send(builder.body(Body::from(body.to_vec())).unwrap())
        .await
}

pub async fn send(
    harness: &Harness,
    method: Method,
    path: &str,
    signed: &SignedHeaders,
    body: &[u8],
) -> Reply {
    send_pairs(harness, method, path, &pairs(signed), body).await
}

pub fn event<'a>(events: &'a [Captured], name: &str) -> Vec<&'a Captured> {
    events
        .iter()
        .filter(|event| {
            event["target"] == "jaunt::audit"
                && event.get("event").map(String::as_str) == Some(name)
        })
        .collect()
}

pub fn outcomes(events: &[Captured]) -> Vec<(String, Option<String>)> {
    events
        .iter()
        .filter(|event| event["target"] == "jaunt::audit")
        .filter_map(|event| match event.get("event").map(String::as_str) {
            Some("admin.signed_request") => {
                Some((event["decision"].clone(), event.get("reason").cloned()))
            }
            Some("admin.signed_request_refused") => {
                assert!(event.get("user_id").is_none(), "{event:?}");
                Some(("unproven".to_owned(), event.get("reason").cloned()))
            }
            _ => None,
        })
        .collect()
}

pub fn refused(reason: &str) -> (String, Option<String>) {
    ("refused".to_owned(), Some(reason.to_owned()))
}

pub fn unproven(reason: &str) -> (String, Option<String>) {
    ("unproven".to_owned(), Some(reason.to_owned()))
}

pub fn accepted() -> (String, Option<String>) {
    ("accepted".to_owned(), None)
}

pub fn assert_unauthorized(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.text());
    assert_eq!(reply.json(), serde_json::json!({ "error": "unauthorized" }));
}

pub fn genuine_certificate(
    harness: &Harness,
    holder: &Holder,
    subject: &PrivateKey,
    serial: u64,
    web: bool,
) -> Certificate {
    let (_, authority) =
        FileBackend::load(&harness.ca_root, CaKind::User, &harness.identity).unwrap();
    let params = UserCertParams {
        subject_public_key: subject.public_key().clone(),
        user_id: Uuid::parse_str(&holder.user_id()).unwrap(),
        email: "alice@example.com".to_owned(),
        serial,
        validity: Duration::from_secs(600),
    };
    let now = UNIX_EPOCH + Duration::from_secs(u64::try_from(harness.clock.now_secs()).unwrap());
    let certificate = if web {
        sign_web_user_certificate(&authority, params, now)
    } else {
        sign_user_certificate(&authority, params, now)
    };
    certificate.unwrap()
}

pub struct RealAgent {
    child: Child,
    pub socket: PathBuf,
    _dir: TempDir,
}

impl RealAgent {
    pub async fn start() -> Option<RealAgent> {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let child = match Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: ssh-agent is not installed");
                return None;
            }
            Err(err) => panic!("ssh-agent cannot be started: {err}"),
        };
        let agent = RealAgent {
            child,
            socket,
            _dir: dir,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !agent.socket.exists() {
            assert!(
                Instant::now() < deadline,
                "ssh-agent did not create its socket"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Some(agent)
    }
}

impl Drop for RealAgent {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}
