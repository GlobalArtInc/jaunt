use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_control::{AuthenticatedNode, KillOrder, SessionKiller};
use jaunt_proto::BoxFuture;
use jaunt_store::{NewApiToken, NewCertificate, NewUser};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use serde_json::Value;
use x509_parser::parse_x509_certificate;

use crate::support::{Harness, Reply, send, sha256_hex};

pub const DOMAIN: &str = "svc.example.com";
pub const HOUR: i64 = 3600;
pub const DAY: i64 = 24 * HOUR;
pub const P256_SPKI: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEanZ0rT4BJD289J5+WMF4qUSAs3z31JnWJKgtAvud9DVSr1Q/3EwV8OxuoDXqK92h3Ybls3lBBpyAAVKBHxnQFw==";

pub struct Session {
    pub user_id: String,
    pub email: String,
    pub parent: i64,
    pub token: String,
}

pub async fn session(
    harness: &Harness,
    name: &str,
    window: (i64, i64),
    token_ends: i64,
) -> Session {
    let now = harness.clock.now_secs();
    let email = format!("{name}@example.com");
    let user = harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: name.to_owned(),
                email: email.clone(),
                username: name.to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            now,
        )
        .await
        .unwrap();
    let parent = harness
        .store
        .certificates()
        .allocate_serial()
        .await
        .unwrap();
    harness
        .store
        .certificates()
        .record(&NewCertificate {
            serial: parent,
            user_id: user.id.clone(),
            kind: "user".to_owned(),
            key_id: format!("jaunt:{email}:{parent}"),
            valid_after: window.0,
            valid_before: window.1,
            issued_at: now,
            ca_fingerprint: None,
            host_trust_id: Some("host-trust".to_owned()),
            subject_fingerprint: None,
        })
        .await
        .unwrap();
    let token = format!("jt_{:A>43}", parent);
    harness
        .store
        .api_tokens()
        .create(&NewApiToken {
            token_hash: sha256_hex(&token),
            user_id: user.id.clone(),
            cert_serial: parent,
            created_at: now,
            expires_at: token_ends,
        })
        .await
        .unwrap();
    Session {
        user_id: user.id,
        email,
        parent,
        token,
    }
}

pub async fn eight_hour_session(harness: &Harness, name: &str) -> Session {
    let now = harness.clock.now_secs();
    session(harness, name, (now - 120, now + 8 * HOUR), now + 8 * HOUR).await
}

pub fn spki() -> (String, Vec<u8>) {
    let agent = crate::support::new_agent();
    (agent.tls_public_key, agent.tls_der)
}

pub async fn post_json(router: &Router, path: &str, bearer: Option<&str>, body: &Value) -> Reply {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    send(router.clone(), request).await
}

pub async fn get(router: &Router, path: &str, bearer: Option<&str>, node: Option<&str>) -> Reply {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let mut request = builder.body(Body::empty()).unwrap();
    if let Some(node_id) = node {
        request
            .extensions_mut()
            .insert(AuthenticatedNode(node_id.to_owned()));
    }
    send(router.clone(), request).await
}

pub fn der_of(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

pub struct Parsed {
    pub common_names: Vec<String>,
    pub sans: Vec<String>,
    pub client_auth: bool,
    pub server_auth: bool,
    pub serial: u128,
    pub not_before: i64,
    pub not_after: i64,
}

pub fn parsed(der: &[u8]) -> Parsed {
    let (rest, certificate) = parse_x509_certificate(der).unwrap();
    assert!(rest.is_empty());
    let usage = certificate.extended_key_usage().unwrap().unwrap().value;
    Parsed {
        common_names: certificate
            .subject()
            .iter_common_name()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect(),
        sans: certificate
            .subject_alternative_name()
            .unwrap()
            .map(|san| {
                san.value
                    .general_names
                    .iter()
                    .map(|name| format!("{name:?}"))
                    .collect()
            })
            .unwrap_or_default(),
        client_auth: usage.client_auth,
        server_auth: usage.server_auth,
        serial: certificate
            .raw_serial()
            .iter()
            .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)),
        not_before: certificate.validity().not_before.timestamp(),
        not_after: certificate.validity().not_after.timestamp(),
    }
}

fn store_of(roots: &[Vec<u8>]) -> Arc<RootCertStore> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(CertificateDer::from(root.clone())).unwrap();
    }
    Arc::new(store)
}

fn at(secs: i64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(secs).unwrap()))
}

pub fn client_verifies(roots: &[Vec<u8>], cert: &[u8], at_secs: i64) -> bool {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(store_of(roots), Arc::new(default_provider()))
            .build()
            .unwrap();
    verifier
        .verify_client_cert(&CertificateDer::from(cert.to_vec()), &[], at(at_secs))
        .is_ok()
}

pub fn server_verifies(roots: &[Vec<u8>], cert: &[u8], name: &str, at_secs: i64) -> bool {
    let verifier =
        WebPkiServerVerifier::builder_with_provider(store_of(roots), Arc::new(default_provider()))
            .build()
            .unwrap();
    let Ok(server_name) = ServerName::try_from(name.to_owned()) else {
        return false;
    };
    verifier
        .verify_server_cert(
            &CertificateDer::from(cert.to_vec()),
            &[],
            &server_name,
            &[],
            at(at_secs),
        )
        .is_ok()
}

fn openssl() -> Option<&'static str> {
    let version = match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => output.stdout,
        Ok(_) | Err(_) => {
            eprintln!("skipped: no openssl binary on PATH");
            return None;
        }
    };
    if String::from_utf8_lossy(&version).starts_with("LibreSSL") {
        eprintln!("skipped: the openssl on PATH is LibreSSL, which cannot verify Ed25519 chains");
        return None;
    }
    Some("openssl")
}

fn pem(dir: &Path, name: &str, ders: &[Vec<u8>]) -> String {
    let mut text = String::new();
    for der in ders {
        let encoded = STANDARD.encode(der);
        text.push_str("-----BEGIN CERTIFICATE-----\n");
        for line in encoded.as_bytes().chunks(64) {
            text.push_str(std::str::from_utf8(line).unwrap());
            text.push('\n');
        }
        text.push_str("-----END CERTIFICATE-----\n");
    }
    let path = dir.join(format!("{name}.pem"));
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

pub fn openssl_verifies(
    roots: &[Vec<u8>],
    cert: &[u8],
    purpose: &str,
    at_secs: i64,
    host: Option<&str>,
) -> Option<bool> {
    let openssl = openssl()?;
    let dir = tempfile::tempdir().unwrap();
    let roots = pem(dir.path(), "roots", roots);
    let leaf = pem(dir.path(), "leaf", &[cert.to_vec()]);
    let mut command = Command::new(openssl);
    command.args([
        "verify",
        "-x509_strict",
        "-purpose",
        purpose,
        "-attime",
        &at_secs.to_string(),
        "-CAfile",
        &roots,
    ]);
    if let Some(host) = host {
        command.args(["-verify_hostname", host]);
    }
    let output = command.arg(&leaf).output().unwrap();
    Some(output.status.success())
}

#[derive(Default)]
pub struct RecordingKiller(Mutex<Vec<KillOrder>>);

impl RecordingKiller {
    pub fn orders(&self) -> Vec<KillOrder> {
        self.0.lock().unwrap().clone()
    }
}

impl SessionKiller for RecordingKiller {
    fn kill<'a>(&'a self, order: &'a KillOrder) -> BoxFuture<'a, ()> {
        self.0.lock().unwrap().push(order.clone());
        Box::pin(async {})
    }
}
