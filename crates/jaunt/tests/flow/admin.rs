use std::ffi::OsString;
use std::time::{Duration, SystemTime};

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::admin::{AdminContext, AdminError, whoami};
use jaunt::admin_signature::content_digest;
use jaunt::agent::SshAgent;
use jaunt::login::KeyPlacement;
use jaunt::profile::ProfileName;
use jaunt::store::ProfileStore;
use jaunt_proto::admin_signature_base;
use ssh_key::{Certificate, PublicKey, SshSig};

use crate::agent::{RealAgent, login_with};
use crate::support::{Behavior, EMAIL, FakeServer, USER_ID, serial_section};

fn context<'a>(store: &'a ProfileStore, socket: Option<&'a OsString>) -> AdminContext<'a> {
    AdminContext {
        store,
        agent_socket: socket,
        clock: &SystemTime::now,
        agent_timeout: Duration::from_secs(10),
    }
}

fn assert_signed_by_the_profile_key(server: &FakeServer, store: &ProfileStore) {
    let requests = server.seen(|seen| seen.admin_requests.clone());
    assert_eq!(requests.len(), 1);
    let header = |name: &str| {
        requests[0]
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("{name} was not sent"))
    };
    let certificate_text = header("jaunt-certificate");
    let certificate = Certificate::from_openssh(&certificate_text).unwrap();
    let public_line = store.read_public_key_line().unwrap().unwrap();
    assert_eq!(
        certificate.public_key(),
        PublicKey::from_openssh(&public_line).unwrap().key_data()
    );
    assert_eq!(header("content-digest"), content_digest(b""));
    let input = header("signature-input");
    let params = input.strip_prefix("jaunt=").unwrap();
    assert!(params.contains(&format!("keyid=\"{}\"", certificate.serial())));
    let base = admin_signature_base(
        [
            "GET",
            &format!("{}/v1/admin/whoami", server.url()),
            &header("content-digest"),
            &certificate_text,
        ],
        params,
    );
    let signature = header("signature");
    let encoded = signature
        .strip_prefix("jaunt=:")
        .and_then(|rest| rest.strip_suffix(':'))
        .unwrap();
    let bytes = STANDARD.decode(encoded).unwrap();
    let sshsig = <SshSig as ssh_encoding::Decode>::decode(&mut bytes.as_slice()).unwrap();
    PublicKey::from(certificate.public_key().clone())
        .verify("jaunt-admin@1", base.as_bytes(), &sshsig)
        .unwrap();
}

#[test]
fn admin_whoami_signs_with_the_profile_key_file_when_no_agent_holds_the_key() {
    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let report = login_with(&server, home.path(), &SshAgent::new(None));
    assert!(matches!(report.placement, KeyPlacement::Disk { .. }));
    let store = ProfileStore::new(home.path(), &ProfileName::default_name());

    let identity = whoami(&context(&store, None)).unwrap();

    assert_eq!(identity.user_id, USER_ID);
    assert_eq!(identity.email, EMAIL);
    assert_signed_by_the_profile_key(&server, &store);
}

#[test]
fn admin_whoami_signs_through_the_agent_that_holds_the_session_key() {
    let _serial = serial_section();
    let Some(agent) = RealAgent::start() else {
        return;
    };
    let server = FakeServer::start(Behavior::default());
    let home = tempfile::tempdir().unwrap();
    let report = login_with(&server, home.path(), &agent.client());
    assert_eq!(report.placement, KeyPlacement::Agent);
    let store = ProfileStore::new(home.path(), &ProfileName::default_name());
    assert!(!store.private_key_path().exists());
    let socket = agent.socket().as_os_str().to_owned();

    let identity = whoami(&context(&store, Some(&socket))).unwrap();

    assert_eq!(identity.email, EMAIL);
    assert_signed_by_the_profile_key(&server, &store);
}

#[test]
fn refusals_from_the_server_become_admin_errors_without_echoing_its_text() {
    for status in [
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
        StatusCode::NOT_FOUND,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        let server = FakeServer::start(Behavior {
            admin_status: Some(status),
            ..Behavior::default()
        });
        let home = tempfile::tempdir().unwrap();
        login_with(&server, home.path(), &SshAgent::new(None));
        let store = ProfileStore::new(home.path(), &ProfileName::default_name());

        let outcome = whoami(&context(&store, None));

        let message = match (status, outcome) {
            (StatusCode::UNAUTHORIZED, Err(err @ AdminError::Refused))
            | (StatusCode::FORBIDDEN, Err(err @ AdminError::Forbidden))
            | (StatusCode::NOT_FOUND, Err(err @ AdminError::NotFound))
            | (StatusCode::TOO_MANY_REQUESTS, Err(err @ AdminError::TooMany)) => err.to_string(),
            (status, other) => panic!("{status}: {other:?}"),
        };
        let hint = match status {
            StatusCode::UNAUTHORIZED => {
                "the address of the server in this profile must equal the server's public address"
            }
            StatusCode::NOT_FOUND => "web console disabled",
            StatusCode::TOO_MANY_REQUESTS => "retry later",
            _ => "administrator right",
        };
        assert!(message.contains(hint), "{message}");
        assert!(!message.contains("unauthorized") && !message.contains("forbidden"));
    }
}

#[test]
fn admin_whoami_without_a_sign_in_says_so() {
    let home = tempfile::tempdir().unwrap();
    let store = ProfileStore::new(home.path(), &ProfileName::default_name());
    assert!(matches!(
        whoami(&context(&store, None)),
        Err(AdminError::NotSignedIn)
    ));
}
