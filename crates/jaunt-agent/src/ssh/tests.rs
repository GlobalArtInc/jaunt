use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, DenyReason, SessionEnd, SessionPermissions,
};
use jaunt_ssh::{
    AgentLimits, AuthorityError, InnerCa, InnerTarget, NoObserver, SessionAuthority, SshError,
    UserCaKeys,
};
use jaunt_tunnel::{H2Io, IncomingStream, SessionId, StreamHandler, StreamKind, StreamMeta};
use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::{ControlAuthority, InnerTargetError, SshService, check_inner_target};
use crate::keys::HostKey;
use crate::state::{SSH_CERTIFICATE_FILE, SSH_HOST_KEY_FILE, StateDir};
use crate::testkit::{
    AUTHORIZE_PATH, ApiStep, SESSION_END_PATH, TestPki, gate_and_api, soon, sshd_host_key_file,
    unix_now, user_ca_line,
};

type Expected = fn(&SshError) -> bool;

const PERMISSIONS: SessionPermissions = SessionPermissions {
    pty: false,
    port_forwarding: true,
    record_input: true,
    max_duration_secs: 600,
};

fn target(sshd_host_key: &Path) -> InnerTarget {
    InnerTarget {
        sshd_addr: "127.0.0.1:22".parse().unwrap(),
        sshd_host_key: sshd_host_key.to_path_buf(),
    }
}

fn service(authority: Arc<dyn SessionAuthority>) -> SshService {
    SshService::new(
        Arc::new(InnerCa::generate().unwrap()),
        target(Path::new("/nonexistent")),
        authority,
        AgentLimits::default(),
        Arc::new(NoObserver),
    )
}

fn write_host_files(dir: &Path, pki: &TestPki, key: &HostKey, valid_before: i64) -> String {
    let key_path = dir.join(SSH_HOST_KEY_FILE);
    fs::write(&key_path, key.private_openssh().unwrap().as_bytes()).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    let now = unix_now();
    let certificate = pki.host_certificate(
        key.key_data(),
        &["web-01.jaunt.test", "web-01"],
        now - 60,
        valid_before,
    );
    fs::write(dir.join(SSH_CERTIFICATE_FILE), format!("{certificate}\n")).unwrap();
    certificate
}

#[test]
fn the_inner_target_must_be_loopback_and_pin_an_ed25519_key() {
    let dir = tempfile::tempdir().unwrap();
    let good = sshd_host_key_file(dir.path());
    check_inner_target(&target(&good)).unwrap();
    check_inner_target(&InnerTarget {
        sshd_addr: "[::1]:2222".parse().unwrap(),
        sshd_host_key: good.clone(),
    })
    .unwrap();

    let remote = InnerTarget {
        sshd_addr: "192.0.2.10:22".parse().unwrap(),
        sshd_host_key: good,
    };
    assert!(matches!(
        check_inner_target(&remote),
        Err(InnerTargetError::NotLoopback(_))
    ));

    let file = |name: &str, content: &[u8]| {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    };
    let ecdsa = russh::keys::PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        },
    )
    .unwrap()
    .public_key()
    .to_openssh()
    .unwrap();
    let cases: [(PathBuf, Expected); 6] = [
        (dir.path().join("missing.pub"), |error| {
            matches!(error, SshError::ReadFile { .. })
        }),
        (file("empty.pub", b""), |error| {
            matches!(error, SshError::PinnedHostKey)
        }),
        (file("garbage.pub", b"ssh-ed25519 !!!\n"), |error| {
            matches!(error, SshError::PinnedHostKey)
        }),
        (file("binary.pub", &[0xff, 0xfe, 0x00]), |error| {
            matches!(error, SshError::PinnedHostKey)
        }),
        (file("ecdsa.pub", ecdsa.as_bytes()), |error| {
            matches!(error, SshError::PinnedHostKey)
        }),
        (file("large.pub", &vec![b'a'; 64 * 1024 + 1]), |error| {
            matches!(error, SshError::FileTooLarge { .. })
        }),
    ];
    for (path, expected) in cases {
        let error = check_inner_target(&target(&path)).unwrap_err();
        let InnerTargetError::HostKey { source, .. } = &error else {
            panic!("{}: {error}", path.display());
        };
        assert!(expected(source), "{}: {error}", path.display());
    }
}

#[tokio::test]
async fn the_control_authority_maps_answers_and_failures() {
    let (gate, api) = gate_and_api().await;
    let authority = ControlAuthority::new(api);
    gate.script(
        AUTHORIZE_PATH,
        vec![
            ApiStep::Json(
                200,
                json!({"decision": "allow", "permissions": PERMISSIONS}),
            ),
            ApiStep::Json(200, json!({"decision": "deny"})),
            ApiStep::Json(500, json!({"error": "server_error"})),
            ApiStep::Json(200, json!({"decision": "allow"})),
        ],
    );
    let request = AuthorizeRequest {
        session_id: "session-9".to_owned(),
        user_id: "4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11".to_owned(),
        serial: 3,
        key_id: "jaunt:alice@example.com:3".to_owned(),
        login: "deploy".to_owned(),
        client_addr: "203.0.113.9:5000".to_owned(),
        subject_fingerprint: Some("cd".repeat(32)),
    };
    assert_eq!(
        authority.authorize(request.clone()).await,
        Ok(AuthorizeDecision::Allow {
            permissions: PERMISSIONS
        })
    );
    assert_eq!(
        authority.authorize(request.clone()).await,
        Ok(AuthorizeDecision::Deny {
            reason: DenyReason::PolicyDenied
        })
    );
    assert_eq!(
        authority.authorize(request.clone()).await,
        Err(AuthorityError::Unavailable)
    );
    assert_eq!(
        authority.authorize(request).await,
        Err(AuthorityError::InvalidResponse)
    );

    gate.script(
        SESSION_END_PATH,
        vec![
            ApiStep::Json(200, json!({"outcome": "recorded"})),
            ApiStep::Json(200, json!({"outcome": "rejected"})),
            ApiStep::Json(503, json!({"error": "unavailable"})),
        ],
    );
    let end = SessionEnd {
        session_id: "session-9".to_owned(),
        exit_status: None,
        bytes_in: 1,
        bytes_out: 2,
        recording_incomplete: true,
    };
    assert_eq!(authority.session_end(end.clone()).await, Ok(()));
    assert_eq!(authority.session_end(end.clone()).await, Ok(()));
    assert_eq!(
        authority.session_end(end).await,
        Err(AuthorityError::Unavailable)
    );
    gate.stop().await;
}

async fn bare_h2_stream() -> (H2Io, h2::RecvStream, h2::client::SendRequest<Bytes>) {
    let (client_io, server_io) = tokio::io::duplex(1024 * 1024);
    let (halves, accepted) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, mut respond) = connection.accept().await.unwrap().unwrap();
        let send = respond
            .send_response(http::Response::new(()), false)
            .unwrap();
        drop(halves.send((request.into_body(), send)));
        while connection.accept().await.is_some() {}
    });
    let (sender, connection) = h2::client::handshake(client_io).await.unwrap();
    tokio::spawn(connection);
    let mut ready = sender.clone().ready().await.unwrap();
    let request = http::Request::post("http://node/stream").body(()).unwrap();
    let (response, _upload) = ready.send_request(request, false).unwrap();
    let (body, send) = accepted.await.unwrap();
    let response = response.await.unwrap();
    (H2Io::new(body, send), response.into_body(), sender)
}

#[tokio::test]
async fn cancelling_the_stream_token_ends_the_ssh_session_on_a_stream_that_ignores_it() {
    let (gate, api) = gate_and_api().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    write_host_files(
        dir.path(),
        &pki,
        &HostKey::generate().unwrap(),
        unix_now() + 3600,
    );
    let state = StateDir::open(dir.path(), false).unwrap();
    let service = service(Arc::new(ControlAuthority::new(api)));
    service.install_trust(UserCaKeys::from_openssh_lines([user_ca_line()]).unwrap());
    service.reload_host_identity(&state, u64::try_from(unix_now()).unwrap());

    let (io, mut downstream, _sender) = bare_h2_stream().await;
    let cancel = CancellationToken::new();
    let meta = StreamMeta::new(
        SessionId::new("cancelled").unwrap(),
        StreamKind::Ssh,
        "203.0.113.5:40000",
    )
    .unwrap();
    let served = tokio::spawn(service.handle(IncomingStream {
        meta,
        io,
        cancel: cancel.clone(),
    }));
    let first = soon("the banner", downstream.data())
        .await
        .unwrap()
        .unwrap();
    assert!(first.starts_with(b"SSH-2.0-Jaunt"));

    cancel.cancel();
    soon("the session to end on cancellation", served)
        .await
        .unwrap();
    gate.stop().await;
}

#[tokio::test]
async fn sessions_are_served_only_once_both_trust_and_host_certificate_are_loaded() {
    let (gate, api) = gate_and_api().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let key = HostKey::generate().unwrap();
    write_host_files(dir.path(), &pki, &key, unix_now() + 3600);
    let state = StateDir::open(dir.path(), false).unwrap();
    let service = service(Arc::new(ControlAuthority::new(api)));
    assert!(service.ready.get().is_none());

    let first = vec![user_ca_line()];
    service.install_trust(UserCaKeys::from_openssh_lines(&first).unwrap());
    assert!(service.ready.get().is_none());
    service.reload_host_identity(&state, u64::try_from(unix_now()).unwrap());
    let terminator = service.ready.get().cloned().unwrap();

    let second = vec![user_ca_line()];
    service.install_trust(UserCaKeys::from_openssh_lines(&second).unwrap());
    assert!(Arc::ptr_eq(&terminator, service.ready.get().unwrap()));
    assert_eq!(
        *service.trust().unwrap(),
        UserCaKeys::from_openssh_lines(&second).unwrap()
    );
    gate.stop().await;
}

#[tokio::test]
async fn a_reload_swaps_the_host_certificate_and_a_broken_one_keeps_the_previous() {
    let (gate, api) = gate_and_api().await;
    let pki = TestPki::new();
    let dir = tempfile::tempdir().unwrap();
    let key = HostKey::generate().unwrap();
    let now = u64::try_from(unix_now()).unwrap();
    let presented = |service: &SshService| {
        service.server_config().unwrap().certificates[0]
            .to_openssh()
            .unwrap()
    };
    let state = StateDir::open(dir.path(), false).unwrap();
    let service = service(Arc::new(ControlAuthority::new(api)));

    let first = write_host_files(dir.path(), &pki, &key, unix_now() + 3600);
    service.reload_host_identity(&state, now);
    assert_eq!(presented(&service), first);

    let second = write_host_files(dir.path(), &pki, &key, unix_now() + 7200);
    service.reload_host_identity(&state, now);
    assert_eq!(presented(&service), second);

    let certificate = dir.path().join(SSH_CERTIFICATE_FILE);
    fs::write(&certificate, "not a certificate\n").unwrap();
    service.reload_host_identity(&state, now);
    assert_eq!(presented(&service), second);

    let other = HostKey::generate().unwrap();
    let foreign = pki.host_certificate(
        other.key_data(),
        &["web-01"],
        unix_now() - 60,
        unix_now() + 60,
    );
    fs::write(&certificate, foreign).unwrap();
    service.reload_host_identity(&state, now);
    assert_eq!(presented(&service), second);

    let elsewhere = tempfile::tempdir().unwrap();
    let third = write_host_files(elsewhere.path(), &pki, &key, unix_now() + 9000);
    fs::remove_file(&certificate).unwrap();
    std::os::unix::fs::symlink(elsewhere.path().join(SSH_CERTIFICATE_FILE), &certificate).unwrap();
    service.reload_host_identity(&state, now);
    assert_ne!(presented(&service), third);
    assert_eq!(presented(&service), second);
    gate.stop().await;
}
