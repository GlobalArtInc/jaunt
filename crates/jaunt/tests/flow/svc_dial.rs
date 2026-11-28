use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt::ensure::{RenewOptions, login_hint};
use jaunt::gate_tls::{GateError, GateProtocol, GateRoute, ServiceGate, connect_with};
use jaunt::lock::ProfileLock;
use jaunt::profile::ProfileName;
use jaunt::service_dial::{
    ClientIdentity, ConnectError, DialError, DialKind, ServiceDialer, ServiceName,
    ServiceSetupError, dial, service_config,
};
use jaunt::service_identity::{IdentityError, ProfileIdentity};
use jaunt::store::ProfileStore;
use jaunt_proto::{GATE_ALPN_SSH, GATE_ALPN_SVC};
use rustls::HandshakeKind;
use rustls::client::Resumption;
use ssh_key::private::Ed25519Keypair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::gate::{FakeGate, GATE_NAME, INTERCEPTION, Script, TestCa, gate_config};
use crate::support::{now_secs, user_certificate_under};
use crate::svc_fake::{
    App, FakeSvc, Pki, Setup, TRAILER, issuing_api, json_alpn, pem_certificate, requiring_client,
    sign_in, svc_services_json, within_deadline,
};

const REFUSED_TCP: &str = "the gate refused the connection (no access, service unavailable or revoked): run `jaunt ls --kind tcp` to see what you can reach";
const ED25519_PKCS8_PREFIX_LEN: usize = 16;
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn gate_of(fake: &FakeSvc, pki: &Pki) -> ServiceGate {
    ServiceGate::new(
        GateRoute::new(GATE_NAME.to_owned(), fake.port, vec![pki.internal.der()]),
        GATE_NAME.to_owned(),
    )
}

fn identity_under(users: &TestCa) -> (ClientIdentity, Vec<u8>) {
    let (certificate, key) = users.client_leaf();
    (
        ClientIdentity::new(certificate.clone(), key).unwrap(),
        certificate,
    )
}

fn grafana() -> ServiceName {
    ServiceName::parse("grafana").unwrap()
}

fn tcp_inner() -> String {
    format!("grafana.tcp.{GATE_NAME}")
}

#[test]
fn the_full_path_carries_bytes_both_ways_with_half_close_and_shows_the_certificate_at_both_layers()
{
    let pki = Pki::new();
    let fake = FakeSvc::start(Setup::standard(&pki, &tcp_inner(), App::Echo));
    let (identity, certificate) = identity_under(&pki.users);

    let received = within_deadline(async {
        let mut stream = dial(&gate_of(&fake, &pki), &identity, DialKind::Tcp, &grafana())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        (echoed, rest)
    });

    assert_eq!(&received.0, b"ping");
    assert_eq!(received.1, TRAILER);
    let session = fake.log(|log| log.sessions[0].clone());
    assert_eq!(
        session.outer_alpn.as_deref(),
        Some(GATE_ALPN_SVC.as_bytes())
    );
    assert_eq!(session.outer_client.as_ref(), Some(&certificate));
    assert_eq!(session.inner_sni.as_deref(), Some(tcp_inner().as_str()));
    assert_eq!(session.inner_client.as_ref(), Some(&certificate));
    assert!(session.client_ended);
}

#[test]
fn a_certificate_outside_the_pinned_root_or_for_another_name_is_refused_at_either_layer_once() {
    let pki = Pki::new();
    let other = TestCa::new("intercepting root");
    let (identity, _) = identity_under(&pki.users);
    type Change = fn(&mut Setup, &Pki, &TestCa);
    let cases: Vec<(&str, Change, String)> = vec![
        (
            "outer leaf under another root",
            |setup, pki, other| {
                setup.outer = requiring_client(
                    other.server_leaf(GATE_NAME),
                    &pki.users,
                    false,
                    &[GATE_ALPN_SVC],
                );
            },
            INTERCEPTION.to_owned(),
        ),
        (
            "inner leaf under another root",
            |setup, pki, other| {
                setup.inner = Some(requiring_client(
                    other.server_leaf(&tcp_inner()),
                    &pki.users,
                    false,
                    &[],
                ));
            },
            INTERCEPTION.to_owned(),
        ),
        (
            "inner leaf for another service",
            |setup, pki, _| {
                setup.inner = Some(requiring_client(
                    pki.internal.server_leaf(&format!("other.tcp.{GATE_NAME}")),
                    &pki.users,
                    false,
                    &[],
                ));
            },
            INTERCEPTION.to_owned(),
        ),
        (
            "inner leaf for the database of the same name",
            |setup, pki, _| {
                setup.inner = Some(requiring_client(
                    pki.internal.server_leaf(&format!("grafana.db.{GATE_NAME}")),
                    &pki.users,
                    false,
                    &[],
                ));
            },
            INTERCEPTION.to_owned(),
        ),
        (
            "expired inner leaf",
            |setup, pki, _| {
                setup.inner = Some(requiring_client(
                    pki.internal.leaf(&tcp_inner(), true),
                    &pki.users,
                    false,
                    &[],
                ));
            },
            GateError::CertificateTime.to_string(),
        ),
    ];
    for (case, change, expected) in cases {
        let mut setup = Setup::standard(&pki, &tcp_inner(), App::Echo);
        change(&mut setup, &pki, &other);
        let fake = FakeSvc::start(setup);

        let outcome = within_deadline(dial(
            &gate_of(&fake, &pki),
            &identity,
            DialKind::Tcp,
            &grafana(),
        ));

        let err = outcome.err().unwrap_or_else(|| panic!("{case}: connected"));
        assert!(matches!(err, DialError::Gate(_)), "{case}: {err:?}");
        assert_eq!(err.to_string(), expected, "{case}");
        assert_eq!(fake.log(|log| log.accepted), 1, "{case}");
    }
}

#[test]
fn tls_1_2_at_either_layer_is_refused() {
    let pki = Pki::new();
    let (identity, _) = identity_under(&pki.users);
    let outer_old = |pki: &Pki| {
        requiring_client(
            pki.internal.server_leaf(GATE_NAME),
            &pki.users,
            true,
            &[GATE_ALPN_SVC],
        )
    };
    let inner_old = |pki: &Pki| {
        requiring_client(
            pki.internal.server_leaf(&tcp_inner()),
            &pki.users,
            true,
            &[],
        )
    };
    type Expected = fn(&DialError) -> bool;
    let cases: Vec<(&str, Setup, Expected)> = vec![
        (
            "outer",
            Setup {
                outer: outer_old(&pki),
                ..Setup::standard(&pki, &tcp_inner(), App::Echo)
            },
            |err| matches!(err, DialError::Gate(GateError::Protocol)),
        ),
        (
            "inner",
            Setup {
                inner: Some(inner_old(&pki)),
                ..Setup::standard(&pki, &tcp_inner(), App::Echo)
            },
            |err| err.to_string() == REFUSED_TCP,
        ),
    ];
    for (case, setup, expected) in cases {
        let fake = FakeSvc::start(setup);

        let outcome = within_deadline(dial(
            &gate_of(&fake, &pki),
            &identity,
            DialKind::Tcp,
            &grafana(),
        ));

        let err = outcome.err().unwrap_or_else(|| panic!("{case}: connected"));
        assert!(expected(&err), "{case}: {err:?}");
        assert_eq!(fake.log(|log| log.accepted), 1, "{case}");
    }
}

#[test]
fn a_gate_that_refuses_is_reported_in_one_line_that_names_the_listing() {
    let pki = Pki::new();
    let strangers = TestCa::new("another user-x509 root");
    let (identity, _) = identity_under(&pki.users);
    let only_ssh = |pki: &Pki| {
        requiring_client(
            pki.internal.server_leaf(GATE_NAME),
            &pki.users,
            false,
            &[GATE_ALPN_SSH],
        )
    };
    let cases: Vec<(&str, Setup, String)> = vec![
        (
            "the gate closes before the inner handshake",
            Setup {
                inner: None,
                ..Setup::standard(&pki, &tcp_inner(), App::Echo)
            },
            REFUSED_TCP.to_owned(),
        ),
        (
            "the gate does not take the client certificate",
            Setup {
                outer: requiring_client(
                    pki.internal.server_leaf(GATE_NAME),
                    &strangers,
                    false,
                    &[GATE_ALPN_SVC],
                ),
                ..Setup::standard(&pki, &tcp_inner(), App::Echo)
            },
            REFUSED_TCP.to_owned(),
        ),
        (
            "the gate speaks only SSH",
            Setup {
                outer: only_ssh(&pki),
                ..Setup::standard(&pki, &tcp_inner(), App::Echo)
            },
            GateError::SvcAlpn.to_string(),
        ),
    ];
    for (case, setup, expected) in cases {
        let fake = FakeSvc::start(setup);

        let outcome = within_deadline(dial(
            &gate_of(&fake, &pki),
            &identity,
            DialKind::Tcp,
            &grafana(),
        ));

        let err = outcome.err().unwrap_or_else(|| panic!("{case}: connected"));
        assert_eq!(err.to_string(), expected, "{case}");
        assert_eq!(err.to_string().lines().count(), 1, "{case}");
    }
}

fn profile_identity(home: &std::path::Path, interactive: bool) -> ProfileIdentity {
    ProfileIdentity {
        renew: RenewOptions {
            home: home.to_owned(),
            custom_home: true,
            profile: ProfileName::default_name(),
            deadline: Duration::from_secs(20),
            ssh: None,
        },
        interactive,
        ssh_auth_sock: None,
        clock: SystemTime::now,
    }
}

fn spki_of_stored_key(store: &ProfileStore) -> Vec<u8> {
    let pem = fs::read_to_string(store.x509_dir().join("key.pem")).unwrap();
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let pkcs8 = STANDARD.decode(body).unwrap();
    let seed: [u8; 32] = pkcs8[ED25519_PKCS8_PREFIX_LEN..].try_into().unwrap();
    let public = Ed25519Keypair::from_seed(&seed).public;
    [ED25519_SPKI_PREFIX.as_slice(), public.0.as_slice()].concat()
}

#[test]
fn each_connection_reads_the_profile_again_renews_an_expired_certificate_and_leaves_the_lock_free()
{
    let pki = Pki::new();
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let profile = ProfileName::default_name();
    let store = ProfileStore::new(&home, &profile);
    let mut setup = Setup::standard(&pki, &tcp_inner(), App::Echo);
    setup.lock_probe = Some((home.clone(), store.lock_path()));
    let fake = FakeSvc::start(setup);
    let ssh_end = i64::try_from(now_secs()).unwrap() + 3600;
    let api = issuing_api(&pki, ssh_end);
    sign_in(
        &home,
        &api,
        ssh_end,
        Some(&svc_services_json(fake.port, &pki)),
    );
    let now = i64::try_from(now_secs()).unwrap();
    let dialer = ServiceDialer::new(Arc::new(profile_identity(&home, false)));
    let connect = || {
        within_deadline(async {
            let mut stream = dialer.connect(DialKind::Tcp, &grafana()).await.unwrap();
            stream.write_all(b"x").await.unwrap();
            stream.flush().await.unwrap();
            let mut echoed = [0_u8; 1];
            stream.read_exact(&mut echoed).await.unwrap();
            stream
        })
    };

    let first = connect();
    let locked_while_open = ProfileLock::acquire(
        &home,
        &store.lock_path(),
        Instant::now() + Duration::from_secs(5),
        &mut || {},
    );
    drop(first);
    assert!(locked_while_open.is_ok(), "{locked_while_open:?}");
    drop(locked_while_open);
    assert_eq!(api.seen(|seen| seen.x509_requests.len()), 1);
    let expired = user_certificate_under(
        &STANDARD.encode(spki_of_stored_key(&store)),
        now - 10,
        &rcgen::Issuer::from_ca_cert_der(
            &pki.users.der().into(),
            rcgen::KeyPair::try_from(pki.users.key_der().as_slice()).unwrap(),
        )
        .unwrap(),
    );
    let expired_der = STANDARD.decode(expired.certificate_der).unwrap();
    fs::write(
        store.x509_dir().join("cert.pem"),
        pem_certificate(&expired_der),
    )
    .unwrap();

    drop(connect());
    drop(connect());

    assert_eq!(api.seen(|seen| seen.x509_requests.len()), 2);
    let sessions = fake.log(|log| log.sessions.clone());
    assert_eq!(sessions.len(), 3);
    for session in &sessions {
        assert_eq!(session.lock_free, Some(true));
        assert_eq!(session.inner_client, session.outer_client);
    }
    assert_ne!(sessions[1].outer_client.as_ref(), Some(&expired_der));
    assert_eq!(sessions[1].outer_client, sessions[2].outer_client);
    let mut only_ssh = svc_services_json(fake.port, &pki);
    json_alpn(&mut only_ssh, &[GATE_ALPN_SSH]);
    fs::write(store.dir().join("services.json"), only_ssh.to_string()).unwrap();
    let outcome = within_deadline(dialer.connect(DialKind::Tcp, &grafana()));
    assert!(
        matches!(
            outcome,
            Err(ConnectError::Identity(IdentityError::Setup(
                ServiceSetupError::NoSvc { .. }
            )))
        ),
        "{:?}",
        outcome.err()
    );
    assert_eq!(fake.log(|log| log.accepted), 3);
    fs::remove_file(store.dir().join("services.json")).unwrap();
    let prepared = profile_identity(&home, false).load();
    assert!(
        matches!(
            prepared,
            Err(IdentityError::Setup(ServiceSetupError::NotOffered { .. }))
        ),
        "{:?}",
        prepared.err()
    );
}

#[test]
fn the_profile_preparation_waits_at_most_its_deadline_and_says_the_profile_is_busy() {
    let pki = Pki::new();
    let fake = FakeSvc::start(Setup::standard(&pki, &tcp_inner(), App::Echo));
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let store = ProfileStore::new(&home, &ProfileName::default_name());
    let ssh_end = i64::try_from(now_secs()).unwrap() + 3600;
    let api = issuing_api(&pki, ssh_end);
    sign_in(
        &home,
        &api,
        ssh_end,
        Some(&svc_services_json(fake.port, &pki)),
    );
    let held = ProfileLock::acquire(
        &home,
        &store.lock_path(),
        Instant::now() + Duration::from_secs(5),
        &mut || {},
    )
    .unwrap();
    let dialer = ServiceDialer::new(Arc::new(profile_identity(&home, false)))
        .with_prepare_deadline(Duration::from_millis(300));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let outcome = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(20),
            dialer.connect(DialKind::Tcp, &grafana()),
        )
        .await
        .expect("the busy profile was not reported in time")
    });

    drop(held);
    drop(runtime);
    let err = outcome.err().unwrap();
    assert!(matches!(err, ConnectError::Busy), "{err:?}");
    assert_eq!(
        err.to_string(),
        "the profile is busy (a sign-in may be in progress); try again"
    );
    assert_eq!(fake.log(|log| log.accepted), 0);
}

#[test]
fn a_silent_service_meets_the_inner_handshake_deadline() {
    let pki = Pki::new();
    let fake = FakeSvc::start(Setup {
        silent: true,
        ..Setup::standard(&pki, &tcp_inner(), App::Echo)
    });
    let (identity, _) = identity_under(&pki.users);
    let mut gate = gate_of(&fake, &pki);
    gate.inner_handshake_timeout = Duration::from_millis(200);

    let outcome = within_deadline(dial(&gate, &identity, DialKind::Tcp, &grafana()));

    let err = outcome.err().unwrap();
    assert!(matches!(err, DialError::InnerTimeout), "{err:?}");
    assert_eq!(
        err.to_string(),
        "the TLS handshake with the service timed out"
    );
}

#[test]
fn a_second_connection_never_resumes_the_first_session() {
    let pki = Pki::new();
    let (identity, _) = identity_under(&pki.users);
    let roots = vec![pki.internal.der()];
    let pinned = service_config(&roots, &identity, Some(GATE_ALPN_SVC)).unwrap();
    let mut resuming = (*pinned).clone();
    resuming.resumption = Resumption::default();
    let cases = [
        (pinned, [HandshakeKind::Full, HandshakeKind::Full]),
        (
            Arc::new(resuming),
            [HandshakeKind::Full, HandshakeKind::Resumed],
        ),
    ];
    for (config, expected) in cases {
        let gate = FakeGate::start(
            gate_config(&pki.internal, false, &[GATE_ALPN_SVC]),
            Script::EndFirst,
        );
        let route = GateRoute::new(GATE_NAME.to_owned(), gate.port, roots.clone());

        let kinds = within_deadline(async {
            let mut kinds = Vec::new();
            for _ in 0..2 {
                let mut stream = connect_with(&route, Arc::clone(&config), GateProtocol::Svc)
                    .await
                    .unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                kinds.push(stream.get_ref().1.handshake_kind());
            }
            kinds
        });

        assert_eq!(kinds, expected.map(Some));
    }
}

#[test]
fn a_stale_sign_in_without_a_terminal_fails_with_the_hint_and_dials_nothing() {
    let pki = Pki::new();
    let fake = FakeSvc::start(Setup::standard(&pki, &tcp_inner(), App::Echo));
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("state");
    let profile = ProfileName::default_name();
    let almost_over = i64::try_from(now_secs()).unwrap() + 30;
    let api = issuing_api(&pki, almost_over);
    sign_in(
        &home,
        &api,
        almost_over,
        Some(&svc_services_json(fake.port, &pki)),
    );
    let dialer = ServiceDialer::new(Arc::new(profile_identity(&home, false)));

    let outcome = within_deadline(dialer.connect(DialKind::Tcp, &grafana()));

    let err = outcome.err().unwrap();
    assert!(
        matches!(
            err,
            ConnectError::Identity(IdentityError::SignInNeeded { .. })
        ),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!(
            "sign-in needed for profile `default`: run `{}`",
            login_hint(&home, true, &profile)
        )
    );
    assert_eq!(fake.log(|log| log.accepted), 0);
    assert_eq!(api.seen(|seen| seen.x509_requests.len()), 0);
}
