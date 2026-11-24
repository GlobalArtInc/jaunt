use std::time::{Duration, Instant};

use jaunt_proto::{AuthorizeRequest, SessionEnd};
use jaunt_ssh::{AgentLimits, EndReason};
use russh::keys::ssh_key::certificate::CertType;

use crate::sshd::{LoginMode, SshdOptions, SshdStats};
use crate::support::{
    CLIENT_ADDR, Decision, Fixture, KEY_ID, LOGIN, Options, SESSION_ID, USER_ID, certify, key, now,
    permissions,
};

fn end_without_exit() -> SessionEnd {
    SessionEnd {
        session_id: SESSION_ID.to_owned(),
        exit_status: None,
        bytes_in: 0,
        bytes_out: 0,
        recording_incomplete: false,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_session_looks_like_permission_denied_and_never_reaches_sshd() {
    let fixture = Fixture::new(Options {
        decision: Decision::Deny,
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    let outcome = client.finish().await;
    assert!(!outcome.authorized);
    assert_eq!(outcome.reason, EndReason::Denied);
    assert_eq!(fixture.authority.requests().len(), 1);
    assert!(fixture.authority.ends().is_empty());
    assert_eq!(SshdStats::count(&fixture.sshd.stats.connections), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn unverifiable_certificates_bad_logins_and_passwords_never_reach_authorize() {
    let fixture = Fixture::new(Options::default()).await;
    let user = &fixture.user_key;
    let issued = now();
    let cases = [
        (
            "wrong CA",
            LOGIN,
            certify(&key(), user, CertType::User, issued - 120, issued + 3600),
        ),
        (
            "expired",
            LOGIN,
            certify(
                &fixture.user_ca,
                user,
                CertType::User,
                issued - 7200,
                issued - 60,
            ),
        ),
        (
            "host certificate",
            LOGIN,
            certify(
                &fixture.user_ca,
                user,
                CertType::Host,
                issued - 120,
                issued + 3600,
            ),
        ),
        ("uppercase login", "Deploy", fixture.cert.clone()),
        ("path login", "../deploy", fixture.cert.clone()),
    ];
    let mut attempts = tokio::task::JoinSet::new();
    for (name, login, cert) in cases {
        let mut client = fixture.connect().await;
        attempts.spawn(async move { (name, client.authenticate(login, cert).await) });
    }
    let mut password = fixture.connect().await;
    attempts.spawn(async move {
        let accepted = password
            .handle
            .authenticate_password(LOGIN, "hunter2")
            .await
            .is_ok_and(|result| result.success());
        ("password", accepted)
    });
    while let Some(attempt) = attempts.join_next().await {
        let (name, accepted) = attempt.unwrap();
        assert!(!accepted, "{name} was accepted");
    }
    assert!(fixture.authority.requests().is_empty());
    assert_eq!(SshdStats::count(&fixture.sshd.stats.connections), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn authorize_is_asked_once_with_the_stream_and_certificate_fields() {
    let fixture = Fixture::new(Options::default()).await;
    let client = fixture.login().await;
    let outcome = client.finish().await;
    assert_eq!(
        fixture.authority.requests(),
        [AuthorizeRequest {
            session_id: SESSION_ID.to_owned(),
            user_id: USER_ID.to_owned(),
            serial: 42,
            key_id: KEY_ID.to_owned(),
            login: LOGIN.to_owned(),
            client_addr: CLIENT_ADDR.to_owned(),
        }]
    );
    assert!(outcome.authorized);
    assert_eq!(fixture.authority.ends().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_login_attempt_on_a_stream_is_refused_without_asking_again() {
    let fixture = Fixture::new(Options {
        decision: Decision::Deny,
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    client.finish().await;
    assert_eq!(fixture.authority.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_inner_login_denies_the_user_and_ends_the_session_once() {
    let fixture = Fixture::new(Options {
        sshd: SshdOptions {
            login: LoginMode::Refuse,
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    let outcome = client.finish().await;
    assert!(outcome.authorized);
    assert_eq!(outcome.reason, EndReason::InnerLoginFailed);
    assert_eq!(SshdStats::count(&fixture.sshd.stats.attempts), 1);
    assert_eq!(fixture.authority.ends(), [end_without_exit()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mismatched_sshd_host_key_aborts_before_the_certificate_is_shown() {
    let fixture = Fixture::new(Options {
        wrong_pin: true,
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    let outcome = client.finish().await;
    assert_eq!(outcome.reason, EndReason::InnerLoginFailed);
    assert_eq!(SshdStats::count(&fixture.sshd.stats.connections), 1);
    assert_eq!(SshdStats::count(&fixture.sshd.stats.attempts), 0);
    assert_eq!(fixture.authority.ends(), [end_without_exit()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_inner_certificate_is_short_lived_loopback_only_and_names_the_login() {
    let fixture = Fixture::new(Options::default()).await;
    let before = now();
    let client = fixture.login().await;
    let after = now();
    client.finish().await;
    let certificates = fixture.sshd.stats.certificates.lock().unwrap().clone();
    let [(user, cert)] = certificates.as_slice() else {
        panic!("expected one inner login, got {}", certificates.len());
    };
    assert_eq!(user, LOGIN);
    assert_eq!(cert.cert_type(), CertType::User);
    assert_eq!(cert.serial(), 0);
    assert_eq!(cert.valid_principals(), [LOGIN]);
    assert_eq!(
        cert.key_id(),
        format!("jaunt:{SESSION_ID}:alice@example.com")
    );
    assert_eq!(cert.valid_before() - cert.valid_after(), 65);
    assert!((before - 5..=after - 5).contains(&cert.valid_after()));
    let critical: Vec<(&str, &str)> = cert
        .critical_options()
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(critical, [("source-address", "127.0.0.1/32,::1/128")]);
    let extensions: Vec<&str> = cert.extensions().keys().map(String::as_str).collect();
    assert_eq!(extensions, ["permit-pty"]);
    assert_eq!(cert.signature_key(), fixture.inner_ca.key_data());
    assert_ne!(cert.public_key(), fixture.user_key.public_key().key_data());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_silent_authority_times_out_into_a_plain_denial() {
    let fixture = Fixture::new(Options {
        decision: Decision::Hang,
        limits: AgentLimits {
            authorize_timeout: Duration::from_millis(300),
            ..AgentLimits::default()
        },
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    let started = Instant::now();
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    assert!(started.elapsed() < Duration::from_secs(5));
    let outcome = client.finish().await;
    assert!(!outcome.authorized);
    assert!(fixture.authority.ends().is_empty());
    assert_eq!(SshdStats::count(&fixture.sshd.stats.connections), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_inner_login_times_out_and_ends_the_session_once() {
    let fixture = Fixture::new(Options {
        decision: Decision::Allow(permissions()),
        limits: AgentLimits {
            inner_login_timeout: Duration::from_millis(300),
            ..AgentLimits::default()
        },
        sshd: SshdOptions {
            login: LoginMode::Stall,
            ..SshdOptions::default()
        },
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    let started = Instant::now();
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    assert!(started.elapsed() < Duration::from_secs(5));
    let outcome = client.finish().await;
    assert_eq!(outcome.reason, EndReason::InnerLoginFailed);
    assert_eq!(fixture.authority.ends(), [end_without_exit()]);
}
