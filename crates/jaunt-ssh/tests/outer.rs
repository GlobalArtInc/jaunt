#[path = "outer/support.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use jaunt_ssh::{
    AuthDenial, CertRejection, ForwardRefusal, OuterEndReason, OuterEvent, OuterLimits,
    RouteRefusal, StreamEnd,
};
use russh::client::{self, KeyboardInteractiveAuthResponse};
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::certificate::CertType;
use russh::{ChannelMsg, ChannelOpenFailure, Disconnect};
use tokio::io::AsyncWriteExt;
use tokio::task::JoinSet;
use tokio::time::Instant;

use support::{
    Gate, Mode, STEP, SUFFIX, TUNNEL_BUFFER, USER_ID, drain, finished, key, next_data, node,
    pattern, send, trust, unix_now, until,
};

const LIMIT_TEXT: &str = "jaunt: too many open sessions";
const DENIED_TEXT: &str = "jaunt: access denied or node unavailable";
const GRACE: Duration = Duration::from_secs(2);
const WINDOW: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
enum Attempt {
    Valid,
    WrongCa,
    Expired,
    NotYetValid,
    ExpiredByTheSystemClock,
    HostCertificate,
    PlainKey,
    Password,
    KeyboardInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Accepted,
    Denied(AuthDenial),
    RefusedBeforeTheHandler,
}

async fn attempt(attempt: Attempt) -> (bool, OuterEndReason, Gate) {
    let shift = match attempt {
        Attempt::Expired => 2 * 3600,
        Attempt::NotYetValid => -3600,
        _ => 0,
    };
    let gate = Gate::with_clock_shift(OuterLimits::default(), Mode::Echo, shift);
    let mut client = gate.connect().await;
    let user_ca = gate.user_ca.clone();
    let accepted = match attempt {
        Attempt::Valid | Attempt::Expired | Attempt::NotYetValid => {
            client.authenticate_with(&user_ca, CertType::User).await
        }
        Attempt::ExpiredByTheSystemClock => {
            let subject = key();
            let now = unix_now();
            let cert =
                support::certificate(&user_ca, &subject, CertType::User, now - 7200, now - 60);
            client
                .handle
                .authenticate_openssh_cert("jaunt", Arc::new(subject), cert)
                .await
                .unwrap()
                .success()
        }
        Attempt::WrongCa => client.authenticate_with(&key(), CertType::User).await,
        Attempt::HostCertificate => client.authenticate_with(&user_ca, CertType::Host).await,
        Attempt::PlainKey => client
            .handle
            .authenticate_publickey("jaunt", PrivateKeyWithHashAlg::new(Arc::new(key()), None))
            .await
            .unwrap()
            .success(),
        Attempt::Password => client
            .handle
            .authenticate_password("jaunt", "hunter2")
            .await
            .unwrap()
            .success(),
        Attempt::KeyboardInteractive => matches!(
            client
                .handle
                .authenticate_keyboard_interactive_start("jaunt", None)
                .await
                .unwrap(),
            KeyboardInteractiveAuthResponse::Success
        ),
    };
    assert_eq!(gate.idle_permits(), accepted, "{attempt:?}");
    let end = client.ended().await;
    assert_eq!(end.identity.is_some(), accepted, "{attempt:?}");
    (accepted, end.reason, gate)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_valid_user_certificate_authenticates() {
    let certificate = |rejection| Outcome::Denied(AuthDenial::Certificate(rejection));
    let cases = [
        (Attempt::Valid, Outcome::Accepted),
        (Attempt::WrongCa, certificate(CertRejection::UntrustedCa)),
        (Attempt::Expired, certificate(CertRejection::Expired)),
        (
            Attempt::NotYetValid,
            certificate(CertRejection::NotYetValid),
        ),
        (
            Attempt::ExpiredByTheSystemClock,
            Outcome::RefusedBeforeTheHandler,
        ),
        (
            Attempt::HostCertificate,
            certificate(CertRejection::NotUserCertificate),
        ),
        (Attempt::PlainKey, Outcome::Denied(AuthDenial::PlainKey)),
        (Attempt::Password, Outcome::Denied(AuthDenial::Password)),
        (
            Attempt::KeyboardInteractive,
            Outcome::Denied(AuthDenial::KeyboardInteractive),
        ),
    ];
    let mut runs = JoinSet::new();
    for (case, outcome) in cases {
        runs.spawn(async move { (case, outcome, attempt(case).await) });
    }
    while let Some(run) = runs.join_next().await {
        let (case, outcome, (accepted, reason, gate)) = run.unwrap();
        assert_eq!(accepted, outcome == Outcome::Accepted, "{case:?}");
        let (denials, expected_reason) = match outcome {
            Outcome::Accepted => (Vec::new(), OuterEndReason::ClientGone),
            Outcome::Denied(denial) => (vec![denial], OuterEndReason::AuthFailed),
            Outcome::RefusedBeforeTheHandler => (Vec::new(), OuterEndReason::ClientGone),
        };
        assert_eq!(gate.denials(), denials, "{case:?}");
        assert_eq!(reason, expected_reason, "{case:?}");
        let welcomed = gate.events().contains(&OuterEvent::AuthAccepted {
            user_id: USER_ID.to_owned(),
            serial: 42,
            login: "jaunt".to_owned(),
        });
        assert_eq!(welcomed, accepted, "{case:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_ca_set_applies_to_the_next_attempt_on_the_same_connection() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let mut client = gate.connect().await;
    let next_ca = key();
    assert!(!client.authenticate_with(&next_ca, CertType::User).await);
    gate.cas.replace(trust(&next_ca));
    assert!(client.authenticate_with(&next_ca, CertType::User).await);
    assert_eq!(
        gate.denials(),
        [AuthDenial::Certificate(CertRejection::UntrustedCa)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_none_the_configured_failures_end_authentication_even_for_a_valid_certificate() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let mut client = gate.connect().await;
    let none = client.handle.authenticate_none("jaunt").await.unwrap();
    assert!(!none.success());
    let stranger = key();
    for attempt in 0..3 {
        let accepted = client.authenticate_with(&stranger, CertType::User).await;
        assert!(!accepted, "attempt {attempt}");
    }
    let user_ca = gate.user_ca.clone();
    let subject = key();
    let now = unix_now();
    let cert = support::certificate(&user_ca, &subject, CertType::User, now - 60, now + 600);
    let late = client
        .handle
        .authenticate_openssh_cert("jaunt", Arc::new(subject), cert)
        .await;
    assert!(!late.is_ok_and(|result| result.success()));
    assert_eq!(
        client.disconnect_notice().await,
        (
            "NoMoreAuthMethodsAvailable".to_owned(),
            "jaunt: too many authentication attempts".to_owned()
        )
    );
    let end = finished(client.serve).await;
    assert_eq!(end.reason, OuterEndReason::AuthAttempts);
    assert_eq!(gate.denials().len(), 3);
    assert!(gate.idle_permits());
}

#[tokio::test(start_paused = true)]
async fn endless_key_offers_end_the_connection() {
    let limits = OuterLimits {
        auth_deadline: Duration::from_secs(600),
        max_auth_attempts: 100,
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Echo);
    let mut client = gate.connect().await;
    for _ in 0..40 {
        let offered = client
            .handle
            .authenticate_publickey("jaunt", PrivateKeyWithHashAlg::new(Arc::new(key()), None))
            .await;
        match offered {
            Ok(result) => assert!(!result.success()),
            Err(_) => break,
        }
    }
    let end = finished(client.serve).await;
    assert_eq!(end.reason, OuterEndReason::AuthAttempts);
    assert_eq!(gate.denials().len(), 32);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_does_not_authenticate_in_time_is_dropped() {
    let deadline = Duration::from_secs(1);
    let limits = OuterLimits {
        auth_deadline: deadline,
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Echo);

    let started = Instant::now();
    let (silent, serve, _shutdown) = gate.serve();
    assert_eq!(finished(serve).await.reason, OuterEndReason::AuthTimeout);
    assert_eq!(started.elapsed(), deadline);
    drop(silent);

    let started = Instant::now();
    let (mut stalled, serve, _shutdown) = gate.serve();
    stalled.write_all(b"SSH-2.0-stalled\r\n").await.unwrap();
    assert_eq!(finished(serve).await.reason, OuterEndReason::AuthTimeout);
    assert_eq!(started.elapsed(), deadline + GRACE);
    drop(stalled);

    let idle = gate.connect().await;
    assert_eq!(
        idle.disconnect_notice().await,
        (
            "ByApplication".to_owned(),
            "jaunt: authentication timed out".to_owned()
        )
    );
    assert_eq!(
        finished(idle.serve).await.reason,
        OuterEndReason::AuthTimeout
    );
    assert!(gate.idle_permits());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_channels_and_session_requests_are_refused() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let client = gate.login().await;
    assert!(client.handle.channel_open_session().await.is_err());
    let (code, text) = client.failure(0).await;
    assert_eq!(code, ChannelOpenFailure::AdministrativelyProhibited);
    assert!(text.starts_with("jaunt: this is the Jaunt SSH gateway and it has no shell."));
    assert!(
        text.contains(&format!("ssh <login>@<node>.{SUFFIX}")),
        "{text}"
    );
    assert!(text.contains("ProxyJump, ssh -J"), "{text}");
    let channel = client.open_node().await;
    channel.request_shell(true).await.unwrap();
    channel.exec(true, "id").await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    channel
        .request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel
        .request_x11(true, false, "MIT-MAGIC-COOKIE-1", "00", 0)
        .await
        .unwrap();
    channel.agent_forward(true).await.unwrap();
    channel.set_env(true, "LANG", "C").await.unwrap();
    let (mut read, write) = channel.split();
    for request in 0..7 {
        let reply = tokio::time::timeout(STEP, read.wait()).await.unwrap();
        assert!(matches!(reply, Some(ChannelMsg::Failure)), "{request}");
    }
    send(&write, b"still a tunnel").await;
    write.eof().await.unwrap();
    assert_eq!(drain(&mut read).await.data, b"still a tunnel");
    assert!(gate.events().contains(&OuterEvent::SessionRefused));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_node_names_under_the_suffix_on_port_22_are_forwarded() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let client = gate.login().await;
    let cases = [
        (node(), 22, true),
        (node().to_uppercase(), 22, true),
        ("node1.other.example.com".to_owned(), 22, false),
        (node(), 2222, false),
        ("10.0.0.1".to_owned(), 22, false),
        (format!(".{SUFFIX}"), 22, false),
        (format!("{}.{SUFFIX}", "a".repeat(64)), 22, false),
    ];
    let expected = format!("jaunt: only <node>.{SUFFIX} port 22 is reachable through this gateway");
    let mut refused = 0;
    for (host, port, allowed) in cases {
        assert_eq!(
            client.open(&host, port).await.is_ok(),
            allowed,
            "{host}:{port}"
        );
        if !allowed {
            let failure = client.failure(refused).await;
            assert_eq!(
                failure,
                (
                    ChannelOpenFailure::AdministrativelyProhibited,
                    expected.clone()
                ),
                "{host}:{port}"
            );
            refused += 1;
        }
    }
    assert_eq!(gate.backend.routes(), ["node1", "node1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_refusals_reveal_nothing_but_a_limit() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let client = gate.login().await;
    let refusals = [
        RouteRefusal::Denied,
        RouteRefusal::Unavailable,
        RouteRefusal::Limit,
    ];
    let mut seen = Vec::new();
    for (index, refusal) in refusals.into_iter().enumerate() {
        gate.backend.set_mode(Mode::Refuse(refusal));
        assert!(client.open(&node(), 22).await.is_err());
        seen.push(client.failure(index).await);
    }
    let denied = (ChannelOpenFailure::ConnectFailed, DENIED_TEXT.to_owned());
    let limit = (ChannelOpenFailure::ResourceShortage, LIMIT_TEXT.to_owned());
    assert_eq!(seen, [denied.clone(), denied, limit]);
    assert_eq!(gate.backend.released(), 0);
    let outcomes: Vec<_> = gate
        .events()
        .into_iter()
        .filter_map(|event| match event {
            OuterEvent::ForwardRefused { node, refusal } => Some((node, refusal)),
            _ => None,
        })
        .collect();
    let node = Some("node1".to_owned());
    assert_eq!(
        outcomes,
        [
            (node.clone(), ForwardRefusal::Denied),
            (node.clone(), ForwardRefusal::Unavailable),
            (node, ForwardRefusal::Limit),
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_route_does_not_stall_other_channels() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let client = gate.login().await;
    let (mut read, write) = client.open_node().await.split();
    gate.backend.set_mode(Mode::Gated);
    let target = node();
    let (opened, ()) = tokio::join!(client.open(&target, 22), async {
        until("the slow route starts", || gate.backend.routing() == 1).await;
        send(&write, b"ping").await;
        let echoed = tokio::time::timeout(Duration::from_secs(5), next_data(&mut read))
            .await
            .expect("the echo waited for another channel's route");
        assert_eq!(echoed.as_ref(), b"ping");
        gate.backend.open_gate();
    });
    let (mut read, write) = opened.unwrap().split();
    send(&write, b"late").await;
    write.eof().await.unwrap();
    assert_eq!(drain(&mut read).await.data, b"late");
}

#[tokio::test(start_paused = true)]
async fn aborting_serve_while_routing_cancels_the_route() {
    let gate = Gate::new(OuterLimits::default(), Mode::Pending);
    let client = gate.login().await;
    let started = Instant::now();
    let target = node();
    let (opened, ()) = tokio::join!(client.open(&target, 22), async {
        until("the route starts", || gate.backend.routing() == 1).await;
        client.serve.abort();
        until("the route is dropped", || gate.backend.routing() == 0).await;
    });
    assert!(opened.is_err());
    assert!(started.elapsed() < Duration::from_secs(10));
    gate.assert_settled(&[]);
}

#[tokio::test(start_paused = true)]
async fn every_failed_route_gives_its_forward_slot_back() {
    let limits = OuterLimits {
        max_forwards: 1,
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Refuse(RouteRefusal::Denied));
    let client = gate.login().await;
    let denied = (ChannelOpenFailure::ConnectFailed, DENIED_TEXT.to_owned());
    assert!(client.open(&node(), 22).await.is_err());
    assert_eq!(client.failure(0).await, denied);

    gate.backend.set_mode(Mode::PanicRoute);
    assert!(client.open(&node(), 22).await.is_err());
    assert_eq!(
        client.failure(1).await.0,
        ChannelOpenFailure::AdministrativelyProhibited
    );

    gate.backend.set_mode(Mode::Pending);
    let started = Instant::now();
    assert!(client.open(&node(), 22).await.is_err());
    let waited = started.elapsed();
    assert!(
        (Duration::from_secs(10)..Duration::from_secs(11)).contains(&waited),
        "{waited:?}"
    );
    assert_eq!(client.failure(2).await, denied);
    assert_eq!(gate.backend.routing(), 0);

    gate.backend.set_mode(Mode::Echo);
    let (mut read, write) = client.open_node().await.split();
    send(&write, b"still alive").await;
    write.eof().await.unwrap();
    assert_eq!(drain(&mut read).await.data, b"still alive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_forwards_and_opens_per_minute_are_limited() {
    let limits = OuterLimits {
        max_forwards: 2,
        opens_per_minute: 4,
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Echo);
    let client = gate.login().await;
    let limit = (ChannelOpenFailure::ResourceShortage, LIMIT_TEXT.to_owned());
    let first = client.open_node().await;
    let second = client.open_node().await;
    assert!(client.open(&node(), 22).await.is_err());
    assert_eq!(client.failure(0).await, limit);
    first.close().await.unwrap();
    until("the first forward is released", || {
        gate.backend.released() == 1
    })
    .await;
    let _third = client.open_node().await;
    second.close().await.unwrap();
    until("the second forward is released", || {
        gate.backend.released() == 2
    })
    .await;
    assert!(client.open(&node(), 22).await.is_err());
    assert_eq!(client.failure(1).await, limit);
    assert_eq!(gate.backend.routes().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_echo_with_a_slow_reader_completes() {
    const TOTAL: usize = 64 * 1024 * 1024;
    const CHUNK: usize = 32 * 1024;
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let config = client::Config {
        window_size: 512 * 1024,
        channel_buffer_size: 8,
        ..client::Config::default()
    };
    let mut client = gate.connect_with(config).await;
    client.authenticate().await;
    let (mut read, write) = client.open_node().await.split();
    let transfer = async move {
        let writer = tokio::spawn(async move {
            for offset in (0..TOTAL).step_by(CHUNK) {
                write
                    .data_bytes(Bytes::from(pattern(offset, CHUNK)))
                    .await
                    .unwrap();
            }
            write.eof().await.unwrap();
        });
        let mut received = 0;
        while let Some(message) = read.wait().await {
            match message {
                ChannelMsg::Data { data } => {
                    assert_eq!(data.as_ref(), pattern(received, data.len()).as_slice());
                    received += data.len();
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        writer.await.unwrap();
        received
    };
    let received = tokio::time::timeout(Duration::from_secs(60), transfer)
        .await
        .expect("the gate deadlocked");
    assert_eq!(received, TOTAL);
    let total = u64::try_from(TOTAL).unwrap();
    assert_eq!(
        gate.closed_forwards(1).await,
        [(StreamEnd::Eof, total, total)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eof_and_close_travel_in_both_directions() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let client = gate.login().await;

    let (mut read, write) = client.open_node().await.split();
    send(&write, b"hello").await;
    write.eof().await.unwrap();
    let echoed = drain(&mut read).await;
    assert_eq!(
        (echoed.data.as_slice(), echoed.eof, echoed.closed),
        (&b"hello"[..], true, true)
    );

    gate.backend.set_mode(Mode::Greet);
    let (mut read, _write) = client.open_node().await.split();
    let greeted = drain(&mut read).await;
    assert_eq!(
        (greeted.data.as_slice(), greeted.eof, greeted.closed),
        (&b"bye"[..], true, true)
    );

    gate.backend.set_mode(Mode::Flood);
    let (mut read, write) = client.open_node().await.split();
    tokio::time::timeout(STEP, next_data(&mut read))
        .await
        .unwrap();
    drop(read);
    write.close().await.unwrap();
    assert_eq!(
        gate.closed_reasons(3).await,
        [StreamEnd::Eof, StreamEnd::Eof, StreamEnd::ClientGone]
    );
    assert_eq!(gate.backend.live(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_close_cancels_a_pump_blocked_on_the_tunnel() {
    let gate = Gate::new(OuterLimits::default(), Mode::Hold);
    let client = gate.login().await;
    let (_read, write) = client.open_node().await.split();
    assert!(client.fill(&write).await >= WINDOW);
    write.close().await.unwrap();
    assert_eq!(gate.closed_reasons(1).await, [StreamEnd::ClientGone]);
    assert_eq!(gate.backend.live(), 0);
}

#[derive(Debug, Clone, Copy)]
enum EndPath {
    BackendPanic,
    ReleasePanics,
    ClientDisconnect,
    ServeCancelled,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_forward_is_released_exactly_once() {
    for (path, reason) in [
        (EndPath::BackendPanic, StreamEnd::TunnelGone),
        (EndPath::ReleasePanics, StreamEnd::Eof),
        (EndPath::ClientDisconnect, StreamEnd::ClientGone),
        (EndPath::ServeCancelled, StreamEnd::Shutdown),
    ] {
        let mode = match path {
            EndPath::BackendPanic => Mode::Explode,
            EndPath::ReleasePanics | EndPath::ClientDisconnect | EndPath::ServeCancelled => {
                Mode::Echo
            }
        };
        let gate = Gate::new(OuterLimits::default(), mode);
        let client = gate.login().await;
        let (mut read, write) = client.open_node().await.split();
        match path {
            EndPath::BackendPanic => {
                let ended = drain(&mut read).await;
                assert!(ended.closed && !ended.eof && ended.data.is_empty());
                assert_eq!(client.ended().await.reason, OuterEndReason::ClientGone);
            }
            EndPath::ReleasePanics => {
                gate.backend.fail_releases();
                send(&write, b"x").await;
                write.eof().await.unwrap();
                assert_eq!(drain(&mut read).await.data, b"x");
                assert_eq!(client.ended().await.reason, OuterEndReason::ClientGone);
            }
            EndPath::ClientDisconnect => {
                assert_eq!(client.ended().await.reason, OuterEndReason::ClientGone);
            }
            EndPath::ServeCancelled => {
                client.serve.abort();
                assert!(drain(&mut read).await.data.is_empty());
            }
        }
        assert_eq!(gate.closed_reasons(1).await, [reason], "{path:?}");
        assert_eq!(gate.backend.live(), 0, "{path:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shutdown_ends_the_connection_and_every_forward() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let (_silent, serve, shutdown) = gate.serve();
    let started = Instant::now();
    shutdown.cancel();
    assert_eq!(finished(serve).await.reason, OuterEndReason::Shutdown);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(gate.idle_permits());
    let disconnected = OuterEvent::Disconnected {
        reason: OuterEndReason::Shutdown,
    };
    assert_eq!(gate.events().last(), Some(&disconnected));

    let client = gate.login().await;
    let _first = client.open_node().await;
    let _second = client.open_node().await;
    let started = Instant::now();
    client.shutdown.cancel();
    assert_eq!(
        client.disconnect_notice().await,
        (
            "ByApplication".to_owned(),
            "jaunt: the gateway is shutting down".to_owned()
        )
    );
    let end = finished(client.serve).await;
    assert!(started.elapsed() < GRACE + Duration::from_secs(1));
    assert_eq!(end.reason, OuterEndReason::Shutdown);
    gate.assert_settled(&[StreamEnd::Shutdown, StreamEnd::Shutdown]);
    assert_eq!(gate.events().last(), Some(&disconnected));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminated_connection_hears_only_the_refusal_text_and_loses_every_forward() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let (client, terminate) = gate.login_terminable().await;
    let (bystander, _keep) = gate.login_terminable().await;
    let _first = client.open_node().await;
    let _second = client.open_node().await;
    let started = Instant::now();

    terminate.cancel();

    assert_eq!(
        client.disconnect_notice().await,
        ("ByApplication".to_owned(), DENIED_TEXT.to_owned())
    );
    let end = finished(client.serve).await;
    assert!(started.elapsed() < GRACE + Duration::from_secs(1));
    assert_eq!(end.reason, OuterEndReason::Terminated);
    assert_eq!(end.reason.reason(), "terminated");
    assert_eq!(
        end.identity.map(|identity| identity.user_id).as_deref(),
        Some(USER_ID)
    );
    assert_eq!(
        gate.closed_reasons(2).await,
        [StreamEnd::Shutdown, StreamEnd::Shutdown]
    );
    assert!(gate.events().contains(&OuterEvent::Disconnected {
        reason: OuterEndReason::Terminated
    }));
    let _alive = bystander.open_node().await;
    assert_eq!(bystander.ended().await.reason, OuterEndReason::ClientGone);
}

#[tokio::test(start_paused = true)]
async fn a_client_that_disconnects_but_keeps_the_transport_open_is_let_go() {
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let mut client = gate.connect_held_open().await;
    client.authenticate().await;
    let _first = client.open_node().await;
    let _second = client.open_node().await;
    let started = Instant::now();
    client
        .handle
        .disconnect(Disconnect::ByApplication, "bye", "en")
        .await
        .unwrap();
    let end = finished(client.serve).await;
    assert!(started.elapsed() >= GRACE);
    assert!(started.elapsed() <= GRACE + Duration::from_millis(100));
    assert_eq!(end.reason, OuterEndReason::ClientGone);
    gate.assert_settled(&[StreamEnd::ClientGone, StreamEnd::ClientGone]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_ends_when_the_certificate_expires() {
    let gate = Gate::with_clock_shift(OuterLimits::default(), Mode::Echo, 3596);
    let client = gate.login().await;
    let (mut read, _write) = client.open_node().await.split();
    assert_eq!(
        client.disconnect_notice().await,
        (
            "ByApplication".to_owned(),
            "jaunt: your certificate has expired, run jaunt login".to_owned()
        )
    );
    assert!(!drain(&mut read).await.closed);
    let end = finished(client.serve).await;
    assert_eq!(end.reason, OuterEndReason::CertificateExpired);
    assert_eq!(
        end.identity.map(|identity| identity.user_id).as_deref(),
        Some(USER_ID)
    );
    gate.assert_settled(&[StreamEnd::Shutdown]);
}

fn blocked_reader() -> client::Config {
    client::Config {
        window_size: 64 * 1024,
        channel_buffer_size: 2,
        ..client::Config::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_whose_writes_stall_is_closed() {
    let limits = OuterLimits {
        write_stall_timeout: Some(Duration::from_millis(300)),
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Flood);
    gate.fail_closed_events();
    let mut client = gate.connect_with(blocked_reader()).await;
    client.authenticate().await;
    let (mut read, _write) = client.open_node().await.split();
    assert_eq!(gate.closed_reasons(1).await, [StreamEnd::Stall]);
    assert_eq!(gate.backend.live(), 0);
    let stalled = drain(&mut read).await;
    assert!(stalled.closed && !stalled.eof);
}

#[tokio::test(start_paused = true)]
async fn a_zero_stall_timeout_disables_the_watchdog() {
    let limits = OuterLimits {
        write_stall_timeout: Some(Duration::ZERO),
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Flood);
    let mut client = gate.connect_with(blocked_reader()).await;
    client.authenticate().await;
    let (mut read, _write) = client.open_node().await.split();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(gate.stream_ends().is_empty());
    assert_eq!(gate.backend.live(), 1);
    let resumed = tokio::time::timeout(STEP, next_data(&mut read))
        .await
        .unwrap();
    assert!(!resumed.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_gate_buffers_at_most_one_window_per_forward() {
    let limits = OuterLimits {
        max_forwards: 2,
        ..OuterLimits::default()
    };
    let gate = Gate::new(limits, Mode::Hold);
    let client = gate.login().await;
    let mut writers = Vec::new();
    for _ in 0..2 {
        let (_read, write) = client.open_node().await.split();
        let sent = client.fill(&write).await;
        assert!(
            (WINDOW..=WINDOW + TUNNEL_BUFFER).contains(&sent),
            "{sent} bytes accepted"
        );
        writers.push(write);
    }
    assert!(client.open(&node(), 22).await.is_err());
    gate.backend.resume();
    for write in &writers {
        let deadline = Instant::now() + STEP;
        while write.writable_packet_size().await == 0 {
            assert!(Instant::now() < deadline, "no window after consumption");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_reaches_a_node_through_the_hop() {
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::Stdio;

    use russh::keys::ssh_key::LineEnding;
    use tokio::io::AsyncReadExt;
    use tokio_util::sync::CancellationToken;

    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("ssh is not installed; skipping the OpenSSH interop test");
        return;
    }
    let gate = Gate::new(OuterLimits::default(), Mode::Echo);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hop = Arc::clone(&gate.hop);
    let permits = Arc::clone(&gate.permits);
    let server = tokio::spawn(async move {
        let (tcp, peer) = listener.accept().await.unwrap();
        let permit = permits.try_acquire_owned().unwrap();
        hop.serve(tcp, peer, permit, CancellationToken::new()).await
    });
    let dir = tempfile::tempdir().unwrap();
    let subject = key();
    let now = unix_now();
    let cert = support::certificate(
        &gate.user_ca,
        &subject,
        CertType::User,
        now - 120,
        now + 600,
    );
    let key_path = dir.path().join("id_ed25519");
    let mut key_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap();
    std::io::Write::write_all(
        &mut key_file,
        subject.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let cert_path = dir.path().join("id_ed25519-cert.pub");
    std::fs::write(&cert_path, cert.to_openssh().unwrap()).unwrap();
    let known_hosts = dir.path().join("known_hosts");
    let host_ca = gate.host_ca.public_key().to_openssh().unwrap();
    std::fs::write(
        &known_hosts,
        format!("@cert-authority gate.test {host_ca}\n"),
    )
    .unwrap();

    let mut ssh = tokio::process::Command::new("ssh")
        .arg("-F")
        .arg("/dev/null")
        .args(["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes"])
        .args([
            "-o",
            "IdentityAgent=none",
            "-o",
            "StrictHostKeyChecking=yes",
        ])
        .args([
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlias=gate.test",
        ])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-o")
        .arg(format!("CertificateFile={}", cert_path.display()))
        .arg("-i")
        .arg(&key_path)
        .args(["-p", &port.to_string(), "-W", &format!("{}:22", node())])
        .arg("jaunt@127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let payload = pattern(0, 1024 * 1024);
    let mut stdin = ssh.stdin.take().unwrap();
    let mut stdout = ssh.stdout.take().unwrap();
    let mut stderr = ssh.stderr.take().unwrap();
    let sent = payload.clone();
    let exchange = async move {
        let writer = tokio::spawn(async move {
            stdin.write_all(&sent).await.unwrap();
            drop(stdin);
        });
        let mut echoed = Vec::new();
        stdout.read_to_end(&mut echoed).await.unwrap();
        let mut errors = String::new();
        stderr.read_to_string(&mut errors).await.unwrap();
        writer.await.unwrap();
        (echoed, ssh.wait().await.unwrap(), errors)
    };
    let (echoed, status, errors) = tokio::time::timeout(STEP, exchange).await.unwrap();
    assert!(status.success(), "{status}: {errors}");
    assert_eq!(echoed.len(), payload.len(), "{errors}");
    assert!(echoed == payload);
    let end = finished(server).await;
    assert_eq!(end.reason, OuterEndReason::ClientGone);
    gate.assert_settled(&[StreamEnd::Eof]);
}
