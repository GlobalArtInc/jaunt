use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::ServiceOutcome;

use super::fake_pg::{Mode, SERVER_NAME};
use super::harness::{
    DbHarness, DbOptions, Decision, default_startup, fatal, query, startup, text,
};
use crate::db::DB_LIMITS;
use crate::db::wire::{PASSWORD_REQUESTED, UNAVAILABLE};
use crate::runtime::tests::support::later;

#[tokio::test]
async fn the_database_gets_the_granted_user_and_name_not_the_requested_ones() {
    let harness = DbHarness::new().await;
    harness
        .control
        .script(Decision::AllowAs("reporting", "analytics"));
    let (_opened, mut client, _) = harness.login("s-grant").await;
    client.send(&query("SELECT 1")).await;
    client.until_ready().await;
    let seen = harness.pg.seen();
    let parameter = |name: &str| {
        seen.startups[0]
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(parameter("user").as_deref(), Some("reporting"));
    assert_eq!(parameter("database").as_deref(), Some("analytics"));
    assert_eq!(seen.client_names, [Some("reporting".to_owned())]);
    let asked = harness.control.authorizations()[0].db.clone().unwrap();
    assert_eq!((asked.user.as_str(), asked.name.as_str()), ("app", "main"));
    assert_eq!(STANDARD.decode(&asked.agent_key).unwrap().len(), 44);
}

#[tokio::test]
async fn every_authentication_request_but_ok_is_a_readable_error_and_a_protocol_error_event() {
    for code in [3, 5, 7, 9, 10, 99] {
        let harness = DbHarness::new().await;
        harness.pg.set_mode(Mode::Password(code));
        let (opened, mut client) = harness.connect("s-password").await;
        client.send(&startup(&default_startup())).await;
        let answer = client.rest().await;
        assert_eq!(
            fatal(&answer),
            Some((
                PASSWORD_REQUESTED.0.to_owned(),
                PASSWORD_REQUESTED.1.to_owned()
            )),
            "{code}"
        );
        assert_eq!(answer.len(), 1, "{code}");
        opened.finished().await;
        assert_eq!(
            harness.ended("s-password").await.outcome,
            ServiceOutcome::UpstreamError
        );
        let problems = harness.named("s-password", "db.protocol_error");
        assert_eq!(problems.len(), 1, "{code}");
        assert_eq!(
            text(&problems[0], "reason").as_deref(),
            Some("password_requested"),
            "{code}"
        );
    }
}

#[tokio::test]
async fn a_database_refusal_passes_only_a_well_formed_sqlstate_to_the_client() {
    for (code, expected) in [
        ("3D000", "3D000"),
        ("3D0000", "08006"),
        ("3d000", "08006"),
        ("3D\"00", "08006"),
        ("XX", "08006"),
    ] {
        let harness = DbHarness::new().await;
        harness.pg.set_mode(Mode::Refuse(code));
        let (opened, mut client) = harness.connect("s-refuse").await;
        client.send(&startup(&default_startup())).await;
        let answer = client.rest().await;
        assert_eq!(
            fatal(&answer),
            Some((
                expected.to_owned(),
                "the database refused the session".to_owned()
            )),
            "{code}"
        );
        opened.finished().await;
        harness.ended("s-refuse").await;
        let errors = harness.named("s-refuse", "db.error");
        assert!(
            text(&errors[0], "error_message")
                .unwrap()
                .contains("10.9.8.7")
        );
    }
}

#[tokio::test]
async fn a_ca_file_above_one_mebibyte_is_not_read_and_the_database_is_never_contacted() {
    for (size, works) in [(1024 * 1024, true), (1024 * 1024 + 1, false)] {
        let harness = DbHarness::with(DbOptions {
            ca_file_bytes: Some(size),
            ..DbOptions::default()
        })
        .await;
        let (_opened, mut client) = harness.connect("s-ca-size").await;
        client.send(&startup(&default_startup())).await;
        if works {
            assert!(fatal(&client.until_ready().await).is_none());
        } else {
            assert_eq!(
                fatal(&client.rest().await),
                Some((UNAVAILABLE.0.to_owned(), UNAVAILABLE.1.to_owned()))
            );
            harness.ended("s-ca-size").await;
            assert_eq!(harness.pg.seen().connections, 0);
        }
    }
}

#[tokio::test]
async fn every_session_asks_control_with_a_key_of_its_own() {
    let harness = DbHarness::new().await;
    let (_first, _client, _) = harness.login("s-key-1").await;
    let (_second, _other, _) = harness.login("s-key-2").await;
    let keys: Vec<String> = harness
        .control
        .authorizations()
        .into_iter()
        .map(|request| request.db.unwrap().agent_key)
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1]);
}

enum Fault {
    Down,
    Silent,
    NoTls,
    ForeignCa,
    OtherName,
    NoCaFile,
}

async fn unavailable(fault: Fault) {
    let mut options = DbOptions::default();
    match fault {
        Fault::Down => {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            options.address = Some(listener.local_addr().unwrap().to_string());
        }
        Fault::ForeignCa => options.foreign_server_ca = true,
        Fault::OtherName => options.server_name = Some("other.test"),
        Fault::NoCaFile => options.ca_file = false,
        Fault::Silent | Fault::NoTls => {}
    }
    let harness = DbHarness::with(options).await;
    match fault {
        Fault::Silent => harness.pg.set_mode(Mode::Silent),
        Fault::NoTls => harness.pg.set_mode(Mode::NoTls),
        _ => {}
    }
    let (opened, mut client) = harness.connect("s-down").await;
    client.send(&startup(&default_startup())).await;
    if matches!(fault, Fault::Silent) {
        harness
            .pg
            .wait("the agent to connect", |seen| seen.connections == 1)
            .await;
        let deadline = later(&harness.clock, DB_LIMITS.connect_timeout);
        harness.clock.wait_for_sleeper(deadline).await;
        harness.clock.advance(DB_LIMITS.connect_timeout);
    }
    let answer = client.rest().await;
    assert_eq!(
        fatal(&answer),
        Some((UNAVAILABLE.0.to_owned(), UNAVAILABLE.1.to_owned()))
    );
    assert_eq!(answer.len(), 1);
    opened.finished().await;
    assert_eq!(
        harness.ended("s-down").await.outcome,
        ServiceOutcome::UpstreamError
    );
    assert!(harness.pg.seen().startups.is_empty());
    let mut names: Vec<String> = harness
        .session_events("s-down")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["db.session.end", "db.session.start"]);
}

#[tokio::test]
async fn an_unreachable_database_is_a_fatal_08006() {
    unavailable(Fault::Down).await;
}

#[tokio::test]
async fn a_database_that_does_not_answer_is_a_fatal_08006_after_ten_seconds() {
    unavailable(Fault::Silent).await;
}

#[tokio::test]
async fn a_database_without_tls_is_a_fatal_08006() {
    unavailable(Fault::NoTls).await;
}

#[tokio::test]
async fn a_database_certificate_from_another_ca_is_a_fatal_08006() {
    unavailable(Fault::ForeignCa).await;
}

#[tokio::test]
async fn a_database_certificate_for_another_name_is_a_fatal_08006() {
    unavailable(Fault::OtherName).await;
}

#[tokio::test]
async fn a_service_without_a_ca_file_is_never_connected() {
    unavailable(Fault::NoCaFile).await;
}

#[tokio::test]
async fn without_a_server_name_the_certificate_must_carry_the_address() {
    for (names, works) in [(vec!["127.0.0.1"], true), (vec![SERVER_NAME], false)] {
        let harness = DbHarness::with(DbOptions {
            server_name: None,
            names,
            ..DbOptions::default()
        })
        .await;
        let (_opened, mut client) = harness.connect("s-address").await;
        client.send(&startup(&default_startup())).await;
        let answer = if works {
            client.until_ready().await
        } else {
            client.rest().await
        };
        assert_eq!(fatal(&answer).is_none(), works);
    }
}

#[tokio::test]
async fn a_database_that_speaks_only_tls_1_2_is_reached() {
    let harness = DbHarness::with(DbOptions {
        tls12_only: true,
        ..DbOptions::default()
    })
    .await;
    let (_opened, mut client, _) = harness.login("s-tls12").await;
    client.send(&query("SELECT 1")).await;
    assert!(fatal(&client.until_ready().await).is_none());
}

#[tokio::test]
async fn a_client_that_vanishes_closes_the_database_connection_within_five_seconds() {
    let harness = DbHarness::new().await;
    let (opened, client, _) = harness.login("s-vanish").await;
    drop(client);
    let closed = tokio::time::timeout(
        Duration::from_secs(5),
        harness
            .pg
            .wait("the database connection to close", |seen| seen.closed == 1),
    )
    .await
    .unwrap();
    assert_eq!(closed.messages.last().map(|(tag, _)| *tag), Some(b'X'));
    opened.finished().await;
    assert_eq!(
        harness.ended("s-vanish").await.outcome,
        ServiceOutcome::Closed
    );
}

#[tokio::test]
async fn the_grant_duration_ends_the_session_and_its_database_connection() {
    let harness = DbHarness::new().await;
    harness.control.set_max_duration(60);
    let (opened, _client, _) = harness.login("s-long").await;
    let deadline = later(&harness.clock, Duration::from_secs(60));
    harness.clock.wait_for_sleeper(deadline).await;
    harness.clock.advance(Duration::from_secs(60));
    harness
        .pg
        .wait("the database connection to close", |seen| seen.closed == 1)
        .await;
    opened.finished().await;
    assert_eq!(
        harness.ended("s-long").await.outcome,
        ServiceOutcome::MaxDuration
    );
    let ends = harness.named("s-long", "db.session.end");
    assert_eq!(ends.len(), 1);
}

#[tokio::test]
async fn the_greeting_of_the_database_is_passed_on_up_to_sixty_four_kib() {
    for (size, works) in [(64 * 1024, true), (64 * 1024 + 1, false)] {
        let harness = DbHarness::new().await;
        harness.pg.set_mode(Mode::Greeting(size));
        let (opened, mut client) = harness.connect("s-greeting").await;
        client.send(&startup(&default_startup())).await;
        if works {
            let greeting = client.until_ready().await;
            assert!(fatal(&greeting).is_none());
            continue;
        }
        assert_eq!(
            fatal(&client.rest().await),
            Some((UNAVAILABLE.0.to_owned(), UNAVAILABLE.1.to_owned()))
        );
        opened.finished().await;
        assert_eq!(
            harness.ended("s-greeting").await.outcome,
            ServiceOutcome::ProtocolError
        );
        let problems = harness.named("s-greeting", "db.protocol_error");
        assert_eq!(
            text(&problems[0], "reason").as_deref(),
            Some("server_too_large")
        );
    }
}
