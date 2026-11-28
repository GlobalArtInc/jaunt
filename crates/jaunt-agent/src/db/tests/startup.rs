use jaunt_pgwire::{BackendMessage, DecodeError, Event, FrontendDecoder};

use super::fake_pg::message;
use super::harness::{
    DbHarness, Decision, SERVICE, default_startup, fatal, packet, query, startup,
};
use crate::db::DB_LIMITS;
use crate::db::wire::{ACCESS_DENIED, UNAVAILABLE};
use crate::runtime::limits::SERVICE_LIMITS;
use crate::runtime::tests::support::{later, service_id, wait_until};

const SSL_REQUEST: u32 = (1234 << 16) | 5679;
const GSSENC_REQUEST: u32 = (1234 << 16) | 5680;

#[tokio::test]
async fn negotiation_requests_get_n_and_the_greeting_comes_from_the_agent_in_order() {
    let harness = DbHarness::new().await;
    let (_opened, mut client) = harness.connect("s-order").await;
    client.send(&packet(GSSENC_REQUEST, &[])).await;
    assert_eq!(client.byte().await, Some(b'N'));
    client.send(&packet(SSL_REQUEST, &[])).await;
    assert_eq!(client.byte().await, Some(b'N'));
    client.send(&startup(&default_startup())).await;
    let greeting = client.until_ready().await;
    assert!(matches!(&greeting[0], BackendMessage::Authentication(auth) if auth.is_ok()));
    let parameters: Vec<&str> = greeting
        .iter()
        .filter_map(|message| match message {
            BackendMessage::ParameterStatus(status) => Some(status.name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(parameters, ["server_version", "client_encoding"]);
    assert!(matches!(
        &greeting[greeting.len() - 2],
        BackendMessage::BackendKeyData(key) if key.process_id() == 4001
    ));
    assert_eq!(greeting.len(), 5);

    let mut extended = message(b'P', b"\0SELECT 1\0\0\0");
    extended.extend(message(b'B', b"\0\0\0\0\0\0\0\0"));
    extended.extend(message(b'D', b"P\0"));
    extended.extend(message(b'E', b"\0\0\0\0\0"));
    extended.extend(message(b'S', &[]));
    client.send(&extended).await;
    let replies: Vec<u8> = client
        .until_ready()
        .await
        .iter()
        .map(|message| match message {
            BackendMessage::Other { tag, .. } => *tag,
            BackendMessage::CommandComplete(_) => b'C',
            BackendMessage::ReadyForQuery(_) => b'Z',
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(replies, b"12nCZ");
    let seen = harness.pg.seen();
    let tags: Vec<u8> = seen.messages.iter().map(|(tag, _)| *tag).collect();
    assert_eq!(tags, b"PBDES");
    assert_eq!(
        seen.startups[0],
        [
            ("user".to_owned(), "app".to_owned()),
            ("database".to_owned(), "main".to_owned()),
            ("application_name".to_owned(), "psql".to_owned()),
            ("client_encoding".to_owned(), "UTF8".to_owned()),
        ]
    );
}

#[tokio::test]
async fn a_third_or_repeated_negotiation_request_closes_the_connection() {
    for requests in [
        [SSL_REQUEST, GSSENC_REQUEST, SSL_REQUEST].as_slice(),
        [GSSENC_REQUEST, SSL_REQUEST, GSSENC_REQUEST].as_slice(),
        [SSL_REQUEST, SSL_REQUEST].as_slice(),
    ] {
        let harness = DbHarness::new().await;
        let (opened, mut client) = harness.connect("s-negotiate").await;
        let (last, allowed) = requests.split_last().unwrap();
        for code in allowed {
            client.send(&packet(*code, &[])).await;
            assert_eq!(client.byte().await, Some(b'N'));
        }
        client.send(&packet(*last, &[])).await;
        assert_eq!(client.byte().await, None, "{requests:?}");
        opened.finished().await;
        assert!(harness.control.authorizations().is_empty());
    }
}

#[tokio::test]
async fn refused_startup_messages_get_a_protocol_error_and_control_is_never_asked() {
    let many: Vec<(String, String)> = (0..65)
        .map(|index| (format!("p{index}"), String::new()))
        .collect();
    let mut many_refs: Vec<(&str, &str)> = vec![("user", "app")];
    many_refs.extend(
        many.iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let big = "x".repeat(10 * 1024);
    let cases: Vec<Vec<u8>> = vec![
        startup(&[("user", "app"), ("replication", "database")]),
        startup(&[("user", "app"), ("options", "-c log_statement=none")]),
        startup(&[("database", "main")]),
        startup(&many_refs),
        startup(&[("user", "app"), ("application_name", big.as_str())]),
        packet(2 << 16, &[0]),
        query("SELECT 1"),
    ];
    for bytes in cases {
        let harness = DbHarness::new().await;
        let (opened, mut client) = harness.connect("s-refused").await;
        client.send(&bytes).await;
        let answer = client.rest().await;
        let (code, _) = fatal(&answer).unwrap_or_else(|| panic!("no error for {:?}", &bytes[..12]));
        assert_eq!(code, "08P01");
        assert_eq!(answer.len(), 1);
        opened.finished().await;
        assert!(harness.control.authorizations().is_empty());
        assert_eq!(harness.pg.seen().connections, 0);
    }
}

#[tokio::test]
async fn a_client_that_never_sends_its_startup_is_cut_after_ten_seconds() {
    let harness = DbHarness::new().await;
    let (opened, mut client) = harness.connect("s-quiet").await;
    wait_until("the handshake to finish on the agent", || {
        harness
            .runtime
            .gauges()
            .handshakes_held(&service_id(SERVICE))
            == 0
    })
    .await;
    let deadline = later(&harness.clock, SERVICE_LIMITS.handshake_timeout);
    harness.clock.wait_for_sleeper(deadline).await;
    harness.clock.advance(SERVICE_LIMITS.handshake_timeout);
    assert!(client.rest().await.is_empty());
    opened.finished().await;
    assert!(harness.control.authorizations().is_empty());
}

#[tokio::test]
async fn a_denied_or_failed_authorization_answers_generically_without_the_database() {
    for (decision, expected) in [
        (Decision::Deny, ACCESS_DENIED),
        (Decision::Fail(503), UNAVAILABLE),
        (Decision::Fail(403), UNAVAILABLE),
    ] {
        let harness = DbHarness::new().await;
        harness.control.script(decision);
        let (opened, mut client) = harness.connect("s-denied").await;
        client.send(&startup(&default_startup())).await;
        let answer = client.rest().await;
        assert_eq!(
            fatal(&answer),
            Some((expected.0.to_owned(), expected.1.to_owned()))
        );
        assert_eq!(answer.len(), 1);
        opened.finished().await;
        let asked = harness.control.authorizations();
        assert_eq!(asked.len(), 1);
        let db = asked[0].db.clone().unwrap();
        assert_eq!((db.user.as_str(), db.name.as_str()), ("app", "main"));
        assert_eq!(harness.pg.seen().connections, 0);
    }
}

#[test]
fn the_startup_decoder_takes_ten_kib_and_sixty_four_parameters() {
    let decode = |bytes: &[u8]| {
        let mut decoder = FrontendDecoder::with_streamed_queries(DB_LIMITS.frontend).unwrap();
        decoder.push(bytes).unwrap();
        decoder.next_event()
    };
    let sized = |length: usize| {
        let value = "v".repeat(length);
        startup(&[("user", "app"), ("application_name", value.as_str())])
    };
    assert_eq!(sized(10_204).len(), 10 * 1024);
    assert!(matches!(decode(&sized(10_204)), Ok(Some(Event::Frame(_)))));
    assert!(matches!(
        decode(&sized(10_205)),
        Err(DecodeError::TooLarge { limit: 10_240, .. })
    ));
    let names: Vec<String> = (0..64).map(|index| format!("p{index}")).collect();
    let counted = |count: usize| {
        let mut parameters = vec![("user", "app")];
        parameters.extend(names.iter().take(count - 1).map(|name| (name.as_str(), "")));
        startup(&parameters)
    };
    assert!(matches!(decode(&counted(64)), Ok(Some(Event::Frame(_)))));
    assert!(matches!(
        decode(&counted(65)),
        Err(DecodeError::TooManyStartupParameters { limit: 64 })
    ));
}
