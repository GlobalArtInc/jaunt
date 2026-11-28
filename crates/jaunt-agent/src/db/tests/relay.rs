use std::sync::Arc;
use std::time::{Duration, SystemTime};

use jaunt_pgwire::{BackendDecoder, Event, FrontendDecoder, FrontendMessage, Limits};
use jaunt_proto::{AgentEventBatch, AgentEventsAccepted, QueryAudit, ServiceOutcome};
use jaunt_tunnel::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::fake_pg::{cstr, message};
use super::harness::{default_startup, query, startup};
use crate::clock::Clock;
use crate::db::DB_LIMITS;
use crate::db::audit::{QuerySettings, SessionAudit, SessionStart};
use crate::db::relay::{Relay, RelayContext, relay};
use crate::db::wire::TERMINATE;
use crate::run::api::{ApiError, EventsAnswer};
use crate::runtime::events::{EventSink, EventTransport, SINK_LIMITS};
use crate::runtime::tests::support::fixed;
use crate::testkit::{ManualClock, soon};

struct Accepting;

impl EventTransport for Accepting {
    fn send<'a>(
        &'a self,
        batch: &'a AgentEventBatch,
    ) -> BoxFuture<'a, Result<EventsAnswer, ApiError>> {
        let accepted = u64::try_from(batch.events.len()).unwrap();
        Box::pin(async move {
            Ok(EventsAnswer::Accepted(AgentEventsAccepted {
                accepted,
                ..AgentEventsAccepted::default()
            }))
        })
    }
}

struct Wired {
    client: DuplexStream,
    database: DuplexStream,
    cancel: CancellationToken,
    relaying: JoinHandle<ServiceOutcome>,
}

fn after_startup() -> FrontendDecoder {
    let mut decoder = FrontendDecoder::with_streamed_queries(DB_LIMITS.frontend).unwrap();
    decoder.push(&startup(&default_startup())).unwrap();
    let Some(Event::Frame(frame)) = decoder.next_event().unwrap() else {
        panic!("expected the startup message");
    };
    assert!(matches!(frame.message(), FrontendMessage::Startup(_)));
    decoder
}

fn wire() -> Wired {
    let (client, client_end) = tokio::io::duplex(64 * 1024);
    let (database, database_end) = tokio::io::duplex(64 * 1024);
    let clock: Arc<dyn Clock> = ManualClock::new(SystemTime::now());
    let sink = EventSink::new(Arc::new(Accepting), clock.clone(), fixed(1.0), SINK_LIMITS);
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let relaying = tokio::spawn(async move {
        let audit = SessionAudit::start(
            sink.session("s-relay"),
            clock.clone(),
            QuerySettings {
                mode: QueryAudit::Text,
                limit: 4096,
            },
            &SessionStart {
                db_user: "app",
                db_name: "main",
                application_name: None,
                server: "127.0.0.1:5432",
            },
        );
        relay(
            Relay {
                client: client_end,
                upstream: database_end,
                frontend: after_startup(),
                backend: BackendDecoder::new(Limits::default()).unwrap(),
            },
            RelayContext {
                audit: &audit,
                cancel: &token,
                clock: &clock,
                close_timeout: DB_LIMITS.close_timeout,
                session_id: "s-relay",
            },
        )
        .await
    });
    Wired {
        client,
        database,
        cancel,
        relaying,
    }
}

async fn until_closed(database: &mut DuplexStream) -> Vec<u8> {
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), database.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    received
}

#[tokio::test]
async fn a_cancelled_session_terminates_the_database_connection_in_the_middle_of_a_query() {
    let mut wired = wire();
    let sleep = query("SELECT pg_sleep(60)");
    wired.client.write_all(&sleep).await.unwrap();
    let mut forwarded = vec![0_u8; sleep.len()];
    soon(
        "the query to reach the database",
        wired.database.read_exact(&mut forwarded),
    )
    .await
    .unwrap();
    assert_eq!(forwarded, sleep);
    wired.cancel.cancel();
    assert_eq!(until_closed(&mut wired.database).await, TERMINATE);
    assert_eq!(
        soon("the relay to end", wired.relaying).await.unwrap(),
        ServiceOutcome::Closed
    );
}

#[tokio::test]
async fn a_client_that_vanishes_inside_a_message_adds_nothing_to_the_database_stream() {
    let mut body = cstr("SELECT ");
    body.splice(7..7, vec![b'x'; 100]);
    let whole = message(b'Q', &body);
    let copy = message(b'd', &[b'r'; 120]);
    let parse = message(b'P', &[b'p'; 120]);
    let mut finished = whole.clone();
    finished.extend_from_slice(&TERMINATE);
    let cases: [(Vec<u8>, Vec<u8>); 4] = [
        (whole[..60].to_vec(), whole[..60].to_vec()),
        (copy[..70].to_vec(), copy[..70].to_vec()),
        (parse[..70].to_vec(), TERMINATE.to_vec()),
        (whole.clone(), finished),
    ];
    for (sent, expected) in cases {
        let mut wired = wire();
        wired.client.write_all(&sent).await.unwrap();
        drop(wired.client);
        assert_eq!(until_closed(&mut wired.database).await, expected);
        assert_eq!(
            soon("the relay to end", wired.relaying).await.unwrap(),
            ServiceOutcome::Closed
        );
    }
}
