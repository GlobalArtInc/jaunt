use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use jaunt_pgwire::{BackendDecoder, Event, FrontendDecoder, FrontendMessage, Limits};
use jaunt_proto::{AgentEventBatch, AgentEventsAccepted, QueryAudit, ServiceOutcome};
use jaunt_tunnel::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::fake_pg::{cstr, message};
use super::harness::{default_startup, query, startup};
use crate::clock::Clock;
use crate::db::DB_LIMITS;
use crate::db::audit::{QuerySettings, SessionAudit, SessionStart};
use crate::db::relay::{Relay, RelayContext, relay};
use crate::db::wire::{FUNCTION_CALLS, TERMINATE, error_response};
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
    clock: Arc<ManualClock>,
    relaying: JoinHandle<ServiceOutcome>,
}

struct Unread(DuplexStream);

impl AsyncRead for Unread {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for Unread {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
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
    wire_with(|client_end| client_end)
}

fn wire_with<C, F>(client_end: F) -> Wired
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnOnce(DuplexStream) -> C,
{
    let (client, client_side) = tokio::io::duplex(64 * 1024);
    let (database, database_end) = tokio::io::duplex(64 * 1024);
    let manual = ManualClock::new(SystemTime::now());
    let clock: Arc<dyn Clock> = manual.clone();
    let sink = EventSink::new(Arc::new(Accepting), clock.clone(), fixed(1.0), SINK_LIMITS);
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let client_end = client_end(client_side);
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
                cancel_close_timeout: DB_LIMITS.cancel_close_timeout,
                session_id: "s-relay",
            },
        )
        .await
    });
    Wired {
        client,
        database,
        cancel,
        clock: manual,
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

#[tokio::test]
async fn a_function_call_answer_is_never_put_inside_a_message_of_the_database() {
    let row = message(b'D', &[7; 100]);
    for (sent, answered) in [(row[..15].to_vec(), false), (row.clone(), true)] {
        let mut wired = wire();
        wired.database.write_all(&sent).await.unwrap();
        let mut forwarded = vec![0_u8; sent.len()];
        soon(
            "the row to reach the client",
            wired.client.read_exact(&mut forwarded),
        )
        .await
        .unwrap();
        assert_eq!(forwarded, sent);
        wired
            .client
            .write_all(&message(b'F', &[0; 10]))
            .await
            .unwrap();
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), wired.client.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        let expected = if answered {
            error_response(FUNCTION_CALLS.0, FUNCTION_CALLS.1)
        } else {
            Vec::new()
        };
        assert_eq!(rest, expected);
        assert_eq!(
            soon("the relay to end", wired.relaying).await.unwrap(),
            ServiceOutcome::ProtocolError
        );
    }
}

#[tokio::test]
async fn a_cancelled_session_closes_within_half_a_second_when_the_client_reads_nothing() {
    let mut wired = wire_with(Unread);
    wired
        .database
        .write_all(&message(b'D', &[7; 100]))
        .await
        .unwrap();
    wired.cancel.cancel();
    let deadline = wired.clock.now() + DB_LIMITS.cancel_close_timeout;
    wired.clock.wait_for_sleeper(deadline).await;
    assert!(!wired.relaying.is_finished());
    assert_eq!(until_closed(&mut wired.database).await, TERMINATE);
    wired.clock.advance(DB_LIMITS.cancel_close_timeout);
    assert_eq!(
        soon("the relay to end", wired.relaying).await.unwrap(),
        ServiceOutcome::Closed
    );
    assert_eq!(DB_LIMITS.cancel_close_timeout, Duration::from_millis(500));
}
