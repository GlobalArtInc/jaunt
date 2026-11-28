use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use jaunt_pgwire::{
    BackendDecoder, BackendMessage, DecodeError, Event, FrontendDecoder, FrontendMessage,
};
use jaunt_proto::ServiceOutcome;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::audit::{ProtocolProblem, QueryCapture, SessionAudit};
use super::upstream::{deadline, is_safe_parameter, server_problem};
use super::wire::{FUNCTION_CALLS, TERMINATE, error_response};
use crate::clock::Clock;

pub const READ_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    ClientTerminated,
    ClientClosed,
    ServerClosed,
    Cancelled,
    Client(ProtocolProblem),
    Server(ProtocolProblem),
    ClientIo,
    ServerIo,
}

impl Ending {
    fn outcome(self) -> ServiceOutcome {
        match self {
            Self::ClientTerminated
            | Self::ClientClosed
            | Self::ClientIo
            | Self::ServerClosed
            | Self::Cancelled => ServiceOutcome::Closed,
            Self::Client(_) | Self::Server(_) => ServiceOutcome::ProtocolError,
            Self::ServerIo => ServiceOutcome::UpstreamError,
        }
    }

    fn client_side(self) -> bool {
        matches!(
            self,
            Self::ClientClosed | Self::ClientIo | Self::Cancelled | Self::Client(_)
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ClientTerminated => "client_terminated",
            Self::ClientClosed => "client_closed",
            Self::ServerClosed => "server_closed",
            Self::Cancelled => "cancelled",
            Self::Client(problem) | Self::Server(problem) => problem.as_str(),
            Self::ClientIo => "client_io",
            Self::ServerIo => "server_io",
        }
    }
}

fn client_problem(error: &DecodeError) -> ProtocolProblem {
    match error {
        DecodeError::TooLarge { .. }
        | DecodeError::PendingTooLarge { .. }
        | DecodeError::BindPrefixTooLarge { .. } => ProtocolProblem::ClientTooLarge,
        DecodeError::FunctionCallRefused => ProtocolProblem::ClientFunctionCall,
        _ => ProtocolProblem::ClientMalformed,
    }
}

struct StreamedQuery {
    remaining: usize,
    capture: QueryCapture,
}

struct Frontier {
    open: usize,
    boundary: bool,
}

impl Frontier {
    fn new() -> Self {
        Self {
            open: 0,
            boundary: true,
        }
    }
}

async fn client_to_server<R, W>(
    reader: &mut R,
    writer: &mut W,
    decoder: &mut FrontendDecoder,
    audit: &SessionAudit,
    frontier: &mut Frontier,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; READ_CHUNK];
    let mut query: Option<StreamedQuery> = None;
    loop {
        loop {
            let event = match decoder.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => return Ending::Client(client_problem(&error)),
            };
            let mut terminate = false;
            let bytes: Bytes = match event {
                Event::Frame(frame) => {
                    match frame.message() {
                        FrontendMessage::QueryText { length } => {
                            query = Some(StreamedQuery {
                                remaining: *length,
                                capture: QueryCapture::default(),
                            });
                        }
                        FrontendMessage::Query(statement) => {
                            audit.simple_query(&QueryCapture::of(statement.as_bytes()).finish());
                        }
                        FrontendMessage::Parse(parse) => {
                            audit.extended_query(
                                &QueryCapture::of(parse.statement.as_bytes()).finish(),
                            );
                        }
                        FrontendMessage::Sync => audit.sync_sent(),
                        FrontendMessage::Terminate => terminate = true,
                        FrontendMessage::SslRequest
                        | FrontendMessage::GssEncRequest
                        | FrontendMessage::Cancel(_)
                        | FrontendMessage::Startup(_)
                        | FrontendMessage::Password(_) => {
                            return Ending::Client(ProtocolProblem::ClientUnexpected);
                        }
                        FrontendMessage::Bind(_)
                        | FrontendMessage::Execute(_)
                        | FrontendMessage::Describe(_)
                        | FrontendMessage::Close(_)
                        | FrontendMessage::Flush
                        | FrontendMessage::CopyData { .. }
                        | FrontendMessage::CopyDone
                        | FrontendMessage::CopyFail(_) => {}
                    }
                    frontier.open = frame.remaining();
                    frame.raw().clone()
                }
                Event::Continuation(chunk) => {
                    frontier.open = frontier.open.saturating_sub(chunk.bytes().len());
                    if let Some(streamed) = &mut query {
                        streamed.remaining = streamed.remaining.saturating_sub(chunk.bytes().len());
                        let text = chunk.bytes();
                        if streamed.remaining == 0 {
                            streamed.capture.feed(&text[..text.len().saturating_sub(1)]);
                            if let Some(done) = query.take() {
                                audit.simple_query(&done.capture.finish());
                            }
                        } else {
                            streamed.capture.feed(text);
                        }
                    }
                    chunk.into_bytes()
                }
            };
            audit.add_bytes(bytes.len());
            frontier.boundary = false;
            if writer.write_all(&bytes).await.is_err() {
                return Ending::ServerIo;
            }
            frontier.boundary = frontier.open == 0;
            if terminate {
                frontier.boundary = false;
                return match writer.flush().await {
                    Ok(()) => Ending::ClientTerminated,
                    Err(_) => Ending::ServerIo,
                };
            }
        }
        if writer.flush().await.is_err() {
            return Ending::ServerIo;
        }
        let read = match reader.read(&mut buffer).await {
            Ok(0) => return Ending::ClientClosed,
            Ok(read) => read,
            Err(_) => return Ending::ClientIo,
        };
        if let Err(error) = decoder.push(&buffer[..read]) {
            return Ending::Client(client_problem(&error));
        }
    }
}

async fn server_to_client<R, W>(
    reader: &mut R,
    writer: &mut W,
    decoder: &mut BackendDecoder,
    audit: &SessionAudit,
    frontier: &mut Frontier,
) -> Ending
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        loop {
            let event = match decoder.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(error) => return Ending::Server(server_problem(&error)),
            };
            let bytes: Bytes = match event {
                Event::Frame(frame) => {
                    match frame.message() {
                        BackendMessage::ErrorResponse(notice) => audit.error(notice),
                        BackendMessage::ReadyForQuery(_) => audit.ready(),
                        BackendMessage::ParameterStatus(status)
                            if !is_safe_parameter(&status.name) =>
                        {
                            continue;
                        }
                        BackendMessage::Authentication(_)
                        | BackendMessage::BackendKeyData(_)
                        | BackendMessage::NegotiateProtocolVersion(_) => {
                            return Ending::Server(ProtocolProblem::ServerUnexpected);
                        }
                        _ => {}
                    }
                    frontier.open = frame.remaining();
                    frame.raw().clone()
                }
                Event::Continuation(chunk) => {
                    frontier.open = frontier.open.saturating_sub(chunk.bytes().len());
                    chunk.into_bytes()
                }
            };
            audit.add_bytes(bytes.len());
            frontier.boundary = false;
            if writer.write_all(&bytes).await.is_err() {
                return Ending::ClientIo;
            }
            frontier.boundary = frontier.open == 0;
        }
        if writer.flush().await.is_err() {
            return Ending::ClientIo;
        }
        let read = match reader.read(&mut buffer).await {
            Ok(0) => return Ending::ServerClosed,
            Ok(read) => read,
            Err(_) => return Ending::ServerIo,
        };
        if let Err(error) = decoder.push(&buffer[..read]) {
            return Ending::Server(server_problem(&error));
        }
    }
}

pub struct Relay<C, U> {
    pub client: C,
    pub upstream: U,
    pub frontend: FrontendDecoder,
    pub backend: BackendDecoder,
}

pub struct RelayContext<'a> {
    pub audit: &'a SessionAudit,
    pub cancel: &'a CancellationToken,
    pub clock: &'a Arc<dyn Clock>,
    pub close_timeout: Duration,
    pub session_id: &'a str,
}

pub async fn relay<C, U>(relay: Relay<C, U>, context: RelayContext<'_>) -> ServiceOutcome
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let Relay {
        client,
        upstream,
        mut frontend,
        mut backend,
    } = relay;
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
    let mut to_server = Frontier::new();
    let mut to_client = Frontier::new();
    let ending = {
        let pumps = async {
            tokio::select! {
                ending = client_to_server(
                    &mut client_read,
                    &mut upstream_write,
                    &mut frontend,
                    context.audit,
                    &mut to_server,
                ) => ending,
                ending = server_to_client(
                    &mut upstream_read,
                    &mut client_write,
                    &mut backend,
                    context.audit,
                    &mut to_client,
                ) => ending,
            }
        };
        tokio::select! {
            biased;
            () = context.cancel.cancelled() => Ending::Cancelled,
            ending = pumps => ending,
        }
    };
    if let Ending::Client(problem) | Ending::Server(problem) = ending {
        context.audit.protocol_error(problem);
    }
    tracing::debug!(
        target: "jaunt::agent",
        session_id = context.session_id,
        ending = ending.as_str(),
        "the database session ended"
    );
    let terminate = ending.client_side() && to_server.boundary;
    let answer = (ending == Ending::Client(ProtocolProblem::ClientFunctionCall)
        && to_client.boundary)
        .then(|| error_response(FUNCTION_CALLS.0, FUNCTION_CALLS.1));
    let close = async {
        if terminate && upstream_write.write_all(&TERMINATE).await.is_ok() {
            drop(upstream_write.flush().await);
        }
        drop(upstream_write.shutdown().await);
        if let Some(answer) = answer
            && client_write.write_all(&answer).await.is_ok()
        {
            drop(client_write.flush().await);
        }
        drop(client_write.shutdown().await);
    };
    let close_by = deadline(context.clock, context.close_timeout);
    tokio::select! {
        () = close => {}
        () = context.clock.sleep_until(close_by) => {}
    }
    ending.outcome()
}
