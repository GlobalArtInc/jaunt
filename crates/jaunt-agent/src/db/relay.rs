use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use jaunt_pgwire::{
    BackendDecoder, BackendMessage, DecodeError, Event, FrontendDecoder, FrontendMessage, Target,
    TargetKind,
};
use jaunt_proto::ServiceOutcome;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use super::audit::{ProtocolProblem, QueryCapture, SessionAudit, cut};
use super::upstream::{
    CLIENT_ENCODING, STANDARD_CONFORMING_STRINGS, deadline, is_safe_parameter, is_utf8,
    server_problem,
};
use super::wire::{ENCODING_REFUSED, FUNCTION_CALLS, TERMINATE, error_response};
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

const MAX_SECRET_NAMES: usize = 1024;
const NAME_KEY_BYTES: usize = 63;
pub const MAX_NAME_BYTES: usize = 64 * 1024;

fn key(name: &str) -> &str {
    cut(name, NAME_KEY_BYTES)
}

fn oversized(names: &[&str]) -> bool {
    names.iter().any(|name| name.len() > MAX_NAME_BYTES)
}

#[derive(Default)]
struct SecretNames {
    statements: HashSet<String>,
    portals: HashSet<String>,
    saturated: bool,
}

impl SecretNames {
    fn remember(names: &mut HashSet<String>, saturated: &mut bool, name: &str) {
        let key = key(name);
        if names.len() >= MAX_SECRET_NAMES && !names.contains(key) {
            *saturated = true;
        } else {
            names.insert(key.to_owned());
        }
    }

    fn parsed(&mut self, statement: &str, sensitive: bool) {
        if sensitive {
            Self::remember(&mut self.statements, &mut self.saturated, statement);
        } else {
            self.statements.remove(key(statement));
        }
    }

    fn bound(&mut self, portal: &str, statement: &str) -> bool {
        let sensitive = self.saturated || self.statements.contains(key(statement));
        if sensitive {
            Self::remember(&mut self.portals, &mut self.saturated, portal);
        } else {
            self.portals.remove(key(portal));
        }
        sensitive
    }

    fn executes(&self, portal: &str) -> bool {
        self.saturated || self.portals.contains(key(portal))
    }

    fn describes(&self, target: &Target) -> bool {
        self.saturated
            || match target.kind {
                TargetKind::Statement => self.statements.contains(key(&target.name)),
                TargetKind::Portal => self.portals.contains(key(&target.name)),
            }
    }

    fn closed(&mut self, target: &Target) {
        match target.kind {
            TargetKind::Statement => self.statements.remove(key(&target.name)),
            TargetKind::Portal => self.portals.remove(key(&target.name)),
        };
        if self.statements.is_empty() && self.portals.is_empty() {
            self.saturated = false;
        }
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
    let mut secrets = SecretNames::default();
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
                                capture: QueryCapture::new(audit.backslash_escapes()),
                            });
                        }
                        FrontendMessage::Query(statement) => {
                            let captured =
                                QueryCapture::of(statement.as_bytes(), audit.backslash_escapes())
                                    .finish();
                            if captured.is_malformed() {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            audit.simple_query(&captured);
                        }
                        FrontendMessage::Parse(parse) => {
                            if oversized(&[&parse.name]) {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            let captured = QueryCapture::of(
                                parse.statement.as_bytes(),
                                audit.backslash_escapes(),
                            )
                            .finish();
                            if captured.is_malformed() {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            secrets.parsed(&parse.name, captured.is_sensitive());
                            audit.extended_query(&captured);
                        }
                        FrontendMessage::Bind(bind) => {
                            if oversized(&[&bind.portal, &bind.statement]) {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            if secrets.bound(&bind.portal, &bind.statement) {
                                audit.sensitive_cycle();
                            }
                        }
                        FrontendMessage::Execute(execute) => {
                            if oversized(&[&execute.portal]) {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            if secrets.executes(&execute.portal) {
                                audit.sensitive_cycle();
                            }
                        }
                        FrontendMessage::Describe(target) => {
                            if oversized(&[&target.name]) {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            if secrets.describes(target) {
                                audit.sensitive_cycle();
                            }
                        }
                        FrontendMessage::Close(target) => {
                            if oversized(&[&target.name]) {
                                return Ending::Client(ProtocolProblem::ClientMalformed);
                            }
                            secrets.closed(target);
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
                        FrontendMessage::Flush
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
                        } else {
                            streamed.capture.feed(text);
                        }
                        if streamed.capture.is_malformed() {
                            return Ending::Client(ProtocolProblem::ClientMalformed);
                        }
                        if streamed.remaining == 0
                            && let Some(done) = query.take()
                        {
                            audit.simple_query(&done.capture.finish());
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
                            if status.name == STANDARD_CONFORMING_STRINGS =>
                        {
                            audit.set_backslash_escapes(status.value.eq_ignore_ascii_case("off"));
                        }
                        BackendMessage::ParameterStatus(status)
                            if status.name == CLIENT_ENCODING && !is_utf8(&status.value) =>
                        {
                            return Ending::Client(ProtocolProblem::ClientEncoding);
                        }
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
    pub cancel_close_timeout: Duration,
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
    let answer = match ending {
        Ending::Client(ProtocolProblem::ClientFunctionCall) => Some(FUNCTION_CALLS),
        Ending::Client(ProtocolProblem::ClientEncoding) => Some(ENCODING_REFUSED),
        _ => None,
    }
    .filter(|_| to_client.boundary)
    .map(|(code, message)| error_response(code, message));
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
    let bound = if ending == Ending::Cancelled {
        context.cancel_close_timeout
    } else {
        context.close_timeout
    };
    let close_by = deadline(context.clock, bound);
    tokio::select! {
        () = close => {}
        () = context.clock.sleep_until(close_by) => {}
    }
    ending.outcome()
}

#[cfg(test)]
mod tests {
    use jaunt_pgwire::{Target, TargetKind};

    use super::SecretNames;

    fn statement(name: &str) -> Target {
        Target {
            kind: TargetKind::Statement,
            name: name.to_owned(),
        }
    }

    fn portal(name: &str) -> Target {
        Target {
            kind: TargetKind::Portal,
            name: name.to_owned(),
        }
    }

    #[test]
    fn at_most_1024_names_are_remembered_and_then_every_use_counts_until_all_are_closed() {
        let mut names = SecretNames::default();
        for index in 0..1024 {
            names.parsed(&format!("s{index}"), true);
        }
        assert!(!names.saturated);
        assert!(names.bound("p", "s1023"));
        assert!(!names.bound("q", "plain"));
        names.parsed("s1024", true);
        assert!(names.saturated);
        assert!(names.bound("q", "plain"));
        assert!(names.executes("anything"));
        for index in 0..1024 {
            names.closed(&statement(&format!("s{index}")));
        }
        names.closed(&portal("p"));
        assert!(names.saturated);
        names.closed(&portal("q"));
        assert!(!names.saturated);
        assert!(!names.executes("anything"));
        assert!(!names.describes(&statement("s1")));
    }

    #[test]
    fn names_are_known_by_their_first_63_bytes() {
        let mut names = SecretNames::default();
        let ascii = "a".repeat(63);
        names.parsed(&format!("{ascii}x"), true);
        assert!(names.bound("", &format!("{ascii}y")));
        assert!(names.describes(&statement(&format!("{ascii}z"))));
        let prefix = "b".repeat(62);
        names.parsed(&format!("{prefix}\u{e9}"), true);
        assert!(names.bound("", &format!("{prefix}\u{436}")));
        assert!(!names.bound("", &"c".repeat(63)));
    }
}
