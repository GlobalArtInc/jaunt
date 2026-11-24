use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use russh::ChannelWriteHalf;
use russh::server::{ChannelOpenHandle, Msg};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::io::PanicSafe;
use super::{
    Connection, OuterEvent, ROUTE_TIMEOUT, RouteRefusal, RouteTarget, RoutedStream, StreamEnd,
    TunnelStream,
};
use crate::cert::UserIdentity;
use crate::intake::{IntakeEvent, IntakeReader};

const READ_CHUNK: usize = 64 * 1024;

type Tunnel = PanicSafe<Box<dyn TunnelStream>>;

#[derive(Default)]
pub(super) struct Cause(OnceLock<StreamEnd>);

impl Cause {
    pub(super) fn set(&self, end: StreamEnd) {
        self.0.get_or_init(|| end);
    }

    fn get(&self) -> Option<StreamEnd> {
        self.0.get().copied()
    }

    fn needs_close(&self) -> bool {
        matches!(self.get(), Some(StreamEnd::Stall | StreamEnd::TunnelGone))
    }
}

#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
}

impl Counters {
    fn add(counter: &AtomicU64, bytes: usize) {
        counter.fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

struct ForwardGuard {
    connection: Arc<Connection>,
    identity: UserIdentity,
    node: String,
    session_id: String,
    cause: Arc<Cause>,
    counters: Counters,
    opened: Instant,
}

impl Drop for ForwardGuard {
    fn drop(&mut self) {
        let hop = &self.connection.hop;
        let reason = self
            .cause
            .get()
            .or_else(|| self.connection.end.get().copied())
            .unwrap_or(StreamEnd::ClientGone);
        drop(catch_unwind(AssertUnwindSafe(|| {
            hop.backend.released(&self.identity, &self.node);
        })));
        let event = OuterEvent::ForwardClosed {
            node: self.node.clone(),
            session_id: self.session_id.clone(),
            bytes_up: self.counters.up.load(Ordering::Relaxed),
            bytes_down: self.counters.down.load(Ordering::Relaxed),
            duration: self.opened.elapsed(),
            reason,
        };
        drop(catch_unwind(AssertUnwindSafe(|| hop.emit(event))));
    }
}

pub(super) struct Opening {
    pub(super) connection: Arc<Connection>,
    pub(super) target: RouteTarget,
    pub(super) reply: ChannelOpenHandle,
    pub(super) reader: IntakeReader,
    pub(super) output: ChannelWriteHalf<Msg>,
    pub(super) token: CancellationToken,
    pub(super) cause: Arc<Cause>,
}

pub(super) async fn open(opening: Opening) {
    let Opening {
        connection,
        target,
        reply,
        reader,
        output,
        token,
        cause,
    } = opening;
    let _slot = token.clone().drop_guard();
    let identity = target.identity.clone();
    let node = target.node.clone();
    let routed = tokio::select! {
        biased;
        () = token.cancelled() => Err(RouteRefusal::Unavailable),
        routed = tokio::time::timeout(ROUTE_TIMEOUT, connection.hop.backend.route(target)) => {
            routed.unwrap_or(Err(RouteRefusal::Unavailable))
        }
    };
    let RoutedStream { session_id, stream } = match routed {
        Ok(routed) => routed,
        Err(refusal) => {
            token.cancel();
            connection
                .hop
                .refuse(reply, Some(node), refusal.into())
                .await;
            return;
        }
    };
    let guard = ForwardGuard {
        connection: Arc::clone(&connection),
        identity,
        node: node.clone(),
        session_id: session_id.clone(),
        cause,
        counters: Counters::default(),
        opened: Instant::now(),
    };
    reply.accept().await;
    let opened = OuterEvent::ForwardOpened { node, session_id };
    drop(catch_unwind(AssertUnwindSafe(|| {
        connection.hop.emit(opened)
    })));
    run(Forward {
        reader,
        output,
        stream,
        token,
        connection: connection.token.clone(),
        stall: connection.hop.limits.write_stall_timeout,
        guard,
    })
    .await;
}

struct Forward {
    reader: IntakeReader,
    output: ChannelWriteHalf<Msg>,
    stream: Box<dyn TunnelStream>,
    token: CancellationToken,
    connection: CancellationToken,
    stall: Option<Duration>,
    guard: ForwardGuard,
}

async fn run(forward: Forward) {
    let Forward {
        reader,
        output,
        stream,
        token,
        connection,
        stall,
        guard,
    } = forward;
    let writes = WriteClock::default();
    let (tunnel_read, tunnel_write) = tokio::io::split(PanicSafe::new(stream));
    let pumps = async {
        let ((), closed) = tokio::join!(
            pump_up(reader, tunnel_write, &token, &guard),
            pump_down(tunnel_read, &output, &token, &guard, &writes),
        );
        token.cancel();
        closed
    };
    let (closed, ()) = tokio::join!(pumps, watch_stall(&writes, stall, &token, &guard.cause));
    let close = !closed && guard.cause.needs_close();
    drop(guard);
    if close {
        tokio::select! {
            biased;
            () = connection.cancelled() => {}
            _ = output.close() => {}
        }
    }
}

async fn pump_up(
    mut reader: IntakeReader,
    mut tunnel: WriteHalf<Tunnel>,
    token: &CancellationToken,
    guard: &ForwardGuard,
) {
    loop {
        let event = tokio::select! {
            biased;
            () = token.cancelled() => return,
            event = reader.next() => event,
        };
        match event {
            Some(IntakeEvent::Data(bytes)) => {
                let written = tokio::select! {
                    biased;
                    () = token.cancelled() => return,
                    written = tunnel.write_all(&bytes) => written,
                };
                if written.is_err() {
                    guard.cause.set(StreamEnd::TunnelGone);
                    token.cancel();
                    return;
                }
                Counters::add(&guard.counters.up, bytes.len());
                if reader.consumed(bytes.len()).is_err() {
                    token.cancel();
                    return;
                }
            }
            Some(IntakeEvent::Eof) => {
                let shut = tokio::select! {
                    biased;
                    () = token.cancelled() => return,
                    shut = tunnel.shutdown() => shut,
                };
                if shut.is_err() {
                    guard.cause.set(StreamEnd::TunnelGone);
                    token.cancel();
                }
                return;
            }
            Some(IntakeEvent::Close) | None => {
                token.cancel();
                return;
            }
        }
    }
}

async fn pump_down(
    mut tunnel: ReadHalf<Tunnel>,
    output: &ChannelWriteHalf<Msg>,
    token: &CancellationToken,
    guard: &ForwardGuard,
    writes: &WriteClock,
) -> bool {
    let mut buffer = vec![0; READ_CHUNK];
    loop {
        let read = tokio::select! {
            biased;
            () = token.cancelled() => return false,
            read = tunnel.read(&mut buffer) => read,
        };
        let len = match read {
            Ok(0) => {
                guard.cause.set(StreamEnd::Eof);
                return close_channel(output, token, true).await;
            }
            Ok(len) => len,
            Err(_) => {
                guard.cause.set(StreamEnd::TunnelGone);
                return close_channel(output, token, false).await;
            }
        };
        let chunk = Bytes::copy_from_slice(&buffer[..len]);
        writes.begin();
        let written = tokio::select! {
            biased;
            () = token.cancelled() => None,
            written = output.data_bytes(chunk) => Some(written),
        };
        writes.end();
        match written {
            Some(Ok(())) => Counters::add(&guard.counters.down, len),
            Some(Err(_)) => {
                token.cancel();
                return false;
            }
            None => return false,
        }
    }
}

async fn close_channel(
    output: &ChannelWriteHalf<Msg>,
    token: &CancellationToken,
    eof: bool,
) -> bool {
    let closed = tokio::select! {
        biased;
        () = token.cancelled() => false,
        closed = send_close(output, eof) => closed,
    };
    token.cancel();
    closed
}

async fn send_close(output: &ChannelWriteHalf<Msg>, eof: bool) -> bool {
    if eof && output.eof().await.is_err() {
        return false;
    }
    output.close().await.is_ok()
}

async fn watch_stall(
    writes: &WriteClock,
    limit: Option<Duration>,
    token: &CancellationToken,
    cause: &Cause,
) {
    let Some(limit) = limit.filter(|limit| !limit.is_zero()) else {
        return;
    };
    tokio::select! {
        biased;
        () = token.cancelled() => {}
        () = writes.stalled(limit) => {
            cause.set(StreamEnd::Stall);
            token.cancel();
        }
    }
}

#[derive(Default)]
struct WriteClock(Mutex<Option<Instant>>);

impl WriteClock {
    fn lock(&self) -> MutexGuard<'_, Option<Instant>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn begin(&self) {
        *self.lock() = Some(Instant::now());
    }

    fn end(&self) {
        *self.lock() = None;
    }

    fn pending_since(&self) -> Option<Instant> {
        *self.lock()
    }

    async fn stalled(&self, limit: Duration) {
        loop {
            let since = self.pending_since().unwrap_or_else(Instant::now);
            let Some(check) = since.checked_add(limit) else {
                return std::future::pending().await;
            };
            tokio::time::sleep_until(check).await;
            if self
                .pending_since()
                .is_some_and(|start| start.elapsed() >= limit)
            {
                return;
            }
        }
    }
}
