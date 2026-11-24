use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use http::StatusCode;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::control::{
    AgentMessage, ControlChannel, ControlError, ServerMessage, agent_version_is_valid,
};
use crate::h2io::{H2Io, StreamSlot};
use crate::options::{OptionsError, TunnelOptions, keepalive};
use crate::proto::{CONTROL_VERSION, MetaError, StreamMeta, control_request};

const CONTROL_QUEUE_DEPTH: usize = 64;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId(u64);

impl ConnectionId {
    fn next() -> Self {
        Self(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TunnelError {
    #[error("http/2 handshake failed")]
    H2Handshake,
    #[error("http/2 handshake timed out")]
    HandshakeTimeout,
    #[error("control stream was refused")]
    ControlRefused,
    #[error("agent did not say hello in time")]
    HelloTimeout,
    #[error("agent hello is invalid")]
    InvalidHello,
    #[error("agent speaks an unsupported control version")]
    UnsupportedVersion,
    #[error("agent sent an unexpected control message")]
    UnexpectedMessage,
    #[error("control channel failed")]
    Control(#[from] ControlError),
    #[error("connection closed during setup")]
    Closed,
    #[error("internal error")]
    Internal,
    #[error("no tokio runtime is running")]
    NoRuntime,
    #[error("tunnel options are invalid")]
    InvalidOptions(#[from] OptionsError),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenError {
    #[error("agent is not connected")]
    NotConnected,
    #[error("stream metadata is invalid")]
    InvalidMetadata(#[from] MetaError),
    #[error("agent is at its stream limit")]
    AtCapacity,
    #[error("agent refused the stream with status {0}")]
    Refused(u16),
    #[error("connection to the agent is closed")]
    Closed,
    #[error("agent did not answer in time")]
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SendError {
    #[error("agent is not connected")]
    NotConnected,
    #[error("connection to the agent is closed")]
    Closed,
    #[error("control queue of the agent is full")]
    Backlogged,
}

#[derive(Clone)]
pub(crate) struct StreamOpener {
    slot: Arc<Mutex<Option<SendRequest<Bytes>>>>,
    active: Arc<AtomicUsize>,
    token: CancellationToken,
    open_timeout: Duration,
}

impl StreamOpener {
    pub(crate) async fn open(&self, meta: &StreamMeta) -> Result<H2Io, OpenError> {
        let mut sender = self
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or(OpenError::Closed)?;
        let request = meta.to_request()?;
        let user_limit = sender.current_max_send_streams().saturating_sub(1);
        let slot = StreamSlot::acquire(&self.active, user_limit).ok_or(OpenError::AtCapacity)?;
        match poll_fn(|cx| Poll::Ready(sender.poll_ready(cx))).await {
            Poll::Pending => return Err(OpenError::AtCapacity),
            Poll::Ready(Err(_)) => return Err(OpenError::Closed),
            Poll::Ready(Ok(())) => {}
        }
        let (response, send) = sender
            .send_request(request, false)
            .map_err(|_| OpenError::Closed)?;
        let response = timeout(self.open_timeout, response)
            .await
            .map_err(|_| OpenError::Timeout)?
            .map_err(|_| OpenError::Closed)?;
        let status = response.status();
        if status != StatusCode::OK {
            return Err(OpenError::Refused(status.as_u16()));
        }
        Ok(H2Io::new(response.into_body(), send)
            .with_slot(slot)
            .with_cancel(&self.token))
    }
}

pub struct TunnelConnection {
    id: ConnectionId,
    opener: StreamOpener,
    control: mpsc::Sender<ServerMessage>,
    closed: CancellationToken,
    _close_on_drop: DropGuard,
}

impl TunnelConnection {
    pub async fn establish<IO>(
        io: IO,
        options: &TunnelOptions,
        parent: &CancellationToken,
    ) -> Result<Self, TunnelError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Handle::try_current().map_err(|_| TunnelError::NoRuntime)?;
        options.validate()?;
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(options.stream_window)
            .initial_connection_window_size(options.connection_window)
            .max_header_list_size(options.max_header_list_size)
            .enable_push(false);
        let (sender, mut connection) =
            timeout(options.handshake_timeout, builder.handshake::<_, Bytes>(io))
                .await
                .map_err(|_| TunnelError::HandshakeTimeout)?
                .map_err(|_| TunnelError::H2Handshake)?;
        let pings = connection.ping_pong().ok_or(TunnelError::Internal)?;

        let closed = parent.child_token();
        let slot = Arc::new(Mutex::new(Some(sender.clone())));
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE_DEPTH);
        let (ready_tx, ready_rx) = oneshot::channel();
        let handle = Self {
            id: ConnectionId::next(),
            opener: StreamOpener {
                slot: slot.clone(),
                active: Arc::new(AtomicUsize::new(0)),
                token: closed.clone(),
                open_timeout: options.open_timeout,
            },
            control: control_tx,
            closed: closed.clone(),
            _close_on_drop: closed.clone().drop_guard(),
        };

        let keepalive_task: BoxTask = Box::pin(keepalive(pings, options.keepalive, closed.clone()));
        let control_task: BoxTask =
            Box::pin(run_control(sender, control_rx, ready_tx, options.clone()));
        runtime.spawn(supervise(
            connection,
            keepalive_task,
            control_task,
            slot,
            closed,
            options.close_grace,
        ));

        ready_rx.await.map_err(|_| TunnelError::Closed)??;
        Ok(handle)
    }

    pub fn id(&self) -> ConnectionId {
        self.id
    }

    pub fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub(crate) fn closed_token(&self) -> CancellationToken {
        self.closed.clone()
    }

    pub(crate) fn opener(&self) -> StreamOpener {
        self.opener.clone()
    }

    pub(crate) fn queue_control(&self, message: ServerMessage) -> Result<(), SendError> {
        use mpsc::error::TrySendError;
        self.control.try_send(message).map_err(|error| match error {
            TrySendError::Full(_) => SendError::Backlogged,
            TrySendError::Closed(_) => SendError::Closed,
        })
    }
}

enum End {
    Cancelled,
    PeerClosed,
    KeepaliveFailed,
    ControlEnded,
}

type BoxTask = Pin<Box<dyn Future<Output = ()> + Send>>;

async fn supervise<IO>(
    mut connection: h2::client::Connection<IO, Bytes>,
    mut keepalive_task: BoxTask,
    mut control_task: BoxTask,
    slot: Arc<Mutex<Option<SendRequest<Bytes>>>>,
    token: CancellationToken,
    close_grace: Duration,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let end = tokio::select! {
        biased;
        () = token.cancelled() => End::Cancelled,
        _ = &mut connection => End::PeerClosed,
        () = keepalive_task.as_mut() => End::KeepaliveFailed,
        () = control_task.as_mut() => End::ControlEnded,
    };
    token.cancel();
    slot.lock().unwrap_or_else(PoisonError::into_inner).take();
    drop(control_task);
    drop(keepalive_task);
    if !matches!(end, End::PeerClosed) {
        drop(timeout(close_grace, &mut connection).await);
    }
}

async fn run_control(
    sender: SendRequest<Bytes>,
    outbound: mpsc::Receiver<ServerMessage>,
    ready: oneshot::Sender<Result<(), TunnelError>>,
    options: TunnelOptions,
) {
    let mut ready = Some(ready);
    if let Err(error) = control_session(sender, outbound, &mut ready, &options).await
        && let Some(ready) = ready.take()
    {
        drop(ready.send(Err(error)));
    }
}

async fn control_session(
    sender: SendRequest<Bytes>,
    mut outbound: mpsc::Receiver<ServerMessage>,
    ready: &mut Option<oneshot::Sender<Result<(), TunnelError>>>,
    options: &TunnelOptions,
) -> Result<(), TunnelError> {
    let (mut channel, hello) = timeout(options.hello_timeout, async {
        let io = open_control(sender).await?;
        let mut channel = ControlChannel::new(io);
        let hello = channel.recv::<AgentMessage>().await?;
        Ok::<_, TunnelError>((channel, hello))
    })
    .await
    .map_err(|_| TunnelError::HelloTimeout)??;

    match hello {
        Some(AgentMessage::Hello {
            version,
            agent_version,
        }) => {
            if version != CONTROL_VERSION {
                return Err(TunnelError::UnsupportedVersion);
            }
            if !agent_version_is_valid(&agent_version) {
                return Err(TunnelError::InvalidHello);
            }
        }
        None => return Err(TunnelError::Closed),
    }
    channel.send(&ServerMessage::Welcome {}).await?;
    if let Some(ready) = ready.take() {
        drop(ready.send(Ok(())));
    }

    loop {
        tokio::select! {
            incoming = channel.recv::<AgentMessage>() => match incoming? {
                Some(_) => return Err(TunnelError::UnexpectedMessage),
                None => return Ok(()),
            },
            outgoing = outbound.recv() => match outgoing {
                Some(message) => channel.send(&message).await?,
                None => return Ok(()),
            },
        }
    }
}

async fn open_control(sender: SendRequest<Bytes>) -> Result<H2Io, TunnelError> {
    let request = control_request().map_err(|_| TunnelError::Internal)?;
    let mut sender = sender
        .ready()
        .await
        .map_err(|_| TunnelError::ControlRefused)?;
    let (response, send) = sender
        .send_request(request, false)
        .map_err(|_| TunnelError::ControlRefused)?;
    let response = response.await.map_err(|_| TunnelError::ControlRefused)?;
    if response.status() != StatusCode::OK {
        return Err(TunnelError::ControlRefused);
    }
    Ok(H2Io::new(response.into_body(), send))
}
