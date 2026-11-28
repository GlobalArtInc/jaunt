use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use jaunt_tunnel::BoxFuture;
use tokio::sync::Notify;
use tokio_util::sync::{CancellationToken, DropGuard, WaitForCancellationFutureOwned};

use super::lease::Lease;
use super::upstream::Slot;
use crate::clock::Clock;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyError {
    #[error("the body from the Kubernetes API server failed: {0}")]
    Api(#[source] hyper::Error),
    #[error("the body from the client failed: {0}")]
    Client(#[source] hyper::Error),
    #[error("the stream made no progress for too long and was reset")]
    Stalled,
}

pub(crate) struct Held {
    _lease: Lease,
    _slot: Slot,
}

impl Held {
    pub(crate) fn new(lease: Lease, slot: Slot) -> Self {
        Self {
            _lease: lease,
            _slot: slot,
        }
    }
}

pub(crate) struct RequestBody {
    inner: Incoming,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    idle: Option<BoxFuture<'static, ()>>,
}

impl RequestBody {
    pub(crate) fn new(inner: Incoming, clock: Arc<dyn Clock>, timeout: Duration) -> Self {
        Self {
            inner,
            clock,
            timeout,
            idle: None,
        }
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        let this = self.get_mut();
        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    this.idle = None;
                    if let Ok(data) = frame.into_data() {
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    return Poll::Ready(Some(Err(BodyError::Client(error))));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    let idle = this.idle.get_or_insert_with(|| {
                        let clock = Arc::clone(&this.clock);
                        let now = clock.now();
                        let deadline = now.checked_add(this.timeout).unwrap_or(now);
                        Box::pin(async move { clock.sleep_until(deadline).await })
                    });
                    if idle.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Some(Err(BodyError::Stalled)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

struct Watched {
    clock: Arc<dyn Clock>,
    state: Mutex<WatchedState>,
    armed: Notify,
}

struct WatchedState {
    inner: Option<Incoming>,
    held: Option<Held>,
    owing_since: Option<SystemTime>,
    watchdog_idle: bool,
    stalled: bool,
}

impl Watched {
    fn state(&self) -> MutexGuard<'_, WatchedState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub(crate) enum ProxyBody {
    Fixed(Option<Bytes>),
    Upstream(UpstreamBody),
}

pub(crate) struct UpstreamBody {
    watched: Arc<Watched>,
    stop: Pin<Box<WaitForCancellationFutureOwned>>,
    _done: DropGuard,
}

impl Drop for UpstreamBody {
    fn drop(&mut self) {
        let mut state = self.watched.state();
        state.inner = None;
        state.held = None;
    }
}

impl ProxyBody {
    pub(crate) fn fixed(bytes: impl Into<Bytes>) -> Self {
        Self::Fixed(Some(bytes.into()))
    }

    pub(crate) fn upstream(
        inner: Incoming,
        held: Held,
        stopping: CancellationToken,
        clock: Arc<dyn Clock>,
        timeout: Duration,
    ) -> Self {
        let watched = Arc::new(Watched {
            clock,
            state: Mutex::new(WatchedState {
                inner: Some(inner),
                held: Some(held),
                owing_since: None,
                watchdog_idle: false,
                stalled: false,
            }),
            armed: Notify::new(),
        });
        let done = CancellationToken::new();
        tokio::spawn(watchdog(Arc::clone(&watched), timeout, done.clone()));
        Self::Upstream(UpstreamBody {
            watched,
            stop: Box::pin(stopping.cancelled_owned()),
            _done: done.drop_guard(),
        })
    }
}

async fn watchdog(watched: Arc<Watched>, timeout: Duration, done: CancellationToken) {
    loop {
        let owing = {
            let mut state = watched.state();
            if state.inner.is_none() {
                return;
            }
            state.watchdog_idle = state.owing_since.is_none();
            state.owing_since
        };
        let Some(since) = owing else {
            tokio::select! {
                () = done.cancelled() => return,
                () = watched.armed.notified() => continue,
            }
        };
        let deadline = since.checked_add(timeout).unwrap_or(since);
        tokio::select! {
            () = done.cancelled() => return,
            () = watched.clock.sleep_until(deadline) => {}
        }
        let mut state = watched.state();
        if state.owing_since == Some(since) && state.inner.is_some() {
            state.inner = None;
            state.held = None;
            state.stalled = true;
            drop(state);
            tracing::debug!(
                target: "jaunt::agent",
                "a client accepted no data of a Kubernetes response for too long; its stream to the API server was reset"
            );
            return;
        }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        match self.get_mut() {
            Self::Fixed(bytes) => Poll::Ready(bytes.take().map(|bytes| Ok(Frame::data(bytes)))),
            Self::Upstream(body) => {
                if body.stop.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                let watched = &body.watched;
                let mut state = watched.state();
                state.owing_since = None;
                let Some(inner) = state.inner.as_mut() else {
                    return Poll::Ready(state.stalled.then_some(Err(BodyError::Stalled)));
                };
                match Pin::new(inner).poll_frame(cx) {
                    Poll::Ready(Some(Ok(frame))) => {
                        state.owing_since = Some(watched.clock.now());
                        if state.watchdog_idle {
                            state.watchdog_idle = false;
                            watched.armed.notify_one();
                        }
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Ready(Some(Err(error))) => {
                        state.inner = None;
                        state.held = None;
                        Poll::Ready(Some(Err(BodyError::Api(error))))
                    }
                    Poll::Ready(None) => {
                        state.inner = None;
                        state.held = None;
                        Poll::Ready(None)
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Fixed(bytes) => bytes.is_none(),
            Self::Upstream(body) => {
                let state = body.watched.state();
                !state.stalled && state.inner.as_ref().is_none_or(Incoming::is_end_stream)
            }
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Fixed(bytes) => SizeHint::with_exact(
                bytes
                    .as_ref()
                    .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            ),
            Self::Upstream(body) => {
                let state = body.watched.state();
                match state.inner.as_ref() {
                    Some(inner) => inner.size_hint(),
                    None if state.stalled => SizeHint::default(),
                    None => SizeHint::with_exact(0),
                }
            }
        }
    }
}
