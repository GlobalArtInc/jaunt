use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::AddExtension;
use axum::response::Response;
use axum::{Extension, Router};
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use jaunt_control::AuthenticatedNode;
use jaunt_gate::AgentApiHandler;
use jaunt_tunnel::{BoxFuture, GateTlsStream, NodeId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tokio_util::sync::CancellationToken;
use tower::{Layer, ServiceExt};

const MAX_CONCURRENT_STREAMS: u32 = 32;
const MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
const CLIENT_PREFACE_LEN: u64 = 24;
const REQUEST_TIMED_OUT: &str = r#"{"error":"request_timeout"}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiLimits {
    pub preface_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub request_timeout: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub close_grace: Duration,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            preface_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            max_lifetime: Duration::from_secs(60 * 60),
            request_timeout: Duration::from_secs(30),
            keepalive_interval: Duration::from_secs(20),
            keepalive_timeout: Duration::from_secs(10),
            close_grace: Duration::from_secs(5),
        }
    }
}

pub(crate) struct AgentApi {
    router: Router,
    limits: ApiLimits,
}

impl AgentApi {
    pub(crate) fn new(router: Router, limits: ApiLimits) -> Self {
        Self { router, limits }
    }
}

impl AgentApiHandler for AgentApi {
    fn serve(
        &self,
        node: NodeId,
        stream: GateTlsStream,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        let service =
            Extension(AuthenticatedNode(node.as_str().to_owned())).layer(self.router.clone());
        Box::pin(serve_connection(stream, service, self.limits, shutdown))
    }
}

struct Activity {
    received: AtomicU64,
    in_flight: AtomicUsize,
    last: Mutex<Instant>,
}

impl Activity {
    fn new() -> Self {
        Self {
            received: AtomicU64::new(0),
            in_flight: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
        }
    }

    fn last(&self) -> Instant {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn touch(&self) {
        *self.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn begin(self: &Arc<Self>) -> Busy {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        self.touch();
        Busy(self.clone())
    }

    async fn preface_missed(&self, limit: Duration) {
        sleep(limit).await;
        if self.received.load(Ordering::SeqCst) >= CLIENT_PREFACE_LEN {
            std::future::pending::<()>().await;
        }
    }

    async fn idle_for(&self, limit: Duration) {
        loop {
            let deadline = if self.in_flight.load(Ordering::SeqCst) > 0 {
                Instant::now() + limit
            } else {
                self.last() + limit
            };
            sleep_until(deadline).await;
            if self.in_flight.load(Ordering::SeqCst) == 0 && self.last().elapsed() >= limit {
                return;
            }
        }
    }
}

struct Busy(Arc<Activity>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.0.touch();
    }
}

struct Watched<IO> {
    inner: IO,
    activity: Arc<Activity>,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Watched<IO> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let received = buf.filled().len().saturating_sub(before);
        if received > 0 {
            self.activity.received.fetch_add(
                u64::try_from(received).unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Watched<IO> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

enum Ending {
    Shutdown,
    Idle,
    Lifetime,
}

async fn serve_connection(
    stream: GateTlsStream,
    service: AddExtension<Router, AuthenticatedNode>,
    limits: ApiLimits,
    shutdown: CancellationToken,
) {
    let activity = Arc::new(Activity::new());
    let io = TokioIo::new(Watched {
        inner: stream,
        activity: activity.clone(),
    });
    let tracked = activity.clone();
    let request_timeout = limits.request_timeout;
    let handler = service_fn(move |request: Request<Incoming>| {
        let busy = tracked.begin();
        let call = timeout(request_timeout, service.clone().oneshot(request));
        async move {
            let response = match call.await {
                Ok(answered) => answered,
                Err(_) => Ok(request_timed_out()),
            };
            drop(busy);
            response
        }
    });
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .max_header_list_size(MAX_HEADER_LIST_SIZE)
        .keep_alive_interval(limits.keepalive_interval)
        .keep_alive_timeout(limits.keepalive_timeout);
    let connection = builder.serve_connection(io, handler);
    tokio::pin!(connection);
    let ending = tokio::select! {
        served = connection.as_mut() => {
            report(served);
            return;
        }
        () = shutdown.cancelled() => Ending::Shutdown,
        () = activity.idle_for(limits.idle_timeout) => Ending::Idle,
        () = sleep(limits.max_lifetime) => Ending::Lifetime,
        () = activity.preface_missed(limits.preface_timeout) => {
            tracing::debug!(
                target: "jaunt::agents",
                "an agent api connection sent no http/2 preface in time"
            );
            return;
        }
    };
    match ending {
        Ending::Shutdown => {}
        Ending::Idle => {
            tracing::debug!(target: "jaunt::agents", "an idle agent api connection is being closed");
        }
        Ending::Lifetime => {
            tracing::debug!(
                target: "jaunt::agents",
                "an agent api connection reached its maximum lifetime"
            );
        }
    }
    connection.as_mut().graceful_shutdown();
    match timeout(limits.close_grace, connection).await {
        Ok(served) => report(served),
        Err(_) => tracing::debug!(
            target: "jaunt::agents",
            "an agent api connection did not close in time after goaway"
        ),
    }
}

fn request_timed_out() -> Response {
    tracing::debug!(target: "jaunt::agents", "an agent api request timed out");
    let mut response = Response::new(Body::from(REQUEST_TIMED_OUT));
    *response.status_mut() = StatusCode::REQUEST_TIMEOUT;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

fn report(served: Result<(), hyper::Error>) {
    if let Err(error) = served {
        tracing::debug!(
            target: "jaunt::agents",
            error = %error,
            "an agent api connection ended with an error"
        );
    }
}
