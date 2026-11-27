use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use jaunt_proto::{DbAccessRequest, ServiceAccess, ServiceOutcome};
use jaunt_tunnel::{BoxFuture, ServiceName, StreamKind};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;

use super::x509::VerifiedUser;

pub trait ServiceIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> ServiceIo for T {}

pub type Transport = Box<dyn ServiceIo>;
pub type ServiceStream = Counted<TlsStream<Transport>>;

#[derive(Debug, Default)]
pub struct ByteCounts {
    read: AtomicU64,
    written: AtomicU64,
}

impl ByteCounts {
    pub fn read(&self) -> u64 {
        self.read.load(Ordering::Acquire)
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Acquire)
    }

    fn add(counter: &AtomicU64, len: usize) {
        counter.fetch_add(u64::try_from(len).unwrap_or(u64::MAX), Ordering::AcqRel);
    }
}

pub struct Counted<S> {
    inner: S,
    counts: Arc<ByteCounts>,
}

impl<S> Counted<S> {
    pub fn new(inner: S, counts: Arc<ByteCounts>) -> Self {
        Self { inner, counts }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            ByteCounts::add(&self.counts.read, buf.filled().len().saturating_sub(before));
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            ByteCounts::add(&self.counts.written, written);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct ServiceConnection {
    #[cfg_attr(not(test), expect(dead_code))]
    pub stream: ServiceStream,
    pub alpn: Option<Vec<u8>>,
    pub user: VerifiedUser,
    pub client_addr: String,
}

impl fmt::Debug for ServiceConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceConnection")
            .field("alpn", &self.alpn)
            .field("user", &self.user)
            .field("client_addr", &self.client_addr)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGrant {
    pub access: ServiceAccess,
    pub max_duration: Duration,
    pub target: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(not(test), expect(dead_code))]
pub struct ServiceSession {
    pub session_id: String,
    pub service: ServiceName,
    pub cancel: CancellationToken,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prepared {
    pub db: Option<DbAccessRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the service handler failed")]
pub struct HandlerError;

pub trait ServiceHandler: Send + Sync {
    fn prepare<'a>(
        &'a self,
        _connection: &'a mut ServiceConnection,
    ) -> BoxFuture<'a, Result<Prepared, HandlerError>> {
        Box::pin(async { Ok(Prepared::default()) })
    }

    fn serve(
        &self,
        connection: ServiceConnection,
        grant: ServiceGrant,
        session: ServiceSession,
    ) -> BoxFuture<'static, Result<ServiceOutcome, HandlerError>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("SSH streams are served by the SSH terminator, not by a service handler")]
#[cfg_attr(not(test), expect(dead_code))]
pub struct NotAServiceKind;

#[derive(Clone, Default)]
pub struct HandlerRegistry {
    kube: Option<Arc<dyn ServiceHandler>>,
    db: Option<Arc<dyn ServiceHandler>>,
    tcp: Option<Arc<dyn ServiceHandler>>,
}

impl fmt::Debug for HandlerRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandlerRegistry")
            .field("kube", &self.kube.is_some())
            .field("db", &self.db.is_some())
            .field("tcp", &self.tcp.is_some())
            .finish()
    }
}

impl HandlerRegistry {
    #[cfg_attr(not(test), expect(dead_code))]
    pub fn register(
        &mut self,
        kind: StreamKind,
        handler: Arc<dyn ServiceHandler>,
    ) -> Result<(), NotAServiceKind> {
        let slot = match kind {
            StreamKind::Kube => &mut self.kube,
            StreamKind::Db => &mut self.db,
            StreamKind::Tcp => &mut self.tcp,
            StreamKind::Ssh => return Err(NotAServiceKind),
        };
        *slot = Some(handler);
        Ok(())
    }

    pub fn get(&self, kind: StreamKind) -> Option<&Arc<dyn ServiceHandler>> {
        match kind {
            StreamKind::Kube => self.kube.as_ref(),
            StreamKind::Db => self.db.as_ref(),
            StreamKind::Tcp => self.tcp.as_ref(),
            StreamKind::Ssh => None,
        }
    }
}
