use std::future::Future;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use super::DISCONNECT_GRACE;

type CutWait = Pin<Box<WaitForCancellationFutureOwned>>;

pub(super) struct Severable<S> {
    inner: S,
    read_cut: CutWait,
    write_cut: CutWait,
    linger: Option<Pin<Box<Sleep>>>,
}

impl<S> Severable<S> {
    pub(super) fn new(inner: S, token: &CancellationToken) -> Self {
        Self {
            inner,
            read_cut: Box::pin(token.clone().cancelled_owned()),
            write_cut: Box::pin(token.clone().cancelled_owned()),
            linger: None,
        }
    }

    fn lingered(&mut self, cx: &mut Context<'_>) -> bool {
        self.linger
            .as_mut()
            .is_some_and(|linger| linger.as_mut().poll(cx).is_ready())
    }

    fn read_cut(&mut self, cx: &mut Context<'_>) -> bool {
        cut(&mut self.read_cut, cx) || self.lingered(cx)
    }

    fn write_cut(&mut self, cx: &mut Context<'_>) -> bool {
        cut(&mut self.write_cut, cx) || self.lingered(cx)
    }
}

fn severed() -> io::Error {
    io::Error::from(io::ErrorKind::ConnectionAborted)
}

fn cut(wait: &mut CutWait, cx: &mut Context<'_>) -> bool {
    wait.as_mut().poll(cx).is_ready()
}

impl<S: AsyncRead + Unpin> AsyncRead for Severable<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_cut(cx) {
            return Poll::Ready(Err(severed()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Severable<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_cut(cx) {
            return Poll::Ready(Err(severed()));
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write_cut(cx) {
            return Poll::Ready(Err(severed()));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.linger.is_none() {
            this.linger = Some(Box::pin(tokio::time::sleep(DISCONNECT_GRACE)));
        }
        if this.write_cut(cx) {
            return Poll::Ready(Err(severed()));
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

pub(super) struct PanicSafe<S> {
    inner: S,
    broken: bool,
}

impl<S> PanicSafe<S> {
    pub(super) fn new(inner: S) -> Self {
        Self {
            inner,
            broken: false,
        }
    }

    fn guarded<T>(
        &mut self,
        poll: impl FnOnce(Pin<&mut S>) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>>
    where
        S: Unpin,
    {
        if self.broken {
            return Poll::Ready(Err(broken()));
        }
        let inner = &mut self.inner;
        match catch_unwind(AssertUnwindSafe(|| poll(Pin::new(inner)))) {
            Ok(polled) => polled,
            Err(_) => {
                self.broken = true;
                Poll::Ready(Err(broken()))
            }
        }
    }
}

fn broken() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

impl<S: AsyncRead + Unpin> AsyncRead for PanicSafe<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().guarded(|inner| inner.poll_read(cx, buf))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PanicSafe<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().guarded(|inner| inner.poll_write(cx, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().guarded(|inner| inner.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().guarded(|inner| inner.poll_shutdown(cx))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio_util::sync::CancellationToken;

    use super::{PanicSafe, Severable};

    #[tokio::test]
    async fn a_cut_fails_pending_and_later_io() {
        let token = CancellationToken::new();
        let (near, mut far) = tokio::io::duplex(64);
        let mut stream = Severable::new(near, &token);
        stream.write_all(b"ping").await.unwrap();
        let mut seen = [0; 4];
        far.read_exact(&mut seen).await.unwrap();
        let reader = tokio::spawn(async move {
            let mut buf = [0; 1];
            let read = stream.read(&mut buf).await;
            (stream, read)
        });
        token.cancel();
        let (mut stream, read) = reader.await.unwrap();
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionAborted);
        let write = stream.write_all(b"late").await.unwrap_err();
        assert_eq!(write.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(
            stream.shutdown().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_shut_down_transport_is_cut_after_the_grace() {
        let token = CancellationToken::new();
        let (near, _far) = tokio::io::duplex(64);
        let mut stream = Severable::new(near, &token);
        stream.shutdown().await.unwrap();
        let started = tokio::time::Instant::now();
        let mut buf = [0; 1];
        let read = tokio::time::timeout(2 * super::DISCONNECT_GRACE, stream.read(&mut buf))
            .await
            .expect("the transport was not cut after the grace")
            .unwrap_err();
        assert_eq!(read.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(started.elapsed(), super::DISCONNECT_GRACE);
        assert!(!token.is_cancelled());
    }

    struct Exploding;

    impl AsyncRead for Exploding {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            panic!("the backend stream failed");
        }
    }

    impl AsyncWrite for Exploding {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_panicking_stream_becomes_a_broken_pipe_for_good() {
        let mut stream = PanicSafe::new(Exploding);
        stream.write_all(b"fine").await.unwrap();
        let mut buf = [0; 1];
        let read = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(read.kind(), io::ErrorKind::BrokenPipe);
        let write = stream.write_all(b"after").await.unwrap_err();
        assert_eq!(write.kind(), io::ErrorKind::BrokenPipe);
    }
}
