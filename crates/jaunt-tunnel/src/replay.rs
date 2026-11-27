use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Replay<IO> {
    prefix: Vec<u8>,
    replayed: usize,
    inner: IO,
}

impl<IO> Replay<IO> {
    pub fn new(prefix: Vec<u8>, inner: IO) -> Self {
        Self {
            prefix,
            replayed: 0,
            inner,
        }
    }

    pub fn pending(&self) -> &[u8] {
        self.prefix.get(self.replayed..).unwrap_or_default()
    }

    pub fn get_ref(&self) -> &IO {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut IO {
        &mut self.inner
    }

    pub fn map<T>(self, wrap: impl FnOnce(IO) -> T) -> Replay<T> {
        Replay {
            prefix: self.prefix,
            replayed: self.replayed,
            inner: wrap(self.inner),
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Replay<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = this.prefix.get(this.replayed..).unwrap_or_default();
        if pending.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let count = pending.len().min(buf.remaining());
        let (now, _) = pending.split_at(count);
        buf.put_slice(now);
        this.replayed += count;
        if this.replayed == this.prefix.len() {
            this.prefix = Vec::new();
            this.replayed = 0;
        }
        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Replay<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::Replay;

    async fn bounded<T>(read: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), read)
            .await
            .expect("the read stalled instead of returning the replayed bytes")
    }

    #[tokio::test(start_paused = true)]
    async fn the_prefix_comes_first_then_the_stream_and_writes_go_straight_through() {
        let (near, mut far) = tokio::io::duplex(64);
        far.write_all(b" world").await.unwrap();
        let mut replay = Replay::new(b"hello".to_vec(), near);
        let mut first = [0_u8; 3];
        bounded(replay.read_exact(&mut first)).await.unwrap();
        assert_eq!(&first, b"hel");
        assert_eq!(replay.pending(), b"lo");
        let mut rest = [0_u8; 8];
        bounded(replay.read_exact(&mut rest)).await.unwrap();
        assert_eq!(&rest, b"lo world");
        assert!(replay.pending().is_empty());
        replay.write_all(b"back").await.unwrap();
        let mut back = [0_u8; 4];
        bounded(far.read_exact(&mut back)).await.unwrap();
        assert_eq!(&back, b"back");
    }

    #[tokio::test(start_paused = true)]
    async fn an_empty_prefix_reads_the_stream_only() {
        let (near, mut far) = tokio::io::duplex(64);
        far.write_all(b"data").await.unwrap();
        far.shutdown().await.unwrap();
        let mut replay = Replay::new(Vec::new(), near);
        let mut all = Vec::new();
        bounded(replay.read_to_end(&mut all)).await.unwrap();
        assert_eq!(all, b"data");
    }
}
