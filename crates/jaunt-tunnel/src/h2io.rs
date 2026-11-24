use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use h2::{Reason, RecvStream, SendStream};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

const MAX_WRITE_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("stream was aborted")]
pub struct StreamAborted;

type CancelWait = Pin<Box<WaitForCancellationFutureOwned>>;

pub(crate) struct StreamSlot(Arc<AtomicUsize>);

impl StreamSlot {
    pub(crate) fn acquire(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current < limit).then_some(current + 1)
            })
            .ok()
            .map(|_| Self(active.clone()))
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Halves {
    recv: RecvStream,
    send: SendStream<Bytes>,
}

pub struct H2Io {
    halves: Option<Halves>,
    pending: Bytes,
    recv_finished: bool,
    shutdown_sent: bool,
    read_cancel: Option<CancelWait>,
    write_cancel: Option<CancelWait>,
    slot: Option<StreamSlot>,
}

impl fmt::Debug for H2Io {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("H2Io")
            .field(
                "stream_id",
                &self.halves.as_ref().map(|halves| halves.send.stream_id()),
            )
            .field("unread", &self.pending.len())
            .field("recv_finished", &self.recv_finished)
            .field("shutdown_sent", &self.shutdown_sent)
            .field("aborted", &self.halves.is_none())
            .finish()
    }
}

impl H2Io {
    pub fn new(recv: RecvStream, send: SendStream<Bytes>) -> Self {
        Self {
            halves: Some(Halves { recv, send }),
            pending: Bytes::new(),
            recv_finished: false,
            shutdown_sent: false,
            read_cancel: None,
            write_cancel: None,
            slot: None,
        }
    }

    pub(crate) fn with_slot(mut self, slot: StreamSlot) -> Self {
        self.slot = Some(slot);
        self
    }

    pub(crate) fn with_cancel(mut self, token: &CancellationToken) -> Self {
        self.read_cancel = Some(Box::pin(token.clone().cancelled_owned()));
        self.write_cancel = Some(Box::pin(token.clone().cancelled_owned()));
        self
    }

    fn halves(&mut self) -> io::Result<&mut Halves> {
        self.halves.as_mut().ok_or_else(aborted_error)
    }

    fn check_abort(&mut self, cx: &mut Context<'_>, reading: bool) -> io::Result<()> {
        if self.halves.is_none() {
            return Err(aborted_error());
        }
        let wait = if reading {
            self.read_cancel.as_mut()
        } else {
            self.write_cancel.as_mut()
        };
        if let Some(wait) = wait
            && wait.as_mut().poll(cx).is_ready()
        {
            self.abort();
            return Err(aborted_error());
        }
        Ok(())
    }

    fn abort(&mut self) {
        if let Some(mut halves) = self.halves.take() {
            halves.send.send_reset(Reason::CANCEL);
        }
        self.pending = Bytes::new();
        self.read_cancel = None;
        self.write_cancel = None;
        self.slot = None;
    }

    fn closed_write_error(&mut self, cx: &mut Context<'_>) -> io::Error {
        let Some(halves) = self.halves.as_mut() else {
            return aborted_error();
        };
        match halves.send.poll_reset(cx) {
            Poll::Ready(Ok(reason)) => {
                io::Error::new(io::ErrorKind::ConnectionReset, h2::Error::from(reason))
            }
            Poll::Ready(Err(error)) => h2_to_io(error),
            Poll::Pending => io::Error::from(io::ErrorKind::BrokenPipe),
        }
    }
}

fn aborted_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, StreamAborted)
}

fn h2_to_io(error: h2::Error) -> io::Error {
    let kind = if error.is_reset() {
        io::ErrorKind::ConnectionReset
    } else if error.is_go_away() {
        io::ErrorKind::ConnectionAborted
    } else if error.is_io() {
        return error
            .into_io()
            .unwrap_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe));
    } else {
        io::ErrorKind::BrokenPipe
    };
    io::Error::new(kind, error)
}

impl AsyncRead for H2Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_abort(cx, true)?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..take]);
                this.pending.advance(take);
                this.halves()?
                    .recv
                    .flow_control()
                    .release_capacity(take)
                    .map_err(h2_to_io)?;
                return Poll::Ready(Ok(()));
            }
            if this.recv_finished {
                return Poll::Ready(Ok(()));
            }
            let halves = this.halves()?;
            match halves.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(bytes))) => this.pending = bytes,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_to_io(error))),
                Poll::Ready(None) => {
                    this.recv_finished = true;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check_abort(cx, false)?;
        if this.shutdown_sent {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = buf.len().min(MAX_WRITE_CHUNK);
        let halves = this.halves()?;
        halves.send.reserve_capacity(wanted);
        let mut capacity = halves.send.capacity();
        if capacity == 0 {
            match halves.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(assigned))) => capacity = assigned,
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(h2_to_io(error))),
                Poll::Ready(None) => return Poll::Ready(Err(this.closed_write_error(cx))),
            }
        }
        let accepted = capacity.min(wanted);
        this.halves()?
            .send
            .send_data(Bytes::copy_from_slice(&buf[..accepted]), false)
            .map_err(h2_to_io)?;
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_abort(cx, false)?;
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check_abort(cx, false)?;
        if !this.shutdown_sent {
            this.halves()?
                .send
                .send_data(Bytes::new(), true)
                .map_err(h2_to_io)?;
            this.shutdown_sent = true;
        }
        Poll::Ready(Ok(()))
    }
}
