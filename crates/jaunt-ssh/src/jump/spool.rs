use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use russh::ChannelMsg;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

use super::inbox::{Inbound, Window};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Finished,
    Broken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(super) enum Refused {
    #[error("the spool is closed")]
    Closed,
    #[error("the spool is over its limit")]
    Overflow,
}

struct State {
    chunks: VecDeque<Bytes>,
    queued: usize,
    written: u64,
    ending: Option<Ending>,
    reader: Option<Waker>,
}

pub(super) struct Spool {
    limit: usize,
    state: Mutex<State>,
    progress: Notify,
}

fn broken() -> io::Error {
    io::Error::from(io::ErrorKind::BrokenPipe)
}

fn length(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

impl Spool {
    pub(super) fn new(limit: usize) -> Spool {
        Spool {
            limit,
            state: Mutex::new(State {
                chunks: VecDeque::new(),
                queued: 0,
                written: 0,
                ending: None,
                reader: None,
            }),
            progress: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn changed(&self, mut state: MutexGuard<'_, State>) {
        let reader = state.reader.take();
        drop(state);
        if let Some(reader) = reader {
            reader.wake();
        }
        self.progress.notify_waiters();
    }

    fn end(&self, ending: Ending) {
        let mut state = self.lock();
        match (state.ending, ending) {
            (Some(Ending::Broken), _) | (Some(Ending::Finished), Ending::Finished) => return,
            _ => {}
        }
        state.ending = Some(ending);
        if ending == Ending::Broken {
            state.chunks.clear();
            state.queued = 0;
        }
        self.changed(state);
    }

    pub(super) fn push(&self, data: Bytes) -> Result<(), Refused> {
        let mut state = self.lock();
        if state.ending.is_some() {
            return Err(Refused::Closed);
        }
        if data.is_empty() {
            return Ok(());
        }
        if state.queued.saturating_add(data.len()) > self.limit {
            drop(state);
            self.end(Ending::Broken);
            return Err(Refused::Overflow);
        }
        state.queued += data.len();
        state.written = state.written.saturating_add(length(data.len()));
        state.chunks.push_back(data);
        self.changed(state);
        Ok(())
    }

    pub(super) fn finish(&self) {
        self.end(Ending::Finished);
    }

    pub(super) fn break_off(&self) {
        self.end(Ending::Broken);
    }

    #[cfg(test)]
    pub(super) fn queued(&self) -> usize {
        self.lock().queued
    }

    fn poll_take(&self, cx: &mut Context<'_>, max: usize) -> Poll<Result<Option<Bytes>, Refused>> {
        let mut state = self.lock();
        if state.ending == Some(Ending::Broken) {
            return Poll::Ready(Err(Refused::Closed));
        }
        if max == 0 {
            return Poll::Ready(Ok(Some(Bytes::new())));
        }
        if let Some(mut chunk) = state.chunks.pop_front() {
            if chunk.len() > max {
                let rest = chunk.split_off(max);
                state.chunks.push_front(rest);
            }
            state.queued -= chunk.len();
            drop(state);
            self.progress.notify_waiters();
            return Poll::Ready(Ok(Some(chunk)));
        }
        if state.ending == Some(Ending::Finished) {
            return Poll::Ready(Ok(None));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }

    pub(super) async fn take(&self, max: usize) -> Result<Option<Bytes>, Refused> {
        poll_fn(|cx| self.poll_take(cx, max)).await
    }

    fn poll_read_into(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<usize>> {
        match self.poll_take(cx, buf.remaining()) {
            Poll::Ready(Ok(Some(chunk))) => {
                buf.put_slice(&chunk);
                Poll::Ready(Ok(chunk.len()))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(broken())),
            Poll::Pending => Poll::Pending,
        }
    }

    async fn until(&self, done: impl Fn(&State) -> bool) -> Result<(), Refused> {
        loop {
            let mut notified = pin!(self.progress.notified());
            notified.as_mut().enable();
            {
                let state = self.lock();
                if state.ending.is_some() {
                    return Err(Refused::Closed);
                }
                if done(&state) {
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    pub(super) async fn drained_to(&self, level: usize) -> Result<(), Refused> {
        self.until(|state| state.queued <= level).await
    }

    pub(super) fn written(&self) -> u64 {
        self.lock().written
    }

    pub(super) async fn written_up_to(&self, total: u64) -> Result<(), Refused> {
        self.until(|state| state.written >= total).await
    }
}

pub(super) struct Inlet<W> {
    spool: Arc<Spool>,
    write: W,
}

impl<W> Inlet<W> {
    pub(super) fn new(spool: Arc<Spool>, write: W) -> Self {
        Self { spool, write }
    }
}

impl<W> Drop for Inlet<W> {
    fn drop(&mut self) {
        self.spool.break_off();
    }
}

impl<W: Unpin> AsyncRead for Inlet<W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.spool.poll_read_into(cx, buf).map_ok(drop)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Inlet<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.write).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.write).poll_shutdown(cx)
    }
}

pub(super) async fn carry_in<R: AsyncRead + Unpin>(mut read: R, spool: Arc<Spool>, chunk: usize) {
    let mut buffer = vec![0; chunk];
    loop {
        match read.read(&mut buffer).await {
            Ok(0) => {
                spool.finish();
                return;
            }
            Ok(got) => match spool.push(Bytes::copy_from_slice(&buffer[..got])) {
                Ok(()) => {}
                Err(Refused::Overflow) => {
                    tracing::warn!(target: "jaunt::web", "the gate sent a web terminal more than its windows allow");
                    return;
                }
                Err(Refused::Closed) => return,
            },
            Err(_) => {
                spool.break_off();
                return;
            }
        }
    }
}

pub(super) trait Grants: Send + Unpin {
    fn grant(&self, bytes: u32);
}

pub(super) struct Tunnel<G> {
    down: Arc<Spool>,
    up: Arc<Spool>,
    window: Arc<Window>,
    grants: G,
    step: usize,
    pending: usize,
}

impl<G: Grants> Tunnel<G> {
    pub(super) fn new(
        down: Arc<Spool>,
        up: Arc<Spool>,
        window: Arc<Window>,
        grants: G,
        step: usize,
    ) -> Self {
        Self {
            down,
            up,
            window,
            grants,
            step,
            pending: 0,
        }
    }

    fn consumed(&mut self, bytes: usize) {
        self.pending = self.pending.saturating_add(bytes);
        if self.pending < self.step {
            return;
        }
        let Ok(grant) = u32::try_from(self.pending) else {
            return;
        };
        self.window.grant(self.pending);
        self.grants.grant(grant);
        self.pending = 0;
    }
}

impl<G> Drop for Tunnel<G> {
    fn drop(&mut self) {
        self.down.break_off();
        self.up.finish();
    }
}

impl<G: Grants> AsyncRead for Tunnel<G> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let read = std::task::ready!(this.down.poll_read_into(cx, buf))?;
        this.consumed(read);
        Poll::Ready(Ok(()))
    }
}

impl<G: Grants> AsyncWrite for Tunnel<G> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.up.push(Bytes::copy_from_slice(data)) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(refused) => {
                if refused == Refused::Overflow {
                    tracing::info!(
                        target: "jaunt::web",
                        reason = "node_violation",
                        "a web terminal was cut off from a node that stopped reading"
                    );
                }
                Poll::Ready(Err(broken()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.up.finish();
        Poll::Ready(Ok(()))
    }
}

pub(super) async fn carry_down<I: Inbound>(mut tunnel: I, down: Arc<Spool>, window: Arc<Window>) {
    let mut received = 0_u64;
    loop {
        let Some(message) = tunnel.receive().await else {
            down.finish();
            return;
        };
        match message {
            ChannelMsg::Data { data } => {
                received = received.saturating_add(length(data.len()));
                let pushed = if window.admits(received) {
                    down.push(data)
                } else {
                    Err(Refused::Overflow)
                };
                match pushed {
                    Ok(()) => {}
                    Err(Refused::Overflow) => {
                        tracing::warn!(target: "jaunt::web", "the gate broke the flow control of a web terminal");
                        down.break_off();
                        return;
                    }
                    Err(Refused::Closed) => return,
                }
            }
            ChannelMsg::ExtendedData { .. } => {
                tracing::warn!(target: "jaunt::web", "the gate sent extended data on a web terminal tunnel");
                down.break_off();
                return;
            }
            ChannelMsg::Eof | ChannelMsg::Close => {
                down.finish();
                return;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use bytes::Bytes;
    use russh::ChannelMsg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    use super::{Grants, Refused, Spool, Tunnel, carry_down};
    use crate::jump::inbox::Window;

    const PATIENCE: Duration = Duration::from_secs(10);
    const LIMIT: usize = 64 * 1024;
    const STEP: usize = 16 * 1024;

    #[derive(Clone, Default)]
    struct Granted(Arc<AtomicU64>);

    impl Grants for Granted {
        fn grant(&self, bytes: u32) {
            self.0.fetch_add(u64::from(bytes), Ordering::SeqCst);
        }
    }

    fn bytes(length: usize) -> Bytes {
        Bytes::from(vec![b'x'; length])
    }

    fn tunnel(
        window: u32,
    ) -> (
        Tunnel<Granted>,
        Arc<Spool>,
        Arc<Spool>,
        Arc<Window>,
        Granted,
    ) {
        let down = Arc::new(Spool::new(usize::try_from(window).unwrap()));
        let up = Arc::new(Spool::new(LIMIT));
        let window = Arc::new(Window::new(window));
        let granted = Granted::default();
        let tunnel = Tunnel::new(
            Arc::clone(&down),
            Arc::clone(&up),
            Arc::clone(&window),
            granted.clone(),
            STEP,
        );
        (tunnel, down, up, window, granted)
    }

    #[tokio::test]
    async fn a_spool_hands_out_bounded_chunks_in_order_and_ends_after_its_data() {
        let spool = Spool::new(LIMIT);
        spool.push(Bytes::from_static(b"abcdef")).unwrap();
        spool.push(Bytes::from_static(b"gh")).unwrap();
        spool.finish();
        assert_eq!(spool.push(bytes(1)), Err(Refused::Closed));
        assert_eq!(spool.take(4).await, Ok(Some(Bytes::from_static(b"abcd"))));
        assert_eq!(spool.take(4).await, Ok(Some(Bytes::from_static(b"ef"))));
        assert_eq!(spool.take(4).await, Ok(Some(Bytes::from_static(b"gh"))));
        assert_eq!(spool.take(4).await, Ok(None));
    }

    #[tokio::test]
    async fn a_spool_over_its_limit_breaks_and_keeps_nothing() {
        let spool = Spool::new(LIMIT);
        spool.push(bytes(LIMIT)).unwrap();
        assert_eq!(spool.push(bytes(1)), Err(Refused::Overflow));
        assert_eq!(spool.queued(), 0);
        assert_eq!(spool.take(LIMIT).await, Err(Refused::Closed));
    }

    #[tokio::test]
    async fn writes_toward_the_gate_never_wait_and_a_peer_that_stops_reading_is_cut_at_the_limit() {
        let (mut tunnel, _down, up, _window, _granted) = tunnel(1024);
        for _ in 0..LIMIT / 1024 {
            tokio::time::timeout(PATIENCE, tunnel.write_all(&[b'w'; 1024]))
                .await
                .expect("a write toward the gate waited")
                .unwrap();
        }
        assert_eq!(up.queued(), LIMIT);
        assert!(tunnel.write_all(b"one more").await.is_err());
        assert_eq!(up.queued(), 0);
    }

    #[tokio::test]
    async fn the_gate_gets_window_back_only_for_bytes_the_node_connection_has_read() {
        let window = 4 * u32::try_from(STEP).unwrap();
        let (mut tunnel, down, _up, allowance, granted) = tunnel(window);
        down.push(bytes(STEP + STEP / 2)).unwrap();
        let mut buffer = vec![0; STEP / 2];
        tunnel.read_exact(&mut buffer).await.unwrap();
        assert_eq!(granted.0.load(Ordering::SeqCst), 0);
        tunnel.read_exact(&mut buffer).await.unwrap();
        assert_eq!(
            granted.0.load(Ordering::SeqCst),
            u64::try_from(STEP).unwrap()
        );
        assert!(allowance.admits(u64::from(window) + u64::try_from(STEP).unwrap()));
        assert!(!allowance.admits(u64::from(window) + u64::try_from(STEP).unwrap() + 1));
    }

    #[tokio::test]
    async fn a_gate_that_sends_past_the_tunnel_window_breaks_the_tunnel_and_nothing_is_kept() {
        let window = 4 * u32::try_from(STEP).unwrap();
        let (mut tunnel, down, _up, allowance, granted) = tunnel(window);
        let (sender, receiver) = mpsc::channel(1);
        let carried = tokio::spawn(carry_down(receiver, Arc::clone(&down), allowance));
        for _ in 0..4 {
            sender
                .send(ChannelMsg::Data { data: bytes(STEP) })
                .await
                .unwrap();
        }
        let mut buffer = vec![0; STEP / 2];
        tunnel.read_exact(&mut buffer).await.unwrap();
        assert_eq!(granted.0.load(Ordering::SeqCst), 0);
        sender
            .send(ChannelMsg::Data { data: bytes(1) })
            .await
            .unwrap();
        tokio::time::timeout(PATIENCE, carried)
            .await
            .expect("the tunnel kept taking bytes past its window")
            .unwrap();
        assert_eq!(down.queued(), 0);
        assert!(tunnel.read(&mut buffer).await.is_err());
    }

    #[tokio::test]
    async fn input_waits_below_the_admission_mark_and_until_the_node_connection_wrote_it() {
        let spool = Arc::new(Spool::new(LIMIT));
        spool.push(bytes(LIMIT / 2)).unwrap();
        let level = Arc::clone(&spool);
        let admitted = tokio::spawn(async move { level.drained_to(LIMIT / 4).await });
        tokio::task::yield_now().await;
        assert!(!admitted.is_finished());
        spool.take(LIMIT / 4).await.unwrap();
        assert_eq!(
            tokio::time::timeout(PATIENCE, admitted)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        let mark = spool.written();
        let progress = Arc::clone(&spool);
        let written = tokio::spawn(async move { progress.written_up_to(mark + 10).await });
        spool.push(bytes(4)).unwrap();
        tokio::task::yield_now().await;
        assert!(!written.is_finished());
        spool.push(bytes(6)).unwrap();
        assert_eq!(
            tokio::time::timeout(PATIENCE, written)
                .await
                .unwrap()
                .unwrap(),
            Ok(())
        );
        spool.break_off();
        assert_eq!(spool.drained_to(LIMIT).await, Err(Refused::Closed));
    }
}
