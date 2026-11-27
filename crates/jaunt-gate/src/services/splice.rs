use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

use crate::audit::Carried;

pub const HALF_CLOSE_GRACE: Duration = Duration::from_secs(30);
const SPLICE_BUFFER: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpliceEnd {
    Closed,
    Failed,
    Shutdown,
    HalfCloseTimeout,
}

impl SpliceEnd {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Failed => "failed",
            Self::Shutdown => "shutdown",
            Self::HalfCloseTimeout => "half_close_timeout",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Up,
    Down,
}

const ABORTED: &str = "aborted";

pub(crate) struct Ledger {
    up: AtomicU64,
    down: AtomicU64,
    started: Instant,
    end: Option<SpliceEnd>,
    emit: Option<Box<dyn FnOnce(Carried) + Send>>,
}

impl Ledger {
    pub(crate) fn new(emit: impl FnOnce(Carried) + Send + 'static) -> Self {
        Self {
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            started: Instant::now(),
            end: None,
            emit: Some(Box::new(emit)),
        }
    }

    fn carried(&self) -> Carried {
        Carried {
            reason: self.end.map_or(ABORTED, SpliceEnd::as_str),
            bytes_up: self.up.load(Ordering::Relaxed),
            bytes_down: self.down.load(Ordering::Relaxed),
            duration: self.started.elapsed(),
        }
    }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        if let Some(emit) = self.emit.take() {
            emit(self.carried());
        }
    }
}

pub(crate) async fn splice<C, A>(
    client: C,
    agent: A,
    shutdown: &CancellationToken,
    grace: Duration,
    ledger: &mut Ledger,
) -> SpliceEnd
where
    C: AsyncRead + AsyncWrite,
    A: AsyncRead + AsyncWrite,
{
    let (client_read, client_write) = tokio::io::split(client);
    let (agent_read, agent_write) = tokio::io::split(agent);
    let end = {
        let up = pump(client_read, agent_write, &ledger.up);
        let down = pump(agent_read, client_write, &ledger.down);
        tokio::pin!(up, down);
        let first = tokio::select! {
            biased;
            () = shutdown.cancelled() => None,
            finished = &mut up => Some((finished, Side::Up)),
            finished = &mut down => Some((finished, Side::Down)),
        };
        match first {
            None => SpliceEnd::Shutdown,
            Some((Err(_), _)) => SpliceEnd::Failed,
            Some((Ok(()), Side::Up)) => remaining(down, grace, shutdown).await,
            Some((Ok(()), Side::Down)) => remaining(up, grace, shutdown).await,
        }
    };
    ledger.end = Some(end);
    end
}

async fn remaining<F>(
    other: Pin<&mut F>,
    grace: Duration,
    shutdown: &CancellationToken,
) -> SpliceEnd
where
    F: Future<Output = io::Result<()>>,
{
    tokio::select! {
        biased;
        () = shutdown.cancelled() => SpliceEnd::Shutdown,
        finished = timeout(grace, other) => match finished {
            Ok(Ok(())) => SpliceEnd::Closed,
            Ok(Err(_)) => SpliceEnd::Failed,
            Err(_) => SpliceEnd::HalfCloseTimeout,
        },
    }
}

async fn pump<R, W>(mut from: R, mut to: W, moved: &AtomicU64) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; SPLICE_BUFFER];
    loop {
        let read = from.read(&mut buffer).await?;
        let Some(chunk) = buffer.get(..read) else {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        };
        if chunk.is_empty() {
            return to.shutdown().await;
        }
        to.write_all(chunk).await?;
        to.flush().await?;
        moved.fetch_add(u64::try_from(read).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio_util::sync::CancellationToken;

    use super::{HALF_CLOSE_GRACE, Ledger, SpliceEnd, splice};
    use crate::audit::Carried;

    type Seen = Arc<Mutex<Vec<Carried>>>;

    fn ledger() -> (Ledger, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        (
            Ledger::new(move |carried| sink.lock().unwrap().push(carried)),
            seen,
        )
    }

    async fn bounded<T>(what: &str, future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
    }

    fn only(seen: &Seen) -> Carried {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        seen[0]
    }

    #[tokio::test]
    async fn bytes_pass_both_ways_and_each_half_close_reaches_the_other_side() {
        let (mut client, client_side) = duplex(64 * 1024);
        let (agent_side, mut agent) = duplex(64 * 1024);
        let (mut ledger, seen) = ledger();
        let token = CancellationToken::new();
        let spliced = tokio::spawn(async move {
            let end = splice(
                client_side,
                agent_side,
                &token,
                HALF_CLOSE_GRACE,
                &mut ledger,
            )
            .await;
            drop(ledger);
            end
        });

        let up: Vec<u8> = (0..1000_u32).map(|at| (at % 251) as u8).collect();
        client.write_all(&up).await.unwrap();
        client.shutdown().await.unwrap();
        let mut received = Vec::new();
        bounded("the client bytes", agent.read_to_end(&mut received))
            .await
            .unwrap();
        assert_eq!(received, up);

        agent
            .write_all(b"answer after the client half-closed")
            .await
            .unwrap();
        agent.shutdown().await.unwrap();
        let mut back = Vec::new();
        bounded("the agent bytes", client.read_to_end(&mut back))
            .await
            .unwrap();
        assert_eq!(back, b"answer after the client half-closed");

        assert_eq!(
            bounded("the splice end", spliced).await.unwrap(),
            SpliceEnd::Closed
        );
        let carried = only(&seen);
        assert_eq!(
            (carried.reason, carried.bytes_up, carried.bytes_down),
            ("closed", 1000, 35)
        );
    }

    #[tokio::test]
    async fn a_shutdown_ends_the_splice_and_keeps_the_counts() {
        let (mut client, client_side) = duplex(64 * 1024);
        let (agent_side, mut agent) = duplex(64 * 1024);
        let (mut ledger, seen) = ledger();
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let spliced = tokio::spawn(async move {
            let end = splice(
                client_side,
                agent_side,
                &token,
                HALF_CLOSE_GRACE,
                &mut ledger,
            )
            .await;
            drop(ledger);
            end
        });
        client.write_all(b"abc").await.unwrap();
        let mut three = [0_u8; 3];
        bounded("the first bytes", agent.read_exact(&mut three))
            .await
            .unwrap();
        shutdown.cancel();
        assert_eq!(
            bounded("the splice end", spliced).await.unwrap(),
            SpliceEnd::Shutdown
        );
        let carried = only(&seen);
        assert_eq!(
            (carried.reason, carried.bytes_up, carried.bytes_down),
            ("shutdown", 3, 0)
        );
        let mut rest = Vec::new();
        assert_eq!(
            bounded("the agent end", agent.read_to_end(&mut rest))
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_broken_side_ends_both_directions() {
        let (client, client_side) = duplex(64 * 1024);
        let (agent_side, mut agent) = duplex(64 * 1024);
        drop(client);
        let (mut ledger, seen) = ledger();
        let token = CancellationToken::new();
        let spliced = tokio::spawn(async move {
            let end = splice(
                client_side,
                agent_side,
                &token,
                HALF_CLOSE_GRACE,
                &mut ledger,
            )
            .await;
            drop(ledger);
            end
        });
        let mut rest = Vec::new();
        assert_eq!(
            bounded("the agent end", agent.read_to_end(&mut rest))
                .await
                .unwrap(),
            0
        );
        agent.write_all(b"late").await.unwrap();
        assert_eq!(
            bounded("the splice end", spliced).await.unwrap(),
            SpliceEnd::Failed
        );
        assert_eq!(only(&seen).reason, "failed");
    }

    #[tokio::test]
    async fn every_write_is_flushed_through_a_buffering_side() {
        let (mut client, client_side) = duplex(64 * 1024);
        let (client_read, client_write) = tokio::io::split(client_side);
        let buffered = tokio::io::join(client_read, tokio::io::BufWriter::new(client_write));
        let (agent_side, mut agent) = duplex(64 * 1024);
        let (mut ledger, _seen) = ledger();
        let token = CancellationToken::new();
        let stop = token.clone();
        let spliced = tokio::spawn(async move {
            splice(buffered, agent_side, &token, HALF_CLOSE_GRACE, &mut ledger).await
        });
        agent.write_all(b"held back by a buffer").await.unwrap();
        let mut seen = [0_u8; 21];
        bounded("the flushed bytes", client.read_exact(&mut seen))
            .await
            .unwrap();
        assert_eq!(&seen, b"held back by a buffer");
        stop.cancel();
        assert_eq!(
            bounded("the splice end", spliced).await.unwrap(),
            SpliceEnd::Shutdown
        );
    }

    #[tokio::test(start_paused = true)]
    async fn after_one_side_closes_a_silent_other_side_gets_only_the_grace() {
        assert_eq!(HALF_CLOSE_GRACE, Duration::from_secs(30));
        let (mut client, client_side) = duplex(64 * 1024);
        let (agent_side, mut agent) = duplex(64 * 1024);
        let (mut ledger, seen) = ledger();
        let token = CancellationToken::new();
        let spliced = tokio::spawn(async move {
            let end = splice(
                client_side,
                agent_side,
                &token,
                HALF_CLOSE_GRACE,
                &mut ledger,
            )
            .await;
            drop(ledger);
            end
        });
        client.write_all(b"q").await.unwrap();
        let mut one = [0_u8; 1];
        bounded("the first byte", agent.read_exact(&mut one))
            .await
            .unwrap();
        agent.shutdown().await.unwrap();
        let mut nothing = Vec::new();
        bounded("the half-close", client.read_to_end(&mut nothing))
            .await
            .unwrap();
        let started = tokio::time::Instant::now();
        let end = tokio::time::timeout(Duration::from_secs(60), spliced)
            .await
            .expect("the grace did not end the splice")
            .unwrap();
        assert_eq!(end, SpliceEnd::HalfCloseTimeout);
        assert_eq!(started.elapsed(), HALF_CLOSE_GRACE);
        let carried = only(&seen);
        assert_eq!(
            (carried.reason, carried.bytes_up),
            ("half_close_timeout", 1)
        );
        let mut rest = Vec::new();
        assert_eq!(
            bounded("the agent end", agent.read_to_end(&mut rest))
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn a_splice_cut_off_midway_still_reports_once_with_its_counts() {
        let (mut client, client_side) = duplex(64 * 1024);
        let (agent_side, mut agent) = duplex(64 * 1024);
        let (mut ledger, seen) = ledger();
        let token = CancellationToken::new();
        let spliced = tokio::spawn(async move {
            splice(
                client_side,
                agent_side,
                &token,
                HALF_CLOSE_GRACE,
                &mut ledger,
            )
            .await;
        });
        client.write_all(b"abcd").await.unwrap();
        let mut four = [0_u8; 4];
        bounded("the first bytes", agent.read_exact(&mut four))
            .await
            .unwrap();
        spliced.abort();
        assert!(
            bounded("the aborted task", spliced)
                .await
                .unwrap_err()
                .is_cancelled()
        );
        let carried = only(&seen);
        assert_eq!(
            (carried.reason, carried.bytes_up, carried.bytes_down),
            ("aborted", 4, 0)
        );
    }
}
