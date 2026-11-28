use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use jaunt_limits::LogThrottle;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::Semaphore;

use crate::local_listen::{DEFAULT_LOOPBACK, ListenError};
use crate::service_dial::{ConnectError, DialError, DialKind, ServiceDialer, ServiceName};

pub const MAX_LOCAL_CONNECTIONS: usize = 64;
pub const REFUSAL_NOTICE_EVERY: Duration = Duration::from_secs(10);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);
const RELAY_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Listen(#[from] ListenError),
    #[error("cannot start the connection runtime: {0}")]
    Runtime(io::Error),
    #[error("cannot watch for signals: {0}")]
    Signals(io::Error),
}

pub fn proxy_runtime() -> Result<tokio::runtime::Runtime, RunError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)
}

pub enum LocalListener {
    Unix(UnixListener),
    Tcp(Vec<TcpListener>),
}

enum LocalStream {
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl LocalListener {
    pub fn unix(
        listener: std::os::unix::net::UnixListener,
        path: &Path,
    ) -> Result<LocalListener, ListenError> {
        UnixListener::from_std(listener)
            .map(LocalListener::Unix)
            .map_err(|source| ListenError::Io {
                action: "listen on",
                path: path.to_owned(),
                source,
            })
    }

    pub fn tcp(listeners: Vec<std::net::TcpListener>) -> Result<LocalListener, ListenError> {
        let mut converted = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let address = listener.local_addr().map_err(|source| ListenError::Bind {
                address: DEFAULT_LOOPBACK,
                source,
            })?;
            converted.push(
                TcpListener::from_std(listener)
                    .map_err(|source| ListenError::Bind { address, source })?,
            );
        }
        Ok(LocalListener::Tcp(converted))
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        match self {
            LocalListener::Unix(_) => Vec::new(),
            LocalListener::Tcp(listeners) => listeners
                .iter()
                .filter_map(|listener| listener.local_addr().ok())
                .collect(),
        }
    }

    async fn accept(&self) -> io::Result<LocalStream> {
        match self {
            LocalListener::Unix(listener) => listener
                .accept()
                .await
                .map(|(stream, _)| LocalStream::Unix(stream)),
            LocalListener::Tcp(listeners) => poll_fn(|cx| {
                for listener in listeners {
                    if let Poll::Ready(accepted) = listener.poll_accept(cx) {
                        return Poll::Ready(accepted.map(|(stream, _)| stream));
                    }
                }
                Poll::Pending
            })
            .await
            .map(LocalStream::Tcp),
        }
    }
}

pub struct Target {
    dialer: Arc<ServiceDialer>,
    kind: DialKind,
    name: ServiceName,
    notices: Notices,
}

impl Target {
    pub fn new(dialer: Arc<ServiceDialer>, kind: DialKind, name: ServiceName) -> Target {
        Target {
            dialer,
            kind,
            name,
            notices: Notices::new(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Reason {
    Refused,
    CutOff,
    SignIn,
    Busy,
    Other,
}

struct Notices {
    started: Instant,
    refused: LogThrottle,
    cut_off: LogThrottle,
    sign_in: LogThrottle,
    busy: LogThrottle,
    other: LogThrottle,
}

impl Notices {
    fn new() -> Notices {
        Notices {
            started: Instant::now(),
            refused: LogThrottle::new(REFUSAL_NOTICE_EVERY),
            cut_off: LogThrottle::new(REFUSAL_NOTICE_EVERY),
            sign_in: LogThrottle::new(REFUSAL_NOTICE_EVERY),
            busy: LogThrottle::new(REFUSAL_NOTICE_EVERY),
            other: LogThrottle::new(REFUSAL_NOTICE_EVERY),
        }
    }

    fn say(&self, reason: Reason, line: impl std::fmt::Display) {
        let throttle = match reason {
            Reason::Refused => &self.refused,
            Reason::CutOff => &self.cut_off,
            Reason::SignIn => &self.sign_in,
            Reason::Busy => &self.busy,
            Reason::Other => &self.other,
        };
        if let Some(suppressed) = throttle.admit(self.started.elapsed()) {
            eprintln!("jaunt: {line}{}", held_back(suppressed));
        }
    }
}

fn reason_of(err: &ConnectError) -> Reason {
    match err {
        ConnectError::Dial(DialError::Refused { .. }) => Reason::Refused,
        ConnectError::Identity(_) => Reason::SignIn,
        ConnectError::Busy => Reason::Busy,
        _ => Reason::Other,
    }
}

pub struct StopSignals {
    interrupt: Signal,
    terminate: Signal,
    hangup: Signal,
}

impl StopSignals {
    pub fn install() -> io::Result<StopSignals> {
        Ok(StopSignals {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    pub async fn next(&mut self) -> Option<StopKind> {
        tokio::select! {
            biased;
            Some(()) = self.interrupt.recv() => Some(StopKind::Interrupt),
            Some(()) = self.terminate.recv() => Some(StopKind::Terminate),
            Some(()) = self.hangup.recv() => Some(StopKind::Hangup),
            else => None,
        }
    }

    pub async fn stopped(&mut self) {
        self.next().await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopKind {
    Interrupt,
    Terminate,
    Hangup,
}

fn held_back(suppressed: u64) -> String {
    if suppressed == 0 {
        String::new()
    } else {
        format!(" ({suppressed} more since the last notice)")
    }
}

pub async fn serve<F>(listener: LocalListener, target: Arc<Target>, stop: F)
where
    F: Future<Output = ()>,
{
    let slots = Arc::new(Semaphore::new(MAX_LOCAL_CONNECTIONS));
    let refusals = LogThrottle::new(REFUSAL_NOTICE_EVERY);
    let accept_failures = LogThrottle::new(REFUSAL_NOTICE_EVERY);
    let started = Instant::now();
    tokio::pin!(stop);
    loop {
        let accepted = tokio::select! {
            biased;
            () = &mut stop => break,
            accepted = listener.accept() => accepted,
        };
        let local = match accepted {
            Ok(local) => local,
            Err(err) => {
                if let Some(suppressed) = accept_failures.admit(started.elapsed()) {
                    eprintln!(
                        "jaunt: accepting a local connection failed: {err}{}",
                        held_back(suppressed)
                    );
                }
                tokio::select! {
                    biased;
                    () = &mut stop => break,
                    () = tokio::time::sleep(ACCEPT_ERROR_PAUSE) => {}
                }
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            drop(local);
            if let Some(suppressed) = refusals.admit(started.elapsed()) {
                eprintln!(
                    "jaunt: refused a local connection: {MAX_LOCAL_CONNECTIONS} connections are already open{}",
                    held_back(suppressed)
                );
            }
            continue;
        };
        let target = Arc::clone(&target);
        tokio::spawn(async move {
            match local {
                LocalStream::Unix(stream) => carry(stream, &target).await,
                LocalStream::Tcp(stream) => carry(stream, &target).await,
            }
            drop(slot);
        });
    }
}

async fn carry<S>(local: S, target: &Target)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let remote = match target.dialer.connect(target.kind, &target.name).await {
        Ok(remote) => remote,
        Err(err) => {
            target.notices.say(reason_of(&err), err);
            return;
        }
    };
    match relay(local, remote).await {
        RelayEnd::Closed | RelayEnd::LocalFailed => {}
        RelayEnd::Refused => target.notices.say(
            Reason::Refused,
            DialError::Refused {
                kind: target.kind.label(),
            },
        ),
        RelayEnd::CutOff => target.notices.say(
            Reason::CutOff,
            format_args!(
                "the connection to {} `{}` was cut off",
                target.kind.label(),
                target.name
            ),
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEnd {
    Closed,
    Refused,
    CutOff,
    LocalFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpEnd {
    Done,
    LocalFailed,
    RemoteFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownEnd {
    Done,
    LocalFailed,
    RemoteFailed,
}

pub async fn relay<L, R>(local: L, remote: R) -> RelayEnd
where
    L: AsyncRead + AsyncWrite,
    R: AsyncRead + AsyncWrite,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    let heard = AtomicBool::new(false);
    let up = async {
        let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
        loop {
            let count = match local_read.read(&mut buffer).await {
                Ok(0) => break,
                Ok(count) => count,
                Err(_) => return UpEnd::LocalFailed,
            };
            if remote_write.write_all(&buffer[..count]).await.is_err()
                || remote_write.flush().await.is_err()
            {
                return UpEnd::RemoteFailed;
            }
        }
        match remote_write.shutdown().await {
            Ok(()) => UpEnd::Done,
            Err(_) => UpEnd::RemoteFailed,
        }
    };
    let down = async {
        let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
        loop {
            let count = match remote_read.read(&mut buffer).await {
                Ok(0) => break,
                Ok(count) => count,
                Err(_) => return DownEnd::RemoteFailed,
            };
            heard.store(true, Ordering::Relaxed);
            if local_write.write_all(&buffer[..count]).await.is_err()
                || local_write.flush().await.is_err()
            {
                return DownEnd::LocalFailed;
            }
        }
        match local_write.shutdown().await {
            Ok(()) => DownEnd::Done,
            Err(_) => DownEnd::LocalFailed,
        }
    };
    tokio::pin!(up, down);
    let mut up_end = None;
    let mut down_end = None;
    while up_end.is_none() || down_end.is_none() {
        tokio::select! {
            end = &mut up, if up_end.is_none() => {
                up_end = Some(end);
                if end == UpEnd::LocalFailed {
                    break;
                }
            }
            end = &mut down, if down_end.is_none() => {
                down_end = Some(end);
                if end != DownEnd::Done {
                    break;
                }
            }
        }
    }
    match (down_end, up_end) {
        (Some(DownEnd::RemoteFailed), _) if heard.load(Ordering::Relaxed) => RelayEnd::CutOff,
        (Some(DownEnd::RemoteFailed), _) => RelayEnd::Refused,
        (Some(DownEnd::LocalFailed), _) | (_, Some(UpEnd::LocalFailed)) => RelayEnd::LocalFailed,
        _ => RelayEnd::Closed,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
    use tokio::time::timeout;

    use super::{RelayEnd, relay};

    const DEADLINE: Duration = Duration::from_secs(10);

    struct Service {
        reads: VecDeque<io::Result<Vec<u8>>>,
        writes_fail: bool,
        silent: bool,
    }

    impl Service {
        fn new(reads: Vec<io::Result<Vec<u8>>>, writes_fail: bool) -> Service {
            Service {
                reads: reads.into(),
                writes_fail,
                silent: false,
            }
        }

        fn silent() -> Service {
            Service {
                reads: VecDeque::new(),
                writes_fail: false,
                silent: true,
            }
        }

        fn broken() -> io::Error {
            io::Error::from(io::ErrorKind::BrokenPipe)
        }
    }

    impl AsyncRead for Service {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.reads.pop_front() {
                Some(Ok(bytes)) => {
                    buf.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Some(Err(err)) => Poll::Ready(Err(err)),
                None if self.silent => Poll::Pending,
                None => Poll::Ready(Ok(())),
            }
        }
    }

    struct BrokenClient;

    impl AsyncRead for BrokenClient {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(reset()))
        }
    }

    impl AsyncWrite for BrokenClient {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn a_broken_local_client_ends_the_relay_even_when_the_service_stays_silent() {
        let end = bounded(relay(BrokenClient, Service::silent()));

        assert_eq!(end, RelayEnd::LocalFailed);
    }

    impl AsyncWrite for Service {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.writes_fail {
                Poll::Ready(Err(Service::broken()))
            } else {
                Poll::Ready(Ok(buf.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.writes_fail {
                Poll::Ready(Err(Service::broken()))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    fn bounded<F: Future>(work: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(DEADLINE, work)
                    .await
                    .expect("the relay did not finish in time")
            })
    }

    fn reset() -> io::Error {
        io::Error::from(io::ErrorKind::ConnectionReset)
    }

    #[test]
    fn each_direction_ends_on_its_own_and_the_other_keeps_flowing() {
        bounded(async {
            let (local, mut client) = duplex(64);
            let (remote, mut server) = duplex(64);
            let relayed = tokio::spawn(relay(local, remote));

            client.write_all(b"ping").await.unwrap();
            client.shutdown().await.unwrap();
            let mut seen = Vec::new();
            server.read_to_end(&mut seen).await.unwrap();
            server.write_all(b"pong").await.unwrap();
            server.shutdown().await.unwrap();
            let mut answer = Vec::new();
            client.read_to_end(&mut answer).await.unwrap();

            assert_eq!(seen, b"ping");
            assert_eq!(answer, b"pong");
            assert_eq!(relayed.await.unwrap(), RelayEnd::Closed);
        });
    }

    #[test]
    fn a_service_that_answered_and_closed_is_heard_even_when_writing_to_it_fails() {
        bounded(async {
            let (local, mut client) = duplex(64);
            client.write_all(b"request").await.unwrap();
            let service = Service::new(vec![Ok(b"answer".to_vec())], true);
            let relayed = tokio::spawn(relay(local, service));

            let mut answer = Vec::new();
            client.read_to_end(&mut answer).await.unwrap();

            assert_eq!(answer, b"answer");
            assert_eq!(relayed.await.unwrap(), RelayEnd::Closed);
        });
    }

    #[test]
    fn the_client_sees_the_end_of_the_service_and_may_still_write_afterwards() {
        bounded(async {
            let (local, mut client) = duplex(64);
            let service = Service::new(vec![Ok(b"bye".to_vec())], true);
            let relayed = tokio::spawn(relay(local, service));

            let mut answer = Vec::new();
            client.read_to_end(&mut answer).await.unwrap();
            client.write_all(b"more").await.unwrap();

            assert_eq!(answer, b"bye");
            assert_eq!(relayed.await.unwrap(), RelayEnd::Closed);
        });
    }

    #[test]
    fn a_service_that_fails_after_a_byte_is_cut_off_and_before_any_byte_refused() {
        let cases = [
            (
                vec![Ok(b"a".to_vec()), Err(reset())],
                false,
                RelayEnd::CutOff,
                &b"a"[..],
            ),
            (vec![Err(reset())], false, RelayEnd::Refused, &b""[..]),
            (vec![Err(reset())], true, RelayEnd::Refused, &b""[..]),
        ];
        for (reads, writes_fail, expected, delivered) in cases {
            bounded(async {
                let (local, mut client) = duplex(64);
                client.write_all(b"request").await.unwrap();
                let relayed = tokio::spawn(relay(local, Service::new(reads, writes_fail)));

                let mut answer = Vec::new();
                client.read_to_end(&mut answer).await.unwrap();

                assert_eq!(answer, delivered);
                assert_eq!(relayed.await.unwrap(), expected);
            });
        }
    }
}
