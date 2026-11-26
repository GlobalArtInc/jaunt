use std::future::Future;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::{Extension, Router};
use hyper::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use jaunt_limits::{ClientKey, ConcurrencyGuard, ConcurrencyLimiter, LogThrottle, TrustedProxies};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::JoinSet;
use tower::{Layer, ServiceExt};

pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub(crate) const MAX_HEADER_BYTES: usize = 32 * 1024;
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub(crate) struct ServerLimits {
    pub(crate) max_connections: usize,
    pub(crate) per_address: usize,
    pub(crate) exempt: TrustedProxies,
    pub(crate) header_read_timeout: Duration,
    pub(crate) max_header_bytes: usize,
}

impl ServerLimits {
    pub(crate) fn new(
        max_connections: usize,
        per_address: usize,
        exempt: TrustedProxies,
    ) -> ServerLimits {
        ServerLimits {
            max_connections,
            per_address,
            exempt,
            header_read_timeout: HEADER_READ_TIMEOUT,
            max_header_bytes: MAX_HEADER_BYTES,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SocketWrites(Arc<AtomicU64>);

impl SocketWrites {
    pub(crate) fn total(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }

    pub(crate) fn add(&self, written: usize) {
        self.0.fetch_add(
            u64::try_from(written).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }
}

struct Metered<T> {
    inner: T,
    writes: SocketWrites,
}

impl<T> Metered<T> {
    fn counted(&self, written: Poll<io::Result<usize>>) -> Poll<io::Result<usize>> {
        if let Poll::Ready(Ok(count)) = &written {
            self.writes.add(*count);
        }
        written
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write(cx, data);
        this.counted(written)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let written = Pin::new(&mut this.inner).poll_write_vectored(cx, data);
        this.counted(written)
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

struct Slot {
    _global: OwnedSemaphorePermit,
    _address: Option<ConcurrencyGuard<ClientKey>>,
}

#[derive(Debug, Clone, Copy)]
enum Refusal {
    Address,
    Full,
}

impl Refusal {
    const fn reason(self) -> &'static str {
        match self {
            Refusal::Address => "per_address",
            Refusal::Full => "global",
        }
    }
}

fn admit(
    limits: &ServerLimits,
    permits: &Arc<Semaphore>,
    addresses: &ConcurrencyLimiter<ClientKey>,
    peer: SocketAddr,
) -> Result<Slot, Refusal> {
    let address = if limits.exempt.contains(peer.ip()) {
        None
    } else {
        Some(
            addresses
                .try_acquire(ClientKey::of(peer.ip()))
                .map_err(|_| Refusal::Address)?,
        )
    };
    let global = Arc::clone(permits)
        .try_acquire_owned()
        .map_err(|_| Refusal::Full)?;
    Ok(Slot {
        _global: global,
        _address: address,
    })
}

pub(crate) async fn serve(
    router: Router,
    listener: TcpListener,
    limits: ServerLimits,
    shutdown: impl Future<Output = ()> + Send + 'static,
) {
    let permits = Arc::new(Semaphore::new(limits.max_connections));
    let addresses = ConcurrencyLimiter::new(limits.per_address, limits.max_connections.max(1));
    let (stop, stopped) = watch::channel(false);
    let refusals = LogThrottle::new(REFUSAL_LOG_INTERVAL);
    let accept_errors = LogThrottle::new(REFUSAL_LOG_INTERVAL);
    let origin = Instant::now();
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            Some(finished) = connections.join_next() => report(finished),
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => match admit(&limits, &permits, &addresses, peer) {
                    Ok(slot) => {
                        connections.spawn(connection(router.clone(), tcp, peer, limits.clone(), slot, stopped.clone()));
                    }
                    Err(refusal) => {
                        drop(tcp);
                        if let Some(suppressed) = refusals.admit(origin.elapsed()) {
                            tracing::info!(
                                target: "jaunt::audit",
                                event = "http.connection_limited",
                                peer_addr = %peer,
                                reason = refusal.reason(),
                                suppressed
                            );
                        }
                    }
                },
                Err(error) => {
                    if let Some(suppressed) = accept_errors.admit(origin.elapsed()) {
                        tracing::warn!(target: "jaunt::control", error = %error, suppressed, "accepting an http connection failed");
                    }
                    tokio::select! {
                        () = &mut shutdown => break,
                        () = tokio::time::sleep(ACCEPT_ERROR_PAUSE) => {}
                    }
                }
            },
        }
    }
    drop(listener);
    stop.send_replace(true);
    while let Some(finished) = connections.join_next().await {
        report(finished);
    }
}

fn report(finished: Result<(), tokio::task::JoinError>) {
    if finished.is_err_and(|error| error.is_panic()) {
        tracing::error!(target: "jaunt::control", "an http connection task panicked");
    }
}

async fn connection(
    router: Router,
    tcp: TcpStream,
    peer: SocketAddr,
    limits: ServerLimits,
    slot: Slot,
    mut stopped: watch::Receiver<bool>,
) {
    if let Err(error) = tcp.set_nodelay(true) {
        tracing::debug!(target: "jaunt::control", peer_addr = %peer, error = %error, "an http connection could not be tuned");
    }
    let writes = SocketWrites::default();
    let service = Extension(ConnectInfo(peer)).layer(Extension(writes.clone()).layer(router));
    let handler = service_fn(move |request: Request<Incoming>| service.clone().oneshot(request));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .max_header_size(limits.max_header_bytes);
    let served = builder
        .serve_connection(TokioIo::new(Metered { inner: tcp, writes }), handler)
        .with_upgrades();
    tokio::pin!(served);
    let stop = async move {
        drop(stopped.wait_for(|stopped| *stopped).await);
    };
    let finished = tokio::select! {
        finished = served.as_mut() => finished,
        () = stop => {
            served.as_mut().graceful_shutdown();
            served.await
        }
    };
    if let Err(error) = finished {
        tracing::debug!(target: "jaunt::control", peer_addr = %peer, error = %error, "an http connection ended with an error");
    }
    drop(slot);
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use axum::{Extension, Router};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use jaunt_limits::TrustedProxies;

    use super::{
        HEADER_READ_TIMEOUT, MAX_HEADER_BYTES, Metered, ServerLimits, SocketWrites, serve,
    };

    const PATIENCE: Duration = Duration::from_secs(10);
    const BIG: usize = 256 * 1024;

    fn limits(max_connections: usize, per_address: usize) -> ServerLimits {
        ServerLimits::new(max_connections, per_address, TrustedProxies::default())
    }

    async fn answered(addr: SocketAddr) -> TcpStream {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut status = [0_u8; 12];
        tcp.read_exact(&mut status).await.unwrap();
        assert_eq!(&status, b"HTTP/1.1 200");
        tcp
    }

    #[test]
    fn the_connection_deadlines_and_sizes_stay_tight() {
        assert!(HEADER_READ_TIMEOUT <= Duration::from_secs(30));
        assert!(HEADER_READ_TIMEOUT >= Duration::from_secs(5));
        assert_eq!(MAX_HEADER_BYTES, 32 * 1024);
    }

    async fn start(limits: ServerLimits) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router =
            Router::new()
                .route(
                    "/peer",
                    get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move {
                        peer.ip().to_string()
                    }),
                )
                .route("/big", get(|| async { "b".repeat(BIG) }))
                .route(
                    "/written",
                    get(|Extension(writes): Extension<SocketWrites>| async move {
                        writes.total().to_string()
                    }),
                );
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(router, listener, limits, async move {
            drop(stopped.await);
        }));
        (addr, stop, task)
    }

    async fn read_all(tcp: &mut TcpStream) -> String {
        let mut answer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = tokio::time::timeout(PATIENCE, tcp.read(&mut chunk))
                .await
                .expect("the server kept the connection open");
            match read {
                Ok(0) | Err(_) => break,
                Ok(count) => answer.extend_from_slice(&chunk[..count]),
            }
        }
        String::from_utf8_lossy(&answer).into_owned()
    }

    #[tokio::test]
    async fn requests_see_the_peer_and_a_silent_client_is_dropped_after_the_header_deadline() {
        let limits = ServerLimits {
            header_read_timeout: Duration::from_millis(200),
            ..limits(8, 8)
        };
        let (addr, stop, task) = start(limits).await;

        let mut asking = TcpStream::connect(addr).await.unwrap();
        asking
            .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let answer = read_all(&mut asking).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("127.0.0.1"), "{answer}");

        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /peer HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        let answer = read_all(&mut slow).await;
        assert!(!answer.contains("200 OK"), "{answer}");

        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn oversized_headers_are_refused() {
        let limits = ServerLimits {
            max_header_bytes: 8 * 1024,
            ..limits(8, 8)
        };
        let (addr, stop, task) = start(limits).await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let filler = "a".repeat(9 * 1024);
        tcp.write_all(
            format!("GET /peer HTTP/1.1\r\nHost: x\r\nX-Fill: {filler}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let answer = read_all(&mut tcp).await;
        assert!(
            answer.starts_with("HTTP/1.1 431") || answer.is_empty(),
            "{answer}"
        );
        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed_at_once_and_the_slot_returns() {
        let (addr, stop, task) = start(limits(1, 1)).await;
        let held = answered(addr).await;

        let mut refused = TcpStream::connect(addr).await.unwrap();
        let answer = read_all(&mut refused).await;
        assert!(answer.is_empty(), "{answer}");

        drop(held);
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut retry = TcpStream::connect(addr).await.unwrap();
            retry
                .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            if read_all(&mut retry).await.starts_with("HTTP/1.1 200") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the slot never came back"
            );
            tokio::task::yield_now().await;
        }
        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn one_address_holds_at_most_its_share_unless_it_is_a_trusted_proxy() {
        let (addr, stop, task) = start(limits(64, 4)).await;
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(answered(addr).await);
        }
        let mut refused = TcpStream::connect(addr).await.unwrap();
        assert!(read_all(&mut refused).await.is_empty());
        drop(held);
        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();

        let exempt = ServerLimits::new(
            64,
            4,
            TrustedProxies::new(vec!["127.0.0.0/8".parse().unwrap()]).unwrap(),
        );
        let (addr, stop, task) = start(exempt).await;
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(answered(addr).await);
        }
        drop(held);
        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();
    }

    async fn response(tcp: &mut TcpStream, path: &str) -> (usize, String) {
        tcp.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).unwrap();
        let length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .unwrap()
            .parse()
            .unwrap();
        let mut body = vec![0_u8; length];
        tcp.read_exact(&mut body).await.unwrap();
        (head.len() + length, String::from_utf8(body).unwrap())
    }

    #[tokio::test]
    async fn each_connection_counts_exactly_the_bytes_its_socket_took() {
        let (addr, stop, task) = start(limits(8, 8)).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        let (received, body) = response(&mut first, "/big").await;
        assert_eq!(body.len(), BIG);
        let (_, written) = response(&mut first, "/written").await;
        assert_eq!(written, received.to_string());
        let mut second = TcpStream::connect(addr).await.unwrap();
        assert_eq!(response(&mut second, "/written").await.1, "0");
        stop.send(()).unwrap();
        tokio::time::timeout(PATIENCE, task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn only_bytes_the_stream_accepted_are_counted_not_bytes_waiting_to_be_written() {
        let (near, mut far) = tokio::io::duplex(1024);
        let writes = SocketWrites::default();
        let mut metered = Metered {
            inner: near,
            writes: writes.clone(),
        };
        let writer = tokio::spawn(async move {
            metered.write_all(&[b'w'; 4096]).await.unwrap();
            metered
        });
        let deadline = tokio::time::Instant::now() + PATIENCE;
        while writes.total() < 1024 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "nothing was counted"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(writes.total(), 1024);
        let mut taken = vec![0_u8; 512];
        far.read_exact(&mut taken).await.unwrap();
        while writes.total() < 1536 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the next write was not counted"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(writes.total(), 1536);
        let mut rest = vec![0_u8; 4096 - 512];
        far.read_exact(&mut rest).await.unwrap();
        let mut metered = tokio::time::timeout(PATIENCE, writer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(writes.total(), 4096);
        metered.shutdown().await.unwrap();
        let ended = tokio::time::timeout(PATIENCE, far.read(&mut taken))
            .await
            .expect("the shutdown never reached the stream");
        assert_eq!(ended.unwrap(), 0);
    }
}
