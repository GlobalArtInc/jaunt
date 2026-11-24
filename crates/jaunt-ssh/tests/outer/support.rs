use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use jaunt_ssh::{
    AuthDenial, HostKey, OuterEnd, OuterEvent, OuterHop, OuterLimits, RouteBackend, RouteFuture,
    RouteRefusal, RouteTarget, RoutedStream, ServerConfigCell, ServerProfile, StreamEnd,
    UserCaKeys, UserCaSource, UserIdentity,
};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelOpenFailure, ChannelWriteHalf, Disconnect, client,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const SUFFIX: &str = "nodes.example.com";
pub const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
pub const STEP: Duration = Duration::from_secs(20);
pub const TUNNEL_BUFFER: usize = 64 * 1024;
const TRANSPORT: usize = 8 * 1024 * 1024;
const PERMITS: usize = 4;

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn key() -> PrivateKey {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()
}

pub fn node() -> String {
    format!("node1.{SUFFIX}")
}

pub fn certificate(
    ca: &PrivateKey,
    subject: &PrivateKey,
    cert_type: CertType,
    valid_after: u64,
    valid_before: u64,
) -> Certificate {
    let mut builder = Builder::new_with_random_nonce(
        &mut safe_rng(),
        subject.public_key().key_data().clone(),
        valid_after,
        valid_before,
    )
    .unwrap();
    builder.serial(42).unwrap();
    builder.cert_type(cert_type).unwrap();
    builder.key_id("jaunt:alice@example.com:42").unwrap();
    builder.valid_principal(USER_ID).unwrap();
    builder.extension("permit-pty", "").unwrap();
    builder.sign(ca).unwrap()
}

pub fn trust(ca: &PrivateKey) -> UserCaKeys {
    UserCaKeys::from_openssh_lines([ca.public_key().to_openssh().unwrap()]).unwrap()
}

pub fn pattern(offset: usize, len: usize) -> Vec<u8> {
    (offset..offset + len)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect()
}

pub async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + STEP;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Echo,
    Refuse(RouteRefusal),
    Hold,
    Flood,
    Greet,
    Explode,
    Gated,
    Pending,
    PanicRoute,
}

pub struct Backend {
    mode: Mutex<Mode>,
    routes: Mutex<Vec<String>>,
    released: Mutex<Vec<String>>,
    held: Mutex<Vec<DuplexStream>>,
    sessions: AtomicUsize,
    routing: AtomicUsize,
    gate: Semaphore,
    failing_releases: AtomicBool,
    alive: Arc<()>,
}

struct InFlight<'a>(&'a AtomicUsize);

impl<'a> InFlight<'a> {
    fn enter(counter: &'a AtomicUsize) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Backend {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(mode),
            routes: Mutex::new(Vec::new()),
            released: Mutex::new(Vec::new()),
            held: Mutex::new(Vec::new()),
            sessions: AtomicUsize::new(0),
            routing: AtomicUsize::new(0),
            gate: Semaphore::new(0),
            failing_releases: AtomicBool::new(false),
            alive: Arc::new(()),
        })
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    pub fn routes(&self) -> Vec<String> {
        self.routes.lock().unwrap().clone()
    }

    pub fn routing(&self) -> usize {
        self.routing.load(Ordering::SeqCst)
    }

    pub fn released(&self) -> usize {
        self.released.lock().unwrap().len()
    }

    pub fn live(&self) -> usize {
        Arc::strong_count(&self.alive) - 1
    }

    pub fn fail_releases(&self) {
        self.failing_releases.store(true, Ordering::SeqCst);
    }

    pub fn open_gate(&self) {
        self.gate.add_permits(Semaphore::MAX_PERMITS / 2);
    }

    pub fn resume(&self) {
        for mut far in self.held.lock().unwrap().drain(..) {
            tokio::spawn(async move {
                let mut sink = tokio::io::sink();
                let _ = tokio::io::copy(&mut far, &mut sink).await;
            });
        }
    }
}

impl RouteBackend for Backend {
    fn route(&self, target: RouteTarget) -> RouteFuture<'_> {
        Box::pin(async move {
            let _in_flight = InFlight::enter(&self.routing);
            let mode = *self.mode.lock().unwrap();
            assert_ne!(mode, Mode::PanicRoute, "the test route exploded");
            self.routes.lock().unwrap().push(target.node);
            match mode {
                Mode::Refuse(refusal) => return Err(refusal),
                Mode::Pending => std::future::pending::<()>().await,
                Mode::Gated => drop(self.gate.acquire().await.unwrap()),
                _ => {}
            }
            let (near, far) = tokio::io::duplex(TUNNEL_BUFFER);
            match mode {
                Mode::Echo | Mode::Gated => drop(tokio::spawn(echo(far))),
                Mode::Hold => self.held.lock().unwrap().push(far),
                Mode::Flood => drop(tokio::spawn(flood(far))),
                Mode::Greet => drop(tokio::spawn(greet(far))),
                Mode::Explode | Mode::Refuse(_) | Mode::Pending | Mode::PanicRoute => drop(far),
            }
            let session = self.sessions.fetch_add(1, Ordering::SeqCst) + 1;
            Ok(RoutedStream {
                session_id: format!("session-{session}"),
                stream: Box::new(TestStream {
                    inner: near,
                    explode: mode == Mode::Explode,
                    _alive: Arc::clone(&self.alive),
                }),
            })
        })
    }

    fn released(&self, identity: &UserIdentity, node: &str) {
        assert_eq!(identity.user_id, USER_ID);
        self.released.lock().unwrap().push(node.to_owned());
        assert!(
            !self.failing_releases.load(Ordering::SeqCst),
            "the test release exploded"
        );
    }
}

async fn echo(far: DuplexStream) {
    let (mut read, mut write) = tokio::io::split(far);
    let _ = tokio::io::copy(&mut read, &mut write).await;
    let _ = write.shutdown().await;
}

async fn flood(mut far: DuplexStream) {
    let chunk = pattern(0, 16 * 1024);
    while far.write_all(&chunk).await.is_ok() {}
}

async fn greet(mut far: DuplexStream) {
    let _ = far.write_all(b"bye").await;
    let _ = far.shutdown().await;
    let mut sink = tokio::io::sink();
    let _ = tokio::io::copy(&mut far, &mut sink).await;
}

struct TestStream {
    inner: DuplexStream,
    explode: bool,
    _alive: Arc<()>,
}

impl AsyncRead for TestStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        assert!(!self.explode, "the test backend stream exploded");
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TestStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
pub struct ClientLog {
    failures: Mutex<Vec<(ChannelOpenFailure, String)>>,
    disconnect: Mutex<Option<(String, String)>>,
}

pub struct TestClient {
    log: Arc<ClientLog>,
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn channel_open_failure(
        &mut self,
        _channel: ChannelId,
        reason: ChannelOpenFailure,
        description: &str,
        _language: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.log
            .failures
            .lock()
            .unwrap()
            .push((reason, description.to_owned()));
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        match reason {
            client::DisconnectReason::ReceivedDisconnect(info) => {
                *self.log.disconnect.lock().unwrap() =
                    Some((format!("{:?}", info.reason_code), info.message));
                Ok(())
            }
            client::DisconnectReason::Error(error) => Err(error),
        }
    }
}

pub struct Client {
    pub handle: client::Handle<TestClient>,
    pub serve: JoinHandle<OuterEnd>,
    pub shutdown: CancellationToken,
    log: Arc<ClientLog>,
    user_ca: PrivateKey,
}

impl Client {
    pub async fn authenticate_with(&mut self, ca: &PrivateKey, cert_type: CertType) -> bool {
        let subject = key();
        let now = unix_now();
        let cert = certificate(ca, &subject, cert_type, now - 120, now + 3600);
        self.handle
            .authenticate_openssh_cert("jaunt", Arc::new(subject), cert)
            .await
            .unwrap()
            .success()
    }

    pub async fn authenticate(&mut self) {
        let ca = self.user_ca.clone();
        assert!(self.authenticate_with(&ca, CertType::User).await);
    }

    pub async fn open(&self, host: &str, port: u32) -> Result<Channel<client::Msg>, russh::Error> {
        let open = self
            .handle
            .channel_open_direct_tcpip(host, port, "127.0.0.1", 50_000);
        tokio::time::timeout(STEP, open)
            .await
            .expect("the channel open was not answered")
    }

    pub async fn open_node(&self) -> Channel<client::Msg> {
        self.open(&node(), 22).await.unwrap()
    }

    pub async fn fill(&self, write: &ChannelWriteHalf<client::Msg>) -> usize {
        const PACKET: usize = 256;
        let mut sent = 0;
        loop {
            let room = write.writable_packet_size().await;
            if room == 0 {
                self.handle.send_ping().await.unwrap();
                if write.writable_packet_size().await == 0 {
                    return sent;
                }
                continue;
            }
            let packet = room.min(PACKET);
            write
                .data_bytes(Bytes::from(vec![7; packet]))
                .await
                .unwrap();
            sent += packet;
        }
    }

    pub async fn failure(&self, index: usize) -> (ChannelOpenFailure, String) {
        until("a channel open failure", || {
            self.log.failures.lock().unwrap().len() > index
        })
        .await;
        self.log.failures.lock().unwrap()[index].clone()
    }

    pub async fn disconnect_notice(&self) -> (String, String) {
        until("a disconnect notice", || {
            self.log.disconnect.lock().unwrap().is_some()
        })
        .await;
        self.log.disconnect.lock().unwrap().clone().unwrap()
    }

    pub async fn ended(self) -> OuterEnd {
        let Client { handle, serve, .. } = self;
        handle
            .disconnect(Disconnect::ByApplication, "bye", "en")
            .await
            .unwrap();
        drop(handle);
        finished(serve).await
    }
}

pub async fn finished(serve: JoinHandle<OuterEnd>) -> OuterEnd {
    tokio::time::timeout(STEP, serve)
        .await
        .expect("serve did not return")
        .unwrap()
}

pub struct Received {
    pub data: Vec<u8>,
    pub eof: bool,
    pub closed: bool,
}

pub async fn drain(read: &mut russh::ChannelReadHalf) -> Received {
    let mut received = Received {
        data: Vec::new(),
        eof: false,
        closed: false,
    };
    loop {
        let message = tokio::time::timeout(STEP, read.wait())
            .await
            .expect("the channel went quiet");
        match message {
            Some(ChannelMsg::Data { data }) => received.data.extend_from_slice(&data),
            Some(ChannelMsg::Eof) => received.eof = true,
            Some(ChannelMsg::Close) => {
                received.closed = true;
                return received;
            }
            None => return received,
            Some(_) => {}
        }
    }
}

pub async fn next_data(read: &mut russh::ChannelReadHalf) -> Bytes {
    loop {
        match read.wait().await {
            Some(ChannelMsg::Data { data }) => return data,
            Some(_) => {}
            None => panic!("the channel ended before any data"),
        }
    }
}

pub async fn send(write: &ChannelWriteHalf<client::Msg>, data: &'static [u8]) {
    write.data_bytes(Bytes::from_static(data)).await.unwrap();
}

pub struct Gate {
    pub hop: Arc<OuterHop>,
    pub backend: Arc<Backend>,
    pub permits: Arc<Semaphore>,
    pub cas: Arc<UserCaSource>,
    pub user_ca: PrivateKey,
    pub host_ca: PrivateKey,
    events: Arc<Mutex<Vec<OuterEvent>>>,
    failing_events: Arc<AtomicBool>,
}

impl Gate {
    pub fn new(limits: OuterLimits, mode: Mode) -> Self {
        Self::with_clock_shift(limits, mode, 0)
    }

    pub fn with_clock_shift(limits: OuterLimits, mode: Mode, shift_secs: i64) -> Self {
        let host_ca = key();
        let host = HostKey::generate().unwrap();
        let public = PublicKey::from_openssh(&host.public_openssh().unwrap()).unwrap();
        let now = unix_now();
        let mut builder = Builder::new_with_random_nonce(
            &mut safe_rng(),
            public.key_data().clone(),
            now - 60,
            now + 3600,
        )
        .unwrap();
        builder.serial(1).unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.key_id("jaunt-host:gate.test:1").unwrap();
        builder.valid_principal("gate.test").unwrap();
        let host_cert = builder.sign(&host_ca).unwrap();
        let identity = host
            .with_certificate(&host_cert.to_openssh().unwrap(), now)
            .unwrap();
        let config = Arc::new(ServerConfigCell::new(identity, ServerProfile::Gate));
        let user_ca = key();
        let cas = Arc::new(UserCaSource::new(trust(&user_ca)));
        let backend = Backend::new(mode);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&events);
        let failing_events = Arc::new(AtomicBool::new(false));
        let failing = Arc::clone(&failing_events);
        let shift = Duration::from_secs(shift_secs.unsigned_abs());
        let hop = OuterHop::new(config, Arc::clone(&cas), SUFFIX, limits, backend.clone())
            .with_events(move |event| {
                let closed = matches!(event, OuterEvent::ForwardClosed { .. });
                sink.lock().unwrap().push(event);
                assert!(
                    !(closed && failing.load(Ordering::SeqCst)),
                    "the test event sink exploded"
                );
            })
            .with_clock(move || {
                if shift_secs >= 0 {
                    SystemTime::now() + shift
                } else {
                    SystemTime::now() - shift
                }
            });
        Self {
            hop: Arc::new(hop),
            backend,
            permits: Arc::new(Semaphore::new(PERMITS)),
            cas,
            user_ca,
            host_ca,
            events,
            failing_events,
        }
    }

    pub fn fail_closed_events(&self) {
        self.failing_events.store(true, Ordering::SeqCst);
    }

    pub fn idle_permits(&self) -> bool {
        self.permits.available_permits() == PERMITS
    }

    pub fn events(&self) -> Vec<OuterEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn denials(&self) -> Vec<AuthDenial> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                OuterEvent::AuthDenied { reason, login } => {
                    assert_eq!(login, "jaunt");
                    Some(reason)
                }
                _ => None,
            })
            .collect()
    }

    pub fn stream_ends(&self) -> Vec<(StreamEnd, u64, u64)> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                OuterEvent::ForwardClosed {
                    reason,
                    bytes_up,
                    bytes_down,
                    ..
                } => Some((reason, bytes_up, bytes_down)),
                _ => None,
            })
            .collect()
    }

    pub async fn closed_forwards(&self, count: usize) -> Vec<(StreamEnd, u64, u64)> {
        until("forwards to close", || self.stream_ends().len() >= count).await;
        let ends = self.stream_ends();
        assert_eq!(ends.len(), count);
        assert_eq!(self.backend.released(), count);
        ends
    }

    pub async fn closed_reasons(&self, count: usize) -> Vec<StreamEnd> {
        let ends = self.closed_forwards(count).await;
        ends.into_iter().map(|end| end.0).collect()
    }

    pub fn assert_settled(&self, reasons: &[StreamEnd]) {
        let ends: Vec<_> = self.stream_ends().into_iter().map(|end| end.0).collect();
        assert_eq!(ends, reasons);
        assert_eq!(self.backend.released(), reasons.len());
        assert_eq!(self.backend.live(), 0);
        assert_eq!(self.backend.routing(), 0);
    }

    fn start(&self, server_io: DuplexStream) -> (JoinHandle<OuterEnd>, CancellationToken) {
        let permit = Arc::clone(&self.permits).try_acquire_owned().unwrap();
        let hop = Arc::clone(&self.hop);
        let shutdown = CancellationToken::new();
        let stop = shutdown.clone();
        let client_addr = SocketAddr::from(([192, 0, 2, 7], 40_022));
        let serve =
            tokio::spawn(async move { hop.serve(server_io, client_addr, permit, stop).await });
        (serve, shutdown)
    }

    pub fn serve(&self) -> (DuplexStream, JoinHandle<OuterEnd>, CancellationToken) {
        let (client_io, server_io) = tokio::io::duplex(TRANSPORT);
        let (serve, shutdown) = self.start(server_io);
        (client_io, serve, shutdown)
    }

    pub async fn connect(&self) -> Client {
        self.connect_with(client::Config::default()).await
    }

    pub async fn connect_with(&self, config: client::Config) -> Client {
        let (io, serve, shutdown) = self.serve();
        self.connect_over(io, serve, shutdown, config).await
    }

    pub async fn connect_held_open(&self) -> Client {
        let (client_io, relay_client) = tokio::io::duplex(TRANSPORT);
        let (relay_server, server_io) = tokio::io::duplex(TRANSPORT);
        let (serve, shutdown) = self.start(server_io);
        tokio::spawn(async move {
            let (mut server_read, mut server_write) = tokio::io::split(relay_server);
            let (mut client_read, mut client_write) = tokio::io::split(relay_client);
            let up = async {
                let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
                std::future::pending::<()>().await;
            };
            let down = async {
                let _ = tokio::io::copy(&mut server_read, &mut client_write).await;
                std::future::pending::<()>().await;
            };
            tokio::join!(up, down);
        });
        self.connect_over(client_io, serve, shutdown, client::Config::default())
            .await
    }

    async fn connect_over(
        &self,
        io: DuplexStream,
        serve: JoinHandle<OuterEnd>,
        shutdown: CancellationToken,
        config: client::Config,
    ) -> Client {
        let log = Arc::new(ClientLog::default());
        let handler = TestClient {
            log: Arc::clone(&log),
        };
        let handle =
            tokio::time::timeout(STEP, client::connect_stream(Arc::new(config), io, handler))
                .await
                .expect("the handshake hung")
                .unwrap();
        Client {
            handle,
            serve,
            shutdown,
            log,
            user_ca: self.user_ca.clone(),
        }
    }

    pub async fn login(&self) -> Client {
        let mut client = self.connect().await;
        client.authenticate().await;
        client
    }
}
