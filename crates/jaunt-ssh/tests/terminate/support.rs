use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, BoxFuture, DenyReason, SessionEnd, SessionPermissions,
};
use jaunt_ssh::{
    AgentLimits, AuthorityError, ChannelExit, ChannelStart, ForwardTarget, HostKey, InnerCa,
    InnerTarget, ObserverFactory, OutputStream, Recording, ServerConfigCell, ServerProfile,
    SessionAuthority, SessionObserver, SessionOutcome, StreamContext, TerminalSize, Terminator,
    TunnelStream, UserCaKeys, UserCaSource,
};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelMsg, client};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

use crate::sshd::{FakeSshd, SshdOptions};

pub const STEP: Duration = Duration::from_secs(20);
pub const TRANSPORT: usize = 8 * 1024 * 1024;
pub const OUTPUT_WINDOW: usize = jaunt_ssh::OUTPUT_WINDOW as usize;
pub const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
pub const SESSION_ID: &str = "4f1c2a8e-5d3b-4c6a-9e7f-0a1b2c3d4e5f";
pub const CLIENT_ADDR: &str = "203.0.113.5:40000";
pub const LOGIN: &str = "deploy";
pub const KEY_ID: &str = "jaunt:alice@example.com:42";

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn key() -> PrivateKey {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()
}

pub fn certify(
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
    builder.key_id(KEY_ID).unwrap();
    builder.valid_principal(USER_ID).unwrap();
    builder.extension("permit-pty", "").unwrap();
    builder.sign(ca).unwrap()
}

pub fn permissions() -> SessionPermissions {
    SessionPermissions {
        pty: true,
        port_forwarding: false,
        record_input: true,
        max_duration_secs: 3600,
    }
}

pub fn forwarding() -> SessionPermissions {
    SessionPermissions {
        port_forwarding: true,
        ..permissions()
    }
}

pub async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + STEP;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub enum Decision {
    Allow(SessionPermissions),
    Deny,
    Hang,
}

pub struct FakeAuthority {
    pub end_calls: AtomicUsize,
    end_delay: Duration,
    decision: Decision,
    requests: Mutex<Vec<AuthorizeRequest>>,
    ends: Mutex<Vec<SessionEnd>>,
}

impl FakeAuthority {
    pub fn requests(&self) -> Vec<AuthorizeRequest> {
        self.requests.lock().unwrap().clone()
    }

    pub fn ends(&self) -> Vec<SessionEnd> {
        self.ends.lock().unwrap().clone()
    }
}

impl SessionAuthority for FakeAuthority {
    fn authorize<'a>(
        &'a self,
        request: AuthorizeRequest,
    ) -> BoxFuture<'a, Result<AuthorizeDecision, AuthorityError>> {
        self.requests.lock().unwrap().push(request);
        Box::pin(async move {
            match &self.decision {
                Decision::Allow(permissions) => Ok(AuthorizeDecision::Allow {
                    permissions: *permissions,
                }),
                Decision::Deny => Ok(AuthorizeDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                }),
                Decision::Hang => std::future::pending().await,
            }
        })
    }

    fn session_end<'a>(&'a self, end: SessionEnd) -> BoxFuture<'a, Result<(), AuthorityError>> {
        self.end_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            tokio::time::sleep(self.end_delay).await;
            self.ends.lock().unwrap().push(end);
            Ok(())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Start(u32, ChannelStart),
    Input(u32, usize),
    Output(u32, OutputStream, usize),
    Resize(u32, TerminalSize),
    End(u32, ChannelExit),
    ForwardOpen(u32, ForwardTarget),
    ForwardClose(u32),
    Finish,
}

struct Recorder {
    events: Arc<Mutex<Vec<Event>>>,
    panic_on_output: bool,
    panic_on_input: bool,
    stall: Option<Arc<AtomicBool>>,
    skip: usize,
}

impl ObserverFactory for Recorder {
    fn create(
        &self,
        session_id: &str,
        permissions: &SessionPermissions,
    ) -> Box<dyn SessionObserver> {
        assert_eq!(session_id, SESSION_ID);
        assert!(permissions.record_input);
        Box::new(Recorder {
            events: Arc::clone(&self.events),
            panic_on_output: self.panic_on_output,
            panic_on_input: self.panic_on_input,
            stall: self.stall.clone(),
            skip: self.skip,
        })
    }
}

impl Recorder {
    fn push(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }
}

impl SessionObserver for Recorder {
    fn channel_start(&mut self, channel: u32, start: &ChannelStart) {
        self.push(Event::Start(channel, start.clone()));
    }

    fn input(&mut self, channel: u32, data: &[u8]) {
        assert!(!self.panic_on_input, "the recorder broke");
        self.push(Event::Input(channel, data.len()));
    }

    fn output(&mut self, channel: u32, stream: OutputStream, data: &[u8]) {
        assert!(!self.panic_on_output, "the recorder broke");
        if self.skip > 0 {
            self.skip -= 1;
        } else if let Some(stalled) = self.stall.take() {
            stalled.store(true, Ordering::SeqCst);
            tokio::task::block_in_place(|| std::thread::sleep(Duration::from_secs(3)));
        }
        self.push(Event::Output(channel, stream, data.len()));
    }

    fn resize(&mut self, channel: u32, size: TerminalSize) {
        self.push(Event::Resize(channel, size));
    }

    fn channel_end(&mut self, channel: u32, exit: &ChannelExit) {
        self.push(Event::End(channel, exit.clone()));
    }

    fn forward_open(&mut self, channel: u32, target: &ForwardTarget) {
        self.push(Event::ForwardOpen(channel, target.clone()));
    }

    fn forward_close(&mut self, channel: u32) {
        self.push(Event::ForwardClose(channel));
    }

    fn finish(&mut self) -> Recording {
        self.push(Event::Finish);
        Recording::Complete
    }
}

pub struct Options {
    pub decision: Decision,
    pub limits: AgentLimits,
    pub sshd: SshdOptions,
    pub wrong_pin: bool,
    pub panic_on_output: bool,
    pub panic_on_input: bool,
    pub slow_observer: bool,
    pub skip_outputs: usize,
    pub end_delay: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            decision: Decision::Allow(permissions()),
            limits: AgentLimits::default(),
            sshd: SshdOptions::default(),
            wrong_pin: false,
            panic_on_output: false,
            panic_on_input: false,
            slow_observer: false,
            skip_outputs: 0,
            end_delay: Duration::ZERO,
        }
    }
}

pub struct Fixture {
    pub sshd: FakeSshd,
    pub authority: Arc<FakeAuthority>,
    pub events: Arc<Mutex<Vec<Event>>>,
    pub inner_ca: PublicKey,
    pub user_ca: PrivateKey,
    pub user_key: Arc<PrivateKey>,
    pub cert: Certificate,
    pub stalled: Arc<AtomicBool>,
    terminator: Arc<Terminator>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    pub async fn new(options: Options) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let inner_ca = InnerCa::generate().unwrap();
        let inner_public = PublicKey::from_openssh(&inner_ca.public_openssh().unwrap()).unwrap();
        let sshd = FakeSshd::start(&inner_public, options.sshd).await;
        let pin = dir.path().join("ssh_host_ed25519_key.pub");
        let pinned = if options.wrong_pin {
            key().public_key().clone()
        } else {
            sshd.host_key.clone()
        };
        std::fs::write(&pin, pinned.to_openssh().unwrap()).unwrap();
        let host_ca = key();
        let host = HostKey::generate().unwrap();
        let host_public = PublicKey::from_openssh(&host.public_openssh().unwrap()).unwrap();
        let host_cert = {
            let mut builder = Builder::new_with_random_nonce(
                &mut safe_rng(),
                host_public.key_data().clone(),
                now() - 120,
                now() + 3600,
            )
            .unwrap();
            builder.cert_type(CertType::Host).unwrap();
            builder.key_id("jaunt-host:node1").unwrap();
            builder.valid_principal("node1.jaunt.test").unwrap();
            builder.sign(&host_ca).unwrap()
        };
        let identity = host
            .with_certificate(&host_cert.to_openssh().unwrap(), now())
            .unwrap();
        let config = Arc::new(ServerConfigCell::new(identity, ServerProfile::Agent));
        let user_ca = key();
        let cas =
            UserCaKeys::from_openssh_lines([user_ca.public_key().to_openssh().unwrap()]).unwrap();
        let authority = Arc::new(FakeAuthority {
            end_calls: AtomicUsize::new(0),
            end_delay: options.end_delay,
            decision: options.decision,
            requests: Mutex::new(Vec::new()),
            ends: Mutex::new(Vec::new()),
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let stalled = Arc::new(AtomicBool::new(false));
        let recorder = Arc::new(Recorder {
            events: Arc::clone(&events),
            panic_on_output: options.panic_on_output,
            panic_on_input: options.panic_on_input,
            stall: options.slow_observer.then(|| Arc::clone(&stalled)),
            skip: options.skip_outputs,
        });
        let terminator = Arc::new(Terminator::new(
            config,
            Arc::new(UserCaSource::new(cas)),
            Arc::new(inner_ca),
            InnerTarget {
                sshd_addr: sshd.addr,
                sshd_host_key: pin,
            },
            Arc::clone(&authority) as Arc<dyn SessionAuthority>,
            options.limits,
            recorder,
        ));
        let user_key = key();
        let cert = certify(
            &user_ca,
            &user_key,
            CertType::User,
            now() - 120,
            now() + 3600,
        );
        Self {
            sshd,
            authority,
            events,
            inner_ca: inner_public,
            user_ca,
            user_key: Arc::new(user_key),
            cert,
            stalled,
            terminator,
            _dir: dir,
        }
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    pub fn serve_on<S: TunnelStream>(&self, stream: S, cancel: CancellationToken) -> Serving {
        let terminator = Arc::clone(&self.terminator);
        let stop = cancel.clone();
        let task = tokio::spawn(async move { terminator.serve(stream, context(), stop).await });
        Serving { task, cancel }
    }

    pub fn serve_apart<S: TunnelStream>(&self, stream: S) -> (Serving, Arc<OnceLock<usize>>) {
        let terminator = Arc::clone(&self.terminator);
        let leftover = Arc::new(OnceLock::new());
        let record = Arc::clone(&leftover);
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let outcome = runtime.block_on(terminator.serve(stream, context(), stop));
            record.set(runtime.metrics().num_alive_tasks()).unwrap();
            outcome
        });
        (Serving { task, cancel }, leftover)
    }

    pub async fn connect_over<S>(&self, stream: S, serve: Serving, config: client::Config) -> Client
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let seen = Arc::new(ClientSeen::default());
        let handle = tokio::time::timeout(
            STEP,
            client::connect_stream(Arc::new(config), stream, TestClient(Arc::clone(&seen))),
        )
        .await
        .expect("the agent handshake hung")
        .unwrap();
        Client {
            handle,
            seen,
            serve: serve.task,
            cancel: serve.cancel,
            key: Arc::clone(&self.user_key),
        }
    }

    pub async fn connect(&self) -> Client {
        let (client_io, agent_io) = tokio::io::duplex(TRANSPORT);
        let serve = self.serve_on(agent_io, CancellationToken::new());
        self.connect_over(client_io, serve, client::Config::default())
            .await
    }

    pub async fn login(&self) -> Client {
        let mut client = self.connect().await;
        assert!(client.authenticate(LOGIN, self.cert.clone()).await);
        client
    }
}

#[derive(Default)]
pub struct ClientSeen {
    pub open_failures: Mutex<Vec<String>>,
    pub open_codes: Mutex<Vec<u32>>,
    pub disconnect: Mutex<Option<String>>,
}

pub struct TestClient(Arc<ClientSeen>);

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
        _channel: russh::ChannelId,
        reason: russh::ChannelOpenFailure,
        description: &str,
        _language: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.0.open_codes.lock().unwrap().push(reason.code());
        self.0
            .open_failures
            .lock()
            .unwrap()
            .push(description.to_owned());
        Ok(())
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        if let client::DisconnectReason::ReceivedDisconnect(info) = reason {
            *self.0.disconnect.lock().unwrap() = Some(info.message);
        }
        Ok(())
    }
}

pub struct Serving {
    pub task: JoinHandle<SessionOutcome>,
    pub cancel: CancellationToken,
}

fn context() -> StreamContext {
    StreamContext {
        session_id: SESSION_ID.to_owned(),
        client_addr: CLIENT_ADDR.to_owned(),
    }
}

pub fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

pub struct Client {
    pub handle: client::Handle<TestClient>,
    pub seen: Arc<ClientSeen>,
    pub serve: JoinHandle<SessionOutcome>,
    pub cancel: CancellationToken,
    pub key: Arc<PrivateKey>,
}

impl Client {
    pub async fn authenticate(&mut self, login: &str, cert: Certificate) -> bool {
        let attempt = self
            .handle
            .authenticate_openssh_cert(login, Arc::clone(&self.key), cert);
        match tokio::time::timeout(STEP, attempt).await {
            Ok(Ok(result)) => result.success(),
            Ok(Err(_)) => false,
            Err(_) => panic!("authentication hung"),
        }
    }

    pub async fn open(&self) -> Channel<client::Msg> {
        tokio::time::timeout(STEP, self.handle.channel_open_session())
            .await
            .expect("channel open hung")
            .unwrap()
    }

    pub async fn exec(&self, command: &str) -> Channel<client::Msg> {
        let mut channel = self.open().await;
        channel.exec(true, command).await.unwrap();
        assert!(reply(&mut channel).await, "exec {command} was refused");
        channel
    }

    pub async fn outcome(self) -> SessionOutcome {
        drop(self.handle);
        tokio::time::timeout(STEP, self.serve)
            .await
            .expect("serve did not return")
            .unwrap()
    }

    pub async fn finish(self) -> SessionOutcome {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
        self.outcome().await
    }
}

pub async fn reply(channel: &mut Channel<client::Msg>) -> bool {
    let answer = async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return true,
                Some(ChannelMsg::Failure) | None => return false,
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(other) => panic!("unexpected message before the reply: {other:?}"),
            }
        }
    };
    tokio::time::timeout(STEP, answer)
        .await
        .expect("no reply arrived")
}

#[derive(Debug, Default)]
pub struct Transcript {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_status: Option<u32>,
    pub exit_signal: Option<String>,
    pub order: Vec<&'static str>,
}

pub async fn transcript(channel: &mut Channel<client::Msg>) -> Transcript {
    let mut seen = Transcript::default();
    let reading = async {
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => seen.stdout.extend_from_slice(&data),
                Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                    seen.stderr.extend_from_slice(&data)
                }
                Some(ChannelMsg::Eof) => seen.order.push("eof"),
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    seen.order.push("exit");
                    seen.exit_status = Some(exit_status);
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    seen.order.push("signal");
                    seen.exit_signal = Some(format!("{signal_name:?}"));
                }
                Some(ChannelMsg::Close) | None => break,
                Some(_) => {}
            }
        }
    };
    tokio::time::timeout(STEP, reading)
        .await
        .expect("the channel never closed");
    seen
}

pub async fn read_until(channel: &mut Channel<client::Msg>, needle: &str) -> String {
    let mut text = String::new();
    let reading = async {
        while !text.contains(needle) {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => text.push_str(&String::from_utf8_lossy(&data)),
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                other => panic!("waiting for {needle:?} after {text:?}, got {other:?}"),
            }
        }
    };
    tokio::time::timeout(STEP, reading)
        .await
        .expect("the expected output never came");
    text
}

pub struct Severable<S> {
    inner: S,
    read_cut: Pin<Box<WaitForCancellationFutureOwned>>,
    write_cut: Pin<Box<WaitForCancellationFutureOwned>>,
}

impl<S> Severable<S> {
    pub fn new(inner: S, cut: &CancellationToken) -> Self {
        Self {
            inner,
            read_cut: Box::pin(cut.clone().cancelled_owned()),
            write_cut: Box::pin(cut.clone().cancelled_owned()),
        }
    }
}

fn severed(cut: Pin<&mut WaitForCancellationFutureOwned>, cx: &mut Context<'_>) -> bool {
    cut.poll(cx).is_ready()
}

fn aborted<T>() -> Poll<std::io::Result<T>> {
    Poll::Ready(Err(std::io::ErrorKind::ConnectionAborted.into()))
}

impl<S: AsyncRead + Unpin> AsyncRead for Severable<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if severed(this.read_cut.as_mut(), cx) {
            return aborted();
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Severable<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if severed(this.write_cut.as_mut(), cx) {
            return aborted();
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if severed(this.write_cut.as_mut(), cx) {
            return aborted();
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct Tap<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S> Tap<S> {
    pub fn new(inner: S, seen: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, seen }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        this.seen
            .lock()
            .unwrap()
            .extend_from_slice(&buf.filled()[before..]);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            this.seen.lock().unwrap().extend_from_slice(&buf[..written]);
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
