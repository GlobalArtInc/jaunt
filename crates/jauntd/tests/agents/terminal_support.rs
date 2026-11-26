use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use axum::extract::ConnectInfo;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Method, Request, StatusCode, header};
use jaunt_control::{Clock, Ticker, WebTerminalSettings};
use jaunt_gate::DEFAULT_SSH_CLIENT_LIMITS;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlPlane, NodeCaller, SessionEnd, SessionPermissions,
};
use jaunt_record::{Recorder, RecorderConfig, SessionKind, SessionManifest, SystemClock};
use jaunt_ssh::{
    AgentLimits, AuthorityError, ChannelExit, ChannelProgram, ChannelStart, EphemeralKey,
    HostIdentity, InnerCa, InnerTarget, KeyWatch, ObserverFactory, OutputStream, Recording,
    ServerConfigCell, ServerProfile, SessionAuthority, SessionInfo, SessionObserver, StreamContext,
    Terminal, TerminalSize, Terminator, UserCaKeys, UserCaSource,
};
use jaunt_store::NewUser;
use jaunt_tunnel::{BoxFuture, IncomingStream, NodeId, StreamHandler};
use jauntd::gate_ssh::{GateSshParts, GateSshServer, GateSshSettings, HostAuthorityIssuer};
use jauntd::killer::InProcessKiller;
use jauntd::presence::RegistryPresence;
use jauntd::web_terminal::GateTerminals;
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer};
use russh::{Channel, ChannelId, ChannelWriteHalf};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};
use tokio_tungstenite::{WebSocketStream, client_async_with_config};
use tower::ServiceExt;

use crate::support::{
    EnrolledAgent, Harness, Options, PUBLIC_ORIGIN, TestAgent, eventually, spawn_agent_with,
    unix_secs,
};

pub const NODE: &str = "web-01";
pub const RECORDED_LOGIN: &str = "deploy";
pub const PLAIN_LOGIN: &str = "plain";
pub const BROWSER_ADDR: &str = "203.0.113.9";
pub const STEP: Duration = Duration::from_secs(20);
pub const SSHD_WINDOW: u32 = 64 * 1024;
pub const HOSTILE: &[u8] = b"\x1b]0;owned\x07\x1b[2J\x1b[?1049h\x9b31m\xff\xfe\x00tail\r\n";
const FLOOD_CHUNK: usize = 32 * 1024;
const TICKS: usize = 45;
const TICK_EVERY: Duration = Duration::from_millis(200);
const QUIET_WATCHERS: Duration = Duration::from_secs(3600);
const EAGER_SWEEP: Duration = Duration::from_millis(50);
const GATE_NAME: &str = "gate.jaunt.test";
const ROLES: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: recorded }\nspec:\n  \
     members: { users: [alice@example.com, bob@example.com, carol@example.com] }\n  \
     ssh: { nodes: { env: [test] }, logins: [deploy], recordInput: true }\n---\n\
     apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: plain }\nspec:\n  \
     members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [test] }, logins: [plain] }\n";
const ROLES_WITHOUT_DEPLOY: &str = "apiVersion: jaunt/v1\nkind: Role\nmetadata: { name: plain }\nspec:\n  \
     members: { users: [alice@example.com] }\n  ssh: { nodes: { env: [test] }, logins: [plain] }\n";

#[derive(Clone, Default)]
pub struct ManualTime {
    clock_secs: Arc<AtomicU64>,
    tick_secs: Arc<AtomicU64>,
}

impl ManualTime {
    pub fn advance_clock(&self, by: Duration) {
        self.clock_secs.fetch_add(by.as_secs(), Ordering::SeqCst);
    }

    pub fn advance_ticker(&self, by: Duration) {
        self.tick_secs.fetch_add(by.as_secs(), Ordering::SeqCst);
    }

    fn clock(&self) -> Clock {
        let offset = Arc::clone(&self.clock_secs);
        Arc::new(move || SystemTime::now() + Duration::from_secs(offset.load(Ordering::SeqCst)))
    }

    fn ticker(&self) -> Ticker {
        let offset = Arc::clone(&self.tick_secs);
        let origin = Instant::now();
        Arc::new(move || origin.elapsed() + Duration::from_secs(offset.load(Ordering::SeqCst)))
    }
}

#[derive(Default)]
pub struct SshdLog {
    pub logins: AtomicUsize,
    pub flooded: AtomicU64,
    pub input: AtomicU64,
    pub tasks: AtomicUsize,
    sinking: AtomicBool,
}

struct Running(Arc<SshdLog>);

impl Running {
    fn start(log: &Arc<SshdLog>) -> Running {
        log.tasks.fetch_add(1, Ordering::SeqCst);
        Running(Arc::clone(log))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.tasks.fetch_sub(1, Ordering::SeqCst);
    }
}

enum ShellInput {
    Echo(Vec<u8>),
    Line(String),
    Resize(u32, u32),
}

struct SshdConnection {
    log: Arc<SshdLog>,
    connected: watch::Sender<()>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    shells: HashMap<ChannelId, mpsc::UnboundedSender<ShellInput>>,
    sizes: HashMap<ChannelId, (u32, u32)>,
    lines: HashMap<ChannelId, Vec<u8>>,
}

impl SshdConnection {
    fn feed(&mut self, channel: ChannelId, input: ShellInput) {
        if let Some(shell) = self.shells.get(&channel) {
            drop(shell.send(input));
        }
    }
}

impl server::Handler for SshdConnection {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.log.logins.fetch_add(1, Ordering::SeqCst);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.sizes.insert(channel, (col_width, row_height));
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let Some(opened) = self.channels.remove(&channel) else {
            return session.channel_failure(channel);
        };
        session.channel_success(channel)?;
        let (_read, write) = opened.split();
        let (sender, receiver) = mpsc::unbounded_channel();
        let size = self.sizes.get(&channel).copied().unwrap_or((80, 24));
        let running = Running::start(&self.log);
        let mut connection = self.connected.subscribe();
        let program = shell(
            Shell {
                write,
                handle: session.handle(),
                channel,
            },
            receiver,
            size,
            Arc::clone(&self.log),
        );
        tokio::spawn(async move {
            let _running = running;
            tokio::select! {
                () = program => {}
                _ = connection.changed() => {}
            }
        });
        self.shells.insert(channel, sender);
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.feed(channel, ShellInput::Resize(col_width, row_height));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.log
            .input
            .fetch_add(u64::try_from(data.len()).unwrap(), Ordering::SeqCst);
        if self.log.sinking.load(Ordering::SeqCst) {
            return Ok(());
        }
        session
            .handle()
            .grant_window(channel, u32::try_from(data.len()).unwrap())
            .unwrap();
        self.feed(channel, ShellInput::Echo(data.to_vec()));
        let mut finished = Vec::new();
        let line = self.lines.entry(channel).or_default();
        for byte in data {
            if *byte == b'\r' || *byte == b'\n' {
                finished.push(String::from_utf8_lossy(line).into_owned());
                line.clear();
            } else {
                line.push(*byte);
            }
        }
        for line in finished {
            self.feed(channel, ShellInput::Line(line));
        }
        Ok(())
    }
}

struct Shell {
    write: ChannelWriteHalf<Msg>,
    handle: server::Handle,
    channel: ChannelId,
}

async fn shell(
    terminal: Shell,
    mut input: mpsc::UnboundedReceiver<ShellInput>,
    mut size: (u32, u32),
    log: Arc<SshdLog>,
) {
    let write = &terminal.write;
    while let Some(next) = input.recv().await {
        let written = match next {
            ShellInput::Echo(bytes) => write.data_bytes(Bytes::from(bytes)).await,
            ShellInput::Resize(cols, rows) => {
                size = (cols, rows);
                Ok(())
            }
            ShellInput::Line(line) => match line.as_str() {
                "size" => {
                    write
                        .data_bytes(Bytes::from(format!("{}x{}\r\n", size.0, size.1)))
                        .await
                }
                "hostile" => write.data_bytes(Bytes::from_static(HOSTILE)).await,
                "ticker" => {
                    let mut written = Ok(());
                    for _ in 0..TICKS {
                        tokio::time::sleep(TICK_EVERY).await;
                        written = write.data_bytes(Bytes::from_static(b"tick\r\n")).await;
                        if written.is_err() {
                            break;
                        }
                    }
                    written
                }
                "sink" => {
                    log.sinking.store(true, Ordering::SeqCst);
                    write.data_bytes(Bytes::from_static(b"sinking\r\n")).await
                }
                "flood" => {
                    let chunk = Bytes::from(vec![b'x'; FLOOD_CHUNK]);
                    while write.data_bytes(chunk.clone()).await.is_ok() {
                        log.flooded
                            .fetch_add(u64::try_from(FLOOD_CHUNK).unwrap(), Ordering::SeqCst);
                    }
                    return;
                }
                "signal" => {
                    drop(write.data_bytes(Bytes::from_static(b"bye\r\n")).await);
                    terminal
                        .handle
                        .exit_signal_request(
                            terminal.channel,
                            russh::Sig::TERM,
                            false,
                            String::new(),
                            "en".to_owned(),
                        )
                        .await
                        .unwrap();
                    drop(write.eof().await);
                    drop(write.close().await);
                    return;
                }
                command => match command.strip_prefix("exit ") {
                    Some(status) => {
                        let status: u32 = status.trim().parse().unwrap();
                        drop(write.data_bytes(Bytes::from_static(b"bye\r\n")).await);
                        drop(write.exit_status(status).await);
                        drop(write.eof().await);
                        drop(write.close().await);
                        return;
                    }
                    None => Ok(()),
                },
            },
        };
        if written.is_err() {
            return;
        }
    }
}

pub struct FakeSshd {
    pub log: Arc<SshdLog>,
    target: InnerTarget,
    task: JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl FakeSshd {
    async fn start() -> FakeSshd {
        let dir = tempfile::tempdir().unwrap();
        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let pin: PathBuf = dir.path().join("ssh_host_ed25519_key.pub");
        std::fs::write(&pin, key.public_key().to_openssh().unwrap()).unwrap();
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::from_millis(10),
            auth_rejection_time_initial: Some(Duration::ZERO),
            manual_window: true,
            window_size: SSHD_WINDOW,
            maximum_packet_size: 32 * 1024,
            ..server::Config::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(SshdLog::default());
        let shared = Arc::clone(&log);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let handler = SshdConnection {
                    log: Arc::clone(&shared),
                    connected: watch::channel(()).0,
                    channels: HashMap::new(),
                    shells: HashMap::new(),
                    sizes: HashMap::new(),
                    lines: HashMap::new(),
                };
                let config = Arc::clone(&config);
                let connection = Running::start(&shared);
                tokio::spawn(async move {
                    let _connection = connection;
                    if let Ok(running) = server::run_stream(config, tcp, handler).await {
                        drop(running.await);
                    }
                });
            }
        });
        FakeSshd {
            log,
            target: InnerTarget {
                sshd_addr: addr,
                sshd_host_key: pin,
            },
            task,
            _dir: dir,
        }
    }
}

impl Drop for FakeSshd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone, Default)]
pub struct Recorded {
    pub record_input: bool,
    pub terminal: Option<Terminal>,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub resizes: Vec<TerminalSize>,
    pub exit: Option<ChannelExit>,
    pub manifest: Option<SessionManifest>,
    pub cast: String,
}

#[derive(Default)]
pub struct Capture {
    sessions: Mutex<HashMap<String, Recorded>>,
}

impl Capture {
    pub fn of(&self, session_id: &str) -> Option<Recorded> {
        self.sessions.lock().unwrap().get(session_id).cloned()
    }

    fn update(&self, session_id: &str, change: impl FnOnce(&mut Recorded)) {
        let mut sessions = self.sessions.lock().unwrap();
        change(sessions.entry(session_id.to_owned()).or_default());
    }
}

struct CaptureObserver {
    capture: Arc<Capture>,
    info: SessionInfo,
    record_input: bool,
    recorder: Option<Recorder>,
}

impl CaptureObserver {
    fn finish_recording(&mut self, exit: &ChannelExit) {
        let Some(mut recorder) = self.recorder.take() else {
            return;
        };
        let status = match exit {
            ChannelExit::Status(status) => i32::try_from(*status).ok(),
            ChannelExit::Signal(_) | ChannelExit::Unknown => None,
        };
        let manifest = recorder
            .finish(status, unix_secs(SystemTime::now()))
            .unwrap();
        let cast: String = recorder
            .take_chunks()
            .iter()
            .map(|chunk| {
                let raw = zstd::bulk::decompress(
                    &chunk.compressed,
                    usize::try_from(chunk.raw_len).unwrap(),
                )
                .unwrap();
                String::from_utf8(raw).unwrap()
            })
            .collect();
        self.capture.update(&self.info.session_id, |recorded| {
            recorded.manifest = Some(manifest);
            recorded.cast = cast;
        });
    }
}

impl SessionObserver for CaptureObserver {
    fn channel_start(&mut self, _channel: u32, start: &ChannelStart) {
        if let (ChannelProgram::Shell, Some(terminal)) = (&start.program, &start.terminal) {
            self.recorder = Some(
                Recorder::new(
                    RecorderConfig {
                        session_id: self.info.session_id.clone(),
                        kind: SessionKind::Shell,
                        node: NODE.to_owned(),
                        user: self.info.user_id.clone(),
                        login: self.info.login.clone(),
                        command: None,
                        started_at: unix_secs(SystemTime::now()),
                        width: u16::try_from(terminal.size.columns).unwrap(),
                        height: u16::try_from(terminal.size.rows).unwrap(),
                        shell: "sh".to_owned(),
                        term: terminal.term.clone(),
                        record_input: self.record_input,
                    },
                    Box::new(SystemClock::start()),
                )
                .unwrap(),
            );
            let terminal = terminal.clone();
            self.capture.update(&self.info.session_id, |recorded| {
                recorded.terminal = Some(terminal);
            });
        }
    }

    fn input(&mut self, _channel: u32, data: &[u8]) {
        if let Some(recorder) = &mut self.recorder {
            recorder.push_input(data).unwrap();
        }
        self.capture.update(&self.info.session_id, |recorded| {
            recorded.input.extend_from_slice(data);
        });
    }

    fn output(&mut self, _channel: u32, _stream: OutputStream, data: &[u8]) {
        if let Some(recorder) = &mut self.recorder {
            recorder.push_output(data).unwrap();
        }
        self.capture.update(&self.info.session_id, |recorded| {
            recorded.output.extend_from_slice(data);
        });
    }

    fn resize(&mut self, _channel: u32, size: TerminalSize) {
        if let Some(recorder) = &mut self.recorder {
            recorder
                .resize(
                    u16::try_from(size.columns).unwrap(),
                    u16::try_from(size.rows).unwrap(),
                )
                .unwrap();
        }
        self.capture.update(&self.info.session_id, |recorded| {
            recorded.resizes.push(size)
        });
    }

    fn channel_end(&mut self, _channel: u32, exit: &ChannelExit) {
        self.finish_recording(exit);
        let exit = exit.clone();
        self.capture
            .update(&self.info.session_id, |recorded| recorded.exit = Some(exit));
    }

    fn finish(&mut self) -> Recording {
        Recording::Complete
    }
}

struct CaptureFactory(Arc<Capture>);

impl ObserverFactory for CaptureFactory {
    fn create(
        &self,
        session: &SessionInfo,
        permissions: &SessionPermissions,
    ) -> Box<dyn SessionObserver> {
        let record_input = permissions.record_input;
        self.0.update(&session.session_id, |recorded| {
            recorded.record_input = record_input;
        });
        Box::new(CaptureObserver {
            capture: Arc::clone(&self.0),
            info: session.clone(),
            record_input,
            recorder: None,
        })
    }
}

struct ControlAuthority {
    control: jaunt_control::Control,
    node_id: String,
}

impl SessionAuthority for ControlAuthority {
    fn authorize<'a>(
        &'a self,
        request: AuthorizeRequest,
    ) -> BoxFuture<'a, Result<AuthorizeDecision, AuthorityError>> {
        Box::pin(async move {
            self.control
                .authorize(NodeCaller(self.node_id.clone()), request)
                .await
                .map_err(|_| AuthorityError::Unavailable)
        })
    }

    fn session_end<'a>(&'a self, end: SessionEnd) -> BoxFuture<'a, Result<(), AuthorityError>> {
        Box::pin(async move {
            self.control
                .session_end(NodeCaller(self.node_id.clone()), end)
                .await
                .map(|_| ())
                .map_err(|_| AuthorityError::Unavailable)
        })
    }
}

struct TerminalAgent(Arc<Terminator>);

impl StreamHandler for TerminalAgent {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let terminator = Arc::clone(&self.0);
        Box::pin(async move {
            let context = StreamContext {
                session_id: stream.meta.session().as_str().to_owned(),
                client_addr: stream.meta.client().to_owned(),
            };
            terminator.serve(stream.io, context, stream.cancel).await;
        })
    }
}

fn foreign_host_certificate(enrolled: &EnrolledAgent) -> String {
    let host_key = PrivateKey::from_openssh(&enrolled.ssh_private_openssh).unwrap();
    let stranger = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let now = unix_secs(SystemTime::now());
    let mut builder = Builder::new_with_random_nonce(
        &mut safe_rng(),
        host_key.public_key().key_data().clone(),
        now - 60,
        now + 3600,
    )
    .unwrap();
    builder.serial(1).unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.key_id("jaunt-host:web-01.jaunt.test:1").unwrap();
    builder
        .valid_principal(format!("{NODE}.jaunt.test"))
        .unwrap();
    builder.valid_principal(NODE).unwrap();
    builder.sign(&stranger).unwrap().to_openssh().unwrap()
}

fn terminal_agent(
    harness: &Harness,
    enrolled: &EnrolledAgent,
    sshd: &FakeSshd,
    capture: &Arc<Capture>,
    foreign: bool,
) -> TestAgent {
    let certificate = if foreign {
        foreign_host_certificate(enrolled)
    } else {
        enrolled.ssh_certificate.clone()
    };
    let identity = HostIdentity::from_openssh(
        enrolled.ssh_private_openssh.as_bytes(),
        certificate.as_bytes(),
        unix_secs(SystemTime::now()),
    )
    .unwrap();
    let cas = Arc::new(UserCaSource::new(
        UserCaKeys::from_openssh_lines(harness.authorities.user_lines.clone()).unwrap(),
    ));
    let terminator = Terminator::new(
        Arc::new(ServerConfigCell::new(identity, ServerProfile::Agent)),
        cas,
        Arc::new(InnerCa::generate().unwrap()),
        sshd.target.clone(),
        Arc::new(ControlAuthority {
            control: harness.control.clone(),
            node_id: enrolled.node_id.clone(),
        }),
        AgentLimits::default(),
        Arc::new(CaptureFactory(Arc::clone(capture))),
    );
    spawn_agent_with(
        harness,
        enrolled,
        Arc::new(TerminalAgent(Arc::new(terminator))),
    )
}

pub struct Browser {
    pub user_id: String,
    pub cookie: String,
    pub csrf: String,
}

#[derive(Default)]
pub struct Keys {
    seeds: Mutex<Vec<[u8; 32]>>,
    watches: Mutex<Vec<KeyWatch>>,
}

impl Keys {
    pub fn seeds(&self) -> Vec<[u8; 32]> {
        self.seeds.lock().unwrap().clone()
    }

    pub fn all_released(&self) -> bool {
        self.watches.lock().unwrap().iter().all(KeyWatch::released)
    }
}

#[derive(Default)]
pub struct StandOptions {
    pub settings: WebTerminalSettings,
    pub time: Option<ManualTime>,
    pub quiet_watchers: bool,
    pub eager_sweep: bool,
    pub foreign_host_certificate: bool,
}

pub struct TerminalStand {
    pub harness: Harness,
    pub gate: GateSshServer,
    pub sshd: FakeSshd,
    pub capture: Arc<Capture>,
    pub keys: Arc<Keys>,
    pub node_id: String,
    pub http: SocketAddr,
    pub alice: Browser,
    pub bob: Browser,
    pub carol: Browser,
    agent: Option<TestAgent>,
    _stop_http: oneshot::Sender<()>,
}

impl TerminalStand {
    pub async fn start() -> TerminalStand {
        TerminalStand::start_with(StandOptions::default()).await
    }

    pub async fn start_with(options: StandOptions) -> TerminalStand {
        let harness = Harness::start(Options {
            web: true,
            forwarded_for: true,
            control_clock: options.time.as_ref().map(ManualTime::clock),
            control_ticker: options.time.as_ref().map(ManualTime::ticker),
            session_sweep_interval: if options.quiet_watchers {
                Some(QUIET_WATCHERS)
            } else {
                options.eager_sweep.then_some(EAGER_SWEEP)
            },
            agent_gone_after: options.eager_sweep.then_some(Duration::ZERO),
            revocation_watch_interval: options.quiet_watchers.then_some(QUIET_WATCHERS),
            ..Options::default()
        })
        .await;
        load_roles(&harness, ROLES);
        let enrolled = harness.enroll(NODE).await;
        let sshd = FakeSshd::start().await;
        let capture = Arc::new(Capture::default());
        let agent = terminal_agent(
            &harness,
            &enrolled,
            &sshd,
            &capture,
            options.foreign_host_certificate,
        );
        let registry = harness.server.registry().clone();
        let node = NodeId::new(enrolled.node_id.clone()).unwrap();
        eventually("the agent tunnel", || registry.is_connected(&node)).await;
        let gate = GateSshServer::start(GateSshParts {
            settings: GateSshSettings {
                listen: "127.0.0.1:0".parse().unwrap(),
                hostnames: vec![GATE_NAME.to_owned()],
                proxy_protocol: false,
                trusted_proxies: Vec::new(),
                max_unauthenticated: 16,
                write_stall: Some(Duration::from_secs(900)),
                client_limits: DEFAULT_SSH_CLIENT_LIMITS,
            },
            ssh_suffix: "jaunt.test".to_owned(),
            issuer: Arc::new(HostAuthorityIssuer::following(
                harness.control.clone(),
                harness.store.clone(),
                Arc::new(SystemTime::now),
            )),
            user_cas: Arc::new(UserCaSource::new(
                UserCaKeys::from_openssh_lines(harness.authorities.user_lines.clone()).unwrap(),
            )),
            control: Arc::new(harness.control.clone()),
            registry: harness.server.registry().clone(),
        })
        .await
        .unwrap();
        harness
            .control
            .install_session_killer(Arc::new(InProcessKiller::new(
                harness.server.agents(),
                Some(Arc::clone(gate.gate())),
            )));
        harness
            .control
            .install_agent_presence(Arc::new(RegistryPresence::new(harness.server.agents())));
        harness.control.install_web_terminal(
            Arc::new(GateTerminals::new(Arc::clone(gate.gate()))),
            options.settings,
        );
        let keys = Arc::new(Keys::default());
        let source = Arc::clone(&keys);
        harness.control.use_web_terminal_keys(move || {
            let seed = random_seed();
            let key = EphemeralKey::from_seed(&seed);
            source.seeds.lock().unwrap().push(seed);
            source.watches.lock().unwrap().push(key.watch());
            Ok(key)
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http = listener.local_addr().unwrap();
        let (stop_http, stopped) = oneshot::channel::<()>();
        let serving = harness.control.clone();
        tokio::spawn(async move {
            serving
                .serve(listener, async move {
                    drop(stopped.await);
                })
                .await
                .unwrap();
        });
        let alice = browser(&harness, "alice").await;
        let bob = browser(&harness, "bob").await;
        let carol = browser(&harness, "carol").await;
        TerminalStand {
            harness,
            gate,
            sshd,
            capture,
            keys,
            node_id: enrolled.node_id,
            http,
            alice,
            bob,
            carol,
            agent: Some(agent),
            _stop_http: stop_http,
        }
    }

    pub async fn cut_agent(&mut self) {
        if let Some(agent) = self.agent.take() {
            agent.stop().await;
        }
    }

    pub fn deny_the_recorded_login(&self) {
        load_roles(&self.harness, ROLES_WITHOUT_DEPLOY);
    }

    pub async fn ticket(&self, who: &Browser, login: &str) -> String {
        let reply = self
            .post(
                who,
                "/v1/web/terminal/ticket",
                &json!({"node": NODE, "login": login}),
            )
            .await;
        assert_eq!(reply.0, StatusCode::OK, "{}", reply.1);
        reply.1["ticket"].as_str().unwrap().to_owned()
    }

    pub async fn post(&self, who: &Browser, path: &str, body: &Value) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::COOKIE, &who.cookie)
            .header("x-jaunt-csrf", &who.csrf)
            .header(header::ORIGIN, PUBLIC_ORIGIN)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:40000".parse::<SocketAddr>().unwrap(),
        ));
        let response = self
            .harness
            .control
            .router()
            .oneshot(request)
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    pub async fn open(&self, who: &Browser, login: &str) -> Ws {
        let ticket = self.ticket(who, login).await;
        self.open_with_ticket(who, login, &ticket).await.unwrap()
    }

    pub async fn open_with_ticket(
        &self,
        who: &Browser,
        login: &str,
        ticket: &str,
    ) -> Result<Ws, StatusCode> {
        let tcp = TcpStream::connect(self.http).await.unwrap();
        let url = format!(
            "ws://{}/v1/web/terminal?node={NODE}&login={login}&cols=80&rows=24",
            self.http
        );
        let mut request = url.into_client_request().unwrap();
        let headers = request.headers_mut();
        headers.insert(header::ORIGIN, PUBLIC_ORIGIN.parse().unwrap());
        headers.insert(header::COOKIE, who.cookie.parse().unwrap());
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            format!("jaunt-terminal.v1, jaunt-ticket.{ticket}")
                .parse()
                .unwrap(),
        );
        headers.insert("x-forwarded-for", BROWSER_ADDR.parse().unwrap());
        let config = WebSocketConfig::default().max_message_size(Some(64 << 20));
        match client_async_with_config(request, tcp, Some(config)).await {
            Ok((socket, response)) => {
                assert_eq!(
                    response.headers()[header::SEC_WEBSOCKET_PROTOCOL],
                    "jaunt-terminal.v1"
                );
                Ok(Ws {
                    socket,
                    output: Vec::new(),
                })
            }
            Err(tungstenite::Error::Http(response)) => Err(response.status()),
            Err(other) => panic!("the websocket handshake failed: {other}"),
        }
    }

    pub async fn ready(&self, who: &Browser, login: &str) -> (Ws, String) {
        let mut ws = self.open(who, login).await;
        let session_id = ws.ready().await;
        (ws, session_id)
    }

    pub async fn upgrade_raw(&self, who: &Browser, login: &str) -> TcpStream {
        let ticket = self.ticket(who, login).await;
        let mut tcp = TcpStream::connect(self.http).await.unwrap();
        let request = format!(
            "GET /v1/web/terminal?node={NODE}&login={login}&cols=80&rows=24 HTTP/1.1\r\n\
             Host: jaunt.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Origin: {PUBLIC_ORIGIN}\r\nCookie: {}\r\n\
             Sec-WebSocket-Protocol: jaunt-terminal.v1, jaunt-ticket.{ticket}\r\n\r\n",
            who.cookie
        );
        tcp.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            tcp.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 101"));
        tcp
    }

    pub async fn raw(&self, who: &Browser, login: &str) -> (RawBrowser, String) {
        let (read, write) = self.upgrade_raw(who, login).await.into_split();
        let seen = Arc::new(RawSeen::default());
        let (texts, mut ready) = mpsc::unbounded_channel();
        let (reading, allowed) = watch::channel(true);
        let reader = tokio::spawn(read_frames(read, Arc::clone(&seen), texts, allowed));
        let first = tokio::time::timeout(STEP, ready.recv())
            .await
            .expect("the raw terminal sent nothing in time")
            .expect("the raw terminal closed before it was ready");
        let first: Value = serde_json::from_str(&first).unwrap();
        assert_eq!(first["t"], "ready", "{first}");
        let session_id = first["session_id"].as_str().unwrap().to_owned();
        (
            RawBrowser {
                write,
                seen,
                reading,
                reader,
            },
            session_id,
        )
    }
}

#[derive(Default)]
pub struct RawSeen {
    pub pings: AtomicU64,
    pub output: AtomicU64,
    pub closed: AtomicBool,
    pub close_code: Mutex<Option<u16>>,
    pub texts: Mutex<Vec<Value>>,
}

pub struct RawBrowser {
    write: OwnedWriteHalf,
    pub seen: Arc<RawSeen>,
    reading: watch::Sender<bool>,
    reader: JoinHandle<()>,
}

impl RawBrowser {
    pub async fn send(&mut self, data: &[u8]) {
        assert!(
            self.try_send(data).await,
            "the raw terminal stopped taking input"
        );
    }

    pub fn read_output(&self, reading: bool) {
        self.reading.send_replace(reading);
    }

    pub async fn pong(&mut self) {
        assert!(
            self.try_send_frame(0x8a, b"").await,
            "the raw terminal stopped taking frames"
        );
    }

    pub async fn try_send(&mut self, data: &[u8]) -> bool {
        self.try_send_frame(0x82, data).await
    }

    async fn try_send_frame(&mut self, head: u8, data: &[u8]) -> bool {
        const MASK: [u8; 4] = [0x5a, 0x17, 0xc3, 0x81];
        let mut frame = vec![head];
        match u16::try_from(data.len()) {
            Ok(short) if short < 126 => frame.push(0x80 | u8::try_from(short).unwrap()),
            Ok(medium) => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&medium.to_be_bytes());
            }
            Err(_) => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&u64::try_from(data.len()).unwrap().to_be_bytes());
            }
        }
        frame.extend_from_slice(&MASK);
        frame.extend(
            data.iter()
                .zip(MASK.iter().cycle())
                .map(|(byte, mask)| byte ^ mask),
        );
        self.write.write_all(&frame).await.is_ok()
    }
}

impl Drop for RawBrowser {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn read_frame(read: &mut OwnedReadHalf) -> Option<(u8, Vec<u8>)> {
    let mut head = [0_u8; 2];
    read.read_exact(&mut head).await.ok()?;
    let length = match head[1] & 0x7f {
        126 => {
            let mut extended = [0_u8; 2];
            read.read_exact(&mut extended).await.ok()?;
            u64::from(u16::from_be_bytes(extended))
        }
        127 => {
            let mut extended = [0_u8; 8];
            read.read_exact(&mut extended).await.ok()?;
            u64::from_be_bytes(extended)
        }
        short => u64::from(short),
    };
    let mut payload = vec![0; usize::try_from(length).ok()?];
    read.read_exact(&mut payload).await.ok()?;
    Some((head[0] & 0x0f, payload))
}

async fn read_frames(
    mut read: OwnedReadHalf,
    seen: Arc<RawSeen>,
    texts: mpsc::UnboundedSender<String>,
    mut allowed: watch::Receiver<bool>,
) {
    while allowed.wait_for(|reading| *reading).await.is_ok() {
        let Some((opcode, payload)) = read_frame(&mut read).await else {
            break;
        };
        match opcode {
            0x1 => {
                let text = String::from_utf8_lossy(&payload).into_owned();
                seen.texts
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(&text).unwrap());
                drop(texts.send(text));
            }
            0x2 => {
                seen.output
                    .fetch_add(u64::try_from(payload.len()).unwrap(), Ordering::SeqCst);
            }
            0x8 => {
                *seen.close_code.lock().unwrap() = payload
                    .get(..2)
                    .map(|code| u16::from_be_bytes([code[0], code[1]]));
                break;
            }
            0x9 => {
                seen.pings.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
    seen.closed.store(true, Ordering::SeqCst);
}

fn random_seed() -> [u8; 32] {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    key.key_data().ed25519().unwrap().private.to_bytes()
}

fn load_roles(harness: &Harness, roles: &str) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("roles.yaml"), roles).unwrap();
    let outcome = harness.control.policy().reload(dir.path());
    assert!(outcome.applied, "{:?}", outcome.errors);
}

async fn browser(harness: &Harness, name: &str) -> Browser {
    let user_id = harness
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: "https://idp.example".to_owned(),
                subject: name.to_owned(),
                email: format!("{name}@example.com"),
                username: name.to_owned(),
                display_name: None,
                groups: Vec::new(),
            },
            i64::try_from(unix_secs(SystemTime::now())).unwrap(),
        )
        .await
        .unwrap()
        .id;
    let opened = harness.control.open_web_session(&user_id).await.unwrap();
    Browser {
        user_id,
        cookie: opened.cookie,
        csrf: opened.csrf_token,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Received {
    Output(Vec<u8>),
    Json(Value),
    Closed(Option<u16>),
}

pub struct Ws {
    pub socket: WebSocketStream<TcpStream>,
    pub output: Vec<u8>,
}

impl Ws {
    pub async fn next(&mut self) -> Received {
        self.next_before(tokio::time::Instant::now() + STEP).await
    }

    async fn next_before(&mut self, deadline: tokio::time::Instant) -> Received {
        loop {
            let message = tokio::time::timeout_at(deadline, self.socket.next())
                .await
                .expect("the terminal sent nothing in time");
            match message {
                Some(Ok(Message::Binary(data))) => return Received::Output(data.to_vec()),
                Some(Ok(Message::Text(text))) => {
                    return Received::Json(serde_json::from_str(text.as_str()).unwrap());
                }
                Some(Ok(Message::Close(frame))) => {
                    return Received::Closed(frame.map(|frame| u16::from(frame.code)));
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => return Received::Closed(None),
            }
        }
    }

    pub async fn ready(&mut self) -> String {
        match self.next().await {
            Received::Json(value) if value["t"] == "ready" => {
                value["session_id"].as_str().unwrap().to_owned()
            }
            other => panic!("the terminal did not become ready: {other:?}"),
        }
    }

    pub async fn send(&mut self, data: &[u8]) {
        self.socket
            .send(Message::Binary(Bytes::copy_from_slice(data)))
            .await
            .unwrap();
    }

    pub async fn send_text(&mut self, text: &str) {
        self.socket
            .send(Message::Text(text.to_owned().into()))
            .await
            .unwrap();
    }

    pub async fn output_until(&mut self, wanted: &[u8]) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + STEP;
        while !self
            .output
            .windows(wanted.len())
            .any(|window| window == wanted)
        {
            match self.next_before(deadline).await {
                Received::Output(data) => self.output.extend_from_slice(&data),
                other => panic!(
                    "waiting for {:?} the terminal sent {other:?}",
                    String::from_utf8_lossy(wanted)
                ),
            }
        }
        self.output.clone()
    }

    pub async fn ending(&mut self) -> (Vec<Value>, Option<u16>) {
        let deadline = tokio::time::Instant::now() + STEP;
        let mut messages = Vec::new();
        loop {
            match self.next_before(deadline).await {
                Received::Output(data) => self.output.extend_from_slice(&data),
                Received::Json(value) => messages.push(value),
                Received::Closed(code) => return (messages, code),
            }
        }
    }
}
