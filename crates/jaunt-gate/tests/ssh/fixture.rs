use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_gate::{Clock, HostCertIssuer, IssueError, SshGate, SshGateConfig};
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError, ControlPlane, DenyReason, NodeCaller,
    RouteDecision, RouteRequest, SessionEnd, SessionEndOutcome,
};
use jaunt_ssh::{UserCaKeys, UserCaSource};
use jaunt_tunnel::{BoxFuture, IncomingStream, StreamHandler};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::{Channel, ChannelId, ChannelMsg, ChannelOpenFailure, Preferred, client};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::support::{
    HubOptions, Pki, TestAgent, TestHub, Verdicts, eventually, node, spawn_agent_with, start_hub,
};

pub const SUFFIX: &str = "nodes.test";
pub const GATE_NAME: &str = "gate.test";
pub const NODE: &str = "node-a";
pub const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
pub const DENIED_TEXT: &str = "jaunt: access denied or node unavailable";
pub const LIMIT_TEXT: &str = "jaunt: too many open sessions";
pub const STEP: Duration = Duration::from_secs(20);
const HOST_VALIDITY: u64 = 7 * 24 * 3600;

pub fn key() -> PrivateKey {
    PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap()
}

pub fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn user_certificate(ca: &PrivateKey, subject: &PrivateKey) -> Certificate {
    let now = unix(SystemTime::now());
    let mut builder = Builder::new_with_random_nonce(
        &mut safe_rng(),
        subject.public_key().key_data().clone(),
        now - 120,
        now + 3600,
    )
    .unwrap();
    builder.serial(42).unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.key_id("jaunt:alice@example.com:42").unwrap();
    builder.valid_principal(USER_ID).unwrap();
    builder.sign(ca).unwrap()
}

#[derive(Clone)]
pub struct TestClock(Arc<AtomicU64>);

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_secs(), Ordering::SeqCst);
    }

    pub fn clock(&self) -> Clock {
        let offset = Arc::clone(&self.0);
        Arc::new(move || SystemTime::now() + Duration::from_secs(offset.load(Ordering::SeqCst)))
    }
}

pub struct TestIssuer {
    ca: PrivateKey,
    clock: Clock,
    calls: AtomicUsize,
    failures_left: AtomicUsize,
}

impl TestIssuer {
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    pub fn fail_next(&self, count: usize) {
        self.failures_left.store(count, Ordering::SeqCst);
    }
}

impl HostCertIssuer for TestIssuer {
    fn issue<'a>(
        &'a self,
        public_key_openssh: &'a str,
        hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let failing = self
                .failures_left
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok();
            if failing {
                return Err(IssueError::Unavailable);
            }
            let public = PublicKey::from_openssh(public_key_openssh)
                .map_err(|_| IssueError::InvalidRequest)?;
            let now = unix((self.clock)());
            let mut builder = Builder::new_with_random_nonce(
                &mut safe_rng(),
                public.key_data().clone(),
                now - 120,
                now + HOST_VALIDITY,
            )
            .unwrap();
            builder
                .serial(u64::try_from(self.calls()).unwrap())
                .unwrap();
            builder.cert_type(CertType::Host).unwrap();
            builder.key_id("jaunt-host:gate").unwrap();
            for name in hostnames {
                builder.valid_principal(name.as_str()).unwrap();
            }
            Ok(builder.sign(&self.ca).unwrap().to_openssh().unwrap())
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    AllowAbsentNode,
    Deny,
    Fail,
}

pub struct FakeControl {
    verdict: Mutex<Verdict>,
    seen: Mutex<Vec<RouteRequest>>,
    sessions: AtomicUsize,
}

impl Default for FakeControl {
    fn default() -> Self {
        Self {
            verdict: Mutex::new(Verdict::Allow),
            seen: Mutex::new(Vec::new()),
            sessions: AtomicUsize::new(0),
        }
    }
}

impl FakeControl {
    pub fn set(&self, verdict: Verdict) {
        *self.verdict.lock().unwrap() = verdict;
    }

    pub fn seen(&self) -> Vec<RouteRequest> {
        self.seen.lock().unwrap().clone()
    }
}

impl ControlPlane for FakeControl {
    fn route(&self, request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        self.seen.lock().unwrap().push(request);
        let session = self.sessions.fetch_add(1, Ordering::SeqCst);
        let verdict = *self.verdict.lock().unwrap();
        Box::pin(async move {
            match verdict {
                Verdict::Allow => Ok(RouteDecision::Allow {
                    session_id: format!("session-{session}"),
                    node_id: NODE.to_owned(),
                }),
                Verdict::AllowAbsentNode => Ok(RouteDecision::Allow {
                    session_id: format!("session-{session}"),
                    node_id: "node-gone".to_owned(),
                }),
                Verdict::Deny => Ok(RouteDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                }),
                Verdict::Fail => Err(ControlError::Store),
            }
        })
    }

    fn authorize(
        &self,
        _node: NodeCaller,
        _request: AuthorizeRequest,
    ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }

    fn session_end(
        &self,
        _node: NodeCaller,
        _request: SessionEnd,
    ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
        Box::pin(async { Err(ControlError::InvalidRequest) })
    }
}

struct Echo;

impl StreamHandler for Echo {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let (mut read, mut write) = tokio::io::split(stream.io);
            let _ = tokio::io::copy(&mut read, &mut write).await;
            let _ = write.shutdown().await;
        })
    }
}

pub struct Fixture {
    pub gate: Arc<SshGate>,
    pub addr: SocketAddr,
    pub issuer: Arc<TestIssuer>,
    pub control: Arc<FakeControl>,
    pub user_ca: PrivateKey,
    pub host_ca: PrivateKey,
    pub shutdown: CancellationToken,
    pub serve: JoinHandle<()>,
    _hub: TestHub,
    agent: TestAgent,
}

impl Fixture {
    pub async fn start(configure: impl FnOnce(&mut SshGateConfig)) -> Self {
        Self::start_with(configure, TestClock::new()).await
    }

    pub async fn start_with(configure: impl FnOnce(&mut SshGateConfig), clock: TestClock) -> Self {
        let pki = Pki::new("tunnel ca");
        let leaf = pki.client_leaf(NODE);
        let verdicts = Arc::new(Verdicts::default());
        verdicts.allow(&leaf, NODE);
        let hub = start_hub(&pki, verdicts, HubOptions::default()).await;
        let agent = spawn_agent_with(hub.addr, &pki, &leaf, Arc::new(Echo));
        let registry = hub.hub.registry().clone();
        eventually("the agent tunnel", || registry.is_connected(&node(NODE))).await;
        let host_ca = key();
        let issuer = Arc::new(TestIssuer {
            ca: host_ca.clone(),
            clock: clock.clock(),
            calls: AtomicUsize::new(0),
            failures_left: AtomicUsize::new(0),
        });
        let user_ca = key();
        let cas = Arc::new(UserCaSource::new(
            UserCaKeys::from_openssh_lines([user_ca.public_key().to_openssh().unwrap()]).unwrap(),
        ));
        let control = Arc::new(FakeControl::default());
        let mut config = SshGateConfig::new(vec![GATE_NAME.to_owned()], SUFFIX);
        configure(&mut config);
        let gate = Arc::new(
            SshGate::new_with_clock(
                config,
                issuer.clone(),
                cas,
                control.clone(),
                registry,
                clock.clock(),
            )
            .await
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = CancellationToken::new();
        let serving = Arc::clone(&gate);
        let token = shutdown.clone();
        let serve = tokio::spawn(async move { serving.serve(listener, token).await.unwrap() });
        Self {
            gate,
            addr,
            issuer,
            control,
            user_ca,
            host_ca,
            shutdown,
            serve,
            _hub: hub,
            agent,
        }
    }

    pub async fn connect(&self) -> Client {
        Client::over(TcpStream::connect(self.addr).await.unwrap())
            .await
            .unwrap()
    }

    pub async fn login(&self) -> Client {
        let mut client = self.connect().await;
        assert!(client.login(&self.user_ca).await);
        client
    }

    pub async fn stop(self) {
        self.shutdown.cancel();
        tokio::time::timeout(STEP, self.serve)
            .await
            .expect("the gate did not stop")
            .unwrap();
        self.agent.stop().await;
    }
}

#[derive(Default)]
pub struct Log {
    host_certificates: Mutex<Vec<Option<Certificate>>>,
    failures: Mutex<Vec<(ChannelOpenFailure, String)>>,
}

pub struct Recorder(Arc<Log>);

impl client::Handler for Recorder {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented = match key {
            PublicKeyOrCertificate::Certificate(certificate) => Some(certificate.clone()),
            PublicKeyOrCertificate::PublicKey { .. } => None,
        };
        self.0.host_certificates.lock().unwrap().push(presented);
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
        self.0
            .failures
            .lock()
            .unwrap()
            .push((reason, description.to_owned()));
        Ok(())
    }
}

pub struct Client {
    pub handle: client::Handle<Recorder>,
    log: Arc<Log>,
}

impl Client {
    pub async fn over(stream: TcpStream) -> Result<Self, russh::Error> {
        let config = client::Config {
            preferred: Preferred {
                host_key_certificates: Cow::Borrowed(&[Algorithm::Ed25519]),
                ..Preferred::DEFAULT
            },
            ..client::Config::default()
        };
        let log = Arc::new(Log::default());
        let handle = tokio::time::timeout(
            STEP,
            client::connect_stream(Arc::new(config), stream, Recorder(Arc::clone(&log))),
        )
        .await
        .expect("the ssh handshake hung")?;
        Ok(Self { handle, log })
    }

    pub async fn login(&mut self, ca: &PrivateKey) -> bool {
        let subject = key();
        let certificate = user_certificate(ca, &subject);
        self.handle
            .authenticate_openssh_cert("jaunt", Arc::new(subject), certificate)
            .await
            .unwrap()
            .success()
    }

    pub fn host_certificate(&self) -> Certificate {
        let seen = self.log.host_certificates.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        seen[0].clone().expect("the gate presented a plain key")
    }

    async fn failure(&self, index: usize) -> (ChannelOpenFailure, String) {
        let deadline = tokio::time::Instant::now() + STEP;
        loop {
            let recorded = self.log.failures.lock().unwrap().get(index).cloned();
            if let Some(failure) = recorded {
                return failure;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no channel open failure was recorded"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    pub async fn open(
        &self,
        host: &str,
    ) -> Result<Channel<client::Msg>, (ChannelOpenFailure, String)> {
        let index = self.log.failures.lock().unwrap().len();
        let opened = tokio::time::timeout(
            STEP,
            self.handle
                .channel_open_direct_tcpip(host, 22, "127.0.0.1", 50_000),
        )
        .await
        .expect("the channel open was not answered");
        match opened {
            Ok(channel) => Ok(channel),
            Err(_) => Err(self.failure(index).await),
        }
    }

    pub async fn open_node(&self) -> Result<Channel<client::Msg>, (ChannelOpenFailure, String)> {
        self.open(&format!("{NODE}.{SUFFIX}")).await
    }
}

pub async fn echo_once(channel: &mut Channel<client::Msg>, payload: &'static [u8]) {
    channel.data(payload).await.unwrap();
    let mut received = Vec::new();
    while received.len() < payload.len() {
        let message = tokio::time::timeout(STEP, channel.wait())
            .await
            .expect("the echo did not come back");
        match message {
            Some(ChannelMsg::Data { data }) => received.extend_from_slice(&data),
            Some(_) => {}
            None => panic!("the channel closed before the echo"),
        }
    }
    assert_eq!(received, payload);
}
