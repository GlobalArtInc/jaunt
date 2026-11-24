use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_ca::ssh_key::PublicKey as CaPublicKey;
use jaunt_ca::{
    AgeIdentity, CaKind, DEFAULT_HOST_VALIDITY, FileBackend, HostCertParams, Signer,
    UserCertParams, Uuid, sign_host_certificate, sign_user_certificate,
};
use jaunt_gate::{
    AgentApiHandler, AgentHub, AgentHubConfig, DEFAULT_SSH_CLIENT_LIMITS, HostCertIssuer,
    IssueError,
};
use jaunt_limits::{AddressLimits, Rate};
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError, ControlPlane, DenyReason, NodeCaller,
    RouteDecision, RouteRequest, SessionEnd, SessionEndOutcome,
};
use jaunt_ssh::{UserCaKeys, UserCaSource, verify_user_certificate};
use jaunt_store::Store;
use jaunt_tunnel::{
    AgentRegistry, BackoffPolicy, BoxFuture, IncomingStream, NodeId, PeerAuthenticator, Rejection,
    StreamHandler, TunnelClient, TunnelClientConfig, agent_client_config, agent_server_config,
};
use jauntd::agents::ssh_tunnel_options;
use jauntd::gate_ssh::{
    GateSshError, GateSshParts, GateSshServer, GateSshSettings, HostAuthorityIssuer,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use russh::keys::key::safe_rng;
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKeyOrCertificate};
use russh::server::{self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session};
use russh::{Channel, ChannelId, client};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

const SUFFIX: &str = "jaunt.test";
const GATE_NAME: &str = "gate.jaunt.test";
const NODE_ID: &str = "node-id-1";
const AGENTS_SNI: &str = "agents.test";
const USER_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";
const DENIED_TEXT: &str = "jaunt: access denied or node unavailable";
const SESSION_TEXT: &str = "jaunt: this is the Jaunt SSH gateway and it has no shell";
const STEP: Duration = Duration::from_secs(60);
const STUCK: Duration = Duration::from_secs(3);

fn openssh_available() -> bool {
    let present = ["ssh", "ssh-keygen", "ssh-keyscan"].iter().all(|tool| {
        std::process::Command::new("which")
            .arg(tool)
            .output()
            .is_ok_and(|output| output.status.success())
    });
    if !present {
        eprintln!(
            "skipping: the OpenSSH client tools (ssh, ssh-keygen, ssh-keyscan) are not installed"
        );
    }
    present
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Allow,
    Deny,
    Fail,
    AbsentNode,
    Stuck,
}

struct Control {
    entered: tokio::sync::Notify,
    verdict: Mutex<Verdict>,
    sessions: AtomicUsize,
    seen: Mutex<Vec<RouteRequest>>,
}

impl Control {
    fn set(&self, verdict: Verdict) {
        *self.verdict.lock().unwrap() = verdict;
    }
}

impl ControlPlane for Control {
    fn route(&self, request: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
        self.seen.lock().unwrap().push(request);
        let session = self.sessions.fetch_add(1, Ordering::SeqCst);
        let verdict = *self.verdict.lock().unwrap();
        Box::pin(async move {
            let allow = |node_id: &str| RouteDecision::Allow {
                session_id: format!("session-{session}"),
                node_id: node_id.to_owned(),
            };
            match verdict {
                Verdict::Allow => Ok(allow(NODE_ID)),
                Verdict::AbsentNode => Ok(allow("node-id-gone")),
                Verdict::Deny => Ok(RouteDecision::Deny {
                    reason: DenyReason::PolicyDenied,
                }),
                Verdict::Fail => Err(ControlError::Store),
                Verdict::Stuck => {
                    self.entered.notify_one();
                    tokio::task::block_in_place(|| std::thread::sleep(STUCK));
                    Err(ControlError::Store)
                }
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

struct AnyNode;

impl PeerAuthenticator for AnyNode {
    fn authenticate<'a>(
        &'a self,
        _peer_cert_der: &'a [u8],
    ) -> BoxFuture<'a, Result<NodeId, Rejection>> {
        Box::pin(async { Ok(NodeId::new(NODE_ID).unwrap()) })
    }
}

struct NoApi;

impl AgentApiHandler for NoApi {
    fn serve(
        &self,
        _node: NodeId,
        _stream: tokio_rustls::server::TlsStream<TcpStream>,
        _shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

struct InnerSshd {
    config: Arc<server::Config>,
    cas: Arc<UserCaSource>,
}

impl StreamHandler for InnerSshd {
    fn handle(&self, stream: IncomingStream) -> BoxFuture<'static, ()> {
        let config = Arc::clone(&self.config);
        let handler = InnerHandler {
            cas: Arc::clone(&self.cas),
            channels: HashMap::new(),
        };
        Box::pin(async move {
            if let Ok(running) = server::run_stream(config, stream.io, handler).await {
                let _ = running.await;
            }
        })
    }
}

struct InnerHandler {
    cas: Arc<UserCaSource>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl server::Handler for InnerHandler {
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
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        let now = unix(SystemTime::now());
        match verify_user_certificate(certificate, &self.cas.current(), now) {
            Ok(_) => Ok(Auth::Accept),
            Err(_) => Ok(Auth::reject()),
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        let answer = if data == b"echo ok" { "ok\n" } else { "?\n" };
        session.data(channel, answer.as_bytes().to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

struct Authorities {
    user: Arc<dyn Signer>,
    host: Arc<dyn Signer>,
    host_line: String,
    user_cas: Arc<UserCaSource>,
}

fn authorities(dir: &Path) -> Authorities {
    let root = dir.join("ca");
    let identity = AgeIdentity::generate();
    for kind in [CaKind::User, CaKind::Host] {
        FileBackend::init(&root, kind, &identity.recipient()).unwrap();
    }
    let (user_trust, user) = FileBackend::load(&root, CaKind::User, &identity).unwrap();
    let (_, host) = FileBackend::load(&root, CaKind::Host, &identity).unwrap();
    let host_line = host.public_key().to_openssh().unwrap();
    let user_cas = Arc::new(UserCaSource::new(
        UserCaKeys::from_openssh_lines(user_trust.to_authorized_lines().unwrap()).unwrap(),
    ));
    Authorities {
        user: Arc::new(user),
        host: Arc::new(host),
        host_line,
        user_cas,
    }
}

fn inner_sshd(authorities: &Authorities) -> InnerSshd {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let subject = CaPublicKey::from_openssh(&key.public_key().to_openssh().unwrap()).unwrap();
    let issued = sign_host_certificate(
        authorities.host.as_ref(),
        HostCertParams {
            subject_public_key: subject,
            hostnames: vec![format!("node1.{SUFFIX}"), "node1".to_owned()],
            serial: 900,
            validity: DEFAULT_HOST_VALIDITY,
        },
        SystemTime::now(),
    )
    .unwrap();
    let certificate = Certificate::from_openssh(&issued.to_openssh().unwrap()).unwrap();
    let config = server::Config {
        keys: vec![key],
        certificates: vec![certificate],
        auth_rejection_time: Duration::from_millis(10),
        ..server::Config::default()
    };
    InnerSshd {
        config: Arc::new(config),
        cas: Arc::clone(&authorities.user_cas),
    }
}

struct TunnelPki {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl TunnelPki {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, "tunnel ca");
        Self {
            issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    fn leaf(
        &self,
        name: &str,
        purpose: ExtendedKeyUsagePurpose,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.extended_key_usages = vec![purpose];
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &*self.issuer).unwrap();
        (
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }
}

struct Stand {
    dir: TempDir,
    gate: Option<GateSshServer>,
    hub: Option<AgentHub>,
    agent_stop: CancellationToken,
    control: Arc<Control>,
    gate_addr: SocketAddr,
    host_line: String,
    user: Arc<dyn Signer>,
    store: Store,
}

impl Stand {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(configure: impl FnOnce(&mut GateSshSettings)) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let authorities = authorities(dir.path());
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();

        let pki = TunnelPki::new();
        let (server_chain, server_key) = pki.leaf(AGENTS_SNI, ExtendedKeyUsagePurpose::ServerAuth);
        let tls = agent_server_config(server_chain, server_key, pki.roots()).unwrap();
        let mut hub_config = AgentHubConfig::new(AGENTS_SNI, Arc::new(tls));
        hub_config.tunnel = ssh_tunnel_options();
        let hub = AgentHub::start(
            TcpListener::bind("127.0.0.1:0").await.unwrap(),
            hub_config,
            Arc::new(AnyNode),
            Arc::new(NoApi),
        )
        .unwrap();
        let (client_chain, client_key) = pki.leaf("node1", ExtendedKeyUsagePurpose::ClientAuth);
        let client_tls = agent_client_config(pki.roots(), client_chain, client_key).unwrap();
        let mut agent = TunnelClientConfig::new(
            Arc::new(client_tls),
            hub.local_addr().to_string(),
            AGENTS_SNI,
            "test-agent/1",
        );
        agent.options = ssh_tunnel_options();
        agent.backoff = BackoffPolicy {
            initial: Duration::from_millis(20),
            max: Duration::from_millis(200),
            reset_after: Duration::from_secs(30),
        };
        let agent_stop = CancellationToken::new();
        let sshd = Arc::new(inner_sshd(&authorities));
        let token = agent_stop.clone();
        tokio::spawn(async move { TunnelClient::run(agent, sshd, token).await });
        let registry = hub.registry().clone();
        wait_connected(&registry).await;

        let control = Arc::new(Control {
            entered: tokio::sync::Notify::new(),
            verdict: Mutex::new(Verdict::Allow),
            sessions: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        });
        let issuer = Arc::new(HostAuthorityIssuer::new(
            Arc::clone(&authorities.host),
            store.clone(),
            Arc::new(SystemTime::now),
        ));
        let mut settings = GateSshSettings {
            listen: "127.0.0.1:0".parse().unwrap(),
            hostnames: vec![GATE_NAME.to_owned()],
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
            max_unauthenticated: 16,
            client_limits: DEFAULT_SSH_CLIENT_LIMITS,
            write_stall: Some(Duration::from_secs(900)),
        };
        configure(&mut settings);
        let gate = GateSshServer::start(GateSshParts {
            settings,
            ssh_suffix: SUFFIX.to_owned(),
            issuer,
            user_cas: Arc::clone(&authorities.user_cas),
            control: control.clone(),
            registry,
        })
        .await
        .unwrap();
        let gate_addr = gate.local_addr();
        let stand = Self {
            dir,
            gate: Some(gate),
            hub: Some(hub),
            agent_stop,
            control,
            gate_addr,
            host_line: authorities.host_line,
            user: authorities.user,
            store,
        };
        std::fs::write(
            stand.path("known_hosts"),
            format!(
                "@cert-authority {GATE_NAME},*.{SUFFIX} {}\n",
                stand.host_line
            ),
        )
        .unwrap();
        stand
    }

    async fn listed_gate_certificate(&self) -> String {
        let scanned = run(Command::new("ssh-keyscan").args([
            "-c",
            "-t",
            "ed25519",
            "-p",
            &self.gate_addr.port().to_string(),
            "127.0.0.1",
        ]))
        .await;
        let line = String::from_utf8_lossy(&scanned.stdout)
            .lines()
            .find(|line| line.starts_with("ssh-ed25519-cert-v01@openssh.com "))
            .map(str::to_owned)
            .expect("the gate presented no certificate");
        let path = self.path("gate-cert.pub");
        std::fs::write(&path, format!("{line}\n")).unwrap();
        let listed = run(Command::new("ssh-keygen")
            .env("TZ", "UTC")
            .arg("-L")
            .arg("-f")
            .arg(&path))
        .await;
        String::from_utf8_lossy(&listed.stdout).into_owned()
    }

    fn certificate_for(&self, key: &PrivateKey) -> Certificate {
        let subject = CaPublicKey::from_openssh(&key.public_key().to_openssh().unwrap()).unwrap();
        let certificate = sign_user_certificate(
            self.user.as_ref(),
            UserCertParams {
                subject_public_key: subject,
                user_id: Uuid::parse_str(USER_ID).unwrap(),
                email: "alice@example.com".to_owned(),
                serial: 7,
                validity: Duration::from_secs(3600),
            },
            SystemTime::now(),
        )
        .unwrap();
        Certificate::from_openssh(&certificate.to_openssh().unwrap()).unwrap()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    async fn keygen(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        run(Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", name, "-f"])
            .arg(&path))
        .await;
        path
    }

    async fn identity(&self, name: &str, now: SystemTime) -> PathBuf {
        let path = self.keygen(name).await;
        let public = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        let certificate = sign_user_certificate(
            self.user.as_ref(),
            UserCertParams {
                subject_public_key: CaPublicKey::from_openssh(public.trim()).unwrap(),
                user_id: Uuid::parse_str(USER_ID).unwrap(),
                email: "alice@example.com".to_owned(),
                serial: 7,
                validity: Duration::from_secs(3600),
            },
            now,
        )
        .unwrap();
        std::fs::write(
            cert_path(&path),
            format!("{}\n", certificate.to_openssh().unwrap()),
        )
        .unwrap();
        path
    }

    async fn foreign_identity(&self, name: &str) -> PathBuf {
        let ca = self.keygen(&format!("{name}-ca")).await;
        let path = self.keygen(name).await;
        run(Command::new("ssh-keygen")
            .args(["-q", "-s"])
            .arg(&ca)
            .args([
                "-I",
                "jaunt:alice@example.com:7",
                "-n",
                USER_ID,
                "-z",
                "7",
                "-V",
                "-5m:+1h",
            ])
            .arg(path.with_extension("pub")))
        .await;
        path
    }

    fn config(&self, identity: &Path) -> PathBuf {
        let path = self.path(&format!(
            "{}.config",
            identity.file_name().unwrap().to_string_lossy()
        ));
        let text = format!(
            "Host gate\n  HostName 127.0.0.1\n  Port {port}\n  User jaunt\n  HostKeyAlias {GATE_NAME}\n\
             Host *.{SUFFIX}\n  ProxyJump gate\n\
             Host *\n  UserKnownHostsFile {known}\n  GlobalKnownHostsFile /dev/null\n  \
             StrictHostKeyChecking yes\n  CheckHostIP no\n  BatchMode yes\n  IdentitiesOnly yes\n  \
             IdentityAgent none\n  IdentityFile {identity}\n  ConnectTimeout 30\n  \
             ServerAliveInterval 0\n",
            port = self.gate_addr.port(),
            known = self.path("known_hosts").display(),
            identity = identity.display(),
        );
        std::fs::write(&path, text).unwrap();
        path
    }

    async fn ssh(&self, config: &Path, args: &[&str]) -> Output {
        let mut command = Command::new("ssh");
        command.arg("-F").arg(config).args(args);
        output(&mut command).await
    }

    async fn stop(mut self) {
        if let Some(gate) = self.gate.take() {
            assert!(gate.shutdown(Duration::from_secs(10)).await);
        }
        self.agent_stop.cancel();
        if let Some(hub) = self.hub.take() {
            hub.shutdown(Duration::from_secs(5)).await;
        }
    }
}

fn serial(listed: &str) -> u64 {
    listed
        .lines()
        .find_map(|line| line.trim().strip_prefix("Serial: "))
        .expect("no serial in the listing")
        .parse()
        .unwrap()
}

fn validity_secs(listed: &str) -> u64 {
    let line = listed
        .lines()
        .find_map(|line| line.trim().strip_prefix("Valid: from "))
        .expect("no validity in the listing");
    let (from, to) = line.split_once(" to ").unwrap();
    utc_secs(to) - utc_secs(from)
}

fn utc_secs(stamp: &str) -> u64 {
    let (date, time) = stamp.split_once('T').unwrap();
    let date: Vec<i64> = date.split('-').map(|part| part.parse().unwrap()).collect();
    let time: Vec<i64> = time.split(':').map(|part| part.parse().unwrap()).collect();
    let (year, month, day) = (date[0], date[1], date[2]);
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    u64::try_from(days * 86_400 + time[0] * 3600 + time[1] * 60 + time[2]).unwrap()
}

fn cert_path(key: &Path) -> PathBuf {
    let mut name = key.file_name().unwrap().to_os_string();
    name.push("-cert.pub");
    key.with_file_name(name)
}

async fn wait_connected(registry: &AgentRegistry) {
    let node = NodeId::new(NODE_ID).unwrap();
    let deadline = tokio::time::Instant::now() + STEP;
    while !registry.is_connected(&node) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the agent never connected"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn output(command: &mut Command) -> Output {
    command
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null());
    tokio::time::timeout(STEP, command.output())
        .await
        .expect("the command hung")
        .unwrap()
}

async fn run(command: &mut Command) -> Output {
    let output = output(command).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_reaches_a_node_through_the_gate_and_trusts_its_certificate() {
    if !openssh_available() {
        return;
    }
    let stand = Stand::start().await;
    let identity = stand.identity("alice", SystemTime::now()).await;
    let config = stand.config(&identity);

    let reached = stand
        .ssh(&config, &[&format!("deploy@node1.{SUFFIX}"), "echo ok"])
        .await;
    assert!(reached.status.success(), "{}", stderr(&reached));
    assert_eq!(String::from_utf8_lossy(&reached.stdout), "ok\n");
    let routed = stand.control.seen.lock().unwrap().clone();
    assert_eq!(routed.len(), 1);
    assert_eq!(routed[0].node_name, "node1");
    assert_eq!(routed[0].user_id, USER_ID);
    assert_eq!(routed[0].serial, 7);

    let listed = stand.listed_gate_certificate().await;
    assert!(listed.contains("host certificate"), "{listed}");
    assert!(
        listed.contains(&format!("Principals: \n                {GATE_NAME}\n")),
        "{listed}"
    );
    assert_eq!(validity_secs(&listed), 7 * 24 * 3600 + 120, "{listed}");
    let first_serial = serial(&listed);
    stand
        .gate
        .as_ref()
        .unwrap()
        .gate()
        .reissue_host_certificate()
        .await
        .unwrap();
    let relisted = stand.listed_gate_certificate().await;
    let second_serial = serial(&relisted);
    assert!(
        second_serial > first_serial,
        "{first_serial} {second_serial}"
    );
    let next = stand.store.certificates().allocate_serial().await.unwrap();
    assert_eq!(u64::try_from(next).unwrap(), second_serial + 1);
    let ca_fingerprint = run(Command::new("ssh-keygen").arg("-l").arg("-f").arg({
        let path = stand.path("host_ca.pub");
        std::fs::write(&path, format!("{}\n", stand.host_line)).unwrap();
        path
    }))
    .await;
    let ca_fingerprint = String::from_utf8_lossy(&ca_fingerprint.stdout)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_owned();
    assert!(listed.contains(&ca_fingerprint), "{listed}");
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn openssh_sees_the_gate_refusals() {
    if !openssh_available() {
        return;
    }
    let stand = Stand::start().await;
    let identity = stand.identity("alice", SystemTime::now()).await;
    let config = stand.config(&identity);
    let target = format!("deploy@node1.{SUFFIX}");

    let session = stand.ssh(&config, &["gate", "true"]).await;
    assert!(!session.status.success());
    assert!(
        stderr(&session).contains(SESSION_TEXT),
        "{}",
        stderr(&session)
    );
    assert!(
        stderr(&session).contains(&format!("ssh <login>@<node>.{SUFFIX}")),
        "{}",
        stderr(&session)
    );

    let only = format!("jaunt: only <node>.{SUFFIX} port 22 is reachable through this gateway");
    for forward in ["node1.other.test:22", &format!("node1.{SUFFIX}:2222")] {
        let refused = stand.ssh(&config, &["-W", forward, "gate"]).await;
        assert!(!refused.status.success(), "{forward}");
        assert!(
            stderr(&refused).contains(&only),
            "{forward}: {}",
            stderr(&refused)
        );
    }

    let mut refusals = Vec::new();
    for verdict in [Verdict::Deny, Verdict::Fail, Verdict::AbsentNode] {
        stand.control.set(verdict);
        let refused = stand.ssh(&config, &[&target, "echo ok"]).await;
        assert!(!refused.status.success(), "{verdict:?}");
        assert!(
            stderr(&refused).contains(DENIED_TEXT),
            "{verdict:?}: {}",
            stderr(&refused)
        );
        refusals.push(stderr(&refused));
    }
    assert!(
        refusals.windows(2).all(|pair| pair[0] == pair[1]),
        "{refusals:#?}"
    );
    stand.control.set(Verdict::Allow);

    let plain = stand.keygen("plain").await;
    let expired = stand
        .identity(
            "expired",
            SystemTime::now() - Duration::from_secs(2 * 24 * 3600),
        )
        .await;
    let foreign = stand.foreign_identity("foreign").await;
    for (name, identity) in [
        ("plain key", &plain),
        ("expired", &expired),
        ("foreign ca", &foreign),
    ] {
        let config = stand.config(identity);
        let refused = stand.ssh(&config, &[&target, "echo ok"]).await;
        assert!(!refused.status.success(), "{name}");
        assert!(
            stderr(&refused).contains("Permission denied"),
            "{name}: {}",
            stderr(&refused)
        );
    }
    assert_eq!(stand.control.seen.lock().unwrap().len(), 3);
    stand.stop().await;
}

struct AnyHostKey;

impl client::Handler for AnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn proxy_header(client: [u8; 4], port: u16) -> Vec<u8> {
    let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    header.extend_from_slice(&[0x21, 0x11, 0, 12]);
    header.extend_from_slice(&client);
    header.extend_from_slice(&[127, 0, 0, 1]);
    header.extend_from_slice(&port.to_be_bytes());
    header.extend_from_slice(&2222_u16.to_be_bytes());
    header
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_header_from_a_trusted_peer_sets_the_address_route_sees() {
    let stand = Stand::start_with(|settings| {
        settings.proxy_protocol = true;
        settings.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
    })
    .await;
    stand.control.set(Verdict::Deny);
    let mut tcp = TcpStream::connect(stand.gate_addr).await.unwrap();
    tcp.write_all(&proxy_header([203, 0, 113, 9], 40_000))
        .await
        .unwrap();
    let mut handle = tokio::time::timeout(
        STEP,
        client::connect_stream(Arc::new(client::Config::default()), tcp, AnyHostKey),
    )
    .await
    .expect("the handshake hung")
    .unwrap();
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let certificate = stand.certificate_for(&key);
    let login = handle
        .authenticate_openssh_cert("jaunt", Arc::new(key), certificate)
        .await
        .unwrap();
    assert!(login.success());
    let opened = handle
        .channel_open_direct_tcpip(format!("node1.{SUFFIX}"), 22, "127.0.0.1", 50_000)
        .await;
    assert!(opened.is_err());
    let seen = stand.control.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].client_addr, "203.0.113.9:40000");
    drop(handle);
    stand.stop().await;
}

async fn proxied_connection(stand: &Stand, client: [u8; 4], port: u16) -> TcpStream {
    let mut tcp = TcpStream::connect(stand.gate_addr).await.unwrap();
    tcp.write_all(&proxy_header(client, port)).await.unwrap();
    tcp
}

async fn banner_arrives(tcp: &mut TcpStream) -> bool {
    let mut banner = [0_u8; 13];
    let read = tokio::time::timeout(STEP, tcp.read_exact(&mut banner))
        .await
        .expect("the gate neither answered nor closed");
    read.is_ok() && &banner == b"SSH-2.0-Jaunt"
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_silent_connections_from_one_address_does_not_stop_a_login_from_another() {
    let stand = Stand::start_with(|settings| {
        settings.proxy_protocol = true;
        settings.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        settings.max_unauthenticated = 8;
        settings.client_limits = AddressLimits {
            rate: Rate::new(6, 1).unwrap(),
            concurrent: 3,
            tracked: 64,
        };
    })
    .await;
    let flooder = [203, 0, 113, 66];
    let mut held = Vec::new();
    for port in 0..50 {
        let mut tcp = proxied_connection(&stand, flooder, 40_000 + port).await;
        if banner_arrives(&mut tcp).await {
            held.push(tcp);
        }
    }
    assert_eq!(held.len(), 3);

    let user = [198, 51, 100, 7];
    let tcp = proxied_connection(&stand, user, 50_000).await;
    let mut handle = tokio::time::timeout(
        STEP,
        client::connect_stream(Arc::new(client::Config::default()), tcp, AnyHostKey),
    )
    .await
    .expect("the handshake hung")
    .unwrap();
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let certificate = stand.certificate_for(&key);
    let login = handle
        .authenticate_openssh_cert("jaunt", Arc::new(key), certificate)
        .await
        .unwrap();
    assert!(login.success());

    let mut silent = Vec::new();
    for port in 0..3 {
        let mut tcp = proxied_connection(&stand, user, 50_001 + port).await;
        assert!(banner_arrives(&mut tcp).await, "{port}");
        silent.push(tcp);
    }

    drop(held);
    let mut late = proxied_connection(&stand, flooder, 41_000).await;
    assert!(!banner_arrives(&mut late).await);
    drop((handle, silent));
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_health_checks_sent_as_local_are_not_held_to_the_per_address_limits() {
    let stand = Stand::start_with(|settings| {
        settings.proxy_protocol = true;
        settings.trusted_proxies = vec!["127.0.0.0/8".parse().unwrap()];
        settings.client_limits = AddressLimits {
            rate: Rate::new(2, 1).unwrap(),
            concurrent: 1,
            tracked: 64,
        };
    })
    .await;
    let mut local = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    local.extend_from_slice(&[0x20, 0x00, 0, 0]);
    let mut held = Vec::new();
    for index in 0..6 {
        let mut tcp = TcpStream::connect(stand.gate_addr).await.unwrap();
        tcp.write_all(&local).await.unwrap();
        assert!(banner_arrives(&mut tcp).await, "{index}");
        held.push(tcp);
    }
    let mut proxied = proxied_connection(&stand, [127, 0, 0, 1], 40_000).await;
    assert!(banner_arrives(&mut proxied).await);
    let mut over = proxied_connection(&stand, [127, 0, 0, 1], 40_001).await;
    assert!(!banner_arrives(&mut over).await);
    drop((held, proxied));
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_silent_connection_is_closed_when_one_unauthenticated_is_allowed() {
    let stand = Stand::start_with(|settings| settings.max_unauthenticated = 1).await;
    let mut first = TcpStream::connect(stand.gate_addr).await.unwrap();
    let mut banner = [0_u8; 13];
    tokio::time::timeout(STEP, first.read_exact(&mut banner))
        .await
        .expect("no banner arrived")
        .unwrap();
    assert_eq!(&banner, b"SSH-2.0-Jaunt");
    let mut second = TcpStream::connect(stand.gate_addr).await.unwrap();
    let mut buffer = [0_u8; 64];
    let read = tokio::time::timeout(STEP, second.read(&mut buffer))
        .await
        .expect("the second connection was kept open");
    assert!(!matches!(read, Ok(count) if count > 0), "{read:?}");
    drop(first);
    stand.stop().await;
}

struct CountingIssuer(AtomicUsize);

impl HostCertIssuer for CountingIssuer {
    fn issue<'a>(
        &'a self,
        _public_key_openssh: &'a str,
        _hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(IssueError::Unavailable) })
    }
}

#[tokio::test]
async fn a_busy_port_stops_the_gate_before_any_certificate_is_issued() {
    let dir = tempfile::tempdir().unwrap();
    let authorities = authorities(dir.path());
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = Arc::new(CountingIssuer(AtomicUsize::new(0)));
    let started = GateSshServer::start(GateSshParts {
        settings: GateSshSettings {
            listen: taken.local_addr().unwrap(),
            hostnames: vec![GATE_NAME.to_owned()],
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
            max_unauthenticated: 16,
            client_limits: DEFAULT_SSH_CLIENT_LIMITS,
            write_stall: None,
        },
        ssh_suffix: SUFFIX.to_owned(),
        issuer: issuer.clone(),
        user_cas: authorities.user_cas,
        control: Arc::new(Control {
            entered: tokio::sync::Notify::new(),
            verdict: Mutex::new(Verdict::Allow),
            sessions: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }),
        registry: AgentRegistry::new(),
    })
    .await;
    let error = started.err().expect("the gate started on a busy port");
    assert!(matches!(error, GateSshError::Listen { .. }), "{error}");
    assert_eq!(issuer.0.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shutdown_past_its_grace_aborts_the_gate_task() {
    let mut stand = Stand::start().await;
    stand.control.set(Verdict::Stuck);
    let mut handle = tokio::time::timeout(
        STEP,
        client::connect_stream(
            Arc::new(client::Config::default()),
            TcpStream::connect(stand.gate_addr).await.unwrap(),
            AnyHostKey,
        ),
    )
    .await
    .expect("the handshake hung")
    .unwrap();
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let certificate = stand.certificate_for(&key);
    let login = handle
        .authenticate_openssh_cert("jaunt", Arc::new(key), certificate)
        .await
        .unwrap();
    assert!(login.success());
    let opening = tokio::spawn(async move {
        let opened = handle
            .channel_open_direct_tcpip(format!("node1.{SUFFIX}"), 22, "127.0.0.1", 50_000)
            .await;
        (handle, opened.is_ok())
    });
    tokio::time::timeout(STEP, stand.control.entered.notified())
        .await
        .expect("the route never started");
    let server = stand.gate.take().unwrap();
    let gate = Arc::clone(server.gate());
    let started = tokio::time::Instant::now();
    assert!(!server.shutdown(Duration::from_millis(50)).await);
    while Arc::strong_count(&gate) > 1 {
        assert!(
            started.elapsed() < STUCK / 3,
            "the gate task outlived its aborted shutdown"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (_handle, opened) = opening.await.unwrap();
    assert!(!opened);
    stand.stop().await;
}
