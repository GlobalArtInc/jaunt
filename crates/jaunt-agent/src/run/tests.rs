mod accounts;

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_host_users::{HostUsersSection, Name};
use jaunt_proto::{
    AGENT_CAPABILITIES_PATH, AGENT_SERVICES_PATH, AGENT_TRUST_V3_PATH, RenewRequest,
    ServiceAnnouncement,
};
use jaunt_ssh::SshError;
use jaunt_tunnel::{
    BackoffPolicy, BoxFuture, NodeId, RegistryEvent, SessionId, StreamKind, StreamMeta,
};
use russh::keys::key::safe_rng;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKeyOrCertificate};
use russh::{Preferred, client};
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::config::InnerConfig;
use super::renew::host_signer;
use super::{
    RunEnv, RunError, RunSettings, SSH_CONNECTION_WINDOW, SSH_STREAM_WINDOW, run, tunnel_config,
};
use crate::accounts::{HostUsersPaths, LookupError, PasswdLookup, Presence};
use crate::clock::{SystemClock, at_unix_secs};
use crate::endpoint::AgentEndpoint;
use crate::enroll::{EnrollEnv, EnrollOptions, enroll};
use crate::keys::{HostKey, TlsKey};
use crate::ssh::InnerTargetError;
use crate::state::{EnrollmentFiles, EnrollmentRecord, StateDir, StateError};
use crate::testkit::{
    AUTHORIZE_PATH, ApiStep, Approval, ControlScript, FakeControl, FakeGate, LogCapture,
    ManualClock, NODE_ID, NODE_NAME, NodeIdentity, PollStep, RenewStep, SESSION_END_PATH,
    TRUST_PATH, TRUST_V2_PATH, TestPki, eventually, soon, sshd_host_key_file, trust_reply,
    trust_v2_reply, unix_now, user_ca_line,
};
use crate::trust::TrustTiming;

const HOUR: i64 = 3600;

struct EveryoneExists;

impl PasswdLookup for EveryoneExists {
    fn passwd<'a>(&'a self, _login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>> {
        Box::pin(async { Ok(Presence::Present) })
    }
}

struct Agent {
    shutdown: CancellationToken,
    join: JoinHandle<Result<(), RunError>>,
    _sshd: tempfile::TempDir,
}

const FAST: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_millis(20),
    max: Duration::from_millis(200),
    reset_after: Duration::from_secs(30),
};

fn settings(dir: &Path, sshd_host_key: PathBuf) -> RunSettings {
    RunSettings {
        inner: InnerConfig {
            sshd_host_key,
            ..InnerConfig::default()
        },
        tunnel_backoff: FAST,
        trust: TrustTiming {
            backoff: FAST,
            refresh_min: Duration::from_secs(3600),
            refresh_max: Duration::from_secs(3600),
            wake_jitter: Duration::from_millis(1),
            refusal_interval: Duration::from_secs(60),
        },
        ..RunSettings::new(dir.to_path_buf())
    }
}

impl Agent {
    fn start(dir: &Path, clock: Arc<ManualClock>) -> Self {
        Self::start_with_jitter(dir, clock, 1.0)
    }

    fn start_with_jitter(dir: &Path, clock: Arc<ManualClock>, sample: f64) -> Self {
        Self::start_with(dir, clock, sample, |_| {})
    }

    fn start_with(
        dir: &Path,
        clock: Arc<ManualClock>,
        sample: f64,
        adjust: impl FnOnce(&mut RunSettings),
    ) -> Self {
        let sshd = tempfile::tempdir().unwrap();
        let mut settings = settings(dir, sshd_host_key_file(sshd.path()));
        adjust(&mut settings);
        let env = RunEnv {
            clock,
            jitter: Box::new(move || sample),
            passwd: Some(Arc::new(EveryoneExists)),
        };
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(run(settings, env, shutdown.clone()));
        Self {
            shutdown,
            join,
            _sshd: sshd,
        }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        soon("the agent to stop", self.join).await.unwrap().unwrap();
    }
}

struct Enrolled {
    dir: tempfile::TempDir,
    tls: TlsKey,
    host: HostKey,
}

impl Enrolled {
    fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    fn identity(&self) -> NodeIdentity {
        NodeIdentity {
            spki: self.tls.spki_der().to_vec(),
            host_key: self.host.key_data().clone(),
        }
    }

    fn file(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.path().join(name)).unwrap()
    }

    fn record(&self) -> EnrollmentRecord {
        serde_json::from_slice(&self.file("state.json")).unwrap()
    }
}

fn enrolled(pki: &TestPki, endpoint: &str, not_before: i64, not_after: i64) -> Enrolled {
    let dir = tempfile::tempdir().unwrap();
    let tls = TlsKey::generate().unwrap();
    let host = HostKey::generate().unwrap();
    let certificates = pki.node_certificates_for(
        tls.spki_der(),
        host.key_data(),
        NODE_ID,
        NODE_NAME,
        not_before,
        not_after,
    );
    let record = EnrollmentRecord {
        node_id: NODE_ID.to_owned(),
        name: NODE_NAME.to_owned(),
        server_url: "https://jaunt.test".to_owned(),
        agent_endpoint: endpoint.to_owned(),
        x509_not_after: not_after,
        ssh_not_after: not_after,
        enrolled_at: not_before,
    };
    let (state, _lock) = StateDir::prepare_enrollment(dir.path(), false).unwrap();
    state
        .store_enrollment(
            &EnrollmentFiles {
                record: &record,
                tls_key: &tls,
                host_key: &host,
                x509_der: &STANDARD.decode(&certificates.x509_certificate_der).unwrap(),
                ssh_certificate: &certificates.ssh_host_certificate,
                ca_root_der: pki.root_der(),
            },
            not_before,
            false,
        )
        .unwrap();
    Enrolled { dir, tls, host }
}

async fn gate_and_node(
    renewals: &[RenewStep],
    not_before: i64,
    not_after: i64,
) -> (Arc<TestPki>, FakeGate, Enrolled) {
    let pki = Arc::new(TestPki::new());
    let placeholder = NodeIdentity {
        spki: Vec::new(),
        host_key: HostKey::generate().unwrap().key_data().clone(),
    };
    let gate = FakeGate::start(pki.clone(), placeholder, renewals).await;
    let node = enrolled(&pki, &gate.endpoint(), not_before, not_after);
    gate.set_identity(node.identity());
    (pki, gate, node)
}

fn service_reads(gate: &FakeGate) -> usize {
    gate.requests(AGENT_SERVICES_PATH)
        .iter()
        .filter(|seen| seen.method == "GET")
        .count()
}

fn paths_besides_announcements(gate: &FakeGate) -> Vec<String> {
    let mut paths = gate.paths();
    paths.retain(|path| path != AGENT_CAPABILITIES_PATH && path != AGENT_SERVICES_PATH);
    paths
}

fn node_id() -> NodeId {
    NodeId::new(NODE_ID).unwrap()
}

fn stream_meta(session: &str) -> StreamMeta {
    StreamMeta::new(
        SessionId::new(session).unwrap(),
        StreamKind::Ssh,
        "203.0.113.5:40000",
    )
    .unwrap()
}

async fn first_line(gate: &FakeGate, session: &str) -> Vec<u8> {
    let mut stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta(session))
        .await
        .unwrap();
    soon("the first line of the stream", async {
        let mut seen = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).await.unwrap() == 1 {
            seen.push(byte[0]);
            if seen.ends_with(b"\r\n") {
                break;
            }
        }
        seen
    })
    .await
}

struct HostCertificates(Arc<Mutex<Vec<Option<Certificate>>>>);

impl client::Handler for HostCertificates {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let presented = match key {
            PublicKeyOrCertificate::Certificate(certificate) => Some(certificate.clone()),
            PublicKeyOrCertificate::PublicKey { .. } => None,
        };
        self.0.lock().unwrap().push(presented);
        Ok(true)
    }
}

async fn presented_host_certificate(gate: &FakeGate, session: &str) -> String {
    let stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta(session))
        .await
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let config = client::Config {
        preferred: Preferred {
            host_key_certificates: Cow::Borrowed(&[Algorithm::Ed25519]),
            ..Preferred::DEFAULT
        },
        ..client::Config::default()
    };
    let handle = soon(
        "the SSH handshake",
        client::connect_stream(Arc::new(config), stream, HostCertificates(seen.clone())),
    )
    .await
    .unwrap();
    drop(handle);
    let presented = seen.lock().unwrap().clone();
    match presented.as_slice() {
        [Some(certificate)] => certificate.to_openssh().unwrap(),
        other => panic!("expected one host certificate, saw {other:?}"),
    }
}

fn certificate_file(node: &Enrolled) -> String {
    String::from_utf8(node.file("ssh_host_ed25519-cert.pub"))
        .unwrap()
        .trim()
        .to_owned()
}

fn assert_no_key_material(logs: &str, dir: &Path) {
    for name in ["tls.key", "x509.der", "ca-root.der"] {
        let secret = STANDARD.encode(fs::read(dir.join(name)).unwrap());
        assert!(!logs.contains(&secret[..40]));
    }
    assert!(!logs.contains("PRIVATE KEY"));
    assert!(!logs.contains("-cert-v01@openssh.com"));
}

#[test]
fn default_settings_are_privileged_exactly_when_running_as_root() {
    let settings = RunSettings::new(std::path::PathBuf::from("/var/lib/jaunt"));
    assert_eq!(settings.privileged, rustix::process::geteuid().is_root());
}

#[tokio::test]
async fn run_refuses_to_start_without_an_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let env = RunEnv {
        clock: Arc::new(SystemClock),
        jitter: Box::new(|| 0.5),
        passwd: None,
    };
    let error = run(
        RunSettings::new(dir.path().to_path_buf()),
        env,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        RunError::State(StateError::NotEnrolled { .. })
    ));
    assert!(error.to_string().contains("jaunt-agent enroll"));
}

#[tokio::test]
async fn an_enrolled_agent_serves_ssh_on_its_tunnel_and_survives_drops_and_restarts() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let pki = Arc::new(TestPki::new());
    let placeholder = NodeIdentity {
        spki: Vec::new(),
        host_key: HostKey::generate().unwrap().key_data().clone(),
    };
    let mut gate = FakeGate::start(pki.clone(), placeholder, &[]).await;
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.agent_endpoint = gate.endpoint();
    let control = FakeControl::start(pki.clone(), script).await;
    let dir = tempfile::tempdir().unwrap();
    let options = EnrollOptions {
        server: control.url.parse().unwrap(),
        name: NODE_NAME.to_owned(),
        labels: BTreeMap::new(),
        replace: false,
        ca_pin: None,
        state_dir: dir.path().to_path_buf(),
        hostname: "web-01.example.com".to_owned(),
        timeout: Duration::from_secs(60),
        join_token: None,
    };
    let enroll_clock = ManualClock::auto(SystemTime::now());
    let mut jitter = || 0.5;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    enroll(
        &options,
        &mut EnrollEnv {
            privileged: false,
            clock: &*enroll_clock,
            jitter: &mut jitter,
            out: &mut out,
            err: &mut err,
        },
    )
    .await
    .unwrap();

    let agent = Agent::start(dir.path(), ManualClock::new(SystemTime::now()));
    gate.wait_connected().await;
    eventually("the agent to accept SSH sessions", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    assert_eq!(first_line(&gate, "session-1").await, b"SSH-2.0-Jaunt\r\n");

    assert!(gate.registry.disconnect(&node_id()));
    gate.wait_connected().await;
    let mut gate = gate.restart().await;
    gate.wait_connected().await;
    assert_eq!(gate.registry.connected_nodes(), [node_id()]);

    agent.stop().await;
    gate.stop().await;
    let text = logs.text();
    assert!(text.contains("the tunnel is connected"));
    assert_no_key_material(&text, dir.path());
}

#[tokio::test]
async fn renewal_at_half_life_swaps_the_certificate_for_new_connections_only() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[
            RenewStep::Issue {
                not_before: t0 - 60,
                not_after: t0 + 2 * HOUR,
            },
            RenewStep::Issue {
                not_before: t0 - 60,
                not_after: t0 + 4 * HOUR,
            },
        ],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let old_x509 = node.file("x509.der");
    let old_ssh = node.file("ssh_host_ed25519-cert.pub");
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the startup calls of the agent API", || {
        !gate.requests(TRUST_PATH).is_empty()
            && !gate.requests(AGENT_CAPABILITIES_PATH).is_empty()
            && gate
                .requests(AGENT_SERVICES_PATH)
                .iter()
                .any(|seen| seen.method == "POST")
            && service_reads(&gate) > 0
    })
    .await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    assert!(gate.renewals().is_empty());

    clock.set(at_unix_secs(t0));
    eventually("the renewed certificate to be stored", || {
        node.file("x509.der") != old_x509
    })
    .await;
    eventually("the renewed state to be stored", || {
        node.record().x509_not_after == t0 + 2 * HOUR
    })
    .await;
    let new_x509 = node.file("x509.der");
    assert_ne!(node.file("ssh_host_ed25519-cert.pub"), old_ssh);
    let renewals = gate.renewals();
    assert_eq!(renewals.len(), 1);
    assert_eq!(renewals[0].node, node_id());
    assert_eq!(renewals[0].path, "/v1/agent/renew");
    assert_eq!(
        renewals[0].content_type.as_deref(),
        Some("application/json")
    );
    assert_eq!(
        renewals[0].request,
        Some(RenewRequest {
            tls_public_key: None,
            ssh_host_public_key: None,
        })
    );
    assert!(gate.auth.presented().iter().all(|der| *der == old_x509));
    loop {
        match gate.events.try_recv() {
            Ok(RegistryEvent::Disconnected { .. }) => panic!("the existing tunnel was dropped"),
            Ok(_) | Err(TryRecvError::Lagged(_)) => {}
            Err(TryRecvError::Empty | TryRecvError::Closed) => break,
        }
    }

    let presented_at_disconnect = gate.auth.presented().len();
    let reads_before = service_reads(&gate);
    assert!(gate.registry.disconnect(&node_id()));
    gate.wait_connected().await;
    eventually(
        "the approved services to be read after the reconnection",
        || service_reads(&gate) > reads_before,
    )
    .await;
    let reconnected = gate.auth.presented();
    assert!(
        reconnected.len() >= presented_at_disconnect + 2,
        "the tunnel and the API connection reconnect"
    );
    assert!(
        reconnected[presented_at_disconnect..]
            .iter()
            .all(|der| *der == new_x509)
    );
    clock.wait_for_sleeper(at_unix_secs(t0 + 3570)).await;
    clock.set(at_unix_secs(t0 + 3570));
    eventually("the second renewal to be stored", || {
        gate.renewals().len() == 2 && node.record().x509_not_after == t0 + 4 * HOUR
    })
    .await;
    let newest_x509 = node.file("x509.der");
    let presented = gate.auth.presented();
    assert!(
        presented[presented_at_disconnect..]
            .iter()
            .all(|der| *der == new_x509 || *der == newest_x509)
    );

    agent.stop().await;
    gate.stop().await;
    let text = logs.text();
    assert!(text.contains("renewed the node certificates"));
    assert_no_key_material(&text, node.dir.path());
}

#[tokio::test]
async fn failed_and_invalid_renewals_back_off_and_keep_the_old_files() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[
            RenewStep::Status(500, "server_error"),
            RenewStep::OtherKey,
            RenewStep::Issue {
                not_before: t0 - 60,
                not_after: t0 + 2 * HOUR,
            },
        ],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let before: Vec<Vec<u8>> = ["x509.der", "ssh_host_ed25519-cert.pub", "state.json"]
        .iter()
        .map(|name| node.file(name))
        .collect();
    let unchanged = || {
        ["x509.der", "ssh_host_ed25519-cert.pub", "state.json"]
            .iter()
            .map(|name| node.file(name))
            .collect::<Vec<_>>()
            == before
    };
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start_with_jitter(&node.path(), clock.clone(), 0.5);
    gate.wait_connected().await;

    eventually("the first attempt", || gate.renewals().len() == 1).await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 30)).await;
    assert!(unchanged());

    clock.set(at_unix_secs(t0 + 30));
    eventually("the second attempt", || gate.renewals().len() == 2).await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 90)).await;
    assert!(unchanged());

    clock.set(at_unix_secs(t0 + 90));
    eventually("the third attempt to store new files", || !unchanged()).await;
    assert_eq!(gate.renewals().len(), 3);

    agent.stop().await;
    gate.stop().await;
    let text = logs.text();
    assert_eq!(text.matches("certificate renewal failed").count(), 2);
    assert!(text.contains("the node certificate is for another key"));
    assert_no_key_material(&text, node.dir.path());
}

#[tokio::test]
async fn a_renewed_certificate_past_its_half_life_waits_at_least_a_minute() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[
            RenewStep::Issue {
                not_before: t0 - 2 * HOUR,
                not_after: t0 + 600,
            },
            RenewStep::Status(500, "server_error"),
        ],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the renewal to be stored", || {
        node.record().x509_not_after == t0 + 600
    })
    .await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 60)).await;
    assert_eq!(gate.renewals().len(), 1);
    assert!(
        clock
            .sleepers()
            .iter()
            .all(|deadline| *deadline >= at_unix_secs(t0 + 60))
    );

    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_removed_node_stops_renewing_after_one_attempt() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[RenewStep::Status(403, "node_removed")],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the renewal to stop", || {
        logs.text().contains("node_removed") && clock.sleepers().is_empty()
    })
    .await;
    clock.advance(Duration::from_secs(10 * 24 * 3600));
    assert_eq!(gate.renewals().len(), 1);
    assert!(gate.registry.is_connected(&node_id()));
    eventually("the renewal connection to close", || {
        gate.open_api_connections() < gate.api_connections()
    })
    .await;
    assert_eq!(gate.renewals().len(), 1);
    eventually("the trust set to be fetched", || {
        !gate.requests(TRUST_PATH).is_empty()
    })
    .await;
    assert_eq!(
        paths_besides_announcements(&gate),
        [
            "/v1/agent/renew",
            TRUST_PATH,
            TRUST_V2_PATH,
            AGENT_TRUST_V3_PATH
        ]
    );

    agent.stop().await;
    gate.stop().await;
    assert_eq!(logs.text().matches("was removed").count(), 1);
}

#[tokio::test]
async fn an_expired_certificate_asks_for_reenrollment_without_renewal() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    for (now, reports) in [(t0 + HOUR, 1), (t0 + 2 * HOUR, 2)] {
        let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
        let clock = ManualClock::new(at_unix_secs(now));
        let agent = Agent::start(&node.path(), clock.clone());
        gate.wait_connected().await;
        eventually("the expiry to be reported", || {
            logs.text().matches("jaunt-agent enroll --replace").count() == reports
        })
        .await;
        eventually("the trust set to be fetched", || {
            !gate.requests(TRUST_PATH).is_empty()
        })
        .await;
        assert!(gate.renewals().is_empty());
        assert_eq!(
            paths_besides_announcements(&gate),
            [TRUST_PATH, TRUST_V2_PATH, AGENT_TRUST_V3_PATH]
        );

        agent.stop().await;
        gate.stop().await;
    }
}

#[tokio::test]
async fn aborting_the_agent_closes_its_api_connection() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let agent = Agent::start(&node.path(), ManualClock::new(at_unix_secs(t0 - 600)));
    gate.wait_connected().await;
    eventually("the trust fetch to hold an API connection", || {
        !gate.requests(TRUST_PATH).is_empty() && gate.open_api_connections() == 1
    })
    .await;
    agent.join.abort();
    eventually("the API connection to close", || {
        gate.open_api_connections() == 0
    })
    .await;
    agent.shutdown.cancel();
    gate.stop().await;
}

#[tokio::test]
async fn run_refuses_to_start_without_a_usable_sshd_host_key() {
    let t0 = unix_now();
    let (_pki, gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let sshd = tempfile::tempdir().unwrap();
    let env = || RunEnv {
        clock: Arc::new(SystemClock),
        jitter: Box::new(|| 0.5),
        passwd: None,
    };
    let missing = settings(&node.path(), sshd.path().join("missing.pub"));
    let error = soon("the refusal", run(missing, env(), CancellationToken::new()))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        RunError::InnerTarget(InnerTargetError::HostKey {
            source: SshError::ReadFile { .. },
            ..
        })
    ));
    assert!(error.to_string().contains("missing.pub"));
    let wrong = sshd.path().join("rsa.pub");
    fs::write(&wrong, "ssh-rsa AAAAB3NzaC1yc2E= root@host\n").unwrap();
    let error = soon(
        "the refusal",
        run(
            settings(&node.path(), wrong),
            env(),
            CancellationToken::new(),
        ),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        error,
        RunError::InnerTarget(InnerTargetError::HostKey {
            source: SshError::PinnedHostKey,
            ..
        })
    ));
    assert!(!node.dir.path().join("inner-ca.pub").exists());
    assert!(gate.registry.connected_nodes().is_empty());
    gate.stop().await;
}

#[tokio::test]
async fn the_inner_ca_is_published_for_sshd_and_replaced_at_every_start() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let mut published = Vec::new();
    for _ in 0..2 {
        let agent = Agent::start(&node.path(), ManualClock::new(SystemTime::now()));
        gate.wait_connected().await;
        let path = node.dir.path().join("inner-ca.pub");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o644);
        let line = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        assert!(
            line.starts_with("ssh-ed25519 ") && line.ends_with('\n'),
            "{line}"
        );
        assert_eq!(line.lines().count(), 1);
        published.push(line);
        agent.stop().await;
    }
    assert_ne!(published[0], published[1]);
    let leftovers: Vec<String> = fs::read_dir(node.dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    gate.stop().await;
}

#[tokio::test]
async fn streams_are_refused_until_the_trust_set_loads_and_a_trust_update_refetches_it() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    gate.set_standing(
        TRUST_PATH,
        ApiStep::Json(503, json!({"error": "unavailable"})),
    );
    let agent = Agent::start(&node.path(), ManualClock::new(SystemTime::now()));
    gate.wait_connected().await;
    eventually("a failed trust fetch", || {
        !gate.requests(TRUST_PATH).is_empty()
    })
    .await;
    assert!(first_line(&gate, "early").await.is_empty());
    eventually("the refusal to be logged", || {
        logs.text().contains("\"reason\":\"trust_not_loaded\"")
    })
    .await;

    gate.set_standing(TRUST_PATH, trust_reply(&[user_ca_line()]));
    eventually("the trust set to load", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    assert_eq!(first_line(&gate, "later").await, b"SSH-2.0-Jaunt\r\n");

    let fetched = gate.requests(TRUST_PATH).len();
    gate.registry.send_trust_update(&node_id()).unwrap();
    eventually("the announced set to be fetched", || {
        logs.text().contains("\"wake\":\"announced\"") && gate.requests(TRUST_PATH).len() > fetched
    })
    .await;
    assert!(
        gate.requests(TRUST_PATH)
            .iter()
            .all(|seen| seen.node == node_id() && seen.method == "GET")
    );

    agent.stop().await;
    gate.stop().await;
    assert_no_key_material(&logs.text(), node.dir.path());
}

#[tokio::test]
async fn the_agent_announces_its_capabilities_once_the_tunnel_is_up_and_keeps_repeating() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let helper = tempfile::tempdir().unwrap();
    let socket = helper.path().join("h.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let agent = Agent::start_with(
        &node.path(),
        ManualClock::new(SystemTime::now()),
        1.0,
        |settings| {
            settings.host_users = HostUsersSection {
                enabled: true,
                ..HostUsersSection::default()
            };
            settings.host_users_paths = HostUsersPaths {
                socket,
                nsswitch: helper.path().join("nsswitch.conf"),
                sssd_conf: helper.path().join("sssd.conf"),
            };
            settings.accounts.announce_every = Duration::from_millis(50);
        },
    );
    gate.wait_connected().await;
    eventually("repeated announcements despite 404 answers", || {
        gate.requests(AGENT_CAPABILITIES_PATH).len() >= 3
    })
    .await;
    assert!(gate.requests(AGENT_CAPABILITIES_PATH).iter().all(|seen| {
        seen.node == node_id()
            && seen.method == "PUT"
            && serde_json::from_slice::<serde_json::Value>(&seen.body).unwrap()
                == json!({"creates_accounts": true})
    }));
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn the_agent_announces_its_services_once_the_tunnel_is_up() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    gate.set_standing(AGENT_SERVICES_PATH, ApiStep::Json(204, json!({})));
    let declared: ServiceAnnouncement = serde_json::from_value(json!({
        "ssh_enabled": false,
        "services": [{"kind": "tcp", "name": "grafana", "labels": {"team": "ops"},
                      "address": "10.0.0.5:3000"}],
    }))
    .unwrap();
    let expected = serde_json::to_value(&declared).unwrap();
    let agent = Agent::start_with(
        &node.path(),
        ManualClock::new(SystemTime::now()),
        1.0,
        |settings| settings.services = declared,
    );
    gate.wait_connected().await;
    eventually("the service announcement", || {
        !gate.requests(AGENT_SERVICES_PATH).is_empty()
    })
    .await;
    eventually("the service announcement", || {
        gate.requests(AGENT_SERVICES_PATH)
            .iter()
            .any(|seen| seen.method == "POST")
    })
    .await;
    let seen: Vec<_> = gate
        .requests(AGENT_SERVICES_PATH)
        .into_iter()
        .filter(|seen| seen.method == "POST")
        .collect();
    assert_eq!(seen[0].node, node_id());
    assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&seen[0].body).unwrap(),
        expected
    );
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_renewal_presents_the_new_host_certificate_to_new_ssh_connections() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 2 * HOUR,
        }],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let before = certificate_file(&node);
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the agent to accept SSH sessions", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    assert_eq!(presented_host_certificate(&gate, "before").await, before);

    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    clock.set(at_unix_secs(t0));
    eventually("the renewed host certificate to be used", || {
        logs.text()
            .contains("new SSH connections use the renewed host certificate")
    })
    .await;
    let after = certificate_file(&node);
    assert_ne!(after, before);
    assert_eq!(presented_host_certificate(&gate, "after").await, after);

    agent.stop().await;
    gate.stop().await;
}

#[test]
fn the_tunnel_is_configured_with_the_ssh_windows_and_the_given_backoff() {
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let endpoint = AgentEndpoint::parse("agents.example.com:8443").unwrap();
    let config = tunnel_config(Arc::new(tls), &endpoint, FAST);
    assert_eq!(config.options.stream_window, 1024 * 1024);
    assert_eq!(config.options.connection_window, 16 * 1024 * 1024);
    assert_eq!(
        (SSH_STREAM_WINDOW, SSH_CONNECTION_WINDOW),
        (1024 * 1024, 16 * 1024 * 1024)
    );
    assert_eq!(config.options.validate(), Ok(()));
    assert_eq!(config.backoff, FAST);
    assert_eq!(config.server_addr, "agents.example.com:8443");
    assert_eq!(config.sni, "agents.example.com");
}

#[tokio::test]
async fn without_a_host_certificate_streams_are_refused_until_a_renewal_supplies_one() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 2 * HOUR,
        }],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    fs::write(
        node.dir.path().join("ssh_host_ed25519-cert.pub"),
        "not a certificate\n",
    )
    .unwrap();
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the trust set to load", || {
        logs.text().contains("loaded the user CA trust set")
    })
    .await;
    assert!(first_line(&gate, "early").await.is_empty());
    eventually("the refusal to be logged", || {
        logs.text()
            .contains("\"reason\":\"host_certificate_not_loaded\"")
    })
    .await;

    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    clock.set(at_unix_secs(t0));
    eventually("the renewal to make the agent ready", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    assert_eq!(first_line(&gate, "later").await, b"SSH-2.0-Jaunt\r\n");
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn terminating_a_session_in_the_tunnel_cancels_the_ssh_session() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let agent = Agent::start(&node.path(), ManualClock::new(SystemTime::now()));
    gate.wait_connected().await;
    eventually("the agent to accept SSH sessions", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    let mut stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta("doomed"))
        .await
        .unwrap();
    let mut banner = [0_u8; 15];
    soon("the banner", stream.read_exact(&mut banner))
        .await
        .unwrap();
    assert_eq!(&banner, b"SSH-2.0-Jaunt\r\n");

    gate.registry
        .terminate_session(&node_id(), &SessionId::new("doomed").unwrap())
        .unwrap();
    let mut rest = Vec::new();
    assert!(
        soon("the stream to close", stream.read_to_end(&mut rest))
            .await
            .is_err()
    );
    eventually("the SSH session to end", || {
        let text = logs.text();
        text.contains("\"event\":\"agent.ssh.end\"") && text.contains("\"session_id\":\"doomed\"")
    })
    .await;
    agent.stop().await;
    gate.stop().await;
}

struct User {
    ca_line: String,
    key: Arc<PrivateKey>,
    certificate: Certificate,
}

fn user() -> User {
    let ca = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let now = u64::try_from(unix_now()).unwrap();
    let mut builder = Builder::new_with_random_nonce(
        &mut safe_rng(),
        key.public_key().key_data().clone(),
        now - 120,
        now + 3600,
    )
    .unwrap();
    builder.serial(7).unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.key_id("jaunt:alice@example.com:7").unwrap();
    builder
        .valid_principal("4f0e7a52-6c1b-4b39-9d55-2a8f1f0c7e11")
        .unwrap();
    User {
        ca_line: ca.public_key().to_openssh().unwrap(),
        key: Arc::new(key),
        certificate: builder.sign(&ca).unwrap(),
    }
}

#[tokio::test]
async fn stopping_the_agent_still_reports_the_end_of_a_live_session() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let user = user();
    gate.set_standing(TRUST_PATH, trust_reply(std::slice::from_ref(&user.ca_line)));
    gate.script(
        AUTHORIZE_PATH,
        vec![ApiStep::Json(
            200,
            json!({"decision": "allow", "permissions": {
                "pty": true, "port_forwarding": false, "record_input": false,
                "max_duration_secs": 3600,
            }}),
        )],
    );
    gate.set_standing(
        SESSION_END_PATH,
        ApiStep::Json(200, json!({"outcome": "recorded"})),
    );
    let silent_sshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sshd_addr = silent_sshd.local_addr().unwrap();
    let agent = Agent::start_with(
        &node.path(),
        ManualClock::new(SystemTime::now()),
        1.0,
        |settings| settings.inner.sshd_addr = sshd_addr,
    );
    gate.wait_connected().await;
    eventually("the trust set to load", || {
        !gate.requests(TRUST_PATH).is_empty()
    })
    .await;

    let stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta("live"))
        .await
        .unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut handle = soon(
        "the SSH handshake",
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            HostCertificates(seen),
        ),
    )
    .await
    .unwrap();
    let login = tokio::spawn(async move {
        let outcome = handle
            .authenticate_openssh_cert("deploy", user.key, user.certificate)
            .await;
        (handle, outcome)
    });
    let (_inner, _) = soon("the inner login to reach sshd", silent_sshd.accept())
        .await
        .unwrap();
    assert_eq!(gate.requests(AUTHORIZE_PATH).len(), 1);
    assert!(gate.requests(SESSION_END_PATH).is_empty());

    agent.stop().await;
    let ends = gate.requests(SESSION_END_PATH);
    assert_eq!(ends.len(), 1);
    let end: jaunt_proto::SessionEnd = serde_json::from_slice(&ends[0].body).unwrap();
    assert_eq!(end.session_id, "live");
    login.abort();
    gate.stop().await;
}

fn host_ca_key(line: &str) -> ssh_key::public::KeyData {
    ssh_key::PublicKey::from_openssh(line)
        .unwrap()
        .key_data()
        .clone()
}

fn stored_signer(node: &Enrolled) -> Option<ssh_key::public::KeyData> {
    host_signer(&certificate_file(node))
}

#[tokio::test]
async fn an_old_server_without_the_second_trust_version_keeps_the_half_life_schedule() {
    let t0 = unix_now();
    let (pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    pki.rotate_host_ca();
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    eventually("the first trust version to be read", || {
        !gate.requests(TRUST_PATH).is_empty()
    })
    .await;
    gate.registry.send_trust_update(&node_id()).unwrap();
    eventually("the announced set to be read", || {
        gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    assert_eq!(clock.sleepers(), [at_unix_secs(t0)]);
    assert_eq!(gate.requests(TRUST_V2_PATH).len(), 1);
    assert!(gate.renewals().is_empty());
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_new_active_host_ca_key_renews_the_host_certificate_once_within_the_spread() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (pki, mut gate, node) = gate_and_node(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 4 * HOUR,
        }],
        t0 - HOUR,
        t0 + 3 * HOUR,
    )
    .await;
    let previous = host_ca_key(&pki.host_ca_line());
    let active = pki.rotate_host_ca();
    gate.set_standing(TRUST_V2_PATH, trust_v2_reply(&[user_ca_line()], &active));
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start_with_jitter(&node.path(), clock.clone(), 0.5);
    gate.wait_connected().await;
    assert_eq!(stored_signer(&node), Some(previous));
    clock.wait_for_sleeper(at_unix_secs(t0 + 150)).await;
    assert!(gate.renewals().is_empty());

    clock.set(at_unix_secs(t0 + 150));
    eventually("the host certificate to be signed by the new key", || {
        stored_signer(&node) == Some(host_ca_key(&active))
    })
    .await;
    let half_life = at_unix_secs((t0 - 60 + t0 + 4 * HOUR) / 2);
    clock.wait_for_sleeper(half_life).await;
    gate.registry.send_trust_update(&node_id()).unwrap();
    eventually("the announced set to be read", || {
        gate.requests(TRUST_V2_PATH).len() == 2
    })
    .await;
    clock.wait_for_sleeper(half_life).await;
    assert_eq!(gate.renewals().len(), 1);
    assert_eq!(clock.sleepers(), [half_life]);
    assert!(gate.requests(TRUST_PATH).is_empty());
    agent.stop().await;
    gate.stop().await;
    assert!(
        logs.text()
            .contains("the host certificate is renewed early")
    );
    assert_no_key_material(&logs.text(), node.dir.path());
}

#[tokio::test]
async fn a_failed_early_renewal_retries_with_the_renewal_backoff() {
    let t0 = unix_now();
    let (pki, mut gate, node) = gate_and_node(
        &[
            RenewStep::Status(500, "server_error"),
            RenewStep::Issue {
                not_before: t0 - 60,
                not_after: t0 + 4 * HOUR,
            },
        ],
        t0 - HOUR,
        t0 + 3 * HOUR,
    )
    .await;
    let active = pki.rotate_host_ca();
    gate.set_standing(TRUST_V2_PATH, trust_v2_reply(&[user_ca_line()], &active));
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start_with_jitter(&node.path(), clock.clone(), 0.5);
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 150)).await;
    clock.set(at_unix_secs(t0 + 150));
    eventually("the first attempt", || gate.renewals().len() == 1).await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 180)).await;
    assert_ne!(stored_signer(&node), Some(host_ca_key(&active)));

    clock.set(at_unix_secs(t0 + 180));
    eventually("the retry to store the new host certificate", || {
        stored_signer(&node) == Some(host_ca_key(&active))
    })
    .await;
    assert_eq!(gate.renewals().len(), 2);
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_refused_certificate_rereads_the_trust_set_and_is_accepted_next_time() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let user = user();
    let previous = user_ca_line();
    gate.set_standing(TRUST_PATH, trust_reply(std::slice::from_ref(&previous)));
    gate.script(
        AUTHORIZE_PATH,
        vec![ApiStep::Json(
            200,
            json!({"decision": "allow", "permissions": {
                "pty": false, "port_forwarding": false, "record_input": false,
                "max_duration_secs": 3600,
            }}),
        )],
    );
    gate.set_standing(
        SESSION_END_PATH,
        ApiStep::Json(200, json!({"outcome": "recorded"})),
    );
    let silent_sshd = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sshd_addr = silent_sshd.local_addr().unwrap();
    let agent = Agent::start_with(
        &node.path(),
        ManualClock::new(SystemTime::now()),
        1.0,
        |settings| settings.inner.sshd_addr = sshd_addr,
    );
    gate.wait_connected().await;
    eventually("the agent to accept SSH sessions", || {
        logs.text().contains("the agent now accepts SSH sessions")
    })
    .await;
    gate.set_standing(TRUST_PATH, trust_reply(&[previous, user.ca_line.clone()]));

    let mut refused = connect_user(&gate, "refused").await;
    let outcome = refused
        .authenticate_openssh_cert("deploy", user.key.clone(), user.certificate.clone())
        .await
        .unwrap();
    assert!(!outcome.success());
    eventually("the refusal to reread the trust set", || {
        logs.text().contains("\"wake\":\"untrusted_ca\"") && gate.requests(TRUST_PATH).len() == 2
    })
    .await;
    assert!(gate.requests(AUTHORIZE_PATH).is_empty());
    eventually("the reread set to be installed", || {
        logs.text().matches("loaded the user CA trust set").count() == 2
    })
    .await;

    let mut accepted = connect_user(&gate, "accepted").await;
    let login = tokio::spawn(async move {
        let outcome = accepted
            .authenticate_openssh_cert("deploy", user.key, user.certificate)
            .await;
        (accepted, outcome)
    });
    let (_inner, _) = soon("the inner login to reach sshd", silent_sshd.accept())
        .await
        .unwrap();
    assert_eq!(gate.requests(AUTHORIZE_PATH).len(), 1);
    agent.stop().await;
    login.abort();
    gate.stop().await;
}

async fn connect_user(gate: &FakeGate, session: &str) -> client::Handle<HostCertificates> {
    let stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta(session))
        .await
        .unwrap();
    soon(
        "the SSH handshake",
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            HostCertificates(Arc::new(Mutex::new(Vec::new()))),
        ),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_announced_key_matching_the_stored_certificate_keeps_the_half_life_schedule() {
    let t0 = unix_now();
    let (pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let release = Arc::new(tokio::sync::Notify::new());
    let reply = trust_v2_reply(&[user_ca_line()], &pki.host_ca_line());
    gate.script(
        TRUST_V2_PATH,
        vec![ApiStep::Held(release.clone(), Box::new(reply.clone()))],
    );
    gate.set_standing(TRUST_V2_PATH, reply);
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    assert_eq!(clock.slept().len(), 1);
    release.notify_one();
    eventually("the renewal loop to see the announced key", || {
        clock.slept().len() >= 2
    })
    .await;
    assert_eq!(clock.sleepers(), [at_unix_secs(t0)]);
    assert!(gate.renewals().is_empty());
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_server_that_still_signs_with_the_old_key_gets_one_early_renewal() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 4 * HOUR,
        }],
        t0 - HOUR,
        t0 + 3 * HOUR,
    )
    .await;
    let announced = user_ca_line();
    gate.set_standing(TRUST_V2_PATH, trust_v2_reply(&[user_ca_line()], &announced));
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start_with_jitter(&node.path(), clock.clone(), 0.5);
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 150)).await;
    clock.set(at_unix_secs(t0 + 150));
    eventually("the early renewal", || gate.renewals().len() == 1).await;
    let half_life = at_unix_secs((t0 - 60 + t0 + 4 * HOUR) / 2);
    clock.wait_for_sleeper(half_life).await;
    assert_ne!(stored_signer(&node), Some(host_ca_key(&announced)));

    clock.set(at_unix_secs(t0 + 750));
    clock.wait_for_sleeper(half_life).await;
    assert_eq!(clock.sleepers(), [half_life]);
    assert_eq!(gate.renewals().len(), 1);
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test]
async fn a_second_new_key_within_a_minute_waits_for_the_renewal_floor() {
    let t0 = unix_now();
    let issue = RenewStep::Issue {
        not_before: t0 - 60,
        not_after: t0 + 4 * HOUR,
    };
    let (pki, mut gate, node) =
        gate_and_node(&[issue.clone(), issue], t0 - HOUR, t0 + 3 * HOUR).await;
    let first = pki.rotate_host_ca();
    gate.set_standing(TRUST_V2_PATH, trust_v2_reply(&[user_ca_line()], &first));
    let clock = ManualClock::new(at_unix_secs(t0));
    let agent = Agent::start_with_jitter(&node.path(), clock.clone(), 0.0);
    gate.wait_connected().await;
    eventually("the first early renewal", || {
        stored_signer(&node) == Some(host_ca_key(&first))
    })
    .await;

    let second = pki.rotate_host_ca();
    gate.set_standing(TRUST_V2_PATH, trust_v2_reply(&[user_ca_line()], &second));
    gate.registry.send_trust_update(&node_id()).unwrap();
    clock.wait_for_sleeper(at_unix_secs(t0 + 60)).await;
    assert_eq!(gate.renewals().len(), 1);

    clock.set(at_unix_secs(t0 + 60));
    eventually("the second early renewal", || {
        stored_signer(&node) == Some(host_ca_key(&second))
    })
    .await;
    assert_eq!(gate.renewals().len(), 2);
    agent.stop().await;
    gate.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_trust_loader_does_not_spin_the_renewal_loop() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 4 * HOUR,
        }],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let release = Arc::new(tokio::sync::Notify::new());
    gate.script(
        TRUST_V2_PATH,
        vec![ApiStep::Held(
            release.clone(),
            Box::new(ApiStep::Json(403, json!({"error": "node_removed"}))),
        )],
    );
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(&node.path(), clock.clone());
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    release.notify_one();
    eventually("the renewal loop to see the loader stop", || {
        clock.slept().len() >= 2
    })
    .await;
    clock.set(at_unix_secs(t0));
    eventually("the renewal at half-life", || gate.renewals().len() == 1).await;
    assert!(clock.slept().len() < 10, "{}", clock.slept().len());
    assert_eq!(gate.requests(TRUST_V2_PATH).len(), 1);
    agent.stop().await;
    gate.stop().await;
}

struct AcceptingSshd {
    started: Arc<tokio::sync::Notify>,
    channels: Vec<russh::Channel<russh::server::Msg>>,
}

impl russh::server::Handler for AcceptingSshd {
    type Error = russh::Error;

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<russh::server::Auth, Self::Error> {
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.push(channel);
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: russh::ChannelId,
        _data: &[u8],
        session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.started.notify_one();
        Ok(())
    }
}

async fn accepting_sshd(dir: &Path) -> (SocketAddr, PathBuf, Arc<tokio::sync::Notify>) {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    let host_key = dir.join("inner_host_key.pub");
    fs::write(
        &host_key,
        format!("{}\n", key.public_key().to_openssh().unwrap()),
    )
    .unwrap();
    let config = Arc::new(russh::server::Config {
        keys: vec![key],
        ..russh::server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let started = Arc::new(tokio::sync::Notify::new());
    let notify = Arc::clone(&started);
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let handler = AcceptingSshd {
                started: Arc::clone(&notify),
                channels: Vec::new(),
            };
            let config = Arc::clone(&config);
            tokio::spawn(async move {
                if let Ok(running) = russh::server::run_stream(config, tcp, handler).await {
                    drop(running.await);
                }
            });
        }
    });
    (addr, host_key, started)
}

#[tokio::test]
async fn stopping_the_agent_lets_a_pending_recording_upload_finish() {
    let t0 = unix_now();
    let (_pki, mut gate, node) = gate_and_node(&[], t0 - HOUR, t0 + HOUR).await;
    let logs = LogCapture::default();
    let _guard = logs.install();
    let user = user();
    gate.set_standing(TRUST_PATH, trust_reply(std::slice::from_ref(&user.ca_line)));
    gate.script(
        AUTHORIZE_PATH,
        vec![ApiStep::Json(
            200,
            json!({"decision": "allow", "permissions": {
                "pty": true, "port_forwarding": false, "record_input": false,
                "max_duration_secs": 3600,
            }}),
        )],
    );
    gate.set_standing(
        SESSION_END_PATH,
        ApiStep::Json(200, json!({"outcome": "recorded"})),
    );
    let complete_path = jaunt_proto::recording_complete_path("live");
    let release = Arc::new(tokio::sync::Notify::new());
    gate.script(
        &complete_path,
        vec![ApiStep::Held(
            Arc::clone(&release),
            Box::new(ApiStep::Json(
                200,
                json!({"state": "complete", "chunks": 0}),
            )),
        )],
    );
    let inner = tempfile::tempdir().unwrap();
    let (sshd_addr, sshd_host_key, exec_started) = accepting_sshd(inner.path()).await;
    let agent = Agent::start_with(
        &node.path(),
        ManualClock::new(SystemTime::now()),
        1.0,
        |settings| {
            settings.inner.sshd_addr = sshd_addr;
            settings.inner.sshd_host_key = sshd_host_key;
        },
    );
    gate.wait_connected().await;
    eventually("the trust set to load", || {
        !gate.requests(TRUST_PATH).is_empty()
    })
    .await;
    let stream = gate
        .registry
        .open_stream(&node_id(), &stream_meta("live"))
        .await
        .unwrap();
    let mut handle = soon(
        "the SSH handshake",
        client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            HostCertificates(Arc::default()),
        ),
    )
    .await
    .unwrap();
    let authenticated = soon(
        "the login",
        handle.authenticate_openssh_cert("deploy", user.key, user.certificate),
    )
    .await
    .unwrap();
    assert!(authenticated.success());
    let channel = soon("a session channel", handle.channel_open_session())
        .await
        .unwrap();
    channel.exec(true, "sleep 300").await.unwrap();
    soon("the inner exec", exec_started.notified()).await;

    let stopping = tokio::spawn(agent.stop());
    eventually("the recording manifest to reach the server", || {
        !gate.requests(&complete_path).is_empty()
    })
    .await;
    release.notify_one();
    soon("the agent to stop", stopping).await.unwrap();
    let text = logs.text();
    assert!(text.contains("agent.ssh.recording_stored"), "{text}");
    assert!(!text.contains("agent.ssh.recording_dropped"), "{text}");
    drop(handle);
    gate.stop().await;
}
