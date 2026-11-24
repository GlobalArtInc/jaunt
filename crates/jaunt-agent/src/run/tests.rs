use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_proto::RenewRequest;
use jaunt_tunnel::{BackoffPolicy, NodeId, RegistryEvent, SessionId, StreamKind, StreamMeta};
use tokio::io::AsyncReadExt;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::{RunEnv, RunError, RunSettings, run};
use crate::clock::{SystemClock, at_unix_secs};
use crate::enroll::{EnrollEnv, EnrollOptions, enroll};
use crate::keys::{HostKey, TlsKey};
use crate::state::{EnrollmentFiles, EnrollmentRecord, StateDir, StateError};
use crate::testkit::{
    Approval, ControlScript, FakeControl, FakeGate, LogCapture, ManualClock, NODE_ID, NODE_NAME,
    NodeIdentity, PollStep, RenewStep, TestPki, eventually, soon, unix_now,
};

const HOUR: i64 = 3600;

struct Agent {
    shutdown: CancellationToken,
    join: JoinHandle<Result<(), RunError>>,
}

impl Agent {
    fn start(dir: &Path, clock: Arc<ManualClock>) -> Self {
        Self::start_with_jitter(dir, clock, 1.0)
    }

    fn start_with_jitter(dir: &Path, clock: Arc<ManualClock>, sample: f64) -> Self {
        let settings = RunSettings {
            tunnel_backoff: BackoffPolicy {
                initial: Duration::from_millis(20),
                max: Duration::from_millis(200),
                reset_after: Duration::from_secs(30),
            },
            ..RunSettings::new(dir.to_path_buf())
        };
        let env = RunEnv {
            clock,
            jitter: Box::new(move || sample),
        };
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(run(settings, env, shutdown.clone()));
        Self { shutdown, join }
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

fn node_id() -> NodeId {
    NodeId::new(NODE_ID).unwrap()
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
async fn an_enrolled_agent_holds_its_tunnel_refuses_streams_and_survives_drops_and_restarts() {
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

    let meta = StreamMeta::new(
        SessionId::new("session-1").unwrap(),
        StreamKind::Ssh,
        "203.0.113.5:40000",
    )
    .unwrap();
    let mut stream = gate.registry.open_stream(&node_id(), &meta).await.unwrap();
    let mut received = Vec::new();
    soon(
        "the refused stream to end",
        stream.read_to_end(&mut received),
    )
    .await
    .unwrap();
    assert!(received.is_empty());
    eventually("the refusal to be logged", || {
        logs.text().contains("\"refused_streams\":1")
    })
    .await;

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

    assert!(gate.registry.disconnect(&node_id()));
    gate.wait_connected().await;
    assert_eq!(gate.auth.presented().last(), Some(&new_x509));
    clock.wait_for_sleeper(at_unix_secs(t0 + 3570)).await;
    let presented_before = gate.auth.presented().len();
    clock.set(at_unix_secs(t0 + 3570));
    eventually("the second renewal", || gate.renewals().len() == 2).await;
    let presented = gate.auth.presented();
    assert_eq!(presented.len(), presented_before + 1);
    assert_eq!(presented.last(), Some(&new_x509));

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
    eventually("the idle API connection to close", || {
        gate.open_api_connections() == 0
    })
    .await;

    agent.stop().await;
    gate.stop().await;
    assert_eq!(logs.text().matches("was removed").count(), 1);
}

#[tokio::test]
async fn an_expired_certificate_asks_for_reenrollment_without_calling_the_server() {
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
        assert!(gate.renewals().is_empty());
        assert_eq!(gate.api_connections(), 0);

        agent.stop().await;
        gate.stop().await;
    }
}
