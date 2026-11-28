mod fake;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_host_users::Name;
use jaunt_proto::{AGENT_SERVICES_PATH, ServiceAnnouncement};
use jaunt_tunnel::{
    BackoffPolicy, BoxFuture, NodeId, OpenError, RegistryEvent, SessionId, StreamKind, StreamMeta,
};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::client::{ApiError, IN_CLUSTER_API, SecretClient, SetupError, api_address};
use super::persist::{PERSIST_BACKOFF, PersistTiming};
use super::secret::KubernetesSecret;
use super::{
    ClusterError, EnrollPlan, KubernetesBackend, MirrorError, Restored, StateBackend, StateMirror,
    serve,
};
use crate::accounts::{LookupError, PasswdLookup, Presence};
use crate::clock::{Clock, at_unix_secs};
use crate::enroll::EnrollError;
use crate::fsio::effective_uid;
use crate::keys::{HostKey, TlsKey, sha256_hex};
use crate::pin::CaPin;
use crate::run::config::InnerConfig;
use crate::run::{RunEnv, RunError, RunSettings};
use crate::state::{EnrollmentFiles, EnrollmentRecord, MANAGED_FILES, StateDir, StateError};
use crate::testkit::{
    Approval, ControlScript, FakeControl, FakeGate, LogCapture, ManualClock, NODE_ID, NODE_NAME,
    NodeIdentity, PollStep, RenewStep, TestPki, eventually, soon, unix_now,
};
use crate::trust::TrustTiming;
use fake::{FakeKube, SA_TOKEN, Step, Stored};

const TOKEN: &str = "jt1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HOUR: i64 = 3600;
const WEEK: i64 = 7 * 24 * HOUR;
const CLUSTER_NODE: &str = "kube-prod";
const FAST: BackoffPolicy = BackoffPolicy {
    initial: Duration::from_millis(20),
    max: Duration::from_millis(200),
    reset_after: Duration::from_secs(30),
};

struct NoAccounts;

impl PasswdLookup for NoAccounts {
    fn passwd<'a>(&'a self, _login: &'a Name) -> BoxFuture<'a, Result<Presence, LookupError>> {
        Box::pin(async { Ok(Presence::Absent) })
    }
}

fn announcement() -> ServiceAnnouncement {
    serde_json::from_value(json!({
        "ssh_enabled": false,
        "services": [{"kind": "kubernetes", "name": "prod",
                      "kubernetes": {"api": "in-cluster", "audit": "mutating"}}],
    }))
    .unwrap()
}

fn settings(state_dir: PathBuf) -> RunSettings {
    RunSettings {
        inner: InnerConfig {
            sshd_host_key: PathBuf::from("/nonexistent/etc/ssh/ssh_host_ed25519_key.pub"),
            ..InnerConfig::default()
        },
        services: announcement(),
        tunnel_backoff: FAST,
        trust: TrustTiming {
            backoff: FAST,
            refresh_min: Duration::from_secs(3600),
            refresh_max: Duration::from_secs(3600),
            wake_jitter: Duration::from_millis(1),
            refusal_interval: Duration::from_secs(60),
        },
        privileged: false,
        ..RunSettings::new(state_dir)
    }
}

struct Pod {
    root: tempfile::TempDir,
}

impl Pod {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().unwrap(),
        }
    }

    fn state(&self) -> PathBuf {
        self.root.path().join("state")
    }

    fn token(&self) -> PathBuf {
        self.root.path().join("join-token")
    }

    fn with_token(self) -> Self {
        fs::write(self.token(), format!("{TOKEN}\n")).unwrap();
        fs::set_permissions(self.token(), fs::Permissions::from_mode(0o644)).unwrap();
        self
    }

    fn file(&self, name: &str) -> Vec<u8> {
        fs::read(self.state().join(name)).unwrap()
    }

    fn mode(&self, name: &str) -> u32 {
        fs::metadata(self.state().join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }
}

fn pin_of(pki: &TestPki) -> CaPin {
    format!("sha256:{}", sha256_hex(pki.root_der()))
        .parse()
        .unwrap()
}

fn backend(kube: &FakeKube, server: &str, pod: &Pod, name: &str, ca_pin: CaPin) -> StateBackend {
    StateBackend::Kubernetes(Box::new(KubernetesBackend {
        cluster: kube.settings(),
        enrollment: EnrollPlan {
            server: server.parse().unwrap(),
            name: name.to_owned(),
            labels: BTreeMap::new(),
            ca_pin,
            token_file: pod.token(),
            token_attempts: 3,
            token_retry_every: Duration::from_secs(1),
            hostname: Some("jaunt-agent-7d9f8".to_owned()),
        },
        timing: PersistTiming {
            backoff: PERSIST_BACKOFF,
            log_every: Duration::from_secs(60),
            sample: Arc::new(|| 1.0),
        },
    }))
}

fn env(clock: Arc<ManualClock>) -> RunEnv {
    RunEnv {
        clock,
        jitter: Box::new(|| 1.0),
        passwd: Some(Arc::new(NoAccounts)),
    }
}

struct Agent {
    shutdown: CancellationToken,
    join: JoinHandle<Result<(), RunError>>,
}

impl Agent {
    fn start(pod: &Pod, clock: Arc<ManualClock>, backend: StateBackend) -> Self {
        let shutdown = CancellationToken::new();
        let join = tokio::spawn(serve(
            settings(pod.state()),
            env(clock),
            shutdown.clone(),
            backend,
        ));
        Self { shutdown, join }
    }

    async fn stop(self) {
        self.shutdown.cancel();
        soon("the agent to stop", self.join).await.unwrap().unwrap();
    }

    async fn failure(self) -> RunError {
        soon("the agent to fail", self.join)
            .await
            .unwrap()
            .unwrap_err()
    }
}

struct Enrollment {
    data: BTreeMap<String, String>,
    identity: NodeIdentity,
    pin: CaPin,
}

fn enrollment(pki: &TestPki, endpoint: &str, not_before: i64, not_after: i64) -> Enrollment {
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
    let data = MANAGED_FILES
        .iter()
        .map(|name| {
            let content = fs::read(dir.path().join(name)).unwrap();
            ((*name).to_owned(), STANDARD.encode(content))
        })
        .collect();
    Enrollment {
        data,
        identity: NodeIdentity {
            spki: tls.spki_der().to_vec(),
            host_key: host.key_data().clone(),
        },
        pin: pin_of(pki),
    }
}

fn placeholder() -> NodeIdentity {
    NodeIdentity {
        spki: Vec::new(),
        host_key: HostKey::generate().unwrap().key_data().clone(),
    }
}

async fn restored_agent(
    renewals: &[RenewStep],
    not_before: i64,
    not_after: i64,
) -> (FakeGate, FakeKube, Enrollment) {
    let pki = Arc::new(TestPki::new());
    let gate = FakeGate::start(pki.clone(), placeholder(), renewals).await;
    let enrolled = enrollment(&pki, &gate.endpoint(), not_before, not_after);
    gate.set_identity(NodeIdentity {
        spki: enrolled.identity.spki.clone(),
        host_key: enrolled.identity.host_key.clone(),
    });
    let kube = FakeKube::start(Some(Stored::holding(enrolled.data.clone()))).await;
    (gate, kube, enrolled)
}

async fn token_control(pki: &Arc<TestPki>, gate: &FakeGate, accepted: &str) -> FakeControl {
    let mut script = ControlScript::new(&[PollStep::Approve(Approval::Valid)]);
    script.join_token = Some(accepted.to_owned());
    script.agent_endpoint = gate.endpoint();
    FakeControl::start(pki.clone(), script).await
}

fn empty() -> Stored {
    Stored::holding(BTreeMap::new())
}

fn calls(kube: &FakeKube, expected: &[(&str, u16)]) -> bool {
    let expected: Vec<(String, u16)> = expected
        .iter()
        .map(|(method, status)| ((*method).to_owned(), *status))
        .collect();
    kube.methods() == expected
}

fn plant(pod: &Pod, data: &BTreeMap<String, String>) {
    fs::create_dir(pod.state()).unwrap();
    fs::set_permissions(pod.state(), fs::Permissions::from_mode(0o700)).unwrap();
    for (name, value) in data {
        let path = pod.state().join(name);
        fs::write(&path, STANDARD.decode(value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn errors_logged(logs: &LogCapture, event: &str) -> usize {
    logs.text()
        .lines()
        .filter(|line| line.contains("\"level\":\"ERROR\"") && line.contains(event))
        .count()
}

fn assert_nothing_secret_in(text: &str, secret: &Stored) {
    for needle in [TOKEN, SA_TOKEN, "PRIVATE KEY", "-----BEGIN"] {
        assert!(!text.contains(needle), "{needle} leaked");
    }
    for (name, value) in &secret.data {
        assert!(
            !text.contains(&value[..value.len().min(40)]),
            "{name} leaked"
        );
    }
}

#[tokio::test]
async fn a_first_start_enrols_from_the_token_stores_the_state_before_serving_and_a_new_pod_restores_it()
 {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let pki = Arc::new(TestPki::new());
    let mut gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    let control = token_control(&pki, &gate, TOKEN).await;
    let kube = Arc::new(FakeKube::start(Some(empty())).await);
    kube.script_put(Step::Pass);
    kube.script_put(Step::Status(503));
    kube.script_put(Step::Status(503));
    let mut registrations = gate.registry.subscribe();
    let first_connection = {
        let kube = kube.clone();
        tokio::spawn(async move {
            loop {
                if let Ok(RegistryEvent::Connected { .. }) = registrations.recv().await {
                    return kube.secret().unwrap().data.len();
                }
            }
        })
    };
    let pod = Pod::new().with_token();
    let clock = ManualClock::new(SystemTime::now());
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(&kube, &control.url, &pod, CLUSTER_NODE, pin_of(&pki)),
    );

    eventually("the enrollment to wait for its poll", || {
        !clock.sleepers().is_empty()
    })
    .await;
    assert!(
        calls(&kube, &[("GET", 200), ("PUT", 200)]),
        "the Secret is probed before the token is spent"
    );
    clock.advance(Duration::from_secs(5));
    for (attempt, delay) in [(1, 1), (2, 2)] {
        eventually("a failed attempt to store the enrollment", || {
            kube.methods()
                .iter()
                .filter(|seen| **seen == ("PUT".to_owned(), 503))
                .count()
                == attempt
        })
        .await;
        clock
            .wait_for_sleeper(clock.now() + Duration::from_secs(delay))
            .await;
        assert!(gate.registry.connected_nodes().is_empty());
        assert_eq!(gate.api_connections(), 0);
        assert!(kube.secret().unwrap().data.is_empty());
        assert!(pod.state().join("state.json").exists());
        clock.advance(Duration::from_secs(delay));
    }
    gate.wait_connected().await;
    let held = soon("the first connection", first_connection)
        .await
        .unwrap();
    assert_eq!(held, MANAGED_FILES.len(), "the Secret held {held} files");
    let stored = kube.secret().unwrap();
    let names: Vec<&str> = stored.data.keys().map(String::as_str).collect();
    let mut managed = MANAGED_FILES.to_vec();
    managed.sort_unstable();
    assert_eq!(names, managed);
    for name in MANAGED_FILES {
        assert_eq!(stored.file(name), pod.file(name), "{name}");
    }
    assert!(pod.state().join("inner-ca.pub").exists());
    let enrolls = control.enrolls();
    assert_eq!(enrolls.len(), 1);
    assert_eq!(enrolls[0].name, CLUSTER_NODE);
    assert!(enrolls[0].replace);
    assert_eq!(enrolls[0].hostname, "jaunt-agent-7d9f8");
    assert_eq!(enrolls[0].join_token.as_deref(), Some(TOKEN));
    agent.stop().await;
    let first_start = [
        ("GET", 200),
        ("PUT", 200),
        ("PUT", 503),
        ("PUT", 503),
        ("PUT", 200),
    ];
    assert!(calls(&kube, &first_start), "{:?}", kube.methods());

    let second = Pod::new();
    let agent = Agent::start(
        &second,
        ManualClock::new(SystemTime::now()),
        backend(&kube, &control.url, &second, CLUSTER_NODE, pin_of(&pki)),
    );
    gate.wait_connected().await;
    assert_eq!(control.enrolls().len(), 1);
    let record: EnrollmentRecord = serde_json::from_slice(&second.file("state.json")).unwrap();
    assert_eq!(record.node_id, NODE_ID);
    assert_eq!(record.name, CLUSTER_NODE);
    for name in MANAGED_FILES {
        assert_eq!(second.file(name), stored.file(name), "{name}");
        assert_eq!(second.mode(name), 0o600, "{name}");
    }
    let dir_mode = fs::metadata(second.state()).unwrap().permissions().mode() & 0o7777;
    assert_eq!(dir_mode, 0o700);
    let expected = serde_json::to_value(announcement()).unwrap();
    eventually("the kubernetes service to be announced", || {
        gate.requests(AGENT_SERVICES_PATH).iter().any(|seen| {
            seen.method == "POST"
                && serde_json::from_slice::<serde_json::Value>(&seen.body)
                    .ok()
                    .as_ref()
                    == Some(&expected)
        })
    })
    .await;
    let ssh = StreamMeta::new(
        SessionId::new("s-ssh").unwrap(),
        StreamKind::Ssh,
        "203.0.113.5:40000",
    )
    .unwrap();
    assert!(matches!(
        gate.registry
            .open_stream(&NodeId::new(NODE_ID).unwrap(), &ssh)
            .await,
        Err(OpenError::Refused(400))
    ));
    agent.stop().await;
    let mut both_starts = first_start.to_vec();
    both_starts.push(("GET", 200));
    assert!(calls(&kube, &both_starts), "{:?}", kube.methods());

    kube.assert_only_the_secret_was_touched();
    assert_nothing_secret_in(&logs.text(), &kube.secret().unwrap());
    assert!(logs.text().contains("the join token was accepted"));
    assert!(logs.text().contains("does not serve until it is stored"));
    gate.stop().await;
}

#[tokio::test]
async fn a_secret_that_fails_validation_is_refused_and_left_as_it_is() {
    let pki = TestPki::new();
    let t0 = unix_now();
    let enrolled = enrollment(&pki, "agents.jaunt.test:443", t0 - 60, t0 + WEEK);
    let valid = enrolled.data.clone();
    let changed = |key: &str, value: Vec<u8>| {
        let mut data = valid.clone();
        data.insert(key.to_owned(), STANDARD.encode(value));
        data
    };
    let mut not_base64 = valid.clone();
    not_base64.insert("x509.der".to_owned(), "%%%".to_owned());
    let mut partial = valid.clone();
    partial.remove("x509.der");
    let leaky = br#"{"node_id": "n", "secret_field_xyz": "VALUE_xyz"}"#.to_vec();
    type Check = fn(&MirrorError) -> bool;
    let cases: Vec<(&str, BTreeMap<String, String>, Check)> = vec![
        (
            "unknown key",
            changed("authorized_keys", b"x".to_vec()),
            |e| matches!(e, MirrorError::UnknownEntry { key } if key == "authorized_keys"),
        ),
        ("path as a key", changed("../tls.key", b"x".to_vec()), |e| {
            matches!(e, MirrorError::UnknownEntry { .. })
        }),
        (
            "oversized entry",
            changed("x509.der", vec![0; 64 * 1024 + 1]),
            |e| matches!(e, MirrorError::EntryTooLarge { key: "x509.der" }),
        ),
        ("not base64", not_base64, |e| {
            matches!(e, MirrorError::Encoding { key: "x509.der" })
        }),
        ("partial enrollment", partial, |e| {
            matches!(
                e,
                MirrorError::Incomplete {
                    missing: "x509.der"
                }
            )
        }),
        ("bad record", changed("state.json", leaky), |e| {
            matches!(e, MirrorError::Record)
        }),
        (
            "bad tls key",
            changed("tls.key", b"not a key".to_vec()),
            |e| matches!(e, MirrorError::Invalid(StateError::Key { .. })),
        ),
        (
            "bad host key",
            changed("ssh_host_ed25519", vec![0xff, 0xfe]),
            |e| matches!(e, MirrorError::Invalid(StateError::Utf8 { .. })),
        ),
        (
            "over one MiB",
            changed("padding", vec![0; 800 * 1024]),
            |e| matches!(e, MirrorError::TooLarge),
        ),
        (
            "another root",
            changed("ca-root.der", TestPki::new().root_der().to_vec()),
            |e| matches!(e, MirrorError::PinMismatch),
        ),
    ];
    for (what, data, expected) in cases {
        let kube = FakeKube::start(Some(Stored::holding(data.clone()))).await;
        let pod = Pod::new().with_token();
        let backend = backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            CLUSTER_NODE,
            enrolled.pin.clone(),
        );
        let error = Agent::start(&pod, ManualClock::new(SystemTime::now()), backend)
            .failure()
            .await;
        let RunError::Cluster(ClusterError::Restore { source, .. }) = &error else {
            panic!("{what}: {error}");
        };
        assert!(expected(source), "{what}: {source}");
        assert_eq!(kube.secret(), Some(Stored::holding(data.clone())), "{what}");
        assert!(calls(&kube, &[("GET", 200)]), "{what}");
        assert!(!pod.state().join("state.json").exists(), "{what}");
        let shown = error.to_string();
        assert_nothing_secret_in(&shown, &Stored::holding(valid.clone()));
        assert!(
            !shown.contains("secret_field_xyz") && !shown.contains("VALUE_xyz"),
            "{shown}"
        );
    }

    let kube = FakeKube::start(Some(Stored::holding(valid.clone()))).await;
    kube.script_get(Step::Raw(200, vec![b' '; 2 * 1024 * 1024 + 1]));
    let pod = Pod::new();
    let error = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            CLUSTER_NODE,
            enrolled.pin.clone(),
        ),
    )
    .failure()
    .await;
    assert!(
        matches!(
            error,
            RunError::Cluster(ClusterError::Restore {
                source: MirrorError::Api(ApiError::BodyTooLarge),
                ..
            })
        ),
        "{error}"
    );

    let pod = Pod::new();
    let error = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            CLUSTER_NODE,
            pin_of(&TestPki::new()),
        ),
    )
    .failure()
    .await;
    assert!(
        matches!(
            error,
            RunError::Cluster(ClusterError::Restore {
                source: MirrorError::PinMismatch,
                ..
            })
        ),
        "{error}"
    );
    assert_eq!(kube.secret(), Some(Stored::holding(valid)));
}

#[tokio::test]
async fn renewed_certificates_reach_the_secret_after_failed_writes_with_backoff() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let pki = Arc::new(TestPki::new());
    let mut gate = FakeGate::start(
        pki.clone(),
        placeholder(),
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 2 * HOUR,
        }],
    )
    .await;
    let enrolled = enrollment(&pki, &gate.endpoint(), t0 - HOUR, t0 + HOUR);
    gate.set_identity(NodeIdentity {
        spki: enrolled.identity.spki.clone(),
        host_key: enrolled.identity.host_key.clone(),
    });
    let mut earlier = enrolled.data.clone();
    earlier.insert(
        "inner-ca.pub".to_owned(),
        STANDARD.encode(b"ssh-ed25519 AAAA old\n"),
    );
    let kube = FakeKube::start(Some(Stored::holding(earlier))).await;
    let pod = Pod::new();
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            NODE_NAME,
            enrolled.pin.clone(),
        ),
    );
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    assert_ne!(pod.file("inner-ca.pub"), b"ssh-ed25519 AAAA old\n");
    assert!(calls(&kube, &[("GET", 200)]));
    let before = kube.secret().unwrap().file("x509.der");
    kube.script_put(Step::Status(500));
    kube.script_put(Step::Status(503));

    clock.set(at_unix_secs(t0));
    eventually("the first failed write", || {
        kube.methods().contains(&("PUT".to_owned(), 500))
    })
    .await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 1)).await;
    clock.set(at_unix_secs(t0 + 1));
    eventually("the second failed write", || {
        kube.methods().contains(&("PUT".to_owned(), 503))
    })
    .await;
    clock.wait_for_sleeper(at_unix_secs(t0 + 3)).await;
    clock.set(at_unix_secs(t0 + 3));
    eventually("the renewed certificate in the Secret", || {
        kube.secret().unwrap().file("x509.der") != before
    })
    .await;
    let stored = kube.secret().unwrap();
    assert_eq!(stored.file("x509.der"), pod.file("x509.der"));
    assert!(!stored.data.contains_key("inner-ca.pub"));
    assert_eq!(stored.data.len(), MANAGED_FILES.len());
    let record: EnrollmentRecord = serde_json::from_slice(&stored.file("state.json")).unwrap();
    assert_eq!(record.x509_not_after, t0 + 2 * HOUR);
    agent.stop().await;
    assert!(calls(
        &kube,
        &[("GET", 200), ("PUT", 500), ("PUT", 503), ("PUT", 200)]
    ));

    let text = logs.text();
    assert_eq!(
        errors_logged(&logs, "persist_failed"),
        1,
        "two failures within a minute are logged once"
    );
    assert!(text.contains("the agent keeps running and retries"));
    assert!(text.contains("the agent state is stored in the Secret again"));
    kube.assert_only_the_secret_was_touched();
    assert_nothing_secret_in(&text, &stored);
    gate.stop().await;
}

#[tokio::test]
async fn a_conflict_rereads_the_secret_and_keeps_what_others_changed() {
    let t0 = unix_now();
    let pki = Arc::new(TestPki::new());
    let mut gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    let enrolled = enrollment(&pki, &gate.endpoint(), t0 - 60, t0 + WEEK);
    let kube = FakeKube::start(Some(empty())).await;
    kube.script_put(Step::Conflict(Box::new(|stored| {
        stored
            .annotations
            .insert("example.com/owner".to_owned(), "platform".to_owned());
    })));
    let pod = Pod::new();
    plant(&pod, &enrolled.data);
    let agent = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            NODE_NAME,
            enrolled.pin.clone(),
        ),
    );
    gate.wait_connected().await;
    let stored = kube.secret().unwrap();
    assert_eq!(stored.annotations["example.com/owner"], "platform");
    assert_eq!(stored.data, enrolled.data);
    assert!(calls(
        &kube,
        &[("GET", 200), ("PUT", 409), ("GET", 200), ("PUT", 200)]
    ));
    agent.stop().await;
    kube.assert_only_the_secret_was_touched();
    gate.stop().await;
}

#[tokio::test]
async fn a_secret_filled_by_someone_else_before_the_first_write_is_never_overwritten() {
    let t0 = unix_now();
    let other = enrollment(&TestPki::new(), "agents.jaunt.test:443", t0 - 60, t0 + WEEK).data;
    let unreadable = BTreeMap::from([("authorized_keys".to_owned(), STANDARD.encode(b"x"))]);
    for (what, written) in [
        ("another enrollment", other),
        ("unreadable keys", unreadable),
    ] {
        let logs = LogCapture::default();
        let _guard = logs.install();
        let pki = Arc::new(TestPki::new());
        let gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
        let control = token_control(&pki, &gate, TOKEN).await;
        let kube = FakeKube::start(Some(empty())).await;
        let filled = written.clone();
        kube.script_put(Step::Pass);
        kube.script_put(Step::Conflict(Box::new(move |stored| stored.data = filled)));
        let pod = Pod::new().with_token();
        let clock = ManualClock::new(SystemTime::now());
        let agent = Agent::start(
            &pod,
            clock.clone(),
            backend(&kube, &control.url, &pod, CLUSTER_NODE, pin_of(&pki)),
        );
        eventually("the enrollment to wait for its poll", || {
            !clock.sleepers().is_empty()
        })
        .await;
        clock.advance(Duration::from_secs(5));
        let error = agent.failure().await;
        assert!(
            matches!(error, RunError::Cluster(ClusterError::Foreign { .. })),
            "{what}: {error}"
        );
        assert_eq!(kube.secret().unwrap().data, written, "{what}");
        assert!(
            calls(
                &kube,
                &[("GET", 200), ("PUT", 200), ("PUT", 409), ("GET", 200)]
            ),
            "{what}"
        );
        assert!(gate.registry.connected_nodes().is_empty(), "{what}");
        assert_eq!(
            errors_logged(&logs, "agent.state.foreign_enrollment"),
            1,
            "{what}"
        );
        gate.stop().await;
    }
}

#[tokio::test]
async fn a_different_enrollment_found_while_serving_stops_the_agent() {
    let logs = LogCapture::default();
    let _guard = logs.install();
    let t0 = unix_now();
    let (mut gate, kube, enrolled) = restored_agent(
        &[RenewStep::Issue {
            not_before: t0 - 60,
            not_after: t0 + 2 * HOUR,
        }],
        t0 - HOUR,
        t0 + HOUR,
    )
    .await;
    let other = enrollment(&TestPki::new(), "agents.jaunt.test:443", t0 - 60, t0 + WEEK).data;
    let written = other.clone();
    kube.script_put(Step::Conflict(Box::new(move |stored| {
        stored.data = written
    })));
    let pod = Pod::new();
    let clock = ManualClock::new(at_unix_secs(t0 - 600));
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            NODE_NAME,
            enrolled.pin.clone(),
        ),
    );
    gate.wait_connected().await;
    clock.wait_for_sleeper(at_unix_secs(t0)).await;
    clock.set(at_unix_secs(t0));
    let error = agent.failure().await;
    assert!(
        matches!(error, RunError::Cluster(ClusterError::Foreign { .. })),
        "{error}"
    );
    assert_eq!(kube.secret().unwrap().data, other);
    assert!(calls(&kube, &[("GET", 200), ("PUT", 409), ("GET", 200)]));
    assert!(logs.text().contains("agent.state.foreign_enrollment"));
    gate.stop().await;
}

#[tokio::test]
async fn an_enrollment_left_in_the_pod_directory_is_checked_like_a_secret_before_it_is_stored() {
    let t0 = unix_now();
    let pki = Arc::new(TestPki::new());
    let mut gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    let enrolled = enrollment(&pki, &gate.endpoint(), t0 - 60, t0 + WEEK);
    let kube = FakeKube::start(Some(empty())).await;
    let pod = Pod::new();
    plant(&pod, &enrolled.data);
    let agent = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(
            &kube,
            "https://jaunt.invalid",
            &pod,
            NODE_NAME,
            enrolled.pin.clone(),
        ),
    );
    gate.wait_connected().await;
    assert_eq!(kube.secret().unwrap().data, enrolled.data);
    agent.stop().await;
    gate.stop().await;

    let other = enrollment(&pki, "agents.jaunt.test:443", t0 - 60, t0 + WEEK);
    let mut mismatched = enrolled.data.clone();
    mismatched.insert("x509.der".to_owned(), other.data["x509.der"].clone());
    let gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    type Check = fn(&ClusterError) -> bool;
    let cases: [(&str, BTreeMap<String, String>, CaPin, Check); 2] = [
        (
            "certificate of other keys",
            mismatched,
            enrolled.pin.clone(),
            |e| matches!(e, ClusterError::LocalIdentity { .. }),
        ),
        (
            "planted under another root",
            enrolled.data.clone(),
            pin_of(&TestPki::new()),
            |e| {
                matches!(
                    e,
                    ClusterError::Local {
                        source: MirrorError::PinMismatch,
                        ..
                    }
                )
            },
        ),
    ];
    for (what, data, pin, expected) in cases {
        let pod = Pod::new();
        plant(&pod, &data);
        let kube = FakeKube::start(Some(empty())).await;
        let error = Agent::start(
            &pod,
            ManualClock::new(SystemTime::now()),
            backend(&kube, "https://jaunt.invalid", &pod, NODE_NAME, pin),
        )
        .failure()
        .await;
        let RunError::Cluster(cluster) = &error else {
            panic!("{what}: {error}");
        };
        assert!(expected(cluster), "{what}: {error}");
        assert_eq!(kube.secret(), Some(empty()), "{what}");
        assert!(calls(&kube, &[("GET", 200)]), "{what}");
        assert_eq!(gate.api_connections(), 0, "{what}");
    }
    gate.stop().await;
}

#[tokio::test]
async fn an_empty_secret_waits_briefly_for_the_token_and_reports_a_refused_one_plainly() {
    let pki = Arc::new(TestPki::new());
    let gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    let control = token_control(
        &pki,
        &gate,
        "jt1.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    )
    .await;
    let kube = FakeKube::start(Some(empty())).await;
    let pod = Pod::new();
    let clock = ManualClock::new(SystemTime::now());
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(&kube, &control.url, &pod, CLUSTER_NODE, pin_of(&pki)),
    );
    for _ in 0..2 {
        clock
            .wait_for_sleeper(clock.now() + Duration::from_secs(1))
            .await;
        clock.advance(Duration::from_secs(1));
    }
    let error = agent.failure().await;
    let RunError::Cluster(ClusterError::NoJoinToken { path, .. }) = &error else {
        panic!("{error}");
    };
    assert_eq!(*path, pod.token());
    assert!(error.to_string().contains(CLUSTER_NODE));
    assert_eq!(kube.secret(), Some(empty()));
    assert!(calls(&kube, &[("GET", 200)]));
    assert!(control.enrolls().is_empty());

    let kube = FakeKube::start(Some(empty())).await;
    let pod = Pod::new();
    let clock = ManualClock::new(SystemTime::now());
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(&kube, &control.url, &pod, CLUSTER_NODE, pin_of(&pki)),
    );
    clock
        .wait_for_sleeper(clock.now() + Duration::from_secs(1))
        .await;
    let pod = pod.with_token();
    clock.advance(Duration::from_secs(1));
    let error = agent.failure().await;
    assert!(
        matches!(&error, RunError::Cluster(ClusterError::TokenRefused { .. })),
        "{error}"
    );
    let shown = error.to_string();
    assert!(
        shown.contains("--allow-replace") && !shown.contains(" --replace"),
        "{shown}"
    );
    assert_eq!(control.enrolls().len(), 1);
    assert_eq!(control.enrolls()[0].join_token.as_deref(), Some(TOKEN));
    assert_eq!(kube.secret().unwrap().data, BTreeMap::new());
    drop(pod);
    drop(gate);
}

#[tokio::test]
async fn the_token_is_spent_only_when_the_secret_is_writable_and_the_root_matches_the_pin() {
    let pki = Arc::new(TestPki::new());
    let gate = FakeGate::start(pki.clone(), placeholder(), &[]).await;
    let control = token_control(&pki, &gate, TOKEN).await;

    let kube = FakeKube::start(Some(empty())).await;
    kube.script_put(Step::Status(403));
    let pod = Pod::new().with_token();
    let error = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(&kube, &control.url, &pod, CLUSTER_NODE, pin_of(&pki)),
    )
    .failure()
    .await;
    assert!(
        matches!(
            &error,
            RunError::Cluster(ClusterError::Probe {
                source: MirrorError::Api(ApiError::Forbidden { verb: "update", .. }),
                ..
            })
        ),
        "{error}"
    );
    assert!(error.to_string().contains("the join token was not used"));
    assert!(control.enrolls().is_empty());
    assert!(calls(&kube, &[("GET", 200), ("PUT", 403)]));

    let kube = FakeKube::start(Some(empty())).await;
    let pod = Pod::new().with_token();
    let clock = ManualClock::new(SystemTime::now());
    let agent = Agent::start(
        &pod,
        clock.clone(),
        backend(
            &kube,
            &control.url,
            &pod,
            CLUSTER_NODE,
            pin_of(&TestPki::new()),
        ),
    );
    eventually("the enrollment to wait for its poll", || {
        !clock.sleepers().is_empty()
    })
    .await;
    clock.advance(Duration::from_secs(5));
    let error = agent.failure().await;
    assert!(
        matches!(
            error,
            RunError::Cluster(ClusterError::Enroll(EnrollError::PinMismatch))
        ),
        "{error}"
    );
    assert_eq!(kube.secret().unwrap().data, BTreeMap::new());
    assert!(calls(&kube, &[("GET", 200), ("PUT", 200)]));
    assert!(!pod.state().join("state.json").exists());
}

#[tokio::test]
async fn stopping_the_pod_during_the_enrollment_request_does_not_wait_for_the_server() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let silent = {
        let accepted = accepted.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
                accepted.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let kube = FakeKube::start(Some(empty())).await;
    let pod = Pod::new().with_token();
    let agent = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(&kube, &server, &pod, CLUSTER_NODE, pin_of(&TestPki::new())),
    );
    eventually("the enrollment request to reach the server", || {
        accepted.load(Ordering::SeqCst) > 0
    })
    .await;
    agent.shutdown.cancel();
    let error = agent.failure().await;
    assert!(
        matches!(error, RunError::Cluster(ClusterError::Interrupted)),
        "{error}"
    );
    assert!(kube.secret().unwrap().data.is_empty());
    assert!(calls(&kube, &[("GET", 200), ("PUT", 200)]));
    silent.abort();
}

#[tokio::test]
async fn a_missing_secret_or_a_pod_without_a_service_account_is_refused() {
    let pod = Pod::new();
    let pin = pin_of(&TestPki::new());
    let missing = FakeKube::start(None).await;
    let error = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(
            &missing,
            "https://jaunt.invalid",
            &pod,
            CLUSTER_NODE,
            pin.clone(),
        ),
    )
    .failure()
    .await;
    assert!(
        matches!(
            error,
            RunError::Cluster(ClusterError::Restore {
                source: MirrorError::Api(ApiError::NotFound { .. }),
                ..
            })
        ),
        "{error}"
    );

    let kube = FakeKube::start(Some(empty())).await;
    kube.remove_token();
    let error = Agent::start(
        &pod,
        ManualClock::new(SystemTime::now()),
        backend(&kube, "https://jaunt.invalid", &pod, CLUSTER_NODE, pin),
    )
    .failure()
    .await;
    assert!(
        matches!(
            error,
            RunError::Cluster(ClusterError::Setup(SetupError::NotInCluster { .. }))
        ),
        "{error}"
    );
    assert!(kube.seen().is_empty());
}

#[tokio::test]
async fn a_state_directory_of_another_user_is_refused_before_the_secret_is_read() {
    let kube = FakeKube::start(Some(empty())).await;
    let clock: Arc<dyn Clock> = ManualClock::new(SystemTime::now());
    let client = SecretClient::new(&kube.settings(), clock, effective_uid()).unwrap();
    let foreign = effective_uid().wrapping_add(1);
    let mirror = KubernetesSecret::new(client, false, pin_of(&TestPki::new()), foreign);
    let pod = Pod::new();
    let refused = mirror.restore(&pod.state()).await.err();
    assert!(
        matches!(refused, Some(MirrorError::DirAccess { uid, .. }) if uid == foreign),
        "{refused:?}"
    );
    assert!(kube.seen().is_empty());

    let client = SecretClient::new(
        &kube.settings(),
        ManualClock::new(SystemTime::now()),
        effective_uid(),
    )
    .unwrap();
    let mirror = KubernetesSecret::new(client, false, pin_of(&TestPki::new()), effective_uid());
    assert_eq!(mirror.restore(&pod.state()).await.unwrap(), Restored::Empty);
}

#[tokio::test]
async fn the_client_rereads_a_rotated_token_and_maps_answers_without_following_redirects() {
    let kube = FakeKube::start(Some(empty())).await;
    let clock = ManualClock::new(SystemTime::now());
    let client = SecretClient::new(&kube.settings(), clock.clone(), effective_uid()).unwrap();
    assert_eq!(client.secret(), "jaunt/jaunt-agent-state");
    let sent = |kube: &FakeKube| kube.seen().last().unwrap().authorization.clone().unwrap();

    client.get().await.unwrap();
    assert_eq!(sent(&kube), format!("Bearer {SA_TOKEN}"));
    kube.replace_token("sa-token-2");
    client.get().await.unwrap();
    assert_eq!(sent(&kube), "Bearer sa-token-2");
    kube.rewrite_token_in_place("sa-token-3");
    client.get().await.unwrap();
    assert_eq!(sent(&kube), "Bearer sa-token-2");
    clock.advance(Duration::from_secs(59));
    client.get().await.unwrap();
    assert_eq!(sent(&kube), "Bearer sa-token-2");
    clock.advance(Duration::from_secs(1));
    client.get().await.unwrap();
    assert_eq!(sent(&kube), "Bearer sa-token-3");
    kube.script_get(Step::Status(401));
    assert!(matches!(client.get().await, Err(ApiError::Unauthorized)));
    kube.rewrite_token_in_place("sa-token-4");
    client.get().await.unwrap();
    assert_eq!(sent(&kube), "Bearer sa-token-4");

    type Check = fn(&ApiError) -> bool;
    let answers: [(Step, Check); 8] = [
        (Step::Status(403), |e| {
            matches!(e, ApiError::Forbidden { verb: "get", .. })
                && e.to_string().contains("get and update")
        }),
        (Step::Status(404), |e| {
            matches!(e, ApiError::NotFound { .. })
        }),
        (Step::Status(500), |e| {
            matches!(e, ApiError::Status { status: 500 })
        }),
        (Step::Redirect(307), |e| {
            matches!(e, ApiError::Status { status: 307 })
        }),
        (Step::Raw(200, b"not json".to_vec()), |e| {
            matches!(e, ApiError::BadResponse)
        }),
        (
            Step::Raw(
                200,
                br#"{"kind":"ConfigMap","metadata":{"resourceVersion":"1"}}"#.to_vec(),
            ),
            |e| matches!(e, ApiError::BadResponse),
        ),
        (
            Step::Raw(
                200,
                br#"{"kind":"Secret","metadata":{"name":"x"}}"#.to_vec(),
            ),
            |e| matches!(e, ApiError::BadResponse),
        ),
        (
            Step::Raw(
                200,
                br#"{"kind":"Secret","metadata":{"resourceVersion":"1"},"data":[]}"#.to_vec(),
            ),
            |e| matches!(e, ApiError::BadResponse),
        ),
    ];
    for (step, expected) in answers {
        kube.script_get(step);
        let before = kube.seen().len();
        let error = client.get().await.err().unwrap();
        assert!(expected(&error), "{error}");
        assert_eq!(kube.seen().len(), before + 1, "{error}");
    }
    kube.assert_only_the_secret_was_touched();

    let mut settings = kube.settings();
    settings.timeout = Duration::from_millis(200);
    let impatient = SecretClient::new(&settings, clock.clone(), effective_uid()).unwrap();
    kube.script_get(Step::Hang);
    assert!(matches!(impatient.get().await, Err(ApiError::TimedOut)));
}

#[tokio::test]
async fn the_client_refuses_a_service_account_directory_it_cannot_trust() {
    let kube = FakeKube::start(None).await;
    let clock: Arc<dyn Clock> = ManualClock::new(SystemTime::now());
    let dir = kube.accounts_path();
    let write = |name: &str, content: &str| fs::write(dir.join(name), content).unwrap();
    let setup = |api: &str, secret: &str| {
        let mut settings = kube.settings();
        settings.api = api.to_owned();
        settings.secret_name = secret.to_owned();
        SecretClient::new(&settings, clock.clone(), effective_uid()).err()
    };
    let api = kube.api.clone();
    assert!(matches!(setup(&api, "a/b"), Some(SetupError::SecretName)));
    for bad in [
        "http://127.0.0.1:1",
        "https://127.0.0.1:1/api",
        "https://u:p@127.0.0.1:1",
        "https://10.96.0.1:https",
    ] {
        assert!(
            matches!(setup(bad, "s"), Some(SetupError::Address)),
            "{bad}"
        );
    }
    write("namespace", "../kube-system");
    assert!(matches!(
        setup(&api, "s"),
        Some(SetupError::Namespace { .. })
    ));
    write("namespace", "jaunt\n");
    let ca = fs::read_to_string(dir.join("ca.crt")).unwrap();
    write("ca.crt", "no certificate here\n");
    assert!(matches!(setup(&api, "s"), Some(SetupError::Ca { .. })));
    write("ca.crt", &ca);
    write("token", " \n");
    assert!(matches!(setup(&api, "s"), Some(SetupError::Token { .. })));
    fs::set_permissions(dir.join("token"), fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(
        setup(&api, "s"),
        Some(SetupError::Mount(super::mount::MountError::Writable { .. }))
    ));
    write("token", SA_TOKEN);
    fs::set_permissions(dir.join("token"), fs::Permissions::from_mode(0o600)).unwrap();
    assert!(setup(&api, "s").is_none());
}

#[test]
fn the_api_server_address_follows_the_service_environment_like_client_go() {
    for (host, port, expected) in [
        (Some("10.96.0.1"), Some("443"), "https://10.96.0.1:443"),
        (
            Some("fd00:10:96::1"),
            Some("6443"),
            "https://[fd00:10:96::1]:6443",
        ),
        (Some(" 10.96.0.1 "), Some(" 443 "), "https://10.96.0.1:443"),
        (None, Some("443"), IN_CLUSTER_API),
        (Some("10.96.0.1"), None, IN_CLUSTER_API),
        (Some(""), Some("443"), IN_CLUSTER_API),
        (Some("10.96.0.1"), Some(""), IN_CLUSTER_API),
    ] {
        assert_eq!(api_address(host, port), expected, "{host:?} {port:?}");
    }
    assert_eq!(IN_CLUSTER_API, "https://kubernetes.default.svc");
}
