use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jaunt_ca::ssh_key::{Fingerprint, HashAlg, PublicKey as CaPublicKey};
use jaunt_ca::{
    AgeIdentity, CaKind, CaLock, DEFAULT_HOST_VALIDITY, FileBackend, HostCertParams,
    IDENTITY_FILE_VAR, fingerprint_hex, sign_host_certificate,
};
use jaunt_control::Control;
use jaunt_gate::{HostCertIssuer, IssueError, SshGate, SshGateConfig};
use jaunt_ssh::{UserCaKeys, UserCaSource};
use jaunt_tunnel::{AgentRegistry, BoxFuture, IncomingStream, NodeId, StreamHandler};
use jauntd::ca_reload::{CaReloadParts, CaReloader, CaWatcher, GateCertificate, Reload, Tick};
use russh::keys::{Algorithm, Certificate, PublicKeyOrCertificate};
use russh::{Preferred, client};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tokio::net::TcpStream;

use crate::recorder::audit_events;
use crate::stand::{Identity, Stand};
use crate::support::{Harness, Options, TestAgent, eventually, field, spawn_agent_with, within};

const START: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(START + secs)
}

struct Keys {
    root: PathBuf,
    identity: Arc<Mutex<PathBuf>>,
    reads: Arc<AtomicUsize>,
}

impl Keys {
    fn of(harness: &Harness) -> Keys {
        Keys {
            root: harness.ca_root.clone(),
            identity: Arc::new(Mutex::new(harness.identity_file.clone())),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reloader(
        &self,
        harness: &Harness,
        gate: Option<Arc<SshGate>>,
        registry: Option<AgentRegistry>,
    ) -> CaReloader {
        let identity = Arc::clone(&self.identity);
        let reads = Arc::clone(&self.reads);
        CaReloader::new(CaReloadParts {
            ca_dir: self.root.clone(),
            env: Arc::new(move |name: &str| {
                (name == IDENTITY_FILE_VAR).then(|| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    identity.lock().unwrap().clone().into_os_string()
                })
            }),
            control: harness.control.clone(),
            gate,
            registry,
        })
    }

    fn age(&self) -> AgeIdentity {
        AgeIdentity::read_file(&self.identity.lock().unwrap()).unwrap()
    }

    fn slot(&self, kind: CaKind) -> PathBuf {
        self.root.join(kind.as_str())
    }

    fn add_next(&self, kind: CaKind) -> String {
        let lock = CaLock::acquire(&self.root).unwrap();
        fingerprint_hex(&FileBackend::add_next(&lock, kind, &self.age()).unwrap())
    }

    fn promote(&self, kind: CaKind) {
        let lock = CaLock::acquire(&self.root).unwrap();
        let next = FileBackend::read_slot(&self.root, kind)
            .unwrap()
            .trust
            .next()
            .unwrap()
            .fingerprint(HashAlg::Sha256);
        FileBackend::promote(&lock, kind, &self.age(), &next).unwrap();
    }

    fn retire(&self, kind: CaKind) {
        let lock = CaLock::acquire(&self.root).unwrap();
        let previous: Vec<Fingerprint> = FileBackend::read_slot(&self.root, kind)
            .unwrap()
            .trust
            .previous()
            .map(|key| key.fingerprint(HashAlg::Sha256))
            .collect();
        FileBackend::retire(&lock, kind, &previous).unwrap();
    }
}

fn applied(kinds: &[CaKind], notified: usize) -> Reload {
    Reload::Applied {
        kinds: kinds.to_vec(),
        notified,
    }
}

fn user_signer(harness: &Harness) -> String {
    fingerprint_hex(harness.control.ca_snapshot().user_signer().public_key())
}

fn host_signer(harness: &Harness) -> String {
    fingerprint_hex(harness.control.ca_snapshot().host_signer().public_key())
}

fn events_named(name: &str) -> Vec<crate::recorder::Captured> {
    audit_events()
        .into_iter()
        .filter(|event| field(event, "event") == name)
        .collect()
}

fn certificate_signer(certificate: &Certificate) -> String {
    certificate
        .signature_key()
        .fingerprint(russh::keys::HashAlg::Sha256)
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct TrustCounter(Arc<AtomicUsize>);

impl StreamHandler for TrustCounter {
    fn handle(&self, _stream: IncomingStream) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }

    fn trust_update(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

async fn counting_agents(
    harness: &Harness,
    names: &[&str],
) -> (Vec<TestAgent>, Vec<Arc<AtomicUsize>>) {
    let (mut agents, mut counters) = (Vec::new(), Vec::new());
    for name in names {
        let enrolled = harness.enroll(name).await;
        let count = Arc::new(AtomicUsize::new(0));
        agents.push(spawn_agent_with(
            harness,
            &enrolled,
            Arc::new(TrustCounter(count.clone())),
        ));
        counters.push(count);
        let registry = harness.server.registry().clone();
        let node = NodeId::new(enrolled.node_id.clone()).unwrap();
        eventually("the agent tunnel", || registry.is_connected(&node)).await;
    }
    (agents, counters)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_connected_agent_hears_each_change_once_and_nothing_without_a_change() {
    let harness = Harness::start(Options::default()).await;
    let keys = Keys::of(&harness);
    let (agents, counters) = counting_agents(&harness, &["web-01", "web-02"]).await;
    let mut reloader = keys.reloader(&harness, None, Some(harness.server.registry().clone()));
    let counts = || -> Vec<usize> {
        counters
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .collect()
    };

    for secs in 0..10 {
        assert_eq!(reloader.tick(at(secs)).await.reload, Reload::Unchanged);
    }
    assert_eq!(counts(), [0, 0]);
    assert_eq!(keys.reads.load(Ordering::SeqCst), 0);
    assert!(events_named("ca.reloaded").is_empty());

    keys.add_next(CaKind::User);
    assert_eq!(
        reloader.tick(at(20)).await.reload,
        applied(&[CaKind::User], 2)
    );
    eventually("both agents to hear the first change", || {
        counts() == [1, 1]
    })
    .await;
    assert_eq!(reloader.tick(at(30)).await.reload, Reload::Unchanged);
    assert_eq!(keys.reads.load(Ordering::SeqCst), 1);

    keys.add_next(CaKind::Host);
    assert_eq!(
        reloader.tick(at(40)).await.reload,
        applied(&[CaKind::Host], 2)
    );
    eventually("both agents to hear the second change", || {
        counts() == [2, 2]
    })
    .await;
    assert_eq!(reloader.tick(at(50)).await.reload, Reload::Unchanged);
    for agent in agents {
        agent.stop().await;
    }
    assert_eq!(counts(), [2, 2]);
    let reloaded = events_named("ca.reloaded");
    assert_eq!(reloaded.len(), 2);
    let snapshot = harness.control.ca_snapshot();
    assert_eq!(field(&reloaded[0], "kind"), "user");
    assert_eq!(field(&reloaded[1], "kind"), "host");
    assert_eq!(
        field(&reloaded[1], "trust_id"),
        snapshot.host_trust().set_id()
    );
    assert_eq!(field(&reloaded[1], "active_fp"), host_signer(&harness));
}

struct Breakage {
    name: &'static str,
    expected: &'static str,
    break_it: fn(&Keys),
    repair: fn(&Keys),
    recovered: fn(&Reload) -> bool,
}

fn next_age(keys: &Keys, kind: CaKind) -> PathBuf {
    let slot = keys.slot(kind);
    let next = std::fs::read_to_string(slot.join("next")).unwrap();
    slot.join(format!("{}.age", next.trim()))
}

fn half_written(keys: &Keys) -> PathBuf {
    keys.slot(CaKind::User)
        .join(format!("{}.pub", "ab".repeat(32)))
}

fn spoil(age: &Path) {
    std::fs::rename(age, age.with_extension("kept")).unwrap();
    std::fs::write(age, b"age-encryption.org/v1\nnot really").unwrap();
}

fn unspoil(age: &Path) {
    std::fs::rename(age.with_extension("kept"), age).unwrap();
}

fn stranger(keys: &Keys) {
    let other = keys.identity.lock().unwrap().with_file_name("stranger.txt");
    if !other.exists() {
        AgeIdentity::generate().write_new_file(&other).unwrap();
    }
    *keys.identity.lock().unwrap() = other;
}

fn trusted(keys: &Keys) {
    let mut identity = keys.identity.lock().unwrap();
    *identity = identity.with_file_name("identity.txt");
}

fn moved_away(keys: &Keys) -> PathBuf {
    keys.root.join("user.away")
}

fn is_applied(reload: &Reload) -> bool {
    *reload == applied(&[CaKind::User], 0)
}

fn is_unchanged(reload: &Reload) -> bool {
    *reload == Reload::Unchanged
}

#[tokio::test]
async fn a_broken_change_keeps_the_old_keys_reports_once_a_minute_and_recovers() {
    let cases = [
        Breakage {
            name: "next that does not decrypt",
            expected: "could not decrypt",
            break_it: |keys| {
                keys.add_next(CaKind::User);
                spoil(&next_age(keys, CaKind::User));
            },
            repair: |keys| unspoil(&next_age(keys, CaKind::User)),
            recovered: is_applied,
        },
        Breakage {
            name: "next pointer that is not a fingerprint",
            expected: "next file does not hold a key fingerprint",
            break_it: |keys| {
                std::fs::write(keys.slot(CaKind::User).join("next"), b"garbage\n").unwrap();
            },
            repair: |keys| {
                std::fs::remove_file(keys.slot(CaKind::User).join("next")).unwrap();
            },
            recovered: is_unchanged,
        },
        Breakage {
            name: "half written public key",
            expected: "not an OpenSSH public key",
            break_it: |keys| std::fs::write(half_written(keys), b"ssh-ed25519 AAAAC3Nz").unwrap(),
            repair: |keys| std::fs::remove_file(half_written(keys)).unwrap(),
            recovered: is_unchanged,
        },
        Breakage {
            name: "wrong age identity",
            expected: "could not decrypt",
            break_it: |keys| {
                keys.add_next(CaKind::User);
                stranger(keys);
            },
            repair: trusted,
            recovered: is_applied,
        },
        Breakage {
            name: "missing directory",
            expected: "not initialized",
            break_it: |keys| {
                std::fs::rename(keys.slot(CaKind::User), moved_away(keys)).unwrap();
            },
            repair: |keys| {
                std::fs::rename(moved_away(keys), keys.slot(CaKind::User)).unwrap();
            },
            recovered: is_unchanged,
        },
    ];
    for case in cases {
        let harness = Harness::start(Options::default()).await;
        let keys = Keys::of(&harness);
        let mut reloader = keys.reloader(&harness, None, None);
        let before = harness.control.ca_snapshot();
        let failures_before = events_named("ca.reload.failed").len();

        (case.break_it)(&keys);
        let ticks: Vec<Tick> = vec![
            reloader.tick(at(0)).await,
            reloader.tick(at(10)).await,
            reloader.tick(at(59)).await,
            reloader.tick(at(60)).await,
        ];

        let reported: Vec<bool> = ticks
            .iter()
            .map(|tick| match &tick.reload {
                Reload::Failed { reason, reported } => {
                    assert!(reason.contains(case.expected), "{}: {reason}", case.name);
                    *reported
                }
                other => panic!("{}: {other:?}", case.name),
            })
            .collect();
        assert_eq!(reported, [true, false, false, true], "{}", case.name);
        assert!(
            Arc::ptr_eq(&before, &harness.control.ca_snapshot()),
            "{}",
            case.name
        );
        let failures = events_named("ca.reload.failed");
        assert_eq!(failures.len() - failures_before, 2, "{}", case.name);
        assert!(
            field(failures.last().unwrap(), "reason").contains(case.expected),
            "{}",
            case.name
        );

        (case.repair)(&keys);
        let recovered = reloader.tick(at(70)).await.reload;
        assert!((case.recovered)(&recovered), "{}: {recovered:?}", case.name);
        assert_eq!(
            reloader.tick(at(80)).await.reload,
            Reload::Unchanged,
            "{}",
            case.name
        );
    }
}

fn reported(reload: &Reload) -> bool {
    match reload {
        Reload::Failed { reported, .. } => *reported,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_failure_after_a_recovery_is_reported_at_once() {
    let harness = Harness::start(Options::default()).await;
    let keys = Keys::of(&harness);
    let mut reloader = keys.reloader(&harness, None, None);
    let next = keys.slot(CaKind::User).join("next");

    std::fs::write(&next, b"garbage\n").unwrap();
    assert!(reported(&reloader.tick(at(0)).await.reload));
    std::fs::remove_file(&next).unwrap();
    assert_eq!(reloader.tick(at(10)).await.reload, Reload::Unchanged);
    std::fs::write(&next, b"garbage\n").unwrap();
    assert!(reported(&reloader.tick(at(20)).await.reload));
    std::fs::remove_file(&next).unwrap();
    assert_eq!(reloader.tick(at(30)).await.reload, Reload::Unchanged);

    keys.add_next(CaKind::User);
    stranger(&keys);
    assert!(reported(&reloader.tick(at(40)).await.reload));
    trusted(&keys);
    assert_eq!(
        reloader.tick(at(50)).await.reload,
        applied(&[CaKind::User], 0)
    );
    keys.promote(CaKind::User);
    stranger(&keys);
    assert!(reported(&reloader.tick(at(55)).await.reload));
}

#[tokio::test]
async fn a_broken_kind_that_changed_holds_back_the_other_kind_until_it_is_fixed() {
    let harness = Harness::start(Options::default()).await;
    let keys = Keys::of(&harness);
    let mut reloader = keys.reloader(&harness, None, None);
    let before = harness.control.ca_snapshot();
    keys.add_next(CaKind::Host);
    let host_next = next_age(&keys, CaKind::Host);
    spoil(&host_next);
    keys.add_next(CaKind::User);

    let held = reloader.tick(at(0)).await.reload;

    let Reload::Failed { reason, .. } = &held else {
        panic!("{held:?}");
    };
    assert!(
        reason.starts_with("host keys: could not decrypt"),
        "{reason}"
    );
    assert!(Arc::ptr_eq(&before, &harness.control.ca_snapshot()));
    unspoil(&host_next);
    assert_eq!(
        reloader.tick(at(10)).await.reload,
        applied(&[CaKind::User, CaKind::Host], 0)
    );
    let applied = harness.control.ca_snapshot();
    assert!(applied.user_trust().next().is_some());
    assert!(applied.host_trust().next().is_some());
}

#[tokio::test]
async fn a_broken_kind_that_did_not_change_does_not_block_the_other_kind() {
    let harness = Harness::start(Options::default()).await;
    let keys = Keys::of(&harness);
    let mut reloader = keys.reloader(&harness, None, None);
    let host_before = host_signer(&harness);
    spoil(&keys.slot(CaKind::Host).join(format!("{host_before}.age")));

    let next = keys.add_next(CaKind::User);

    assert_eq!(
        reloader.tick(at(0)).await.reload,
        applied(&[CaKind::User], 0)
    );
    let snapshot = harness.control.ca_snapshot();
    assert_eq!(
        snapshot.user_trust().next().map(fingerprint_hex),
        Some(next)
    );
    assert_eq!(host_signer(&harness), host_before);
}

async fn gate_accepts(stand: &Stand, identity: &Identity) -> bool {
    let tcp = TcpStream::connect(stand.gate.local_addr()).await.unwrap();
    let mut handle = within(
        "the gate handshake",
        client::connect_stream(
            Arc::new(client::Config::default()),
            tcp,
            crate::stand::Quiet,
        ),
    )
    .await
    .unwrap();
    within(
        "the gate login",
        handle.authenticate_openssh_cert(
            "jaunt",
            Arc::new(identity.key.clone()),
            identity.certificate.clone(),
        ),
    )
    .await
    .is_ok_and(|login| login.success())
}

struct Presented(Arc<Mutex<Option<String>>>);

impl client::Handler for Presented {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if let PublicKeyOrCertificate::Certificate(certificate) = key {
            *self.0.lock().unwrap() = Some(certificate_signer(certificate));
        }
        Ok(true)
    }
}

async fn presented_signer(stand: &Stand) -> String {
    let seen = Arc::new(Mutex::new(None));
    let tcp = TcpStream::connect(stand.gate.local_addr()).await.unwrap();
    let config = client::Config {
        preferred: Preferred {
            host_key_certificates: Cow::Borrowed(&[Algorithm::Ed25519]),
            ..Preferred::DEFAULT
        },
        ..client::Config::default()
    };
    let handle = within(
        "the gate handshake",
        client::connect_stream(Arc::new(config), tcp, Presented(Arc::clone(&seen))),
    )
    .await
    .unwrap();
    drop(handle);
    let signer = seen.lock().unwrap().clone();
    signer.expect("the gate presented no host certificate")
}

fn stand_reloader(stand: &Stand, keys: &Keys) -> CaReloader {
    keys.reloader(
        &stand.harness,
        Some(Arc::clone(stand.gate.gate())),
        Some(stand.harness.server.registry().clone()),
    )
}

fn put(path: &Path, bytes: &[u8]) {
    let temporary = path.with_extension("writing");
    std::fs::write(&temporary, bytes).unwrap();
    std::fs::rename(&temporary, path).unwrap();
}

struct Step<'a> {
    name: &'static str,
    write: Box<dyn Fn() + 'a>,
    changes_trust: bool,
    old_key_trusted: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_single_write_of_a_user_rotation_applies_cleanly_and_keeps_the_needed_keys_trusted() {
    let stand = Stand::start(&["web-01"]).await;
    let keys = Keys::of(&stand.harness);
    let (agents, counters) = counting_agents(&stand.harness, &["web-02"]).await;
    let mut reloader = stand_reloader(&stand, &keys);
    let old = stand.identity().await;
    let (_outer, inner) = stand.session(&old, "web-01").await;
    let slot = keys.slot(CaKind::User);
    let first = user_signer(&stand.harness);
    let scratch = tempfile::tempdir().unwrap();
    let next = fingerprint_hex(
        &FileBackend::init(scratch.path(), CaKind::User, &keys.age().recipient()).unwrap(),
    );
    let made = scratch.path().join("user");
    let copy = |suffix: &str| {
        let name = format!("{next}.{suffix}");
        put(&slot.join(&name), &std::fs::read(made.join(&name)).unwrap());
    };
    let pointer = |name: &str| put(&slot.join(name), format!("{next}\n").as_bytes());
    let steps = [
        Step {
            name: "add-next writes the private key",
            write: Box::new(|| copy("age")),
            changes_trust: false,
            old_key_trusted: true,
        },
        Step {
            name: "add-next writes the public key",
            write: Box::new(|| copy("pub")),
            changes_trust: true,
            old_key_trusted: true,
        },
        Step {
            name: "add-next writes the next pointer",
            write: Box::new(|| pointer("next")),
            changes_trust: true,
            old_key_trusted: true,
        },
        Step {
            name: "promote moves the active pointer",
            write: Box::new(|| pointer("active")),
            changes_trust: true,
            old_key_trusted: true,
        },
        Step {
            name: "promote removes the next pointer",
            write: Box::new(|| std::fs::remove_file(slot.join("next")).unwrap()),
            changes_trust: false,
            old_key_trusted: true,
        },
        Step {
            name: "retire moves the public key away",
            write: Box::new(|| {
                std::fs::create_dir_all(slot.join("retired")).unwrap();
                let name = format!("{first}.pub");
                std::fs::rename(slot.join(&name), slot.join("retired").join(&name)).unwrap();
            }),
            changes_trust: true,
            old_key_trusted: false,
        },
        Step {
            name: "retire removes the private key",
            write: Box::new(|| std::fs::remove_file(slot.join(format!("{first}.age"))).unwrap()),
            changes_trust: false,
            old_key_trusted: false,
        },
    ];
    let mut changes = 0;
    for (index, step) in (0_u64..).zip(&steps) {
        (step.write)();
        let reload = reloader.tick(at(10 * index)).await.reload;

        let expected = if step.changes_trust {
            changes += 1;
            applied(&[CaKind::User], 2)
        } else {
            Reload::Unchanged
        };
        assert_eq!(reload, expected, "{}", step.name);
        assert_eq!(
            gate_accepts(&stand, &old).await,
            step.old_key_trusted,
            "{}",
            step.name
        );
        let current = stand.identity().await;
        assert!(gate_accepts(&stand, &current).await, "{}", step.name);
        assert_eq!(inner.echo().await, b"ok\n", "{}", step.name);
        eventually("the agent to hear each applied change", || {
            counters[0].load(Ordering::SeqCst) == changes
        })
        .await;
    }
    assert_eq!(user_signer(&stand.harness), next);
    let (_second_outer, second) = stand.session(&stand.identity().await, "web-01").await;
    assert_eq!(second.echo().await, b"ok\n");
    for agent in agents {
        agent.stop().await;
    }
    assert_eq!(counters[0].load(Ordering::SeqCst), changes);
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forced_promote_and_retire_in_one_tick_swaps_the_signer_and_drops_the_old_key_once() {
    let stand = Stand::start(&["web-01"]).await;
    let keys = Keys::of(&stand.harness);
    let mut reloader = stand_reloader(&stand, &keys);
    let old = stand.identity().await;
    let (_outer, inner) = stand.session(&old, "web-01").await;
    let next = keys.add_next(CaKind::User);
    assert_eq!(
        reloader.tick(at(0)).await.reload,
        applied(&[CaKind::User], 1)
    );

    keys.promote(CaKind::User);
    keys.retire(CaKind::User);
    let reload = reloader.tick(at(10)).await.reload;

    assert_eq!(reload, applied(&[CaKind::User], 1));
    assert_eq!(user_signer(&stand.harness), next);
    let reloaded = events_named("ca.reloaded");
    assert_eq!(reloaded.len(), 2);
    assert_eq!(field(&reloaded[1], "active_fp"), next);
    assert_eq!(reloader.tick(at(20)).await.reload, Reload::Unchanged);
    assert_eq!(
        stand
            .harness
            .control
            .ca_snapshot()
            .user_trust()
            .keys()
            .len(),
        1
    );
    let new = stand.identity().await;
    assert_eq!(certificate_signer(&new.certificate), next);
    assert!(!gate_accepts(&stand, &old).await);
    assert!(gate_accepts(&stand, &new).await);
    assert_eq!(inner.echo().await, b"ok\n");
    stand.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_key_promotion_moves_the_gate_certificate_within_one_tick_and_keeps_the_session() {
    let stand = Stand::start(&["web-01"]).await;
    let keys = Keys::of(&stand.harness);
    let mut reloader = stand_reloader(&stand, &keys);
    let identity = stand.identity().await;
    let (_outer, inner) = stand.session(&identity, "web-01").await;
    let first = host_signer(&stand.harness);
    assert_eq!(presented_signer(&stand).await, first);

    let next = keys.add_next(CaKind::Host);
    let added = reloader.tick(at(0)).await;
    assert_eq!(added.reload, applied(&[CaKind::Host], 1));
    assert_eq!(added.gate, GateCertificate::Current);
    assert_eq!(presented_signer(&stand).await, first);

    keys.promote(CaKind::Host);
    assert_eq!(presented_signer(&stand).await, first);
    let promoted = reloader.tick(at(10)).await;

    assert_eq!(promoted.reload, applied(&[CaKind::Host], 1));
    assert_eq!(promoted.gate, GateCertificate::Reissued);
    assert_eq!(host_signer(&stand.harness), next);
    assert_eq!(presented_signer(&stand).await, next);
    assert_eq!(stand.gate.gate().host_certificate_signer(), next);
    assert_eq!(inner.echo().await, b"ok\n");
    let (_second_outer, second) = stand.session(&identity, "web-01").await;
    assert_eq!(second.echo().await, b"ok\n");
    let steady = reloader.tick(at(20)).await;
    assert_eq!(steady.reload, Reload::Unchanged);
    assert_eq!(steady.gate, GateCertificate::Current);
    stand.stop().await;
}

const HIDE_SERIALS: &str = "ALTER TABLE serial_counter RENAME TO serial_counter_away";
const RESTORE_SERIALS: &str = "ALTER TABLE serial_counter_away RENAME TO serial_counter";

async fn serials(harness: &Harness, statement: &'static str) {
    let options = SqliteConnectOptions::new().filename(&harness.db_path);
    let pool = SqlitePool::connect_with(options).await.unwrap();
    sqlx::query(statement).execute(&pool).await.unwrap();
    pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_gate_certificate_keeps_the_old_one_served_and_is_retried_on_the_next_tick() {
    let stand = Stand::start(&["web-01"]).await;
    let keys = Keys::of(&stand.harness);
    let mut reloader = stand_reloader(&stand, &keys);
    let first = host_signer(&stand.harness);
    let next = keys.add_next(CaKind::Host);
    keys.promote(CaKind::Host);
    serials(&stand.harness, HIDE_SERIALS).await;

    let ticks = [reloader.tick(at(0)).await, reloader.tick(at(10)).await];

    assert_eq!(ticks[0].reload, applied(&[CaKind::Host], 1));
    assert_eq!(ticks[1].reload, Reload::Unchanged);
    let reported: Vec<bool> = ticks
        .iter()
        .map(|tick| match &tick.gate {
            GateCertificate::Failed { reason, reported } => {
                assert!(reason.contains("gate host certificate"), "{reason}");
                *reported
            }
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(reported, [true, false]);
    assert_eq!(host_signer(&stand.harness), next);
    assert_eq!(presented_signer(&stand).await, first);
    let failed = events_named("ca.reload.failed");
    assert_eq!(failed.len(), 1);
    assert!(field(&failed[0], "reason").contains("gate host certificate"));

    serials(&stand.harness, RESTORE_SERIALS).await;
    let repaired = reloader.tick(at(20)).await;

    assert_eq!(repaired.reload, Reload::Unchanged);
    assert_eq!(repaired.gate, GateCertificate::Reissued);
    assert_eq!(presented_signer(&stand).await, next);
    stand.stop().await;
}

struct HangingIssuer {
    control: Control,
    calls: AtomicUsize,
}

impl HostCertIssuer for HangingIssuer {
    fn issue<'a>(
        &'a self,
        public_key_openssh: &'a str,
        hostnames: &'a [String],
    ) -> BoxFuture<'a, Result<String, IssueError>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            if call > 0 {
                std::future::pending::<()>().await;
            }
            let signed = sign_host_certificate(
                self.control.ca_snapshot().host_signer().as_ref(),
                HostCertParams {
                    subject_public_key: CaPublicKey::from_openssh(public_key_openssh).unwrap(),
                    hostnames: hostnames.to_vec(),
                    serial: 1,
                    validity: DEFAULT_HOST_VALIDITY,
                },
                SystemTime::now(),
            )
            .unwrap();
            Ok(signed.to_openssh().unwrap())
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopping_the_watcher_does_not_wait_for_a_gate_certificate_that_never_comes() {
    let harness = Harness::start(Options::default()).await;
    let keys = Keys::of(&harness);
    let issuer = Arc::new(HangingIssuer {
        control: harness.control.clone(),
        calls: AtomicUsize::new(0),
    });
    let gate = Arc::new(
        SshGate::new(
            SshGateConfig::new(vec!["gate.jaunt.test".to_owned()], "jaunt.test"),
            issuer.clone(),
            Arc::new(UserCaSource::new(
                UserCaKeys::from_openssh_lines(harness.authorities.user_lines.clone()).unwrap(),
            )),
            Arc::new(harness.control.clone()),
            harness.server.registry().clone(),
        )
        .await
        .unwrap(),
    );
    let first = host_signer(&harness);
    let next = keys.add_next(CaKind::Host);
    keys.promote(CaKind::Host);
    let watcher = CaWatcher::start(
        keys.reloader(&harness, Some(Arc::clone(&gate)), None),
        Duration::from_millis(20),
        Arc::new(SystemTime::now),
    );

    eventually("the re-issue to start", || {
        issuer.calls.load(Ordering::SeqCst) == 2
    })
    .await;
    within("the watcher to stop", watcher.stop(Duration::from_secs(60))).await;

    assert_eq!(host_signer(&harness), next);
    assert_eq!(gate.host_certificate_signer(), first);
}
