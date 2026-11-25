use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ssh_key::{Fingerprint, HashAlg, LineEnding, PrivateKey, PublicKey};

use super::{CaLock, Seal, ensure_owner};
use crate::error::CaError;
use crate::file::{FileBackend, MAX_PRIVATE_LEN};
use crate::fsutil::fingerprint_hex;
use crate::identity::{AgeIdentity, AgeRecipient, encrypt};
use crate::kind::CaKind;
use crate::trust::KeyRole;

const KIND: CaKind = CaKind::User;
const CRASH_OP: &str = "JAUNT_CA_TEST_CRASH_OP";
const CRASH_STEP: &str = "JAUNT_CA_TEST_CRASH_STEP";
const CRASH_ROOT: &str = "JAUNT_CA_TEST_CRASH_ROOT";
const CRASH_IDENTITY: &str = "JAUNT_CA_TEST_CRASH_IDENTITY";
const CRASH_EXIT: i32 = 86;
const CHILD_TEST: &str = "rotation::tests::crash_child";
const WAIT: Duration = Duration::from_secs(30);

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    identity_file: PathBuf,
    identity: AgeIdentity,
    first: String,
    second: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Shape {
    active: String,
    next: Option<String>,
    previous: Vec<String>,
    retired: Vec<String>,
    stray: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    AddNext,
    Promote,
    Retire,
}

impl Op {
    const ALL: [(Op, usize); 3] = [(Op::AddNext, 3), (Op::Promote, 2), (Op::Retire, 3)];

    fn name(self) -> &'static str {
        match self {
            Op::AddNext => "add-next",
            Op::Promote => "promote",
            Op::Retire => "retire",
        }
    }

    fn parse(name: &str) -> Op {
        match name {
            "add-next" => Op::AddNext,
            "promote" => Op::Promote,
            "retire" => Op::Retire,
            other => panic!("unknown op {other}"),
        }
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("ca");
    let identity_file = dir.path().join("identity.txt");
    let identity = AgeIdentity::generate();
    identity.write_new_file(&identity_file).unwrap();
    let first = fingerprint_hex(&FileBackend::init(&root, KIND, &identity.recipient()).unwrap());
    Fixture {
        _dir: dir,
        root,
        identity_file,
        identity,
        first,
        second: None,
    }
}

fn prepared(op: Op) -> Fixture {
    let mut fixture = fixture();
    if op == Op::AddNext {
        return fixture;
    }
    let lock = CaLock::acquire(&fixture.root).unwrap();
    let next = FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
    fixture.second = Some(fingerprint_hex(&next));
    if op == Op::Retire {
        FileBackend::promote(
            &lock,
            KIND,
            &fixture.identity,
            &next.fingerprint(HashAlg::Sha256),
        )
        .unwrap();
    }
    fixture
}

fn shape(root: &Path) -> Shape {
    let listing = FileBackend::read_slot(root, KIND).unwrap();
    Shape {
        active: fingerprint_hex(listing.trust.active()),
        next: listing.trust.next().map(fingerprint_hex),
        previous: listing.trust.previous().map(fingerprint_hex).collect(),
        retired: listing.retired,
        stray: listing.stray,
    }
}

fn expected_shape(fixture: &Fixture, op: Op, completed_steps: usize) -> Shape {
    let first = fixture.first.clone();
    let second = fixture.second.clone();
    let none: Vec<String> = Vec::new();
    match (op, completed_steps) {
        (Op::Promote, 0) => Shape {
            active: first,
            next: second,
            previous: none.clone(),
            retired: none.clone(),
            stray: none,
        },
        (Op::Promote, _) | (Op::Retire, 0 | 1) => Shape {
            active: second.unwrap(),
            next: None,
            previous: vec![first],
            retired: none.clone(),
            stray: none,
        },
        (Op::Retire, 2) => Shape {
            active: second.unwrap(),
            next: None,
            previous: none,
            retired: vec![first.clone()],
            stray: vec![first],
        },
        (Op::Retire, _) => Shape {
            active: second.unwrap(),
            next: None,
            previous: none,
            retired: vec![first],
            stray: Vec::new(),
        },
        (Op::AddNext, _) => panic!("add-next shapes depend on the generated key"),
    }
}

fn previous_binary_load(root: &Path, identity: &AgeIdentity) -> (String, Vec<String>) {
    let dir = root.join(KIND.as_str());
    let active = fs::read_to_string(dir.join("active")).unwrap();
    let active = active.strip_suffix('\n').unwrap_or(&active).to_owned();
    let mut trusted = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if let Some(stem) = name.strip_suffix(".pub") {
            let line = fs::read_to_string(dir.join(&name)).unwrap();
            let key = PublicKey::from_openssh(&line).unwrap();
            assert_eq!(fingerprint_hex(&key), stem);
            trusted.push(stem.to_owned());
        }
    }
    trusted.sort();
    assert!(trusted.contains(&active));
    let ciphertext = fs::read(dir.join(format!("{active}.age"))).unwrap();
    let plaintext = identity.decrypt(&ciphertext, MAX_PRIVATE_LEN).unwrap();
    let key = PrivateKey::from_openssh(&*plaintext).unwrap();
    assert_eq!(fingerprint_hex(key.public_key()), active);
    (active, trusted)
}

fn assert_loads(fixture: &Fixture, context: &str) {
    let (trust, backend) = FileBackend::load(&fixture.root, KIND, &fixture.identity)
        .unwrap_or_else(|err| panic!("{context}: {err}"));
    FileBackend::load_with_next(&fixture.root, KIND, &fixture.identity)
        .unwrap_or_else(|err| panic!("{context}: {err}"));
    let (old_active, old_trusted) = previous_binary_load(&fixture.root, &fixture.identity);
    let mut trusted: Vec<String> = trust.keys().iter().map(fingerprint_hex).collect();
    trusted.sort();
    assert_eq!(old_active, fingerprint_hex(trust.active()), "{context}");
    assert_eq!(old_trusted, trusted, "{context}");
    assert_eq!(
        fingerprint_hex(crate::signer::Signer::public_key(&backend)),
        old_active,
        "{context}"
    );
}

fn run_op(
    fixture: &Fixture,
    op: Op,
    after_step: &dyn Fn(&Path) -> io::Result<()>,
) -> Result<(), CaError> {
    let lock = CaLock::acquire(&fixture.root)?;
    let trust = FileBackend::read_slot(&fixture.root, KIND)?.trust;
    match op {
        Op::AddNext => {
            FileBackend::add_next_with(&lock, KIND, &fixture.identity, after_step).map(|_| ())
        }
        Op::Promote => {
            let next = trust.next().ok_or(CaError::NoNextKey(KIND))?;
            FileBackend::promote_with(
                &lock,
                KIND,
                &fixture.identity,
                &next.fingerprint(HashAlg::Sha256),
                after_step,
            )
            .map(|_| ())
        }
        Op::Retire => {
            let previous: Vec<Fingerprint> = trust
                .previous()
                .map(|key| key.fingerprint(HashAlg::Sha256))
                .collect();
            FileBackend::retire_with(&lock, KIND, &previous, after_step).map(|_| ())
        }
    }
}

#[test]
fn a_directory_made_by_init_loads_as_a_slot_with_only_an_active_key() {
    let fixture = fixture();
    let (trust, _) = FileBackend::load_with_next(&fixture.root, KIND, &fixture.identity).unwrap();
    assert_eq!(fingerprint_hex(trust.active()), fixture.first);
    assert!(trust.next().is_none());
    assert_eq!(trust.previous().count(), 0);
    let roles: Vec<KeyRole> = trust.roles().map(|(role, _)| role).collect();
    assert_eq!(roles, [KeyRole::Active]);
    assert_eq!(
        shape(&fixture.root),
        Shape {
            active: fixture.first.clone(),
            next: None,
            previous: Vec::new(),
            retired: Vec::new(),
            stray: Vec::new(),
        }
    );
}

#[test]
fn a_full_rotation_moves_a_key_from_active_to_retired_and_deletes_its_private_key() {
    let fixture = fixture();
    let dir = fixture.root.join(KIND.as_str());
    let first_set = FileBackend::read_slot(&fixture.root, KIND)
        .unwrap()
        .trust
        .set_id();
    let lock = CaLock::acquire(&fixture.root).unwrap();

    let second = fingerprint_hex(&FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap());
    let staged = FileBackend::read_slot(&fixture.root, KIND).unwrap().trust;
    assert_eq!(fingerprint_hex(staged.active()), fixture.first);
    assert_eq!(staged.next().map(fingerprint_hex), Some(second.clone()));
    assert_eq!(
        fs::read_to_string(dir.join("next")).unwrap(),
        format!("{second}\n")
    );
    assert!(dir.join(format!("{second}.age")).exists());
    assert_ne!(staged.set_id(), first_set);

    let next = staged.next().unwrap().fingerprint(HashAlg::Sha256);
    let promoted = FileBackend::promote(&lock, KIND, &fixture.identity, &next).unwrap();
    assert_eq!(fingerprint_hex(&promoted.active), second);
    assert_eq!(fingerprint_hex(&promoted.previous), fixture.first);
    let (switched, backend) = FileBackend::load(&fixture.root, KIND, &fixture.identity).unwrap();
    assert_eq!(fingerprint_hex(switched.active()), second);
    assert_eq!(
        fingerprint_hex(crate::signer::Signer::public_key(&backend)),
        second
    );
    assert!(!dir.join("next").exists());
    assert_eq!(switched.set_id(), staged.set_id());
    assert_eq!(
        switched.previous().map(fingerprint_hex).collect::<Vec<_>>(),
        vec![fixture.first.clone()]
    );

    let old = switched
        .previous()
        .next()
        .unwrap()
        .fingerprint(HashAlg::Sha256);
    let retired = FileBackend::retire(&lock, KIND, &[old]).unwrap();
    assert_eq!(retired.len(), 1);
    let left = FileBackend::read_slot(&fixture.root, KIND).unwrap();
    assert_eq!(left.trust.keys().len(), 1);
    assert!(!left.trust.contains(&old));
    assert_eq!(left.retired, vec![fixture.first.clone()]);
    assert!(left.stray.is_empty());
    assert!(!dir.join(format!("{}.age", fixture.first)).exists());
    assert!(!dir.join(format!("{}.pub", fixture.first)).exists());
    assert!(
        dir.join("retired")
            .join(format!("{}.pub", fixture.first))
            .exists()
    );
    assert_ne!(left.trust.set_id(), switched.set_id());
    assert_loads(&fixture, "after retire");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("retired")), 0o700);
        assert_eq!(mode(&fixture.root.join(".lock")), 0o600);
        for name in [
            format!("{second}.age"),
            format!("{second}.pub"),
            "active".to_owned(),
        ] {
            assert_eq!(mode(&dir.join(&name)), 0o600, "{name}");
        }
    }
}

#[test]
fn a_second_next_key_is_refused_and_nothing_changes() {
    let fixture = prepared(Op::Promote);
    let before = shape(&fixture.root);
    let lock = CaLock::acquire(&fixture.root).unwrap();
    assert!(matches!(
        FileBackend::add_next(&lock, KIND, &fixture.identity),
        Err(CaError::NextKeyExists(KIND))
    ));
    assert_eq!(shape(&fixture.root), before);
}

#[test]
fn promote_is_refused_while_a_previous_key_is_present() {
    let fixture = prepared(Op::Retire);
    let lock = CaLock::acquire(&fixture.root).unwrap();
    let third = FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
    let before = shape(&fixture.root);
    assert!(matches!(
        FileBackend::promote(
            &lock,
            KIND,
            &fixture.identity,
            &third.fingerprint(HashAlg::Sha256)
        ),
        Err(CaError::PreviousKeyPresent(KIND))
    ));
    assert_eq!(shape(&fixture.root), before);
}

#[test]
fn operations_refuse_a_slot_that_changed_since_the_check() {
    let promote = prepared(Op::Promote);
    let stranger = crate::test_support::subject_key().fingerprint(HashAlg::Sha256);
    let lock = CaLock::acquire(&promote.root).unwrap();
    assert!(matches!(
        FileBackend::promote(&lock, KIND, &promote.identity, &stranger),
        Err(CaError::SlotChanged(KIND))
    ));
    drop(lock);

    let retire = prepared(Op::Retire);
    let before = shape(&retire.root);
    let lock = CaLock::acquire(&retire.root).unwrap();
    for expected in [Vec::new(), vec![stranger]] {
        assert!(matches!(
            FileBackend::retire(&lock, KIND, &expected),
            Err(CaError::SlotChanged(KIND))
        ));
    }
    assert_eq!(shape(&retire.root), before);
}

#[test]
fn promote_is_refused_when_the_next_key_does_not_decrypt() {
    let fixture = prepared(Op::Promote);
    let second = fixture.second.clone().unwrap();
    let dir = fixture.root.join(KIND.as_str());
    let other = fixture.root.join("other");
    FileBackend::init(&other, KIND, &fixture.identity.recipient()).unwrap();
    let other_age = fs::read_dir(other.join(KIND.as_str()))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "age"))
        .unwrap();
    fs::copy(other_age, dir.join(format!("{second}.age"))).unwrap();
    let before = shape(&fixture.root);
    let lock = CaLock::acquire(&fixture.root).unwrap();
    let next = fingerprint_from(&second);

    let err = FileBackend::promote(&lock, KIND, &fixture.identity, &next).unwrap_err();

    assert!(matches!(err, CaError::CorruptStore { .. }), "{err}");
    assert_eq!(shape(&fixture.root), before);
    assert!(FileBackend::load(&fixture.root, KIND, &fixture.identity).is_ok());
}

#[test]
fn add_next_is_refused_with_an_identity_that_cannot_open_the_active_key() {
    let fixture = fixture();
    let before = shape(&fixture.root);
    let lock = CaLock::acquire(&fixture.root).unwrap();
    assert!(matches!(
        FileBackend::add_next(&lock, KIND, &AgeIdentity::generate()),
        Err(CaError::Decrypt)
    ));
    assert_eq!(shape(&fixture.root), before);
}

#[test]
fn the_internal_authority_is_not_rotated() {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    let key = FileBackend::init(dir.path(), CaKind::Internal, &identity.recipient()).unwrap();
    let lock = CaLock::acquire(dir.path()).unwrap();
    let fingerprint = key.fingerprint(HashAlg::Sha256);
    let refused = |result: Result<(), CaError>| {
        matches!(result, Err(CaError::RotationUnsupported(CaKind::Internal)))
    };
    assert!(refused(
        FileBackend::add_next(&lock, CaKind::Internal, &identity).map(|_| ())
    ));
    assert!(refused(
        FileBackend::promote(&lock, CaKind::Internal, &identity, &fingerprint).map(|_| ())
    ));
    assert!(refused(
        FileBackend::retire(&lock, CaKind::Internal, &[fingerprint]).map(|_| ())
    ));
    assert!(refused(
        FileBackend::finish_retired(&lock, CaKind::Internal).map(|_| ())
    ));
}

#[test]
fn a_failure_after_any_write_step_leaves_a_directory_that_loads() {
    for (op, steps) in Op::ALL {
        for step in 1..=steps {
            let fixture = prepared(op);
            let before = shape(&fixture.root);
            let calls = AtomicUsize::new(0);
            let fail_at_step = |_: &Path| {
                if calls.fetch_add(1, Ordering::SeqCst) + 1 == step {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            };

            let err = run_op(&fixture, op, &fail_at_step).unwrap_err();

            let context = format!("{} step {step}", op.name());
            assert!(matches!(err, CaError::Io { .. }), "{context}: {err}");
            assert_loads(&fixture, &context);
            let expected = if op == Op::AddNext {
                before
            } else {
                expected_shape(&fixture, op, step)
            };
            assert_eq!(shape(&fixture.root), expected, "{context}");
        }
    }
}

#[test]
fn a_crash_after_any_write_step_leaves_a_directory_that_loads_and_unlocks() {
    let exe = std::env::current_exe().unwrap();
    for (op, steps) in Op::ALL {
        for step in 1..=steps + 1 {
            let fixture = prepared(op);
            let before = shape(&fixture.root);
            let child = Command::new(&exe)
                .args([CHILD_TEST, "--exact", "--ignored", "--test-threads=1"])
                .env(CRASH_OP, op.name())
                .env(CRASH_STEP, step.to_string())
                .env(CRASH_ROOT, &fixture.root)
                .env(CRASH_IDENTITY, &fixture.identity_file)
                .output()
                .unwrap();

            let context = format!(
                "{} crash at step {step}: {}{}",
                op.name(),
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            let expected_exit = if step <= steps { CRASH_EXIT } else { 0 };
            assert_eq!(child.status.code(), Some(expected_exit), "{context}");
            assert_loads(&fixture, &context);
            assert!(CaLock::acquire(&fixture.root).is_ok(), "{context}");
            let after = shape(&fixture.root);
            match op {
                Op::AddNext => assert_add_next_crash(&fixture, &before, &after, step),
                _ => assert_eq!(after, expected_shape(&fixture, op, step), "{context}"),
            }
            recover(&fixture, op);
        }
    }
}

fn assert_add_next_crash(fixture: &Fixture, before: &Shape, after: &Shape, step: usize) {
    assert_eq!(after.active, fixture.first, "add-next step {step}");
    assert!(after.retired.is_empty());
    let created: Vec<String> = after
        .stray
        .iter()
        .chain(&after.previous)
        .chain(&after.next)
        .cloned()
        .collect();
    assert_eq!(created.len(), 1, "add-next step {step}: {after:?}");
    let expected = Shape {
        active: before.active.clone(),
        next: (step >= 3).then(|| created[0].clone()),
        previous: if step == 2 {
            created.clone()
        } else {
            Vec::new()
        },
        retired: Vec::new(),
        stray: if step == 1 { created } else { Vec::new() },
    };
    assert_eq!(after, &expected, "add-next step {step}");
}

fn recover(fixture: &Fixture, op: Op) {
    let lock = CaLock::acquire(&fixture.root).unwrap();
    match op {
        Op::AddNext => {
            if shape(&fixture.root).next.is_none() {
                FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
            }
            assert!(shape(&fixture.root).next.is_some());
        }
        Op::Promote => {
            let promoted = shape(&fixture.root);
            assert_eq!(Some(promoted.active), fixture.second);
            FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
            assert!(shape(&fixture.root).next.is_some());
        }
        Op::Retire => {
            FileBackend::finish_retired(&lock, KIND).unwrap();
            let previous: Vec<Fingerprint> = FileBackend::read_slot(&fixture.root, KIND)
                .unwrap()
                .trust
                .previous()
                .map(|key| key.fingerprint(HashAlg::Sha256))
                .collect();
            if !previous.is_empty() {
                FileBackend::retire(&lock, KIND, &previous).unwrap();
            }
            let done = shape(&fixture.root);
            assert!(
                done.previous.is_empty() && done.stray.is_empty(),
                "{done:?}"
            );
        }
    }
}

#[test]
#[ignore = "child process of a_crash_after_any_write_step_leaves_a_directory_that_loads_and_unlocks"]
fn crash_child() {
    let Ok(op) = std::env::var(CRASH_OP) else {
        return;
    };
    let var = |name: &str| std::env::var_os(name).unwrap();
    let step: usize = var(CRASH_STEP).into_string().unwrap().parse().unwrap();
    let identity = AgeIdentity::read_file(Path::new(&var(CRASH_IDENTITY))).unwrap();
    let fixture = fixture_at(PathBuf::from(var(CRASH_ROOT)), identity);
    let calls = AtomicUsize::new(0);
    let crash_at_step = |_: &Path| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == step {
            std::process::exit(CRASH_EXIT);
        }
        Ok(())
    };
    run_op(&fixture, Op::parse(&op), &crash_at_step).unwrap();
}

fn fixture_at(root: PathBuf, identity: AgeIdentity) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let first = fingerprint_hex(FileBackend::read_slot(&root, KIND).unwrap().trust.active());
    Fixture {
        identity_file: dir.path().join("unused"),
        _dir: dir,
        root,
        identity,
        first,
        second: None,
    }
}

fn fingerprint_from(hex: &str) -> Fingerprint {
    crate::fsutil::fingerprint_from_hex(hex).unwrap()
}

#[test]
fn the_previous_binary_still_loads_every_rotated_directory() {
    let fixture = fixture();
    fs::create_dir(fixture.root.join(KIND.as_str()).join("retired")).unwrap();
    let lock = CaLock::acquire(&fixture.root).unwrap();
    let next = FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
    let (active, trusted) = previous_binary_load(&fixture.root, &fixture.identity);
    assert_eq!(active, fixture.first);
    assert_eq!(trusted.len(), 2);
    assert!(trusted.contains(&fingerprint_hex(&next)));
    assert_loads(&fixture, "with next");

    FileBackend::promote(
        &lock,
        KIND,
        &fixture.identity,
        &next.fingerprint(HashAlg::Sha256),
    )
    .unwrap();
    let (active, trusted) = previous_binary_load(&fixture.root, &fixture.identity);
    assert_eq!(active, fingerprint_hex(&next));
    assert_eq!(trusted.len(), 2);
}

#[test]
fn a_stale_next_equal_to_the_active_key_is_ignored_and_cleared_by_add_next() {
    let fixture = prepared(Op::Retire);
    let dir = fixture.root.join(KIND.as_str());
    let second = fixture.second.clone().unwrap();
    fs::write(dir.join("next"), format!("{second}\n")).unwrap();
    assert_eq!(
        shape(&fixture.root),
        expected_shape(&fixture, Op::Retire, 0)
    );

    let lock = CaLock::acquire(&fixture.root).unwrap();
    let third = FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap();
    assert_eq!(shape(&fixture.root).next, Some(fingerprint_hex(&third)));
}

#[test]
fn a_next_file_outside_the_set_or_malformed_is_rejected() {
    let fixture = fixture();
    let next = fixture.root.join(KIND.as_str()).join("next");
    fs::write(&next, format!("{}\n", "a".repeat(64))).unwrap();
    assert!(matches!(
        FileBackend::load(&fixture.root, KIND, &fixture.identity),
        Err(CaError::NextKeyNotTrusted)
    ));
    for malformed in ["../active\n", "", &"A".repeat(64)] {
        fs::write(&next, malformed).unwrap();
        assert!(
            matches!(
                FileBackend::read_slot(&fixture.root, KIND),
                Err(CaError::CorruptStore { .. })
            ),
            "{malformed:?}"
        );
    }
}

#[test]
fn a_held_lock_refuses_a_second_command_until_it_is_released() {
    let fixture = fixture();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let root = &fixture.root;
    let identity = &fixture.identity;
    thread::scope(|scope| {
        let first = scope.spawn(move || {
            let lock = CaLock::acquire(root).unwrap();
            let paused = AtomicBool::new(false);
            let pause_once = |_: &Path| {
                if !paused.swap(true, Ordering::SeqCst) {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(WAIT).unwrap();
                }
                Ok(())
            };
            FileBackend::add_next_with(&lock, KIND, identity, &pause_once)
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        assert!(matches!(CaLock::acquire(root), Err(CaError::LockBusy)));
        release_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
    });
    let lock = CaLock::acquire(root).unwrap();
    assert!(matches!(
        FileBackend::add_next(&lock, KIND, identity),
        Err(CaError::NextKeyExists(KIND))
    ));
}

#[test]
fn private_key_material_never_shows_in_debug_output_or_errors() {
    let fixture = prepared(Op::Promote);
    let second = fixture.second.clone().unwrap();
    let dir = fixture.root.join(KIND.as_str());
    let ciphertext = fs::read(dir.join(format!("{second}.age"))).unwrap();
    let plaintext = fixture
        .identity
        .decrypt(&ciphertext, MAX_PRIVATE_LEN)
        .unwrap();
    let key = PrivateKey::from_openssh(&*plaintext).unwrap();
    let secret: String = key
        .key_data()
        .ed25519()
        .unwrap()
        .private
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let pem = key.to_openssh(LineEnding::LF).unwrap();

    let lock = CaLock::acquire(&fixture.root).unwrap();
    let listing = FileBackend::read_slot(&fixture.root, KIND).unwrap();
    let (trust, backend) =
        FileBackend::load_with_next(&fixture.root, KIND, &fixture.identity).unwrap();
    let refused = FileBackend::add_next(&lock, KIND, &fixture.identity).unwrap_err();
    let wrong = FileBackend::promote(
        &lock,
        KIND,
        &AgeIdentity::generate(),
        &fingerprint_from(&second),
    )
    .unwrap_err();
    let promoted =
        FileBackend::promote(&lock, KIND, &fixture.identity, &fingerprint_from(&second)).unwrap();
    let printed = format!(
        "{listing:?} {trust:?} {backend:?} {lock:?} {promoted:?} {refused} {refused:?} {wrong} {wrong:?}"
    );

    assert!(!printed.to_lowercase().contains(&secret));
    assert!(!printed.contains("PRIVATE KEY"));
    assert!(!printed.to_uppercase().contains("AGE-SECRET-KEY"));
    for body_line in pem.lines().filter(|line| line.len() > 20) {
        assert!(!printed.contains(body_line));
    }
    assert!(printed.contains("TrustSet") && printed.contains("next key"));
}

#[test]
fn a_half_finished_retirement_is_completed_once_and_unrelated_private_keys_stay() {
    let fixture = prepared(Op::Retire);
    let dir = fixture.root.join(KIND.as_str());
    fs::create_dir(dir.join("retired")).unwrap();
    fs::rename(
        dir.join(format!("{}.pub", fixture.first)),
        dir.join("retired").join(format!("{}.pub", fixture.first)),
    )
    .unwrap();
    assert_eq!(
        shape(&fixture.root),
        expected_shape(&fixture, Op::Retire, 2)
    );
    let orphan = orphan_private_key(&fixture);
    let lock = CaLock::acquire(&fixture.root).unwrap();

    assert_eq!(
        FileBackend::finish_retired(&lock, KIND).unwrap(),
        vec![fixture.first.clone()]
    );
    assert!(FileBackend::finish_retired(&lock, KIND).unwrap().is_empty());
    assert!(dir.join(format!("{orphan}.age")).exists());
    let mut expected = expected_shape(&fixture, Op::Retire, 3);
    expected.stray = vec![orphan];
    assert_eq!(shape(&fixture.root), expected);
    assert!(matches!(
        FileBackend::retire(&lock, KIND, &[]),
        Err(CaError::NoPreviousKey(KIND))
    ));
}

fn orphan_private_key(fixture: &Fixture) -> String {
    let other = fixture.root.join("other");
    let key = FileBackend::init(&other, KIND, &fixture.identity.recipient()).unwrap();
    let hex = fingerprint_hex(&key);
    fs::copy(
        other.join(KIND.as_str()).join(format!("{hex}.age")),
        fixture.root.join(KIND.as_str()).join(format!("{hex}.age")),
    )
    .unwrap();
    hex
}

#[test]
fn add_next_refuses_a_key_that_does_not_survive_its_own_encryption() {
    let fixture = fixture();
    let before = shape(&fixture.root);
    let stranger = AgeIdentity::generate().recipient();
    let to_stranger = |_: &AgeRecipient, plaintext: &[u8]| encrypt(&stranger, plaintext);
    let truncated = |recipient: &AgeRecipient, plaintext: &[u8]| {
        let mut sealed = encrypt(recipient, plaintext)?;
        sealed.truncate(sealed.len() - 1);
        Ok(sealed)
    };
    let lock = CaLock::acquire(&fixture.root).unwrap();
    let seals: [&Seal<'_>; 2] = [&to_stranger, &truncated];
    for seal in seals {
        let refused =
            FileBackend::add_next_sealed(&lock, KIND, &fixture.identity, seal, &|_| Ok(()));
        assert!(matches!(refused, Err(CaError::KeyRoundTrip)));
        assert_eq!(shape(&fixture.root), before);
    }
}

#[test]
fn only_the_owner_of_the_directory_may_take_the_lock() {
    let dir = Path::new("/srv/jaunt/ca");
    assert!(ensure_owner(dir, 1000, 1000).is_ok());
    let refused = ensure_owner(dir, 1000, 0).unwrap_err();
    assert!(matches!(
        refused,
        CaError::NotOwner {
            owner: 1000,
            euid: 0,
            ..
        }
    ));
    let message = refused.to_string();
    assert!(
        message.contains("/srv/jaunt/ca belongs to uid 1000"),
        "{message}"
    );
    assert!(message.contains("runs as uid 0"), "{message}");
    assert!(message.contains("nothing was changed"), "{message}");
}

#[test]
fn a_lock_file_that_is_a_link_or_a_directory_is_refused() {
    let fixture = fixture();
    let lock_path = fixture.root.join(".lock");
    let elsewhere = fixture.root.join("elsewhere");
    std::os::unix::fs::symlink(&elsewhere, &lock_path).unwrap();
    assert!(matches!(
        CaLock::acquire(&fixture.root),
        Err(CaError::UnsafeLock(_))
    ));
    assert!(!elsewhere.exists());

    fs::remove_file(&lock_path).unwrap();
    fs::create_dir(&lock_path).unwrap();
    assert!(matches!(
        CaLock::acquire(&fixture.root),
        Err(CaError::UnsafeLock(_))
    ));
}
