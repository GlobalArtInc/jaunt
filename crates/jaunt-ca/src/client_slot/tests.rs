use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ssh_key::{HashAlg, LineEnding, PrivateKey};

use crate::error::CaError;
use crate::file::{FileBackend, MAX_PRIVATE_LEN};
use crate::fsutil::fingerprint_hex;
use crate::identity::AgeIdentity;
use crate::kind::CaKind;
use crate::test_support::{
    ClientAuthority, acquire_lock, client_authority, subject_key, verify_client,
};
use crate::trust::KeyRole;
use crate::x509::{ClientCa, DbClientParams, SubjectPublicKey, UserX509Params};

const NOW_SECS: u64 = 1_700_000_000;
const KINDS: [CaKind; 2] = [CaKind::UserX509, CaKind::DbClient];

fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

fn names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn sorted(names: &[String]) -> Vec<String> {
    let mut names = names.to_vec();
    names.sort();
    names
}

fn key_files(hex: &str) -> Vec<String> {
    [".age", ".pub", ".root.der"]
        .iter()
        .map(|suffix| format!("{hex}{suffix}"))
        .collect()
}

fn roles(root: &Path, kind: CaKind) -> Vec<(KeyRole, String)> {
    ClientCa::read_roots(root, kind)
        .unwrap()
        .1
        .into_iter()
        .map(|root| (root.role, root.fingerprint))
        .collect()
}

fn issue(ca: &ClientCa) -> Vec<u8> {
    let subject_public_key = SubjectPublicKey::from_ssh_key(&subject_key()).unwrap();
    let issued = match ca.kind() {
        CaKind::UserX509 => ca.issue_user_certificate(
            UserX509Params {
                subject_public_key,
                user_id: crate::Uuid::from_u128(7),
                email: "ada@example.com".to_owned(),
                serial: 9,
                valid_before: now() + Duration::from_secs(3600),
            },
            now(),
        ),
        _ => ca.issue_db_client_certificate(
            DbClientParams {
                subject_public_key,
                role: "app".to_owned(),
            },
            now(),
        ),
    };
    issued.unwrap().certificate_der
}

fn fail_at(step: usize) -> impl Fn(&Path) -> io::Result<()> {
    let calls = AtomicUsize::new(0);
    move |_: &Path| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == step {
            Err(io::Error::other("injected"))
        } else {
            Ok(())
        }
    }
}

fn active_hex(authority: &ClientAuthority) -> String {
    fingerprint_hex(authority.slot.trust.active())
}

fn rotated(authority: &ClientAuthority) -> String {
    let kind = authority.slot.ca.kind();
    let root = authority.dir.path();
    let lock = acquire_lock(root).unwrap();
    let next = ClientCa::add_next(&lock, kind, &authority.identity, now())
        .unwrap()
        .public_key;
    FileBackend::promote(
        &lock,
        kind,
        &authority.identity,
        &next.fingerprint(HashAlg::Sha256),
    )
    .unwrap();
    fingerprint_hex(&next)
}

#[test]
fn init_writes_a_root_beside_the_key_and_the_slot_loads() {
    for kind in KINDS {
        let dir = tempfile::tempdir().unwrap();
        let identity = AgeIdentity::generate();
        let initialized = ClientCa::init(dir.path(), kind, &identity.recipient(), now()).unwrap();
        assert!(initialized.sync_failure.is_none());
        let hex = fingerprint_hex(&initialized.public_key);
        let slot_dir = dir.path().join(kind.as_str());
        assert_eq!(names(dir.path()), [kind.as_str()]);
        let mut expected = key_files(&hex);
        expected.push("active".to_owned());
        assert_eq!(names(&slot_dir), sorted(&expected));
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&slot_dir), 0o700);
            for name in names(&slot_dir) {
                assert_eq!(mode(&slot_dir.join(&name)), 0o600, "{name}");
            }
        }

        let slot = ClientCa::load(dir.path(), kind, &identity).unwrap();
        assert_eq!(slot.ca.root_sha256_hex(), initialized.root.sha256_hex());
        assert_eq!(
            slot.ca.root_der(),
            fs::read(slot_dir.join(format!("{hex}.root.der"))).unwrap()
        );
        assert_eq!(roles(dir.path(), kind), [(KeyRole::Active, hex.clone())]);

        let before: Vec<(String, Vec<u8>)> = names(&slot_dir)
            .into_iter()
            .map(|name| (name.clone(), fs::read(slot_dir.join(&name)).unwrap()))
            .collect();
        assert!(matches!(
            ClientCa::init(dir.path(), kind, &identity.recipient(), now()),
            Err(CaError::AlreadyInitialized(found)) if found == kind
        ));
        let after: Vec<(String, Vec<u8>)> = names(&slot_dir)
            .into_iter()
            .map(|name| (name.clone(), fs::read(slot_dir.join(&name)).unwrap()))
            .collect();
        assert_eq!(after, before);
        assert_eq!(names(dir.path()), [kind.as_str()]);

        assert!(matches!(
            FileBackend::init(dir.path(), kind, &identity.recipient()),
            Err(CaError::RootRequired(found)) if found == kind
        ));
        let lock = acquire_lock(dir.path()).unwrap();
        assert!(matches!(
            FileBackend::add_next(&lock, kind, &identity),
            Err(CaError::RootRequired(found)) if found == kind
        ));
    }

    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    let lock = acquire_lock(dir.path()).unwrap();
    for kind in [CaKind::User, CaKind::Host, CaKind::Internal] {
        let refused = |result: Result<(), CaError>| matches!(result, Err(CaError::NotAClientAuthority(found)) if found == kind);
        assert!(refused(
            ClientCa::init(dir.path(), kind, &identity.recipient(), now()).map(drop)
        ));
        assert!(refused(
            ClientCa::add_next(&lock, kind, &identity, now()).map(drop)
        ));
        assert!(refused(ClientCa::read_roots(dir.path(), kind).map(drop)));
    }
}

#[test]
fn a_client_slot_rotates_and_every_trusted_key_keeps_its_root() {
    for kind in KINDS {
        let authority = client_authority(kind, now());
        let root = authority.dir.path();
        let slot_dir = root.join(kind.as_str());
        let first = active_hex(&authority);
        let first_root = authority.slot.ca.root_der().to_vec();
        let old_cert = issue(&authority.slot.ca);
        let lock = acquire_lock(root).unwrap();

        let added = ClientCa::add_next(&lock, kind, &authority.identity, now()).unwrap();
        let next = added.public_key.clone();
        let second = fingerprint_hex(&next);
        assert_eq!(
            roles(root, kind),
            [
                (KeyRole::Active, first.clone()),
                (KeyRole::Next, second.clone())
            ]
        );
        let (_, staged_roots) = ClientCa::read_roots(root, kind).unwrap();
        assert_eq!(staged_roots[1].certificate_der, added.root.certificate_der);
        let staged = ClientCa::load(root, kind, &authority.identity).unwrap();
        assert_eq!(staged.ca.root_der(), first_root.as_slice());

        FileBackend::promote(
            &lock,
            kind,
            &authority.identity,
            &next.fingerprint(HashAlg::Sha256),
        )
        .unwrap();
        assert_eq!(
            roles(root, kind),
            [
                (KeyRole::Active, second.clone()),
                (KeyRole::Previous, first.clone())
            ]
        );
        let promoted = ClientCa::load(root, kind, &authority.identity).unwrap();
        let new_cert = issue(&promoted.ca);
        let previous_root = &promoted.roots[1].certificate_der;
        assert_eq!(previous_root, &first_root);
        assert!(verify_client(promoted.ca.root_der(), &new_cert, NOW_SECS).is_ok());
        assert!(verify_client(previous_root, &old_cert, NOW_SECS).is_ok());
        assert!(verify_client(&first_root, &new_cert, NOW_SECS).is_err());

        let retired = FileBackend::retire(
            &lock,
            kind,
            &[authority.slot.trust.active().fingerprint(HashAlg::Sha256)],
        )
        .unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(roles(root, kind), [(KeyRole::Active, second.clone())]);
        let mut expected = key_files(&second);
        expected.extend(["active".to_owned(), "retired".to_owned()]);
        assert_eq!(names(&slot_dir), sorted(&expected));
        assert_eq!(
            names(&slot_dir.join("retired")),
            [format!("{first}.pub"), format!("{first}.root.der")]
        );
        let listing = FileBackend::read_slot(root, kind).unwrap();
        assert_eq!(listing.retired, [first]);
        assert!(listing.stray.is_empty());
    }
}

#[test]
fn a_failure_at_any_write_step_leaves_a_root_for_every_trusted_key() {
    let kind = CaKind::DbClient;
    for step in 1..=4 {
        let dir = tempfile::tempdir().unwrap();
        let identity = AgeIdentity::generate();
        let err = ClientCa::init_with(
            dir.path(),
            kind,
            &identity.recipient(),
            now(),
            &fail_at(step),
        )
        .unwrap_err();
        assert!(matches!(err, CaError::Io { .. }), "init step {step}: {err}");
        assert!(names(dir.path()).is_empty(), "init step {step}");
    }

    for step in 1..=4 {
        let authority = client_authority(kind, now());
        let root = authority.dir.path();
        let before = roles(root, kind);
        let lock = acquire_lock(root).unwrap();
        let err = ClientCa::add_next_with(&lock, kind, &authority.identity, now(), &fail_at(step))
            .unwrap_err();
        assert!(
            matches!(err, CaError::Io { .. }),
            "add-next step {step}: {err}"
        );
        assert_eq!(roles(root, kind), before, "add-next step {step}");
        assert!(ClientCa::load(root, kind, &authority.identity).is_ok());
        assert_eq!(
            names(&root.join(kind.as_str())).len(),
            4,
            "add-next step {step}"
        );
    }

    for step in 1..=4 {
        let authority = client_authority(kind, now());
        let root = authority.dir.path();
        let first = active_hex(&authority);
        let second = rotated(&authority);
        let lock = acquire_lock(root).unwrap();
        let previous = [authority.slot.trust.active().fingerprint(HashAlg::Sha256)];
        let err = FileBackend::retire_with(&lock, kind, &previous, &fail_at(step)).unwrap_err();
        assert!(
            matches!(err, CaError::Io { .. }),
            "retire step {step}: {err}"
        );
        let context = format!("retire step {step}");
        ClientCa::read_roots(root, kind).unwrap_or_else(|err| panic!("{context}: {err}"));
        ClientCa::load(root, kind, &authority.identity)
            .unwrap_or_else(|err| panic!("{context}: {err}"));

        FileBackend::finish_retired(&lock, kind).unwrap();
        if roles(root, kind).len() > 1 {
            FileBackend::retire(&lock, kind, &previous).unwrap();
        }
        let slot_dir = root.join(kind.as_str());
        let mut expected = key_files(&second);
        expected.extend(["active".to_owned(), "retired".to_owned()]);
        assert_eq!(names(&slot_dir), sorted(&expected), "{context}");
        assert_eq!(
            names(&slot_dir.join("retired")),
            [format!("{first}.pub"), format!("{first}.root.der")],
            "{context}"
        );
    }
}

#[test]
fn promote_refuses_a_next_key_without_its_own_root() {
    let authority = client_authority(CaKind::UserX509, now());
    let root = authority.dir.path();
    let kind = CaKind::UserX509;
    let first = active_hex(&authority);
    let lock = acquire_lock(root).unwrap();
    let next = ClientCa::add_next(&lock, kind, &authority.identity, now())
        .unwrap()
        .public_key;
    let fingerprint = next.fingerprint(HashAlg::Sha256);
    let next_root = root
        .join(kind.as_str())
        .join(format!("{}.root.der", fingerprint_hex(&next)));
    let saved = fs::read(&next_root).unwrap();
    let promote = || FileBackend::promote(&lock, kind, &authority.identity, &fingerprint);

    fs::remove_file(&next_root).unwrap();
    assert!(matches!(promote(), Err(CaError::CorruptStore { .. })));
    fs::write(&next_root, authority.slot.ca.root_der()).unwrap();
    let refused = promote().unwrap_err();
    assert!(
        refused
            .to_string()
            .contains(&format!("{}.root.der", fingerprint_hex(&next))),
        "{refused}"
    );
    assert!(matches!(
        ClientCa::read_roots(root, kind),
        Err(CaError::CorruptStore { .. })
    ));
    assert_eq!(
        fingerprint_hex(FileBackend::read_slot(root, kind).unwrap().trust.active()),
        first
    );

    fs::write(&next_root, saved).unwrap();
    promote().unwrap();
    assert_eq!(
        roles(root, kind)[0],
        (KeyRole::Active, fingerprint_hex(&next))
    );
}

#[test]
fn add_next_and_promote_refuse_a_damaged_root_of_the_active_key() {
    for kind in KINDS {
        let authority = client_authority(kind, now());
        let root = authority.dir.path();
        let slot_dir = root.join(kind.as_str());
        let active = active_hex(&authority);
        let active_root = slot_dir.join(format!("{active}.root.der"));
        let saved = fs::read(&active_root).unwrap();
        let mut damaged = saved.clone();
        damaged.push(0);
        let lock = acquire_lock(root).unwrap();
        let damaged_message = |err: &CaError| {
            matches!(err, CaError::CorruptStore { .. })
                && err.to_string().contains(&format!("{active}.root.der"))
                && err.to_string().contains("trailing data")
        };

        fs::write(&active_root, &damaged).unwrap();
        let before = names(&slot_dir);
        let refused = ClientCa::add_next(&lock, kind, &authority.identity, now()).unwrap_err();
        assert!(damaged_message(&refused), "{kind}: {refused}");
        assert_eq!(names(&slot_dir), before);

        fs::write(&active_root, &saved).unwrap();
        let next = ClientCa::add_next(&lock, kind, &authority.identity, now())
            .unwrap()
            .public_key;
        fs::write(&active_root, &damaged).unwrap();
        let fingerprint = next.fingerprint(HashAlg::Sha256);
        let refused =
            FileBackend::promote(&lock, kind, &authority.identity, &fingerprint).unwrap_err();
        assert!(damaged_message(&refused), "{kind}: {refused}");
        let listing = FileBackend::read_slot(root, kind).unwrap();
        assert_eq!(fingerprint_hex(listing.trust.active()), active);
        assert!(listing.trust.next().is_some());

        fs::write(&active_root, &saved).unwrap();
        FileBackend::promote(&lock, kind, &authority.identity, &fingerprint).unwrap();
        assert!(ClientCa::load(root, kind, &authority.identity).is_ok());
    }
}

struct Crashes {
    root: PathBuf,
    out: tempfile::TempDir,
    taken: AtomicUsize,
}

impl Crashes {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            out: tempfile::tempdir().unwrap(),
            taken: AtomicUsize::new(0),
        }
    }

    fn after_each_step(&self) -> impl Fn(&Path) -> io::Result<()> + '_ {
        move |_: &Path| {
            let index = self.taken.fetch_add(1, Ordering::SeqCst);
            copy_tree(&self.root, &self.out.path().join(format!("{index:03}")));
            Ok(())
        }
    }

    fn snapshots(&self) -> Vec<PathBuf> {
        names(self.out.path())
            .into_iter()
            .map(|name| self.out.path().join(name))
            .collect()
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn published_and_usable(
    snapshot: &Path,
    kind: CaKind,
    identity: &AgeIdentity,
    label: &str,
) -> bool {
    match FileBackend::read_slot(snapshot, kind) {
        Err(CaError::NotInitialized(_)) => return false,
        Err(err) => panic!("{label}: {err}"),
        Ok(_) => {}
    }
    let (trust, roots) =
        ClientCa::read_roots(snapshot, kind).unwrap_or_else(|err| panic!("{label}: {err}"));
    assert_eq!(trust.keys().len(), roots.len(), "{label}");
    let slot =
        ClientCa::load(snapshot, kind, identity).unwrap_or_else(|err| panic!("{label}: {err}"));
    if trust.next().is_some() {
        FileBackend::load_with_next(snapshot, kind, identity)
            .unwrap_or_else(|err| panic!("{label}: {err}"));
    }
    let certificate = issue(&slot.ca);
    assert!(
        verify_client(slot.ca.root_der(), &certificate, NOW_SECS).is_ok(),
        "{label}"
    );
    true
}

#[test]
fn a_crash_after_any_write_step_leaves_every_trusted_key_with_its_root() {
    for kind in KINDS {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let identity = AgeIdentity::generate();
        let check = |crashes: &Crashes, op: &str, steps: usize, published: bool| {
            let snapshots = crashes.snapshots();
            assert_eq!(snapshots.len(), steps, "{kind} {op}");
            for (step, snapshot) in snapshots.iter().enumerate() {
                let label = format!("{kind} {op} crash after step {}", step + 1);
                assert_eq!(
                    published_and_usable(snapshot, kind, &identity, &label),
                    published,
                    "{label}"
                );
            }
        };

        let crashes = Crashes::new(root);
        ClientCa::init_with(
            root,
            kind,
            &identity.recipient(),
            now(),
            &crashes.after_each_step(),
        )
        .unwrap();
        check(&crashes, "init", 4, false);
        let first = ClientCa::read_roots(root, kind).unwrap().0.active().clone();

        let lock = acquire_lock(root).unwrap();
        let crashes = Crashes::new(root);
        let next =
            ClientCa::add_next_with(&lock, kind, &identity, now(), &crashes.after_each_step())
                .unwrap()
                .public_key;
        check(&crashes, "add-next", 4, true);

        let crashes = Crashes::new(root);
        FileBackend::promote_with(
            &lock,
            kind,
            &identity,
            &next.fingerprint(HashAlg::Sha256),
            &crashes.after_each_step(),
        )
        .unwrap();
        check(&crashes, "promote", 2, true);

        let crashes = Crashes::new(root);
        FileBackend::retire_with(
            &lock,
            kind,
            &[first.fingerprint(HashAlg::Sha256)],
            &crashes.after_each_step(),
        )
        .unwrap();
        check(&crashes, "retire", 4, true);
    }
}

#[test]
fn client_slot_debug_output_reveals_no_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let identity = AgeIdentity::generate();
    let kind = CaKind::UserX509;
    let initialized = ClientCa::init(dir.path(), kind, &identity.recipient(), now()).unwrap();
    let slot = ClientCa::load(dir.path(), kind, &identity).unwrap();
    let hex = fingerprint_hex(&initialized.public_key);
    let ciphertext = fs::read(dir.path().join(kind.as_str()).join(format!("{hex}.age"))).unwrap();
    let plaintext = identity.decrypt(&ciphertext, MAX_PRIVATE_LEN).unwrap();
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

    let printed = format!("{slot:?} {slot:#?} {initialized:?} {:?}", slot.ca);

    assert!(printed.contains("ClientCa") && printed.contains("TrustedRoot"));
    assert!(printed.contains(&slot.ca.root_sha256_hex()));
    assert!(!printed.to_lowercase().contains(&secret));
    assert!(!printed.contains(&format!(
        "{:?}",
        key.key_data().ed25519().unwrap().private.to_bytes()
    )));
    assert!(!printed.contains("PRIVATE KEY"));
    assert!(!printed.to_uppercase().contains("AGE-SECRET-KEY"));
    for body_line in pem.lines().filter(|line| line.len() > 20) {
        assert!(!printed.contains(body_line));
    }
}
