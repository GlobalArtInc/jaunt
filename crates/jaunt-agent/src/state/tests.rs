use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::{
    EnrollmentFiles, EnrollmentRecord, LOCK_FILE, MANAGED_FILES, STATE_FILE, StateDir, StateError,
    TLS_KEY_FILE, is_state_entry, previous_dirs, trusted_existing_dir,
};
use crate::fsio::{DirHandle, Owner, effective_uid, running_as_root, temp_name};
use crate::keys::{HostKey, TlsKey};
use crate::testkit::NODE_ID;

const NOW: i64 = 1_795_000_000;

fn record() -> EnrollmentRecord {
    EnrollmentRecord {
        node_id: NODE_ID.to_owned(),
        name: "web-01".to_owned(),
        server_url: "https://jaunt.example.com".to_owned(),
        agent_endpoint: "agents.example.com:443".to_owned(),
        x509_not_after: 20,
        ssh_not_after: 21,
        enrolled_at: 10,
    }
}

struct Keys {
    tls: TlsKey,
    host: HostKey,
    record: EnrollmentRecord,
}

impl Keys {
    fn new() -> Self {
        Self {
            tls: TlsKey::generate().unwrap(),
            host: HostKey::generate().unwrap(),
            record: record(),
        }
    }

    fn files(&self) -> EnrollmentFiles<'_> {
        EnrollmentFiles {
            record: &self.record,
            tls_key: &self.tls,
            host_key: &self.host,
            x509_der: b"x509",
            ssh_certificate: "ssh-ed25519-cert-v01@openssh.com AAAA",
            ca_root_der: b"root",
        }
    }
}

fn contents(dir: &Path) -> Vec<Vec<u8>> {
    MANAGED_FILES
        .iter()
        .map(|name| fs::read(dir.join(name)).unwrap())
        .collect()
}

fn prepared(path: &Path) -> StateDir {
    let (state, lock) = StateDir::prepare_enrollment(path, false).unwrap();
    drop(lock);
    state
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_stored_enrollment_loads_back_and_unknown_record_fields_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("state");
    let state = prepared(&root);
    let keys = Keys::new();
    assert_eq!(
        state.store_enrollment(&keys.files(), NOW, false).unwrap(),
        None
    );
    let loaded = StateDir::open(&root, false).unwrap().load().unwrap();
    assert_eq!(loaded.record, keys.record);
    assert_eq!(loaded.tls_key.spki_der(), keys.tls.spki_der());
    assert_eq!(loaded.host_key.key_data(), keys.host.key_data());
    assert_eq!(loaded.x509_der, b"x509");
    assert_eq!(loaded.ca_root_der, b"root");

    let path = root.join(STATE_FILE);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["extra"] = serde_json::json!(1);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(state.load(), Err(StateError::Record { .. })));

    fs::write(root.join(TLS_KEY_FILE), b"junk").unwrap();
    fs::remove_file(&path).unwrap();
    assert!(matches!(state.load(), Err(StateError::NotEnrolled { .. })));
    assert!(matches!(
        StateDir::open(&dir.path().join("missing"), false),
        Err(StateError::NotEnrolled { .. })
    ));
}

#[test]
fn an_enrollment_that_appeared_meanwhile_is_kept_without_replace() {
    let dir = tempfile::tempdir().unwrap();
    let state = prepared(dir.path());
    fs::write(dir.path().join(STATE_FILE), b"{}").unwrap();
    let failure = state
        .store_enrollment(&Keys::new().files(), NOW, false)
        .unwrap_err();
    assert!(matches!(failure.error, StateError::AlreadyEnrolled { .. }));
    assert_eq!(failure.previous, None);
    assert_eq!(fs::read(dir.path().join(STATE_FILE)).unwrap(), b"{}");
    assert_eq!(names(dir.path()), [LOCK_FILE, STATE_FILE]);
}

#[test]
fn replacing_twice_in_one_second_keeps_both_backups_and_skips_a_planted_name() {
    let dir = tempfile::tempdir().unwrap();
    let state = prepared(dir.path());
    let decoy = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(decoy.path(), dir.path().join("previous-20261118T110640Z")).unwrap();
    let first = Keys::new();
    state.store_enrollment(&first.files(), NOW, false).unwrap();
    let first_contents = contents(dir.path());
    state
        .store_enrollment(&Keys::new().files(), NOW, true)
        .unwrap();
    let second_contents = contents(dir.path());
    state
        .store_enrollment(&Keys::new().files(), NOW, true)
        .unwrap();

    assert_eq!(
        previous_dirs(dir.path()),
        [
            "previous-20261118T110640Z",
            "previous-20261118T110640Z-1",
            "previous-20261118T110640Z-2"
        ]
    );
    assert_eq!(
        contents(&dir.path().join("previous-20261118T110640Z-1")),
        first_contents
    );
    assert_eq!(
        contents(&dir.path().join("previous-20261118T110640Z-2")),
        second_contents
    );
    assert_eq!(fs::read_dir(decoy.path()).unwrap().count(), 0);
}

#[test]
fn files_take_the_directory_owner_when_privileged_for_enrollment_and_renewal() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("deep/state");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("inner-ca.pub"), b"ssh-ed25519 AAAA\n").unwrap();
    let expected = if running_as_root() {
        std::os::unix::fs::chown(&root, Some(1), Some(1)).unwrap();
        (1, 1)
    } else {
        println!(
            "not running as root: the owner is this user, so fchown is exercised but cannot change it"
        );
        let meta = fs::metadata(&root).unwrap();
        (meta.uid(), meta.gid())
    };
    let (state, lock) = StateDir::prepare_enrollment(&root, true).unwrap();
    state
        .store_enrollment(&Keys::new().files(), NOW, false)
        .unwrap();
    state
        .store_enrollment(&Keys::new().files(), NOW, true)
        .unwrap();
    drop(lock);
    let renewing = StateDir::open(&root, true).unwrap();
    renewing
        .store_renewal(
            &record(),
            b"renewed",
            "ssh-ed25519-cert-v01@openssh.com BBBB",
        )
        .unwrap();
    let previous = root.join(&previous_dirs(&root)[0]);
    let paths: Vec<PathBuf> = MANAGED_FILES
        .iter()
        .map(|name| root.join(name))
        .chain([previous.clone(), root.join(LOCK_FILE)])
        .chain(MANAGED_FILES.iter().map(|name| previous.join(name)))
        .collect();
    for path in paths {
        let meta = fs::symlink_metadata(&path).unwrap();
        assert_eq!((meta.uid(), meta.gid()), expected, "{}", path.display());
    }
    assert_eq!(fs::read(root.join("x509.der")).unwrap(), b"renewed");
}

#[test]
fn a_directory_swapped_for_a_symlink_after_preparation_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("state");
    let (state, _lock) = StateDir::prepare_enrollment(&root, false).unwrap();
    fs::write(root.join(TLS_KEY_FILE), b"leftover").unwrap();
    let moved = dir.path().join("moved");
    let decoy = dir.path().join("decoy");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &root).unwrap();

    assert!(state.holds_enrollment().is_ok_and(|held| !held));
    state
        .store_enrollment(&Keys::new().files(), NOW, true)
        .unwrap();

    assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
    assert!(moved.join(STATE_FILE).exists());
    let previous = previous_dirs(&moved);
    assert_eq!(
        fs::read(moved.join(&previous[0]).join(TLS_KEY_FILE)).unwrap(),
        b"leftover"
    );
}

#[test]
fn a_foreign_directory_is_refused_before_anything_is_written() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("notes.txt"), b"mine").unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        StateDir::prepare_enrollment(dir.path(), false),
        Err(StateError::Foreign { .. })
    ));
    assert_eq!(names(dir.path()), ["notes.txt"]);
    assert_eq!(
        fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[test]
fn as_root_the_installer_rules_refuse_system_directories_before_touching_them() {
    for path in [
        "/etc",
        "/usr/local/lib/jaunt",
        "/home/alice/jaunt",
        "/srv/jaunt",
        "/",
    ] {
        assert!(
            matches!(
                StateDir::prepare_enrollment(Path::new(path), true),
                Err(StateError::Unsafe { .. })
            ),
            "{path}"
        );
    }
}

#[test]
fn a_second_enrollment_run_on_the_same_directory_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let (_state, _lock) = StateDir::prepare_enrollment(dir.path(), false).unwrap();
    let error = StateDir::prepare_enrollment(dir.path(), false)
        .err()
        .unwrap();
    assert!(matches!(error, StateError::Busy { .. }), "{error}");
    assert!(error.to_string().contains("already running"));
}

#[test]
fn an_unwritable_directory_is_found_before_the_request() {
    if running_as_root() {
        println!("running as root: permissions do not stop root, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let read_only = dir.path().join("read-only");
    fs::create_dir(&read_only).unwrap();
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o500)).unwrap();
    let result = StateDir::prepare_enrollment(&read_only, false);
    fs::set_permissions(&read_only, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(StateError::NotWritable { .. })));
    assert!(names(&read_only).is_empty());

    let foreign = ["/var/empty", "/run/sshd"]
        .into_iter()
        .map(Path::new)
        .find(|path| {
            fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
                && fs::metadata(path)
                    .is_ok_and(|meta| meta.uid() != rustix::process::geteuid().as_raw())
        });
    match foreign {
        Some(path) => assert!(
            matches!(
                StateDir::prepare_enrollment(path, false),
                Err(StateError::NotWritable { .. })
            ),
            "{}",
            path.display()
        ),
        None => println!("no empty directory owned by another user found, skipping that case"),
    }
}

#[test]
fn the_state_directory_entries_that_count_as_ours_are_exact() {
    let pid_temp = temp_name("tls.key");
    for (name, ours) in [
        ("state.json", true),
        ("tls.key", true),
        ("inner-ca.pub", true),
        (".enroll.lock", true),
        (pid_temp.as_str(), true),
        (".write-check.42.tmp", true),
        (".ca-root.der.7.tmp", true),
        ("previous-20261118T110640Z", true),
        ("previous-20261118T110640Z-12", true),
        ("notes.txt", false),
        (".bashrc.tmp", false),
        (".tls.key.tmp", false),
        (".tls.key.x1.tmp", false),
        (".secret.42.tmp", false),
        ("previous-", false),
        ("previous-backup", false),
        ("previous-20261118T110640Z-", false),
        ("previous-20261118T110640Z-a", false),
        ("previous-20261118X110640Z", false),
        ("tls.key.bak", false),
    ] {
        assert_eq!(is_state_entry(name), ours, "{name}");
    }
}

#[test]
fn as_root_an_existing_directory_must_belong_to_root_or_come_from_the_installer() {
    for (uid, installer_layout, trusted) in [
        (0, false, true),
        (0, true, true),
        (999, true, true),
        (999, false, false),
        (1, false, false),
    ] {
        assert_eq!(
            trusted_existing_dir(uid, installer_layout),
            trusted,
            "{uid} {installer_layout}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("deep/state");
    fs::create_dir_all(&root).unwrap();
    if running_as_root() {
        std::os::unix::fs::chown(&root, Some(1), Some(1)).unwrap();
    }
    let error = StateDir::prepare_enrollment(&root, true).err().unwrap();
    assert!(
        matches!(error, StateError::UntrustedOwner { .. }),
        "{error}"
    );
    assert!(names(&root).is_empty());
    assert!(StateDir::prepare_enrollment(&root, false).is_ok());

    fs::write(root.join("inner-ca.pub"), b"ssh-ed25519 AAAA\n").unwrap();
    assert!(StateDir::prepare_enrollment(&root, true).is_ok());
}

#[test]
fn a_dangling_symlink_named_state_json_counts_as_an_enrollment() {
    let dir = tempfile::tempdir().unwrap();
    let state = prepared(dir.path());
    std::os::unix::fs::symlink("/nonexistent/state.json", dir.path().join(STATE_FILE)).unwrap();
    assert!(state.holds_enrollment().unwrap());
    let failure = state
        .store_enrollment(&Keys::new().files(), NOW, false)
        .unwrap_err();
    assert!(matches!(failure.error, StateError::AlreadyEnrolled { .. }));
}

#[test]
fn a_refused_chown_stops_moving_aside_and_renewal_before_files_change() {
    if running_as_root() {
        println!("running as root: chown to another user succeeds, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let state = prepared(dir.path());
    state
        .store_enrollment(&Keys::new().files(), NOW, false)
        .unwrap();
    let before = contents(dir.path());
    let handle = DirHandle::open(dir.path()).unwrap();
    let foreign = Owner {
        uid: effective_uid() + 1,
        gid: handle.owner().unwrap().gid,
    };
    let hostile = StateDir {
        dir: handle,
        owner: Some(foreign),
    };

    let failure = hostile
        .store_enrollment(&Keys::new().files(), NOW, true)
        .unwrap_err();
    assert!(
        matches!(&failure.error, StateError::Fs(error) if error.op == "chown"),
        "{failure}"
    );
    assert!(previous_dirs(dir.path()).is_empty());

    let error = hostile
        .store_renewal(
            &record(),
            b"renewed",
            "ssh-ed25519-cert-v01@openssh.com BBBB",
        )
        .unwrap_err();
    assert!(
        matches!(&error, StateError::Fs(error) if error.op == "chown"),
        "{error}"
    );
    assert_eq!(contents(dir.path()), before);
}
