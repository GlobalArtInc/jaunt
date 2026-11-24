use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use rustix::fs::Mode;

use super::{DirError, DirHandle, Owner, effective_uid, normalize, running_as_root, temp_name};

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn fresh() -> (tempfile::TempDir, DirHandle) {
    let dir = tempfile::tempdir().unwrap();
    let (handle, _) = DirHandle::create_or_open(dir.path()).unwrap();
    (dir, handle)
}

fn foreign_owner(handle: &DirHandle) -> Option<Owner> {
    if running_as_root() {
        println!("running as root: chown to another user succeeds, skipping the refusal check");
        return None;
    }
    Some(Owner {
        uid: effective_uid() + 1,
        gid: handle.owner().unwrap().gid,
    })
}

#[test]
fn private_writes_replace_content_with_mode_0600_and_leave_no_temp_file() {
    let dir = tempfile::tempdir().unwrap();
    let (state, created) = DirHandle::create_or_open(&dir.path().join("a/state")).unwrap();
    assert!(created);
    assert_eq!(mode_of(state.path()), 0o700);
    state.write_private("tls.key", b"first", None).unwrap();
    let own = state.owner().unwrap();
    state
        .write_private("tls.key", b"second", Some(own))
        .unwrap();
    let path = state.path().join("tls.key");
    assert_eq!(fs::read(&path).unwrap(), b"second");
    assert_eq!(mode_of(&path), 0o600);
    let meta = fs::metadata(&path).unwrap();
    assert_eq!((meta.uid(), meta.gid()), (own.uid, own.gid));
    assert_eq!(state.entries().unwrap(), ["tls.key"]);
    assert_eq!(&*state.read("tls.key").unwrap(), b"second");
}

#[test]
fn a_stale_regular_file_at_the_temp_name_does_not_block_a_write() {
    let (dir, state) = fresh();
    fs::write(dir.path().join(temp_name("tls.key")), b"stale").unwrap();
    state.write_private("tls.key", b"fresh", None).unwrap();
    assert_eq!(fs::read(dir.path().join("tls.key")).unwrap(), b"fresh");
    assert_eq!(state.entries().unwrap(), ["tls.key"]);
}

#[test]
fn blocked_temp_or_target_names_fail_the_write_and_leave_no_temp_file() {
    let (dir, state) = fresh();
    let blocker = dir.path().join(temp_name("ca-root.der"));
    fs::create_dir(&blocker).unwrap();
    fs::write(blocker.join("keep"), b"x").unwrap();
    assert!(state.write_private("ca-root.der", b"root", None).is_err());
    assert!(!dir.path().join("ca-root.der").exists());

    let (dir, state) = fresh();
    let target = dir.path().join("x509.der");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("keep"), b"x").unwrap();
    assert!(state.write_private("x509.der", b"cert", None).is_err());
    assert_eq!(state.entries().unwrap(), ["x509.der"]);
}

#[test]
fn symlinks_are_refused_even_with_a_trailing_slash() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let with_slash = PathBuf::from(format!("{}/", link.display()));
    for path in [&link, &with_slash] {
        assert!(
            matches!(DirHandle::open(path), Err(DirError::Symlink { .. })),
            "{}",
            path.display()
        );
        assert!(matches!(
            DirHandle::create_or_open(path),
            Err(DirError::Symlink { .. })
        ));
    }
    assert!(matches!(
        DirHandle::open_nofollow(link.clone()),
        Err(DirError::Symlink { .. })
    ));
    let file = dir.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(matches!(
        DirHandle::open(&file),
        Err(DirError::NotDirectory { .. })
    ));
    assert!(matches!(
        DirHandle::open(&dir.path().join("missing")),
        Err(DirError::Missing { .. })
    ));
    assert_eq!(normalize(Path::new("/a//b/./c/")), Path::new("/a/b/c"));
}

#[test]
fn symlinks_fifos_and_hard_links_inside_the_directory_are_refused() {
    let (dir, state) = fresh();
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("secret");
    fs::write(&secret, b"secret").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
    std::os::unix::fs::symlink(&secret, dir.path().join("state.json")).unwrap();
    std::os::unix::fs::symlink(&secret, dir.path().join(".enroll.lock")).unwrap();
    assert!(state.read("state.json").is_err());
    assert!(state.lock(".enroll.lock", None).is_err());

    let (dir, state) = fresh();
    let status = Command::new("mkfifo")
        .arg(dir.path().join("state.json"))
        .arg(dir.path().join(".enroll.lock"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(state.read("state.json").is_err());
    assert!(state.lock(".enroll.lock", None).is_err());

    let (dir, state) = fresh();
    let target = dir.path().join("target");
    fs::write(&target, b"x").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    fs::hard_link(&target, dir.path().join(".enroll.lock")).unwrap();
    let error = state.lock(".enroll.lock", None).unwrap_err();
    assert!(error.to_string().contains("hard link"), "{error}");
    assert_eq!(mode_of(&target), 0o644);
    assert_eq!(fs::metadata(&target).unwrap().uid(), effective_uid());
    assert_eq!(mode_of(&secret), 0o644);
}

#[test]
fn names_that_are_not_plain_file_names_are_refused() {
    let (_dir, state) = fresh();
    for name in ["", ".", "..", "../secret", "/etc/passwd", "a/b", "a\0b"] {
        assert_eq!(state.read(name).unwrap_err().op, "name", "{name:?}");
        assert_eq!(state.exists(name).unwrap_err().op, "name", "{name:?}");
        assert_eq!(
            state.write_private(name, b"x", None).unwrap_err().op,
            "name",
            "{name:?}"
        );
        assert_eq!(state.lock(name, None).unwrap_err().op, "name");
        assert_eq!(state.create_private_dir(name, None).unwrap_err().op, "name");
    }
    assert!(state.entries().unwrap().is_empty());
}

#[test]
fn exclusive_creation_refuses_an_existing_name() {
    let (_dir, state) = fresh();
    drop(state.create_exclusive("taken").unwrap());
    assert!(state.create_exclusive("taken").is_err());
}

#[test]
fn a_chown_that_the_kernel_refuses_fails_each_operation_and_leaves_nothing_half_done() {
    let (_dir, state) = fresh();
    let Some(foreign) = foreign_owner(&state) else {
        return;
    };
    assert_eq!(
        state
            .write_private("tls.key", b"key", Some(foreign))
            .unwrap_err()
            .op,
        "chown"
    );
    assert_eq!(
        state
            .create_private_dir("previous-x", Some(foreign))
            .unwrap_err()
            .op,
        "chown"
    );
    assert!(state.entries().unwrap().is_empty());
    assert_eq!(
        state.lock(".enroll.lock", Some(foreign)).unwrap_err().op,
        "chown"
    );
}

#[test]
fn a_handle_keeps_pointing_at_its_directory_after_the_path_is_swapped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state");
    let (state, _) = DirHandle::create_or_open(&path).unwrap();
    let moved = dir.path().join("moved");
    let decoy = dir.path().join("decoy");
    fs::rename(&path, &moved).unwrap();
    fs::create_dir(&decoy).unwrap();
    std::os::unix::fs::symlink(&decoy, &path).unwrap();

    state.write_private("tls.key", b"key", None).unwrap();
    let previous = state
        .create_private_dir("previous-x", None)
        .unwrap()
        .unwrap();
    state.move_into("tls.key", &previous).unwrap();

    assert_eq!(fs::read(moved.join("previous-x/tls.key")).unwrap(), b"key");
    assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
}

#[test]
fn only_group_and_other_bits_are_removed_and_the_probe_finds_unwritable_directories() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _) = DirHandle::create_or_open(&dir.path().join("state")).unwrap();
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o755)).unwrap();
    state.remove_group_and_other_access().unwrap();
    assert_eq!(mode_of(state.path()), 0o700);
    state.probe_writable().unwrap();
    assert!(state.entries().unwrap().is_empty());

    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o500)).unwrap();
    state.remove_group_and_other_access().unwrap();
    assert_eq!(mode_of(state.path()), 0o500);
    if running_as_root() {
        println!("running as root: a read-only mode does not stop root, skipping the probe check");
    } else {
        assert!(state.probe_writable().is_err());
    }
    fs::set_permissions(state.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn a_second_lock_on_the_same_directory_is_refused_until_the_first_is_released() {
    let dir = tempfile::tempdir().unwrap();
    let (first, _) = DirHandle::create_or_open(dir.path()).unwrap();
    let (second, _) = DirHandle::create_or_open(dir.path()).unwrap();
    let held = first.lock(".enroll.lock", None).unwrap();
    assert!(held.is_some());
    assert!(second.lock(".enroll.lock", None).unwrap().is_none());
    drop(held);
    assert!(second.lock(".enroll.lock", None).unwrap().is_some());
    assert_eq!(mode_of(&dir.path().join(".enroll.lock")), 0o600);
}

const UMASK_CHILD: &str = "JAUNT_AGENT_UMASK_CHILD";

#[test]
fn modes_do_not_depend_on_the_umask() {
    if std::env::var_os(UMASK_CHILD).is_some() {
        return;
    }
    for case in ["strict", "open"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "fsio::tests::umask_child",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(UMASK_CHILD, case)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{case}: {stdout}");
        assert!(stdout.contains("umask child checked"), "{case}: {stdout}");
    }
}

#[test]
fn umask_child() {
    let Some(case) = std::env::var_os(UMASK_CHILD) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("tls.key"), b"x").unwrap();
    fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
    let mask = if case == "strict" {
        Mode::WUSR | Mode::RWXG | Mode::RWXO
    } else {
        Mode::empty()
    };
    rustix::process::umask(mask);

    let (state, created) = DirHandle::create_or_open(&dir.path().join("state")).unwrap();
    assert!(created);
    assert_eq!(mode_of(state.path()), 0o700);
    state.write_private("tls.key", b"key", None).unwrap();
    assert_eq!(mode_of(&state.path().join("tls.key")), 0o600);
    let lock = state.lock(".enroll.lock", None).unwrap();
    assert!(lock.is_some());
    assert_eq!(mode_of(&state.path().join(".enroll.lock")), 0o600);
    state
        .create_private_dir("previous-x", None)
        .unwrap()
        .unwrap();
    assert_eq!(mode_of(&state.path().join("previous-x")), 0o700);

    let (_state, _lock) = crate::state::StateDir::prepare_enrollment(&existing, false).unwrap();
    assert_eq!(mode_of(&existing), 0o700);
    println!("umask child checked");
}
