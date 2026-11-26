use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::time::Duration;

use tempfile::TempDir;

use super::{LOCK_WAIT, STATE_FILE, StateDir, StoreError, TEMP_FILE, WriteStep};
use crate::protocol::{Reference, SessionLabel};
use crate::state::{AccountState, State};
use crate::testing::{
    FakeClock, FakeUsers, NOW, candidate, enabled_config, name, record, state_of, verified,
};

fn owner_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().uid()
}

fn private_dir() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), Permissions::from_mode(0o700)).unwrap();
    dir
}

fn open(path: &Path) -> StateDir {
    StateDir::open(path, owner_of(path)).unwrap()
}

fn load(path: &Path) -> State {
    let dir = open(path);
    let lock = dir.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    lock.load().unwrap()
}

fn copy_files(from: &Path, to: &Path) {
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

fn with_pending_bob(old: &State) -> State {
    let mut new = old.clone();
    let config = enabled_config("");
    new.begin(
        &candidate(&config, "bob"),
        &Reference::parse("H-000000B0").unwrap(),
        &SessionLabel::parse("s-2").unwrap(),
        NOW,
    )
    .unwrap();
    new.bind(&verified(&config, &candidate(&config, "bob"), 30_002))
        .unwrap();
    new
}

#[test]
fn the_state_directory_must_be_a_private_real_directory_of_the_owner() {
    let dir = private_dir();
    let owner = owner_of(dir.path());
    assert_eq!(
        StateDir::open(dir.path(), owner).unwrap().path(),
        dir.path()
    );
    assert!(matches!(
        StateDir::open(dir.path(), owner.wrapping_add(1)),
        Err(StoreError::Untrusted { .. })
    ));

    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("link");
    symlink(dir.path(), &link).unwrap();
    assert!(matches!(
        StateDir::open(&link, owner),
        Err(StoreError::NotDirectory { .. })
    ));
    let file = parent.path().join("file");
    fs::write(&file, b"").unwrap();
    assert!(matches!(
        StateDir::open(&file, owner),
        Err(StoreError::NotDirectory { .. })
    ));
    assert!(matches!(
        StateDir::open(&parent.path().join("missing"), owner),
        Err(StoreError::Io { .. })
    ));

    for mode in [0o750, 0o701, 0o710] {
        fs::set_permissions(dir.path(), Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(
                StateDir::open(dir.path(), owner),
                Err(StoreError::Untrusted { .. })
            ),
            "{mode:o}"
        );
    }
}

#[test]
fn a_missing_state_is_empty_and_a_saved_state_reads_back() {
    let dir = private_dir();
    assert_eq!(load(dir.path()), State::default());

    let state = state_of(vec![record("alice", Some(30_001), "active")], &[NOW]);
    {
        let handle = open(dir.path());
        let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
        lock.save(&state).unwrap();
    }
    assert_eq!(load(dir.path()), state);
    let meta = fs::metadata(dir.path().join(STATE_FILE)).unwrap();
    assert_eq!(meta.mode() & 0o077, 0);
    assert!(!dir.path().join(TEMP_FILE).exists());
}

#[test]
fn a_crash_at_every_step_of_the_write_leaves_the_old_or_the_new_state() {
    let dir = private_dir();
    let old = state_of(vec![record("alice", Some(30_001), "active")], &[NOW - 100]);
    let new = with_pending_bob(&old);
    let handle = open(dir.path());
    let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    lock.save(&old).unwrap();

    let mut snapshots = Vec::new();
    lock.save_observed(&new, &mut |step| {
        let copy = private_dir();
        copy_files(dir.path(), copy.path());
        snapshots.push((step, copy));
    })
    .unwrap();
    drop(lock);
    let steps: Vec<WriteStep> = snapshots.iter().map(|(step, _)| *step).collect();
    assert_eq!(
        steps,
        [
            WriteStep::TempCreated,
            WriteStep::TempWritten,
            WriteStep::TempSynced,
            WriteStep::Renamed,
            WriteStep::DirectorySynced,
        ]
    );

    let bob_exists = FakeUsers::default()
        .with_account("alice", 30_001)
        .with_account("bob", 30_002);
    let bob_missing = FakeUsers::default().with_account("alice", 30_001);
    for (step, copy) in &snapshots {
        let renamed = matches!(step, WriteStep::Renamed | WriteStep::DirectorySynced);
        let loaded = load(copy.path());
        assert_eq!(&loaded, if renamed { &new } else { &old }, "{step:?}");

        for (users, bob_after) in [
            (&bob_exists, Some(AccountState::Unconfirmed)),
            (&bob_missing, None),
        ] {
            let mut state = loaded.clone();
            state.reconcile(users, NOW).unwrap();
            let bob = state.record(&name("bob")).map(|record| record.state());
            assert_eq!(bob, if renamed { bob_after } else { None }, "{step:?}");
            assert_eq!(
                state.record(&name("alice")).map(|record| record.state()),
                Some(AccountState::Active)
            );

            let rewrite = private_dir();
            copy_files(copy.path(), rewrite.path());
            let handle = open(rewrite.path());
            let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
            lock.save(&state).unwrap();
            assert_eq!(lock.load().unwrap(), state, "{step:?}");
            assert!(!rewrite.path().join(TEMP_FILE).exists(), "{step:?}");
        }
    }
}

#[test]
fn the_lock_is_exclusive_and_the_wait_is_bounded_by_the_caller() {
    let dir = private_dir();
    let first = open(dir.path());
    let held = first.lock(&FakeClock::started(), LOCK_WAIT).unwrap();

    let second = open(dir.path());
    let clock = FakeClock::started();
    assert!(matches!(
        second.lock(&clock, LOCK_WAIT),
        Err(StoreError::Busy)
    ));
    assert_eq!(clock.elapsed(), LOCK_WAIT);
    assert!(clock.sleeps() > 1);

    let impatient = FakeClock::started();
    assert!(matches!(
        second.lock(&impatient, Duration::ZERO),
        Err(StoreError::Busy)
    ));
    assert_eq!(impatient.sleeps(), 0);

    drop(held);
    let free = FakeClock::started();
    let lock = second.lock(&free, LOCK_WAIT).unwrap();
    assert_eq!(free.elapsed(), Duration::ZERO);
    assert_eq!(lock.load().unwrap(), State::default());
}

#[test]
fn the_state_file_must_be_a_plain_single_file_and_errors_never_show_its_content() {
    let dir = private_dir();
    let handle = open(dir.path());
    let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    let state_path = dir.path().join(STATE_FILE);

    fs::write(&state_path, b"{\"secret-content\": ").unwrap();
    let error = lock.load().unwrap_err();
    assert!(matches!(error, StoreError::State { .. }), "{error}");
    assert!(!error.to_string().contains("secret-content"), "{error}");

    let elsewhere = dir.path().join("elsewhere.json");
    fs::write(&elsewhere, b"{\"v\":1,\"accounts\":[],\"attempts\":[]}").unwrap();
    fs::remove_file(&state_path).unwrap();
    fs::hard_link(&elsewhere, &state_path).unwrap();
    assert!(matches!(lock.load(), Err(StoreError::NotRegular { .. })));

    fs::remove_file(&state_path).unwrap();
    symlink(&elsewhere, &state_path).unwrap();
    assert!(matches!(lock.load(), Err(StoreError::Io { .. })));
}

struct UmaskGuard(rustix::fs::Mode);

impl UmaskGuard {
    fn open_wide() -> Self {
        Self(rustix::process::umask(rustix::fs::Mode::empty()))
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        rustix::process::umask(self.0);
    }
}

#[test]
fn the_temporary_and_the_final_state_file_stay_private_even_with_an_open_umask() {
    let dir = private_dir();
    let handle = open(dir.path());
    let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    let state = state_of(vec![record("alice", Some(30_001), "active")], &[NOW]);
    let mut temp_modes = Vec::new();
    {
        let _wide = UmaskGuard::open_wide();
        lock.save_observed(&state, &mut |step| {
            if step == WriteStep::TempSynced {
                let meta = fs::symlink_metadata(dir.path().join(TEMP_FILE)).unwrap();
                temp_modes.push(meta.mode() & 0o7777);
            }
        })
        .unwrap();
    }
    assert_eq!(temp_modes, [0o600]);
    let meta = fs::metadata(dir.path().join(STATE_FILE)).unwrap();
    assert_eq!(meta.mode() & 0o7777, 0o600);
    let lock_meta = fs::metadata(dir.path().join("lock")).unwrap();
    assert_eq!(lock_meta.mode() & 0o077, 0);
}

#[test]
fn a_symbolic_link_in_place_of_the_lock_or_the_temporary_file_is_never_followed() {
    let dir = private_dir();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();

    symlink(&victim, dir.path().join("lock")).unwrap();
    let handle = open(dir.path());
    assert!(matches!(
        handle.lock(&FakeClock::started(), LOCK_WAIT),
        Err(StoreError::Io { .. })
    ));
    fs::remove_file(dir.path().join("lock")).unwrap();

    symlink(&victim, dir.path().join(TEMP_FILE)).unwrap();
    let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    let state = state_of(vec![record("alice", Some(30_001), "active")], &[]);
    lock.save(&state).unwrap();
    assert_eq!(lock.load().unwrap(), state);
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert!(!dir.path().join(TEMP_FILE).exists());
}

#[test]
fn an_unreadable_state_file_is_an_error_and_never_an_empty_state() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    let dir = private_dir();
    let handle = open(dir.path());
    let lock = handle.lock(&FakeClock::started(), LOCK_WAIT).unwrap();
    lock.save(&state_of(
        vec![record("alice", Some(30_001), "active")],
        &[],
    ))
    .unwrap();
    let path = dir.path().join(STATE_FILE);
    fs::set_permissions(&path, Permissions::from_mode(0o000)).unwrap();
    let result = lock.load();
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(result, Err(StoreError::Io { .. })), "{result:?}");
}
