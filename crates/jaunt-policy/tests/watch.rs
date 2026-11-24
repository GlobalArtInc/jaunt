use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jaunt_policy::{Identity, NodeInfo, PolicyHandle, ReloadOutcome, watch};

const TICK: Duration = Duration::from_millis(20);
const DEADLINE: Duration = Duration::from_secs(5);
const QUIET_TICKS: u32 = 15;

fn role(login: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: ops }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{login}] }}\n"
    )
}

fn allows(handle: &PolicyHandle, login: &str) -> bool {
    let alice = Identity {
        email: "alice@example.com".to_owned(),
        username: "alice".to_owned(),
        groups: Vec::new(),
    };
    let node = NodeInfo {
        name: "web-1".to_owned(),
        labels: [("env".to_owned(), "prod".to_owned())].into(),
    };
    handle
        .snapshot()
        .authorize_ssh(&alice, &node, login)
        .allowed
}

fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < DEADLINE, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn settle() {
    std::thread::sleep(TICK * QUIET_TICKS);
}

type Outcomes = Arc<Mutex<Vec<ReloadOutcome>>>;

fn recorder() -> (Outcomes, impl Fn(&ReloadOutcome) + Send + 'static) {
    let outcomes: Outcomes = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&outcomes);
    (outcomes, move |outcome: &ReloadOutcome| {
        sink.lock().expect("lock outcomes").push(outcome.clone());
    })
}

fn applied_count(outcomes: &Outcomes) -> usize {
    outcomes
        .lock()
        .expect("lock outcomes")
        .iter()
        .filter(|outcome| outcome.applied)
        .count()
}

fn rejected_count(outcomes: &Outcomes) -> usize {
    outcomes
        .lock()
        .expect("lock outcomes")
        .iter()
        .filter(|outcome| !outcome.applied)
        .count()
}

fn overwrite(dir: &Path, name: &str, content: &str) {
    let temporary = dir.join(format!("{name}.tmp"));
    fs::write(&temporary, content).expect("write temporary file");
    fs::rename(&temporary, dir.join(name)).expect("replace file");
}

#[test]
fn an_edited_file_is_applied() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);

    wait_until("the initial load", || allows(&handle, "deploy"));
    overwrite(dir.path(), "role.yaml", &role("root"));
    wait_until("the edit", || allows(&handle, "root"));

    assert!(!allows(&handle, "deploy"));
    settle();
    watcher.stop();
    assert_eq!(applied_count(&outcomes), 2);
    assert_eq!(rejected_count(&outcomes), 0);
}

#[test]
fn an_invalid_edit_is_reported_once_and_never_applied() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);
    wait_until("the initial load", || allows(&handle, "deploy"));
    let active_hash = handle.snapshot().hash().to_owned();

    overwrite(dir.path(), "role.yaml", "kind: Nope\n");
    wait_until("the rejection report", || rejected_count(&outcomes) == 1);
    settle();
    assert_eq!(rejected_count(&outcomes), 1);
    assert!(allows(&handle, "deploy"));
    assert_eq!(handle.snapshot().hash(), active_hash);
    {
        let seen = outcomes.lock().expect("lock outcomes");
        let rejected = seen
            .iter()
            .find(|outcome| !outcome.applied)
            .expect("rejection");
        assert!(!rejected.errors.is_empty());
        assert_eq!(rejected.hash, None);
    }

    overwrite(dir.path(), "role.yaml", &role("root"));
    wait_until("the valid edit", || allows(&handle, "root"));
    watcher.stop();
    assert_eq!(applied_count(&outcomes), 2);
    assert_eq!(rejected_count(&outcomes), 1);
}

#[test]
fn a_different_invalid_edit_is_reported_again() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);
    wait_until("the initial load", || allows(&handle, "deploy"));

    overwrite(dir.path(), "role.yaml", "kind: Nope\n");
    wait_until("the first rejection", || rejected_count(&outcomes) == 1);
    overwrite(dir.path(), "role.yaml", "kind: Other\n");
    wait_until("the second rejection", || rejected_count(&outcomes) == 2);
    watcher.stop();
    assert!(allows(&handle, "deploy"));
}

#[cfg(unix)]
#[test]
fn a_config_map_generation_swap_is_applied_atomically() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("create temp dir");
    let first = dir.path().join("..2026_01_01");
    fs::create_dir(&first).expect("create first generation");
    fs::write(first.join("role.yaml"), role("deploy")).expect("write first role");
    symlink("..2026_01_01", dir.path().join("..data")).expect("link data");
    symlink("..data/role.yaml", dir.path().join("role.yaml")).expect("link role");

    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);
    wait_until("the first generation", || allows(&handle, "deploy"));

    let second = dir.path().join("..2026_01_02");
    fs::create_dir(&second).expect("create second generation");
    fs::write(second.join("role.yaml"), role("root")).expect("write second role");
    fs::write(
        second.join("extra.yaml"),
        "apiVersion: jaunt/v1\nkind: AccessTest\nspec: []\n",
    )
    .expect("write added key");
    symlink("..data/extra.yaml", dir.path().join("extra.yaml")).expect("link added key early");
    symlink("..2026_01_02", dir.path().join("..data_tmp")).expect("link temporary data");
    settle();
    assert!(allows(&handle, "deploy"));
    assert_eq!(rejected_count(&outcomes), 0);
    fs::rename(dir.path().join("..data_tmp"), dir.path().join("..data")).expect("swap data link");
    fs::remove_dir_all(&first).expect("remove first generation");

    wait_until("the second generation", || allows(&handle, "root"));
    assert!(!allows(&handle, "deploy"));
    watcher.stop();
    assert_eq!(applied_count(&outcomes), 2);
    assert_eq!(rejected_count(&outcomes), 0);
}

#[test]
fn stopping_is_prompt_and_joins_the_thread() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let watcher = watch(
        handle.clone(),
        dir.path().to_path_buf(),
        Duration::from_secs(3600),
        move |_: &ReloadOutcome| {
            counter.fetch_add(1, Ordering::SeqCst);
        },
    );
    wait_until("the immediate load", || allows(&handle, "deploy"));

    let started = Instant::now();
    watcher.stop();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(Arc::strong_count(&calls), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let dropped = watch(
        handle,
        dir.path().to_path_buf(),
        Duration::from_secs(3600),
        |_: &ReloadOutcome| {},
    );
    let started = Instant::now();
    drop(dropped);
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_panicking_callback_does_not_stop_the_watcher() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let watcher = watch(
        handle.clone(),
        dir.path().to_path_buf(),
        TICK,
        move |_: &ReloadOutcome| {
            counter.fetch_add(1, Ordering::SeqCst);
            panic!("callback failure");
        },
    );
    wait_until("the first call", || calls.load(Ordering::SeqCst) == 1);

    overwrite(dir.path(), "role.yaml", &role("root"));
    wait_until("the edit after the panic", || allows(&handle, "root"));
    wait_until("the second call", || calls.load(Ordering::SeqCst) == 2);
    watcher.stop();
}

#[test]
fn the_first_outcome_is_reported_even_for_an_empty_directory() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle, dir.path().to_path_buf(), TICK, callback);
    wait_until("the first report", || applied_count(&outcomes) == 1);
    settle();
    watcher.stop();
    let seen = outcomes.lock().expect("lock outcomes");
    assert_eq!(seen.len(), 1);
    assert!(seen[0].unchanged);
}

#[test]
fn rejecting_the_same_content_again_after_a_valid_set_is_reported_again() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);
    wait_until("the initial load", || allows(&handle, "deploy"));

    overwrite(dir.path(), "role.yaml", "kind: Nope\n");
    wait_until("the first rejection", || rejected_count(&outcomes) == 1);
    overwrite(dir.path(), "role.yaml", &role("root"));
    wait_until("the valid set", || allows(&handle, "root"));
    overwrite(dir.path(), "role.yaml", "kind: Nope\n");
    wait_until("the second rejection", || rejected_count(&outcomes) == 2);
    watcher.stop();
    assert!(allows(&handle, "root"));
}

#[test]
fn recovery_to_the_previously_active_content_is_reported_once() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let (outcomes, callback) = recorder();
    let watcher = watch(handle.clone(), dir.path().to_path_buf(), TICK, callback);
    wait_until("the initial load", || allows(&handle, "deploy"));

    overwrite(dir.path(), "role.yaml", "kind: Nope\n");
    wait_until("the rejection", || rejected_count(&outcomes) == 1);
    overwrite(dir.path(), "role.yaml", &role("deploy"));
    wait_until("the recovery report", || applied_count(&outcomes) == 2);
    settle();
    watcher.stop();
    assert_eq!(applied_count(&outcomes), 2);
    assert_eq!(rejected_count(&outcomes), 1);
}

#[test]
fn a_zero_interval_is_clamped_and_the_watcher_still_stops_promptly() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("role.yaml"), role("deploy")).expect("write role");
    let handle = PolicyHandle::empty();
    let watcher = watch(
        handle.clone(),
        dir.path().to_path_buf(),
        Duration::ZERO,
        |_: &ReloadOutcome| {},
    );
    wait_until("the load", || allows(&handle, "deploy"));
    overwrite(dir.path(), "role.yaml", &role("root"));
    wait_until("the edit", || allows(&handle, "root"));
    let started = Instant::now();
    watcher.stop();
    assert!(started.elapsed() < Duration::from_secs(1));
}
