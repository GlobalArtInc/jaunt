mod common;

use std::fs;

use common::{load_err, load_ok, write_dir};
use jaunt_policy::{Identity, NodeInfo, PolicyHandle};

fn role(name: &str, login: &str) -> String {
    format!(
        "apiVersion: jaunt/v1\nkind: Role\nmetadata: {{ name: {name} }}\nspec:\n  members: {{ users: [alice@example.com] }}\n  ssh: {{ nodes: {{ env: [prod] }}, logins: [{login}] }}\n"
    )
}

fn alice() -> Identity {
    Identity {
        email: "alice@example.com".to_owned(),
        username: "alice".to_owned(),
        groups: Vec::new(),
    }
}

fn prod() -> NodeInfo {
    NodeInfo {
        name: "web-1".to_owned(),
        labels: [("env".to_owned(), "prod".to_owned())].into(),
    }
}

#[test]
fn empty_handle_denies_everything() {
    let handle = PolicyHandle::empty();
    let snapshot = handle.snapshot();
    assert!(!snapshot.route(&alice(), &prod()));
    assert!(!snapshot.authorize_ssh(&alice(), &prod(), "deploy").allowed);
    assert_eq!(snapshot.hash(), load_ok(&[]).hash());
}

#[test]
fn invalid_reload_keeps_the_active_set() {
    let valid = role("ops", "deploy");
    let dir = write_dir(&[("roles.yaml", &valid)]);
    let handle = PolicyHandle::empty();
    let clone = handle.clone();

    let applied = handle.reload(dir.path());
    assert!(applied.applied);
    assert!(applied.errors.is_empty());
    let active_hash = applied.hash.expect("applied reload reports the hash");
    assert_eq!(clone.snapshot().hash(), active_hash);

    fs::write(dir.path().join("roles.yaml"), "kind: Nope\n").expect("overwrite policy file");
    let rejected = handle.reload(dir.path());
    assert!(!rejected.applied);
    assert_eq!(rejected.hash, None);
    assert!(
        rejected.errors[0].starts_with("roles.yaml: document 1:"),
        "{:?}",
        rejected.errors
    );
    assert_eq!(
        rejected.errors,
        load_err(&[("roles.yaml", "kind: Nope\n")]).messages()
    );

    for shared in [&handle, &clone] {
        let snapshot = shared.snapshot();
        assert_eq!(snapshot.hash(), active_hash);
        assert!(snapshot.authorize_ssh(&alice(), &prod(), "deploy").allowed);
    }

    let missing = handle.reload(&dir.path().join("missing"));
    assert!(!missing.applied);
    assert_eq!(handle.snapshot().hash(), active_hash);
}

#[test]
fn valid_reload_replaces_the_set_and_changes_the_hash() {
    let first = role("ops", "deploy");
    let dir = write_dir(&[("roles.yaml", &first)]);
    let handle = PolicyHandle::empty();
    let before = handle.snapshot();

    let one = handle.reload(dir.path());
    let held = handle.snapshot();
    fs::write(dir.path().join("roles.yaml"), role("ops", "root")).expect("rewrite policy file");
    let two = handle.reload(dir.path());

    assert!(one.applied && two.applied);
    assert_ne!(one.hash, two.hash);
    assert_eq!(two.hash.as_deref(), Some(handle.snapshot().hash()));
    assert_ne!(before.hash(), held.hash());

    let current = handle.snapshot();
    assert!(current.authorize_ssh(&alice(), &prod(), "root").allowed);
    assert!(!current.authorize_ssh(&alice(), &prod(), "deploy").allowed);
    assert!(held.authorize_ssh(&alice(), &prod(), "deploy").allowed);
    assert!(!before.authorize_ssh(&alice(), &prod(), "deploy").allowed);
}

#[test]
fn empty_directory_is_allowed_at_startup_but_never_replaces_a_non_empty_set() {
    let empty = write_dir(&[]);
    let handle = PolicyHandle::empty();
    let startup = handle.reload(empty.path());
    assert!(startup.applied, "{:?}", startup.errors);
    assert!(handle.snapshot().is_empty());

    let populated = write_dir(&[("roles.yaml", &role("ops", "deploy"))]);
    let applied = handle.reload(populated.path());
    assert!(applied.applied);
    let active_hash = applied.hash.expect("applied reload reports the hash");

    let refused = handle.reload(empty.path());
    assert!(!refused.applied);
    assert_eq!(refused.hash, None);
    assert_eq!(refused.input_hash.as_deref(), Some(load_ok(&[]).hash()));
    assert_eq!(refused.errors.len(), 1);
    assert!(refused.errors[0].contains("empty"), "{:?}", refused.errors);
    assert_eq!(handle.snapshot().hash(), active_hash);
}

#[test]
fn reloading_identical_content_is_reported_as_unchanged() {
    let dir = write_dir(&[("roles.yaml", &role("ops", "deploy"))]);
    let handle = PolicyHandle::empty();
    assert!(!handle.reload(dir.path()).unchanged);
    let again = handle.reload(dir.path());
    assert!(again.applied && again.unchanged);
}

#[cfg(unix)]
#[test]
fn a_vanished_generation_keeps_the_last_valid_set() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("create temp dir");
    let generation = dir.path().join("..gen1");
    fs::create_dir(&generation).expect("create generation dir");
    fs::write(generation.join("roles.yaml"), role("ops", "deploy")).expect("write role");
    symlink("..gen1", dir.path().join("..data")).expect("link data dir");
    symlink("..data/roles.yaml", dir.path().join("roles.yaml")).expect("link role");

    let handle = PolicyHandle::empty();
    let applied = handle.reload(dir.path());
    assert!(applied.applied, "{:?}", applied.errors);
    let active_hash = handle.snapshot().hash().to_owned();

    fs::remove_dir_all(&generation).expect("remove generation");
    let rejected = handle.reload(dir.path());
    assert!(!rejected.applied);
    assert!(!rejected.errors.is_empty());
    assert_eq!(handle.snapshot().hash(), active_hash);
    assert!(
        handle
            .snapshot()
            .authorize_ssh(&alice(), &prod(), "deploy")
            .allowed
    );
}

#[test]
fn the_load_time_moves_only_when_the_applied_content_changes() {
    use std::time::{Duration, UNIX_EPOCH};

    let at = |secs: u64| UNIX_EPOCH + Duration::from_secs(secs);
    let dir = write_dir(&[("roles.yaml", &role("ops", "deploy"))]);
    let handle = PolicyHandle::empty();
    assert_eq!(handle.loaded().loaded_at, None);

    assert!(handle.reload_at(dir.path(), at(100)).applied);
    assert_eq!(handle.loaded().loaded_at, Some(at(100)));
    assert!(handle.reload_at(dir.path(), at(200)).unchanged);
    assert_eq!(handle.loaded().loaded_at, Some(at(100)));

    fs::write(dir.path().join("roles.yaml"), "kind: Nope\n").unwrap();
    assert!(!handle.reload_at(dir.path(), at(300)).applied);
    assert_eq!(handle.loaded().loaded_at, Some(at(100)));

    fs::write(dir.path().join("roles.yaml"), role("ops", "admin")).unwrap();
    assert!(handle.reload_at(dir.path(), at(400)).applied);
    let loaded = handle.loaded();
    assert_eq!(loaded.loaded_at, Some(at(400)));
    assert_eq!(loaded.set.hash(), handle.snapshot().hash());
}
