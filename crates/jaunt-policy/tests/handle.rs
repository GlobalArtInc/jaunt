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
