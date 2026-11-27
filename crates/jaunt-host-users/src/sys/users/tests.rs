use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use super::{LOOKUP_BUDGET, LOOKUP_TIMEOUT, SystemUsers};
use crate::system::{GroupEntry, LookupError, PasswdEntry, Users};
use crate::testing::name;

const ALICE: &str = "alice:x:30000:30001:jaunt:/home/alice:/bin/bash";
const BOB: &str = "bob:x:30002:30002:jaunt:/home/bob:/bin/sh";

fn getent(dir: &TempDir, label: &str, body: &str) -> SystemUsers {
    getent_within(dir, label, body, Duration::from_secs(20))
}

fn getent_within(dir: &TempDir, label: &str, body: &str, timeout: Duration) -> SystemUsers {
    let path = dir.path().join(label);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
    SystemUsers::with_limits(path, timeout, Duration::from_secs(60))
}

fn database_getent(dir: &TempDir) -> (SystemUsers, PathBuf) {
    let root = dir.path();
    fs::write(root.join("passwd"), format!("{ALICE}\n{BOB}\n")).unwrap();
    fs::write(root.join("group"), "devs:x:30500:alice,bob\n").unwrap();
    let args = root.join("args");
    let body = format!(
        concat!(
            "printf '%s\\n' \"$@\" > '{args}'\n",
            "db=$1; shift; [ \"$1\" = -- ] && shift; rc=0\n",
            "for key in \"$@\"; do\n",
            "  grep \"^$key:\" '{root}'/\"$db\" || rc=2\n",
            "done\n",
            "exit $rc",
        ),
        args = args.display(),
        root = root.display(),
    );
    (getent(dir, "getent", &body), args)
}

fn args_of(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn alice() -> PasswdEntry {
    PasswdEntry {
        name: name("alice"),
        uid: 30_000,
        gid: 30_001,
        home: "/home/alice".to_owned(),
        shell: "/bin/bash".to_owned(),
    }
}

#[test]
fn lookups_run_a_fixed_argv_and_exit_two_means_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let (users, args) = database_getent(&dir);
    assert_eq!(
        (LOOKUP_TIMEOUT, LOOKUP_BUDGET),
        (Duration::from_secs(1), Duration::from_secs(1))
    );

    assert_eq!(users.passwd(&name("alice")).unwrap(), Some(alice()));
    assert_eq!(args_of(&args), ["passwd", "--", "alice"]);
    assert_eq!(users.passwd(&name("carol")).unwrap(), None);
    assert_eq!(
        users.group(&name("devs")).unwrap(),
        Some(GroupEntry {
            name: name("devs"),
            gid: 30_500
        })
    );
    assert_eq!(args_of(&args), ["group", "--", "devs"]);
    assert_eq!(users.group(&name("ops")).unwrap(), None);

    let many = users
        .passwd_many(&[name("alice"), name("carol"), name("bob")])
        .unwrap();
    assert_eq!(args_of(&args), ["passwd", "--", "alice", "carol", "bob"]);
    assert_eq!(many.len(), 3);
    assert_eq!(many[0], Some(alice()));
    assert_eq!(many[1], None);
    assert_eq!(many[2].as_ref().map(|entry| entry.uid), Some(30_002));

    fs::remove_file(&args).unwrap();
    assert_eq!(users.passwd_many(&[]).unwrap(), Vec::new());
    assert!(
        !args.exists(),
        "an empty batch must not enumerate the database"
    );
}

#[test]
fn any_entry_that_is_not_exactly_the_one_asked_for_is_malformed() {
    let dir = tempfile::tempdir().unwrap();
    for (index, body) in [
        "echo 'alice:x:30000:30001::/home/alice'".to_owned(),
        "echo 'alice:x:+5:30001::/home/alice:/bin/bash'".to_owned(),
        "echo 'alice:x:30000:99999999999::/home/alice:/bin/bash'".to_owned(),
        "echo 'Alice:x:30000:30001::/home/alice:/bin/bash'".to_owned(),
        format!("echo '{BOB}'"),
        format!("printf '%s' '{ALICE}'"),
        format!("echo '{ALICE}'; echo '{ALICE}'"),
        "echo; exit 0".to_owned(),
        format!("echo '{ALICE}'; exit 2"),
        "printf 'alice:x:30000:30001::/home/\\377:/bin/sh\\n'".to_owned(),
    ]
    .iter()
    .enumerate()
    {
        let users = getent(&dir, &format!("getent-{index}"), body);
        let result = users.passwd(&name("alice"));
        assert!(
            matches!(result, Err(LookupError::Malformed { database: "passwd" })),
            "{body}: {result:?}"
        );
    }

    let logins = [name("alice"), name("bob")];
    for (index, body) in [
        format!("echo '{ALICE}'"),
        format!("echo '{ALICE}'; echo '{BOB}'; exit 2"),
        format!("echo '{BOB}'; echo '{ALICE}'; exit 2"),
        format!("echo '{ALICE}'; echo '{BOB}'; echo '{BOB}'"),
    ]
    .iter()
    .enumerate()
    {
        let users = getent(&dir, &format!("many-{index}"), body);
        let result = users.passwd_many(&logins);
        assert!(
            matches!(result, Err(LookupError::Malformed { .. })),
            "{body}: {result:?}"
        );
    }
}

#[test]
fn other_exit_codes_timeouts_and_a_missing_program_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let failing = getent(&dir, "failing", "exit 1");
    assert!(matches!(
        failing.group(&name("devs")),
        Err(LookupError::Exit {
            database: "group",
            exit_code: Some(1)
        })
    ));
    let hanging = getent_within(&dir, "hanging", "sleep 30", Duration::from_millis(500));
    assert!(matches!(
        hanging.passwd(&name("alice")),
        Err(LookupError::Exit {
            exit_code: None,
            ..
        })
    ));
    let missing = SystemUsers::new(dir.path().join("absent"));
    assert!(matches!(
        missing.passwd(&name("alice")),
        Err(LookupError::Run { .. })
    ));
}

#[test]
fn all_lookups_of_one_request_share_one_time_budget() {
    let dir = tempfile::tempdir().unwrap();
    let args = dir.path().join("args");
    let path = dir.path().join("slow-getent");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\necho \"$@\" > '{}'\nsleep 1\nexit 2\n",
            args.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o755)).unwrap();
    let users = SystemUsers::with_limits(path, Duration::from_secs(5), Duration::from_millis(1500));

    assert_eq!(users.passwd(&name("alice")).unwrap(), None);
    assert!(matches!(
        users.passwd(&name("bob")),
        Err(LookupError::Exit {
            exit_code: None,
            ..
        })
    ));
    fs::remove_file(&args).unwrap();
    assert!(matches!(
        users.group(&name("devs")),
        Err(LookupError::Exit {
            exit_code: None,
            ..
        })
    ));
    assert!(!args.exists(), "a spent budget must not start getent again");
}
