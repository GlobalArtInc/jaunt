use std::fs::{self, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use super::{
    MAX_SYSTEM_FILE_BYTES, SystemFiles, open_trusted_config, read_limited, read_system_file,
};
use crate::config::{ConfigError, TrustProblem};
use crate::system::{FileFacts, FileKind, Files};
use crate::testing::within;

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn with_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

#[test]
fn lstat_reports_kind_owner_and_mode_without_following_links() {
    let dir = tempfile::tempdir().unwrap();
    let me = fs::metadata(dir.path()).unwrap().uid();
    let file = dir.path().join("file");
    let sub = dir.path().join("sub");
    let link = dir.path().join("link");
    fs::write(&file, "x").unwrap();
    with_mode(&file, 0o640);
    fs::create_dir(&sub).unwrap();
    with_mode(&sub, 0o750);
    symlink(&file, &link).unwrap();

    let facts = |kind, mode| {
        Some(FileFacts {
            kind,
            uid: me,
            mode,
        })
    };
    assert_eq!(
        SystemFiles.lstat(&file).unwrap(),
        facts(FileKind::Regular, 0o640)
    );
    assert_eq!(
        SystemFiles.lstat(&sub).unwrap(),
        facts(FileKind::Directory, 0o750)
    );
    assert_eq!(
        SystemFiles.lstat(&link).unwrap().map(|facts| facts.kind),
        Some(FileKind::Symlink)
    );
    assert_eq!(
        SystemFiles.lstat(&dir.path().join("missing")).unwrap(),
        None
    );
}

#[test]
fn the_home_mode_is_set_through_a_descriptor_only_on_a_real_directory_of_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let me = fs::metadata(dir.path()).unwrap().uid();
    let home = dir.path().join("home");
    let elsewhere = dir.path().join("elsewhere");
    let link = dir.path().join("link");
    let file = dir.path().join("file");
    for directory in [&home, &elsewhere] {
        fs::create_dir(directory).unwrap();
        with_mode(directory, 0o700);
    }
    symlink(&elsewhere, &link).unwrap();
    fs::write(&file, "x").unwrap();

    SystemFiles
        .chmod_directory_nofollow(&home, me, 0o750)
        .unwrap();
    assert_eq!(mode_of(&home), 0o750);

    for (path, owner) in [(&link, me), (&home, me + 1), (&file, me)] {
        assert!(
            SystemFiles
                .chmod_directory_nofollow(path, owner, 0o755)
                .is_err(),
            "{path:?} {owner}"
        );
    }
    assert_eq!(mode_of(&home), 0o750);
    assert_eq!(mode_of(&elsewhere), 0o700);
}

#[test]
fn the_configuration_is_opened_without_following_links_or_blocking_and_judged_by_its_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let me = fs::metadata(dir.path()).unwrap().uid();
    let config = dir.path().join("agent.yaml");
    let link = dir.path().join("link.yaml");
    let fifo = dir.path().join("fifo.yaml");
    fs::write(&config, "host_users:\n  enabled: true\n").unwrap();
    with_mode(&config, 0o644);
    symlink(&config, &link).unwrap();
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );

    for (path, expected) in [
        (link, TrustProblem::Symlink),
        (fifo, TrustProblem::WrongKind),
        (dir.path().to_path_buf(), TrustProblem::WrongKind),
    ] {
        let what = format!("opening {path:?}");
        match within(&what, move || open_trusted_config(&path)) {
            Err(ConfigError::Untrusted { problem, .. }) => assert_eq!(problem, expected, "{what}"),
            other => panic!("{what}: {other:?}"),
        }
    }
    assert!(matches!(
        open_trusted_config(&dir.path().join("missing")),
        Err(ConfigError::Missing { .. })
    ));
    let own = open_trusted_config(&config);
    if me == 0 {
        assert!(own.is_ok(), "{own:?}");
    } else {
        assert!(
            matches!(
                own,
                Err(ConfigError::Untrusted {
                    problem: TrustProblem::NotOwnedByRoot,
                    ..
                })
            ),
            "{own:?}"
        );
    }
}

#[test]
fn reads_stop_one_byte_past_the_limit() {
    assert_eq!(
        read_limited(&b"abcd"[..], 4).unwrap(),
        Some(b"abcd".to_vec())
    );
    assert_eq!(read_limited(&b"abcde"[..], 4).unwrap(), None);
}

#[test]
fn small_system_files_are_bounded_text_and_a_missing_one_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let shells = dir.path().join("shells");
    let big = dir.path().join("big");
    let binary = dir.path().join("binary");
    fs::write(&shells, "/bin/sh\n").unwrap();
    fs::write(&big, vec![b'#'; MAX_SYSTEM_FILE_BYTES + 1]).unwrap();
    fs::write(&binary, [0xff, 0xfe]).unwrap();

    assert_eq!(
        read_system_file(&shells).unwrap().as_deref(),
        Some("/bin/sh\n")
    );
    assert_eq!(read_system_file(&dir.path().join("missing")).unwrap(), None);
    for path in [dir.path(), big.as_path(), binary.as_path()] {
        assert!(read_system_file(path).is_err(), "{path:?}");
    }
}
