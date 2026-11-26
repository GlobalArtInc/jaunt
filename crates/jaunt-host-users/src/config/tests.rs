use std::path::Path;

use super::{
    ConfigError, HomeMode, HostUsersConfig, HostUsersSection, MAX_CONFIG_BYTES, Settings,
    TrustProblem, check_config_trust, check_host, parse_agent_file,
};
use crate::system::FileKind;
use crate::testing::{FakeFiles, FakeUsers, name};

type Expected = fn(&ConfigError) -> bool;
type Check = Box<dyn Fn(&ConfigError) -> bool>;

fn settings(text: &str) -> Result<Settings, ConfigError> {
    parse_agent_file(text)?.settings()
}

fn enabled(extra: &str) -> Result<HostUsersConfig, ConfigError> {
    match settings(&format!("host_users:\n  enabled: true\n{extra}"))? {
        Settings::Enabled(config) => Ok(config),
        Settings::Disabled => panic!("an enabled section came back disabled"),
    }
}

fn untrusted(path: &str, problem: TrustProblem) -> impl Fn(&ConfigError) -> bool {
    let path = path.to_owned();
    move |error| {
        matches!(error, ConfigError::Untrusted { path: found, problem: seen }
            if found == Path::new(&path) && *seen == problem)
    }
}

#[test]
fn the_section_is_optional_off_by_default_and_ignores_other_agent_keys() {
    for text in [
        "",
        "# nothing\n---\n",
        "state_dir: /var/lib/jaunt\ninner:\n  sshd_addr: 127.0.0.1:22\n",
        "host_users:\n",
        "host_users: {}\nrecording:\n  memory_budget_bytes: 1048576\n",
    ] {
        assert_eq!(
            parse_agent_file(text).unwrap(),
            HostUsersSection::default(),
            "{text:?}"
        );
        assert_eq!(settings(text).unwrap(), Settings::Disabled, "{text:?}");
    }
}

#[test]
fn the_design_example_enables_creation_with_its_values() {
    let config = enabled(concat!(
        "  groups: [devs]\n",
        "  privileged_groups: [docker]\n",
        "  shell: /bin/bash\n",
        "  home_base: /home\n",
        "  home_mode: \"0750\"\n",
        "  uid_min: 30000\n",
        "  uid_max: 30999\n",
        "  max_users: 100\n",
        "  names: { deny: [bob], deny_prefixes: [svc-], allow_prefixes: [] }\n",
        "  allow_with_directory: false\n",
    ))
    .unwrap();
    assert_eq!(config.groups(), [name("devs")]);
    assert_eq!(config.privileged_groups(), [name("docker")]);
    assert_eq!(config.shell(), "/bin/bash");
    assert_eq!(config.home_of(&name("alice")), "/home/alice");
    assert_eq!(config.home_mode(), HomeMode::OwnerAndGroup);
    assert_eq!((config.uid_min(), config.uid_max()), (30_000, 30_999));
    assert_eq!(config.max_users(), 100);
    assert_eq!(config.names().deny(), [name("bob")]);
    assert_eq!(config.names().deny_prefixes(), [name("svc-")]);
    assert!(config.names().allow_prefixes().is_empty());
    assert!(!config.allow_with_directory());

    let defaults = enabled("").unwrap();
    assert!(defaults.groups().is_empty() && defaults.privileged_groups().is_empty());
    assert_eq!(defaults.shell(), "/bin/bash");
    assert_eq!(defaults.home_base(), "/home");
    assert_eq!(defaults.home_mode(), HomeMode::OwnerAndGroup);
    assert_eq!(
        (defaults.uid_min(), defaults.uid_max(), defaults.max_users()),
        (30_000, 30_999, 100)
    );
}

#[test]
fn home_mode_takes_three_values_quoted_or_plain() {
    for (value, bits) in [
        ("\"0700\"", Some(0o700)),
        ("0700", Some(0o700)),
        ("\"0750\"", Some(0o750)),
        ("0755", Some(0o755)),
        ("\"0777\"", None),
        ("\"750\"", None),
        ("\"0o750\"", None),
    ] {
        let result = enabled(&format!("  home_mode: {value}\n"));
        match bits {
            Some(bits) => assert_eq!(result.unwrap().home_mode().bits(), bits, "{value}"),
            None => assert!(
                matches!(result, Err(ConfigError::HomeMode)),
                "{value}: {result:?}"
            ),
        }
    }
}

#[test]
fn broken_yaml_and_unknown_keys_inside_the_section_are_errors() {
    let oversized = format!("# {}\n", "x".repeat(MAX_CONFIG_BYTES));
    let cases: [(&str, Expected); 6] = [
        ("host_users:\n  enabled: true\n  sudo: true\n", |error| {
            matches!(error, ConfigError::Syntax { .. })
        }),
        ("host_users:\n  names: { allow: [a] }\n", |error| {
            matches!(error, ConfigError::Syntax { .. })
        }),
        ("host_users: [\n", |error| {
            matches!(error, ConfigError::Syntax { .. })
        }),
        (
            "host_users:\n  enabled: true\n  enabled: false\n",
            |error| matches!(error, ConfigError::Syntax { .. }),
        ),
        ("host_users:\n  uid_min: -1\n", |error| {
            matches!(error, ConfigError::Syntax { .. })
        }),
        (oversized.as_str(), |error| {
            matches!(error, ConfigError::TooLarge)
        }),
    ];
    for (text, expected) in cases {
        let error = settings(text).unwrap_err();
        assert!(expected(&error), "{text:?}: {error}");
    }
    let shown = settings("host_users:\n  shell: /bin/secret-value\n  bogus: 1\n")
        .unwrap_err()
        .to_string();
    assert!(!shown.contains("secret-value"), "{shown}");
}

#[test]
fn validation_refuses_each_broken_field_and_never_returns_a_partial_config() {
    let many: Vec<String> = (0..33).map(|index| format!("g{index}")).collect();
    let too_many = format!("  groups: [{}]\n", many.join(", "));
    let long_base = format!("  home_base: /{}\n", "h".repeat(95));
    let cases: Vec<(&str, Expected)> = vec![
        ("  groups: [Devs]\n", |error| {
            matches!(
                error,
                ConfigError::Name {
                    field: "groups",
                    index: 0
                }
            )
        }),
        ("  privileged_groups: [ok, -x]\n", |error| {
            matches!(
                error,
                ConfigError::Name {
                    field: "privileged_groups",
                    index: 1
                }
            )
        }),
        ("  groups: [devs, sudo]\n", |error| {
            matches!(error, ConfigError::PrivilegedGroup { index: 1 })
        }),
        ("  groups: [wheel]\n", |error| {
            matches!(error, ConfigError::PrivilegedGroup { index: 0 })
        }),
        ("  groups: [root]\n", |error| {
            matches!(error, ConfigError::PrivilegedGroup { index: 0 })
        }),
        ("  groups: [adm]\n", |error| {
            matches!(error, ConfigError::PrivilegedGroup { index: 0 })
        }),
        ("  groups: [devs]\n  privileged_groups: [devs]\n", |error| {
            matches!(error, ConfigError::DuplicateGroup)
        }),
        (too_many.as_str(), |error| {
            matches!(error, ConfigError::TooManyGroups)
        }),
        ("  shell: bin/bash\n", |error| {
            matches!(error, ConfigError::Shell)
        }),
        ("  shell: /bin/../bash\n", |error| {
            matches!(error, ConfigError::Shell)
        }),
        ("  home_base: /\n", |error| {
            matches!(error, ConfigError::HomeBase)
        }),
        ("  home_base: /home/\n", |error| {
            matches!(error, ConfigError::HomeBase)
        }),
        (long_base.as_str(), |error| {
            matches!(error, ConfigError::HomeBase)
        }),
        ("  uid_min: 999\n", |error| {
            matches!(error, ConfigError::UidMin)
        }),
        ("  uid_max: 60000\n", |error| {
            matches!(error, ConfigError::UidMax)
        }),
        ("  max_users: 0\n", |error| {
            matches!(error, ConfigError::MaxUsers)
        }),
        (
            "  uid_min: 1000\n  uid_max: 59999\n  max_users: 1001\n",
            |error| matches!(error, ConfigError::MaxUsers),
        ),
        ("  uid_min: 30000\n  uid_max: 30098\n", |error| {
            matches!(error, ConfigError::UidRange)
        }),
        ("  uid_min: 31000\n  uid_max: 30000\n", |error| {
            matches!(error, ConfigError::UidRange)
        }),
        ("  names: { deny: [Bob] }\n", |error| {
            matches!(
                error,
                ConfigError::Name {
                    field: "names.deny",
                    index: 0
                }
            )
        }),
        ("  names: { deny_prefixes: [\"\"] }\n", |error| {
            matches!(
                error,
                ConfigError::Name {
                    field: "names.deny_prefixes",
                    index: 0
                }
            )
        }),
        ("  names: { allow_prefixes: [u-, \"9\"] }\n", |error| {
            matches!(
                error,
                ConfigError::Name {
                    field: "names.allow_prefixes",
                    index: 1
                }
            )
        }),
    ];
    for (extra, expected) in cases {
        let error = enabled(extra).unwrap_err();
        assert!(expected(&error), "{extra:?}: {error}");
        let disabled = settings(&format!("host_users:\n  enabled: false\n{extra}"));
        assert!(disabled.is_err(), "{extra:?} must not pass while disabled");
    }

    for system in [
        "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot", "/dev", "/proc", "/sys", "/run",
        "/root",
    ] {
        let error = enabled(&format!("  home_base: {system}\n")).unwrap_err();
        assert!(
            matches!(error, ConfigError::HomeBaseSystem),
            "{system}: {error}"
        );
    }

    let base = format!("  home_base: /{}\n", "h".repeat(94));
    for accepted in [
        "  home_base: /var/home\n",
        "  home_base: /etc2\n",
        "  privileged_groups: [sudo, wheel]\n  groups: [devs]\n",
        "  uid_min: 30000\n  uid_max: 30099\n",
        "  uid_min: 1000\n  uid_max: 59999\n  max_users: 1000\n",
        base.as_str(),
    ] {
        assert!(enabled(accepted).is_ok(), "{accepted:?}");
    }
}

#[test]
fn the_config_file_and_its_directories_must_belong_to_root_without_group_or_other_write() {
    let trusted = || {
        FakeFiles::default()
            .root_dirs(&["/", "/etc", "/etc/jaunt"])
            .with("/etc/jaunt/agent.yaml", FileKind::Regular, 0, 0o644)
    };
    let file = "/etc/jaunt/agent.yaml";
    assert!(check_config_trust(Path::new(file), &trusted()).is_ok());
    for (mode, uid) in [(0o600, 0), (0o640, 0)] {
        let files = trusted().with(file, FileKind::Regular, uid, mode);
        assert!(
            check_config_trust(Path::new(file), &files).is_ok(),
            "{mode:o}"
        );
    }

    let cases: Vec<(FakeFiles, Check)> = vec![
        (
            trusted().with(file, FileKind::Regular, 1000, 0o644),
            Box::new(untrusted(file, TrustProblem::NotOwnedByRoot)),
        ),
        (
            trusted().with(file, FileKind::Regular, 0, 0o664),
            Box::new(untrusted(file, TrustProblem::Writable)),
        ),
        (
            trusted().with(file, FileKind::Regular, 0, 0o646),
            Box::new(untrusted(file, TrustProblem::Writable)),
        ),
        (
            trusted().with(file, FileKind::Symlink, 0, 0o777),
            Box::new(untrusted(file, TrustProblem::Symlink)),
        ),
        (
            trusted().with(file, FileKind::Directory, 0, 0o755),
            Box::new(untrusted(file, TrustProblem::WrongKind)),
        ),
        (
            trusted().with("/etc/jaunt", FileKind::Directory, 0, 0o775),
            Box::new(untrusted("/etc/jaunt", TrustProblem::Writable)),
        ),
        (
            trusted().with("/etc/jaunt", FileKind::Directory, 1000, 0o755),
            Box::new(untrusted("/etc/jaunt", TrustProblem::NotOwnedByRoot)),
        ),
        (
            trusted().with("/etc/jaunt", FileKind::Symlink, 0, 0o777),
            Box::new(untrusted("/etc/jaunt", TrustProblem::Symlink)),
        ),
        (
            trusted().with("/etc", FileKind::Directory, 1000, 0o755),
            Box::new(untrusted("/etc", TrustProblem::NotOwnedByRoot)),
        ),
        (
            trusted().with("/etc", FileKind::Directory, 0, 0o757),
            Box::new(untrusted("/etc", TrustProblem::Writable)),
        ),
        (
            trusted().with("/", FileKind::Directory, 1000, 0o755),
            Box::new(untrusted("/", TrustProblem::NotOwnedByRoot)),
        ),
        (
            trusted().with("/", FileKind::Directory, 0, 0o775),
            Box::new(untrusted("/", TrustProblem::Writable)),
        ),
        (
            trusted().without(file),
            Box::new(|error| matches!(error, ConfigError::Missing { .. })),
        ),
    ];
    for (files, expected) in cases {
        let error = check_config_trust(Path::new(file), &files).unwrap_err();
        assert!(expected(&error), "{error}");
    }
    for path in [
        "etc/jaunt/agent.yaml",
        "/etc/jaunt/../jaunt/agent.yaml",
        "/",
    ] {
        let error = check_config_trust(Path::new(path), &trusted()).unwrap_err();
        assert!(
            matches!(error, ConfigError::ConfigPath { .. }),
            "{path}: {error}"
        );
    }
}

#[test]
fn host_checks_need_a_listed_root_shell_a_root_home_base_and_existing_groups() {
    let config = enabled("  groups: [devs]\n  privileged_groups: [sudo]\n").unwrap();
    let shells = "/bin/sh\n/bin/bash\n";
    let files = || {
        FakeFiles::default()
            .root_dirs(&["/", "/home", "/etc", "/etc/skel"])
            .with("/bin/bash", FileKind::Regular, 0, 0o755)
    };
    let users = || {
        FakeUsers::default()
            .with_group("devs", 2000)
            .with_group("sudo", 27)
    };
    assert!(check_host(&config, shells, &users(), &files()).is_ok());

    let cases: Vec<(&str, FakeFiles, FakeUsers, Check)> = vec![
        (
            "/bin/sh\n# /bin/bash\n",
            files(),
            users(),
            Box::new(|error| matches!(error, ConfigError::ShellNotListed)),
        ),
        (
            shells,
            files().without("/bin/bash"),
            users(),
            Box::new(|error| matches!(error, ConfigError::Missing { .. })),
        ),
        (
            shells,
            files().with("/bin/bash", FileKind::Symlink, 0, 0o777),
            users(),
            Box::new(untrusted("/bin/bash", TrustProblem::Symlink)),
        ),
        (
            shells,
            files().with("/bin/bash", FileKind::Regular, 1000, 0o755),
            users(),
            Box::new(untrusted("/bin/bash", TrustProblem::NotOwnedByRoot)),
        ),
        (
            shells,
            files().with("/bin/bash", FileKind::Regular, 0, 0o775),
            users(),
            Box::new(untrusted("/bin/bash", TrustProblem::Writable)),
        ),
        (
            shells,
            files().with("/bin/bash", FileKind::Regular, 0, 0o750),
            users(),
            Box::new(untrusted("/bin/bash", TrustProblem::NotExecutable)),
        ),
        (
            shells,
            files().with("/home", FileKind::Symlink, 0, 0o777),
            users(),
            Box::new(untrusted("/home", TrustProblem::Symlink)),
        ),
        (
            shells,
            files().with("/home", FileKind::Directory, 0, 0o1777),
            users(),
            Box::new(untrusted("/home", TrustProblem::Writable)),
        ),
        (
            shells,
            files().with("/home", FileKind::Directory, 1000, 0o755),
            users(),
            Box::new(untrusted("/home", TrustProblem::NotOwnedByRoot)),
        ),
        (
            shells,
            files(),
            FakeUsers::default().with_group("sudo", 27),
            Box::new(
                |error| matches!(error, ConfigError::GroupMissing { name } if name.as_str() == "devs"),
            ),
        ),
        (
            shells,
            files(),
            FakeUsers::default().with_group("devs", 2000),
            Box::new(
                |error| matches!(error, ConfigError::GroupMissing { name } if name.as_str() == "sudo"),
            ),
        ),
        (
            shells,
            files(),
            FakeUsers::broken(),
            Box::new(|error| matches!(error, ConfigError::Lookup(_))),
        ),
        (
            shells,
            files().with("/etc/skel", FileKind::Symlink, 0, 0o777),
            users(),
            Box::new(untrusted("/etc/skel", TrustProblem::Symlink)),
        ),
        (
            shells,
            files().with("/etc/skel", FileKind::Directory, 1000, 0o755),
            users(),
            Box::new(untrusted("/etc/skel", TrustProblem::NotOwnedByRoot)),
        ),
        (
            shells,
            files().with("/etc/skel", FileKind::Directory, 0, 0o775),
            users(),
            Box::new(untrusted("/etc/skel", TrustProblem::Writable)),
        ),
        (
            shells,
            files().without("/etc/skel"),
            users(),
            Box::new(|error| matches!(error, ConfigError::Missing { .. })),
        ),
    ];
    for (shells, files, users, expected) in cases {
        let error = check_host(&config, shells, &users, &files).unwrap_err();
        assert!(expected(&error), "{error}");
    }
}
