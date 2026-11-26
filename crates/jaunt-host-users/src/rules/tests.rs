use super::{Decision, Facts, FactsError, Reason, check_login, decide, gather};
use crate::config::HostUsersConfig;
use crate::directory::DirectoryUse;
use crate::rate::Attempts;
use crate::system::FileKind;
use crate::testing::{
    FakeFiles, FakeUsers, NOW, candidate, enabled_config, name, record, state_of,
};

const RULES: &str = concat!(
    "  privileged_groups: [ops]\n",
    "  max_users: 3\n",
    "  names: { deny: [bob], deny_prefixes: [svc-] }\n",
);

fn facts(login: &str) -> Facts {
    Facts {
        login: name(login),
        home: format!("/home/{login}"),
        directory: DirectoryUse::Local,
        account_exists: false,
        group_exists: false,
        home_exists: false,
        managed_users: 0,
        attempts: Attempts::default(),
        now: NOW,
    }
}

fn create(config: &HostUsersConfig, login: &str) -> Decision {
    Decision::Create(candidate(config, login))
}

#[test]
fn logins_outside_the_common_predicate_are_refused_by_the_name_rule() {
    let longest = "a".repeat(32);
    let too_long = "a".repeat(33);
    for (login, accepted) in [
        ("alice", true),
        (longest.as_str(), true),
        ("Alice", false),
        ("-oProxyCommand=x", false),
        ("", false),
        ("a b", false),
        ("a/b", false),
        (too_long.as_str(), false),
    ] {
        let result = check_login(login);
        match accepted {
            true => assert_eq!(result.unwrap().as_str(), login),
            false => assert_eq!(result.unwrap_err(), Reason::NameRule, "{login:?}"),
        }
    }
}

#[test]
fn every_rule_maps_to_its_decision_and_reason() {
    let config = enabled_config(RULES);
    let directory_allowed = enabled_config(&format!("{RULES}  allow_with_directory: true\n"));
    let prefixed = enabled_config("  names: { allow_prefixes: [u-] }\n");
    let minute: Vec<u64> = (0..5).map(|offset| NOW - 50 + offset).collect();
    let day: Vec<u64> = (0..50).map(|index| NOW - 80_000 + index * 600).collect();

    let cases: Vec<(&str, &HostUsersConfig, Facts, Decision)> = vec![
        ("allowed", &config, facts("alice"), create(&config, "alice")),
        (
            "network directory",
            &config,
            Facts {
                directory: DirectoryUse::Network,
                ..facts("alice")
            },
            Decision::Disabled,
        ),
        (
            "network directory allowed",
            &directory_allowed,
            Facts {
                directory: DirectoryUse::Network,
                ..facts("alice")
            },
            create(&directory_allowed, "alice"),
        ),
        (
            "network directory wins over an existing account",
            &config,
            Facts {
                directory: DirectoryUse::Network,
                account_exists: true,
                ..facts("alice")
            },
            Decision::Disabled,
        ),
        (
            "account exists",
            &config,
            Facts {
                account_exists: true,
                ..facts("alice")
            },
            Decision::Exists,
        ),
        (
            "existing reserved account",
            &config,
            Facts {
                account_exists: true,
                ..facts("root")
            },
            Decision::Exists,
        ),
        (
            "denied name",
            &config,
            facts("bob"),
            Decision::Refused(Reason::NameRule),
        ),
        (
            "denied prefix",
            &config,
            facts("svc-db"),
            Decision::Refused(Reason::NameRule),
        ),
        (
            "outside allowed prefixes",
            &prefixed,
            facts("alice"),
            Decision::Refused(Reason::NameRule),
        ),
        (
            "inside allowed prefixes",
            &prefixed,
            facts("u-alice"),
            create(&prefixed, "u-alice"),
        ),
        (
            "built-in reserved",
            &config,
            facts("nginx"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "base-passwd name",
            &config,
            facts("www-data"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "systemd prefix",
            &config,
            facts("systemd-x"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "underscore prefix",
            &config,
            facts("_svc"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "privileged group name",
            &config,
            facts("docker"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "configured privileged group",
            &config,
            facts("ops"),
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "group collision",
            &config,
            Facts {
                group_exists: true,
                ..facts("alice")
            },
            Decision::Refused(Reason::GroupCollision),
        ),
        (
            "home exists",
            &config,
            Facts {
                home_exists: true,
                ..facts("alice")
            },
            Decision::Refused(Reason::HomeExists),
        ),
        (
            "below max users",
            &config,
            Facts {
                managed_users: 2,
                ..facts("alice")
            },
            create(&config, "alice"),
        ),
        (
            "at max users",
            &config,
            Facts {
                managed_users: 3,
                ..facts("alice")
            },
            Decision::Refused(Reason::MaxUsers),
        ),
        (
            "five in a minute",
            &config,
            Facts {
                attempts: Attempts::from_times(&minute),
                ..facts("alice")
            },
            Decision::Refused(Reason::RateLimit),
        ),
        (
            "fifty in a day",
            &config,
            Facts {
                attempts: Attempts::from_times(&day),
                ..facts("alice")
            },
            Decision::Refused(Reason::RateLimit),
        ),
        (
            "reserved before collision",
            &config,
            Facts {
                group_exists: true,
                ..facts("nginx")
            },
            Decision::Refused(Reason::ReservedName),
        ),
        (
            "collision before home",
            &config,
            Facts {
                group_exists: true,
                home_exists: true,
                ..facts("alice")
            },
            Decision::Refused(Reason::GroupCollision),
        ),
        (
            "home before quota",
            &config,
            Facts {
                home_exists: true,
                managed_users: 3,
                ..facts("alice")
            },
            Decision::Refused(Reason::HomeExists),
        ),
        (
            "quota before rate",
            &config,
            Facts {
                managed_users: 3,
                attempts: Attempts::from_times(&minute),
                ..facts("alice")
            },
            Decision::Refused(Reason::MaxUsers),
        ),
    ];
    for (label, config, facts, expected) in cases {
        assert_eq!(decide(config, &facts), expected, "{label}");
    }
}

#[test]
fn gather_reads_every_fact_through_the_traits_and_counts_only_live_records() {
    let config = enabled_config("");
    let users = FakeUsers::default()
        .with_account("kept", 30_001)
        .with_account("unbound", 30_002)
        .with_account("taken", 1_005)
        .with_group("alice", 30_100);
    let files = FakeFiles::default().with("/home/alice", FileKind::Directory, 0, 0o755);
    let state = state_of(
        vec![
            record("kept", Some(30_001), "active"),
            record("unbound", None, "unconfirmed"),
            record("taken", Some(30_003), "active"),
            record("gone", Some(30_004), "active"),
        ],
        &[NOW - 10],
    );
    let facts = gather(
        &config,
        name("alice"),
        DirectoryUse::Local,
        &state,
        (&users, &files),
        NOW,
    )
    .unwrap();
    assert_eq!(facts.home, "/home/alice");
    assert!(!facts.account_exists);
    assert!(facts.group_exists && facts.home_exists);
    assert_eq!(facts.managed_users, 2);
    assert_eq!(facts.attempts.times(), [NOW - 10]);
    assert_eq!((users.lookups(), users.batches()), (2, 1));

    let error = gather(
        &config,
        name("alice"),
        DirectoryUse::Local,
        &state,
        (&FakeUsers::broken(), &files),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(error, FactsError::Lookup(_)), "{error}");
}
