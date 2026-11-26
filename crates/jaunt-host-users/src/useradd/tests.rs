use std::path::Path;

use super::{
    AfterFailure, USERADD_TIMEOUT, UseraddOutcome, after_failure, classify_useradd, useradd_args,
    userdel_args,
};
use crate::protocol::{Reference, SessionLabel};
use crate::rules::Reason;
use crate::state::State;
use crate::system::{PasswdEntry, Runner, ToolExit, Users};
use crate::testing::{
    FakeRunner, FakeUsers, NOW, candidate, enabled_config, name, record, state_of, verified,
};

const RANGE: &str = "  uid_min: 30000\n  uid_max: 30999\n";

fn exit(code: Option<i32>, timed_out: bool) -> ToolExit {
    ToolExit {
        code,
        timed_out,
        stderr: b"useradd: message".to_vec(),
    }
}

fn entry(login: &str, uid: u32) -> PasswdEntry {
    PasswdEntry {
        name: name(login),
        uid,
        gid: uid,
        home: format!("/home/{login}"),
        shell: "/bin/bash".to_owned(),
    }
}

fn pending_alice() -> State {
    let config = enabled_config(RANGE);
    let mut state = State::default();
    state
        .begin(
            &candidate(&config, "alice"),
            &Reference::parse("H-0000ABCD").unwrap(),
            &SessionLabel::parse("s-1").unwrap(),
            NOW,
        )
        .unwrap();
    state
}

#[test]
fn the_argv_is_fixed_and_takes_only_operator_settings_and_the_login() {
    let config = enabled_config(concat!(
        "  groups: [devs, ops]\n",
        "  privileged_groups: [docker]\n",
        "  shell: /usr/bin/zsh\n",
        "  home_base: /srv/home\n",
        "  uid_min: 40000\n",
        "  uid_max: 40999\n",
    ));
    let expected = [
        "--create-home",
        "--home-dir",
        "/srv/home/alice",
        "--skel",
        "/etc/skel",
        "--shell",
        "/usr/bin/zsh",
        "--user-group",
        "--groups",
        "devs,ops,docker",
        "--comment",
        "jaunt",
        "--password",
        "*",
        "--no-log-init",
        "-K",
        "UID_MIN=40000",
        "-K",
        "UID_MAX=40999",
        "-K",
        "GID_MIN=40000",
        "-K",
        "GID_MAX=40999",
        "-K",
        "SUB_UID_COUNT=0",
        "-K",
        "SUB_GID_COUNT=0",
        "--",
        "alice",
    ];
    assert_eq!(
        useradd_args(&config, &candidate(&config, "alice")),
        expected
    );

    let plain = enabled_config("");
    let args = useradd_args(&plain, &candidate(&plain, "bob"));
    assert!(!args.iter().any(|arg| arg == "--groups"), "{args:?}");
    assert_eq!(&args[args.len() - 2..], ["--", "bob"]);
}

#[test]
fn exit_codes_map_to_outcomes_and_only_four_is_a_refusal() {
    for (code, timed_out, outcome) in [
        (Some(0), false, UseraddOutcome::Created),
        (Some(4), false, UseraddOutcome::UidRangeExhausted),
        (Some(9), false, UseraddOutcome::NameInUse),
        (
            Some(10),
            false,
            UseraddOutcome::Failed {
                exit_code: Some(10),
            },
        ),
        (
            Some(12),
            false,
            UseraddOutcome::Failed {
                exit_code: Some(12),
            },
        ),
        (
            Some(1),
            false,
            UseraddOutcome::Failed { exit_code: Some(1) },
        ),
        (None, false, UseraddOutcome::Failed { exit_code: None }),
        (None, true, UseraddOutcome::TimedOut),
        (Some(0), true, UseraddOutcome::TimedOut),
    ] {
        assert_eq!(
            classify_useradd(&exit(code, timed_out)),
            outcome,
            "{code:?} {timed_out}"
        );
    }
    assert_eq!(
        UseraddOutcome::UidRangeExhausted.refusal(),
        Some(Reason::UidRange)
    );
    for outcome in [
        UseraddOutcome::Created,
        UseraddOutcome::NameInUse,
        UseraddOutcome::TimedOut,
        UseraddOutcome::Failed { exit_code: Some(1) },
    ] {
        assert_eq!(outcome.refusal(), None, "{outcome:?}");
    }
}

#[test]
fn rollback_needs_a_timeout_or_code_ten_or_twelve_our_pending_trace_a_uid_in_range_and_no_old_home()
{
    let config = enabled_config(RANGE);
    let alice = candidate(&config, "alice");
    let ours = entry("alice", 30_005);
    let timed_out = UseraddOutcome::TimedOut;
    let failed = |code| UseraddOutcome::Failed {
        exit_code: Some(code),
    };
    let mut bound_elsewhere = pending_alice();
    bound_elsewhere
        .bind(&verified(&config, &alice, 30_007))
        .unwrap();
    let active = state_of(vec![record("alice", Some(30_005), "active")], &[]);
    let rollback = |outcome| {
        after_failure(
            outcome,
            &config,
            &alice,
            Some(&ours),
            false,
            &pending_alice(),
        )
    };
    let keep = AfterFailure::KeepUnconfirmed;

    assert!(
        matches!(rollback(timed_out), AfterFailure::RollBack(permit) if permit.login() == &name("alice"))
    );
    assert!(matches!(rollback(failed(10)), AfterFailure::RollBack(_)));
    assert!(matches!(rollback(failed(12)), AfterFailure::RollBack(_)));
    for outcome in [
        failed(1),
        failed(6),
        UseraddOutcome::Failed { exit_code: None },
        UseraddOutcome::UidRangeExhausted,
        UseraddOutcome::Created,
    ] {
        assert_eq!(rollback(outcome), keep, "{outcome:?}");
    }
    for outcome in [UseraddOutcome::NameInUse, timed_out, failed(12)] {
        let result = after_failure(outcome, &config, &alice, None, false, &pending_alice());
        assert_eq!(
            result,
            AfterFailure::Abandon,
            "{outcome:?} without an account"
        );
    }
    for foreign in [entry("alice", 30_005), entry("alice", 1_005)] {
        let result = after_failure(
            UseraddOutcome::NameInUse,
            &config,
            &alice,
            Some(&foreign),
            false,
            &pending_alice(),
        );
        assert_eq!(
            result,
            AfterFailure::Abandon,
            "name in use with uid {}",
            foreign.uid
        );
    }
    let cases: [(&str, PasswdEntry, bool, State); 7] = [
        (
            "uid below range",
            entry("alice", 1_005),
            false,
            pending_alice(),
        ),
        ("uid 0", entry("alice", 0), false, pending_alice()),
        (
            "uid above range",
            entry("alice", 31_000),
            false,
            pending_alice(),
        ),
        ("home existed", ours.clone(), true, pending_alice()),
        ("no pending trace", ours.clone(), false, State::default()),
        (
            "trace bound to another uid",
            ours.clone(),
            false,
            bound_elsewhere,
        ),
        ("record not pending", ours.clone(), false, active),
    ];
    for (label, account, home_existed, state) in cases {
        let result = after_failure(
            timed_out,
            &config,
            &alice,
            Some(&account),
            home_existed,
            &state,
        );
        assert_eq!(result, keep, "{label}");
    }
    let renamed = entry("alicia", 30_005);
    assert_eq!(
        after_failure(
            timed_out,
            &config,
            &alice,
            Some(&renamed),
            false,
            &pending_alice()
        ),
        keep
    );
}

#[test]
fn a_name_taken_between_getent_and_useradd_never_leads_to_userdel() {
    let config = enabled_config(RANGE);
    let alice = candidate(&config, "alice");
    let state = pending_alice();
    let program = Path::new("/usr/sbin/useradd");

    let mut runner = FakeRunner::exiting(Some(9));
    let args = useradd_args(&config, &alice);
    let exit = runner.run(program, &args, USERADD_TIMEOUT).unwrap();
    let outcome = classify_useradd(&exit);
    assert_eq!(outcome, UseraddOutcome::NameInUse);
    let users = FakeUsers::default().with_account("alice", 30_002);
    let taken = users.passwd(&name("alice")).unwrap();
    let handling = after_failure(outcome, &config, &alice, taken.as_ref(), false, &state);
    assert_eq!(handling, AfterFailure::Abandon);
    assert_eq!(
        runner.calls,
        [(program.to_path_buf(), args, USERADD_TIMEOUT)]
    );

    let mut runner = FakeRunner::exiting(Some(12));
    let exit = runner
        .run(program, &useradd_args(&config, &alice), USERADD_TIMEOUT)
        .unwrap();
    let ours = entry("alice", 30_002);
    let AfterFailure::RollBack(permit) = after_failure(
        classify_useradd(&exit),
        &config,
        &alice,
        Some(&ours),
        false,
        &state,
    ) else {
        panic!("code 12 with our pending trace should roll back");
    };
    assert_eq!(userdel_args(&permit), ["--remove", "--", "alice"]);
}
