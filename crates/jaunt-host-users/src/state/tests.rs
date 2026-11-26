use serde_json::json;

use super::{AccountState, MAX_RECORDS, MAX_STATE_BYTES, State, StateError};
use crate::config::HostUsersConfig;
use crate::names::Name;
use crate::protocol::{Reference, SessionLabel};
use crate::system::{GroupEntry, LookupError, PasswdEntry, Users};
use crate::testing::{FakeUsers, NOW, candidate, enabled_config, name, record, state_of, verified};

type Expected = fn(&StateError) -> bool;

const WIDE_RANGE: &str = "  uid_min: 1000\n  uid_max: 59999\n  max_users: 1000\n";

fn begin_with(config: &HostUsersConfig, state: &mut State, login: &str) -> Result<(), StateError> {
    state.begin(
        &candidate(config, login),
        &Reference::parse("H-0000ABCD").unwrap(),
        &SessionLabel::parse("s-9").unwrap(),
        NOW,
    )
}

fn begin(state: &mut State, login: &str) -> Result<(), StateError> {
    begin_with(&enabled_config(""), state, login)
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

#[test]
fn the_state_file_round_trips_and_refuses_inconsistent_content() {
    let state = state_of(
        vec![
            record("alice", Some(30_001), "active"),
            record("bob", None, "pending"),
            record("carol", Some(30_002), "unconfirmed"),
        ],
        &[NOW - 5, NOW],
    );
    let bytes = state.to_json().unwrap();
    assert!(bytes.ends_with(b"}\n"));
    assert_eq!(State::from_json(&bytes).unwrap(), state);
    assert_eq!(
        state.record(&name("bob")).unwrap().state(),
        AccountState::Pending
    );
    assert_eq!(state.record(&name("alice")).unwrap().uid(), Some(30_001));

    let file = |accounts: serde_json::Value| {
        json!({"v": 1, "accounts": accounts, "attempts": []}).to_string()
    };
    let mut only_uid = record("alice", Some(30_001), "active");
    only_uid.as_object_mut().unwrap().remove("gid");
    let mut bad_home = record("alice", Some(30_001), "active");
    bad_home["home"] = json!("home/alice");
    let mut bad_ref = record("alice", Some(30_001), "active");
    bad_ref["ref"] = json!("H-1");
    let mut extra = record("alice", Some(30_001), "active");
    extra["owner"] = json!("x");
    let too_many_attempts =
        json!({"v": 1, "accounts": [], "attempts": vec![NOW; 1025]}).to_string();
    let oversized = " ".repeat(MAX_STATE_BYTES + 1);
    let cases: Vec<(String, Expected)> = vec![
        (r#"{"v":2,"accounts":[],"attempts":[]}"#.into(), |error| {
            matches!(error, StateError::Version)
        }),
        (r#"{"v":1,"accounts":[]}"#.into(), |error| {
            matches!(error, StateError::Malformed)
        }),
        ("{".into(), |error| matches!(error, StateError::Malformed)),
        (file(json!([extra])), |error| {
            matches!(error, StateError::Malformed)
        }),
        (file(json!([bad_ref])), |error| {
            matches!(error, StateError::Malformed)
        }),
        (file(json!([record("Alice", None, "pending")])), |error| {
            matches!(error, StateError::Malformed)
        }),
        (
            file(json!([
                record("alice", None, "pending"),
                record("alice", Some(30_001), "active")
            ])),
            |error| matches!(error, StateError::Invalid(_)),
        ),
        (file(json!([record("alice", None, "active")])), |error| {
            matches!(error, StateError::Invalid(_))
        }),
        (file(json!([only_uid])), |error| {
            matches!(error, StateError::Invalid(_))
        }),
        (file(json!([bad_home])), |error| {
            matches!(error, StateError::Invalid(_))
        }),
        (too_many_attempts, |error| {
            matches!(error, StateError::Invalid(_))
        }),
        (oversized, |error| matches!(error, StateError::TooLarge)),
    ];
    for (text, expected) in cases {
        let error = State::from_json(text.as_bytes()).unwrap_err();
        assert!(expected(&error), "{error}");
    }
}

#[test]
fn reconcile_settles_pending_records_and_forgets_records_whose_account_went_away() {
    let mut state = state_of(
        vec![
            record("ours", Some(30_001), "pending"),
            record("vanished", None, "pending"),
            record("unbound", None, "pending"),
            record("replaced", Some(30_003), "pending"),
            record("steady", Some(30_004), "active"),
            record("deleted", Some(30_005), "active"),
            record("recreated", Some(30_006), "active"),
            record("kept-unbound", None, "unconfirmed"),
            record("gone-unbound", None, "unconfirmed"),
            record("gone-bound", Some(30_007), "unconfirmed"),
        ],
        &[NOW - 90_000, NOW - 30],
    );
    let users = FakeUsers::default()
        .with_account("ours", 30_001)
        .with_account("unbound", 30_002)
        .with_account("replaced", 1_005)
        .with_account("steady", 30_004)
        .with_account("recreated", 1_006)
        .with_account("kept-unbound", 30_008);
    let report = state.reconcile(&users, NOW).unwrap();
    assert_eq!(report.unconfirmed, [name("ours")]);
    assert_eq!(report.dropped, [name("vanished")]);
    assert_eq!(report.not_adopted, [name("unbound"), name("replaced")]);
    assert_eq!(
        report.forgotten,
        [
            name("deleted"),
            name("recreated"),
            name("gone-unbound"),
            name("gone-bound")
        ]
    );
    assert!(report.attempts_settled && report.changed());
    assert_eq!((users.batches(), users.lookups()), (1, 0));

    let remaining: Vec<(&str, AccountState, Option<u32>)> = state
        .accounts()
        .iter()
        .map(|record| (record.login().as_str(), record.state(), record.uid()))
        .collect();
    assert_eq!(
        remaining,
        [
            ("ours", AccountState::Unconfirmed, Some(30_001)),
            ("unbound", AccountState::Unconfirmed, None),
            ("steady", AccountState::Active, Some(30_004)),
            ("kept-unbound", AccountState::Unconfirmed, None),
        ]
    );
    assert!(
        state
            .record(&name("ours"))
            .unwrap()
            .is_managed(Some(&entry("ours", 30_001)))
    );
    assert!(
        !state
            .record(&name("unbound"))
            .unwrap()
            .is_managed(Some(&entry("unbound", 30_002)))
    );
    assert_eq!(state.attempts().times(), [NOW - 30]);

    assert_eq!(state.counted_users(&users).unwrap(), 4);
    assert_eq!((users.batches(), users.lookups()), (2, 0));
    let again = state.reconcile(&users, NOW).unwrap();
    assert!(!again.changed(), "{again:?}");
}

#[test]
fn a_batch_lookup_that_does_not_line_up_with_the_request_is_an_error() {
    struct Misaligned(Vec<Option<PasswdEntry>>);
    impl Users for Misaligned {
        fn passwd(&self, _: &Name) -> Result<Option<PasswdEntry>, LookupError> {
            Ok(None)
        }
        fn passwd_many(&self, _: &[Name]) -> Result<Vec<Option<PasswdEntry>>, LookupError> {
            Ok(self.0.clone())
        }
        fn group(&self, _: &Name) -> Result<Option<GroupEntry>, LookupError> {
            Ok(None)
        }
    }
    let state = state_of(
        vec![
            record("alice", Some(30_001), "active"),
            record("bob", Some(30_002), "active"),
        ],
        &[],
    );
    for answer in [
        vec![Some(entry("alice", 30_001))],
        vec![
            Some(entry("alice", 30_001)),
            Some(entry("carol", 30_002)),
            None,
        ],
        vec![Some(entry("bob", 30_002)), Some(entry("alice", 30_001))],
    ] {
        let users = Misaligned(answer);
        assert!(matches!(
            state.counted_users(&users),
            Err(LookupError::Malformed { .. })
        ));
        let mut copy = state.clone();
        assert!(matches!(
            copy.reconcile(&users, NOW),
            Err(LookupError::Malformed { .. })
        ));
        assert_eq!(copy, state);
    }
    assert!(matches!(
        state.counted_users(&FakeUsers::broken()),
        Err(LookupError::Exit { .. })
    ));
}

#[test]
fn deleted_accounts_free_their_records_so_the_state_never_sticks_at_full() {
    let config = enabled_config(WIDE_RANGE);
    let mut state = State::default();
    let mut created = FakeUsers::default();
    for index in 0..MAX_RECORDS {
        let login = format!("u{index}");
        let uid = 1000 + u32::try_from(index).unwrap();
        begin_with(&config, &mut state, &login).unwrap();
        state
            .bind(&verified(&config, &candidate(&config, &login), uid))
            .unwrap();
        state.activate(&name(&login)).unwrap();
        created = created.with_account(&login, uid);
    }
    assert!(matches!(
        begin_with(&config, &mut state, "late"),
        Err(StateError::Full)
    ));
    assert_eq!(state.accounts().len(), MAX_RECORDS);
    assert!(state.record(&name("late")).is_none());
    assert_eq!(state.counted_users(&created).unwrap(), 4096);
    assert_eq!(created.batches(), 1);

    let all_deleted = FakeUsers::default();
    let report = state.reconcile(&all_deleted, NOW).unwrap();
    assert_eq!(report.forgotten.len(), MAX_RECORDS);
    assert!(state.accounts().is_empty());
    assert_eq!(all_deleted.batches(), 1);
    for index in 0..MAX_RECORDS {
        begin_with(&config, &mut state, &format!("v{index}")).unwrap();
    }
    assert_eq!(state.accounts().len(), MAX_RECORDS);
}

#[test]
fn managed_means_a_settled_record_with_the_same_uid() {
    let state = state_of(
        vec![
            record("alice", Some(30_001), "active"),
            record("bob", Some(30_002), "pending"),
        ],
        &[],
    );
    let alice = state.record(&name("alice")).unwrap();
    assert!(alice.is_managed(Some(&entry("alice", 30_001))));
    assert!(!alice.is_managed(Some(&entry("alice", 30_009))));
    assert!(!alice.is_managed(None));
    let bob = state.record(&name("bob")).unwrap();
    assert!(!bob.is_managed(Some(&entry("bob", 30_002))));
}

#[test]
fn the_pending_lifecycle_allows_only_its_own_transitions() {
    let config = enabled_config("");
    let mut state = state_of(vec![record("alice", Some(30_001), "active")], &[]);
    begin(&mut state, "alice").unwrap();
    let pending = state.record(&name("alice")).unwrap();
    assert_eq!(pending.state(), AccountState::Pending);
    assert_eq!((pending.uid(), pending.home()), (None, "/home/alice"));
    assert_eq!(pending.reference().as_str(), "H-0000ABCD");
    assert_eq!(pending.session().as_str(), "s-9");
    assert_eq!(pending.created_at(), NOW);
    assert_eq!(state.accounts().len(), 1);
    assert_eq!(state.attempts().times(), [NOW]);

    assert!(matches!(
        begin(&mut state, "alice"),
        Err(StateError::AlreadyPending { .. })
    ));
    assert!(matches!(
        state.activate(&name("alice")),
        Err(StateError::Unbound { .. })
    ));
    let elsewhere = enabled_config("  home_base: /srv/home\n");
    let foreign_home = verified(&elsewhere, &candidate(&elsewhere, "alice"), 30_005);
    assert!(matches!(
        state.bind(&foreign_home),
        Err(StateError::HomeMismatch { .. })
    ));
    let alice = verified(&config, &candidate(&config, "alice"), 30_005);
    state.bind(&alice).unwrap();
    state.activate(&name("alice")).unwrap();
    let active = state.record(&name("alice")).unwrap();
    assert_eq!(
        (active.state(), active.uid(), active.gid()),
        (AccountState::Active, Some(30_005), Some(30_005))
    );
    for result in [
        state.bind(&alice),
        state.activate(&name("alice")),
        state.mark_unconfirmed(&name("alice")),
        state.abandon(&name("alice")),
        state.abandon(&name("nobody-here")),
    ] {
        assert!(
            matches!(result, Err(StateError::NotPending { .. })),
            "{result:?}"
        );
    }

    begin(&mut state, "bob").unwrap();
    state.mark_unconfirmed(&name("bob")).unwrap();
    assert_eq!(
        state.record(&name("bob")).unwrap().state(),
        AccountState::Unconfirmed
    );
    begin(&mut state, "carol").unwrap();
    state.abandon(&name("carol")).unwrap();
    assert!(state.record(&name("carol")).is_none());
    assert_eq!(state.attempts().count(), 3);
}

#[test]
fn a_full_state_refuses_new_records_without_changing_anything() {
    let records = (0..MAX_RECORDS)
        .map(|index| record(&format!("u{index}"), Some(30_000), "active"))
        .collect();
    let mut state = state_of(records, &[]);
    let before = state.clone();
    assert!(matches!(begin(&mut state, "alice"), Err(StateError::Full)));
    assert_eq!(state, before);
    begin(&mut state, "u7").unwrap();
    assert_eq!(state.accounts().len(), MAX_RECORDS);
    assert_eq!(
        state.record(&name("u7")).unwrap().state(),
        AccountState::Pending
    );
}
