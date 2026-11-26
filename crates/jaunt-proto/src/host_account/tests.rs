use serde_json::{Value, json};

use super::{
    AccountEvent, AccountReference, AccountRefusal, AccountReport, AccountStage, AgentCapabilities,
    InvalidAccountReport, MAX_ACCOUNT_GROUPS, MAX_ACCOUNT_HOME_BYTES,
};

fn reference() -> AccountReference {
    AccountReference::parse("H-9D0311FE").unwrap()
}

fn parsed(body: &Value) -> Result<AccountEvent, InvalidAccountReport> {
    serde_json::from_value::<AccountReport>(body.clone())
        .expect("the report shape")
        .event()
}

fn base(event: &str) -> Value {
    json!({"session_id": "s-1", "login": "alice", "event": event, "ref": "H-9D0311FE"})
}

fn with(mut body: Value, field: &str, value: Value) -> Value {
    body[field] = value;
    body
}

fn without(mut body: Value, field: &str) -> Value {
    body.as_object_mut().unwrap().remove(field);
    body
}

#[test]
fn capabilities_are_one_strict_flag() {
    let parsed: AgentCapabilities =
        serde_json::from_value(json!({"creates_accounts": true})).unwrap();
    assert!(parsed.creates_accounts);
    for refused in [
        json!({}),
        json!({"creates_accounts": "yes"}),
        json!({"creates_accounts": true, "groups": []}),
    ] {
        assert!(
            serde_json::from_value::<AgentCapabilities>(refused.clone()).is_err(),
            "{refused}"
        );
    }
}

#[test]
fn a_reference_is_h_and_eight_upper_case_hex_digits() {
    for (value, valid) in [
        ("H-9D0311FE", true),
        ("H-00000000", true),
        ("H-9d0311fe", false),
        ("H-9D0311F", false),
        ("H-9D0311FEA", false),
        ("D-9D0311FE", false),
        ("H-9D0311FG", false),
        ("", false),
    ] {
        assert_eq!(AccountReference::parse(value).is_ok(), valid, "{value}");
    }
    let wrong_ref = with(base("creating"), "ref", json!("H-123"));
    assert!(serde_json::from_value::<AccountReport>(wrong_ref).is_err());
}

#[test]
fn every_event_round_trips_through_the_wire_shape() {
    let events = [
        AccountEvent::Creating {
            reference: reference(),
        },
        AccountEvent::Created {
            reference: reference(),
            uid: 30_000,
            home: "/home/alice".to_owned(),
            groups: vec!["alice".to_owned(), "staff".to_owned()],
        },
        AccountEvent::Refused {
            reference: reference(),
            reason: AccountRefusal::RateLimit,
        },
        AccountEvent::Failed {
            reference: reference(),
            stage: AccountStage::Useradd,
            exit_code: Some(12),
        },
        AccountEvent::Failed {
            reference: reference(),
            stage: AccountStage::Busy,
            exit_code: None,
        },
        AccountEvent::Missing {
            reference: reference(),
        },
    ];
    for event in events {
        let report = AccountReport::new("s-1".to_owned(), "alice".to_owned(), event.clone());
        let wire = serde_json::to_value(&report).unwrap();
        assert_eq!(parsed(&wire), Ok(event), "{wire}");
    }
    let created = serde_json::to_value(AccountReport::new(
        "s-1".to_owned(),
        "alice".to_owned(),
        AccountEvent::Created {
            reference: reference(),
            uid: 30_000,
            home: "/home/alice".to_owned(),
            groups: vec!["alice".to_owned()],
        },
    ))
    .unwrap();
    assert_eq!(
        created,
        json!({"session_id": "s-1", "login": "alice", "event": "created", "ref": "H-9D0311FE",
               "uid": 30_000, "home": "/home/alice", "groups": ["alice"]})
    );
}

#[test]
fn fields_that_do_not_belong_to_the_event_make_the_report_inconsistent() {
    let created = with(
        with(
            with(base("created"), "uid", json!(30_000)),
            "home",
            json!("/home/alice"),
        ),
        "groups",
        json!([]),
    );
    for body in [
        without(base("creating"), "ref"),
        with(base("creating"), "uid", json!(1)),
        without(created.clone(), "uid"),
        without(created.clone(), "home"),
        without(created.clone(), "groups"),
        with(created.clone(), "reason", json!("name_rule")),
        base("refused"),
        with(
            with(base("refused"), "reason", json!("max_users")),
            "stage",
            json!("tool"),
        ),
        base("failed"),
        with(
            with(base("failed"), "stage", json!("tool")),
            "home",
            json!("/home/x"),
        ),
        without(base("missing"), "ref"),
        with(base("missing"), "reason", json!("name_rule")),
    ] {
        assert_eq!(
            parsed(&body),
            Err(InvalidAccountReport::Inconsistent),
            "{body}"
        );
    }
}

#[test]
fn unknown_fields_events_reasons_and_stages_are_rejected_by_the_shape() {
    for body in [
        with(base("creating"), "extra", json!(1)),
        base("deleted"),
        with(base("refused"), "reason", json!("too_long")),
        with(base("failed"), "stage", json!("userdel")),
        with(base("failed"), "exit_code", json!("1")),
        with(base("created"), "uid", json!(-1)),
        without(base("creating"), "login"),
    ] {
        assert!(
            serde_json::from_value::<AccountReport>(body.clone()).is_err(),
            "{body}"
        );
    }
}

#[test]
fn the_home_and_the_groups_of_a_created_account_are_bounded() {
    let created = |home: &str, groups: Vec<String>| {
        with(
            with(
                with(base("created"), "uid", json!(30_000)),
                "home",
                json!(home),
            ),
            "groups",
            json!(groups),
        )
    };
    let mut root = created("/root", Vec::new());
    root["uid"] = json!(0);
    assert_eq!(parsed(&root), Err(InvalidAccountReport::Uid));
    root["uid"] = json!(1);
    assert!(parsed(&root).is_ok());
    let longest = format!("/{}", "h".repeat(MAX_ACCOUNT_HOME_BYTES - 1));
    let too_long = format!("/{}", "h".repeat(MAX_ACCOUNT_HOME_BYTES));
    let names = |count: usize| (0..count).map(|index| format!("g{index}")).collect();
    assert!(parsed(&created(&longest, names(MAX_ACCOUNT_GROUPS))).is_ok());
    for home in [
        too_long.as_str(),
        "home/alice",
        "/",
        "/home/../etc",
        "/home//alice",
        "/home/alice\n",
    ] {
        assert_eq!(
            parsed(&created(home, Vec::new())),
            Err(InvalidAccountReport::Home),
            "{home:?}"
        );
    }
    for groups in [
        names(MAX_ACCOUNT_GROUPS + 1),
        vec!["Staff".to_owned()],
        vec![String::new()],
    ] {
        assert_eq!(
            parsed(&created("/home/alice", groups.clone())),
            Err(InvalidAccountReport::Groups),
            "{groups:?}"
        );
    }
}
