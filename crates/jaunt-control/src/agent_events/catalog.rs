use std::collections::BTreeMap;

use jaunt_audit::{
    AuditEvent, EventType, FieldKind, RawValue, Timestamp, is_withheld, stored_char_len,
};
use jaunt_proto::{AgentEvent, AgentEventKind, AgentEventValue, agent_event_name};
use jaunt_store::{MAX_AUDIT_PAYLOAD_BYTES, Session, SessionKind};

pub(crate) const OBSERVED_AT: &str = "observed_at";
pub(crate) const SERVICE: &str = "service";
pub(crate) const CONTROL_FIELDS: &[&str] = &[OBSERVED_AT, SERVICE];
pub(crate) const FUTURE_SKEW_MS: i64 = 60_000;
pub(crate) const WITHHELD: &str = "[withheld]";
const QUERY_TEXT: &str = "text";
const TRUNCATED: &str = "truncated";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    Name,
    Kind,
    Field,
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Checked {
    pub(crate) kind: EventType,
    pub(crate) lifecycle: bool,
    pub(crate) observed_at: i64,
    pub(crate) fields: BTreeMap<String, AgentEventValue>,
    pub(crate) withheld: u64,
}

fn serves(kind: AgentEventKind, session: SessionKind) -> bool {
    matches!(
        (kind, session),
        (AgentEventKind::Kube, SessionKind::Kube)
            | (AgentEventKind::Db, SessionKind::Db)
            | (AgentEventKind::Tcp, SessionKind::Tcp)
    )
}

pub(crate) fn cut(text: &str, max: usize) -> &str {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn shape_fields(
    kind: EventType,
    lifecycle: bool,
    fields: &BTreeMap<String, AgentEventValue>,
) -> Result<(BTreeMap<String, AgentEventValue>, u64), Invalid> {
    let spec = kind.spec();
    let mut shaped = BTreeMap::new();
    let mut withheld = 0;
    for (name, value) in fields {
        if CONTROL_FIELDS.contains(&name.as_str()) {
            return Err(Invalid::Field);
        }
        let field = spec
            .fields
            .iter()
            .find(|field| field.name == name)
            .ok_or(Invalid::Field)?;
        let kept = match (field.kind, value) {
            (FieldKind::Text(max), AgentEventValue::Text(text)) => {
                if !lifecycle && text.len() > max {
                    return Err(Invalid::Field);
                }
                if is_withheld(text) {
                    withheld += 1;
                    AgentEventValue::Text(WITHHELD.to_owned())
                } else {
                    AgentEventValue::Text(cut(text, max).to_owned())
                }
            }
            (FieldKind::Int, AgentEventValue::Int(_))
            | (FieldKind::Bool, AgentEventValue::Bool(_)) => value.clone(),
            _ => return Err(Invalid::Field),
        };
        shaped.insert(name.clone(), kept);
    }
    Ok((shaped, withheld))
}

pub(crate) fn clamp_observed(observed_at: i64, session: &Session, now_ms: i64) -> i64 {
    let earliest = session.created_at.saturating_mul(1000);
    let latest = now_ms.saturating_add(FUTURE_SKEW_MS);
    observed_at.clamp(earliest, latest.max(earliest))
}

pub(crate) fn raw_fields<'a>(
    fields: &'a BTreeMap<String, AgentEventValue>,
    service: Option<&'a str>,
    observed_at: i64,
) -> Vec<(&'a str, RawValue)> {
    let mut raw: Vec<(&str, RawValue)> = fields
        .iter()
        .filter_map(|(name, value)| {
            let value = match value {
                AgentEventValue::Text(text) => RawValue::Text(text.clone()),
                AgentEventValue::Int(number) => RawValue::Signed(*number),
                AgentEventValue::Bool(flag) => RawValue::Bool(*flag),
                AgentEventValue::Invalid => return None,
            };
            Some((name.as_str(), value))
        })
        .collect();
    raw.push((OBSERVED_AT, RawValue::Signed(observed_at)));
    if let Some(service) = service {
        raw.push((SERVICE, RawValue::Text(service.to_owned())));
    }
    raw
}

pub(crate) fn stored_size(
    kind: EventType,
    fields: &BTreeMap<String, AgentEventValue>,
    service: Option<&str>,
    observed_at: i64,
) -> usize {
    let raw = raw_fields(fields, service, observed_at);
    match Timestamp::from_millis(0) {
        Ok(time) => {
            let (event, _) = AuditEvent::from_raw(kind, &raw, String::from("size"), time);
            event.payload_json().len()
        }
        Err(_) => usize::MAX,
    }
}

pub(crate) struct Fitting {
    left: usize,
    used: u64,
}

impl Fitting {
    pub(crate) fn new(left: usize) -> Fitting {
        Fitting { left, used: 0 }
    }

    pub(crate) fn used(&self) -> u64 {
        self.used
    }

    fn take(&mut self) -> bool {
        if self.left == 0 {
            return false;
        }
        self.left -= 1;
        self.used += 1;
        true
    }
}

fn fit_query(
    fields: &mut BTreeMap<String, AgentEventValue>,
    service: Option<&str>,
    observed_at: i64,
) -> Result<(), Invalid> {
    let Some(AgentEventValue::Text(text)) = fields.get(QUERY_TEXT).cloned() else {
        return Err(Invalid::TooLarge);
    };
    fields.insert(TRUNCATED.to_owned(), AgentEventValue::Bool(true));
    fields.insert(QUERY_TEXT.to_owned(), AgentEventValue::Text(String::new()));
    let base = stored_size(EventType::DbQuery, fields, service, observed_at);
    let budget = MAX_AUDIT_PAYLOAD_BYTES
        .checked_sub(base)
        .ok_or(Invalid::TooLarge)?;
    let mut used = 0_usize;
    let mut end = 0;
    for (at, c) in text.char_indices() {
        let stored = stored_char_len(c);
        if used + stored > budget {
            break;
        }
        used += stored;
        end = at + c.len_utf8();
    }
    if end == text.len() {
        end = text.char_indices().last().map_or(0, |(at, _)| at);
    }
    fields.insert(
        QUERY_TEXT.to_owned(),
        AgentEventValue::Text(text[..end].to_owned()),
    );
    if stored_size(EventType::DbQuery, fields, service, observed_at) > MAX_AUDIT_PAYLOAD_BYTES {
        return Err(Invalid::TooLarge);
    }
    Ok(())
}

pub(crate) fn check(
    event: &AgentEvent,
    session: &Session,
    now_ms: i64,
    fitting: &mut Fitting,
) -> Result<Checked, Invalid> {
    let known = agent_event_name(&event.name).ok_or(Invalid::Name)?;
    if !serves(known.kind, session.kind) {
        return Err(Invalid::Kind);
    }
    let kind = EventType::from_name(known.name).ok_or(Invalid::Name)?;
    let (mut fields, withheld) = shape_fields(kind, known.lifecycle, &event.fields)?;
    let observed_at = clamp_observed(event.observed_at, session, now_ms);
    let service = kind
        .spec()
        .fields
        .iter()
        .any(|field| field.name == SERVICE)
        .then_some(session.service_name.as_deref())
        .flatten();
    if stored_size(kind, &fields, service, observed_at) > MAX_AUDIT_PAYLOAD_BYTES {
        if kind != EventType::DbQuery || !fitting.take() {
            return Err(Invalid::TooLarge);
        }
        fit_query(&mut fields, service, observed_at)?;
    }
    Ok(Checked {
        kind,
        lifecycle: known.lifecycle,
        observed_at,
        fields,
        withheld,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jaunt_audit::{EventType, FieldKind};
    use jaunt_proto::{AGENT_EVENT_NAMES, AgentEvent, AgentEventValue};
    use jaunt_store::{MAX_AUDIT_PAYLOAD_BYTES, Session, SessionKind, SessionOrigin, SessionState};

    use super::{
        CONTROL_FIELDS, FUTURE_SKEW_MS, Fitting, Invalid, WITHHELD, check, clamp_observed, cut,
        stored_size,
    };

    const NOW_MS: i64 = 1_800_000_000_000;

    fn session(kind: SessionKind) -> Session {
        Session {
            id: "s-1".to_owned(),
            user_id: "u-1".to_owned(),
            serial: 1,
            node_id: "n-1".to_owned(),
            state: SessionState::Active,
            created_at: NOW_MS / 1000 - 600,
            expires_at: 0,
            authorized_at: Some(NOW_MS / 1000 - 600),
            ended_at: None,
            login: None,
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: None,
            origin: SessionOrigin::Ssh,
            record_input: None,
            kind,
            service_id: Some("svc".to_owned()),
            target: None,
            roles: Vec::new(),
            grant_ids: Vec::new(),
            db_client_serial: None,
            outcome: None,
            decision_hash: None,
            service_name: Some("prod".to_owned()),
            audit_incomplete: false,
            parent_session_id: None,
            record: None,
        }
    }

    fn event(name: &str, fields: &[(&str, AgentEventValue)]) -> AgentEvent {
        AgentEvent {
            session_id: "s-1".to_owned(),
            seq: 1,
            observed_at: NOW_MS,
            name: name.to_owned(),
            fields: fields
                .iter()
                .map(|(name, value)| ((*name).to_owned(), value.clone()))
                .collect(),
        }
    }

    fn text(value: &str) -> AgentEventValue {
        AgentEventValue::Text(value.to_owned())
    }

    fn kind_of(name: &str) -> SessionKind {
        match name.split('.').next() {
            Some("kube") => SessionKind::Kube,
            Some("db") => SessionKind::Db,
            _ => SessionKind::Tcp,
        }
    }

    fn full(kind: EventType) -> BTreeMap<String, AgentEventValue> {
        kind.spec()
            .fields
            .iter()
            .filter(|field| !CONTROL_FIELDS.contains(&field.name))
            .map(|field| {
                let value = match field.kind {
                    FieldKind::Text(max) => AgentEventValue::Text("x".repeat(max.min(32))),
                    FieldKind::Int => AgentEventValue::Int(-7),
                    FieldKind::Bool => AgentEventValue::Bool(true),
                };
                (field.name.to_owned(), value)
            })
            .collect()
    }

    fn text_of<'a>(fields: &'a BTreeMap<String, AgentEventValue>, name: &str) -> &'a str {
        match fields.get(name) {
            Some(AgentEventValue::Text(text)) => text,
            other => panic!("{name}: {other:?}"),
        }
    }

    #[test]
    fn every_agent_event_with_every_field_of_its_spec_is_accepted_for_its_kind_only() {
        for known in AGENT_EVENT_NAMES {
            let kind = EventType::from_name(known.name).unwrap();
            let mut complete = event(known.name, &[]);
            complete.fields = full(kind);
            for session_kind in [
                SessionKind::Kube,
                SessionKind::Db,
                SessionKind::Tcp,
                SessionKind::Ssh,
            ] {
                let checked = check(
                    &complete,
                    &session(session_kind),
                    NOW_MS,
                    &mut Fitting::new(16),
                );
                if session_kind == kind_of(known.name) {
                    let checked = checked.unwrap();
                    assert_eq!(checked.kind, kind);
                    assert_eq!(checked.lifecycle, known.lifecycle);
                    assert_eq!(checked.fields, complete.fields);
                    assert_eq!(checked.withheld, 0);
                } else {
                    assert_eq!(
                        checked,
                        Err(Invalid::Kind),
                        "{} {session_kind:?}",
                        known.name
                    );
                }
            }
            assert!(
                check(
                    &event(known.name, &[]),
                    &session(kind_of(known.name)),
                    NOW_MS,
                    &mut Fitting::new(16),
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn names_outside_the_agent_allow_list_are_refused_whatever_the_session() {
        for name in [
            "session.start",
            "session.audit_incomplete",
            "agent.events.dropped",
            "kube.tls.refused",
            "kube.session",
            "KUBE.SESSION.START",
            "",
        ] {
            assert_eq!(
                check(
                    &event(name, &[]),
                    &session(SessionKind::Kube),
                    NOW_MS,
                    &mut Fitting::new(16)
                ),
                Err(Invalid::Name),
                "{name}"
            );
        }
    }

    #[test]
    fn a_field_outside_the_spec_of_the_wrong_type_or_a_noisy_text_over_its_limit_refuses_the_event()
    {
        let kube = session(SessionKind::Kube);
        let request = "kube.request";
        assert!(
            check(
                &event(request, &[("verb", text(&"a".repeat(32)))]),
                &kube,
                NOW_MS,
                &mut Fitting::new(16),
            )
            .is_ok()
        );
        for (field, value) in [
            ("verb", text(&"a".repeat(33))),
            ("verb", AgentEventValue::Int(1)),
            ("verb", AgentEventValue::Invalid),
            ("status", text("200")),
            ("status", AgentEventValue::Bool(true)),
            ("status", AgentEventValue::Invalid),
            ("user_id", text("u-2")),
            ("node_id", text("n-2")),
            ("session_id", text("s-2")),
            ("policy_hash", text("forged")),
            ("actor", text("u-2")),
            ("kind", text("db")),
            ("roles", text("admin")),
            ("observed_at", AgentEventValue::Int(1)),
            ("service", text("other")),
            ("email", text("a@example.com")),
        ] {
            assert_eq!(
                check(
                    &event(request, &[(field, value.clone())]),
                    &kube,
                    NOW_MS,
                    &mut Fitting::new(16)
                ),
                Err(Invalid::Field),
                "{field} {value:?}"
            );
        }
        let db = session(SessionKind::Db);
        let at_limit = event("db.error", &[("error_message", text(&"é".repeat(256)))]);
        assert!(check(&at_limit, &db, NOW_MS, &mut Fitting::new(16)).is_ok());
        let over = event("db.error", &[("error_message", text(&"é".repeat(257)))]);
        assert_eq!(
            check(&over, &db, NOW_MS, &mut Fitting::new(16)),
            Err(Invalid::Field)
        );
        let start = event("db.session.start", &[("db_user", AgentEventValue::Int(1))]);
        assert_eq!(
            check(&start, &db, NOW_MS, &mut Fitting::new(16)),
            Err(Invalid::Field)
        );
    }

    #[test]
    fn a_lifecycle_text_over_its_limit_is_cut_at_a_character_boundary_and_the_event_kept() {
        let db = session(SessionKind::Db);
        let long = "€".repeat(100);
        let start = event(
            "db.session.start",
            &[("db_user", text(&long)), ("application_name", text("psql"))],
        );
        let checked = check(&start, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
        let kept = text_of(&checked.fields, "db_user");
        assert_eq!(kept, "€".repeat(42));
        assert_eq!(text_of(&checked.fields, "application_name"), "psql");
        for (value, max, expected) in [
            ("abc", 2, "ab"),
            ("abc", 3, "abc"),
            ("aé", 2, "a"),
            ("aé", 3, "aé"),
            ("€", 2, ""),
            ("", 0, ""),
        ] {
            assert_eq!(cut(value, max), expected, "{value} {max}");
        }
    }

    #[test]
    fn a_text_that_looks_like_a_secret_is_withheld_and_the_rest_of_the_event_is_kept() {
        let db = session(SessionKind::Db);
        let digest = "ab".repeat(32);
        for hidden in [
            "SELECT 1 -- bearer abc",
            "SELECT 1 /* Bearer\tabc */",
            "SELECT '-----BEGIN PRIVATE KEY-----'",
            "SELECT 1 -- \u{200b}Bearer abc",
        ] {
            let query = event(
                "db.query",
                &[
                    ("text", text(hidden)),
                    ("sha256", text(&digest)),
                    ("truncated", AgentEventValue::Bool(false)),
                ],
            );
            let checked = check(&query, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
            assert_eq!(text_of(&checked.fields, "text"), WITHHELD, "{hidden}");
            assert_eq!(text_of(&checked.fields, "sha256"), digest);
            assert_eq!(checked.fields["truncated"], AgentEventValue::Bool(false));
            assert_eq!(checked.withheld, 1);
        }
        let pem = event(
            "db.error",
            &[("error_message", text("bad -----BEGIN CERTIFICATE----- x"))],
        );
        let checked = check(&pem, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
        assert_eq!(text_of(&checked.fields, "error_message"), WITHHELD);
        let fine = event("db.query", &[("text", text("SELECT bearers FROM news"))]);
        let checked = check(&fine, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
        assert_eq!(text_of(&checked.fields, "text"), "SELECT bearers FROM news");
        assert_eq!(checked.withheld, 0);
    }

    fn query_fields(query: &str) -> BTreeMap<String, AgentEventValue> {
        [
            ("text", text(query)),
            ("sha256", text(&"cd".repeat(32))),
            ("protocol", text("simple")),
            ("command", text("SELECT")),
            ("truncated", AgentEventValue::Bool(false)),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect()
    }

    fn stored(fields: &BTreeMap<String, AgentEventValue>) -> usize {
        stored_size(EventType::DbQuery, fields, None, NOW_MS)
    }

    #[test]
    fn a_query_is_kept_whole_at_sixteen_kibibytes_and_cut_to_the_longest_prefix_one_byte_over() {
        let db = Session {
            service_name: None,
            ..session(SessionKind::Db)
        };
        let base = stored(&query_fields(""));
        let mixed = "\t\"\\\u{1}".repeat(1500);
        let escaped_mixed = stored(&query_fields(&mixed)) - base;
        assert_eq!(escaped_mixed, 15_000);
        let filler = MAX_AUDIT_PAYLOAD_BYTES - base - escaped_mixed;
        let exact = format!("{mixed}{}", "a".repeat(filler));
        assert!(exact.len() <= 8192);
        assert_eq!(stored(&query_fields(&exact)), MAX_AUDIT_PAYLOAD_BYTES);

        let mut whole = event("db.query", &[]);
        whole.fields = query_fields(&exact);
        let checked = check(&whole, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
        assert_eq!(checked.fields, whole.fields);

        for over in [
            format!("{exact}a"),
            format!("a{exact}"),
            format!("\u{1}{exact}"),
        ] {
            let mut long = event("db.query", &[]);
            long.fields = query_fields(&over);
            assert!(stored(&long.fields) > MAX_AUDIT_PAYLOAD_BYTES);
            let checked = check(&long, &db, NOW_MS, &mut Fitting::new(16)).unwrap();
            let kept = text_of(&checked.fields, "text");
            assert!(kept.len() < over.len() && over.starts_with(kept));
            assert_eq!(checked.fields["truncated"], AgentEventValue::Bool(true));
            assert_eq!(text_of(&checked.fields, "sha256"), "cd".repeat(32));
            assert!(stored(&checked.fields) <= MAX_AUDIT_PAYLOAD_BYTES);
            let next = over[kept.len()..].chars().next().unwrap();
            let extended = format!("{kept}{next}");
            if extended == over {
                assert_eq!(kept.len(), over.len() - next.len_utf8());
            } else {
                let mut longer = checked.fields.clone();
                longer.insert("text".to_owned(), text(&extended));
                assert!(stored(&longer) > MAX_AUDIT_PAYLOAD_BYTES, "{}", kept.len());
            }
        }
        let error = event("db.error", &[("error_message", text(&"\u{1}".repeat(256)))]);
        assert!(check(&error, &db, NOW_MS, &mut Fitting::new(16)).is_ok());
    }

    #[test]
    fn the_observed_time_is_clamped_between_the_session_start_and_a_minute_ahead() {
        let tcp = session(SessionKind::Tcp);
        let start = tcp.created_at * 1000;
        for (observed, expected) in [
            (i64::MIN, start),
            (0, start),
            (start - 1, start),
            (start, start),
            (NOW_MS, NOW_MS),
            (NOW_MS + FUTURE_SKEW_MS, NOW_MS + FUTURE_SKEW_MS),
            (NOW_MS + FUTURE_SKEW_MS + 1, NOW_MS + FUTURE_SKEW_MS),
            (i64::MAX, NOW_MS + FUTURE_SKEW_MS),
        ] {
            assert_eq!(
                clamp_observed(observed, &tcp, NOW_MS),
                expected,
                "{observed}"
            );
        }
        let mut late = event("tcp.session.end", &[]);
        late.observed_at = i64::MAX;
        assert_eq!(
            check(&late, &tcp, NOW_MS, &mut Fitting::new(16))
                .unwrap()
                .observed_at,
            NOW_MS + FUTURE_SKEW_MS
        );
    }

    #[test]
    fn eight_thousand_one_hundred_eighty_one_quotes_and_eleven_letters_fill_a_row_exactly() {
        let text = format!("{}{}", "\"".repeat(8181), "a".repeat(11));
        assert_eq!(text.len(), 8192);
        let escaped: usize = text.chars().map(jaunt_audit::stored_char_len).sum();
        assert_eq!(escaped + r#"{"text":""}"#.len(), MAX_AUDIT_PAYLOAD_BYTES);

        let db = Session {
            service_name: None,
            ..session(SessionKind::Db)
        };
        let base = stored(&query_fields(""));
        let quotes = MAX_AUDIT_PAYLOAD_BYTES - base - 8192;
        let exact = format!("{}{}", "\"".repeat(quotes), "a".repeat(8192 - quotes));
        assert_eq!(stored(&query_fields(&exact)), MAX_AUDIT_PAYLOAD_BYTES);
        let mut whole = event("db.query", &[]);
        whole.fields = query_fields(&exact);
        let mut fitting = Fitting::new(16);
        assert_eq!(
            check(&whole, &db, NOW_MS, &mut fitting).unwrap().fields,
            whole.fields
        );
        assert_eq!(fitting.used(), 0);
        let mut over = event("db.query", &[]);
        over.fields = query_fields(&exact.replacen('a', "\"", 1));
        let checked = check(&over, &db, NOW_MS, &mut fitting).unwrap();
        assert_eq!(checked.fields["truncated"], AgentEventValue::Bool(true));
        assert_eq!(fitting.used(), 1);
    }

    #[test]
    fn only_a_bounded_number_of_queries_per_request_are_cut_and_the_rest_are_refused() {
        let db = session(SessionKind::Db);
        let mut long = event("db.query", &[]);
        long.fields = query_fields(&"\u{1}".repeat(8000));
        let short = event("db.query", &[("text", text("SELECT 1"))]);
        let mut fitting = Fitting::new(2);
        assert!(check(&long, &db, NOW_MS, &mut fitting).is_ok());
        assert!(check(&short, &db, NOW_MS, &mut fitting).is_ok());
        assert!(check(&long, &db, NOW_MS, &mut fitting).is_ok());
        assert_eq!(
            check(&long, &db, NOW_MS, &mut fitting),
            Err(Invalid::TooLarge)
        );
        assert!(check(&short, &db, NOW_MS, &mut fitting).is_ok());
        assert_eq!(fitting.used(), 2);
    }
}
