use std::collections::BTreeMap;

use jaunt_proto::{ADMIN_TOKEN_LEN, ADMIN_TOKEN_PREFIX, admin_token_id};
use jaunt_store::AuditRecord;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};

use crate::spec::{
    ActorRule, DISCARDED_FIELDS, ENVELOPE_TEXT_MAX, EventSpec, EventType, FieldKind, FieldSpec,
};
use crate::time::{TimeError, Timestamp};

pub const SCHEMA_VERSION: u8 = 1;

const SYSTEM_ACTOR: &str = "system";
const ANONYMOUS_ACTOR: &str = "anonymous";
const NODE_ACTOR_PREFIX: &str = "node:";
const PEM_MARKER: &str = "-----begin";
const BEARER_WORD: &str = "bearer";
const SSH_CERTIFICATE_MARKER: &str = "-cert-v01@openssh.com";
const REPLACEMENT: char = '\u{fffd}';
const MAX_REPORTED_NAMES: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    Text(String),
    Signed(i64),
    Unsigned(u64),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Text(String),
    Int(i64),
    Bool(bool),
}

impl Serialize for FieldValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            FieldValue::Text(text) => serializer.serialize_str(text),
            FieldValue::Int(number) => serializer.serialize_i64(*number),
            FieldValue::Bool(flag) => serializer.serialize_bool(*flag),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Actor {
    User(String),
    Node(String),
    System,
    Anonymous,
}

impl Actor {
    pub fn as_wire(&self) -> String {
        match self {
            Actor::User(id) => id.clone(),
            Actor::Node(id) => format!("{NODE_ACTOR_PREFIX}{id}"),
            Actor::System => SYSTEM_ACTOR.to_owned(),
            Actor::Anonymous => ANONYMOUS_ACTOR.to_owned(),
        }
    }

    pub fn from_wire(text: &str) -> Actor {
        match text {
            SYSTEM_ACTOR => Actor::System,
            ANONYMOUS_ACTOR => Actor::Anonymous,
            other => match other.strip_prefix(NODE_ACTOR_PREFIX) {
                Some(id) => Actor::Node(id.to_owned()),
                None => Actor::User(other.to_owned()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub(crate) id: String,
    pub(crate) kind: EventType,
    pub(crate) time: Timestamp,
    pub(crate) actor: Actor,
    pub(crate) node: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) policy_hash: Option<String>,
    pub(crate) fields: BTreeMap<&'static str, FieldValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BuildReport {
    pub fields_dropped: usize,
    pub dropped_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    #[error("the event is not valid JSON")]
    NotJson,
    #[error("the event has an unsupported schema version")]
    UnsupportedVersion,
    #[error("the event type is not known")]
    UnknownType,
    #[error("the event has an invalid time: {0}")]
    Time(#[from] TimeError),
    #[error("the event has an invalid envelope")]
    Envelope,
}

fn is_invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{ad}'
                | '\u{600}'..='\u{605}'
                | '\u{61c}'
                | '\u{6dd}'
                | '\u{70f}'
                | '\u{890}'..='\u{891}'
                | '\u{8e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || c == REPLACEMENT
}

fn has_bearer_credential(lowered: &str) -> bool {
    lowered.match_indices(BEARER_WORD).any(|(at, word)| {
        let before = lowered[..at].chars().next_back();
        let after = lowered[at + word.len()..].chars().next();
        before.is_none_or(|c| !c.is_alphanumeric()) && after.is_some_and(is_separator)
    })
}

fn has_admin_token(value: &str) -> bool {
    value.match_indices(ADMIN_TOKEN_PREFIX).any(|(at, _)| {
        value
            .get(at..at.saturating_add(ADMIN_TOKEN_LEN))
            .is_some_and(|candidate| admin_token_id(candidate).is_some())
    })
}

fn looks_secret(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains(PEM_MARKER)
        || lowered.contains(SSH_CERTIFICATE_MARKER)
        || has_bearer_credential(&lowered)
        || has_admin_token(value)
}

pub fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let sanitized: String = value
        .chars()
        .map(|c| if is_invisible(c) { REPLACEMENT } else { c })
        .collect();
    if looks_secret(value) || looks_secret(&sanitized) {
        return None;
    }
    Some(sanitized.chars().take(max_chars).collect())
}

fn envelope_text(raw: &[(&str, RawValue)], name: Option<&str>) -> Option<String> {
    let name = name?;
    let (_, value) = raw.iter().rev().find(|(field, _)| *field == name)?;
    match value {
        RawValue::Text(text) => clean_text(text, ENVELOPE_TEXT_MAX).filter(|text| !text.is_empty()),
        RawValue::Signed(_) | RawValue::Unsigned(_) | RawValue::Bool(_) => None,
    }
}

fn coerce(spec: &FieldSpec, value: &RawValue) -> Option<FieldValue> {
    match (spec.kind, value) {
        (FieldKind::Text(max), RawValue::Text(text)) => clean_text(text, max).map(FieldValue::Text),
        (FieldKind::Text(max), RawValue::Signed(number)) => {
            clean_text(&number.to_string(), max).map(FieldValue::Text)
        }
        (FieldKind::Text(max), RawValue::Unsigned(number)) => {
            clean_text(&number.to_string(), max).map(FieldValue::Text)
        }
        (FieldKind::Int, RawValue::Signed(number)) => Some(FieldValue::Int(*number)),
        (FieldKind::Int, RawValue::Unsigned(number)) => {
            i64::try_from(*number).ok().map(FieldValue::Int)
        }
        (FieldKind::Bool, RawValue::Bool(flag)) => Some(FieldValue::Bool(*flag)),
        _ => None,
    }
}

impl AuditEvent {
    pub fn from_raw(
        kind: EventType,
        raw: &[(&str, RawValue)],
        id: String,
        time: Timestamp,
    ) -> (AuditEvent, BuildReport) {
        let spec = kind.spec();
        let mut report = BuildReport::default();
        let mut fields = BTreeMap::new();
        for field in spec.fields {
            let Some((_, value)) = raw.iter().rev().find(|(name, _)| *name == field.name) else {
                continue;
            };
            match coerce(field, value) {
                Some(value) => {
                    fields.insert(field.name, value);
                }
                None => report.note_dropped(field.name),
            }
        }
        let mut seen: Vec<&str> = Vec::new();
        for (name, _) in raw {
            if !seen.contains(name) && !is_known_name(spec, name) {
                report.note_dropped(name);
            }
            seen.push(name);
        }
        let event = AuditEvent {
            id,
            kind,
            time,
            actor: actor_for(spec, raw),
            node: envelope_text(raw, spec.node),
            session_id: envelope_text(raw, spec.session),
            policy_hash: envelope_text(raw, spec.policy_hash),
            fields,
        };
        (event, report)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> EventType {
        self.kind
    }

    pub fn time(&self) -> Timestamp {
        self.time
    }

    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    pub fn node(&self) -> Option<&str> {
        self.node.as_deref()
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn policy_hash(&self) -> Option<&str> {
        self.policy_hash.as_deref()
    }

    pub fn fields(&self) -> &BTreeMap<&'static str, FieldValue> {
        &self.fields
    }

    pub fn text(&self, name: &str) -> Option<&str> {
        match self.fields.get(name) {
            Some(FieldValue::Text(text)) => Some(text),
            _ => None,
        }
    }

    pub fn int(&self, name: &str) -> Option<i64> {
        match self.fields.get(name) {
            Some(FieldValue::Int(number)) => Some(*number),
            _ => None,
        }
    }

    pub fn flag(&self, name: &str) -> Option<bool> {
        match self.fields.get(name) {
            Some(FieldValue::Bool(flag)) => Some(*flag),
            _ => None,
        }
    }

    pub fn payload_json(&self) -> String {
        serde_json::to_string(&self.fields).unwrap_or_else(|_| "{}".to_owned())
    }

    pub fn to_record(&self) -> AuditRecord {
        AuditRecord {
            id: self.id.clone(),
            time_ms: self.time.millis(),
            event_type: self.kind.name().to_owned(),
            actor: self.actor.as_wire(),
            node: self.node.clone(),
            session_id: self.session_id.clone(),
            policy_hash: self.policy_hash.clone(),
            payload: self.payload_json(),
            v: i64::from(SCHEMA_VERSION),
        }
    }

    pub fn from_record(record: &AuditRecord) -> Result<AuditEvent, EventError> {
        let payload: serde_json::Value =
            serde_json::from_str(&record.payload).map_err(|_| EventError::NotJson)?;
        AuditEvent::from_parts(Parts {
            v: record.v,
            id: &record.id,
            event_type: &record.event_type,
            time: Timestamp::from_millis(record.time_ms)?,
            actor: &record.actor,
            node: record.node.as_deref(),
            session_id: record.session_id.as_deref(),
            policy_hash: record.policy_hash.as_deref(),
            fields: &payload,
        })
    }

    pub fn from_json_line(line: &str) -> Result<AuditEvent, EventError> {
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|_| EventError::NotJson)?;
        let object = value.as_object().ok_or(EventError::Envelope)?;
        let text = |name: &str| object.get(name).and_then(serde_json::Value::as_str);
        let optional = |name: &str| match object.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(text)) => Ok(Some(text.as_str())),
            Some(_) => Err(EventError::Envelope),
        };
        let v = object
            .get("v")
            .and_then(serde_json::Value::as_i64)
            .ok_or(EventError::Envelope)?;
        let time = Timestamp::parse(text("time").ok_or(EventError::Envelope)?)?;
        let empty = serde_json::Value::Object(serde_json::Map::new());
        AuditEvent::from_parts(Parts {
            v,
            id: text("id").ok_or(EventError::Envelope)?,
            event_type: text("type").ok_or(EventError::Envelope)?,
            time,
            actor: text("actor").ok_or(EventError::Envelope)?,
            node: optional("node")?,
            session_id: optional("session_id")?,
            policy_hash: optional("policy_hash")?,
            fields: object.get("fields").unwrap_or(&empty),
        })
    }

    fn from_parts(parts: Parts<'_>) -> Result<AuditEvent, EventError> {
        if parts.v != i64::from(SCHEMA_VERSION) {
            return Err(EventError::UnsupportedVersion);
        }
        let kind = EventType::from_name(parts.event_type).ok_or(EventError::UnknownType)?;
        let spec = kind.spec();
        let mut fields = BTreeMap::new();
        if let Some(object) = parts.fields.as_object() {
            for field in spec.fields {
                if let Some(value) = object.get(field.name).and_then(|value| typed(field, value)) {
                    fields.insert(field.name, value);
                }
            }
        }
        let clean = |text: Option<&str>| {
            text.and_then(|text| clean_text(text, ENVELOPE_TEXT_MAX))
                .filter(|text| !text.is_empty())
        };
        if parts.id.is_empty() || parts.actor.is_empty() {
            return Err(EventError::Envelope);
        }
        Ok(AuditEvent {
            id: parts.id.to_owned(),
            kind,
            time: parts.time,
            actor: Actor::from_wire(parts.actor),
            node: clean(parts.node),
            session_id: clean(parts.session_id),
            policy_hash: clean(parts.policy_hash),
            fields,
        })
    }
}

impl BuildReport {
    fn note_dropped(&mut self, name: &str) {
        self.fields_dropped += 1;
        if self.dropped_names.len() < MAX_REPORTED_NAMES {
            self.dropped_names.push(name.to_owned());
        }
    }
}

fn is_known_name(spec: &EventSpec, name: &str) -> bool {
    let actor_source = match spec.actor {
        ActorRule::User(field) | ActorRule::Node(field) => Some(field),
        ActorRule::System | ActorRule::Anonymous => None,
    };
    DISCARDED_FIELDS.contains(&name)
        || spec.fields.iter().any(|field| field.name == name)
        || [actor_source, spec.node, spec.session, spec.policy_hash]
            .into_iter()
            .flatten()
            .any(|source| source == name)
}

struct Parts<'a> {
    v: i64,
    id: &'a str,
    event_type: &'a str,
    time: Timestamp,
    actor: &'a str,
    node: Option<&'a str>,
    session_id: Option<&'a str>,
    policy_hash: Option<&'a str>,
    fields: &'a serde_json::Value,
}

fn typed(spec: &FieldSpec, value: &serde_json::Value) -> Option<FieldValue> {
    match (spec.kind, value) {
        (FieldKind::Text(max), serde_json::Value::String(text)) => {
            clean_text(text, max).map(FieldValue::Text)
        }
        (FieldKind::Int, serde_json::Value::Number(number)) => number.as_i64().map(FieldValue::Int),
        (FieldKind::Bool, serde_json::Value::Bool(flag)) => Some(FieldValue::Bool(*flag)),
        _ => None,
    }
}

fn actor_for(spec: &EventSpec, raw: &[(&str, RawValue)]) -> Actor {
    match spec.actor {
        ActorRule::System => Actor::System,
        ActorRule::Anonymous => Actor::Anonymous,
        ActorRule::User(field) => {
            envelope_text(raw, Some(field)).map_or(Actor::Anonymous, Actor::User)
        }
        ActorRule::Node(field) => {
            envelope_text(raw, Some(field)).map_or(Actor::Anonymous, Actor::Node)
        }
    }
}

impl Serialize for AuditEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("v", &SCHEMA_VERSION)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("type", self.kind.name())?;
        map.serialize_entry("time", &self.time.to_string())?;
        map.serialize_entry("actor", &self.actor.as_wire())?;
        if let Some(node) = &self.node {
            map.serialize_entry("node", node)?;
        }
        if let Some(session_id) = &self.session_id {
            map.serialize_entry("session_id", session_id)?;
        }
        if let Some(policy_hash) = &self.policy_hash {
            map.serialize_entry("policy_hash", policy_hash)?;
        }
        map.serialize_entry("fields", &self.fields)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{Actor, AuditEvent, EventError, FieldValue, RawValue, clean_text};
    use crate::spec::ActorRule;
    use crate::spec::{EventType, FieldKind};
    use crate::time::Timestamp;

    fn at() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_123).unwrap()
    }

    fn raw(items: &[(&'static str, RawValue)]) -> Vec<(&'static str, RawValue)> {
        items.to_vec()
    }

    fn sample_for(kind: EventType) -> Vec<(&'static str, RawValue)> {
        let spec = kind.spec();
        let mut items = vec![
            ("node_id", RawValue::Text("node-1".to_owned())),
            ("node", RawValue::Text("node-1".to_owned())),
            ("session_id", RawValue::Text("sess-1".to_owned())),
            ("policy_hash", RawValue::Text("hash-1".to_owned())),
            ("hash", RawValue::Text("hash-1".to_owned())),
            ("user_id", RawValue::Text("user-1".to_owned())),
            ("approved_by", RawValue::Text("user-1".to_owned())),
        ];
        let mut sources: Vec<&str> = [spec.node, spec.session, spec.policy_hash]
            .into_iter()
            .flatten()
            .collect();
        if let ActorRule::User(field) | ActorRule::Node(field) = spec.actor {
            sources.push(field);
        }
        items.retain(|(name, _)| sources.contains(name));
        for field in spec.fields {
            let value = match field.kind {
                FieldKind::Text(_) => RawValue::Text(format!("{}-value", field.name)),
                FieldKind::Int => RawValue::Signed(42),
                FieldKind::Bool => RawValue::Bool(true),
            };
            items.push((field.name, value));
        }
        items
    }

    #[test]
    fn every_event_type_round_trips_through_json_and_the_stored_record() {
        for kind in EventType::ALL {
            let (event, report) =
                AuditEvent::from_raw(*kind, &sample_for(*kind), "id-1".to_owned(), at());
            assert_eq!(report.fields_dropped, 0, "{}", kind.name());
            assert_eq!(
                event.fields.len(),
                kind.spec().fields.len(),
                "{}",
                kind.name()
            );

            let line = serde_json::to_string(&event).unwrap();
            assert!(!line.contains('\n'));
            assert_eq!(AuditEvent::from_json_line(&line).unwrap(), event, "{line}");
            assert_eq!(AuditEvent::from_record(&event.to_record()).unwrap(), event);
        }
    }

    #[test]
    fn the_envelope_carries_actor_node_session_and_policy_hash_per_the_spec() {
        let items = raw(&[
            ("user_id", RawValue::Text("user-9".to_owned())),
            ("node_id", RawValue::Text("n-1".to_owned())),
            ("session_id", RawValue::Text("s-1".to_owned())),
            ("policy_hash", RawValue::Text("abc".to_owned())),
            ("serial", RawValue::Unsigned(7)),
        ]);

        let (event, _) =
            AuditEvent::from_raw(EventType::SessionStart, &items, "i".to_owned(), at());

        assert_eq!(event.actor, Actor::User("user-9".to_owned()));
        assert_eq!(event.node.as_deref(), Some("n-1"));
        assert_eq!(event.session_id.as_deref(), Some("s-1"));
        assert_eq!(event.policy_hash.as_deref(), Some("abc"));
        assert_eq!(event.int("serial"), Some(7));
        assert!(!event.fields.contains_key("user_id"));
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["v"], 1);
        assert_eq!(json["type"], "session.start");
        assert_eq!(json["time"], "2023-11-14T22:13:20.123Z");
        assert_eq!(json["actor"], "user-9");
    }

    #[test]
    fn actors_fall_back_by_rule_and_node_actors_are_prefixed() {
        let cases = [
            (EventType::LoginStarted, vec![], Actor::Anonymous),
            (EventType::PolicyReload, vec![], Actor::System),
            (EventType::CertIssued, vec![], Actor::Anonymous),
            (
                EventType::NodeCertRenewed,
                vec![("node_id", RawValue::Text("n-7".to_owned()))],
                Actor::Node("n-7".to_owned()),
            ),
        ];
        for (kind, items, expected) in cases {
            let (event, _) = AuditEvent::from_raw(kind, &items, "i".to_owned(), at());
            assert_eq!(event.actor, expected, "{}", kind.name());
        }
        assert_eq!(Actor::Node("n-7".to_owned()).as_wire(), "node:n-7");
        assert_eq!(Actor::from_wire("node:n-7"), Actor::Node("n-7".to_owned()));
        assert_eq!(Actor::from_wire("system"), Actor::System);
        assert_eq!(Actor::from_wire("anonymous"), Actor::Anonymous);
        assert_eq!(Actor::from_wire("u-1"), Actor::User("u-1".to_owned()));
    }

    #[test]
    fn fields_outside_the_allow_list_are_dropped_and_wrong_types_are_counted() {
        let items = raw(&[
            ("login_id", RawValue::Text("l-1".to_owned())),
            ("email", RawValue::Text("ada@example.com".to_owned())),
            ("api_token", RawValue::Text("tok-secret".to_owned())),
            ("completion_code", RawValue::Text("code-secret".to_owned())),
            ("key_id", RawValue::Text("ada@example.com:7".to_owned())),
            ("serial", RawValue::Text("not a number".to_owned())),
            ("kind", RawValue::Bool(true)),
        ]);

        let (event, report) =
            AuditEvent::from_raw(EventType::LoginApproved, &items, "i".to_owned(), at());

        let line = serde_json::to_string(&event).unwrap();
        for leaked in ["ada@example.com", "tok-secret", "code-secret", "api_token"] {
            assert!(!line.contains(leaked), "{line}");
        }
        assert_eq!(
            event.fields.keys().copied().collect::<Vec<_>>(),
            ["login_id"]
        );
        assert_eq!(report.fields_dropped, 5);
        assert_eq!(
            report.dropped_names,
            ["kind", "api_token", "completion_code"]
        );
    }

    #[test]
    fn values_are_bounded_control_free_and_pem_blocks_are_refused() {
        let long = "x".repeat(500);
        let items = raw(&[
            ("login_id", RawValue::Text(long)),
            (
                "reason",
                RawValue::Text("line one\nline two\u{1b}[31m\0".to_owned()),
            ),
        ]);

        let (event, report) =
            AuditEvent::from_raw(EventType::LoginDenied, &items, "i".to_owned(), at());

        assert_eq!(event.text("login_id").unwrap().chars().count(), 64);
        let reason = event.text("reason").unwrap();
        assert!(!reason.chars().any(char::is_control), "{reason:?}");
        assert_eq!(report.fields_dropped, 0);

        let pem = RawValue::Text("-----BEGIN PRIVATE KEY-----\nAAAA".to_owned());
        let (event, report) = AuditEvent::from_raw(
            EventType::LoginDenied,
            &raw(&[("reason", pem.clone()), ("user_id", pem)]),
            "i".to_owned(),
            at(),
        );
        assert!(event.fields.is_empty());
        assert_eq!(report.fields_dropped, 2);
        assert_eq!(clean_text("é".repeat(10).as_str(), 3).unwrap(), "ééé");
    }

    #[test]
    fn invisible_characters_are_replaced_and_secret_shapes_are_refused_in_any_case() {
        for invisible in [
            "a\u{202e}b",
            "a\u{200b}b",
            "a\u{feff}b",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{ad}b",
            "a\u{2066}b",
            "a\u{e0041}b",
        ] {
            let cleaned = clean_text(invisible, 32);
            assert_eq!(cleaned.as_deref(), Some("a\u{fffd}b"), "{invisible:?}");
        }
        for secret in [
            "-----begin private key-----",
            "-----Begin RSA PRIVATE KEY-----",
            "x -----BEGIN CERTIFICATE-----",
            "Bearer abc.def",
            "  bearer abc",
            "BEARER abc",
            "\u{200b}Bearer abc",
            "Bearer\tabc",
            "Bearer\u{200b}abc",
            "Bearer\nabc",
            "Authorization: Bearer x",
            "x:Bearer\u{a0}token",
            "-----BEG\u{200b}IN KEY-----bearer\u{2028}x",
            "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5",
            "ecdsa-sha2-nistp256-cert-v01@OPENSSH.COM AAAA",
            "jat_AbC-_09xyzQ_s3cr3t-s3cr3t_s3cr3t-s3cr3t_s3cr3t-s3cr3t_Z",
            "token=jat_AbC-_09xyzQ_s3cr3t-s3cr3t_s3cr3t-s3cr3t_s3cr3t-s3cr3t_Z;",
        ] {
            assert_eq!(clean_text(secret, 512), None, "{secret:?}");
        }
        for fine in [
            "bearer",
            "bearers of news",
            "carbearer x",
            "jat_short",
            "token:AbC-_09xyzQ",
            "ssh-ed25519 AAAA",
            "deploy",
        ] {
            assert_eq!(clean_text(fine, 512).as_deref(), Some(fine), "{fine:?}");
        }
    }

    #[test]
    fn reading_drops_foreign_fields_and_refuses_bad_envelopes() {
        let line = json!({
            "v": 1, "id": "i", "type": "login.started", "time": "2023-11-14T22:13:20.123Z",
            "actor": "anonymous",
            "fields": {"login_id": "l-1", "email": "x@example.com", "secret": "s"}
        })
        .to_string();
        let event = AuditEvent::from_json_line(&line).unwrap();
        assert_eq!(
            event.fields.get("login_id"),
            Some(&FieldValue::Text("l-1".to_owned()))
        );
        assert_eq!(event.fields.len(), 1);

        let base = json!({
            "v": 1, "id": "i", "type": "login.started", "time": "2023-11-14T22:13:20.123Z",
            "actor": "anonymous", "fields": {}
        });
        let with = |key: &str, value: serde_json::Value| {
            let mut changed = base.clone();
            changed[key] = value;
            changed.to_string()
        };
        for (line, expected) in [
            ("nope".to_owned(), EventError::NotJson),
            ("[]".to_owned(), EventError::Envelope),
            (with("v", json!(2)), EventError::UnsupportedVersion),
            (
                with("type", json!("web.login.started")),
                EventError::UnknownType,
            ),
            (with("actor", json!("")), EventError::Envelope),
            (with("node", json!(5)), EventError::Envelope),
        ] {
            assert_eq!(
                AuditEvent::from_json_line(&line).unwrap_err(),
                expected,
                "{line}"
            );
        }
        assert!(matches!(
            AuditEvent::from_json_line(&with("time", json!("yesterday"))),
            Err(EventError::Time(_))
        ));
    }
}
