use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const AGENT_EVENTS_PATH: &str = "/v1/agent/events";
pub const AGENT_EVENTS_MAX_BATCH: usize = 256;
pub const AGENT_EVENTS_MAX_DROPPED: usize = 256;
pub const AGENT_EVENTS_MAX_BODY_BYTES: usize = 256 * 1024;
pub const AGENT_EVENTS_MAX_REFUSED_SESSIONS: usize = 64;
pub const AGENT_EVENTS_INVALID_SESSION: &str = "invalid_session";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentEventKind {
    Kube,
    Db,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentEventName {
    pub name: &'static str,
    pub kind: AgentEventKind,
    pub lifecycle: bool,
}

const fn entry(name: &'static str, kind: AgentEventKind, lifecycle: bool) -> AgentEventName {
    AgentEventName {
        name,
        kind,
        lifecycle,
    }
}

pub const AGENT_EVENT_NAMES: &[AgentEventName] = &[
    entry("kube.session.start", AgentEventKind::Kube, true),
    entry("kube.session.end", AgentEventKind::Kube, true),
    entry("kube.request", AgentEventKind::Kube, false),
    entry("kube.exec.start", AgentEventKind::Kube, true),
    entry("kube.exec.end", AgentEventKind::Kube, true),
    entry("db.session.start", AgentEventKind::Db, true),
    entry("db.query", AgentEventKind::Db, false),
    entry("db.error", AgentEventKind::Db, false),
    entry("db.session.end", AgentEventKind::Db, true),
    entry("db.protocol_error", AgentEventKind::Db, true),
    entry("tcp.session.start", AgentEventKind::Tcp, true),
    entry("tcp.session.end", AgentEventKind::Tcp, true),
];

pub fn agent_event_name(name: &str) -> Option<&'static AgentEventName> {
    AGENT_EVENT_NAMES.iter().find(|known| known.name == name)
}

#[derive(Clone, PartialEq, Eq)]
pub enum AgentEventValue {
    Text(String),
    Int(i64),
    Bool(bool),
    Invalid,
}

impl fmt::Debug for AgentEventValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentEventValue::Text(text) => write!(f, "Text({} bytes)", text.len()),
            AgentEventValue::Int(number) => write!(f, "Int({number})"),
            AgentEventValue::Bool(flag) => write!(f, "Bool({flag})"),
            AgentEventValue::Invalid => f.write_str("Invalid"),
        }
    }
}

impl Serialize for AgentEventValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            AgentEventValue::Text(text) => serializer.serialize_str(text),
            AgentEventValue::Int(number) => serializer.serialize_i64(*number),
            AgentEventValue::Bool(flag) => serializer.serialize_bool(*flag),
            AgentEventValue::Invalid => serializer.serialize_unit(),
        }
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = AgentEventValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an audit field value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<AgentEventValue, E> {
        Ok(i64::try_from(value).map_or(AgentEventValue::Invalid, AgentEventValue::Int))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Invalid)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Text(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Text(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Invalid)
    }

    fn visit_none<E: de::Error>(self) -> Result<AgentEventValue, E> {
        Ok(AgentEventValue::Invalid)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<AgentEventValue, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(AgentEventValue::Invalid)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<AgentEventValue, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(AgentEventValue::Invalid)
    }
}

impl<'de> Deserialize<'de> for AgentEventValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<AgentEventValue, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    pub session_id: String,
    pub seq: u64,
    pub observed_at: i64,
    pub name: String,
    pub fields: BTreeMap<String, AgentEventValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DroppedEvents {
    pub session_id: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEventBatch {
    pub events: Vec<AgentEvent>,
    pub dropped: Vec<DroppedEvents>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEventsAccepted {
    pub accepted: u64,
    pub dropped: u64,
    #[serde(default)]
    pub withheld: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentEventsRefusal {
    pub error: String,
    #[serde(default)]
    pub sessions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AGENT_EVENT_NAMES, AgentEventBatch, AgentEventKind, AgentEventValue, agent_event_name,
    };

    fn batch(event: serde_json::Value) -> serde_json::Value {
        json!({"events": [event], "dropped": []})
    }

    fn event() -> serde_json::Value {
        json!({"session_id": "s", "seq": 1, "observed_at": 5, "name": "tcp.session.start",
               "fields": {"client_addr": "203.0.113.1:5"}})
    }

    #[test]
    fn the_batch_and_its_events_refuse_any_field_the_agent_may_not_set() {
        assert!(serde_json::from_value::<AgentEventBatch>(batch(event())).is_ok());
        for forged in [
            "actor",
            "user_id",
            "node_id",
            "policy_hash",
            "kind",
            "service",
            "time",
        ] {
            let mut forged_event = event();
            forged_event[forged] = json!("x");
            assert!(
                serde_json::from_value::<AgentEventBatch>(batch(forged_event)).is_err(),
                "{forged}"
            );
            let mut forged_batch = batch(event());
            forged_batch[forged] = json!("x");
            assert!(
                serde_json::from_value::<AgentEventBatch>(forged_batch).is_err(),
                "{forged}"
            );
        }
        for missing in ["session_id", "seq", "observed_at", "name", "fields"] {
            let mut partial = event();
            partial.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<AgentEventBatch>(batch(partial)).is_err(),
                "{missing}"
            );
        }
        assert!(serde_json::from_value::<AgentEventBatch>(json!({"events": []})).is_err());
    }

    #[test]
    fn field_values_of_another_shape_parse_as_invalid_instead_of_failing_the_batch() {
        let mut odd = event();
        odd["fields"] = json!({
            "a": "text", "b": -3, "c": true, "d": 1.5, "e": null, "f": [1, [2]],
            "g": {"x": {"y": 1}}, "h": u64::MAX
        });
        let parsed: AgentEventBatch = serde_json::from_value(batch(odd)).unwrap();
        let fields = &parsed.events[0].fields;
        assert_eq!(fields["a"], AgentEventValue::Text("text".to_owned()));
        assert_eq!(fields["b"], AgentEventValue::Int(-3));
        assert_eq!(fields["c"], AgentEventValue::Bool(true));
        for invalid in ["d", "e", "f", "g", "h"] {
            assert_eq!(fields[invalid], AgentEventValue::Invalid, "{invalid}");
        }
        let wire = serde_json::to_value(&parsed).unwrap();
        assert_eq!(wire["events"][0]["fields"]["a"], "text");
    }

    #[test]
    fn answers_need_their_first_fields_read_later_additions_as_zero_and_ignore_unknown_ones() {
        let refusal: super::AgentEventsRefusal =
            serde_json::from_value(json!({"error": "invalid_session", "sessions": ["a", "b"]}))
                .unwrap();
        assert_eq!(refusal.sessions, ["a", "b"]);
        let newer: super::AgentEventsRefusal = serde_json::from_value(
            json!({"error": "invalid_session", "sessions": ["a"], "reason": "x"}),
        )
        .unwrap();
        assert_eq!(newer.sessions, ["a"]);
        let older: super::AgentEventsAccepted =
            serde_json::from_value(json!({"accepted": 1, "dropped": 2})).unwrap();
        assert_eq!(older.withheld, 0);
        let newer: super::AgentEventsAccepted = serde_json::from_value(
            json!({"accepted": 1, "dropped": 0, "withheld": 3, "later": true}),
        )
        .unwrap();
        assert_eq!((newer.accepted, newer.withheld), (1, 3));
        for partial in [
            json!({}),
            json!({"later": true}),
            json!({"error": "x"}),
            json!({"accepted": 1}),
            json!({"dropped": 1, "withheld": 1}),
        ] {
            assert!(
                serde_json::from_value::<super::AgentEventsAccepted>(partial.clone()).is_err(),
                "{partial}"
            );
        }
    }

    #[test]
    fn the_debug_form_of_a_value_hides_its_text() {
        let shown = format!("{:?}", AgentEventValue::Text("SELECT secret".to_owned()));
        assert!(!shown.contains("secret"), "{shown}");
    }

    #[test]
    fn every_agent_event_belongs_to_the_kind_its_name_starts_with() {
        for known in AGENT_EVENT_NAMES {
            let prefix = match known.kind {
                AgentEventKind::Kube => "kube.",
                AgentEventKind::Db => "db.",
                AgentEventKind::Tcp => "tcp.",
            };
            assert!(known.name.starts_with(prefix), "{}", known.name);
            assert_eq!(agent_event_name(known.name), Some(known));
        }
        assert_eq!(agent_event_name("session.start"), None);
        assert_eq!(agent_event_name("kube.tls.refused"), None);
    }
}
