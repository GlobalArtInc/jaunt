use jaunt_store::{AuditCursor, AuditQuery, Store, StoreError};
use serde::Serialize;

use crate::event::AuditEvent;
use crate::time::Timestamp;

pub const DEFAULT_PAGE: u32 = 50;
pub const MAX_PAGE: u32 = 200;

const MAX_TYPE_PREFIX_CHARS: usize = 64;
const MAX_FILTER_TEXT_CHARS: usize = 128;
const MAX_CURSOR_ID_CHARS: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FilterError {
    #[error("unknown query parameter")]
    UnknownParameter,
    #[error("a query parameter is repeated")]
    DuplicateParameter,
    #[error("the type filter is not valid")]
    InvalidType,
    #[error("the actor filter is not valid")]
    InvalidActor,
    #[error("the node filter is not valid")]
    InvalidNode,
    #[error("the session filter is not valid")]
    InvalidSession,
    #[error("a time filter is not an RFC 3339 UTC timestamp")]
    InvalidTime,
    #[error("the time range is empty")]
    InvalidRange,
    #[error("the limit is not valid")]
    InvalidLimit,
    #[error("the cursor is not valid")]
    InvalidCursor,
}

impl FilterError {
    pub fn code(&self) -> &'static str {
        match self {
            FilterError::UnknownParameter => "unknown_parameter",
            FilterError::DuplicateParameter => "duplicate_parameter",
            FilterError::InvalidType => "invalid_type",
            FilterError::InvalidActor => "invalid_actor",
            FilterError::InvalidNode => "invalid_node",
            FilterError::InvalidSession => "invalid_session",
            FilterError::InvalidTime => "invalid_time",
            FilterError::InvalidRange => "invalid_range",
            FilterError::InvalidLimit => "invalid_limit",
            FilterError::InvalidCursor => "invalid_cursor",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("the audit query failed: {0}")]
    Store(#[from] StoreError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFilter {
    pub type_prefix: Option<String>,
    pub actor: Option<String>,
    pub node: Option<String>,
    pub session_id: Option<String>,
    pub from: Option<Timestamp>,
    pub to: Option<Timestamp>,
    pub limit: u32,
    pub cursor: Option<AuditCursor>,
}

#[derive(Debug, Serialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_cursor: Option<String>,
}

impl AuditFilter {
    pub fn from_pairs<K, V>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<AuditFilter, FilterError>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut filter = AuditFilter {
            type_prefix: None,
            actor: None,
            node: None,
            session_id: None,
            from: None,
            to: None,
            limit: DEFAULT_PAGE,
            cursor: None,
        };
        let mut seen: Vec<String> = Vec::new();
        for (key, value) in pairs {
            let (key, value) = (key.as_ref(), value.as_ref());
            if seen.iter().any(|earlier| earlier == key) {
                return Err(FilterError::DuplicateParameter);
            }
            seen.push(key.to_owned());
            match key {
                "type" => filter.type_prefix = Some(type_prefix(value)?),
                "actor" => {
                    filter.actor = Some(text(value).ok_or(FilterError::InvalidActor)?);
                }
                "node" => filter.node = Some(text(value).ok_or(FilterError::InvalidNode)?),
                "session" => {
                    filter.session_id = Some(text(value).ok_or(FilterError::InvalidSession)?);
                }
                "from" => filter.from = Some(time(value)?),
                "to" => filter.to = Some(time(value)?),
                "limit" => filter.limit = limit(value)?,
                "cursor" => filter.cursor = Some(parse_cursor(value)?),
                _ => return Err(FilterError::UnknownParameter),
            }
        }
        if let (Some(from), Some(to)) = (filter.from, filter.to)
            && from >= to
        {
            return Err(FilterError::InvalidRange);
        }
        Ok(filter)
    }

    fn to_store_query(&self) -> AuditQuery {
        AuditQuery {
            type_prefix: self.type_prefix.clone(),
            actor: self.actor.clone(),
            node: self.node.clone(),
            session_id: self.session_id.clone(),
            from_ms: self.from.map(Timestamp::millis),
            to_ms: self.to.map(Timestamp::millis),
            after: self.cursor.clone(),
            limit: self.limit.saturating_add(1),
        }
    }
}

fn type_prefix(value: &str) -> Result<String, FilterError> {
    let valid = !value.is_empty()
        && value.chars().count() <= MAX_TYPE_PREFIX_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_'));
    if valid {
        Ok(value.to_owned())
    } else {
        Err(FilterError::InvalidType)
    }
}

fn text(value: &str) -> Option<String> {
    let valid = !value.is_empty()
        && value.chars().count() <= MAX_FILTER_TEXT_CHARS
        && !value.chars().any(char::is_control);
    valid.then(|| value.to_owned())
}

fn time(value: &str) -> Result<Timestamp, FilterError> {
    Timestamp::parse(value).map_err(|_| FilterError::InvalidTime)
}

fn limit(value: &str) -> Result<u32, FilterError> {
    let digits_only = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    let parsed = digits_only.then(|| value.parse::<u32>().ok()).flatten();
    match parsed {
        Some(limit) if (1..=MAX_PAGE).contains(&limit) => Ok(limit),
        _ => Err(FilterError::InvalidLimit),
    }
}

pub fn encode_cursor(cursor: &AuditCursor) -> String {
    format!("{}.{}", cursor.time_ms, cursor.id)
}

fn parse_cursor(value: &str) -> Result<AuditCursor, FilterError> {
    let invalid = FilterError::InvalidCursor;
    let (time_text, id) = value.split_once('.').ok_or(invalid)?;
    let digits_only = !time_text.is_empty() && time_text.bytes().all(|byte| byte.is_ascii_digit());
    let time_ms = digits_only
        .then(|| time_text.parse::<i64>().ok())
        .flatten()
        .filter(|millis| Timestamp::from_millis(*millis).is_ok())
        .ok_or(invalid)?;
    let id_valid = !id.is_empty()
        && id.chars().count() <= MAX_CURSOR_ID_CHARS
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
    if !id_valid {
        return Err(invalid);
    }
    Ok(AuditCursor {
        time_ms,
        id: id.to_owned(),
    })
}

pub async fn query(store: &Store, filter: &AuditFilter) -> Result<AuditPage, QueryError> {
    let rows = store.audit_events().query(&filter.to_store_query()).await?;
    let page_size = usize::try_from(filter.limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > page_size;
    let shown = &rows[..rows.len().min(page_size)];
    let next_cursor = if has_more {
        shown.last().map(|row| {
            encode_cursor(&AuditCursor {
                time_ms: row.time_ms,
                id: row.id.clone(),
            })
        })
    } else {
        None
    };
    let events = shown
        .iter()
        .filter_map(|row| AuditEvent::from_record(row).ok())
        .collect();
    Ok(AuditPage {
        events,
        next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use jaunt_store::{AuditRecord, Store};

    use super::{AuditFilter, FilterError, MAX_PAGE, encode_cursor, query};

    fn parse(pairs: &[(&str, &str)]) -> Result<AuditFilter, FilterError> {
        AuditFilter::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn valid_filters_parse_and_the_defaults_apply() {
        let filter = parse(&[
            ("type", "login."),
            ("actor", "u-1"),
            ("node", "n-1"),
            ("session", "s-1"),
            ("from", "2023-11-14T22:13:20Z"),
            ("to", "2023-11-14T22:13:21.5Z"),
            ("limit", "200"),
            ("cursor", "1700000000000.0000000000000001abcd"),
        ])
        .unwrap();

        assert_eq!(filter.type_prefix.as_deref(), Some("login."));
        assert_eq!(filter.limit, MAX_PAGE);
        assert_eq!(filter.from.unwrap().millis(), 1_700_000_000_000);
        assert_eq!(filter.to.unwrap().millis(), 1_700_000_001_500);
        assert_eq!(
            encode_cursor(&filter.cursor.unwrap()),
            "1700000000000.0000000000000001abcd"
        );
        let empty = parse(&[]).unwrap();
        assert_eq!(empty.limit, super::DEFAULT_PAGE);
        assert!(empty.type_prefix.is_none() && empty.cursor.is_none());
    }

    #[test]
    fn bad_filters_give_typed_errors() {
        let long = "n".repeat(129);
        let cases: [(&[(&str, &str)], FilterError); 17] = [
            (&[("type", "")], FilterError::InvalidType),
            (&[("type", "Login.")], FilterError::InvalidType),
            (&[("type", "login.%")], FilterError::InvalidType),
            (&[("actor", "")], FilterError::InvalidActor),
            (&[("actor", "a\nb")], FilterError::InvalidActor),
            (&[("node", long.as_str())], FilterError::InvalidNode),
            (&[("session", "")], FilterError::InvalidSession),
            (&[("from", "yesterday")], FilterError::InvalidTime),
            (
                &[("to", "2023-11-14T22:13:20+01:00")],
                FilterError::InvalidTime,
            ),
            (
                &[
                    ("from", "2023-11-14T22:13:20Z"),
                    ("to", "2023-11-14T22:13:20Z"),
                ],
                FilterError::InvalidRange,
            ),
            (&[("limit", "0")], FilterError::InvalidLimit),
            (&[("limit", "201")], FilterError::InvalidLimit),
            (&[("limit", "-1")], FilterError::InvalidLimit),
            (&[("limit", "1e2")], FilterError::InvalidLimit),
            (&[("cursor", "nodot")], FilterError::InvalidCursor),
            (&[("cursor", "12.bad id")], FilterError::InvalidCursor),
            (&[("order", "asc")], FilterError::UnknownParameter),
        ];
        for (pairs, expected) in cases {
            assert_eq!(parse(pairs).unwrap_err(), expected, "{pairs:?}");
        }
        assert_eq!(
            parse(&[("limit", "1"), ("limit", "2")]).unwrap_err(),
            FilterError::DuplicateParameter
        );
        assert_eq!(FilterError::InvalidLimit.code(), "invalid_limit");
    }

    fn row(id: &str, time_ms: i64, event_type: &str, payload: &str) -> AuditRecord {
        AuditRecord {
            id: id.to_owned(),
            time_ms,
            event_type: event_type.to_owned(),
            actor: "anonymous".to_owned(),
            node: None,
            session_id: None,
            policy_hash: None,
            payload: payload.to_owned(),
            v: 1,
        }
    }

    #[tokio::test]
    async fn pages_follow_the_cursor_and_rows_outside_the_schema_never_leave() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        store
            .audit_events()
            .append(&[
                row(
                    "a",
                    100,
                    "login.started",
                    "{\"login_id\":\"l\",\"email\":\"x@example.com\"}",
                ),
                row("b", 100, "future.type", "{}"),
                row("c", 100, "login.started", "{\"login_id\":\"m\"}"),
                row("d", 50, "login.started", "not json"),
                row("e", 40, "login.started", "{}"),
            ])
            .await
            .unwrap();

        let mut filter = parse(&[("limit", "2")]).unwrap();
        let first = query(&store, &filter).await.unwrap();
        let first_ids: Vec<&str> = first.events.iter().map(|event| event.id.as_str()).collect();
        assert_eq!(first_ids, ["c"]);
        let cursor = first.next_cursor.unwrap();
        assert_eq!(cursor, "100.b");

        filter.cursor = Some(super::parse_cursor(&cursor).unwrap());
        let second = query(&store, &filter).await.unwrap();
        let second_ids: Vec<&str> = second
            .events
            .iter()
            .map(|event| event.id.as_str())
            .collect();
        assert_eq!(second_ids, ["a"]);
        let text = serde_json::to_string(&second).unwrap();
        assert!(!text.contains("x@example.com"), "{text}");
        let cursor = second.next_cursor.unwrap();
        assert_eq!(cursor, "50.d");

        filter.cursor = Some(super::parse_cursor(&cursor).unwrap());
        let last = query(&store, &filter).await.unwrap();
        assert_eq!(last.events.len(), 1);
        assert_eq!(last.events[0].id, "e");
        assert!(last.next_cursor.is_none());
    }

    #[tokio::test]
    async fn unknown_rows_first_on_a_page_are_skipped_and_a_full_last_page_has_no_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();
        store
            .audit_events()
            .append(&[
                row("u1", 50, "future.type", "{}"),
                row("a1", 40, "login.started", "{}"),
                row("u2", 30, "future.type", "{}"),
                row("a2", 20, "login.started", "{}"),
            ])
            .await
            .unwrap();

        let mut filter = parse(&[("limit", "2")]).unwrap();
        let first = query(&store, &filter).await.unwrap();
        assert_eq!(first.events.len(), 1);
        assert_eq!(first.events[0].id, "a1");
        let cursor = first.next_cursor.unwrap();
        assert_eq!(cursor, "40.a1");

        filter.cursor = Some(super::parse_cursor(&cursor).unwrap());
        let second = query(&store, &filter).await.unwrap();
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].id, "a2");
        assert!(second.next_cursor.is_none());

        let exact = parse(&[("limit", "4")]).unwrap();
        let all = query(&store, &exact).await.unwrap();
        assert_eq!(all.events.len(), 2);
        assert!(all.next_cursor.is_none());
    }
}
