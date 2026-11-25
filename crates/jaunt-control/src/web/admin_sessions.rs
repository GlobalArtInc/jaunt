use axum::extract::{Path, State};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use jaunt_store::{
    AuditQuery, SessionCursor, SessionEndReason, SessionListing, SessionQuery, SessionState,
    StoreError,
};
use serde::Serialize;

use crate::control::Control;
use crate::http::{json_response, server_error};
use crate::revocation::is_identifier;

use super::admin_common::{DEFAULT_PAGE, Refusal, known_id, not_found, once, page_limit};
use super::session::{RequireAdmin, SessionsRead};

const MAX_FILTER_CHARS: usize = 256;
const CLIENT_EVENT_PREFIX: &str = "session.";
const CLIENT_EVENT_SCAN: u32 = 20;
const MAX_CLIENT_ADDR_CHARS: usize = 64;

#[derive(Serialize)]
struct SessionBody {
    id: String,
    state: &'static str,
    user_id: String,
    user_email: String,
    node_id: String,
    node_name: String,
    login: Option<String>,
    created_at: i64,
    authorized_at: Option<i64>,
    ended_at: Option<i64>,
    end_reason: Option<&'static str>,
    exit_status: Option<i32>,
    bytes_in: Option<i64>,
    bytes_out: Option<i64>,
    recording: &'static str,
}

impl From<SessionListing> for SessionBody {
    fn from(listing: SessionListing) -> SessionBody {
        let session = listing.session;
        SessionBody {
            recording: listing.recording.as_str(),
            state: session.state.as_str(),
            end_reason: session.end_reason.map(SessionEndReason::as_str),
            id: session.id,
            user_id: session.user_id,
            user_email: listing.user_email,
            node_id: session.node_id,
            node_name: listing.node_name,
            login: session.login,
            created_at: session.created_at,
            authorized_at: session.authorized_at,
            ended_at: session.ended_at,
            exit_status: session.exit_status,
            bytes_in: session.bytes_in,
            bytes_out: session.bytes_out,
        }
    }
}

#[derive(Serialize)]
struct ListBody {
    sessions: Vec<SessionBody>,
    next: Option<String>,
}

#[derive(Serialize)]
struct DetailBody {
    #[serde(flatten)]
    session: SessionBody,
    serial: i64,
    expires_at: i64,
    max_duration_secs: Option<i64>,
    client_addr: Option<String>,
}

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<SessionsRead>,
    uri: Uri,
) -> Response {
    let query = match list_query(uri.query()) {
        Ok(query) => query,
        Err(refusal) => return refusal.into_response(),
    };
    match control.store.sessions().page(&query).await {
        Ok(page) => json_response(
            StatusCode::OK,
            &ListBody {
                next: page.next.as_ref().map(cursor_text),
                sessions: page.sessions.into_iter().map(SessionBody::from).collect(),
            },
        ),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing sessions failed");
            server_error()
        }
    }
}

pub(crate) async fn detail(
    State(control): State<Control>,
    _admin: RequireAdmin<SessionsRead>,
    Path(id): Path<String>,
) -> Response {
    let Some(id) = known_id(&id) else {
        return not_found();
    };
    let listing = match control.store.sessions().listing(id).await {
        Ok(Some(listing)) => listing,
        Ok(None) => return not_found(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "reading a session failed");
            return server_error();
        }
    };
    let client_addr = match client_addr(&control, id).await {
        Ok(found) => found,
        Err(err) => {
            tracing::warn!(target: "jaunt::control", error = %err, "reading the session client address from the audit failed");
            None
        }
    };
    json_response(
        StatusCode::OK,
        &DetailBody {
            serial: listing.session.serial,
            expires_at: listing.session.expires_at,
            max_duration_secs: listing.session.max_duration_secs,
            client_addr,
            session: listing.into(),
        },
    )
}

async fn client_addr(control: &Control, session_id: &str) -> Result<Option<String>, StoreError> {
    let mut query = AuditQuery::newest(CLIENT_EVENT_SCAN);
    query.type_prefix = Some(CLIENT_EVENT_PREFIX.to_owned());
    query.session_id = Some(session_id.to_owned());
    let records = control.store.audit_events().query(&query).await?;
    Ok(records.iter().find_map(|record| {
        let payload: serde_json::Value = serde_json::from_str(&record.payload).ok()?;
        let address = payload.get("client_addr")?.as_str()?;
        let clean = !address.is_empty()
            && address.chars().count() <= MAX_CLIENT_ADDR_CHARS
            && !address.chars().any(char::is_control);
        clean.then(|| address.to_owned())
    }))
}

fn list_query(query: Option<&str>) -> Result<SessionQuery, Refusal> {
    let mut parsed = SessionQuery::default();
    let mut limit = None;
    for (key, value) in form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match key.as_ref() {
            "state" => once(&mut parsed.state, session_state(&value)?)?,
            "user" => once(&mut parsed.user, filter_text(&value)?)?,
            "node" => once(&mut parsed.node, filter_text(&value)?)?,
            "login" => once(&mut parsed.login, filter_text(&value)?)?,
            "from" => once(&mut parsed.from, time(&value)?)?,
            "to" => once(&mut parsed.to, time(&value)?)?,
            "limit" => once(&mut limit, page_limit(&value)?)?,
            "cursor" => once(
                &mut parsed.after,
                parse_cursor(&value).ok_or(Refusal::Malformed)?,
            )?,
            _ => return Err(Refusal::Malformed),
        }
    }
    if let (Some(from), Some(to)) = (parsed.from, parsed.to)
        && from > to
    {
        return Err(Refusal::Invalid("invalid_time_range"));
    }
    parsed.limit = limit.unwrap_or(DEFAULT_PAGE);
    Ok(parsed)
}

fn session_state(value: &str) -> Result<SessionState, Refusal> {
    match value {
        "routed" => Ok(SessionState::Routed),
        "active" => Ok(SessionState::Active),
        "ended" => Ok(SessionState::Ended),
        _ => Err(Refusal::Invalid("invalid_state")),
    }
}

fn filter_text(value: &str) -> Result<String, Refusal> {
    if value.is_empty()
        || value.chars().count() > MAX_FILTER_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(Refusal::Invalid("invalid_filter"));
    }
    Ok(value.to_owned())
}

fn time(value: &str) -> Result<i64, Refusal> {
    let secs = value.parse::<i64>().map_err(|_| Refusal::Malformed)?;
    if secs < 0 {
        return Err(Refusal::Invalid("invalid_time_range"));
    }
    Ok(secs)
}

fn cursor_text(cursor: &SessionCursor) -> String {
    format!("{}.{}", cursor.created_at, cursor.id)
}

fn parse_cursor(text: &str) -> Option<SessionCursor> {
    let (created_at, id) = text.split_once('.')?;
    let created_at = created_at.parse::<i64>().ok()?;
    is_identifier(id).then(|| SessionCursor {
        created_at,
        id: id.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use jaunt_store::{SessionCursor, SessionState};

    use super::{Refusal, cursor_text, list_query};

    #[test]
    fn session_list_queries_are_parsed_strictly() {
        let cursor = SessionCursor {
            created_at: 1_700_000_000,
            id: "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        };
        let parsed = list_query(Some(&format!(
            "state=active&user=alice%40example.com&node=web-01&login=deploy&from=10&to=20&limit=7&cursor={}",
            cursor_text(&cursor)
        )))
        .unwrap();
        assert_eq!(parsed.state, Some(SessionState::Active));
        assert_eq!(parsed.user.as_deref(), Some("alice@example.com"));
        assert_eq!(
            (parsed.from, parsed.to, parsed.limit),
            (Some(10), Some(20), 7)
        );
        assert_eq!(parsed.after, Some(cursor));
        assert_eq!(list_query(None).unwrap().limit, 50);

        for (query, refusal) in [
            ("state=live", Refusal::Invalid("invalid_state")),
            ("user=", Refusal::Invalid("invalid_filter")),
            ("from=20&to=10", Refusal::Invalid("invalid_time_range")),
            ("from=-1", Refusal::Invalid("invalid_time_range")),
            ("from=x", Refusal::Malformed),
            ("limit=300", Refusal::Invalid("invalid_limit")),
            ("user=a&user=b", Refusal::Malformed),
            ("cursor=1.bad/id", Refusal::Malformed),
            ("recording=complete", Refusal::Malformed),
        ] {
            assert_eq!(list_query(Some(query)), Err(refusal), "{query}");
        }
    }
}
