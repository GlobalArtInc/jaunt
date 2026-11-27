use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use uuid::Uuid;

use crate::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Routed,
    Active,
    Ended,
}

impl SessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionState::Routed => "routed",
            SessionState::Active => "active",
            SessionState::Ended => "ended",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<SessionState, StoreError> {
        match value {
            "routed" => Ok(SessionState::Routed),
            "active" => Ok(SessionState::Active),
            "ended" => Ok(SessionState::Ended),
            other => Err(StoreError::Corrupt(format!("sessions.state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEndReason {
    Closed,
    Revoked,
    Expired,
    AgentRestarted,
    AgentGone,
    NodeRemoved,
}

impl SessionEndReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionEndReason::Closed => "closed",
            SessionEndReason::Revoked => "revoked",
            SessionEndReason::Expired => "expired",
            SessionEndReason::AgentRestarted => "agent_restarted",
            SessionEndReason::AgentGone => "agent_gone",
            SessionEndReason::NodeRemoved => "node_removed",
        }
    }

    fn parse(value: &str) -> Result<SessionEndReason, StoreError> {
        match value {
            "closed" => Ok(SessionEndReason::Closed),
            "revoked" => Ok(SessionEndReason::Revoked),
            "expired" => Ok(SessionEndReason::Expired),
            "agent_restarted" => Ok(SessionEndReason::AgentRestarted),
            "agent_gone" => Ok(SessionEndReason::AgentGone),
            "node_removed" => Ok(SessionEndReason::NodeRemoved),
            other => Err(StoreError::Corrupt(format!("sessions.end_reason: {other}"))),
        }
    }
}

pub const MAX_SESSION_PAGE: u32 = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCursor {
    pub created_at: i64,
    pub id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionQuery {
    pub state: Option<SessionState>,
    pub user: Option<String>,
    pub node: Option<String>,
    pub login: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub after: Option<SessionCursor>,
    pub limit: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRecording {
    None,
    Receiving,
    Complete,
    Incomplete,
}

impl SessionRecording {
    pub const fn as_str(self) -> &'static str {
        match self {
            SessionRecording::None => "none",
            SessionRecording::Receiving => "receiving",
            SessionRecording::Complete => "complete",
            SessionRecording::Incomplete => "incomplete",
        }
    }

    fn from_row(
        state: Option<&str>,
        salvaged: Option<bool>,
    ) -> Result<SessionRecording, StoreError> {
        Ok(match (state, salvaged.unwrap_or(false)) {
            (None | Some("failed"), _) => SessionRecording::None,
            (Some("receiving" | "complete" | "incomplete"), true) => SessionRecording::Incomplete,
            (Some("receiving"), false) => SessionRecording::Receiving,
            (Some("complete"), false) => SessionRecording::Complete,
            (Some("incomplete"), false) => SessionRecording::Incomplete,
            (Some(other), _) => {
                return Err(StoreError::Corrupt(format!("recordings.state: {other}")));
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListing {
    pub session: Session,
    pub user_email: String,
    pub node_name: String,
    pub recording: SessionRecording,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPage {
    pub sessions: Vec<SessionListing>,
    pub next: Option<SessionCursor>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeSessionCounts {
    pub open: i64,
    pub since: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSession {
    pub user_id: String,
    pub serial: i64,
    pub node_id: String,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub serial: i64,
    pub node_id: String,
    pub state: SessionState,
    pub created_at: i64,
    pub expires_at: i64,
    pub authorized_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub login: Option<String>,
    pub exit_status: Option<i32>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub recording_incomplete: Option<bool>,
    pub end_reason: Option<SessionEndReason>,
    pub max_duration_secs: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivateSession<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub user_id: &'a str,
    pub serial: i64,
    pub login: &'a str,
    pub max_duration_secs: i64,
    pub pty: bool,
    pub record_input: bool,
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndSession<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub exit_status: Option<i32>,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub recording_incomplete: bool,
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndRejection {
    UnknownSession,
    WrongNode,
    NotActive,
    ConflictingEnd,
    ClosedByControl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenSessions<'a> {
    OfUser(&'a str),
    OfSerial(i64),
    OfNode(&'a str),
    OfNodeCreatedBefore {
        node_id: &'a str,
        before: i64,
    },
    RoutedCreatedBefore(i64),
    CreatedBefore(i64),
    ActivePastDeadline {
        default_max_secs: i64,
        margin_secs: i64,
    },
    OfRevokedSubjects,
    OfInactiveNodes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndOutcome {
    Ended(Box<Session>),
    Late(Box<Session>),
    Repeated,
    Rejected(EndRejection),
}

macro_rules! session_columns {
    () => {
        "id, user_id, serial, node_id, state, created_at, expires_at, authorized_at, ended_at, \
         login, exit_status, bytes_in, bytes_out, recording_incomplete, end_reason, \
         max_duration_secs"
    };
}

macro_rules! close_open {
    ($($filter:tt)+) => {
        concat!(
            "UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? \
             WHERE state IN ('routed', 'active') AND ",
            $($filter)+,
            " RETURNING ",
            session_columns!()
        )
    };
}

const CREATE: &str = concat!(
    "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at) \
     VALUES (?, ?, ?, ?, 'routed', ?, ?) RETURNING ",
    session_columns!()
);

const GET: &str = concat!("SELECT ", session_columns!(), " FROM sessions WHERE id = ?");

const ACTIVATE: &str = concat!(
    "UPDATE sessions SET state = 'active', authorized_at = ?, login = ?, max_duration_secs = ?, \
     pty = ?, record_input = ? \
     WHERE id = ? AND node_id = ? AND user_id = ? AND serial = ? \
     AND state = 'routed' AND expires_at > ? \
     AND EXISTS (SELECT 1 FROM nodes WHERE id = ? AND state = 'active') RETURNING ",
    session_columns!()
);

const END: &str = concat!(
    "UPDATE sessions SET state = 'ended', ended_at = ?, exit_status = ?, bytes_in = ?, \
     bytes_out = ?, recording_incomplete = ?, end_reason = 'closed' \
     WHERE id = ? AND node_id = ? AND state = 'active' RETURNING ",
    session_columns!()
);

const CLOSE_OF_USER: &str = close_open!("user_id = ?");

const CLOSE_OF_SERIAL: &str = close_open!(
    "(serial = ? OR serial IN (SELECT c.serial FROM certificates c WHERE c.parent_serial = ?))"
);

const CLOSE_OF_NODE: &str = close_open!("node_id = ?");

const CLOSE_OF_NODE_CREATED_BEFORE: &str = close_open!("node_id = ? AND created_at < ?");

const CLOSE_ROUTED_CREATED_BEFORE: &str = close_open!("state = 'routed' AND created_at < ?");

const CLOSE_CREATED_BEFORE: &str = close_open!("created_at < ?");

const CLOSE_ACTIVE_PAST_DEADLINE: &str =
    close_open!("state = 'active' AND authorized_at + COALESCE(max_duration_secs, ?) + ? < ?");

macro_rules! revoked_subject {
    () => {
        "EXISTS (SELECT 1 FROM revocations r WHERE \
         (r.kind = 'user' AND r.subject = sessions.user_id) \
         OR (r.kind = 'serial' AND r.subject = CAST(sessions.serial AS TEXT)) \
         OR (r.kind = 'serial' AND r.subject = (SELECT CAST(c.parent_serial AS TEXT) \
             FROM certificates c WHERE c.serial = sessions.serial)) \
         OR (r.kind = 'node' AND r.subject = sessions.node_id))"
    };
}

const CLOSE_OF_REVOKED_SUBJECTS: &str = close_open!(revoked_subject!());

const CLOSE_OF_INACTIVE_NODES: &str =
    close_open!("node_id IN (SELECT id FROM nodes WHERE state <> 'active')");

const ANY_OPEN_OF_REVOKED_SUBJECTS: &str = concat!(
    "SELECT 1 FROM sessions WHERE state IN ('routed', 'active') AND ",
    revoked_subject!(),
    " LIMIT 1"
);

const LATE_END: &str = concat!(
    "UPDATE sessions SET exit_status = ?, bytes_in = ?, bytes_out = ?, \
     recording_incomplete = CASE WHEN ? OR recording_incomplete = 1 THEN 1 ELSE 0 END \
     WHERE id = ? AND node_id = ? AND state = 'ended' AND end_reason IS NOT NULL \
     AND end_reason <> 'closed' AND authorized_at IS NOT NULL \
     AND bytes_in IS NULL AND bytes_out IS NULL RETURNING ",
    session_columns!()
);

const LISTING_SELECT: &str = "SELECT s.id AS id, s.user_id AS user_id, s.serial AS serial, \
    s.node_id AS node_id, s.state AS state, s.created_at AS created_at, \
    s.expires_at AS expires_at, s.authorized_at AS authorized_at, s.ended_at AS ended_at, \
    s.login AS login, s.exit_status AS exit_status, s.bytes_in AS bytes_in, \
    s.bytes_out AS bytes_out, s.recording_incomplete AS recording_incomplete, \
    s.end_reason AS end_reason, s.max_duration_secs AS max_duration_secs, \
    u.email AS user_email, n.name AS node_name, \
    r.state AS recording_state, r.salvaged AS recording_salvaged \
    FROM sessions s JOIN users u ON u.id = s.user_id JOIN nodes n ON n.id = s.node_id \
    LEFT JOIN recordings r ON r.session_id = s.id \
    WHERE 1 = 1";

const NODE_COUNTS: &str = "SELECT \
    COALESCE(SUM(CASE WHEN state IN ('routed', 'active') THEN 1 ELSE 0 END), 0) AS open, \
    COALESCE(SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END), 0) AS since \
    FROM sessions WHERE node_id = ?";

const PURGE_EXPIRED_ROUTED: &str = "DELETE FROM sessions WHERE state = 'routed' AND expires_at < ?";

#[derive(Clone)]
pub struct Sessions {
    pool: SqlitePool,
}

impl Sessions {
    pub(crate) fn new(pool: SqlitePool) -> Sessions {
        Sessions { pool }
    }

    pub async fn create(&self, session: &NewSession, now: i64) -> Result<Session, StoreError> {
        if session.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        let expires_at = now
            .checked_add(session.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let row = sqlx::query(CREATE)
            .bind(Uuid::new_v4().to_string())
            .bind(&session.user_id)
            .bind(session.serial)
            .bind(&session.node_id)
            .bind(now)
            .bind(expires_at)
            .fetch_one(&self.pool)
            .await?;
        session_from_row(&row)
    }

    pub async fn get(&self, id: &str) -> Result<Option<Session>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(session_from_row).transpose()
    }

    pub async fn activate(
        &self,
        activation: ActivateSession<'_>,
    ) -> Result<Option<Session>, StoreError> {
        let row = sqlx::query(ACTIVATE)
            .bind(activation.now)
            .bind(activation.login)
            .bind(activation.max_duration_secs)
            .bind(activation.pty)
            .bind(activation.record_input)
            .bind(activation.id)
            .bind(activation.node_id)
            .bind(activation.user_id)
            .bind(activation.serial)
            .bind(activation.now)
            .bind(activation.node_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(session_from_row).transpose()
    }

    pub async fn end(&self, end: EndSession<'_>) -> Result<EndOutcome, StoreError> {
        let row = sqlx::query(END)
            .bind(end.now)
            .bind(end.exit_status)
            .bind(end.bytes_in)
            .bind(end.bytes_out)
            .bind(end.recording_incomplete)
            .bind(end.id)
            .bind(end.node_id)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            return Ok(EndOutcome::Ended(Box::new(session_from_row(&row)?)));
        }
        let Some(stored) = self.get(end.id).await? else {
            return Ok(EndOutcome::Rejected(EndRejection::UnknownSession));
        };
        if stored.node_id != end.node_id {
            return Ok(EndOutcome::Rejected(EndRejection::WrongNode));
        }
        if stored.state != SessionState::Ended {
            return Ok(EndOutcome::Rejected(EndRejection::NotActive));
        }
        if stored
            .end_reason
            .is_some_and(|reason| reason != SessionEndReason::Closed)
        {
            let filled = sqlx::query(LATE_END)
                .bind(end.exit_status)
                .bind(end.bytes_in)
                .bind(end.bytes_out)
                .bind(end.recording_incomplete)
                .bind(end.id)
                .bind(end.node_id)
                .fetch_optional(&self.pool)
                .await?;
            return Ok(match filled {
                Some(row) => EndOutcome::Late(Box::new(session_from_row(&row)?)),
                None => EndOutcome::Rejected(EndRejection::ClosedByControl),
            });
        }
        let identical = stored.exit_status == end.exit_status
            && stored.bytes_in == Some(end.bytes_in)
            && stored.bytes_out == Some(end.bytes_out)
            && stored.recording_incomplete == Some(end.recording_incomplete);
        Ok(if identical {
            EndOutcome::Repeated
        } else {
            EndOutcome::Rejected(EndRejection::ConflictingEnd)
        })
    }

    pub async fn close(
        &self,
        which: OpenSessions<'_>,
        reason: SessionEndReason,
        now: i64,
    ) -> Result<Vec<Session>, StoreError> {
        let closing = |sql| sqlx::query(sql).bind(now).bind(reason.as_str());
        let query = match which {
            OpenSessions::OfUser(user_id) => closing(CLOSE_OF_USER).bind(user_id),
            OpenSessions::OfSerial(serial) => closing(CLOSE_OF_SERIAL).bind(serial).bind(serial),
            OpenSessions::OfNode(node_id) => closing(CLOSE_OF_NODE).bind(node_id),
            OpenSessions::OfNodeCreatedBefore { node_id, before } => {
                closing(CLOSE_OF_NODE_CREATED_BEFORE)
                    .bind(node_id)
                    .bind(before)
            }
            OpenSessions::RoutedCreatedBefore(before) => {
                closing(CLOSE_ROUTED_CREATED_BEFORE).bind(before)
            }
            OpenSessions::CreatedBefore(before) => closing(CLOSE_CREATED_BEFORE).bind(before),
            OpenSessions::ActivePastDeadline {
                default_max_secs,
                margin_secs,
            } => closing(CLOSE_ACTIVE_PAST_DEADLINE)
                .bind(default_max_secs)
                .bind(margin_secs)
                .bind(now),
            OpenSessions::OfRevokedSubjects => closing(CLOSE_OF_REVOKED_SUBJECTS),
            OpenSessions::OfInactiveNodes => closing(CLOSE_OF_INACTIVE_NODES),
        };
        let rows = query.fetch_all(&self.pool).await?;
        rows.iter().map(session_from_row).collect()
    }

    pub async fn any_open_of_revoked_subjects(&self) -> Result<bool, StoreError> {
        let row = sqlx::query(ANY_OPEN_OF_REVOKED_SUBJECTS)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn page(&self, query: &SessionQuery) -> Result<SessionPage, StoreError> {
        if query.limit == 0 || query.limit > MAX_SESSION_PAGE {
            return Err(StoreError::InvalidInput("the page size is out of range"));
        }
        let mut builder = page_builder("", query);
        let rows = builder.build().fetch_all(&self.pool).await?;
        let mut sessions = rows
            .iter()
            .map(listing_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let wanted = query.limit as usize;
        let next = if sessions.len() > wanted {
            sessions.truncate(wanted);
            sessions.last().map(|last| SessionCursor {
                created_at: last.session.created_at,
                id: last.session.id.clone(),
            })
        } else {
            None
        };
        Ok(SessionPage { sessions, next })
    }

    #[doc(hidden)]
    pub async fn page_plan(&self, query: &SessionQuery) -> Result<Vec<String>, StoreError> {
        let mut builder = page_builder("EXPLAIN QUERY PLAN ", query);
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| row.try_get("detail").map_err(StoreError::from))
            .collect()
    }

    pub async fn listing(&self, id: &str) -> Result<Option<SessionListing>, StoreError> {
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(LISTING_SELECT);
        builder.push(" AND s.id = ");
        builder.push_bind(id.to_owned());
        let row = builder.build().fetch_optional(&self.pool).await?;
        row.as_ref().map(listing_from_row).transpose()
    }

    pub async fn node_counts(
        &self,
        node_id: &str,
        created_since: i64,
    ) -> Result<NodeSessionCounts, StoreError> {
        let row = sqlx::query(NODE_COUNTS)
            .bind(created_since)
            .bind(node_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(NodeSessionCounts {
            open: row.try_get("open")?,
            since: row.try_get("since")?,
        })
    }

    pub async fn purge_expired_routed(&self, cutoff: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PURGE_EXPIRED_ROUTED)
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }
}

fn page_builder(prefix: &str, query: &SessionQuery) -> QueryBuilder<Sqlite> {
    let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(format!("{prefix}{LISTING_SELECT}"));
    if let Some(state) = query.state {
        builder.push(" AND s.state = ");
        builder.push_bind(state.as_str());
    }
    if let Some(user) = &query.user {
        builder.push(" AND s.user_id IN (SELECT id FROM users WHERE id = ");
        builder.push_bind(user.clone());
        builder.push(" OR email = ");
        builder.push_bind(user.clone());
        builder.push(")");
    }
    if let Some(node) = &query.node {
        builder.push(" AND s.node_id IN (SELECT id FROM nodes WHERE id = ");
        builder.push_bind(node.clone());
        builder.push(" OR name = ");
        builder.push_bind(node.clone());
        builder.push(")");
    }
    if let Some(login) = &query.login {
        builder.push(" AND s.login = ");
        builder.push_bind(login.clone());
    }
    if let Some(from) = query.from {
        builder.push(" AND s.created_at >= ");
        builder.push_bind(from);
    }
    if let Some(to) = query.to {
        builder.push(" AND s.created_at < ");
        builder.push_bind(to);
    }
    if let Some(cursor) = &query.after {
        builder.push(" AND (s.created_at < ");
        builder.push_bind(cursor.created_at);
        builder.push(" OR (s.created_at = ");
        builder.push_bind(cursor.created_at);
        builder.push(" AND s.id < ");
        builder.push_bind(cursor.id.clone());
        builder.push("))");
    }
    builder.push(" ORDER BY s.created_at DESC, s.id DESC LIMIT ");
    builder.push_bind(i64::from(query.limit) + 1);
    builder
}

fn listing_from_row(row: &SqliteRow) -> Result<SessionListing, StoreError> {
    Ok(SessionListing {
        session: session_from_row(row)?,
        user_email: row.try_get("user_email")?,
        node_name: row.try_get("node_name")?,
        recording: SessionRecording::from_row(
            row.try_get::<Option<String>, _>("recording_state")?
                .as_deref(),
            row.try_get("recording_salvaged")?,
        )?,
    })
}

fn session_from_row(row: &SqliteRow) -> Result<Session, StoreError> {
    let state: String = row.try_get("state")?;
    let end_reason: Option<String> = row.try_get("end_reason")?;
    Ok(Session {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        serial: row.try_get("serial")?,
        node_id: row.try_get("node_id")?,
        state: SessionState::parse(&state)?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        authorized_at: row.try_get("authorized_at")?,
        ended_at: row.try_get("ended_at")?,
        login: row.try_get("login")?,
        exit_status: row.try_get("exit_status")?,
        bytes_in: row.try_get("bytes_in")?,
        bytes_out: row.try_get("bytes_out")?,
        recording_incomplete: row.try_get("recording_incomplete")?,
        end_reason: end_reason
            .as_deref()
            .map(SessionEndReason::parse)
            .transpose()?,
        max_duration_secs: row.try_get("max_duration_secs")?,
    })
}
