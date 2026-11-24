use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
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

    fn parse(value: &str) -> Result<SessionState, StoreError> {
        match value {
            "routed" => Ok(SessionState::Routed),
            "active" => Ok(SessionState::Active),
            "ended" => Ok(SessionState::Ended),
            other => Err(StoreError::Corrupt(format!("sessions.state: {other}"))),
        }
    }
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivateSession<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub user_id: &'a str,
    pub serial: i64,
    pub login: &'a str,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndOutcome {
    Ended(Box<Session>),
    Repeated,
    Rejected(EndRejection),
}

macro_rules! session_columns {
    () => {
        "id, user_id, serial, node_id, state, created_at, expires_at, authorized_at, ended_at, \
         login, exit_status, bytes_in, bytes_out, recording_incomplete"
    };
}

const CREATE: &str = concat!(
    "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at) \
     VALUES (?, ?, ?, ?, 'routed', ?, ?) RETURNING ",
    session_columns!()
);

const GET: &str = concat!("SELECT ", session_columns!(), " FROM sessions WHERE id = ?");

const ACTIVATE: &str = concat!(
    "UPDATE sessions SET state = 'active', authorized_at = ?, login = ? \
     WHERE id = ? AND node_id = ? AND user_id = ? AND serial = ? \
     AND state = 'routed' AND expires_at > ? \
     AND EXISTS (SELECT 1 FROM nodes WHERE id = ? AND state = 'active') RETURNING ",
    session_columns!()
);

const END: &str = concat!(
    "UPDATE sessions SET state = 'ended', ended_at = ?, exit_status = ?, bytes_in = ?, \
     bytes_out = ?, recording_incomplete = ? \
     WHERE id = ? AND node_id = ? AND state = 'active' RETURNING ",
    session_columns!()
);

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

    pub async fn purge_expired_routed(&self, cutoff: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PURGE_EXPIRED_ROUTED)
            .bind(cutoff)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }
}

fn session_from_row(row: &SqliteRow) -> Result<Session, StoreError> {
    let state: String = row.try_get("state")?;
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
    })
}
