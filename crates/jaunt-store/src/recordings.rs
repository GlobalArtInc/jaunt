use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;
use crate::sessions::{SessionKind, SessionState};

pub const MAX_RECORDING_PAGE: u32 = 1000;
pub const SESSION_ID_LEN: usize = 36;

pub fn is_session_id(value: &str) -> bool {
    value.len() == SESSION_ID_LEN
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    Receiving,
    Complete,
    Incomplete,
    Failed,
}

impl RecordingState {
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordingState::Receiving => "receiving",
            RecordingState::Complete => "complete",
            RecordingState::Incomplete => "incomplete",
            RecordingState::Failed => "failed",
        }
    }

    pub const fn is_stored(self) -> bool {
        matches!(self, RecordingState::Complete | RecordingState::Incomplete)
    }

    fn parse(value: &str) -> Result<RecordingState, StoreError> {
        match value {
            "receiving" => Ok(RecordingState::Receiving),
            "complete" => Ok(RecordingState::Complete),
            "incomplete" => Ok(RecordingState::Incomplete),
            "failed" => Ok(RecordingState::Failed),
            other => Err(StoreError::Corrupt(format!("recordings.state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    pub session_id: String,
    pub node_id: String,
    pub state: RecordingState,
    pub chunks: u64,
    pub raw_bytes: u64,
    pub progress_sha256: Option<String>,
    pub digest: Option<String>,
    pub input_recorded: bool,
    pub incomplete: bool,
    pub session_incomplete: Option<bool>,
    pub salvaged: bool,
    pub dropped_chunks: u64,
    pub location: Option<String>,
    pub cast_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadTarget {
    pub session_id: String,
    pub node_id: String,
    pub user_id: String,
    pub state: SessionState,
    pub authorized_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub login: Option<String>,
    pub pty: Option<bool>,
    pub record_input: Option<bool>,
    pub recording: Option<Recording>,
    pub kind: SessionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRecording<'a> {
    pub session_id: &'a str,
    pub node_id: &'a str,
    pub chunks: u64,
    pub raw_bytes: u64,
    pub digest: Option<&'a str>,
    pub input_recorded: bool,
    pub dropped_chunks: u64,
    pub location: &'a str,
    pub cast_sha256: Option<&'a str>,
    pub manifest_sha256: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reconciled {
    pub manifest_incomplete: bool,
    pub session_incomplete: bool,
    pub state: RecordingState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordingCursor {
    pub created_at: i64,
    pub session_id: String,
}

macro_rules! recording_columns {
    ($prefix:literal) => {
        concat!(
            $prefix,
            "session_id AS r_session_id, ",
            $prefix,
            "node_id AS r_node_id, ",
            $prefix,
            "state AS r_state, ",
            $prefix,
            "chunks AS r_chunks, ",
            $prefix,
            "raw_bytes AS r_raw_bytes, ",
            $prefix,
            "progress_sha256 AS r_progress_sha256, ",
            $prefix,
            "digest AS r_digest, ",
            $prefix,
            "input_recorded AS r_input_recorded, ",
            $prefix,
            "incomplete AS r_incomplete, ",
            $prefix,
            "session_incomplete AS r_session_incomplete, ",
            $prefix,
            "salvaged AS r_salvaged, ",
            $prefix,
            "dropped_chunks AS r_dropped_chunks, ",
            $prefix,
            "location AS r_location, ",
            $prefix,
            "cast_sha256 AS r_cast_sha256, ",
            $prefix,
            "manifest_sha256 AS r_manifest_sha256, ",
            $prefix,
            "created_at AS r_created_at, ",
            $prefix,
            "completed_at AS r_completed_at"
        )
    };
}

const TARGET: &str = concat!(
    "SELECT s.id AS s_id, s.node_id AS s_node_id, s.user_id AS s_user_id, s.state AS s_state, \
     s.authorized_at AS s_authorized_at, s.ended_at AS s_ended_at, s.login AS s_login, \
     s.pty AS s_pty, s.record_input AS s_record_input, s.kind AS s_kind, ",
    recording_columns!("r."),
    " FROM sessions s LEFT JOIN recordings r ON r.session_id = s.id WHERE s.id = ?"
);

const GET: &str = concat!(
    "SELECT ",
    recording_columns!(""),
    " FROM recordings WHERE session_id = ?"
);

const LIST_FIRST: &str = concat!(
    "SELECT ",
    recording_columns!(""),
    " FROM recordings WHERE node_id = ? ORDER BY created_at, session_id LIMIT ?"
);

const LIST_AFTER: &str = concat!(
    "SELECT ",
    recording_columns!(""),
    " FROM recordings WHERE node_id = ? AND (created_at, session_id) > (?, ?) \
     ORDER BY created_at, session_id LIMIT ?"
);

const LIST_RECEIVING: &str = concat!(
    "SELECT ",
    recording_columns!(""),
    " FROM recordings WHERE state = 'receiving' ORDER BY created_at, session_id"
);

const BEGIN: &str = "INSERT INTO recordings (session_id, node_id, state, chunks, raw_bytes, \
    input_recorded, incomplete, salvaged, dropped_chunks, created_at) \
    VALUES (?, ?, 'receiving', 0, 0, 0, 0, 0, 0, ?) ON CONFLICT (session_id) DO NOTHING";

const PROGRESS: &str = "UPDATE recordings SET chunks = ?, raw_bytes = ?, progress_sha256 = ? \
    WHERE session_id = ? AND state = 'receiving'";

const STORE: &str = "UPDATE recordings SET state = ?, chunks = ?, raw_bytes = ?, digest = ?, \
    input_recorded = ?, incomplete = ?, salvaged = ?, dropped_chunks = ?, location = ?, \
    cast_sha256 = ?, manifest_sha256 = ?, completed_at = ? \
    WHERE session_id = ? AND node_id = ? AND state = 'receiving'";

const FAIL: &str = "UPDATE recordings SET state = 'failed', completed_at = ? \
    WHERE session_id = ? AND state = 'receiving'";

const RECONCILE: &str = "UPDATE recordings SET session_incomplete = ?, incomplete = ?, state = ? \
    WHERE session_id = ? AND session_incomplete IS NULL \
    AND state IN ('complete', 'incomplete')";

#[derive(Clone)]
pub struct Recordings {
    pool: SqlitePool,
}

impl Recordings {
    pub(crate) fn new(pool: SqlitePool) -> Recordings {
        Recordings { pool }
    }

    pub async fn upload_target(
        &self,
        session_id: &str,
    ) -> Result<Option<UploadTarget>, StoreError> {
        let row = sqlx::query(TARGET)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(target_from_row).transpose()
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<Recording>, StoreError> {
        let row = sqlx::query(GET)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(recording_from_row).transpose()
    }

    pub async fn begin(
        &self,
        session_id: &str,
        node_id: &str,
        now: i64,
    ) -> Result<Recording, StoreError> {
        sqlx::query(BEGIN)
            .bind(session_id)
            .bind(node_id)
            .bind(now)
            .execute(&self.pool)
            .await?;
        self.get(session_id)
            .await?
            .ok_or_else(|| StoreError::Corrupt("recordings: the begun row is missing".to_owned()))
    }

    pub async fn record_progress(
        &self,
        session_id: &str,
        chunks: u64,
        raw_bytes: u64,
        prefix_sha256: &str,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(PROGRESS)
            .bind(to_i64(chunks)?)
            .bind(to_i64(raw_bytes)?)
            .bind(prefix_sha256)
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn list_receiving(&self) -> Result<Vec<Recording>, StoreError> {
        let rows = sqlx::query(LIST_RECEIVING).fetch_all(&self.pool).await?;
        rows.iter().map(recording_from_row).collect()
    }

    pub async fn mark_complete(&self, stored: &StoredRecording<'_>) -> Result<bool, StoreError> {
        self.store(stored, RecordingState::Complete, false).await
    }

    pub async fn mark_incomplete(&self, stored: &StoredRecording<'_>) -> Result<bool, StoreError> {
        self.store(stored, RecordingState::Incomplete, false).await
    }

    pub async fn mark_salvaged(&self, stored: &StoredRecording<'_>) -> Result<bool, StoreError> {
        self.store(stored, RecordingState::Incomplete, true).await
    }

    async fn store(
        &self,
        stored: &StoredRecording<'_>,
        state: RecordingState,
        salvaged: bool,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(STORE)
            .bind(state.as_str())
            .bind(to_i64(stored.chunks)?)
            .bind(to_i64(stored.raw_bytes)?)
            .bind(stored.digest)
            .bind(stored.input_recorded)
            .bind(state == RecordingState::Incomplete)
            .bind(salvaged)
            .bind(to_i64(stored.dropped_chunks)?)
            .bind(stored.location)
            .bind(stored.cast_sha256)
            .bind(stored.manifest_sha256)
            .bind(stored.now)
            .bind(stored.session_id)
            .bind(stored.node_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn mark_failed(&self, session_id: &str, now: i64) -> Result<bool, StoreError> {
        let done = sqlx::query(FAIL)
            .bind(now)
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn reconcile(
        &self,
        session_id: &str,
        session_incomplete: bool,
    ) -> Result<Option<Reconciled>, StoreError> {
        let Some(recording) = self.get(session_id).await? else {
            return Ok(None);
        };
        if !recording.state.is_stored() || recording.session_incomplete.is_some() {
            return Ok(None);
        }
        let incomplete = recording.incomplete || session_incomplete;
        let state = if incomplete {
            RecordingState::Incomplete
        } else {
            RecordingState::Complete
        };
        let done = sqlx::query(RECONCILE)
            .bind(session_incomplete)
            .bind(incomplete)
            .bind(state.as_str())
            .bind(session_id)
            .execute(&self.pool)
            .await?;
        Ok((done.rows_affected() == 1).then_some(Reconciled {
            manifest_incomplete: recording.incomplete,
            session_incomplete,
            state,
        }))
    }

    pub async fn list_for_node(
        &self,
        node_id: &str,
        after: Option<&RecordingCursor>,
        limit: u32,
    ) -> Result<Vec<Recording>, StoreError> {
        if limit == 0 || limit > MAX_RECORDING_PAGE {
            return Err(StoreError::InvalidInput(
                "the recording page size is out of range",
            ));
        }
        let rows = match after {
            None => {
                sqlx::query(LIST_FIRST)
                    .bind(node_id)
                    .bind(i64::from(limit))
                    .fetch_all(&self.pool)
                    .await?
            }
            Some(cursor) => {
                sqlx::query(LIST_AFTER)
                    .bind(node_id)
                    .bind(cursor.created_at)
                    .bind(&cursor.session_id)
                    .bind(i64::from(limit))
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        rows.iter().map(recording_from_row).collect()
    }
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::InvalidInput("a recording counter overflows"))
}

fn to_u64(value: i64, column: &str) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt(format!("recordings.{column}: negative")))
}

fn target_from_row(row: &SqliteRow) -> Result<UploadTarget, StoreError> {
    let state: String = row.try_get("s_state")?;
    let kind: String = row.try_get("s_kind")?;
    let recording_id: Option<String> = row.try_get("r_session_id")?;
    Ok(UploadTarget {
        session_id: row.try_get("s_id")?,
        node_id: row.try_get("s_node_id")?,
        user_id: row.try_get("s_user_id")?,
        state: SessionState::parse(&state)?,
        authorized_at: row.try_get("s_authorized_at")?,
        ended_at: row.try_get("s_ended_at")?,
        login: row.try_get("s_login")?,
        pty: row.try_get("s_pty")?,
        record_input: row.try_get("s_record_input")?,
        recording: match recording_id {
            Some(_) => Some(recording_from_row(row)?),
            None => None,
        },
        kind: SessionKind::parse(&kind)?,
    })
}

fn recording_from_row(row: &SqliteRow) -> Result<Recording, StoreError> {
    let state: String = row.try_get("r_state")?;
    Ok(Recording {
        session_id: row.try_get("r_session_id")?,
        node_id: row.try_get("r_node_id")?,
        state: RecordingState::parse(&state)?,
        chunks: to_u64(row.try_get("r_chunks")?, "chunks")?,
        raw_bytes: to_u64(row.try_get("r_raw_bytes")?, "raw_bytes")?,
        progress_sha256: row.try_get("r_progress_sha256")?,
        digest: row.try_get("r_digest")?,
        input_recorded: row.try_get("r_input_recorded")?,
        incomplete: row.try_get("r_incomplete")?,
        session_incomplete: row.try_get("r_session_incomplete")?,
        salvaged: row.try_get("r_salvaged")?,
        dropped_chunks: to_u64(row.try_get("r_dropped_chunks")?, "dropped_chunks")?,
        location: row.try_get("r_location")?,
        cast_sha256: row.try_get("r_cast_sha256")?,
        manifest_sha256: row.try_get("r_manifest_sha256")?,
        created_at: row.try_get("r_created_at")?,
        completed_at: row.try_get("r_completed_at")?,
    })
}
