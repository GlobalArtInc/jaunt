use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use crate::StoreError;

pub const MAX_AUDIT_PAGE: u32 = 1000;
pub const MAX_AUDIT_PAYLOAD_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: String,
    pub time_ms: i64,
    pub event_type: String,
    pub actor: String,
    pub node: Option<String>,
    pub session_id: Option<String>,
    pub policy_hash: Option<String>,
    pub payload: String,
    pub v: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCursor {
    pub time_ms: i64,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    pub type_prefix: Option<String>,
    pub actor: Option<String>,
    pub node: Option<String>,
    pub session_id: Option<String>,
    pub from_ms: Option<i64>,
    pub to_ms: Option<i64>,
    pub after: Option<AuditCursor>,
    pub limit: u32,
}

impl AuditQuery {
    pub fn newest(limit: u32) -> AuditQuery {
        AuditQuery {
            type_prefix: None,
            actor: None,
            node: None,
            session_id: None,
            from_ms: None,
            to_ms: None,
            after: None,
            limit,
        }
    }
}

const INSERT: &str = "INSERT INTO audit_events \
    (id, time_ms, event_type, actor, node, session_id, policy_hash, payload, v) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO NOTHING";

const SELECT: &str = "SELECT id, time_ms, event_type, actor, node, session_id, policy_hash, \
    payload, v FROM audit_events WHERE 1 = 1";

const COUNT_ALL: &str = "SELECT COUNT(*) AS total FROM audit_events";

const COUNT_BEFORE: &str = "SELECT COUNT(*) AS total FROM audit_events WHERE time_ms < ?";

const NEWEST: &str = "SELECT MAX(time_ms) AS newest FROM audit_events";

const DELETE_BEFORE: &str = "DELETE FROM audit_events WHERE id IN \
    (SELECT id FROM audit_events WHERE time_ms < ? ORDER BY time_ms, id LIMIT ?)";

#[derive(Clone)]
pub struct AuditEvents {
    pool: SqlitePool,
}

impl AuditEvents {
    pub(crate) fn new(pool: SqlitePool) -> AuditEvents {
        AuditEvents { pool }
    }

    pub async fn append(&self, records: &[AuditRecord]) -> Result<u64, StoreError> {
        for record in records {
            validate(record)?;
        }
        if records.is_empty() {
            return Ok(0);
        }
        let mut transaction = self.pool.begin().await?;
        let mut inserted = 0;
        for record in records {
            let result = sqlx::query(INSERT)
                .bind(&record.id)
                .bind(record.time_ms)
                .bind(&record.event_type)
                .bind(&record.actor)
                .bind(&record.node)
                .bind(&record.session_id)
                .bind(&record.policy_hash)
                .bind(&record.payload)
                .bind(record.v)
                .execute(&mut *transaction)
                .await?;
            inserted += result.rows_affected();
        }
        transaction.commit().await?;
        Ok(inserted)
    }

    pub async fn query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, StoreError> {
        let mut builder = select_builder("", query)?;
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter().map(record_from_row).collect()
    }

    #[doc(hidden)]
    pub async fn query_plan(&self, query: &AuditQuery) -> Result<Vec<String>, StoreError> {
        let mut builder = select_builder("EXPLAIN QUERY PLAN ", query)?;
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| row.try_get("detail").map_err(StoreError::from))
            .collect()
    }

    pub async fn count_all(&self) -> Result<u64, StoreError> {
        let row = sqlx::query(COUNT_ALL).fetch_one(&self.pool).await?;
        count_from(&row)
    }

    pub async fn count_before(&self, cutoff_ms: i64) -> Result<u64, StoreError> {
        let row = sqlx::query(COUNT_BEFORE)
            .bind(cutoff_ms)
            .fetch_one(&self.pool)
            .await?;
        count_from(&row)
    }

    pub async fn newest_time_ms(&self) -> Result<Option<i64>, StoreError> {
        let row = sqlx::query(NEWEST).fetch_one(&self.pool).await?;
        Ok(row.try_get("newest")?)
    }

    pub async fn delete_before(&self, cutoff_ms: i64, max_rows: u32) -> Result<u64, StoreError> {
        if max_rows == 0 {
            return Err(StoreError::InvalidInput(
                "the audit prune batch must not be empty",
            ));
        }
        let result = sqlx::query(DELETE_BEFORE)
            .bind(cutoff_ms)
            .bind(i64::from(max_rows))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn select_builder(prefix: &str, query: &AuditQuery) -> Result<QueryBuilder<Sqlite>, StoreError> {
    if query.limit == 0 || query.limit > MAX_AUDIT_PAGE {
        return Err(StoreError::InvalidInput(
            "the audit page size is out of range",
        ));
    }
    let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(format!("{prefix}{SELECT}"));
    if let Some(prefix) = &query.type_prefix {
        let length = i64::try_from(prefix.chars().count())
            .map_err(|_| StoreError::InvalidInput("the audit type prefix is too long"))?;
        builder.push(" AND substr(event_type, 1, ");
        builder.push_bind(length);
        builder.push(") = ");
        builder.push_bind(prefix);
    }
    if let Some(actor) = &query.actor {
        builder.push(" AND actor = ");
        builder.push_bind(actor);
    }
    if let Some(node) = &query.node {
        builder.push(" AND node = ");
        builder.push_bind(node);
    }
    if let Some(session_id) = &query.session_id {
        builder.push(" AND session_id = ");
        builder.push_bind(session_id);
    }
    if let Some(from_ms) = query.from_ms {
        builder.push(" AND time_ms >= ");
        builder.push_bind(from_ms);
    }
    if let Some(to_ms) = query.to_ms {
        builder.push(" AND time_ms < ");
        builder.push_bind(to_ms);
    }
    if let Some(after) = &query.after {
        builder.push(" AND (time_ms, id) < (");
        builder.push_bind(after.time_ms);
        builder.push(", ");
        builder.push_bind(&after.id);
        builder.push(")");
    }
    builder.push(" ORDER BY time_ms DESC, id DESC LIMIT ");
    builder.push_bind(i64::from(query.limit));
    Ok(builder)
}

fn count_from(row: &SqliteRow) -> Result<u64, StoreError> {
    let total: i64 = row.try_get("total")?;
    u64::try_from(total).map_err(|_| StoreError::Corrupt("audit_events: negative count".to_owned()))
}

fn validate(record: &AuditRecord) -> Result<(), StoreError> {
    if record.id.is_empty() || record.event_type.is_empty() || record.actor.is_empty() {
        return Err(StoreError::InvalidInput(
            "an audit record needs an id, a type and an actor",
        ));
    }
    if record.v < 1 {
        return Err(StoreError::InvalidInput(
            "the audit schema version must be positive",
        ));
    }
    if record.payload.len() > MAX_AUDIT_PAYLOAD_BYTES {
        return Err(StoreError::InvalidInput("the audit payload is too large"));
    }
    Ok(())
}

fn record_from_row(row: &SqliteRow) -> Result<AuditRecord, StoreError> {
    Ok(AuditRecord {
        id: row.try_get("id")?,
        time_ms: row.try_get("time_ms")?,
        event_type: row.try_get("event_type")?,
        actor: row.try_get("actor")?,
        node: row.try_get("node")?,
        session_id: row.try_get("session_id")?,
        policy_hash: row.try_get("policy_hash")?,
        payload: row.try_get("payload")?,
        v: row.try_get("v")?,
    })
}
