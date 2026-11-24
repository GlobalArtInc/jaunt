use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;
use crate::users::{User, user_from_row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWebSession {
    pub id_hash: String,
    pub user_id: String,
    pub csrf_token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebSession {
    pub id_hash: String,
    pub user_id: String,
    pub csrf_token_hash: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: i64,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidWebSession {
    pub session: WebSession,
    pub user: User,
}

const INSERT: &str = "INSERT INTO web_sessions \
    (id_hash, user_id, csrf_token_hash, created_at, expires_at, last_seen_at, source_ip, \
    user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

const TRIM_OLDEST: &str = "DELETE FROM web_sessions \
    WHERE user_id = ? AND id_hash <> ? AND id_hash NOT IN \
    (SELECT id_hash FROM web_sessions WHERE user_id = ? AND id_hash <> ? \
    ORDER BY created_at DESC, id_hash DESC LIMIT ?)";

const GET: &str = "SELECT id_hash, user_id, csrf_token_hash, created_at, expires_at, \
    last_seen_at, source_ip, user_agent FROM web_sessions WHERE id_hash = ?";

const FIND_VALID: &str = "SELECT s.id_hash AS id_hash, s.user_id AS user_id, \
    s.csrf_token_hash AS csrf_token_hash, s.created_at AS session_created_at, \
    s.expires_at AS session_expires_at, s.last_seen_at AS last_seen_at, \
    s.source_ip AS source_ip, s.user_agent AS user_agent, \
    u.id AS id, u.issuer AS issuer, u.subject AS subject, u.email AS email, \
    u.username AS username, u.display_name AS display_name, u.groups AS groups, \
    u.created_at AS created_at, u.updated_at AS updated_at \
    FROM web_sessions s JOIN users u ON u.id = s.user_id \
    WHERE s.id_hash = ? AND s.expires_at > ?";

const TOUCH: &str = "UPDATE web_sessions SET last_seen_at = ? \
    WHERE id_hash = ? AND last_seen_at <= ? AND expires_at > ?";

const DELETE: &str = "DELETE FROM web_sessions WHERE id_hash = ? RETURNING user_id";

const DELETE_EXPIRED: &str =
    "DELETE FROM web_sessions WHERE id_hash = ? AND expires_at <= ? RETURNING user_id";

const PURGE_EXPIRED: &str = "DELETE FROM web_sessions WHERE expires_at <= ? RETURNING user_id";

const COUNT_FOR_USER: &str = "SELECT COUNT(*) AS total FROM web_sessions WHERE user_id = ?";

#[derive(Clone)]
pub struct WebSessions {
    pool: SqlitePool,
}

impl WebSessions {
    pub(crate) fn new(pool: SqlitePool) -> WebSessions {
        WebSessions { pool }
    }

    pub async fn create(
        &self,
        session: &NewWebSession,
        max_per_user: u32,
    ) -> Result<(), StoreError> {
        if session.expires_at <= session.created_at {
            return Err(StoreError::InvalidInput(
                "expires_at must be after created_at",
            ));
        }
        if session.id_hash.is_empty() || session.csrf_token_hash.is_empty() {
            return Err(StoreError::InvalidInput("session hashes must not be empty"));
        }
        if max_per_user == 0 {
            return Err(StoreError::InvalidInput(
                "max_per_user must be at least one",
            ));
        }
        let kept_besides_new = i64::from(max_per_user - 1);
        let mut transaction = self.pool.begin().await?;
        sqlx::query(INSERT)
            .bind(&session.id_hash)
            .bind(&session.user_id)
            .bind(&session.csrf_token_hash)
            .bind(session.created_at)
            .bind(session.expires_at)
            .bind(session.created_at)
            .bind(&session.source_ip)
            .bind(&session.user_agent)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(TRIM_OLDEST)
            .bind(&session.user_id)
            .bind(&session.id_hash)
            .bind(&session.user_id)
            .bind(&session.id_hash)
            .bind(kept_besides_new)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get(&self, id_hash: &str) -> Result<Option<WebSession>, StoreError> {
        let row = sqlx::query(GET)
            .bind(id_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(session_from_row).transpose()
    }

    pub async fn find_valid(
        &self,
        id_hash: &str,
        now: i64,
    ) -> Result<Option<ValidWebSession>, StoreError> {
        let row = sqlx::query(FIND_VALID)
            .bind(id_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(valid_session_from_row).transpose()
    }

    pub async fn touch(
        &self,
        id_hash: &str,
        now: i64,
        min_interval_secs: i64,
    ) -> Result<bool, StoreError> {
        let result = sqlx::query(TOUCH)
            .bind(now)
            .bind(id_hash)
            .bind(now.saturating_sub(min_interval_secs))
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete(&self, id_hash: &str) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(DELETE)
            .bind(id_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| row.try_get("user_id").map_err(StoreError::from))
            .transpose()
    }

    pub async fn delete_expired(
        &self,
        id_hash: &str,
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(DELETE_EXPIRED)
            .bind(id_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| row.try_get("user_id").map_err(StoreError::from))
            .transpose()
    }

    pub async fn purge_expired(&self, now: i64) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(PURGE_EXPIRED)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| row.try_get("user_id").map_err(StoreError::from))
            .collect()
    }

    pub async fn count_for_user(&self, user_id: &str) -> Result<i64, StoreError> {
        let row = sqlx::query(COUNT_FOR_USER)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("total")?)
    }
}

fn session_from_row(row: &SqliteRow) -> Result<WebSession, StoreError> {
    Ok(WebSession {
        id_hash: row.try_get("id_hash")?,
        user_id: row.try_get("user_id")?,
        csrf_token_hash: row.try_get("csrf_token_hash")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        source_ip: row.try_get("source_ip")?,
        user_agent: row.try_get("user_agent")?,
    })
}

fn valid_session_from_row(row: &SqliteRow) -> Result<ValidWebSession, StoreError> {
    let user = user_from_row(row)?;
    Ok(ValidWebSession {
        session: WebSession {
            id_hash: row.try_get("id_hash")?,
            user_id: user.id.clone(),
            csrf_token_hash: row.try_get("csrf_token_hash")?,
            created_at: row.try_get("session_created_at")?,
            expires_at: row.try_get("session_expires_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            source_ip: row.try_get("source_ip")?,
            user_agent: row.try_get("user_agent")?,
        },
        user,
    })
}
