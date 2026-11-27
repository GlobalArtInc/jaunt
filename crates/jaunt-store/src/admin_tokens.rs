use std::fmt;

use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};

use crate::StoreError;

const REDACTED: &str = "SecretHash([redacted])";

#[derive(Clone, PartialEq, Eq)]
pub struct SecretHash(String);

impl SecretHash {
    pub fn new(hash: String) -> SecretHash {
        SecretHash(hash)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAdminToken {
    pub id: String,
    pub name: String,
    pub creator_user_id: String,
    pub secret_hash: SecretHash,
    pub scope: Vec<String>,
    pub cidrs: Vec<String>,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminToken {
    pub id: String,
    pub name: String,
    pub creator_user_id: String,
    pub scope: Vec<String>,
    pub cidrs: Vec<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAdminToken {
    pub token: AdminToken,
    pub secret_hash: SecretHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminTokenCaps {
    pub max_live_per_creator: u32,
    pub max_dead_per_creator: u32,
    pub max_created_per_window: u32,
    pub window_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminTokenCreated {
    Created(AdminToken),
    NameTaken,
    TooMany,
    TooFrequent { retry_after_secs: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminTokenRevoked {
    Revoked(AdminToken),
    AlreadyRevoked,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTokenPage {
    pub tokens: Vec<AdminToken>,
    pub truncated: bool,
}

macro_rules! admin_token_columns {
    () => {
        "id, name, creator_user_id, scope, cidrs, created_at, expires_at, revoked_at, last_used_at"
    };
}

macro_rules! died_at {
    () => {
        "MIN(COALESCE(revoked_at, expires_at), expires_at)"
    };
}

const CREATE: &str = concat!(
    "INSERT INTO admin_tokens (id, name, creator_user_id, secret_hash, scope, cidrs, created_at, \
     expires_at, revoked_at, last_used_at) \
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL \
     WHERE NOT EXISTS (SELECT 1 FROM admin_tokens WHERE creator_user_id = ? AND name = ? \
     AND revoked_at IS NULL AND expires_at > ?) \
     AND (SELECT COUNT(*) FROM admin_tokens WHERE creator_user_id = ? AND revoked_at IS NULL \
     AND expires_at > ?) < ? \
     AND (SELECT COUNT(*) FROM admin_tokens WHERE creator_user_id = ? AND created_at > ?) < ? \
     RETURNING ",
    admin_token_columns!()
);

const RECENT: &str = "SELECT COUNT(*) AS recent, MIN(created_at) AS oldest FROM admin_tokens \
    WHERE creator_user_id = ? AND created_at > ?";

const NAME_TAKEN: &str = "SELECT EXISTS (SELECT 1 FROM admin_tokens WHERE creator_user_id = ? \
    AND name = ? AND revoked_at IS NULL AND expires_at > ?) AS taken";

const TRIM_DEAD: &str = concat!(
    "DELETE FROM admin_tokens WHERE creator_user_id = ? AND id IN \
     (SELECT id FROM admin_tokens WHERE creator_user_id = ? \
     AND (revoked_at IS NOT NULL OR expires_at <= ?) ORDER BY ",
    died_at!(),
    " DESC, id DESC LIMIT -1 OFFSET ?)"
);

const GET_FOR_USE: &str = concat!(
    "SELECT ",
    admin_token_columns!(),
    ", secret_hash FROM admin_tokens WHERE id = ?"
);

const LIST: &str = concat!(
    "SELECT ",
    admin_token_columns!(),
    " FROM admin_tokens WHERE (revoked_at IS NULL AND expires_at > ?) OR ",
    died_at!(),
    " >= ? ORDER BY (revoked_at IS NULL AND expires_at > ?) DESC, created_at DESC, id DESC LIMIT ?"
);

const REVOKE: &str = concat!(
    "UPDATE admin_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING ",
    admin_token_columns!()
);

const EXISTS: &str = "SELECT 1 AS present FROM admin_tokens WHERE id = ?";

const TOUCH: &str = "UPDATE admin_tokens SET last_used_at = ? \
    WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)";

const PURGE_DEAD: &str = "DELETE FROM admin_tokens WHERE expires_at < ? OR revoked_at < ?";

#[derive(Clone)]
pub struct AdminTokens {
    pool: SqlitePool,
}

impl AdminTokens {
    pub(crate) fn new(pool: SqlitePool) -> AdminTokens {
        AdminTokens { pool }
    }

    pub async fn create(
        &self,
        token: &NewAdminToken,
        now: i64,
        caps: AdminTokenCaps,
    ) -> Result<AdminTokenCreated, StoreError> {
        if token.id.is_empty() || token.name.is_empty() || token.creator_user_id.is_empty() {
            return Err(StoreError::InvalidInput(
                "the id, name and creator must not be empty",
            ));
        }
        if token.secret_hash.expose().is_empty() {
            return Err(StoreError::InvalidInput(
                "the secret hash must not be empty",
            ));
        }
        if token.scope.is_empty() {
            return Err(StoreError::InvalidInput("the scope must not be empty"));
        }
        if token.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        if caps.max_live_per_creator == 0
            || caps.max_created_per_window == 0
            || caps.window_secs <= 0
        {
            return Err(StoreError::InvalidInput("every cap must be positive"));
        }
        let expires_at = now
            .checked_add(token.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let window_start = now.saturating_sub(caps.window_secs);
        let scope = list_to_text(&token.scope)?;
        let cidrs = list_to_text(&token.cidrs)?;
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(CREATE)
            .bind(&token.id)
            .bind(&token.name)
            .bind(&token.creator_user_id)
            .bind(token.secret_hash.expose())
            .bind(scope)
            .bind(cidrs)
            .bind(now)
            .bind(expires_at)
            .bind(&token.creator_user_id)
            .bind(&token.name)
            .bind(now)
            .bind(&token.creator_user_id)
            .bind(now)
            .bind(i64::from(caps.max_live_per_creator))
            .bind(&token.creator_user_id)
            .bind(window_start)
            .bind(i64::from(caps.max_created_per_window))
            .fetch_optional(&mut *transaction)
            .await?;
        if let Some(row) = row {
            let created = token_from_row(&row)?;
            trim_dead(
                &mut transaction,
                &token.creator_user_id,
                now,
                caps.max_dead_per_creator,
            )
            .await?;
            transaction.commit().await?;
            return Ok(AdminTokenCreated::Created(created));
        }
        transaction.rollback().await?;
        let recent = sqlx::query(RECENT)
            .bind(&token.creator_user_id)
            .bind(window_start)
            .fetch_one(&self.pool)
            .await?;
        if recent.try_get::<i64, _>("recent")? >= i64::from(caps.max_created_per_window) {
            let oldest: Option<i64> = recent.try_get("oldest")?;
            let retry_after_secs = oldest
                .map_or(caps.window_secs, |oldest| {
                    oldest.saturating_add(caps.window_secs).saturating_sub(now)
                })
                .max(1);
            return Ok(AdminTokenCreated::TooFrequent { retry_after_secs });
        }
        let taken = sqlx::query(NAME_TAKEN)
            .bind(&token.creator_user_id)
            .bind(&token.name)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        Ok(if taken.try_get::<i64, _>("taken")? == 1 {
            AdminTokenCreated::NameTaken
        } else {
            AdminTokenCreated::TooMany
        })
    }

    pub async fn get_for_use(&self, id: &str) -> Result<Option<StoredAdminToken>, StoreError> {
        let row = sqlx::query(GET_FOR_USE)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(StoredAdminToken {
                token: token_from_row(&row)?,
                secret_hash: SecretHash(row.try_get("secret_hash")?),
            })
        })
        .transpose()
    }

    pub async fn list(
        &self,
        now: i64,
        dead_since: i64,
        limit: u32,
    ) -> Result<AdminTokenPage, StoreError> {
        let rows = sqlx::query(LIST)
            .bind(now)
            .bind(dead_since)
            .bind(now)
            .bind(i64::from(limit).saturating_add(1))
            .fetch_all(&self.pool)
            .await?;
        let mut tokens = rows
            .iter()
            .map(token_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        let truncated = tokens.len() > wanted;
        tokens.truncate(wanted);
        Ok(AdminTokenPage { tokens, truncated })
    }

    pub async fn revoke(
        &self,
        id: &str,
        now: i64,
        max_dead_per_creator: u32,
    ) -> Result<AdminTokenRevoked, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query(REVOKE)
            .bind(now)
            .bind(id)
            .fetch_optional(&mut *transaction)
            .await?;
        if let Some(row) = row {
            let revoked = token_from_row(&row)?;
            trim_dead(
                &mut transaction,
                &revoked.creator_user_id,
                now,
                max_dead_per_creator,
            )
            .await?;
            transaction.commit().await?;
            return Ok(AdminTokenRevoked::Revoked(revoked));
        }
        transaction.rollback().await?;
        let present = sqlx::query(EXISTS)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(if present.is_some() {
            AdminTokenRevoked::AlreadyRevoked
        } else {
            AdminTokenRevoked::Unknown
        })
    }

    pub async fn touch(
        &self,
        id: &str,
        now: i64,
        min_interval_secs: i64,
    ) -> Result<bool, StoreError> {
        let done = sqlx::query(TOUCH)
            .bind(now)
            .bind(id)
            .bind(now.saturating_sub(min_interval_secs))
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub async fn purge_dead(&self, older_than: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PURGE_DEAD)
            .bind(older_than)
            .bind(older_than)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }
}

async fn trim_dead(
    transaction: &mut Transaction<'_, Sqlite>,
    creator_user_id: &str,
    now: i64,
    keep: u32,
) -> Result<u64, StoreError> {
    let done = sqlx::query(TRIM_DEAD)
        .bind(creator_user_id)
        .bind(creator_user_id)
        .bind(now)
        .bind(i64::from(keep))
        .execute(&mut **transaction)
        .await?;
    Ok(done.rows_affected())
}

fn list_to_text(values: &[String]) -> Result<String, StoreError> {
    serde_json::to_string(values).map_err(|_| StoreError::InvalidInput("list serialization failed"))
}

fn list_from_row(row: &SqliteRow, column: &'static str) -> Result<Vec<String>, StoreError> {
    let text: String = row.try_get(column)?;
    serde_json::from_str(&text)
        .map_err(|err| StoreError::Corrupt(format!("admin_tokens.{column}: {err}")))
}

fn token_from_row(row: &SqliteRow) -> Result<AdminToken, StoreError> {
    Ok(AdminToken {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        creator_user_id: row.try_get("creator_user_id")?,
        scope: list_from_row(row, "scope")?,
        cidrs: list_from_row(row, "cidrs")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        last_used_at: row.try_get("last_used_at")?,
    })
}
