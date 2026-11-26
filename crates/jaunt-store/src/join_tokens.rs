use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::StoreError;
use crate::enrollments::{
    Enrollment, INSERT_NODE, REPLACE_ACTIVE_NODE, enrollment_columns, enrollment_from_row,
    is_unique_violation,
};
use crate::nodes::{Labels, Node, labels_to_text, node_from_row, reject_unclaimed_enrollments};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameScope {
    Exact(String),
    Prefix(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJoinToken {
    pub hash: String,
    pub scope: NameScope,
    pub labels: Labels,
    pub max_uses: i64,
    pub allow_replace: bool,
    pub created_by: String,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinToken {
    pub id: String,
    pub scope: NameScope,
    pub labels: Labels,
    pub max_uses: i64,
    pub uses_left: i64,
    pub expires_at: i64,
    pub allow_replace: bool,
    pub created_by: String,
    pub created_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenFailure {
    Unknown,
    Expired,
    UsedUp,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unusable {
    pub failure: TokenFailure,
    pub token_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct JoinEnrollment<'a> {
    pub token_id: &'a str,
    pub token_hash: &'a str,
    pub handle_hash: &'a str,
    pub name: &'a str,
    pub labels: &'a Labels,
    pub hostname: &'a str,
    pub source_ip: &'a str,
    pub peer_addr: &'a str,
    pub tls_public_key: &'a str,
    pub ssh_host_public_key: &'a str,
    pub tls_spki_sha256: &'a str,
    pub ssh_host_key_fingerprint: &'a str,
    pub replace_existing: bool,
    pub agent_version: &'a str,
    pub approved_by: &'a str,
    pub ttl_secs: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Joined {
    pub enrollment: Enrollment,
    pub node: Node,
    pub replaced: Option<Node>,
    pub uses_left: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinOutcome {
    Joined(Box<Joined>),
    Unusable(Unusable),
    NameTaken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenRevokeOutcome {
    Revoked(Box<JoinToken>),
    AlreadyRevoked,
    Unknown,
}

macro_rules! token_columns {
    () => {
        "id, name, name_prefix, labels, max_uses, uses_left, expires_at, allow_replace, \
         created_by, created_at, revoked_at"
    };
}

const CREATE: &str = concat!(
    "INSERT INTO join_tokens (id, hash, name, name_prefix, labels, max_uses, uses_left, \
     expires_at, allow_replace, created_by, created_at, revoked_at) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL) RETURNING ",
    token_columns!()
);

const FIND_USABLE: &str = concat!(
    "SELECT ",
    token_columns!(),
    " FROM join_tokens WHERE hash = ? AND uses_left > 0 AND revoked_at IS NULL \
     AND expires_at > ?"
);

const CLASSIFY: &str =
    "SELECT id, uses_left, expires_at, revoked_at FROM join_tokens WHERE hash = ?";

const CONSUME: &str = "UPDATE join_tokens SET uses_left = uses_left - 1 \
    WHERE hash = ? AND id = ? AND uses_left > 0 AND revoked_at IS NULL AND expires_at > ? \
    RETURNING uses_left, allow_replace";

const INSERT_APPROVED_ENROLLMENT: &str = concat!(
    "INSERT INTO enrollments (",
    enrollment_columns!(),
    ") VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, NULL, NULL, ?, ?) \
     RETURNING ",
    enrollment_columns!()
);

const LIST: &str = concat!(
    "SELECT ",
    token_columns!(),
    " FROM join_tokens ORDER BY created_at, id"
);

const REVOKE: &str = concat!(
    "UPDATE join_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING ",
    token_columns!()
);

const EXISTS: &str = "SELECT 1 AS present FROM join_tokens WHERE id = ?";

const PURGE_EXPIRED: &str = "DELETE FROM join_tokens WHERE expires_at < ?";

#[derive(Clone)]
pub struct JoinTokens {
    pool: SqlitePool,
}

impl JoinTokens {
    pub(crate) fn new(pool: SqlitePool) -> JoinTokens {
        JoinTokens { pool }
    }

    pub async fn create(&self, token: &NewJoinToken, now: i64) -> Result<JoinToken, StoreError> {
        if token.hash.is_empty() {
            return Err(StoreError::InvalidInput("the token hash must not be empty"));
        }
        if token.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        if token.max_uses <= 0 {
            return Err(StoreError::InvalidInput("max_uses must be positive"));
        }
        if token.created_by.is_empty() {
            return Err(StoreError::InvalidInput("created_by must not be empty"));
        }
        let expires_at = now
            .checked_add(token.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let (name, name_prefix) = match &token.scope {
            NameScope::Exact(name) => (Some(name.as_str()), None),
            NameScope::Prefix(prefix) => (None, Some(prefix.as_str())),
        };
        if name.is_some_and(str::is_empty) || name_prefix.is_some_and(str::is_empty) {
            return Err(StoreError::InvalidInput(
                "the name or name prefix must not be empty",
            ));
        }
        let row = sqlx::query(CREATE)
            .bind(Uuid::new_v4().to_string())
            .bind(&token.hash)
            .bind(name)
            .bind(name_prefix)
            .bind(labels_to_text(&token.labels)?)
            .bind(token.max_uses)
            .bind(token.max_uses)
            .bind(expires_at)
            .bind(i64::from(token.allow_replace))
            .bind(&token.created_by)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        token_from_row(&row)
    }

    pub async fn find_usable(&self, hash: &str, now: i64) -> Result<Option<JoinToken>, StoreError> {
        let row = sqlx::query(FIND_USABLE)
            .bind(hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(token_from_row).transpose()
    }

    pub async fn classify(&self, hash: &str, now: i64) -> Result<Option<Unusable>, StoreError> {
        let row = sqlx::query(CLASSIFY)
            .bind(hash)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(Some(Unusable {
                failure: TokenFailure::Unknown,
                token_id: None,
            }));
        };
        let id: String = row.try_get("id")?;
        let uses_left: i64 = row.try_get("uses_left")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        let revoked_at: Option<i64> = row.try_get("revoked_at")?;
        let failure = if revoked_at.is_some() {
            TokenFailure::Revoked
        } else if expires_at <= now {
            TokenFailure::Expired
        } else if uses_left <= 0 {
            TokenFailure::UsedUp
        } else {
            return Ok(None);
        };
        Ok(Some(Unusable {
            failure,
            token_id: Some(id),
        }))
    }

    pub async fn enroll(&self, request: JoinEnrollment<'_>) -> Result<JoinOutcome, StoreError> {
        if request.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        let expires_at = request
            .now
            .checked_add(request.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let labels = labels_to_text(request.labels)?;
        let node_id = Uuid::new_v4().to_string();

        let mut tx = self.pool.begin().await?;
        let consumed = sqlx::query(CONSUME)
            .bind(request.token_hash)
            .bind(request.token_id)
            .bind(request.now)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(consumed) = consumed else {
            tx.rollback().await?;
            return match self.classify(request.token_hash, request.now).await? {
                Some(unusable) => Ok(JoinOutcome::Unusable(unusable)),
                None => Err(StoreError::InvalidInput(
                    "the token id does not belong to the token hash",
                )),
            };
        };
        let uses_left: i64 = consumed.try_get("uses_left")?;
        let replace_existing =
            request.replace_existing && consumed.try_get::<i64, _>("allow_replace")? == 1;

        let replaced = if replace_existing {
            let removed = sqlx::query(REPLACE_ACTIVE_NODE)
                .bind(request.now)
                .bind(request.name)
                .fetch_optional(&mut *tx)
                .await?;
            match removed {
                Some(row) => {
                    let old = node_from_row(&row)?;
                    reject_unclaimed_enrollments(&mut tx, &old.id).await?;
                    Some(old)
                }
                None => None,
            }
        } else {
            None
        };

        let inserted = sqlx::query(INSERT_NODE)
            .bind(&node_id)
            .bind(request.name)
            .bind(&labels)
            .bind(request.hostname)
            .bind(request.tls_public_key)
            .bind(request.ssh_host_public_key)
            .bind(request.tls_spki_sha256)
            .bind(request.ssh_host_key_fingerprint)
            .bind(request.approved_by)
            .bind(request.now)
            .bind(request.agent_version)
            .fetch_one(&mut *tx)
            .await;
        let node = match inserted {
            Ok(row) => node_from_row(&row)?,
            Err(err) if is_unique_violation(&err) => {
                tx.rollback().await?;
                return Ok(JoinOutcome::NameTaken);
            }
            Err(err) => return Err(err.into()),
        };

        let created = sqlx::query(INSERT_APPROVED_ENROLLMENT)
            .bind(Uuid::new_v4().to_string())
            .bind(request.handle_hash)
            .bind(request.name)
            .bind(&labels)
            .bind(request.hostname)
            .bind(request.source_ip)
            .bind(request.peer_addr)
            .bind(request.tls_public_key)
            .bind(request.ssh_host_public_key)
            .bind(i64::from(replace_existing))
            .bind(request.agent_version)
            .bind(&node.id)
            .bind(request.approved_by)
            .bind(request.now)
            .bind(expires_at)
            .fetch_one(&mut *tx)
            .await?;
        let enrollment = enrollment_from_row(&created)?;
        tx.commit().await?;
        Ok(JoinOutcome::Joined(Box::new(Joined {
            enrollment,
            node,
            replaced,
            uses_left,
        })))
    }

    pub async fn list(&self) -> Result<Vec<JoinToken>, StoreError> {
        let rows = sqlx::query(LIST).fetch_all(&self.pool).await?;
        rows.iter().map(token_from_row).collect()
    }

    pub async fn revoke(&self, id: &str, now: i64) -> Result<TokenRevokeOutcome, StoreError> {
        let row = sqlx::query(REVOKE)
            .bind(now)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            return Ok(TokenRevokeOutcome::Revoked(Box::new(token_from_row(&row)?)));
        }
        let present = sqlx::query(EXISTS)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(if present.is_some() {
            TokenRevokeOutcome::AlreadyRevoked
        } else {
            TokenRevokeOutcome::Unknown
        })
    }

    pub async fn purge_expired(&self, older_than: i64) -> Result<u64, StoreError> {
        let done = sqlx::query(PURGE_EXPIRED)
            .bind(older_than)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected())
    }
}

fn token_from_row(row: &SqliteRow) -> Result<JoinToken, StoreError> {
    let name: Option<String> = row.try_get("name")?;
    let name_prefix: Option<String> = row.try_get("name_prefix")?;
    let scope = match (name, name_prefix) {
        (Some(name), None) => NameScope::Exact(name),
        (None, Some(prefix)) => NameScope::Prefix(prefix),
        _ => {
            return Err(StoreError::Corrupt(
                "join_tokens: exactly one of name and name_prefix must be set".to_owned(),
            ));
        }
    };
    let labels: String = row.try_get("labels")?;
    let labels = serde_json::from_str(&labels)
        .map_err(|err| StoreError::Corrupt(format!("join_tokens.labels: {err}")))?;
    let allow_replace = match row.try_get::<i64, _>("allow_replace")? {
        0 => false,
        1 => true,
        other => {
            return Err(StoreError::Corrupt(format!(
                "join_tokens.allow_replace: {other}"
            )));
        }
    };
    Ok(JoinToken {
        id: row.try_get("id")?,
        scope,
        labels,
        max_uses: row.try_get("max_uses")?,
        uses_left: row.try_get("uses_left")?,
        expires_at: row.try_get("expires_at")?,
        allow_replace,
        created_by: row.try_get("created_by")?,
        created_at: row.try_get("created_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}
