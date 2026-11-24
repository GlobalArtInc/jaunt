use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;
use crate::users::{User, user_from_row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApiToken {
    pub token_hash: String,
    pub user_id: String,
    pub cert_serial: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiToken {
    pub token_hash: String,
    pub user_id: String,
    pub cert_serial: i64,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidApiToken {
    pub token: ApiToken,
    pub user: User,
}

const CREATE: &str = "INSERT INTO api_tokens \
    (token_hash, user_id, cert_serial, created_at, expires_at) \
    VALUES (?, ?, ?, ?, ?)";

const FIND_VALID: &str = "SELECT t.token_hash AS token_hash, t.cert_serial AS cert_serial, \
    t.created_at AS token_created_at, t.expires_at AS token_expires_at, \
    u.id AS id, u.issuer AS issuer, u.subject AS subject, u.email AS email, \
    u.display_name AS display_name, u.groups AS groups, \
    u.created_at AS created_at, u.updated_at AS updated_at \
    FROM api_tokens t JOIN users u ON u.id = t.user_id \
    WHERE t.token_hash = ? AND t.expires_at > ?";

#[derive(Clone)]
pub struct ApiTokens {
    pool: SqlitePool,
}

impl ApiTokens {
    pub(crate) fn new(pool: SqlitePool) -> ApiTokens {
        ApiTokens { pool }
    }

    pub async fn create(&self, token: &NewApiToken) -> Result<(), StoreError> {
        if token.expires_at <= token.created_at {
            return Err(StoreError::InvalidInput(
                "expires_at must be after created_at",
            ));
        }
        sqlx::query(CREATE)
            .bind(&token.token_hash)
            .bind(&token.user_id)
            .bind(token.cert_serial)
            .bind(token.created_at)
            .bind(token.expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn find_valid(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ValidApiToken>, StoreError> {
        let row = sqlx::query(FIND_VALID)
            .bind(token_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(valid_token_from_row).transpose()
    }
}

fn valid_token_from_row(row: &SqliteRow) -> Result<ValidApiToken, StoreError> {
    let user = user_from_row(row)?;
    Ok(ValidApiToken {
        token: ApiToken {
            token_hash: row.try_get("token_hash")?,
            user_id: user.id.clone(),
            cert_serial: row.try_get("cert_serial")?,
            created_at: row.try_get("token_created_at")?,
            expires_at: row.try_get("token_expires_at")?,
        },
        user,
    })
}
