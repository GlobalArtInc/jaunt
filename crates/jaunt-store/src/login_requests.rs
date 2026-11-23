use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRequestState {
    Pending,
    Approved,
    Redeemed,
}

impl LoginRequestState {
    fn parse(value: &str) -> Result<LoginRequestState, StoreError> {
        match value {
            "pending" => Ok(LoginRequestState::Pending),
            "approved" => Ok(LoginRequestState::Approved),
            "redeemed" => Ok(LoginRequestState::Redeemed),
            other => Err(StoreError::Corrupt(format!(
                "login_requests.state: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewLoginRequest {
    pub kind: String,
    pub pkce_challenge: String,
    pub client_label: Option<String>,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub id: String,
    pub kind: String,
    pub state: LoginRequestState,
    pub pkce_challenge: String,
    pub user_id: Option<String>,
    pub client_label: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub redeemed_at: Option<i64>,
}

const CREATE: &str = "INSERT INTO login_requests \
    (id, kind, state, pkce_challenge, client_label, created_at, expires_at) \
    VALUES (?, ?, 'pending', ?, ?, ?, ?) \
    RETURNING id, kind, state, pkce_challenge, user_id, client_label, \
    created_at, expires_at, redeemed_at";

const GET: &str = "SELECT id, kind, state, pkce_challenge, user_id, client_label, \
    created_at, expires_at, redeemed_at FROM login_requests WHERE id = ?";

const APPROVE: &str = "UPDATE login_requests SET state = 'approved', user_id = ? \
    WHERE id = ? AND state = 'pending' AND expires_at > ? RETURNING id";

const REDEEM: &str = "UPDATE login_requests SET state = 'redeemed', redeemed_at = ? \
    WHERE id = ? AND state = 'approved' AND expires_at > ? \
    RETURNING id, kind, state, pkce_challenge, user_id, client_label, \
    created_at, expires_at, redeemed_at";

#[derive(Clone)]
pub struct LoginRequests {
    pool: SqlitePool,
}

impl LoginRequests {
    pub(crate) fn new(pool: SqlitePool) -> LoginRequests {
        LoginRequests { pool }
    }

    pub async fn create(
        &self,
        request: &NewLoginRequest,
        now: i64,
    ) -> Result<LoginRequest, StoreError> {
        if request.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        let expires_at = now
            .checked_add(request.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let row = sqlx::query(CREATE)
            .bind(Uuid::new_v4().to_string())
            .bind(&request.kind)
            .bind(&request.pkce_challenge)
            .bind(&request.client_label)
            .bind(now)
            .bind(expires_at)
            .fetch_one(&self.pool)
            .await?;
        request_from_row(&row)
    }

    pub async fn get(&self, id: &str) -> Result<Option<LoginRequest>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(request_from_row).transpose()
    }

    pub async fn approve(&self, id: &str, user_id: &str, now: i64) -> Result<bool, StoreError> {
        let row = sqlx::query(APPROVE)
            .bind(user_id)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn redeem(&self, id: &str, now: i64) -> Result<Option<LoginRequest>, StoreError> {
        let row = sqlx::query(REDEEM)
            .bind(now)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(request_from_row).transpose()
    }
}

fn request_from_row(row: &SqliteRow) -> Result<LoginRequest, StoreError> {
    let state: String = row.try_get("state")?;
    Ok(LoginRequest {
        id: row.try_get("id")?,
        kind: row.try_get("kind")?,
        state: LoginRequestState::parse(&state)?,
        pkce_challenge: row.try_get("pkce_challenge")?,
        user_id: row.try_get("user_id")?,
        client_label: row.try_get("client_label")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        redeemed_at: row.try_get("redeemed_at")?,
    })
}
