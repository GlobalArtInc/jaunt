use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRequestState {
    Pending,
    Approved,
    Denied,
    Redeemed,
}

impl LoginRequestState {
    fn parse(value: &str) -> Result<LoginRequestState, StoreError> {
        match value {
            "pending" => Ok(LoginRequestState::Pending),
            "approved" => Ok(LoginRequestState::Approved),
            "denied" => Ok(LoginRequestState::Denied),
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
pub struct NewDeviceLoginRequest {
    pub pkce_challenge: String,
    pub client_label: Option<String>,
    pub user_code_hash: String,
    pub requester_ip: String,
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
    pub completion_hash: Option<String>,
    pub user_code_hash: Option<String>,
    pub requester_ip: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub redeemed_at: Option<i64>,
}

const CREATE: &str = "INSERT INTO login_requests \
    (id, kind, state, pkce_challenge, client_label, created_at, expires_at) \
    VALUES (?, ?, 'pending', ?, ?, ?, ?) \
    RETURNING id, kind, state, pkce_challenge, user_id, client_label, \
    completion_hash, user_code_hash, requester_ip, created_at, expires_at, redeemed_at";

const CREATE_DEVICE: &str = "INSERT INTO login_requests \
    (id, kind, state, pkce_challenge, client_label, user_code_hash, requester_ip, \
    created_at, expires_at) \
    SELECT ?, 'device', 'pending', ?, ?, ?, ?, ?, ? \
    WHERE NOT EXISTS (SELECT 1 FROM login_requests \
    WHERE user_code_hash = ? AND state = 'pending' AND expires_at > ?) \
    RETURNING id, kind, state, pkce_challenge, user_id, client_label, \
    completion_hash, user_code_hash, requester_ip, created_at, expires_at, redeemed_at";

const GET: &str = "SELECT id, kind, state, pkce_challenge, user_id, client_label, \
    completion_hash, user_code_hash, requester_ip, created_at, expires_at, redeemed_at \
    FROM login_requests WHERE id = ?";

const FIND_PENDING_DEVICE: &str = "SELECT id, kind, state, pkce_challenge, user_id, \
    client_label, completion_hash, user_code_hash, requester_ip, created_at, expires_at, \
    redeemed_at FROM login_requests \
    WHERE user_code_hash = ? AND kind = 'device' AND state = 'pending' AND expires_at > ? \
    ORDER BY created_at DESC LIMIT 1";

const COUNT_LIVE_DEVICE: &str = "SELECT COUNT(*) AS live FROM login_requests \
    WHERE kind = 'device' AND expires_at > ?";

const APPROVE: &str = "UPDATE login_requests \
    SET state = 'approved', user_id = ?, completion_hash = ? \
    WHERE id = ? AND state = 'pending' AND expires_at > ? RETURNING id";

const DENY: &str = "UPDATE login_requests SET state = 'denied' \
    WHERE id = ? AND state = 'pending' AND expires_at > ? RETURNING id";

const REDEEM: &str = "UPDATE login_requests SET state = 'redeemed', redeemed_at = ? \
    WHERE id = ? AND state = 'approved' AND expires_at > ? \
    RETURNING id, kind, state, pkce_challenge, user_id, client_label, \
    completion_hash, user_code_hash, requester_ip, created_at, expires_at, redeemed_at";

const PURGE_EXPIRED: &str = "DELETE FROM login_requests WHERE expires_at < ?";

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

    pub async fn create_device(
        &self,
        request: &NewDeviceLoginRequest,
        now: i64,
    ) -> Result<Option<LoginRequest>, StoreError> {
        if request.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        if request.user_code_hash.is_empty() {
            return Err(StoreError::InvalidInput("user_code_hash must not be empty"));
        }
        let expires_at = now
            .checked_add(request.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let row = sqlx::query(CREATE_DEVICE)
            .bind(Uuid::new_v4().to_string())
            .bind(&request.pkce_challenge)
            .bind(&request.client_label)
            .bind(&request.user_code_hash)
            .bind(&request.requester_ip)
            .bind(now)
            .bind(expires_at)
            .bind(&request.user_code_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(request_from_row).transpose()
    }

    pub async fn find_pending_device(
        &self,
        user_code_hash: &str,
        now: i64,
    ) -> Result<Option<LoginRequest>, StoreError> {
        let row = sqlx::query(FIND_PENDING_DEVICE)
            .bind(user_code_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(request_from_row).transpose()
    }

    pub async fn count_live_device(&self, now: i64) -> Result<i64, StoreError> {
        let row = sqlx::query(COUNT_LIVE_DEVICE)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("live")?)
    }

    pub async fn get(&self, id: &str) -> Result<Option<LoginRequest>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(request_from_row).transpose()
    }

    pub async fn approve(
        &self,
        id: &str,
        user_id: &str,
        completion_hash: Option<&str>,
        now: i64,
    ) -> Result<bool, StoreError> {
        let row = sqlx::query(APPROVE)
            .bind(user_id)
            .bind(completion_hash)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn deny(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        let row = sqlx::query(DENY)
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

    pub async fn purge_expired(&self, older_than: i64) -> Result<u64, StoreError> {
        let result = sqlx::query(PURGE_EXPIRED)
            .bind(older_than)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
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
        completion_hash: row.try_get("completion_hash")?,
        user_code_hash: row.try_get("user_code_hash")?,
        requester_ip: row.try_get("requester_ip")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        redeemed_at: row.try_get("redeemed_at")?,
    })
}
