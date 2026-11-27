use sqlx::{Row, SqlitePool};

use crate::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinOutcome {
    Pinned,
    AlreadyPinned,
    Full,
}

const PIN: &str = "INSERT INTO user_pins (user_id, node_id, created_at) \
    SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM user_pins p JOIN nodes n ON n.id = p.node_id \
    WHERE p.user_id = ? AND n.state = 'active') < ? \
    ON CONFLICT (user_id, node_id) DO NOTHING";

const EXISTS: &str = "SELECT 1 FROM user_pins WHERE user_id = ? AND node_id = ?";

const UNPIN: &str = "DELETE FROM user_pins WHERE user_id = ? AND node_id = ?";

const NODES_OF_USER: &str = "SELECT p.node_id AS node_id FROM user_pins p \
    JOIN nodes n ON n.id = p.node_id WHERE p.user_id = ? AND n.state = 'active' \
    ORDER BY p.created_at, p.node_id";

#[derive(Clone)]
pub struct UserPins {
    pool: SqlitePool,
}

impl UserPins {
    pub(crate) fn new(pool: SqlitePool) -> UserPins {
        UserPins { pool }
    }

    pub async fn pin(
        &self,
        user_id: &str,
        node_id: &str,
        now: i64,
        max_per_user: u32,
    ) -> Result<PinOutcome, StoreError> {
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(PIN)
            .bind(user_id)
            .bind(node_id)
            .bind(now)
            .bind(user_id)
            .bind(i64::from(max_per_user))
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        let outcome = if inserted == 1 {
            PinOutcome::Pinned
        } else if sqlx::query(EXISTS)
            .bind(user_id)
            .bind(node_id)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some()
        {
            PinOutcome::AlreadyPinned
        } else {
            PinOutcome::Full
        };
        transaction.commit().await?;
        Ok(outcome)
    }

    pub async fn unpin(&self, user_id: &str, node_id: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(UNPIN)
            .bind(user_id)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub async fn is_pinned(&self, user_id: &str, node_id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(EXISTS)
            .bind(user_id)
            .bind(node_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn node_ids(&self, user_id: &str) -> Result<Vec<String>, StoreError> {
        let rows = sqlx::query(NODES_OF_USER)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| row.try_get("node_id").map_err(StoreError::from))
            .collect()
    }
}
