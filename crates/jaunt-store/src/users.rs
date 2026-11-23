use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUser {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

const UPSERT: &str = "INSERT INTO users \
    (id, issuer, subject, email, display_name, groups, created_at, updated_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
    ON CONFLICT (issuer, subject) DO UPDATE SET \
    email = excluded.email, \
    display_name = excluded.display_name, \
    groups = excluded.groups, \
    updated_at = excluded.updated_at \
    RETURNING id, issuer, subject, email, display_name, groups, created_at, updated_at";

const GET: &str = "SELECT id, issuer, subject, email, display_name, groups, created_at, updated_at \
    FROM users WHERE id = ?";

#[derive(Clone)]
pub struct Users {
    pool: SqlitePool,
}

impl Users {
    pub(crate) fn new(pool: SqlitePool) -> Users {
        Users { pool }
    }

    pub async fn upsert(&self, user: &NewUser, now: i64) -> Result<User, StoreError> {
        let groups = serde_json::to_string(&user.groups)
            .map_err(|_| StoreError::InvalidInput("groups serialization failed"))?;
        let row = sqlx::query(UPSERT)
            .bind(Uuid::new_v4().to_string())
            .bind(&user.issuer)
            .bind(&user.subject)
            .bind(&user.email)
            .bind(&user.display_name)
            .bind(groups)
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        user_from_row(&row)
    }

    pub async fn get(&self, id: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(user_from_row).transpose()
    }
}

fn user_from_row(row: &SqliteRow) -> Result<User, StoreError> {
    let groups: String = row.try_get("groups")?;
    let groups = serde_json::from_str(&groups)
        .map_err(|err| StoreError::Corrupt(format!("users.groups: {err}")))?;
    Ok(User {
        id: row.try_get("id")?,
        issuer: row.try_get("issuer")?,
        subject: row.try_get("subject")?,
        email: row.try_get("email")?,
        display_name: row.try_get("display_name")?,
        groups,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}
