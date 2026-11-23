use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCertificate {
    pub serial: i64,
    pub user_id: String,
    pub kind: String,
    pub key_id: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub serial: i64,
    pub user_id: String,
    pub kind: String,
    pub key_id: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub issued_at: i64,
}

const ALLOCATE_SERIAL: &str = "UPDATE serial_counter SET next_serial = next_serial + 1 \
    WHERE id = 1 RETURNING next_serial - 1 AS serial";

const RECORD: &str = "INSERT INTO certificates \
    (serial, user_id, kind, key_id, valid_after, valid_before, issued_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?)";

const GET: &str = "SELECT serial, user_id, kind, key_id, valid_after, valid_before, issued_at \
    FROM certificates WHERE serial = ?";

#[derive(Clone)]
pub struct Certificates {
    pool: SqlitePool,
}

impl Certificates {
    pub(crate) fn new(pool: SqlitePool) -> Certificates {
        Certificates { pool }
    }

    pub async fn allocate_serial(&self) -> Result<i64, StoreError> {
        let row = sqlx::query(ALLOCATE_SERIAL).fetch_one(&self.pool).await?;
        Ok(row.try_get("serial")?)
    }

    pub async fn record(&self, certificate: &NewCertificate) -> Result<(), StoreError> {
        sqlx::query(RECORD)
            .bind(certificate.serial)
            .bind(&certificate.user_id)
            .bind(&certificate.kind)
            .bind(&certificate.key_id)
            .bind(certificate.valid_after)
            .bind(certificate.valid_before)
            .bind(certificate.issued_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get(&self, serial: i64) -> Result<Option<Certificate>, StoreError> {
        let row = sqlx::query(GET)
            .bind(serial)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(certificate_from_row).transpose()
    }
}

fn certificate_from_row(row: &SqliteRow) -> Result<Certificate, StoreError> {
    Ok(Certificate {
        serial: row.try_get("serial")?,
        user_id: row.try_get("user_id")?,
        kind: row.try_get("kind")?,
        key_id: row.try_get("key_id")?,
        valid_after: row.try_get("valid_after")?,
        valid_before: row.try_get("valid_before")?,
        issued_at: row.try_get("issued_at")?,
    })
}
