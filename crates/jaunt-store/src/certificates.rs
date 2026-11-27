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
    pub ca_fingerprint: Option<String>,
    pub host_trust_id: Option<String>,
    pub subject_fingerprint: Option<String>,
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
    pub ca_fingerprint: Option<String>,
    pub host_trust_id: Option<String>,
    pub subject_fingerprint: Option<String>,
    pub parent_serial: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parent<'a> {
    pub serial: i64,
    pub kind: &'a str,
}

const ALLOCATE_SERIAL: &str = "UPDATE serial_counter SET next_serial = next_serial + 1 \
    WHERE id = 1 RETURNING next_serial - 1 AS serial";

const RECORD: &str = "INSERT INTO certificates \
    (serial, user_id, kind, key_id, valid_after, valid_before, issued_at, ca_fingerprint, \
    host_trust_id, subject_fingerprint) \
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

const RECORD_CHILD: &str = "INSERT INTO certificates \
    (serial, user_id, kind, key_id, valid_after, valid_before, issued_at, ca_fingerprint, \
    host_trust_id, subject_fingerprint, parent_serial) \
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, p.serial FROM certificates p \
    WHERE p.serial = ? AND p.user_id = ? AND p.kind = ? AND p.parent_serial IS NULL \
    AND p.valid_after <= ? AND p.valid_before >= ? \
    AND NOT EXISTS (SELECT 1 FROM revocations r \
        WHERE (r.kind = 'serial' AND r.subject = CAST(p.serial AS TEXT)) \
        OR (r.kind = 'user' AND r.subject = p.user_id))";

const GET: &str = "SELECT serial, user_id, kind, key_id, valid_after, valid_before, issued_at, \
    ca_fingerprint, host_trust_id, subject_fingerprint, parent_serial FROM certificates \
    WHERE serial = ?";

const UNEXPIRED_CHILDREN: &str = "SELECT serial FROM certificates \
    WHERE parent_serial = ? AND valid_before > ? ORDER BY serial";

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
            .bind(&certificate.ca_fingerprint)
            .bind(&certificate.host_trust_id)
            .bind(&certificate.subject_fingerprint)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_child(
        &self,
        certificate: &NewCertificate,
        parent: Parent<'_>,
    ) -> Result<bool, StoreError> {
        if certificate.serial == parent.serial || certificate.kind == parent.kind {
            return Err(StoreError::InvalidInput(
                "a child certificate must differ from its parent in serial and kind",
            ));
        }
        let recorded = sqlx::query(RECORD_CHILD)
            .bind(certificate.serial)
            .bind(&certificate.user_id)
            .bind(&certificate.kind)
            .bind(&certificate.key_id)
            .bind(certificate.valid_after)
            .bind(certificate.valid_before)
            .bind(certificate.issued_at)
            .bind(&certificate.ca_fingerprint)
            .bind(&certificate.host_trust_id)
            .bind(&certificate.subject_fingerprint)
            .bind(parent.serial)
            .bind(&certificate.user_id)
            .bind(parent.kind)
            .bind(certificate.issued_at)
            .bind(certificate.valid_before)
            .execute(&self.pool)
            .await?;
        Ok(recorded.rows_affected() == 1)
    }

    pub async fn unexpired_children(
        &self,
        parent_serial: i64,
        now: i64,
    ) -> Result<Vec<i64>, StoreError> {
        let rows = sqlx::query(UNEXPIRED_CHILDREN)
            .bind(parent_serial)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| row.try_get("serial").map_err(StoreError::from))
            .collect()
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
        ca_fingerprint: row.try_get("ca_fingerprint")?,
        host_trust_id: row.try_get("host_trust_id")?,
        subject_fingerprint: row.try_get("subject_fingerprint")?,
        parent_serial: row.try_get("parent_serial")?,
    })
}
