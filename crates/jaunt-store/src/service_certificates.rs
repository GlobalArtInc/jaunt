use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;
use crate::services::ServiceKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewServiceCertificate {
    pub serial: i64,
    pub node_id: String,
    pub service_id: String,
    pub kind: ServiceKind,
    pub name: String,
    pub domain: String,
    pub signed_dns_name: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub issued_at: i64,
    pub root_sha256: String,
    pub subject_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCertificate {
    pub serial: i64,
    pub node_id: String,
    pub service_id: String,
    pub kind: ServiceKind,
    pub name: String,
    pub dns_name: String,
    pub valid_after: i64,
    pub valid_before: i64,
    pub issued_at: i64,
    pub root_sha256: String,
    pub subject_fingerprint: String,
}

macro_rules! row_dns_name {
    () => {
        "s.name || '.' || CASE s.kind WHEN 'kubernetes' THEN 'kube' WHEN 'postgres' THEN 'db' \
         WHEN 'tcp' THEN 'tcp' END || '.' || ?"
    };
}

const RECORD: &str = concat!(
    "INSERT INTO service_certificates \
     (serial, node_id, service_id, kind, name, dns_name, valid_after, valid_before, issued_at, \
     root_sha256, subject_fingerprint) \
     SELECT ?, s.node_id, s.id, s.kind, s.name, ",
    row_dns_name!(),
    ", ?, ?, ?, ?, ? \
     FROM services s JOIN nodes n ON n.id = s.node_id \
     WHERE s.id = ? AND s.node_id = ? AND s.kind = ? AND s.name = ? \
     AND s.state = 'approved' AND s.announced = 1 AND n.state = 'active' AND ",
    row_dns_name!(),
    " = ?"
);

const PURGE_EXPIRED: &str = "DELETE FROM service_certificates WHERE valid_before < ?";

const GET: &str = "SELECT serial, node_id, service_id, kind, name, dns_name, valid_after, \
    valid_before, issued_at, root_sha256, subject_fingerprint FROM service_certificates \
    WHERE serial = ?";

#[derive(Clone)]
pub struct ServiceCertificates {
    pool: SqlitePool,
}

impl ServiceCertificates {
    pub(crate) fn new(pool: SqlitePool) -> ServiceCertificates {
        ServiceCertificates { pool }
    }

    pub async fn record(&self, certificate: &NewServiceCertificate) -> Result<bool, StoreError> {
        let recorded = sqlx::query(RECORD)
            .bind(certificate.serial)
            .bind(&certificate.domain)
            .bind(certificate.valid_after)
            .bind(certificate.valid_before)
            .bind(certificate.issued_at)
            .bind(&certificate.root_sha256)
            .bind(&certificate.subject_fingerprint)
            .bind(&certificate.service_id)
            .bind(&certificate.node_id)
            .bind(certificate.kind.as_str())
            .bind(&certificate.name)
            .bind(&certificate.domain)
            .bind(&certificate.signed_dns_name)
            .execute(&self.pool)
            .await?;
        Ok(recorded.rows_affected() == 1)
    }

    pub async fn purge_expired(&self, expired_before: i64) -> Result<u64, StoreError> {
        let purged = sqlx::query(PURGE_EXPIRED)
            .bind(expired_before)
            .execute(&self.pool)
            .await?;
        Ok(purged.rows_affected())
    }

    pub async fn get(&self, serial: i64) -> Result<Option<ServiceCertificate>, StoreError> {
        let row = sqlx::query(GET)
            .bind(serial)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(certificate_from_row).transpose()
    }
}

fn certificate_from_row(row: &SqliteRow) -> Result<ServiceCertificate, StoreError> {
    let kind: String = row.try_get("kind")?;
    Ok(ServiceCertificate {
        serial: row.try_get("serial")?,
        node_id: row.try_get("node_id")?,
        service_id: row.try_get("service_id")?,
        kind: ServiceKind::parse(&kind)?,
        name: row.try_get("name")?,
        dns_name: row.try_get("dns_name")?,
        valid_after: row.try_get("valid_after")?,
        valid_before: row.try_get("valid_before")?,
        issued_at: row.try_get("issued_at")?,
        root_sha256: row.try_get("root_sha256")?,
        subject_fingerprint: row.try_get("subject_fingerprint")?,
    })
}
