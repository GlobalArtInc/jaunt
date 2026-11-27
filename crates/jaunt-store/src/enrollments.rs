use std::collections::BTreeMap;

use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use uuid::Uuid;

use crate::StoreError;
use crate::nodes::{
    Labels, NewNodeCertificate, Node, insert_certificates, labels_to_text, node_columns,
    node_from_row, reject_unclaimed_enrollments,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Pending,
    Approved,
    Rejected,
    Delivering,
    Delivered,
}

impl EnrollmentState {
    fn parse(value: &str) -> Result<EnrollmentState, StoreError> {
        match value {
            "pending" => Ok(EnrollmentState::Pending),
            "approved" => Ok(EnrollmentState::Approved),
            "rejected" => Ok(EnrollmentState::Rejected),
            "delivering" => Ok(EnrollmentState::Delivering),
            "delivered" => Ok(EnrollmentState::Delivered),
            other => Err(StoreError::Corrupt(format!("enrollments.state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEnrollment {
    pub handle_hash: String,
    pub code_hash: String,
    pub name: String,
    pub labels: Labels,
    pub hostname: String,
    pub source_ip: String,
    pub peer_addr: String,
    pub tls_public_key: String,
    pub ssh_host_public_key: String,
    pub replace_existing: bool,
    pub agent_version: String,
    pub ttl_secs: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnrollmentLimits {
    pub max_pending: i64,
    pub max_pending_per_ip: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrollment {
    pub id: String,
    pub handle_hash: String,
    pub code_hash: String,
    pub name: String,
    pub labels: Labels,
    pub hostname: String,
    pub source_ip: String,
    pub peer_addr: String,
    pub tls_public_key: String,
    pub ssh_host_public_key: String,
    pub replace_existing: bool,
    pub agent_version: String,
    pub state: EnrollmentState,
    pub node_id: Option<String>,
    pub approved_by: Option<String>,
    pub delivering_at: Option<i64>,
    pub expired_reported_at: Option<i64>,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateOutcome {
    Created(Box<Enrollment>),
    TooManyPending,
    TooManyFromIp,
    CodeCollision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeFailure {
    Unknown,
    Expired,
    Rejected,
    AlreadyApproved,
}

#[derive(Debug, Clone, Copy)]
pub struct ApproveEnrollment<'a> {
    pub enrollment_id: &'a str,
    pub code_hash: &'a str,
    pub approver: &'a str,
    pub labels_override: Option<&'a Labels>,
    pub tls_spki_sha256: &'a str,
    pub ssh_host_key_fingerprint: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub enrollment: Enrollment,
    pub node: Node,
    pub replaced: Option<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproveOutcome {
    Approved(Box<Approved>),
    NameTaken,
    Refused(CodeFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectOutcome {
    Rejected(Box<Enrollment>),
    Refused(CodeFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedEnrollment {
    pub id: String,
    pub name: String,
    pub state: EnrollmentState,
    pub expiry_reported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredDelivery {
    pub id: String,
    pub name: String,
}

macro_rules! enrollment_columns {
    () => {
        "id, handle_hash, code_hash, name, labels, hostname, source_ip, peer_addr, \
         tls_public_key, ssh_host_public_key, replace_existing, agent_version, state, node_id, \
         approved_by, delivering_at, expired_reported_at, created_at, expires_at"
    };
}

pub(crate) use enrollment_columns;

const CREATE: &str = concat!(
    "INSERT INTO enrollments (",
    enrollment_columns!(),
    ") SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, NULL, NULL, NULL, ?, ? \
     WHERE (SELECT COUNT(*) FROM enrollments WHERE state = 'pending' AND expires_at > ?) < ? \
     AND (SELECT COUNT(*) FROM enrollments \
          WHERE state = 'pending' AND expires_at > ? AND source_ip = ?) < ? \
     AND NOT EXISTS (SELECT 1 FROM enrollments \
          WHERE code_hash = ? AND state = 'pending' AND expires_at > ?) \
     RETURNING ",
    enrollment_columns!()
);

const COUNT_CAUSES: &str = "SELECT \
    (SELECT COUNT(*) FROM enrollments WHERE state = 'pending' AND expires_at > ?) AS total, \
    (SELECT COUNT(*) FROM enrollments \
     WHERE state = 'pending' AND expires_at > ? AND source_ip = ?) AS from_ip";

const GET_BY_HANDLE: &str = concat!(
    "SELECT ",
    enrollment_columns!(),
    " FROM enrollments WHERE handle_hash = ?"
);

const FIND_PENDING_BY_CODE: &str = concat!(
    "SELECT ",
    enrollment_columns!(),
    " FROM enrollments WHERE code_hash = ? AND state = 'pending' AND expires_at > ?"
);

const LATEST_BY_CODE: &str = "SELECT state, expires_at FROM enrollments \
    WHERE code_hash = ? ORDER BY created_at DESC, id LIMIT 1";

const CLAIM_FOR_APPROVAL: &str = concat!(
    "UPDATE enrollments SET state = 'approved', node_id = ?, approved_by = ? \
     WHERE id = ? AND code_hash = ? AND state = 'pending' AND expires_at > ? RETURNING ",
    enrollment_columns!()
);

const REJECT_BY_CODE: &str = concat!(
    "UPDATE enrollments SET state = 'rejected' \
     WHERE code_hash = ? AND state = 'pending' AND expires_at > ? RETURNING ",
    enrollment_columns!()
);

pub(crate) const REPLACE_ACTIVE_NODE: &str = concat!(
    "UPDATE nodes SET state = 'removed', removed_at = ? WHERE name = ? AND state = 'active' \
     RETURNING ",
    node_columns!()
);

const ACTIVE_NODE_NAME_TAKEN: &str = "SELECT id FROM nodes WHERE name = ? AND state = 'active'";

pub(crate) const INSERT_NODE: &str = concat!(
    "INSERT INTO nodes (",
    node_columns!(),
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, NULL, ?, 1) RETURNING ",
    node_columns!()
);

const BEGIN_DELIVERY: &str = concat!(
    "UPDATE enrollments SET state = 'delivering', delivering_at = ? \
     WHERE id = ? AND state = 'approved' AND expires_at > ? RETURNING ",
    enrollment_columns!()
);

const COMPLETE_DELIVERY: &str = "UPDATE enrollments SET state = 'delivered' \
    WHERE id = ? AND state = 'delivering' AND node_id = ? \
    AND EXISTS (SELECT 1 FROM nodes WHERE id = ? AND state = 'active') RETURNING id";

const RELEASE_DELIVERY: &str = "UPDATE enrollments SET state = 'approved', delivering_at = NULL \
    WHERE id = ? AND state = 'delivering' RETURNING id";

const RECOVER_STALE_DELIVERIES: &str = "UPDATE enrollments SET state = 'approved', \
    delivering_at = NULL WHERE state = 'delivering' AND delivering_at < ? RETURNING id, name";

const REJECT_DELIVERY: &str =
    "UPDATE enrollments SET state = 'rejected' WHERE id = ? AND state = 'delivering' RETURNING id";

const PURGE_EXPIRED: &str = "DELETE FROM enrollments WHERE expires_at < ? \
    RETURNING id, name, state, expired_reported_at";

const COUNT_PENDING: &str =
    "SELECT COUNT(*) AS total FROM enrollments WHERE state = 'pending' AND expires_at > ?";

const MARK_EXPIRY_REPORTED: &str = "UPDATE enrollments SET expired_reported_at = ? \
    WHERE id = ? AND expired_reported_at IS NULL AND expires_at <= ? RETURNING id";

#[derive(Clone)]
pub struct Enrollments {
    pool: SqlitePool,
}

impl Enrollments {
    pub(crate) fn new(pool: SqlitePool) -> Enrollments {
        Enrollments { pool }
    }

    pub async fn create(
        &self,
        enrollment: &NewEnrollment,
        limits: EnrollmentLimits,
        now: i64,
    ) -> Result<CreateOutcome, StoreError> {
        if enrollment.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        let expires_at = now
            .checked_add(enrollment.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let labels = labels_to_text(&enrollment.labels)?;
        let row = sqlx::query(CREATE)
            .bind(Uuid::new_v4().to_string())
            .bind(&enrollment.handle_hash)
            .bind(&enrollment.code_hash)
            .bind(&enrollment.name)
            .bind(&labels)
            .bind(&enrollment.hostname)
            .bind(&enrollment.source_ip)
            .bind(&enrollment.peer_addr)
            .bind(&enrollment.tls_public_key)
            .bind(&enrollment.ssh_host_public_key)
            .bind(i64::from(enrollment.replace_existing))
            .bind(&enrollment.agent_version)
            .bind(now)
            .bind(expires_at)
            .bind(now)
            .bind(limits.max_pending)
            .bind(now)
            .bind(&enrollment.source_ip)
            .bind(limits.max_pending_per_ip)
            .bind(&enrollment.code_hash)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            return Ok(CreateOutcome::Created(Box::new(enrollment_from_row(&row)?)));
        }
        let causes = sqlx::query(COUNT_CAUSES)
            .bind(now)
            .bind(now)
            .bind(&enrollment.source_ip)
            .fetch_one(&self.pool)
            .await?;
        let total: i64 = causes.try_get("total")?;
        let from_ip: i64 = causes.try_get("from_ip")?;
        if total >= limits.max_pending {
            Ok(CreateOutcome::TooManyPending)
        } else if from_ip >= limits.max_pending_per_ip {
            Ok(CreateOutcome::TooManyFromIp)
        } else {
            Ok(CreateOutcome::CodeCollision)
        }
    }

    pub async fn get_by_handle_hash(
        &self,
        handle_hash: &str,
    ) -> Result<Option<Enrollment>, StoreError> {
        let row = sqlx::query(GET_BY_HANDLE)
            .bind(handle_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(enrollment_from_row).transpose()
    }

    pub async fn find_pending_by_code(
        &self,
        code_hash: &str,
        now: i64,
    ) -> Result<Option<Enrollment>, StoreError> {
        let rows = sqlx::query(FIND_PENDING_BY_CODE)
            .bind(code_hash)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        single_pending(&rows)
    }

    pub async fn classify_code(
        &self,
        code_hash: &str,
        now: i64,
    ) -> Result<CodeFailure, StoreError> {
        let row = sqlx::query(LATEST_BY_CODE)
            .bind(code_hash)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(CodeFailure::Unknown);
        };
        let state: String = row.try_get("state")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        Ok(match EnrollmentState::parse(&state)? {
            EnrollmentState::Pending if expires_at <= now => CodeFailure::Expired,
            EnrollmentState::Pending => CodeFailure::Unknown,
            EnrollmentState::Rejected => CodeFailure::Rejected,
            EnrollmentState::Approved
            | EnrollmentState::Delivering
            | EnrollmentState::Delivered => CodeFailure::AlreadyApproved,
        })
    }

    pub async fn approve_enrollment(
        &self,
        request: ApproveEnrollment<'_>,
    ) -> Result<ApproveOutcome, StoreError> {
        let node_id = Uuid::new_v4().to_string();
        let mut tx = self.pool.begin().await?;
        let claimed = sqlx::query(CLAIM_FOR_APPROVAL)
            .bind(&node_id)
            .bind(request.approver)
            .bind(request.enrollment_id)
            .bind(request.code_hash)
            .bind(request.now)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(claimed) = claimed else {
            tx.rollback().await?;
            let failure = self.classify_code(request.code_hash, request.now).await?;
            return Ok(ApproveOutcome::Refused(failure));
        };
        let enrollment = enrollment_from_row(&claimed)?;

        let replaced = if enrollment.replace_existing {
            let removed = sqlx::query(REPLACE_ACTIVE_NODE)
                .bind(request.now)
                .bind(&enrollment.name)
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
            let taken = sqlx::query(ACTIVE_NODE_NAME_TAKEN)
                .bind(&enrollment.name)
                .fetch_optional(&mut *tx)
                .await?;
            if taken.is_some() {
                tx.rollback().await?;
                return Ok(ApproveOutcome::NameTaken);
            }
            None
        };

        let labels = labels_to_text(request.labels_override.unwrap_or(&enrollment.labels))?;
        let inserted = sqlx::query(INSERT_NODE)
            .bind(&node_id)
            .bind(&enrollment.name)
            .bind(&labels)
            .bind(&enrollment.hostname)
            .bind(&enrollment.tls_public_key)
            .bind(&enrollment.ssh_host_public_key)
            .bind(request.tls_spki_sha256)
            .bind(request.ssh_host_key_fingerprint)
            .bind(request.approver)
            .bind(request.now)
            .bind(&enrollment.agent_version)
            .fetch_one(&mut *tx)
            .await;
        let created = match inserted {
            Ok(row) => row,
            Err(err) if is_unique_violation(&err) => {
                tx.rollback().await?;
                return Ok(ApproveOutcome::NameTaken);
            }
            Err(err) => return Err(err.into()),
        };
        let node = node_from_row(&created)?;
        tx.commit().await?;
        Ok(ApproveOutcome::Approved(Box::new(Approved {
            enrollment,
            node,
            replaced,
        })))
    }

    pub async fn reject_by_code(
        &self,
        code_hash: &str,
        now: i64,
    ) -> Result<RejectOutcome, StoreError> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(REJECT_BY_CODE)
            .bind(code_hash)
            .bind(now)
            .fetch_all(&mut *tx)
            .await?;
        let rejected = match single_pending(&rows) {
            Ok(rejected) => rejected,
            Err(err) => {
                tx.rollback().await?;
                return Err(err);
            }
        };
        let Some(rejected) = rejected else {
            tx.rollback().await?;
            let failure = self.classify_code(code_hash, now).await?;
            return Ok(RejectOutcome::Refused(failure));
        };
        tx.commit().await?;
        Ok(RejectOutcome::Rejected(Box::new(rejected)))
    }

    pub async fn begin_delivery(
        &self,
        id: &str,
        now: i64,
    ) -> Result<Option<Enrollment>, StoreError> {
        let row = sqlx::query(BEGIN_DELIVERY)
            .bind(now)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(enrollment_from_row).transpose()
    }

    pub async fn complete_delivery(
        &self,
        id: &str,
        node_id: &str,
        certificates: &[NewNodeCertificate],
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let delivered = sqlx::query(COMPLETE_DELIVERY)
            .bind(id)
            .bind(node_id)
            .bind(node_id)
            .fetch_optional(&mut *tx)
            .await?;
        if delivered.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        insert_certificates(&mut tx, node_id, certificates).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn release_delivery(&self, id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(RELEASE_DELIVERY)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn recover_stale_deliveries(
        &self,
        started_before: i64,
    ) -> Result<Vec<RecoveredDelivery>, StoreError> {
        let rows = sqlx::query(RECOVER_STALE_DELIVERIES)
            .bind(started_before)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(RecoveredDelivery {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                })
            })
            .collect()
    }

    pub async fn reject_delivery(&self, id: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(REJECT_DELIVERY)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn purge_expired(
        &self,
        older_than: i64,
    ) -> Result<Vec<PurgedEnrollment>, StoreError> {
        let rows = sqlx::query(PURGE_EXPIRED)
            .bind(older_than)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let state: String = row.try_get("state")?;
                Ok(PurgedEnrollment {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    state: EnrollmentState::parse(&state)?,
                    expiry_reported: row
                        .try_get::<Option<i64>, _>("expired_reported_at")?
                        .is_some(),
                })
            })
            .collect()
    }

    pub async fn count_pending(&self, now: i64) -> Result<i64, StoreError> {
        let row = sqlx::query(COUNT_PENDING)
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get("total")?)
    }

    pub async fn agent_versions(
        &self,
        node_ids: &[String],
    ) -> Result<BTreeMap<String, String>, StoreError> {
        let mut versions = BTreeMap::new();
        if node_ids.is_empty() {
            return Ok(versions);
        }
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT node_id, agent_version FROM enrollments WHERE node_id IN (");
        let mut ids = builder.separated(", ");
        for id in node_ids {
            ids.push_bind(id.clone());
        }
        builder.push(") ORDER BY created_at, id");
        let rows = builder.build().fetch_all(&self.pool).await?;
        for row in &rows {
            versions.insert(row.try_get("node_id")?, row.try_get("agent_version")?);
        }
        Ok(versions)
    }

    pub async fn mark_expiry_reported(&self, id: &str, now: i64) -> Result<bool, StoreError> {
        let row = sqlx::query(MARK_EXPIRY_REPORTED)
            .bind(now)
            .bind(id)
            .bind(now)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }
}

pub(crate) fn is_unique_violation(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

fn single_pending(rows: &[SqliteRow]) -> Result<Option<Enrollment>, StoreError> {
    match rows {
        [] => Ok(None),
        [row] => enrollment_from_row(row).map(Some),
        _ => Err(StoreError::Corrupt(
            "enrollments.code_hash: more than one pending enrollment".to_owned(),
        )),
    }
}

pub(crate) fn enrollment_from_row(row: &SqliteRow) -> Result<Enrollment, StoreError> {
    let labels: String = row.try_get("labels")?;
    let labels = serde_json::from_str(&labels)
        .map_err(|err| StoreError::Corrupt(format!("enrollments.labels: {err}")))?;
    let state: String = row.try_get("state")?;
    let replace_existing: i64 = row.try_get("replace_existing")?;
    let replace_existing = match replace_existing {
        0 => false,
        1 => true,
        other => {
            return Err(StoreError::Corrupt(format!(
                "enrollments.replace_existing: {other}"
            )));
        }
    };
    Ok(Enrollment {
        id: row.try_get("id")?,
        handle_hash: row.try_get("handle_hash")?,
        code_hash: row.try_get("code_hash")?,
        name: row.try_get("name")?,
        labels,
        hostname: row.try_get("hostname")?,
        source_ip: row.try_get("source_ip")?,
        peer_addr: row.try_get("peer_addr")?,
        tls_public_key: row.try_get("tls_public_key")?,
        ssh_host_public_key: row.try_get("ssh_host_public_key")?,
        replace_existing,
        agent_version: row.try_get("agent_version")?,
        state: EnrollmentState::parse(&state)?,
        node_id: row.try_get("node_id")?,
        approved_by: row.try_get("approved_by")?,
        delivering_at: row.try_get("delivering_at")?,
        expired_reported_at: row.try_get("expired_reported_at")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;
    use sqlx::sqlite::SqlitePoolOptions;

    use super::is_unique_violation;

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        for statement in [
            "CREATE TABLE nodes (name TEXT NOT NULL, state TEXT NOT NULL)",
            "CREATE UNIQUE INDEX nodes_active_name_idx ON nodes (name) WHERE state = 'active'",
        ] {
            sqlx::query(statement).execute(&pool).await.expect("schema");
        }
        pool
    }

    #[tokio::test]
    async fn only_unique_violations_are_reported_as_name_conflicts() {
        let pool = pool().await;
        let insert = "INSERT INTO nodes (name, state) VALUES (?, ?)";
        sqlx::query(insert)
            .bind("web")
            .bind("active")
            .execute(&pool)
            .await
            .unwrap();

        let duplicate = sqlx::query(insert)
            .bind("web")
            .bind("active")
            .execute(&pool)
            .await
            .unwrap_err();
        let missing_value = sqlx::query("INSERT INTO nodes (name, state) VALUES (NULL, 'active')")
            .execute(&pool)
            .await
            .unwrap_err();
        let broken = sqlx::query("INSERT INTO absent VALUES (1)")
            .execute(&pool)
            .await
            .unwrap_err();

        assert!(is_unique_violation(&duplicate));
        assert!(!is_unique_violation(&missing_value));
        assert!(!is_unique_violation(&broken));
        sqlx::query(insert)
            .bind("web")
            .bind("removed")
            .execute(&pool)
            .await
            .unwrap();
    }
}
