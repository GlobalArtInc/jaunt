use std::collections::BTreeMap;

use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::StoreError;

pub type Labels = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Active,
    Removed,
}

impl NodeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeState::Active => "active",
            NodeState::Removed => "removed",
        }
    }

    fn parse(value: &str) -> Result<NodeState, StoreError> {
        match value {
            "active" => Ok(NodeState::Active),
            "removed" => Ok(NodeState::Removed),
            other => Err(StoreError::Corrupt(format!("nodes.state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateState {
    Delivered,
    Pending,
    None,
}

impl CertificateState {
    pub const fn as_str(self) -> &'static str {
        match self {
            CertificateState::Delivered => "delivered",
            CertificateState::Pending => "pending",
            CertificateState::None => "none",
        }
    }

    fn parse(value: &str) -> Result<CertificateState, StoreError> {
        match value {
            "delivered" => Ok(CertificateState::Delivered),
            "pending" => Ok(CertificateState::Pending),
            "none" => Ok(CertificateState::None),
            other => Err(StoreError::Corrupt(format!("certificate state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub labels: Labels,
    pub hostname: String,
    pub tls_public_key: String,
    pub ssh_host_public_key: String,
    pub tls_spki_sha256: String,
    pub ssh_host_key_fingerprint: String,
    pub state: NodeState,
    pub approved_by: String,
    pub created_at: i64,
    pub removed_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeys {
    pub tls_public_key: String,
    pub ssh_host_public_key: String,
    pub tls_spki_sha256: String,
    pub ssh_host_key_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCertificateKind {
    X509,
    SshHost,
}

impl NodeCertificateKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeCertificateKind::X509 => "x509",
            NodeCertificateKind::SshHost => "ssh-host",
        }
    }

    fn parse(value: &str) -> Result<NodeCertificateKind, StoreError> {
        match value {
            "x509" => Ok(NodeCertificateKind::X509),
            "ssh-host" => Ok(NodeCertificateKind::SshHost),
            other => Err(StoreError::Corrupt(format!(
                "node_certificates.kind: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNodeCertificate {
    pub kind: NodeCertificateKind,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCertificate {
    pub id: String,
    pub node_id: String,
    pub kind: NodeCertificateKind,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
    pub issued_at: i64,
}

macro_rules! node_columns {
    () => {
        "id, name, labels, hostname, tls_public_key, ssh_host_public_key, tls_spki_sha256, \
         ssh_host_key_fingerprint, state, approved_by, created_at, removed_at"
    };
}

pub(crate) use node_columns;

const GET: &str = concat!("SELECT ", node_columns!(), " FROM nodes WHERE id = ?");

const GET_ACTIVE: &str = concat!(
    "SELECT ",
    node_columns!(),
    " FROM nodes WHERE id = ? AND state = 'active'"
);

const GET_ACTIVE_BY_NAME: &str = concat!(
    "SELECT ",
    node_columns!(),
    " FROM nodes WHERE name = ? AND state = 'active'"
);

const LIST: &str = concat!(
    "SELECT ",
    node_columns!(),
    " FROM nodes ORDER BY created_at, id"
);

const CERTIFICATE_STATES: &str = "SELECT n.id AS id, \
    CASE WHEN EXISTS (SELECT 1 FROM node_certificates c WHERE c.node_id = n.id) \
         THEN 'delivered' \
         WHEN EXISTS (SELECT 1 FROM enrollments e WHERE e.node_id = n.id \
              AND e.state IN ('approved', 'delivering') AND e.expires_at > ?) \
         THEN 'pending' \
         ELSE 'none' END AS certificates \
    FROM nodes n";

const REMOVE_BY_NAME: &str = concat!(
    "UPDATE nodes SET state = 'removed', removed_at = ? WHERE name = ? AND state = 'active' \
     RETURNING ",
    node_columns!()
);

const REJECT_UNCLAIMED_FOR_NODE: &str = "UPDATE enrollments SET state = 'rejected' \
     WHERE node_id = ? AND state IN ('approved', 'delivering')";

const ROTATE_KEYS: &str = "UPDATE nodes SET tls_public_key = ?, ssh_host_public_key = ?, \
    tls_spki_sha256 = ?, ssh_host_key_fingerprint = ? \
    WHERE id = ? AND state = 'active' RETURNING id";

const INSERT_CERTIFICATE: &str = "INSERT INTO node_certificates \
    (id, node_id, kind, serial, not_before, not_after, issued_at) \
    VALUES (?, ?, ?, ?, ?, ?, ?)";

const LIST_CERTIFICATES: &str = "SELECT id, node_id, kind, serial, not_before, not_after, \
    issued_at FROM node_certificates WHERE node_id = ? ORDER BY issued_at, kind, serial, id";

#[derive(Clone)]
pub struct Nodes {
    pool: SqlitePool,
}

impl Nodes {
    pub(crate) fn new(pool: SqlitePool) -> Nodes {
        Nodes { pool }
    }

    pub async fn get(&self, id: &str) -> Result<Option<Node>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(node_from_row).transpose()
    }

    pub async fn get_active(&self, id: &str) -> Result<Option<Node>, StoreError> {
        let row = sqlx::query(GET_ACTIVE)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(node_from_row).transpose()
    }

    pub async fn get_active_by_name(&self, name: &str) -> Result<Option<Node>, StoreError> {
        let row = sqlx::query(GET_ACTIVE_BY_NAME)
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(node_from_row).transpose()
    }

    pub async fn list(&self) -> Result<Vec<Node>, StoreError> {
        let rows = sqlx::query(LIST).fetch_all(&self.pool).await?;
        rows.iter().map(node_from_row).collect()
    }

    pub async fn certificate_states(
        &self,
        now: i64,
    ) -> Result<BTreeMap<String, CertificateState>, StoreError> {
        let rows = sqlx::query(CERTIFICATE_STATES)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let state: String = row.try_get("certificates")?;
                Ok((row.try_get("id")?, CertificateState::parse(&state)?))
            })
            .collect()
    }

    pub async fn remove_by_name(&self, name: &str, now: i64) -> Result<Option<Node>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(REMOVE_BY_NAME)
            .bind(now)
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let node = node_from_row(&row)?;
        reject_unclaimed_enrollments(&mut tx, &node.id).await?;
        tx.commit().await?;
        Ok(Some(node))
    }

    pub async fn record_renewal(
        &self,
        node_id: &str,
        keys: &NodeKeys,
        certificates: &[NewNodeCertificate],
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await?;
        let rotated = sqlx::query(ROTATE_KEYS)
            .bind(&keys.tls_public_key)
            .bind(&keys.ssh_host_public_key)
            .bind(&keys.tls_spki_sha256)
            .bind(&keys.ssh_host_key_fingerprint)
            .bind(node_id)
            .fetch_optional(&mut *tx)
            .await?;
        if rotated.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        insert_certificates(&mut tx, node_id, certificates).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn certificates(&self, node_id: &str) -> Result<Vec<NodeCertificate>, StoreError> {
        let rows = sqlx::query(LIST_CERTIFICATES)
            .bind(node_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(certificate_from_row).collect()
    }
}

pub(crate) async fn reject_unclaimed_enrollments(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
) -> Result<(), StoreError> {
    sqlx::query(REJECT_UNCLAIMED_FOR_NODE)
        .bind(node_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn insert_certificates(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    certificates: &[NewNodeCertificate],
) -> Result<(), StoreError> {
    for certificate in certificates {
        sqlx::query(INSERT_CERTIFICATE)
            .bind(Uuid::new_v4().to_string())
            .bind(node_id)
            .bind(certificate.kind.as_str())
            .bind(&certificate.serial)
            .bind(certificate.not_before)
            .bind(certificate.not_after)
            .bind(certificate.issued_at)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub(crate) fn labels_to_text(labels: &Labels) -> Result<String, StoreError> {
    serde_json::to_string(labels).map_err(|_| StoreError::InvalidInput("labels serialization"))
}

pub(crate) fn node_from_row(row: &SqliteRow) -> Result<Node, StoreError> {
    let labels: String = row.try_get("labels")?;
    let labels = serde_json::from_str(&labels)
        .map_err(|err| StoreError::Corrupt(format!("nodes.labels: {err}")))?;
    let state: String = row.try_get("state")?;
    Ok(Node {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        labels,
        hostname: row.try_get("hostname")?,
        tls_public_key: row.try_get("tls_public_key")?,
        ssh_host_public_key: row.try_get("ssh_host_public_key")?,
        tls_spki_sha256: row.try_get("tls_spki_sha256")?,
        ssh_host_key_fingerprint: row.try_get("ssh_host_key_fingerprint")?,
        state: NodeState::parse(&state)?,
        approved_by: row.try_get("approved_by")?,
        created_at: row.try_get("created_at")?,
        removed_at: row.try_get("removed_at")?,
    })
}

fn certificate_from_row(row: &SqliteRow) -> Result<NodeCertificate, StoreError> {
    let kind: String = row.try_get("kind")?;
    Ok(NodeCertificate {
        id: row.try_get("id")?,
        node_id: row.try_get("node_id")?,
        kind: NodeCertificateKind::parse(&kind)?,
        serial: row.try_get("serial")?,
        not_before: row.try_get("not_before")?,
        not_after: row.try_get("not_after")?,
        issued_at: row.try_get("issued_at")?,
    })
}
