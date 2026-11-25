use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqlitePool};

use crate::StoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpiredGroup {
    pub id: Option<String>,
    pub count: i64,
    pub nearest_valid_before: i64,
    pub farthest_valid_before: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTrustServed {
    pub node_id: String,
    pub name: String,
    pub trust_id: Option<String>,
    pub served_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHostCertificate {
    pub node_id: String,
    pub name: String,
    pub ca_fingerprint: Option<String>,
    pub not_after: i64,
}

const UNEXPIRED_BY_SIGNER: &str = "SELECT ca_fingerprint AS id, COUNT(*) AS count, \
    MIN(valid_before) AS nearest, MAX(valid_before) AS farthest \
    FROM certificates WHERE valid_before > ? GROUP BY ca_fingerprint";

const UNEXPIRED_BY_HOST_TRUST: &str = "SELECT host_trust_id AS id, COUNT(*) AS count, \
    MIN(valid_before) AS nearest, MAX(valid_before) AS farthest \
    FROM certificates WHERE valid_before > ? GROUP BY host_trust_id";

const NODE_TRUST: &str = "SELECT id, name, trust_served_id, trust_served_at FROM nodes \
    WHERE state = 'active' ORDER BY name, id";

const LATEST_NODE_HOST_CERTIFICATES: &str = "SELECT n.id AS node_id, n.name AS name, \
    c.ca_fingerprint AS ca_fingerprint, c.not_after AS not_after \
    FROM nodes n JOIN node_certificates c ON c.node_id = n.id \
    WHERE n.state = 'active' AND c.kind = 'ssh-host' \
    AND c.issued_at = (SELECT MAX(l.issued_at) FROM node_certificates l \
        WHERE l.node_id = n.id AND l.kind = 'ssh-host') \
    ORDER BY n.name, n.id, c.id";

#[derive(Clone)]
pub struct CaCounters {
    pool: SqlitePool,
}

impl CaCounters {
    pub(crate) fn new(pool: SqlitePool) -> CaCounters {
        CaCounters { pool }
    }

    pub async fn certificates_by_signer(
        &self,
        now: i64,
    ) -> Result<Vec<UnexpiredGroup>, StoreError> {
        self.unexpired(UNEXPIRED_BY_SIGNER, now).await
    }

    pub async fn certificates_by_host_trust(
        &self,
        now: i64,
    ) -> Result<Vec<UnexpiredGroup>, StoreError> {
        self.unexpired(UNEXPIRED_BY_HOST_TRUST, now).await
    }

    pub async fn node_trust(&self) -> Result<Vec<NodeTrustServed>, StoreError> {
        let rows = sqlx::query(NODE_TRUST).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                Ok(NodeTrustServed {
                    node_id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    trust_id: row.try_get("trust_served_id")?,
                    served_at: row.try_get("trust_served_at")?,
                })
            })
            .collect()
    }

    pub async fn latest_node_host_certificates(
        &self,
    ) -> Result<Vec<NodeHostCertificate>, StoreError> {
        let rows = sqlx::query(LATEST_NODE_HOST_CERTIFICATES)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(NodeHostCertificate {
                    node_id: row.try_get("node_id")?,
                    name: row.try_get("name")?,
                    ca_fingerprint: row.try_get("ca_fingerprint")?,
                    not_after: row.try_get("not_after")?,
                })
            })
            .collect()
    }

    async fn unexpired(
        &self,
        query: &'static str,
        now: i64,
    ) -> Result<Vec<UnexpiredGroup>, StoreError> {
        let rows = sqlx::query(query).bind(now).fetch_all(&self.pool).await?;
        let mut groups = rows
            .iter()
            .map(group_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        groups.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(groups)
    }
}

fn group_from_row(row: &SqliteRow) -> Result<UnexpiredGroup, StoreError> {
    Ok(UnexpiredGroup {
        id: row.try_get("id")?,
        count: row.try_get("count")?,
        nearest_valid_before: row.try_get("nearest")?,
        farthest_valid_before: row.try_get("farthest")?,
    })
}
