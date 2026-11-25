use std::collections::BTreeSet;

use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::StoreError;
use crate::nodes::{Node, node_columns, node_from_row, reject_unclaimed_enrollments};

pub const MAX_REVOCATION_PAGE: u32 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationKind {
    User,
    Serial,
    Node,
}

impl RevocationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RevocationKind::User => "user",
            RevocationKind::Serial => "serial",
            RevocationKind::Node => "node",
        }
    }

    pub fn parse(value: &str) -> Option<RevocationKind> {
        match value {
            "user" => Some(RevocationKind::User),
            "serial" => Some(RevocationKind::Serial),
            "node" => Some(RevocationKind::Node),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRevocation {
    pub kind: RevocationKind,
    pub subject: String,
    pub reason: String,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub id: String,
    pub kind: RevocationKind,
    pub subject: String,
    pub reason: String,
    pub created_at: i64,
    pub created_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub revocation: Revocation,
    pub created: bool,
    pub removed_node: Option<Box<Node>>,
    pub ended_web_sessions: u64,
    pub removed_api_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationCursor {
    pub created_at: i64,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationPage {
    pub revocations: Vec<Revocation>,
    pub next: Option<RevocationCursor>,
}

macro_rules! revocation_columns {
    () => {
        "id, kind, subject, reason, created_at, created_by"
    };
}

const INSERT: &str = concat!(
    "INSERT INTO revocations (id, kind, subject, reason, created_at, created_by) \
     VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (kind, subject) DO NOTHING RETURNING ",
    revocation_columns!()
);

const FIND: &str = concat!(
    "SELECT ",
    revocation_columns!(),
    " FROM revocations WHERE kind = ? AND subject = ?"
);

const GET: &str = concat!(
    "SELECT ",
    revocation_columns!(),
    " FROM revocations WHERE id = ?"
);

const DELETE: &str = concat!(
    "DELETE FROM revocations WHERE id = ? RETURNING ",
    revocation_columns!()
);

const FIRST_PAGE: &str = concat!(
    "SELECT ",
    revocation_columns!(),
    " FROM revocations ORDER BY created_at DESC, id DESC LIMIT ?"
);

const NEXT_PAGE: &str = concat!(
    "SELECT ",
    revocation_columns!(),
    " FROM revocations WHERE created_at < ? OR (created_at = ? AND id < ?) \
     ORDER BY created_at DESC, id DESC LIMIT ?"
);

const ANY_MATCH: &str = "SELECT 1 FROM revocations \
    WHERE (kind = 'user' AND subject = ?) OR (kind = 'serial' AND subject = ?) \
    OR (kind = 'node' AND subject = ?) LIMIT 1";

macro_rules! prune_expired_serials {
    () => {
        "DELETE FROM revocations WHERE kind = 'serial' \
         AND CAST(CAST(subject AS BIGINT) AS TEXT) = subject \
         AND EXISTS (SELECT 1 FROM certificates c \
         WHERE c.serial = CAST(revocations.subject AS BIGINT) AND c.valid_before < ?)"
    };
}

const PRUNE_EXPIRED_SERIALS: &str = concat!(
    prune_expired_serials!(),
    " RETURNING ",
    revocation_columns!()
);

const SINCE: &str = concat!(
    "SELECT ",
    revocation_columns!(),
    " FROM revocations WHERE created_at >= ? ORDER BY created_at, id"
);

const REMOVE_NODE: &str = concat!(
    "UPDATE nodes SET state = 'removed', removed_at = ? WHERE id = ? AND state = 'active' \
     RETURNING ",
    node_columns!()
);

const END_WEB_SESSIONS: &str = "DELETE FROM web_sessions WHERE user_id = ?";

const REMOVE_API_TOKENS: &str = "DELETE FROM api_tokens WHERE user_id = ?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subjects<'a> {
    pub user_id: &'a str,
    pub serial: Option<i64>,
    pub node_id: Option<&'a str>,
}

#[derive(Clone)]
pub struct Revocations {
    pool: SqlitePool,
}

impl Revocations {
    pub(crate) fn new(pool: SqlitePool) -> Revocations {
        Revocations { pool }
    }

    pub async fn insert(
        &self,
        revocation: &NewRevocation,
        now: i64,
    ) -> Result<RevokeOutcome, StoreError> {
        if revocation.subject.is_empty() {
            return Err(StoreError::InvalidInput("the revocation subject is empty"));
        }
        if revocation.kind == RevocationKind::Serial
            && let Some(existing) = self.find(revocation.kind, &revocation.subject).await?
        {
            return Ok(RevokeOutcome {
                revocation: existing,
                created: false,
                removed_node: None,
                ended_web_sessions: 0,
                removed_api_tokens: 0,
            });
        }
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(INSERT)
            .bind(Uuid::new_v4().to_string())
            .bind(revocation.kind.as_str())
            .bind(&revocation.subject)
            .bind(&revocation.reason)
            .bind(now)
            .bind(&revocation.created_by)
            .fetch_optional(&mut *tx)
            .await?;
        let created = inserted.is_some();
        let row = match inserted {
            Some(row) => row,
            None => sqlx::query(FIND)
                .bind(revocation.kind.as_str())
                .bind(&revocation.subject)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| {
                    StoreError::Corrupt("revocations: a conflicting row vanished".to_owned())
                })?,
        };
        let stored = revocation_from_row(&row)?;
        let mut outcome = RevokeOutcome {
            revocation: stored,
            created,
            removed_node: None,
            ended_web_sessions: 0,
            removed_api_tokens: 0,
        };
        match outcome.revocation.kind {
            RevocationKind::Node => {
                outcome.removed_node =
                    remove_node(&mut tx, &outcome.revocation.subject, now).await?;
            }
            RevocationKind::User => {
                let subject = outcome.revocation.subject.clone();
                outcome.ended_web_sessions = sqlx::query(END_WEB_SESSIONS)
                    .bind(&subject)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                outcome.removed_api_tokens = sqlx::query(REMOVE_API_TOKENS)
                    .bind(&subject)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
            }
            RevocationKind::Serial => {}
        }
        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn get(&self, id: &str) -> Result<Option<Revocation>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(revocation_from_row).transpose()
    }

    pub async fn find(
        &self,
        kind: RevocationKind,
        subject: &str,
    ) -> Result<Option<Revocation>, StoreError> {
        let row = sqlx::query(FIND)
            .bind(kind.as_str())
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(revocation_from_row).transpose()
    }

    pub async fn revoked_among(
        &self,
        kind: RevocationKind,
        subjects: &[String],
    ) -> Result<BTreeSet<String>, StoreError> {
        let mut revoked = BTreeSet::new();
        if subjects.is_empty() {
            return Ok(revoked);
        }
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT subject FROM revocations WHERE kind = ");
        builder.push_bind(kind.as_str());
        builder.push(" AND subject IN (");
        let mut listed = builder.separated(", ");
        for subject in subjects {
            listed.push_bind(subject.clone());
        }
        builder.push(")");
        for row in builder.build().fetch_all(&self.pool).await? {
            revoked.insert(row.try_get("subject")?);
        }
        Ok(revoked)
    }

    pub async fn any_matches(&self, subjects: Subjects<'_>) -> Result<bool, StoreError> {
        let row = sqlx::query(ANY_MATCH)
            .bind(subjects.user_id)
            .bind(subjects.serial.map(|serial| serial.to_string()))
            .bind(subjects.node_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn delete(&self, id: &str) -> Result<Option<Revocation>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(DELETE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let deleted = revocation_from_row(&row)?;
        if deleted.kind == RevocationKind::User {
            for cleanup in [END_WEB_SESSIONS, REMOVE_API_TOKENS] {
                sqlx::query(cleanup)
                    .bind(&deleted.subject)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(Some(deleted))
    }

    pub async fn since(&self, created_at: i64) -> Result<Vec<Revocation>, StoreError> {
        let rows = sqlx::query(SINCE)
            .bind(created_at)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(revocation_from_row).collect()
    }

    pub async fn prune_expired_serials(
        &self,
        expired_before: i64,
    ) -> Result<Vec<Revocation>, StoreError> {
        let rows = sqlx::query(PRUNE_EXPIRED_SERIALS)
            .bind(expired_before)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(revocation_from_row).collect()
    }

    pub async fn page(
        &self,
        after: Option<&RevocationCursor>,
        limit: u32,
    ) -> Result<RevocationPage, StoreError> {
        if limit == 0 || limit > MAX_REVOCATION_PAGE {
            return Err(StoreError::InvalidInput("the page size is out of range"));
        }
        let fetched = i64::from(limit) + 1;
        let rows = match after {
            None => {
                sqlx::query(FIRST_PAGE)
                    .bind(fetched)
                    .fetch_all(&self.pool)
                    .await?
            }
            Some(cursor) => {
                sqlx::query(NEXT_PAGE)
                    .bind(cursor.created_at)
                    .bind(cursor.created_at)
                    .bind(&cursor.id)
                    .bind(fetched)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        let mut revocations = rows
            .iter()
            .map(revocation_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let wanted = usize::try_from(limit)
            .map_err(|_| StoreError::InvalidInput("the page size is out of range"))?;
        let more = revocations.len() > wanted;
        revocations.truncate(wanted);
        let next = if more {
            revocations.last().map(|last| RevocationCursor {
                created_at: last.created_at,
                id: last.id.clone(),
            })
        } else {
            None
        };
        Ok(RevocationPage { revocations, next })
    }
}

async fn remove_node(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    now: i64,
) -> Result<Option<Box<Node>>, StoreError> {
    let removed = sqlx::query(REMOVE_NODE)
        .bind(now)
        .bind(node_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(row) = removed else {
        return Ok(None);
    };
    let node = node_from_row(&row)?;
    reject_unclaimed_enrollments(tx, &node.id).await?;
    Ok(Some(Box::new(node)))
}

fn revocation_from_row(row: &SqliteRow) -> Result<Revocation, StoreError> {
    let kind: String = row.try_get("kind")?;
    Ok(Revocation {
        id: row.try_get("id")?,
        kind: RevocationKind::parse(&kind)
            .ok_or_else(|| StoreError::Corrupt(format!("revocations.kind: {kind}")))?,
        subject: row.try_get("subject")?,
        reason: row.try_get("reason")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
    })
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    use crate::Store;

    #[tokio::test]
    async fn the_prune_finds_certificates_by_their_key_and_never_scans_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("jaunt.db")).await.unwrap();
        store.migrate().await.unwrap();

        let plan = sqlx::query(concat!("EXPLAIN QUERY PLAN ", prune_expired_serials!()))
            .bind(0_i64)
            .fetch_all(&store.pool)
            .await
            .unwrap();

        let details: Vec<String> = plan
            .iter()
            .map(|row| row.try_get::<String, _>("detail").unwrap())
            .collect();
        assert!(
            details
                .iter()
                .any(|detail| detail.starts_with("SEARCH c USING") && detail.contains("serial=?")),
            "{details:?}"
        );
        assert!(
            !details
                .iter()
                .any(|detail| detail.starts_with("SCAN c") || detail.contains("SCAN certificates")),
            "{details:?}"
        );
        assert!(
            details
                .iter()
                .any(|detail| detail.starts_with("SEARCH revocations USING")
                    && detail.contains("kind=?")),
            "{details:?}"
        );
    }
}
