use std::collections::{BTreeMap, BTreeSet};

use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};
use uuid::Uuid;

use crate::StoreError;
use crate::nodes::{Labels, labels_to_text};

pub const MAX_SERVICE_PAGE: u32 = 200;
pub const MAX_SERVICE_HISTORY: i64 = 8;
pub const MAX_LIVE_SERVICES_PER_NODE: i64 = 128;
pub const MAX_PENDING_SERVICES_PER_NODE: i64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceKind {
    Kubernetes,
    Postgres,
    Tcp,
}

impl ServiceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ServiceKind::Kubernetes => "kubernetes",
            ServiceKind::Postgres => "postgres",
            ServiceKind::Tcp => "tcp",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<ServiceKind, StoreError> {
        match value {
            "kubernetes" => Ok(ServiceKind::Kubernetes),
            "postgres" => Ok(ServiceKind::Postgres),
            "tcp" => Ok(ServiceKind::Tcp),
            other => Err(StoreError::Corrupt(format!("services.kind: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Pending,
    Approved,
    Removed,
}

impl ServiceState {
    pub const fn as_str(self) -> &'static str {
        match self {
            ServiceState::Pending => "pending",
            ServiceState::Approved => "approved",
            ServiceState::Removed => "removed",
        }
    }

    fn parse(value: &str) -> Result<ServiceState, StoreError> {
        match value {
            "pending" => Ok(ServiceState::Pending),
            "approved" => Ok(ServiceState::Approved),
            "removed" => Ok(ServiceState::Removed),
            other => Err(StoreError::Corrupt(format!("services.state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub id: String,
    pub node_id: String,
    pub kind: ServiceKind,
    pub name: String,
    pub labels: Labels,
    pub announced_labels: Labels,
    pub settings: String,
    pub address_hint: Option<String>,
    pub state: ServiceState,
    pub revision: i64,
    pub announced: bool,
    pub approved_by: Option<String>,
    pub approved_at: Option<i64>,
    pub created_at: i64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncedService {
    pub kind: ServiceKind,
    pub name: String,
    pub labels: Labels,
    pub settings: String,
    pub address_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement<'a> {
    pub node_id: &'a str,
    pub ssh_enabled: bool,
    pub services: &'a [AnnouncedService],
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceChange {
    Requested(Service),
    Superseded(Service),
    Withdrawn(Service),
    Reannounced(Service),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announced {
    pub ssh_changed: Option<bool>,
    pub changes: Vec<ServiceChange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnounceOutcome {
    Applied(Announced),
    NodeNotActive,
    TooMany,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceApproval<'a> {
    pub id: &'a str,
    pub approver: &'a str,
    pub labels_override: Option<&'a Labels>,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedService {
    pub service: Service,
    pub replaced: Option<Service>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceApproveOutcome {
    Approved(Box<ApprovedService>),
    NotFound,
    NotPending(ServiceState),
    NodeNotActive,
    NameTaken { node_id: String, node_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDecisionOutcome {
    Done(Box<Service>),
    NotFound,
    WrongState(ServiceState),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCursor {
    pub created_at: i64,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceQuery {
    pub state: Option<ServiceState>,
    pub node_id: Option<String>,
    pub after: Option<ServiceCursor>,
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePage {
    pub services: Vec<Service>,
    pub next: Option<ServiceCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedHolder {
    pub service_id: String,
    pub node_id: String,
    pub node_name: String,
    pub kind: ServiceKind,
    pub name: String,
    pub revision: i64,
    pub labels: Labels,
}

macro_rules! service_columns {
    () => {
        "id, node_id, kind, name, labels, announced_labels, settings, address_hint, state, \
         revision, announced, approved_by, approved_at, created_at, last_seen_at"
    };
}

const BEGIN_WRITE: &str = "BEGIN IMMEDIATE";

const GET: &str = concat!("SELECT ", service_columns!(), " FROM services WHERE id = ?");

const NODE_SSH: &str = "SELECT ssh_enabled FROM nodes WHERE id = ? AND state = 'active'";

const SET_NODE_SSH: &str = "UPDATE nodes SET ssh_enabled = ? WHERE id = ? AND state = 'active'";

const LIVE_FOR_NODE: &str = concat!(
    "SELECT ",
    service_columns!(),
    " FROM services WHERE node_id = ? AND state IN ('pending', 'approved') \
     ORDER BY created_at, id"
);

const REFRESH: &str = concat!(
    "UPDATE services SET settings = ?, address_hint = ?, last_seen_at = ?, announced = 1 \
     WHERE id = ? RETURNING ",
    service_columns!()
);

const SUPERSEDE: &str = concat!(
    "DELETE FROM services WHERE id = ? AND state = 'pending' RETURNING ",
    service_columns!()
);

const PRUNE_HISTORY: &str = "DELETE FROM services WHERE id IN (SELECT id FROM services \
    WHERE node_id = ? AND kind = ? AND name = ? AND state = 'removed' \
    ORDER BY revision DESC LIMIT -1 OFFSET ?)";

const WITHDRAW: &str = concat!(
    "UPDATE services SET announced = 0 WHERE id = ? RETURNING ",
    service_columns!()
);

const DROP_PENDING: &str = concat!(
    "DELETE FROM services WHERE id = ? AND state = 'pending' RETURNING ",
    service_columns!()
);

const LIVE_COUNTS: &str = "SELECT COUNT(*) AS live, \
    COALESCE(SUM(CASE WHEN state = 'pending' THEN 1 ELSE 0 END), 0) AS pending \
    FROM services WHERE node_id = ? AND state IN ('pending', 'approved')";

const LAST_REVISION: &str = "SELECT COALESCE(MAX(revision), 0) AS revision FROM services \
    WHERE node_id = ? AND kind = ? AND name = ?";

const INSERT_PENDING: &str = concat!(
    "INSERT INTO services (",
    service_columns!(),
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, 1, NULL, NULL, ?, ?) RETURNING ",
    service_columns!()
);

const NODE_ACTIVE: &str = "SELECT 1 AS active FROM nodes WHERE id = ? AND state = 'active'";

const HOLDER_ELSEWHERE: &str = "SELECT n.id AS node_id, n.name AS node_name FROM services s \
    JOIN nodes n ON n.id = s.node_id \
    WHERE s.kind = ? AND s.name = ? AND s.state = 'approved' AND n.state = 'active' \
    AND s.node_id <> ? ORDER BY s.approved_at, s.id LIMIT 1";

const RETIRE_APPROVED: &str = concat!(
    "UPDATE services SET state = 'removed' \
     WHERE node_id = ? AND kind = ? AND name = ? AND state = 'approved' RETURNING ",
    service_columns!()
);

const APPROVE: &str = concat!(
    "UPDATE services SET state = 'approved', labels = ?, approved_by = ?, approved_at = ? \
     WHERE id = ? AND state = 'pending' RETURNING ",
    service_columns!()
);

const REJECT: &str = concat!(
    "UPDATE services SET state = 'removed' WHERE id = ? AND state = 'pending' RETURNING ",
    service_columns!()
);

const REMOVE: &str = concat!(
    "UPDATE services SET state = 'removed' WHERE id = ? AND state = 'approved' RETURNING ",
    service_columns!()
);

const OFFERED: &str = concat!(
    "SELECT ",
    service_columns!(),
    " FROM services WHERE state = 'approved' AND announced = 1 \
     AND node_id IN (SELECT id FROM nodes WHERE state = 'active') \
     ORDER BY kind, name, node_id, id"
);

const HOLDERS: &str = "SELECT s.id AS service_id, s.node_id AS node_id, n.name AS node_name, \
    s.kind AS kind, s.name AS name, s.revision AS revision, s.labels AS labels \
    FROM services s \
    JOIN nodes n ON n.id = s.node_id \
    WHERE s.state = 'approved' AND n.state = 'active' ORDER BY s.kind, s.name, s.node_id";

const SELECT_SERVICES: &str = concat!("SELECT ", service_columns!(), " FROM services WHERE 1 = 1");

#[derive(Default)]
struct Slot {
    approved: Option<Service>,
    pending: Option<Service>,
}

#[derive(Clone)]
pub struct Services {
    pool: SqlitePool,
}

impl Services {
    pub(crate) fn new(pool: SqlitePool) -> Services {
        Services { pool }
    }

    pub async fn get(&self, id: &str) -> Result<Option<Service>, StoreError> {
        let row = sqlx::query(GET).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(service_from_row).transpose()
    }

    pub async fn announce(
        &self,
        announcement: &Announcement<'_>,
    ) -> Result<AnnounceOutcome, StoreError> {
        let mut tx = self.pool.begin_with(BEGIN_WRITE).await?;
        let current = sqlx::query(NODE_SSH)
            .bind(announcement.node_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(current) = current else {
            tx.rollback().await?;
            return Ok(AnnounceOutcome::NodeNotActive);
        };
        let mut announced = Announced::default();
        let ssh_enabled: bool = current.try_get("ssh_enabled")?;
        if ssh_enabled != announcement.ssh_enabled {
            sqlx::query(SET_NODE_SSH)
                .bind(announcement.ssh_enabled)
                .bind(announcement.node_id)
                .execute(&mut *tx)
                .await?;
            announced.ssh_changed = Some(announcement.ssh_enabled);
        }

        let rows = sqlx::query(LIVE_FOR_NODE)
            .bind(announcement.node_id)
            .fetch_all(&mut *tx)
            .await?;
        let mut slots: BTreeMap<(ServiceKind, String), Slot> = BTreeMap::new();
        for row in &rows {
            let service = service_from_row(row)?;
            let slot = slots
                .entry((service.kind, service.name.clone()))
                .or_default();
            match service.state {
                ServiceState::Approved => slot.approved = Some(service),
                ServiceState::Pending => slot.pending = Some(service),
                ServiceState::Removed => {}
            }
        }

        let mut seen = BTreeSet::new();
        for item in announcement.services {
            let key = (item.kind, item.name.clone());
            if !seen.insert(key.clone()) {
                tx.rollback().await?;
                return Err(StoreError::InvalidInput(
                    "a service is announced more than once",
                ));
            }
            let slot = slots.remove(&key).unwrap_or_default();
            apply_item(
                &mut tx,
                announcement.node_id,
                announcement.now,
                item,
                slot,
                &mut announced.changes,
            )
            .await?;
        }

        for slot in slots.into_values() {
            if let Some(approved) = slot.approved.filter(|approved| approved.announced) {
                let row = sqlx::query(WITHDRAW)
                    .bind(&approved.id)
                    .fetch_one(&mut *tx)
                    .await?;
                announced
                    .changes
                    .push(ServiceChange::Withdrawn(service_from_row(&row)?));
            }
            if let Some(pending) = slot.pending {
                let row = sqlx::query(DROP_PENDING)
                    .bind(&pending.id)
                    .fetch_one(&mut *tx)
                    .await?;
                announced
                    .changes
                    .push(ServiceChange::Withdrawn(service_from_row(&row)?));
            }
        }
        let counts = sqlx::query(LIVE_COUNTS)
            .bind(announcement.node_id)
            .fetch_one(&mut *tx)
            .await?;
        let live: i64 = counts.try_get("live")?;
        let pending: i64 = counts.try_get("pending")?;
        if live > MAX_LIVE_SERVICES_PER_NODE || pending > MAX_PENDING_SERVICES_PER_NODE {
            tx.rollback().await?;
            return Ok(AnnounceOutcome::TooMany);
        }
        tx.commit().await?;
        Ok(AnnounceOutcome::Applied(announced))
    }

    pub async fn approve(
        &self,
        approval: &ServiceApproval<'_>,
    ) -> Result<ServiceApproveOutcome, StoreError> {
        let mut tx = self.pool.begin_with(BEGIN_WRITE).await?;
        let row = sqlx::query(GET)
            .bind(approval.id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(ServiceApproveOutcome::NotFound);
        };
        let pending = service_from_row(&row)?;
        if pending.state != ServiceState::Pending {
            tx.rollback().await?;
            return Ok(ServiceApproveOutcome::NotPending(pending.state));
        }
        let active = sqlx::query(NODE_ACTIVE)
            .bind(&pending.node_id)
            .fetch_optional(&mut *tx)
            .await?;
        if active.is_none() {
            tx.rollback().await?;
            return Ok(ServiceApproveOutcome::NodeNotActive);
        }
        let holder = sqlx::query(HOLDER_ELSEWHERE)
            .bind(pending.kind.as_str())
            .bind(&pending.name)
            .bind(&pending.node_id)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(holder) = holder {
            tx.rollback().await?;
            return Ok(ServiceApproveOutcome::NameTaken {
                node_id: holder.try_get("node_id")?,
                node_name: holder.try_get("node_name")?,
            });
        }
        let replaced = sqlx::query(RETIRE_APPROVED)
            .bind(&pending.node_id)
            .bind(pending.kind.as_str())
            .bind(&pending.name)
            .fetch_optional(&mut *tx)
            .await?
            .as_ref()
            .map(service_from_row)
            .transpose()?;
        if let Some(replaced) = &replaced {
            prune_history(&mut tx, replaced).await?;
        }
        let labels = labels_to_text(
            approval
                .labels_override
                .unwrap_or(&pending.announced_labels),
        )?;
        let approved = sqlx::query(APPROVE)
            .bind(&labels)
            .bind(approval.approver)
            .bind(approval.now)
            .bind(approval.id)
            .fetch_one(&mut *tx)
            .await?;
        let service = service_from_row(&approved)?;
        tx.commit().await?;
        Ok(ServiceApproveOutcome::Approved(Box::new(ApprovedService {
            service,
            replaced,
        })))
    }

    pub async fn reject(&self, id: &str) -> Result<ServiceDecisionOutcome, StoreError> {
        self.decide(REJECT, id).await
    }

    pub async fn remove(&self, id: &str) -> Result<ServiceDecisionOutcome, StoreError> {
        self.decide(REMOVE, id).await
    }

    async fn decide(
        &self,
        statement: &'static str,
        id: &str,
    ) -> Result<ServiceDecisionOutcome, StoreError> {
        let mut tx = self.pool.begin_with(BEGIN_WRITE).await?;
        let changed = sqlx::query(statement)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = changed {
            let service = service_from_row(&row)?;
            prune_history(&mut tx, &service).await?;
            tx.commit().await?;
            return Ok(ServiceDecisionOutcome::Done(Box::new(service)));
        }
        let found = sqlx::query(GET).bind(id).fetch_optional(&mut *tx).await?;
        tx.rollback().await?;
        match found {
            Some(row) => Ok(ServiceDecisionOutcome::WrongState(
                service_from_row(&row)?.state,
            )),
            None => Ok(ServiceDecisionOutcome::NotFound),
        }
    }

    pub async fn offered(&self) -> Result<Vec<Service>, StoreError> {
        let rows = sqlx::query(OFFERED).fetch_all(&self.pool).await?;
        rows.iter().map(service_from_row).collect()
    }

    pub async fn approved_holders(&self) -> Result<Vec<ApprovedHolder>, StoreError> {
        let rows = sqlx::query(HOLDERS).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| {
                let kind: String = row.try_get("kind")?;
                Ok(ApprovedHolder {
                    service_id: row.try_get("service_id")?,
                    node_id: row.try_get("node_id")?,
                    node_name: row.try_get("node_name")?,
                    kind: ServiceKind::parse(&kind)?,
                    name: row.try_get("name")?,
                    revision: row.try_get("revision")?,
                    labels: labels_from(row, "labels")?,
                })
            })
            .collect()
    }

    pub async fn page(&self, query: &ServiceQuery) -> Result<ServicePage, StoreError> {
        if query.limit == 0 || query.limit > MAX_SERVICE_PAGE {
            return Err(StoreError::InvalidInput("the page size is out of range"));
        }
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(SELECT_SERVICES);
        match query.state {
            Some(state) => {
                builder.push(" AND state = ");
                builder.push_bind(state.as_str());
            }
            None => {
                builder.push(" AND state IN ('pending', 'approved')");
            }
        }
        if let Some(node_id) = &query.node_id {
            builder.push(" AND node_id = ");
            builder.push_bind(node_id.clone());
        }
        if let Some(cursor) = &query.after {
            builder.push(" AND (created_at > ");
            builder.push_bind(cursor.created_at);
            builder.push(" OR (created_at = ");
            builder.push_bind(cursor.created_at);
            builder.push(" AND id > ");
            builder.push_bind(cursor.id.clone());
            builder.push("))");
        }
        builder.push(" ORDER BY created_at, id LIMIT ");
        builder.push_bind(i64::from(query.limit) + 1);
        let rows = builder.build().fetch_all(&self.pool).await?;
        let mut services = rows
            .iter()
            .map(service_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let wanted = usize::try_from(query.limit)
            .map_err(|_| StoreError::InvalidInput("the page size is out of range"))?;
        let next = if services.len() > wanted {
            services.truncate(wanted);
            services.last().map(|last| ServiceCursor {
                created_at: last.created_at,
                id: last.id.clone(),
            })
        } else {
            None
        };
        Ok(ServicePage { services, next })
    }
}

async fn apply_item(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    now: i64,
    item: &AnnouncedService,
    slot: Slot,
    changes: &mut Vec<ServiceChange>,
) -> Result<(), StoreError> {
    let approved_matches = slot
        .approved
        .as_ref()
        .is_some_and(|approved| approved.announced_labels == item.labels);
    if let Some(approved) = &slot.approved {
        refresh(tx, approved, item, now, changes).await?;
    }
    match slot.pending {
        Some(pending) if !approved_matches && pending.announced_labels == item.labels => {
            refresh(tx, &pending, item, now, changes).await?;
        }
        Some(pending) => {
            let row = sqlx::query(SUPERSEDE)
                .bind(&pending.id)
                .fetch_one(&mut **tx)
                .await?;
            changes.push(ServiceChange::Superseded(service_from_row(&row)?));
            if !approved_matches {
                request(tx, node_id, now, item, changes).await?;
            }
        }
        None if !approved_matches => request(tx, node_id, now, item, changes).await?,
        None => {}
    }
    Ok(())
}

async fn prune_history(
    tx: &mut Transaction<'_, Sqlite>,
    service: &Service,
) -> Result<(), StoreError> {
    sqlx::query(PRUNE_HISTORY)
        .bind(&service.node_id)
        .bind(service.kind.as_str())
        .bind(&service.name)
        .bind(MAX_SERVICE_HISTORY)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn refresh(
    tx: &mut Transaction<'_, Sqlite>,
    service: &Service,
    item: &AnnouncedService,
    now: i64,
    changes: &mut Vec<ServiceChange>,
) -> Result<(), StoreError> {
    let row = sqlx::query(REFRESH)
        .bind(&item.settings)
        .bind(&item.address_hint)
        .bind(now)
        .bind(&service.id)
        .fetch_one(&mut **tx)
        .await?;
    let refreshed = service_from_row(&row)?;
    if !service.announced {
        changes.push(ServiceChange::Reannounced(refreshed));
    }
    Ok(())
}

async fn request(
    tx: &mut Transaction<'_, Sqlite>,
    node_id: &str,
    now: i64,
    item: &AnnouncedService,
    changes: &mut Vec<ServiceChange>,
) -> Result<(), StoreError> {
    let last: i64 = sqlx::query(LAST_REVISION)
        .bind(node_id)
        .bind(item.kind.as_str())
        .bind(&item.name)
        .fetch_one(&mut **tx)
        .await?
        .try_get("revision")?;
    let labels = labels_to_text(&item.labels)?;
    let row = sqlx::query(INSERT_PENDING)
        .bind(Uuid::new_v4().to_string())
        .bind(node_id)
        .bind(item.kind.as_str())
        .bind(&item.name)
        .bind(&labels)
        .bind(&labels)
        .bind(&item.settings)
        .bind(&item.address_hint)
        .bind(last.saturating_add(1))
        .bind(now)
        .bind(now)
        .fetch_one(&mut **tx)
        .await?;
    changes.push(ServiceChange::Requested(service_from_row(&row)?));
    Ok(())
}

fn labels_from(row: &SqliteRow, column: &'static str) -> Result<Labels, StoreError> {
    let text: String = row.try_get(column)?;
    serde_json::from_str(&text)
        .map_err(|err| StoreError::Corrupt(format!("services.{column}: {err}")))
}

fn service_from_row(row: &SqliteRow) -> Result<Service, StoreError> {
    let kind: String = row.try_get("kind")?;
    let state: String = row.try_get("state")?;
    Ok(Service {
        id: row.try_get("id")?,
        node_id: row.try_get("node_id")?,
        kind: ServiceKind::parse(&kind)?,
        name: row.try_get("name")?,
        labels: labels_from(row, "labels")?,
        announced_labels: labels_from(row, "announced_labels")?,
        settings: row.try_get("settings")?,
        address_hint: row.try_get("address_hint")?,
        state: ServiceState::parse(&state)?,
        revision: row.try_get("revision")?,
        announced: row.try_get("announced")?,
        approved_by: row.try_get("approved_by")?,
        approved_at: row.try_get("approved_at")?,
        created_at: row.try_get("created_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
    })
}
