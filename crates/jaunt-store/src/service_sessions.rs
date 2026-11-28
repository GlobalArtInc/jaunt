use jaunt_proto::is_kube_child_session_id;
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite, SqliteConnection, SqlitePool};
use uuid::Uuid;

use crate::nodes::Labels;
use crate::services::ServiceKind;
use crate::sessions::{
    EndOutcome, EndRejection, Session, SessionEndReason, SessionKind, SessionState,
    session_columns, session_from_row,
};
use crate::{BEGIN_WRITE, StoreError};

pub const MAX_SESSION_ROLES: usize = 32;
pub const MAX_SESSION_LIST_BYTES: usize = 4096;
pub const MAX_SESSION_TARGET_LEN: usize = 320;
pub const MAX_SESSION_OUTCOME_LEN: usize = 32;
pub const ABANDONED_OUTCOME: &str = "abandoned";
const DECISION_HASH_LEN: usize = 64;
const CHILD_CLOSE_BATCH: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewServiceRoute<'a> {
    pub user_id: &'a str,
    pub serial: i64,
    pub node_id: &'a str,
    pub kind: SessionKind,
    pub service_id: &'a str,
    pub service_name: &'a str,
    pub ttl_secs: i64,
    pub max_open: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceRouted {
    Routed(Box<Session>),
    TooMany,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivateService<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub user_id: &'a str,
    pub serial: i64,
    pub kind: SessionKind,
    pub service_id: &'a str,
    pub login: Option<&'a str>,
    pub target: Option<&'a str>,
    pub roles: &'a [String],
    pub max_duration_secs: i64,
    pub db_client_serial: Option<i64>,
    pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenKubeSession<'a> {
    pub id: &'a str,
    pub user_id: &'a str,
    pub serial: i64,
    pub node_id: &'a str,
    pub service_id: &'a str,
    pub service_name: &'a str,
    pub roles: &'a [String],
    pub max_duration_secs: i64,
    pub decision_hash: &'a str,
    pub record_exec: bool,
    pub record_input: bool,
    pub max_per_user: i64,
    pub max_per_service: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KubeOpened {
    Opened(Box<Session>),
    Repeated,
    NodeInactive,
    ServiceGone,
    TooMany,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenChildSession<'a> {
    pub id: &'a str,
    pub parent_id: &'a str,
    pub node_id: &'a str,
    pub target: &'a str,
    pub tty: bool,
    pub max_per_parent: i64,
    pub max_per_node: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildOpened {
    Opened(Box<Session>),
    ParentNotLive,
    TooManyForParent,
    TooManyForNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEnding {
    pub outcome: EndOutcome,
    pub children: Vec<Session>,
}

#[derive(Debug)]
pub enum LiveEntry<T> {
    Readable(T),
    Unreadable {
        id: String,
        kind: SessionKind,
        error: StoreError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndService<'a> {
    pub id: &'a str,
    pub node_id: &'a str,
    pub outcome: &'a str,
    pub bytes_in: i64,
    pub bytes_out: i64,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentService {
    pub id: String,
    pub kind: ServiceKind,
    pub name: String,
    pub labels: Labels,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveServiceSession {
    pub session: Session,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub service: Option<CurrentService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSshSession {
    pub session: Session,
    pub email: String,
    pub username: String,
    pub groups: Vec<String>,
    pub node_name: String,
    pub node_labels: Labels,
}

macro_rules! live_parent {
    () => {
        "p.id = ? AND p.node_id = ? AND p.kind = 'kube' AND p.parent_session_id IS NULL \
         AND p.state = 'active' AND p.authorized_at IS NOT NULL \
         AND EXISTS (SELECT 1 FROM nodes n WHERE n.id = p.node_id AND n.state = 'active')"
    };
}

const ROUTE: &str = concat!(
    "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, kind, \
     service_id, service_name) \
     SELECT ?, ?, ?, ?, 'routed', ?, ?, ?, ?, ? \
     WHERE (SELECT COUNT(*) FROM sessions o WHERE o.user_id = ? AND o.kind = ? \
     AND o.service_name = ? \
     AND (o.state = 'active' OR (o.state = 'routed' AND o.expires_at > ?))) < ? \
     RETURNING ",
    session_columns!()
);

const ACTIVATE: &str = concat!(
    "UPDATE sessions SET state = 'active', authorized_at = ?, login = ?, target = ?, roles = ?, \
     max_duration_secs = ?, db_client_serial = ? \
     WHERE id = ? AND node_id = ? AND user_id = ? AND serial = ? AND kind = ? AND service_id = ? \
     AND kind <> 'ssh' AND state = 'routed' AND expires_at > ? \
     AND EXISTS (SELECT 1 FROM nodes WHERE id = ? AND state = 'active') \
     AND EXISTS (SELECT 1 FROM services WHERE id = ? AND state = 'approved') RETURNING ",
    session_columns!()
);

const OPEN_KUBE: &str = concat!(
    "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, \
     authorized_at, kind, service_id, service_name, roles, max_duration_secs, decision_hash, \
     record, record_input) \
     SELECT ?, ?, ?, ?, 'active', ?, ?, ?, 'kube', ?, ?, ?, ?, ?, ?, ? \
     WHERE EXISTS (SELECT 1 FROM nodes WHERE id = ? AND state = 'active') \
     AND EXISTS (SELECT 1 FROM services WHERE id = ? AND state = 'approved') \
     AND (SELECT COUNT(*) FROM sessions o WHERE o.kind = 'kube' AND o.state = 'active' \
     AND o.parent_session_id IS NULL AND o.service_name = ? AND o.user_id = ?) < ? \
     AND (SELECT COUNT(*) FROM sessions o WHERE o.kind = 'kube' AND o.state = 'active' \
     AND o.parent_session_id IS NULL AND o.service_name = ?) < ? \
     ON CONFLICT (id) DO NOTHING RETURNING ",
    session_columns!()
);

const OPEN_CHILD: &str = concat!(
    "INSERT INTO sessions (id, user_id, serial, node_id, state, created_at, expires_at, \
     authorized_at, kind, service_id, service_name, target, roles, max_duration_secs, \
     decision_hash, origin, pty, record, record_input, parent_session_id) \
     SELECT ?, p.user_id, p.serial, p.node_id, 'active', ?, ?, ?, 'kube', p.service_id, \
     p.service_name, ?, p.roles, p.max_duration_secs, p.decision_hash, p.origin, ?, \
     COALESCE(p.record, 1), \
     CASE WHEN COALESCE(p.record, 1) = 1 THEN COALESCE(p.record_input, 0) ELSE 0 END, p.id \
     FROM sessions p WHERE ",
    live_parent!(),
    " AND (SELECT COUNT(*) FROM sessions c WHERE c.parent_session_id = p.id \
     AND c.state = 'active') < ? \
     AND (SELECT COUNT(*) FROM sessions c WHERE c.node_id = p.node_id AND c.state = 'active' \
     AND c.parent_session_id IS NOT NULL) < ? RETURNING ",
    session_columns!()
);

const PARENT_LIVE: &str = concat!("SELECT 1 AS found FROM sessions p WHERE ", live_parent!());

const LIVE_CHILDREN_OF_PARENT: &str =
    "SELECT COUNT(*) AS live FROM sessions WHERE parent_session_id = ? AND state = 'active'";

const CLOSE_ORPHANS: &str = concat!(
    "UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = COALESCE(\
     (SELECT CASE WHEN p.end_reason IS NULL OR p.end_reason = 'closed' THEN 'parent_ended' \
     ELSE p.end_reason END FROM sessions p \
     WHERE p.id = sessions.parent_session_id AND p.state = 'ended'), 'parent_ended') \
     WHERE state = 'active' AND parent_session_id IS NOT NULL \
     AND NOT EXISTS (SELECT 1 FROM sessions p WHERE p.id = sessions.parent_session_id \
     AND p.state = 'active') RETURNING ",
    session_columns!()
);

const EXISTS: &str = "SELECT 1 AS found FROM sessions WHERE id = ?";

const NODE_ACTIVE: &str = "SELECT 1 AS found FROM nodes WHERE id = ? AND state = 'active'";

const SERVICE_APPROVED: &str =
    "SELECT 1 AS found FROM services WHERE id = ? AND state = 'approved'";

const MARK_AUDIT_INCOMPLETE: &str = "UPDATE sessions SET audit_incomplete = 1 \
     WHERE id = ? AND node_id = ? AND kind <> 'ssh' AND audit_incomplete = 0";

pub const MAX_AUDIT_LOOKUP: usize = 1024;

const ACTIVE_OF_USER: &str = concat!(
    "SELECT ",
    session_columns!(),
    " FROM sessions WHERE user_id = ? AND kind = ? AND service_name = ? AND state = 'active' \
     AND parent_session_id IS NULL ORDER BY authorized_at, id"
);

const GET: &str = concat!("SELECT ", session_columns!(), " FROM sessions WHERE id = ?");

const END: &str = concat!(
    "UPDATE sessions SET state = 'ended', ended_at = ?, outcome = ?, bytes_in = ?, \
     bytes_out = ?, end_reason = 'closed' \
     WHERE id = ? AND node_id = ? AND state = 'active' AND kind <> 'ssh' RETURNING ",
    session_columns!()
);

const LATE_END: &str = concat!(
    "UPDATE sessions SET outcome = ?, bytes_in = ?, bytes_out = ? \
     WHERE id = ? AND node_id = ? AND state = 'ended' AND kind <> 'ssh' \
     AND end_reason IS NOT NULL AND end_reason <> 'closed' AND authorized_at IS NOT NULL \
     AND bytes_in IS NULL AND bytes_out IS NULL RETURNING ",
    session_columns!()
);

const CLOSE_ACTIVE: &str = concat!(
    "UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = ? \
     WHERE id = ? AND state = 'active' AND kind = ? RETURNING ",
    session_columns!()
);

const MARK_ABANDONED: &str = concat!(
    "UPDATE sessions SET outcome = ? \
     WHERE id = ? AND kind <> 'ssh' AND state = 'ended' AND authorized_at IS NOT NULL \
     AND end_reason IS NOT NULL AND end_reason <> 'closed' AND outcome IS NULL RETURNING ",
    session_columns!()
);

macro_rules! live_select {
    () => {
        "SELECT s.id AS id, s.user_id AS user_id, s.serial AS serial, \
         s.node_id AS node_id, s.state AS state, s.created_at AS created_at, \
         s.expires_at AS expires_at, s.authorized_at AS authorized_at, s.ended_at AS ended_at, \
         s.login AS login, s.exit_status AS exit_status, s.bytes_in AS bytes_in, \
         s.bytes_out AS bytes_out, s.recording_incomplete AS recording_incomplete, \
         s.end_reason AS end_reason, s.max_duration_secs AS max_duration_secs, \
         s.origin AS origin, s.record_input AS record_input, \
         s.kind AS kind, s.service_id AS service_id, s.target AS target, s.roles AS roles, \
         s.grant_ids AS grant_ids, s.db_client_serial AS db_client_serial, \
         s.outcome AS outcome, s.decision_hash AS decision_hash, \
         s.service_name AS service_name, s.audit_incomplete AS audit_incomplete, \
         s.parent_session_id AS parent_session_id, s.record AS record, \
         u.email AS user_email, u.username AS user_username, u.groups AS user_groups, "
    };
}

const LIVE_SSH: &str = concat!(
    live_select!(),
    "n.name AS node_name, n.labels AS node_labels \
     FROM sessions s JOIN users u ON u.id = s.user_id JOIN nodes n ON n.id = s.node_id \
     WHERE s.state = 'active' AND s.kind = 'ssh' AND n.state = 'active' \
     ORDER BY s.created_at, s.id"
);

const LIVE: &str = concat!(
    live_select!(),
    "c.id AS current_id, c.kind AS current_kind, c.name AS current_name, \
     c.labels AS current_labels \
     FROM sessions s JOIN users u ON u.id = s.user_id \
     LEFT JOIN services c ON c.node_id = s.node_id AND c.name = s.service_name \
     AND c.kind = CASE s.kind WHEN 'kube' THEN 'kubernetes' WHEN 'db' THEN 'postgres' \
     ELSE s.kind END AND c.state = 'approved' \
     WHERE s.state = 'active' AND s.kind <> 'ssh' AND s.parent_session_id IS NULL \
     ORDER BY s.created_at, s.id"
);

#[derive(Clone)]
pub struct ServiceSessions {
    pool: SqlitePool,
}

impl ServiceSessions {
    pub(crate) fn new(pool: SqlitePool) -> ServiceSessions {
        ServiceSessions { pool }
    }

    pub async fn route(&self, route: &NewServiceRoute<'_>) -> Result<ServiceRouted, StoreError> {
        service_kind_only(route.kind)?;
        if route.ttl_secs <= 0 {
            return Err(StoreError::InvalidInput("ttl_secs must be positive"));
        }
        if route.max_open <= 0 {
            return Err(StoreError::InvalidInput("max_open must be positive"));
        }
        let expires_at = route
            .now
            .checked_add(route.ttl_secs)
            .ok_or(StoreError::InvalidInput("expiry overflows"))?;
        let row = sqlx::query(ROUTE)
            .bind(Uuid::new_v4().to_string())
            .bind(route.user_id)
            .bind(route.serial)
            .bind(route.node_id)
            .bind(route.now)
            .bind(expires_at)
            .bind(route.kind.as_str())
            .bind(route.service_id)
            .bind(route.service_name)
            .bind(route.user_id)
            .bind(route.kind.as_str())
            .bind(route.service_name)
            .bind(route.now)
            .bind(route.max_open)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(ServiceRouted::Routed(Box::new(session_from_row(&row)?))),
            None => Ok(ServiceRouted::TooMany),
        }
    }

    pub async fn activate(
        &self,
        activation: &ActivateService<'_>,
    ) -> Result<Option<Session>, StoreError> {
        service_kind_only(activation.kind)?;
        if activation.kind == SessionKind::Kube {
            return Err(StoreError::InvalidInput(
                "a kube session is opened, not activated",
            ));
        }
        check_target(activation.target)?;
        check_target(activation.login)?;
        let roles = names_text(activation.roles)?;
        let row = sqlx::query(ACTIVATE)
            .bind(activation.now)
            .bind(activation.login)
            .bind(activation.target)
            .bind(roles)
            .bind(activation.max_duration_secs)
            .bind(activation.db_client_serial)
            .bind(activation.id)
            .bind(activation.node_id)
            .bind(activation.user_id)
            .bind(activation.serial)
            .bind(activation.kind.as_str())
            .bind(activation.service_id)
            .bind(activation.now)
            .bind(activation.node_id)
            .bind(activation.service_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(session_from_row).transpose()
    }

    pub async fn open_kube(&self, open: &OpenKubeSession<'_>) -> Result<KubeOpened, StoreError> {
        let roles = names_text(open.roles)?;
        if open.decision_hash.len() != DECISION_HASH_LEN
            || !open
                .decision_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StoreError::InvalidInput(
                "the decision hash is not a sha-256 hex digest",
            ));
        }
        if open.max_per_user <= 0 || open.max_per_service <= 0 {
            return Err(StoreError::InvalidInput(
                "the kube session caps must be positive",
            ));
        }
        let row = sqlx::query(OPEN_KUBE)
            .bind(open.id)
            .bind(open.user_id)
            .bind(open.serial)
            .bind(open.node_id)
            .bind(open.now)
            .bind(open.now)
            .bind(open.now)
            .bind(open.service_id)
            .bind(open.service_name)
            .bind(roles)
            .bind(open.max_duration_secs)
            .bind(open.decision_hash)
            .bind(open.record_exec)
            .bind(open.record_input)
            .bind(open.node_id)
            .bind(open.service_id)
            .bind(open.service_name)
            .bind(open.user_id)
            .bind(open.max_per_user)
            .bind(open.service_name)
            .bind(open.max_per_service)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            return Ok(KubeOpened::Opened(Box::new(session_from_row(&row)?)));
        }
        if self.found(EXISTS, open.id).await? {
            return Ok(KubeOpened::Repeated);
        }
        if !self.found(NODE_ACTIVE, open.node_id).await? {
            return Ok(KubeOpened::NodeInactive);
        }
        if !self.found(SERVICE_APPROVED, open.service_id).await? {
            return Ok(KubeOpened::ServiceGone);
        }
        Ok(KubeOpened::TooMany)
    }

    pub async fn open_child(&self, open: &OpenChildSession<'_>) -> Result<ChildOpened, StoreError> {
        if !is_kube_child_session_id(open.id) {
            return Err(StoreError::InvalidInput(
                "a child session id is not in the child session id format",
            ));
        }
        check_target(Some(open.target))?;
        if open.max_per_parent <= 0 || open.max_per_node <= 0 {
            return Err(StoreError::InvalidInput(
                "the child session caps must be positive",
            ));
        }
        let row = sqlx::query(OPEN_CHILD)
            .bind(open.id)
            .bind(open.now)
            .bind(open.now)
            .bind(open.now)
            .bind(open.target)
            .bind(open.tty)
            .bind(open.parent_id)
            .bind(open.node_id)
            .bind(open.max_per_parent)
            .bind(open.max_per_node)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = row {
            return Ok(ChildOpened::Opened(Box::new(session_from_row(&row)?)));
        }
        let parent_live = sqlx::query(PARENT_LIVE)
            .bind(open.parent_id)
            .bind(open.node_id)
            .fetch_optional(&self.pool)
            .await?
            .is_some();
        if !parent_live {
            return Ok(ChildOpened::ParentNotLive);
        }
        let live: i64 = sqlx::query(LIVE_CHILDREN_OF_PARENT)
            .bind(open.parent_id)
            .fetch_one(&self.pool)
            .await?
            .try_get("live")?;
        Ok(if live >= open.max_per_parent {
            ChildOpened::TooManyForParent
        } else {
            ChildOpened::TooManyForNode
        })
    }

    pub async fn close_orphans(&self, now: i64) -> Result<Vec<Session>, StoreError> {
        let rows = sqlx::query(CLOSE_ORPHANS)
            .bind(now)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(session_from_row).collect()
    }

    async fn found(&self, statement: &'static str, key: &str) -> Result<bool, StoreError> {
        let row = sqlx::query(statement)
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    pub async fn active_of_user(
        &self,
        user_id: &str,
        kind: SessionKind,
        service_name: &str,
    ) -> Result<Vec<Session>, StoreError> {
        let rows = sqlx::query(ACTIVE_OF_USER)
            .bind(user_id)
            .bind(kind.as_str())
            .bind(service_name)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(session_from_row).collect()
    }

    pub async fn for_audit(&self, ids: &[&str]) -> Result<Vec<Session>, StoreError> {
        if ids.len() > MAX_AUDIT_LOOKUP {
            return Err(StoreError::InvalidInput(
                "too many sessions to look up at once",
            ));
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut builder: QueryBuilder<Sqlite> = QueryBuilder::new(concat!(
            "SELECT ",
            session_columns!(),
            " FROM sessions WHERE id IN ("
        ));
        let mut separated = builder.separated(", ");
        for id in ids {
            separated.push_bind(*id);
        }
        separated.push_unseparated(")");
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter().map(session_from_row).collect()
    }

    pub async fn mark_audit_incomplete(&self, id: &str, node_id: &str) -> Result<bool, StoreError> {
        let done = sqlx::query(MARK_AUDIT_INCOMPLETE)
            .bind(id)
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() == 1)
    }

    pub async fn end(&self, end: &EndService<'_>) -> Result<ServiceEnding, StoreError> {
        if end.outcome.is_empty() || end.outcome.len() > MAX_SESSION_OUTCOME_LEN {
            return Err(StoreError::InvalidInput("the outcome is out of range"));
        }
        let mut tx = self.pool.begin_with(BEGIN_WRITE).await?;
        let row = sqlx::query(END)
            .bind(end.now)
            .bind(end.outcome)
            .bind(end.bytes_in)
            .bind(end.bytes_out)
            .bind(end.id)
            .bind(end.node_id)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(row) = row {
            let ended = session_from_row(&row)?;
            let children = close_children(
                &mut tx,
                std::slice::from_ref(&ended),
                SessionEndReason::ParentEnded,
                end.now,
            )
            .await?;
            tx.commit().await?;
            return Ok(ServiceEnding {
                outcome: EndOutcome::Ended(Box::new(ended)),
                children,
            });
        }
        tx.commit().await?;
        let outcome = self.settle_end(end).await?;
        Ok(ServiceEnding {
            outcome,
            children: Vec::new(),
        })
    }

    async fn settle_end(&self, end: &EndService<'_>) -> Result<EndOutcome, StoreError> {
        let stored = sqlx::query(GET)
            .bind(end.id)
            .fetch_optional(&self.pool)
            .await?
            .as_ref()
            .map(session_from_row)
            .transpose()?
            .filter(|stored| stored.kind != SessionKind::Ssh);
        let Some(stored) = stored else {
            return Ok(EndOutcome::Rejected(EndRejection::UnknownSession));
        };
        if stored.node_id != end.node_id {
            return Ok(EndOutcome::Rejected(EndRejection::WrongNode));
        }
        if stored.state != SessionState::Ended {
            return Ok(EndOutcome::Rejected(EndRejection::NotActive));
        }
        if stored
            .end_reason
            .is_some_and(|reason| reason != SessionEndReason::Closed)
        {
            let filled = sqlx::query(LATE_END)
                .bind(end.outcome)
                .bind(end.bytes_in)
                .bind(end.bytes_out)
                .bind(end.id)
                .bind(end.node_id)
                .fetch_optional(&self.pool)
                .await?;
            let identical = stored.outcome.as_deref() == Some(end.outcome)
                && stored.bytes_in == Some(end.bytes_in)
                && stored.bytes_out == Some(end.bytes_out);
            return Ok(match filled {
                Some(row) => EndOutcome::Late(Box::new(session_from_row(&row)?)),
                None if identical && stored.parent_session_id.is_some() => EndOutcome::Repeated,
                None => EndOutcome::Rejected(EndRejection::ClosedByControl),
            });
        }
        let identical = stored.outcome.as_deref() == Some(end.outcome)
            && stored.bytes_in == Some(end.bytes_in)
            && stored.bytes_out == Some(end.bytes_out);
        Ok(if identical {
            EndOutcome::Repeated
        } else {
            EndOutcome::Rejected(EndRejection::ConflictingEnd)
        })
    }

    pub async fn close_active(
        &self,
        id: &str,
        kind: SessionKind,
        reason: SessionEndReason,
        now: i64,
    ) -> Result<Vec<Session>, StoreError> {
        let mut tx = self.pool.begin_with(BEGIN_WRITE).await?;
        let row = sqlx::query(CLOSE_ACTIVE)
            .bind(now)
            .bind(reason.as_str())
            .bind(id)
            .bind(kind.as_str())
            .fetch_optional(&mut *tx)
            .await?;
        let mut closed = row
            .as_ref()
            .map(session_from_row)
            .transpose()?
            .into_iter()
            .collect::<Vec<_>>();
        let children = close_children(&mut tx, &closed, reason, now).await?;
        tx.commit().await?;
        closed.extend(children);
        Ok(closed)
    }

    pub async fn mark_abandoned(&self, id: &str) -> Result<Option<Session>, StoreError> {
        let row = sqlx::query(MARK_ABANDONED)
            .bind(ABANDONED_OUTCOME)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(session_from_row).transpose()
    }

    pub async fn live(&self) -> Result<Vec<LiveEntry<LiveServiceSession>>, StoreError> {
        let rows = sqlx::query(LIVE).fetch_all(&self.pool).await?;
        rows.iter().map(|row| entry(row, live_from_row)).collect()
    }

    pub async fn live_ssh(&self) -> Result<Vec<LiveEntry<LiveSshSession>>, StoreError> {
        let rows = sqlx::query(LIVE_SSH).fetch_all(&self.pool).await?;
        rows.iter()
            .map(|row| entry(row, live_ssh_from_row))
            .collect()
    }
}

pub(crate) async fn close_children(
    connection: &mut SqliteConnection,
    closed: &[Session],
    reason: SessionEndReason,
    now: i64,
) -> Result<Vec<Session>, StoreError> {
    let parents: Vec<&str> = closed
        .iter()
        .filter(|session| session.kind == SessionKind::Kube && session.parent_session_id.is_none())
        .map(|session| session.id.as_str())
        .collect();
    let mut children = Vec::new();
    for batch in parents.chunks(CHILD_CLOSE_BATCH) {
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("UPDATE sessions SET state = 'ended', ended_at = ");
        builder.push_bind(now);
        builder.push(", end_reason = ");
        builder.push_bind(reason.as_str());
        builder.push(" WHERE state = 'active' AND parent_session_id IN (");
        let mut separated = builder.separated(", ");
        for id in batch {
            separated.push_bind(*id);
        }
        separated.push_unseparated(") RETURNING ");
        builder.push(session_columns!());
        let rows = builder.build().fetch_all(&mut *connection).await?;
        for row in &rows {
            children.push(session_from_row(row)?);
        }
    }
    Ok(children)
}

fn service_kind_only(kind: SessionKind) -> Result<(), StoreError> {
    if kind == SessionKind::Ssh {
        Err(StoreError::InvalidInput(
            "an ssh session is not a service session",
        ))
    } else {
        Ok(())
    }
}

fn check_target(value: Option<&str>) -> Result<(), StoreError> {
    match value {
        Some(text) if text.is_empty() || text.len() > MAX_SESSION_TARGET_LEN => {
            Err(StoreError::InvalidInput("a session target is out of range"))
        }
        _ => Ok(()),
    }
}

fn names_text(names: &[String]) -> Result<String, StoreError> {
    if names.len() > MAX_SESSION_ROLES {
        return Err(StoreError::InvalidInput("too many names for a session"));
    }
    let text = serde_json::to_string(names)
        .map_err(|_| StoreError::InvalidInput("names serialization failed"))?;
    if text.len() > MAX_SESSION_LIST_BYTES {
        return Err(StoreError::InvalidInput(
            "the names of a session are too long",
        ));
    }
    Ok(text)
}

fn entry<T>(
    row: &SqliteRow,
    read: fn(&SqliteRow) -> Result<T, StoreError>,
) -> Result<LiveEntry<T>, StoreError> {
    let id: String = row.try_get("id")?;
    let kind: String = row.try_get("kind")?;
    let kind = SessionKind::parse(&kind)?;
    Ok(match read(row) {
        Ok(live) => LiveEntry::Readable(live),
        Err(error) => LiveEntry::Unreadable { id, kind, error },
    })
}

fn groups_from(row: &SqliteRow) -> Result<Vec<String>, StoreError> {
    let groups: String = row.try_get("user_groups")?;
    serde_json::from_str(&groups).map_err(|err| StoreError::Corrupt(format!("users.groups: {err}")))
}

fn live_ssh_from_row(row: &SqliteRow) -> Result<LiveSshSession, StoreError> {
    let labels: String = row.try_get("node_labels")?;
    Ok(LiveSshSession {
        session: session_from_row(row)?,
        email: row.try_get("user_email")?,
        username: row.try_get("user_username")?,
        groups: groups_from(row)?,
        node_name: row.try_get("node_name")?,
        node_labels: serde_json::from_str(&labels)
            .map_err(|err| StoreError::Corrupt(format!("nodes.labels: {err}")))?,
    })
}

fn live_from_row(row: &SqliteRow) -> Result<LiveServiceSession, StoreError> {
    let groups = groups_from(row)?;
    let current_id: Option<String> = row.try_get("current_id")?;
    let service = match current_id {
        Some(id) => {
            let kind: String = row.try_get("current_kind")?;
            let labels: String = row.try_get("current_labels")?;
            Some(CurrentService {
                id,
                kind: ServiceKind::parse(&kind)?,
                name: row.try_get("current_name")?,
                labels: serde_json::from_str(&labels)
                    .map_err(|err| StoreError::Corrupt(format!("services.labels: {err}")))?,
            })
        }
        None => None,
    };
    Ok(LiveServiceSession {
        session: session_from_row(row)?,
        email: row.try_get("user_email")?,
        username: row.try_get("user_username")?,
        groups,
        service,
    })
}
