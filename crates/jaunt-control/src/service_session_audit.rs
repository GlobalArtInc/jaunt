use jaunt_proto::DenyReason;
use jaunt_store::{Session, SessionKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServicePhase {
    Route,
    Authorize,
}

impl ServicePhase {
    const fn as_str(self) -> &'static str {
        match self {
            ServicePhase::Route => "route",
            ServicePhase::Authorize => "authorize",
        }
    }
}

pub(crate) struct ServiceDenied<'a> {
    pub(crate) phase: ServicePhase,
    pub(crate) kind: SessionKind,
    pub(crate) service: &'a str,
    pub(crate) reason: DenyReason,
    pub(crate) policy_hash: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) serial: u64,
    pub(crate) node_id: Option<&'a str>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) login: Option<&'a str>,
    pub(crate) db_name: Option<&'a str>,
    pub(crate) client_addr: &'a str,
}

pub(crate) struct ServiceRouted<'a> {
    pub(crate) session: &'a Session,
    pub(crate) service: &'a str,
    pub(crate) client_addr: &'a str,
    pub(crate) policy_hash: &'a str,
}

pub(crate) struct ServiceStarted<'a> {
    pub(crate) session: &'a Session,
    pub(crate) service: &'a str,
    pub(crate) users: &'a [String],
    pub(crate) groups: &'a [String],
    pub(crate) record_exec: Option<bool>,
    pub(crate) record_input: Option<bool>,
    pub(crate) client_addr: &'a str,
    pub(crate) policy_hash: &'a str,
}

pub(crate) struct DbClientIssued<'a> {
    pub(crate) session: &'a Session,
    pub(crate) serial: i64,
    pub(crate) db_user: &'a str,
    pub(crate) valid_before: i64,
}

pub(crate) fn denied(event: &ServiceDenied<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "authz.service.deny",
        phase = event.phase.as_str(),
        kind = event.kind.as_str(),
        service = event.service,
        reason = event.reason.code(),
        policy_hash = event.policy_hash,
        user_id = event.user_id,
        serial = event.serial,
        node_id = event.node_id,
        session_id = event.session_id,
        login = event.login,
        db_name = event.db_name,
        client_addr = event.client_addr
    );
}

pub(crate) fn routed(event: &ServiceRouted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.service.routed",
        session_id = event.session.id.as_str(),
        user_id = event.session.user_id.as_str(),
        serial = event.session.serial,
        node_id = event.session.node_id.as_str(),
        kind = event.session.kind.as_str(),
        service = event.service,
        client_addr = event.client_addr,
        policy_hash = event.policy_hash
    );
}

pub(crate) fn started(event: &ServiceStarted<'_>) {
    let roles = event.session.roles.join(",");
    let users = event.users.join(",");
    let groups = event.groups.join(",");
    tracing::info!(
        target: "jaunt::audit",
        event = "session.service.start",
        session_id = event.session.id.as_str(),
        user_id = event.session.user_id.as_str(),
        serial = event.session.serial,
        node_id = event.session.node_id.as_str(),
        kind = event.session.kind.as_str(),
        service = event.service,
        roles = roles.as_str(),
        login = event.session.login.as_deref(),
        db_name = event.session.target.as_deref(),
        users = (!users.is_empty()).then_some(users.as_str()),
        groups = (!groups.is_empty()).then_some(groups.as_str()),
        record_exec = event.record_exec,
        record_input = event.record_input,
        max_duration_secs = event.session.max_duration_secs,
        db_client_serial = event.session.db_client_serial,
        client_addr = event.client_addr,
        policy_hash = event.policy_hash
    );
}

pub(crate) fn db_client_issued(event: &DbClientIssued<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "cert.db_client.issued",
        session_id = event.session.id.as_str(),
        user_id = event.session.user_id.as_str(),
        node_id = event.session.node_id.as_str(),
        serial = event.serial,
        db_user = event.db_user,
        valid_before = event.valid_before
    );
}

pub(crate) fn ended(session: &Session, late: bool) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.service.end",
        session_id = session.id.as_str(),
        user_id = session.user_id.as_str(),
        serial = session.serial,
        node_id = session.node_id.as_str(),
        kind = session.kind.as_str(),
        outcome = session.outcome.as_deref(),
        bytes_in = session.bytes_in,
        bytes_out = session.bytes_out,
        late
    );
}
