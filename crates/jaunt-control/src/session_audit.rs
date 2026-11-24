use jaunt_proto::{DenyReason, SessionPermissions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Route,
    Authorize,
}

impl Phase {
    const fn as_str(self) -> &'static str {
        match self {
            Phase::Route => "route",
            Phase::Authorize => "authorize",
        }
    }
}

pub(crate) struct Denied<'a> {
    pub(crate) phase: Phase,
    pub(crate) reason: DenyReason,
    pub(crate) policy_hash: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) serial: u64,
    pub(crate) node_id: Option<&'a str>,
    pub(crate) node_name: Option<&'a str>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) login: Option<&'a str>,
    pub(crate) client_addr: &'a str,
}

pub(crate) struct Routed<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) serial: i64,
    pub(crate) node_id: &'a str,
    pub(crate) node_name: &'a str,
    pub(crate) client_addr: &'a str,
    pub(crate) policy_hash: &'a str,
}

pub(crate) struct Started<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) serial: i64,
    pub(crate) node_id: &'a str,
    pub(crate) login: &'a str,
    pub(crate) term: bool,
    pub(crate) permissions: SessionPermissions,
    pub(crate) roles: &'a [String],
    pub(crate) client_addr: &'a str,
    pub(crate) policy_hash: &'a str,
}

pub(crate) struct Ended<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) user_id: &'a str,
    pub(crate) serial: i64,
    pub(crate) node_id: &'a str,
    pub(crate) login: Option<&'a str>,
    pub(crate) exit_status: Option<i32>,
    pub(crate) bytes_in: i64,
    pub(crate) bytes_out: i64,
    pub(crate) recording_incomplete: bool,
}

pub(crate) fn denied(event: &Denied<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "authz.deny",
        phase = event.phase.as_str(),
        reason = event.reason.code(),
        policy_hash = event.policy_hash,
        user_id = event.user_id,
        serial = event.serial,
        node_id = event.node_id,
        node_name = event.node_name,
        session_id = event.session_id,
        login = event.login,
        client_addr = event.client_addr
    );
}

pub(crate) fn routed(event: &Routed<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.routed",
        session_id = event.session_id,
        user_id = event.user_id,
        serial = event.serial,
        node_id = event.node_id,
        node_name = event.node_name,
        client_addr = event.client_addr,
        policy_hash = event.policy_hash
    );
}

pub(crate) fn started(event: &Started<'_>) {
    let roles = event.roles.join(",");
    tracing::info!(
        target: "jaunt::audit",
        event = "session.start",
        session_id = event.session_id,
        user_id = event.user_id,
        serial = event.serial,
        node_id = event.node_id,
        login = event.login,
        term = event.term,
        pty = event.permissions.pty,
        port_forwarding = event.permissions.port_forwarding,
        record_input = event.permissions.record_input,
        max_duration_secs = event.permissions.max_duration_secs,
        roles = roles.as_str(),
        client_addr = event.client_addr,
        policy_hash = event.policy_hash
    );
}

pub(crate) fn ended(event: &Ended<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.end",
        session_id = event.session_id,
        user_id = event.user_id,
        serial = event.serial,
        node_id = event.node_id,
        login = event.login,
        exit_status = event.exit_status,
        bytes_in = event.bytes_in,
        bytes_out = event.bytes_out,
        recording_incomplete = event.recording_incomplete
    );
}

pub(crate) fn end_rejected(node_id: &str, session_id: &str, reason: &'static str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.end.rejected",
        node_id,
        session_id,
        reason
    );
}
