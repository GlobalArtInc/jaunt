use jaunt_store::{Revocation, Session};

use crate::killer::KillReason;

pub(crate) fn created(revocation: &Revocation, web_sessions_ended: u64, api_access_removed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "revoke.created",
        revocation_id = revocation.id.as_str(),
        kind = revocation.kind.as_str(),
        subject = revocation.subject.as_str(),
        reason = revocation.reason.as_str(),
        created_by = revocation.created_by.as_str(),
        web_sessions_ended,
        api_access_removed
    );
}

pub(crate) fn removed(revocation: &Revocation, removed_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "revoke.removed",
        revocation_id = revocation.id.as_str(),
        kind = revocation.kind.as_str(),
        subject = revocation.subject.as_str(),
        removed_by
    );
}

pub(crate) fn session_terminated(session: &Session, reason: KillReason) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.terminated",
        session_id = session.id.as_str(),
        user_id = session.user_id.as_str(),
        serial = session.serial,
        node_id = session.node_id.as_str(),
        reason = reason.as_str()
    );
}

pub(crate) fn principal_refused(user_id: &str, phase: &'static str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "authz.deny",
        phase,
        reason = "revoked",
        user_id
    );
}
