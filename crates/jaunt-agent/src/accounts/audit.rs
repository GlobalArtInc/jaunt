use jaunt_proto::{AccountReference, AccountStage};

pub struct Visit<'a> {
    pub session_id: &'a str,
    pub login: &'a str,
}

pub fn created(visit: &Visit<'_>, reference: &AccountReference, uid: u32, home: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.host_user.created",
        session_id = visit.session_id,
        "ref" = reference.as_str(),
        login = ?visit.login,
        uid,
        home
    );
}

pub fn refused(visit: &Visit<'_>, reference: &AccountReference, reason: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.host_user.refused",
        session_id = visit.session_id,
        "ref" = reference.as_str(),
        login = ?visit.login,
        reason
    );
}

pub fn failed(
    visit: &Visit<'_>,
    reference: &AccountReference,
    stage: AccountStage,
    exit_code: Option<i32>,
    cause: &str,
) {
    tracing::warn!(
        target: "jaunt::audit",
        event = "agent.host_user.helper_failed",
        session_id = visit.session_id,
        "ref" = reference.as_str(),
        login = ?visit.login,
        stage = stage.as_str(),
        exit_code,
        cause
    );
}

pub fn missing(visit: &Visit<'_>, reference: &AccountReference, cause: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.host_user.missing",
        session_id = visit.session_id,
        "ref" = reference.as_str(),
        login = ?visit.login,
        cause
    );
}
