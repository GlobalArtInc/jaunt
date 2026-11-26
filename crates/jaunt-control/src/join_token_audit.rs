use jaunt_store::{JoinToken, NameScope};

use crate::join_tokens::Refusal;

pub(crate) struct Used<'a> {
    pub(crate) join_id: &'a str,
    pub(crate) enrollment_id: &'a str,
    pub(crate) node_id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) uses_left: i64,
    pub(crate) replaced_node_id: Option<&'a str>,
    pub(crate) source_ip: &'a str,
    pub(crate) source_network: &'a str,
}

pub(crate) struct Refused<'a> {
    pub(crate) reason: Refusal,
    pub(crate) join_id: Option<&'a str>,
    pub(crate) name: &'a str,
    pub(crate) source_ip: &'a str,
    pub(crate) source_network: &'a str,
}

fn scope_fields(scope: &NameScope) -> (Option<&str>, Option<&str>) {
    match scope {
        NameScope::Exact(name) => (Some(name.as_str()), None),
        NameScope::Prefix(prefix) => (None, Some(prefix.as_str())),
    }
}

fn labels_text(token: &JoinToken) -> String {
    token
        .labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn created(token: &JoinToken) {
    let (name, name_prefix) = scope_fields(&token.scope);
    let labels = labels_text(token);
    tracing::info!(
        target: "jaunt::audit",
        event = "join_token.created",
        join_id = token.id.as_str(),
        created_by = token.created_by.as_str(),
        name,
        name_prefix,
        labels = labels.as_str(),
        max_uses = token.max_uses,
        expires_at = token.expires_at,
        allow_replace = token.allow_replace
    );
}

pub(crate) fn used(event: &Used<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "join_token.used",
        join_id = event.join_id,
        enrollment_id = event.enrollment_id,
        node_id = event.node_id,
        name = event.name,
        uses_left = event.uses_left,
        replaced_node_id = event.replaced_node_id,
        source_ip = event.source_ip,
        source_network = event.source_network
    );
}

pub(crate) fn refused(event: &Refused<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "join_token.refused",
        reason = event.reason.as_str(),
        join_id = event.join_id,
        name = event.name,
        source_ip = event.source_ip,
        source_network = event.source_network
    );
}

pub(crate) fn revoked(token: &JoinToken, revoked_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "join_token.revoked",
        join_id = token.id.as_str(),
        revoked_by,
        uses_left = token.uses_left
    );
}
