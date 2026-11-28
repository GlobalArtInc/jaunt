use jaunt_proto::ChildSessionRequest;
use jaunt_store::Session;

pub(crate) fn created(child: &Session, request: &ChildSessionRequest) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.child.created",
        session_id = child.id.as_str(),
        user_id = child.user_id.as_str(),
        node_id = child.node_id.as_str(),
        parent_session_id = child.parent_session_id.as_deref(),
        kind = request.kind.as_str(),
        service = child.service_name.as_deref(),
        namespace = request.namespace.as_str(),
        pod = request.pod.as_str(),
        container = (!request.container.is_empty()).then_some(request.container.as_str()),
        tty = request.tty,
        record = child.record == Some(true),
        record_input = child.record_input == Some(true),
        serial = child.serial
    );
}

pub(crate) fn refused(
    node_id: &str,
    reason: &'static str,
    parent_session_id: Option<&str>,
    suppressed: u64,
) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.child.refused",
        node_id,
        reason,
        parent_session_id,
        suppressed
    );
}
