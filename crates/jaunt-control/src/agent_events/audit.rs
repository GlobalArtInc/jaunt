use std::collections::BTreeMap;

use jaunt_audit::EventType;
use jaunt_proto::AgentEventValue;
use jaunt_store::Session;

pub(crate) struct Accepted<'a> {
    pub(crate) session: &'a Session,
    pub(crate) observed_at: i64,
    pub(crate) fields: &'a BTreeMap<String, AgentEventValue>,
}

impl Accepted<'_> {
    fn text(&self, name: &str) -> Option<&str> {
        match self.fields.get(name) {
            Some(AgentEventValue::Text(text)) => Some(text),
            _ => None,
        }
    }

    fn int(&self, name: &str) -> Option<i64> {
        match self.fields.get(name) {
            Some(AgentEventValue::Int(number)) => Some(*number),
            _ => None,
        }
    }

    fn flag(&self, name: &str) -> Option<bool> {
        match self.fields.get(name) {
            Some(AgentEventValue::Bool(flag)) => Some(*flag),
            _ => None,
        }
    }

    fn session_id(&self) -> &str {
        &self.session.id
    }

    fn user_id(&self) -> &str {
        &self.session.user_id
    }

    fn node_id(&self) -> &str {
        &self.session.node_id
    }

    fn service(&self) -> Option<&str> {
        self.session.service_name.as_deref()
    }
}

fn kube_session_start(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "kube.session.start",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        user = event.text("user"),
        groups = event.text("groups"),
        client_addr = event.text("client_addr"),
        observed_at = event.observed_at
    );
}

fn kube_session_end(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "kube.session.end",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        requests_read = event.int("requests_read"),
        requests_write = event.int("requests_write"),
        requests_watch = event.int("requests_watch"),
        requests_exec = event.int("requests_exec"),
        bytes_up = event.int("bytes_up"),
        bytes_down = event.int("bytes_down"),
        reason = event.text("reason"),
        observed_at = event.observed_at
    );
}

fn kube_request(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "kube.request",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        verb = event.text("verb"),
        api_group = event.text("api_group"),
        api_version = event.text("api_version"),
        resource = event.text("resource"),
        subresource = event.text("subresource"),
        namespace = event.text("namespace"),
        name = event.text("name"),
        status = event.int("status"),
        duration_ms = event.int("duration_ms"),
        observed_at = event.observed_at
    );
}

fn kube_exec_start(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "kube.exec.start",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        namespace = event.text("namespace"),
        pod = event.text("pod"),
        container = event.text("container"),
        tty = event.flag("tty"),
        exit_status = event.int("exit_status"),
        bytes = event.int("bytes"),
        observed_at = event.observed_at
    );
}

fn kube_exec_end(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "kube.exec.end",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        namespace = event.text("namespace"),
        pod = event.text("pod"),
        container = event.text("container"),
        tty = event.flag("tty"),
        exit_status = event.int("exit_status"),
        bytes = event.int("bytes"),
        observed_at = event.observed_at
    );
}

fn db_session_start(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "db.session.start",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        db_user = event.text("db_user"),
        db_name = event.text("db_name"),
        application_name = event.text("application_name"),
        server = event.text("server"),
        observed_at = event.observed_at
    );
}

fn db_query(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit::private",
        event = "db.query",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        text = event.text("text"),
        truncated = event.flag("truncated"),
        sha256 = event.text("sha256"),
        length = event.int("length"),
        protocol = event.text("protocol"),
        command = event.text("command"),
        observed_at = event.observed_at
    );
}

fn db_error(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit::private",
        event = "db.error",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        sqlstate = event.text("sqlstate"),
        error_message = event.text("error_message"),
        observed_at = event.observed_at
    );
}

fn db_session_end(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "db.session.end",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        queries = event.int("queries"),
        errors = event.int("errors"),
        bytes = event.int("bytes"),
        duration_ms = event.int("duration_ms"),
        observed_at = event.observed_at
    );
}

fn db_protocol_error(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "db.protocol_error",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        reason = event.text("reason"),
        observed_at = event.observed_at
    );
}

fn tcp_session_start(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "tcp.session.start",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        client_addr = event.text("client_addr"),
        bytes_up = event.int("bytes_up"),
        bytes_down = event.int("bytes_down"),
        duration_ms = event.int("duration_ms"),
        reason = event.text("reason"),
        observed_at = event.observed_at
    );
}

fn tcp_session_end(event: &Accepted<'_>) {
    tracing::info!(
        target: "jaunt::audit",
        event = "tcp.session.end",
        session_id = event.session_id(),
        user_id = event.user_id(),
        node_id = event.node_id(),
        service = event.service(),
        client_addr = event.text("client_addr"),
        bytes_up = event.int("bytes_up"),
        bytes_down = event.int("bytes_down"),
        duration_ms = event.int("duration_ms"),
        reason = event.text("reason"),
        observed_at = event.observed_at
    );
}

pub(crate) fn accepted(kind: EventType, event: &Accepted<'_>) {
    match kind {
        EventType::KubeSessionStart => kube_session_start(event),
        EventType::KubeSessionEnd => kube_session_end(event),
        EventType::KubeRequest => kube_request(event),
        EventType::KubeExecStart => kube_exec_start(event),
        EventType::KubeExecEnd => kube_exec_end(event),
        EventType::DbSessionStart => db_session_start(event),
        EventType::DbQuery => db_query(event),
        EventType::DbError => db_error(event),
        EventType::DbSessionEnd => db_session_end(event),
        EventType::DbProtocolError => db_protocol_error(event),
        EventType::TcpSessionStart => tcp_session_start(event),
        EventType::TcpSessionEnd => tcp_session_end(event),
        other => tracing::error!(
            target: "jaunt::control",
            event = other.name(),
            session_id = event.session_id(),
            "an agent event of a type the agent may not send reached the audit writer; it was not recorded"
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DropReason {
    Invalid,
    Budget,
    Duplicate,
    NodeCeiling,
    AgentsCeiling,
    Expired,
    AgentQueue,
}

impl DropReason {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            DropReason::Invalid => "invalid",
            DropReason::Budget => "budget",
            DropReason::Duplicate => "duplicate",
            DropReason::NodeCeiling => "node_ceiling",
            DropReason::AgentsCeiling => "agents_ceiling",
            DropReason::Expired => "expired",
            DropReason::AgentQueue => "agent_queue",
        }
    }
}

pub(crate) fn dropped(session: &Session, reason: DropReason, count: u64, suppressed: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.events.dropped",
        node_id = session.node_id.as_str(),
        session_id = session.id.as_str(),
        count,
        reason = reason.code(),
        suppressed
    );
}

pub(crate) fn refused(
    node_id: &str,
    reason: &'static str,
    events: usize,
    sessions: usize,
    suppressed: u64,
) {
    tracing::info!(
        target: "jaunt::audit",
        event = "agent.events.refused",
        node_id,
        reason,
        events = u64::try_from(events).unwrap_or(u64::MAX),
        sessions = u64::try_from(sessions).unwrap_or(u64::MAX),
        suppressed
    );
}

pub(crate) fn audit_incomplete(session: &Session, dropped_total: u64) {
    tracing::info!(
        target: "jaunt::audit",
        event = "session.audit_incomplete",
        session_id = session.id.as_str(),
        user_id = session.user_id.as_str(),
        node_id = session.node_id.as_str(),
        dropped_total
    );
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jaunt_audit::{Actor, EventType, FieldKind, ScopedCapture};
    use jaunt_proto::{AGENT_EVENT_NAMES, AgentEventValue};
    use jaunt_store::{Session, SessionKind, SessionOrigin, SessionState};

    use super::{Accepted, DropReason, accepted, audit_incomplete, dropped, refused};
    use crate::agent_events::catalog::{CONTROL_FIELDS, OBSERVED_AT, SERVICE};

    fn session() -> Session {
        Session {
            id: "s-1".to_owned(),
            user_id: "u-1".to_owned(),
            serial: 1,
            node_id: "n-1".to_owned(),
            state: SessionState::Active,
            created_at: 0,
            expires_at: 0,
            authorized_at: Some(0),
            ended_at: None,
            login: None,
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: None,
            origin: SessionOrigin::Ssh,
            record_input: None,
            kind: SessionKind::Kube,
            service_id: None,
            target: None,
            roles: Vec::new(),
            grant_ids: Vec::new(),
            db_client_serial: None,
            outcome: None,
            decision_hash: None,
            service_name: Some("prod-eu".to_owned()),
            audit_incomplete: false,
            parent_session_id: None,
            record: None,
        }
    }

    #[tokio::test]
    async fn every_agent_event_is_written_with_every_field_and_the_envelope_of_its_session() {
        let capture = ScopedCapture::start();
        let session = session();
        for known in AGENT_EVENT_NAMES {
            let kind = EventType::from_name(known.name).unwrap();
            let fields: BTreeMap<String, AgentEventValue> = kind
                .spec()
                .fields
                .iter()
                .filter(|field| !CONTROL_FIELDS.contains(&field.name))
                .map(|field| {
                    let value = match field.kind {
                        FieldKind::Text(_) => AgentEventValue::Text(format!("{}-v", field.name)),
                        FieldKind::Int => AgentEventValue::Int(9),
                        FieldKind::Bool => AgentEventValue::Bool(true),
                    };
                    (field.name.to_owned(), value)
                })
                .collect();
            accepted(
                kind,
                &Accepted {
                    session: &session,
                    observed_at: 1234,
                    fields: &fields,
                },
            );
        }
        accepted(
            EventType::SessionStart,
            &Accepted {
                session: &session,
                observed_at: 1,
                fields: &BTreeMap::new(),
            },
        );
        dropped(&session, DropReason::Budget, 3, 4);
        refused("n-1", "foreign_session", 2, 1, 5);
        audit_incomplete(&session, 4);
        let events = capture.finish().await;
        assert_eq!(events.len(), AGENT_EVENT_NAMES.len() + 3);
        let named = |kind: EventType| {
            let found: Vec<_> = events.iter().filter(|event| event.kind() == kind).collect();
            assert_eq!(found.len(), 1, "{}", kind.name());
            found[0].clone()
        };
        for known in AGENT_EVENT_NAMES {
            let event = named(EventType::from_name(known.name).unwrap());
            let spec = event.kind().spec();
            assert_eq!(event.fields().len(), spec.fields.len(), "{}", known.name);
            assert_eq!(event.actor(), &Actor::User("u-1".to_owned()));
            assert_eq!(event.node(), Some("n-1"));
            assert_eq!(event.session_id(), Some("s-1"));
            assert_eq!(event.int(OBSERVED_AT), Some(1234));
            if spec.fields.iter().any(|field| field.name == SERVICE) {
                assert_eq!(event.text(SERVICE), Some("prod-eu"), "{}", known.name);
            }
        }
        let drop = named(EventType::AgentEventsDropped);
        assert_eq!(drop.actor(), &Actor::Node("n-1".to_owned()));
        assert_eq!(drop.session_id(), Some("s-1"));
        assert_eq!(
            (
                drop.int("count"),
                drop.text("reason"),
                drop.int("suppressed")
            ),
            (Some(3), Some("budget"), Some(4))
        );
        let refusal = named(EventType::AgentEventsRefused);
        assert_eq!(refusal.actor(), &Actor::Node("n-1".to_owned()));
        assert_eq!(refusal.session_id(), None);
        assert_eq!(
            (
                refusal.text("reason"),
                refusal.int("events"),
                refusal.int("sessions"),
                refusal.int("suppressed")
            ),
            (Some("foreign_session"), Some(2), Some(1), Some(5))
        );
        let incomplete = named(EventType::SessionAuditIncomplete);
        assert_eq!(incomplete.actor(), &Actor::User("u-1".to_owned()));
        assert_eq!(incomplete.int("dropped_total"), Some(4));
    }
}
