#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text(usize),
    Int,
    Bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorRule {
    Anonymous,
    System,
    User(&'static str),
    Node(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Critical,
    Noisy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventSpec {
    pub name: &'static str,
    pub class: Class,
    pub emitted: &'static str,
    pub actor: ActorRule,
    pub node: Option<&'static str>,
    pub session: Option<&'static str>,
    pub policy_hash: Option<&'static str>,
    pub fields: &'static [FieldSpec],
}

pub const ENVELOPE_TEXT_MAX: usize = 128;

pub const DISCARDED_FIELDS: &[&str] = &["event", "message", "email"];

const ID: FieldKind = FieldKind::Text(64);
const SHORT: FieldKind = FieldKind::Text(32);
const NAME: FieldKind = FieldKind::Text(128);
const ADDR: FieldKind = FieldKind::Text(64);
const HOST: FieldKind = FieldKind::Text(255);
const LIST: FieldKind = FieldKind::Text(512);
const ACCOUNT_GROUPS: FieldKind = FieldKind::Text(1100);
const ERROR: FieldKind = FieldKind::Text(256);
const INT: FieldKind = FieldKind::Int;
const BOOL: FieldKind = FieldKind::Bool;

const NODE: Option<&str> = Some("node_id");
const SESSION: Option<&str> = Some("session_id");
const HASH: Option<&str> = Some("policy_hash");

macro_rules! class_or_critical {
    () => {
        Class::Critical
    };
    ($class:expr) => {
        $class
    };
}

macro_rules! events {
    ($(
        $variant:ident => (
            $name:literal,
            $emitted:literal,
            $actor:expr,
            $node:expr,
            $session:expr,
            $hash:expr,
            [$(($field:literal, $kind:expr)),* $(,)?]
            $(, $class:expr)?
        )
    ),* $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum EventType {
            $($variant),*
        }

        impl EventType {
            pub const ALL: &'static [EventType] = &[$(EventType::$variant),*];

            pub fn class(self) -> Class {
                self.spec().class
            }

            pub fn spec(self) -> &'static EventSpec {
                match self {
                    $(EventType::$variant => &EventSpec {
                        name: $name,
                        class: class_or_critical!($($class)?),
                        emitted: $emitted,
                        actor: $actor,
                        node: $node,
                        session: $session,
                        policy_hash: $hash,
                        fields: &[$(FieldSpec { name: $field, kind: $kind }),*],
                    }),*
                }
            }
        }
    };
}

events! {
    LoginStarted => ("login.started", "login.started", ActorRule::Anonymous, None, None, None,
        [("login_id", ID)]),
    LoginApproved => ("login.approved", "login.approved", ActorRule::User("user_id"), None, None, None,
        [("login_id", ID), ("kind", SHORT)]),
    LoginDenied => ("login.denied", "login.denied", ActorRule::Anonymous, None, None, None,
        [("login_id", ID), ("reason", NAME)]),
    LoginFinishFailed => ("login.finish_failed", "login.finish_failed", ActorRule::User("user_id"), None, None, None,
        [("login_id", ID), ("reason", NAME)]),
    LoginDeviceStarted => ("login.device.started", "login.device.started", ActorRule::Anonymous, None, None, None,
        [("login_id", ID), ("ip", ADDR)]),
    LoginDeviceCodeFailed => ("login.device.code_failed", "login.device.code_failed", ActorRule::Anonymous, None, None, None,
        [("ip", ADDR)], Class::Noisy),
    LoginDeviceLockedOut => ("login.device.locked_out", "login.device.locked_out", ActorRule::Anonymous, None, None, None,
        [("ip", ADDR), ("reason", NAME)]),
    LoginDeviceContinued => ("login.device.continued", "login.device.continued", ActorRule::Anonymous, None, None, None,
        [("login_id", ID)]),
    LoginWebStarted => ("login.web.started", "web.login.started", ActorRule::Anonymous, None, None, None,
        [("login_id", ID)]),
    LoginWebSessionCreated => ("login.web.session_created", "web.session.created", ActorRule::User("user_id"), None, None, None,
        [("login_id", ID), ("ip", ADDR), ("expires_at", INT)]),
    LoginWebSessionEnded => ("login.web.session_ended", "web.session.ended", ActorRule::User("user_id"), None, None, None,
        [("reason", NAME)]),
    CertIssued => ("cert.issued", "cert.issued", ActorRule::User("user_id"), None, None, None,
        [("login_id", ID), ("serial", INT)]),
    CertRotated => ("cert.rotated", "agent.cert.rotated", ActorRule::System, None, None, None,
        [("not_after", INT)]),
    AdminCsrfDenied => ("admin.csrf_denied", "web.csrf.denied", ActorRule::User("user_id"), None, None, None,
        [("reason", NAME)]),
    AdminEnrolmentLookedUp => ("admin.enrolment.looked_up", "admin.enrolment.looked_up", ActorRule::User("looked_up_by"), None, None, None,
        [("outcome", SHORT), ("enrollment_id", ID)]),
    AdminSignedRequest => ("admin.signed_request", "admin.signed_request", ActorRule::User("user_id"), None, None, None,
        [("decision", SHORT), ("reason", NAME), ("serial", INT), ("method", SHORT), ("path", NAME),
         ("client_addr", ADDR)]),
    AdminSignedRequestRefused => ("admin.signed_request_refused", "admin.signed_request_refused", ActorRule::Anonymous, None, None, None,
        [("reason", NAME), ("client_addr", ADDR), ("suppressed", INT)], Class::Noisy),
    AuthzDeny => ("authz.deny", "authz.deny", ActorRule::User("user_id"), NODE, SESSION, HASH,
        [("phase", SHORT), ("reason", NAME), ("permission", NAME), ("serial", INT), ("node_name", NAME),
         ("login", NAME), ("client_addr", ADDR)]),
    SessionRouted => ("session.routed", "session.routed", ActorRule::User("user_id"), NODE, SESSION, HASH,
        [("serial", INT), ("node_name", NAME), ("client_addr", ADDR)]),
    SessionStart => ("session.start", "session.start", ActorRule::User("user_id"), NODE, SESSION, HASH,
        [("serial", INT), ("login", NAME), ("pty", BOOL), ("port_forwarding", BOOL), ("record_input", BOOL),
         ("max_duration_secs", INT), ("roles", LIST), ("client_addr", ADDR)]),
    SessionEnd => ("session.end", "session.end", ActorRule::User("user_id"), NODE, SESSION, None,
        [("serial", INT), ("login", NAME), ("exit_status", INT), ("bytes_in", INT), ("bytes_out", INT),
         ("recording_incomplete", BOOL), ("outcome", SHORT), ("late", BOOL), ("state_before", SHORT)]),
    SessionEndRejected => ("session.end_rejected", "session.end.rejected", ActorRule::Node("node_id"), NODE, SESSION, None,
        [("reason", NAME)]),
    SessionTerminated => ("session.terminated", "session.terminated", ActorRule::User("user_id"), NODE, SESSION, None,
        [("serial", INT), ("reason", NAME)]),
    RevokeCreated => ("revoke.created", "revoke.created", ActorRule::User("created_by"), None, None, None,
        [("revocation_id", ID), ("kind", SHORT), ("subject", ID), ("reason", ERROR),
         ("web_sessions_ended", INT), ("api_access_removed", INT)]),
    RevokeRemoved => ("revoke.removed", "revoke.removed", ActorRule::User("removed_by"), None, None, None,
        [("revocation_id", ID), ("kind", SHORT), ("subject", ID)]),
    GateConnect => ("gate.connect", "gate.ssh.connect", ActorRule::Anonymous, None, None, None,
        [("client_addr", ADDR), ("peer_addr", ADDR), ("proxied", BOOL)], Class::Noisy),
    GateAuth => ("gate.auth", "gate.ssh.auth", ActorRule::User("user_id"), None, None, None,
        [("outcome", SHORT), ("reason", NAME), ("client_addr", ADDR), ("serial", INT), ("login", NAME)]),
    GateSessionRefused => ("gate.session_refused", "gate.ssh.session_refused", ActorRule::Anonymous, None, None, None,
        [("client_addr", ADDR)], Class::Noisy),
    GateForward => ("gate.forward", "gate.ssh.forward", ActorRule::Anonymous, None, SESSION, None,
        [("outcome", NAME), ("node", NAME), ("client_addr", ADDR)]),
    GateStreamEnd => ("gate.stream_end", "gate.ssh.stream_end", ActorRule::Anonymous, None, SESSION, None,
        [("node", NAME), ("client_addr", ADDR), ("bytes_up", INT), ("bytes_down", INT), ("duration_ms", INT), ("reason", NAME)]),
    GateDisconnect => ("gate.disconnect", "gate.ssh.disconnect", ActorRule::Anonymous, None, None, None,
        [("client_addr", ADDR), ("reason", NAME)], Class::Noisy),
    GateTerminated => ("gate.terminated", "gate.ssh.terminated", ActorRule::User("user_id"), None, None, None,
        [("serial", INT), ("reason", NAME), ("connections", INT)]),
    AgentConnected => ("agent.connected", "agent.connected", ActorRule::Node("node_id"), NODE, None, None,
        [("remote_addr", ADDR), ("alpn", SHORT), ("replaced", BOOL)]),
    AgentDisconnected => ("agent.disconnected", "agent.disconnected", ActorRule::Node("node_id"), NODE, None, None,
        [("reason", NAME), ("alpn", SHORT)]),
    AgentRejected => ("agent.rejected", "agent.rejected", ActorRule::Anonymous, NODE, None, None,
        [("reason", NAME), ("remote_addr", ADDR)], Class::Noisy),
    AgentTrustServed => ("agent.trust.served", "agent.trust.served", ActorRule::Node("node_id"), NODE, None, None,
        [("keys", INT), ("trust_id", ID)]),
    NodeEnrollRequested => ("node.enroll.requested", "node.enroll.requested", ActorRule::Anonymous, None, None, None,
        [("enrollment_id", ID), ("name", NAME), ("hostname", HOST), ("source_ip", ADDR),
         ("source_network", ADDR), ("agent_version", SHORT), ("replace", BOOL)]),
    NodeEnrollApproved => ("node.enroll.approved", "node.enroll.approved", ActorRule::User("approved_by"), NODE, None, None,
        [("enrollment_id", ID), ("name", NAME), ("replaced_node_id", ID)]),
    NodeEnrollRejected => ("node.enroll.rejected", "node.enroll.rejected", ActorRule::User("rejected_by"), None, None, None,
        [("enrollment_id", ID), ("name", NAME)]),
    NodeEnrollExpired => ("node.enroll.expired", "node.enroll.expired", ActorRule::System, None, None, None,
        [("enrollment_id", ID), ("name", NAME)]),
    NodeEnrollDelivered => ("node.enroll.delivered", "node.enroll.delivered", ActorRule::Node("node_id"), NODE, None, None,
        [("enrollment_id", ID), ("name", NAME), ("x509_serial", ID), ("ssh_serial", ID)]),
    NodeRemoved => ("node.removed", "node.removed", ActorRule::User("removed_by"), NODE, None, None,
        [("name", NAME), ("reason", NAME)]),
    NodeCertRenewed => ("node.cert.renewed", "node.cert.renewed", ActorRule::Node("node_id"), NODE, None, None,
        [("name", NAME), ("x509_serial", ID), ("ssh_serial", ID), ("rotated", BOOL)]),
    JoinTokenCreated => ("join_token.created", "join_token.created", ActorRule::User("created_by"), None, None, None,
        [("join_id", ID), ("name", NAME), ("name_prefix", NAME), ("labels", LIST), ("max_uses", INT),
         ("expires_at", INT), ("allow_replace", BOOL)]),
    JoinTokenUsed => ("join_token.used", "join_token.used", ActorRule::Anonymous, NODE, None, None,
        [("join_id", ID), ("enrollment_id", ID), ("name", NAME), ("uses_left", INT),
         ("replaced_node_id", ID), ("source_ip", ADDR), ("source_network", ADDR)]),
    JoinTokenRefused => ("join_token.refused", "join_token.refused", ActorRule::Anonymous, None, None, None,
        [("reason", SHORT), ("join_id", ID), ("name", NAME), ("source_ip", ADDR), ("source_network", ADDR)],
        Class::Noisy),
    JoinTokenRevoked => ("join_token.revoked", "join_token.revoked", ActorRule::User("revoked_by"), None, None, None,
        [("join_id", ID), ("uses_left", INT)]),
    NodeSshChanged => ("node.ssh_changed", "node.ssh_changed", ActorRule::Node("node_id"), NODE, None, None,
        [("ssh_enabled", BOOL)]),
    ServiceAnnounceRefused => ("service.announce_refused", "service.announce_refused", ActorRule::Node("node_id"), NODE, None, None,
        [("reason", SHORT)], Class::Noisy),
    ServiceRequested => ("service.requested", "service.requested", ActorRule::Node("node_id"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT), ("labels", LIST)]),
    ServiceSuperseded => ("service.superseded", "service.superseded", ActorRule::Node("node_id"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT)]),
    ServiceWithdrawn => ("service.withdrawn", "service.withdrawn", ActorRule::Node("node_id"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT), ("state", SHORT)]),
    ServiceReannounced => ("service.reannounced", "service.reannounced", ActorRule::Node("node_id"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT), ("state", SHORT)]),
    ServiceApproved => ("service.approved", "service.approved", ActorRule::User("approved_by"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT), ("labels", LIST),
         ("labels_overridden", BOOL), ("replaced_id", ID)]),
    ServiceRejected => ("service.rejected", "service.rejected", ActorRule::User("rejected_by"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT)]),
    ServiceRemoved => ("service.removed", "service.removed", ActorRule::User("removed_by"), NODE, None, None,
        [("service_id", ID), ("kind", SHORT), ("name", NAME), ("revision", INT)]),
    RecordingCompleted => ("recording.completed", "recording.completed", ActorRule::Node("node_id"), NODE, SESSION, None,
        [("chunks", INT), ("raw_bytes", INT), ("incomplete", BOOL), ("input_recorded", BOOL)]),
    RecordingRejected => ("recording.rejected", "recording.rejected", ActorRule::Node("node_id"), NODE, SESSION, None,
        [("reason", NAME), ("suppressed", INT)], Class::Noisy),
    RecordingViewed => ("recording.viewed", "recording.viewed", ActorRule::User("user_id"), None, SESSION, None,
        [("kind", SHORT)]),
    RecordingMismatch => ("recording.mismatch", "recording.mismatch", ActorRule::Node("node_id"), NODE, SESSION, None,
        [("manifest_incomplete", BOOL), ("session_incomplete", BOOL)]),
    PolicyReload => ("policy.reload", "policy.reload", ActorRule::System, None, None, Some("hash"),
        [("applied", BOOL), ("error_count", INT), ("error_1", ERROR), ("error_2", ERROR), ("error_3", ERROR)]),
    LoginCallbackRefused => ("login.callback_refused", "login.callback_refused", ActorRule::Anonymous, None, None, None,
        [("reason", SHORT), ("client", ADDR), ("suppressed", INT)], Class::Noisy),
    HttpRateLimited => ("http.rate_limited", "http.rate_limited", ActorRule::Anonymous, None, None, None,
        [("endpoint", SHORT), ("client", ADDR), ("retry_after", INT), ("suppressed", INT)], Class::Noisy),
    HttpConnectionLimited => ("http.connection_limited", "http.connection_limited", ActorRule::Anonymous, None, None, None,
        [("peer_addr", ADDR), ("reason", SHORT), ("suppressed", INT)], Class::Noisy),
    HttpClientIpHeaderIgnored => ("http.client_ip_header_ignored", "http.client_ip_header_ignored", ActorRule::Anonymous, None, None, None,
        [("peer_addr", ADDR), ("total", INT), ("suppressed", INT)], Class::Noisy),
    GateLimited => ("gate.limited", "gate.ssh.limited", ActorRule::Anonymous, None, None, None,
        [("client", ADDR), ("reason", SHORT), ("suppressed", INT)], Class::Noisy),
    AgentLimited => ("agent.limited", "agent.limited", ActorRule::Anonymous, None, None, None,
        [("client", ADDR), ("reason", SHORT), ("suppressed", INT)], Class::Noisy),
    GateTlsRefused => ("gate.tls.refused", "gate.tls.refused", ActorRule::Anonymous, None, None, None,
        [("client", ADDR), ("reason", SHORT), ("suppressed", INT)], Class::Noisy),
    CaKeyAdded => ("ca.key.added", "ca.key.added", ActorRule::User("changed_by"), None, None, None,
        [("kind", SHORT), ("fp", ID)]),
    CaKeyPromoted => ("ca.key.promoted", "ca.key.promoted", ActorRule::User("changed_by"), None, None, None,
        [("kind", SHORT), ("fp", ID), ("forced", BOOL), ("blocked", BOOL), ("nodes_behind", INT),
         ("old_unexpired", INT)]),
    CaKeyRetired => ("ca.key.retired", "ca.key.retired", ActorRule::User("changed_by"), None, None, None,
        [("kind", SHORT), ("fp", ID), ("forced", BOOL), ("blocked", BOOL), ("old_unexpired", INT),
         ("nodes_old", INT)]),
    CaReloaded => ("ca.reloaded", "ca.reloaded", ActorRule::System, None, None, None,
        [("kind", SHORT), ("trust_id", ID), ("active_fp", ID)]),
    CaReloadFailed => ("ca.reload.failed", "ca.reload.failed", ActorRule::System, None, None, None,
        [("reason", ERROR)]),
    TerminalOpened => ("terminal.opened", "terminal.opened", ActorRule::User("user_id"), NODE, SESSION, None,
        [("node", NAME), ("login", NAME), ("serial", INT), ("client_addr", ADDR)]),
    TerminalClosed => ("terminal.closed", "terminal.closed", ActorRule::User("user_id"), NODE, SESSION, None,
        [("reason", NAME), ("bytes_in", INT), ("bytes_out", INT), ("duration_ms", INT), ("serial", INT)]),
    TerminalDenied => ("terminal.denied", "terminal.denied", ActorRule::User("user_id"), None, None, None,
        [("reason", NAME), ("node", NAME), ("login", NAME), ("client_addr", ADDR), ("suppressed", INT),
         ("ref", SHORT)],
        Class::Noisy),
    HostUserCreated => ("host_user.created", "host_user.created", ActorRule::User("user_id"), NODE, SESSION, None,
        [("login", NAME), ("uid", INT), ("home", NAME), ("groups", ACCOUNT_GROUPS), ("ref", SHORT)]),
    HostUserRefused => ("host_user.refused", "host_user.refused", ActorRule::User("user_id"), NODE, SESSION, None,
        [("login", NAME), ("reason", SHORT), ("ref", SHORT), ("suppressed", INT)], Class::Noisy),
    HostUserHelperFailed => ("host_user.helper_failed", "host_user.helper_failed", ActorRule::User("user_id"), NODE, SESSION, None,
        [("login", NAME), ("stage", SHORT), ("exit_status", INT), ("ref", SHORT)], Class::Noisy),
}

pub const IGNORED_PREFIXES: &[&str] = &["agent.ssh.", "agent.host_user."];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Classified {
    Mapped(EventType),
    Ignored,
    Unknown,
}

impl EventType {
    pub fn from_name(name: &str) -> Option<EventType> {
        EventType::ALL
            .iter()
            .copied()
            .find(|kind| kind.spec().name == name)
    }

    pub fn from_emitted(emitted: &str) -> Option<EventType> {
        EventType::ALL
            .iter()
            .copied()
            .find(|kind| kind.spec().emitted == emitted)
    }

    pub fn name(self) -> &'static str {
        self.spec().name
    }

    pub fn classify(emitted: &str) -> Classified {
        if let Some(kind) = EventType::from_emitted(emitted) {
            Classified::Mapped(kind)
        } else if IGNORED_PREFIXES
            .iter()
            .any(|prefix| emitted.starts_with(prefix))
        {
            Classified::Ignored
        } else {
            Classified::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{Classified, EventType, FieldKind};
    use crate::event::{AuditEvent, FieldValue, RawValue};
    use crate::time::Timestamp;

    #[test]
    fn names_and_emitted_names_are_unique_and_fields_never_repeat_envelope_sources() {
        let mut names = HashSet::new();
        let mut emitted = HashSet::new();
        for kind in EventType::ALL {
            let spec = kind.spec();
            assert!(names.insert(spec.name), "{}", spec.name);
            assert!(emitted.insert(spec.emitted), "{}", spec.emitted);
            let mut fields = HashSet::new();
            for field in spec.fields {
                assert!(fields.insert(field.name), "{} {}", spec.name, field.name);
                assert!(
                    !matches!(field.kind, FieldKind::Text(0)),
                    "{} {}",
                    spec.name,
                    field.name
                );
                assert!(
                    !["event", "message", "target", "id", "time", "v"].contains(&field.name),
                    "{} {}",
                    spec.name,
                    field.name
                );
            }
            let mut sources: Vec<&str> = [spec.node, spec.session, spec.policy_hash]
                .into_iter()
                .flatten()
                .collect();
            if let super::ActorRule::User(field) | super::ActorRule::Node(field) = spec.actor {
                sources.push(field);
            }
            for source in sources {
                assert!(
                    !spec.fields.iter().any(|field| field.name == source),
                    "{} {source}",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn no_field_name_can_carry_a_secret_by_its_name() {
        let forbidden = [
            "token",
            "secret",
            "password",
            "key",
            "code",
            "certificate",
            "cert",
            "email",
            "verifier",
            "handle",
            "authorization",
            "cookie",
        ];
        for kind in EventType::ALL {
            for field in kind.spec().fields {
                let name = field.name;
                for word in forbidden {
                    let allowed = name == "keys" || name == "kind";
                    assert!(allowed || !name.contains(word), "{} {name}", kind.name());
                }
            }
        }
    }

    #[test]
    fn exactly_the_connection_level_noise_and_the_flood_refusals_are_in_the_noisy_class() {
        let noisy: Vec<&str> = EventType::ALL
            .iter()
            .filter(|kind| kind.class() == super::Class::Noisy)
            .map(|kind| kind.name())
            .collect();

        assert_eq!(
            noisy,
            [
                "login.device.code_failed",
                "admin.signed_request_refused",
                "gate.connect",
                "gate.session_refused",
                "gate.disconnect",
                "agent.rejected",
                "join_token.refused",
                "service.announce_refused",
                "recording.rejected",
                "login.callback_refused",
                "http.rate_limited",
                "http.connection_limited",
                "http.client_ip_header_ignored",
                "gate.limited",
                "agent.limited",
                "gate.tls.refused",
                "terminal.denied",
                "host_user.refused",
                "host_user.helper_failed"
            ]
        );
    }

    #[test]
    fn classification_distinguishes_mapped_ignored_and_unknown_events() {
        assert_eq!(
            EventType::classify("gate.ssh.auth"),
            Classified::Mapped(EventType::GateAuth)
        );
        assert_eq!(EventType::classify("agent.ssh.end"), Classified::Ignored);
        assert_eq!(
            EventType::classify("agent.host_user.created"),
            Classified::Ignored
        );
        assert_eq!(
            EventType::classify("host_user.created"),
            Classified::Mapped(EventType::HostUserCreated)
        );
        assert_eq!(EventType::classify("revoke.thing"), Classified::Unknown);
        assert_eq!(EventType::classify(""), Classified::Unknown);
        assert_eq!(
            EventType::from_name("login.web.started"),
            Some(EventType::LoginWebStarted)
        );
        assert_eq!(EventType::from_name("web.login.started"), None);
    }

    #[test]
    fn the_groups_of_a_created_account_fit_whole_at_the_largest_list_the_agent_may_report() {
        let names: Vec<String> = (0..jaunt_proto::MAX_ACCOUNT_GROUPS)
            .map(|index| format!("g{index:0>31}"))
            .collect();
        assert!(names.iter().all(|name| name.len() == 32));
        let joined = names.join(",");
        let (event, report) = AuditEvent::from_raw(
            EventType::HostUserCreated,
            &[("groups", RawValue::Text(joined.clone()))],
            "id-1".to_owned(),
            Timestamp::from_millis(0).unwrap(),
        );
        assert_eq!(report.fields_dropped, 0);
        assert_eq!(
            event.fields().get("groups"),
            Some(&FieldValue::Text(joined))
        );
        let Some(FieldValue::Text(stored)) = event.fields().get("groups") else {
            panic!("the groups were not stored");
        };
        assert!(stored.ends_with(names.last().unwrap().as_str()));
    }
}
