use std::fmt;

use serde::{Deserialize, Serialize};

const REDACTED: &str = "[redacted]";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequest {
    pub user_id: String,
    pub serial: u64,
    pub key_id: String,
    pub node_name: String,
    pub client_addr: String,
}

impl fmt::Debug for RouteRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteRequest")
            .field("user_id", &self.user_id)
            .field("serial", &self.serial)
            .field("key_id", &REDACTED)
            .field("node_name", &self.node_name)
            .field("client_addr", &self.client_addr)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Allow { session_id: String, node_id: String },
    Deny { reason: DenyReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    UnknownUser,
    CertificateNotIssued,
    CertificateExpired,
    NodeUnknown,
    NodeInactive,
    NodeUnavailable,
    PolicyDenied,
    Revoked,
    SessionUnknown,
    WrongNode,
    SessionExpired,
    SessionUsed,
    UserMismatch,
    SerialMismatch,
}

impl DenyReason {
    pub const fn code(self) -> &'static str {
        match self {
            DenyReason::UnknownUser => "unknown_user",
            DenyReason::CertificateNotIssued => "certificate_not_issued",
            DenyReason::CertificateExpired => "certificate_expired",
            DenyReason::NodeUnknown => "node_unknown",
            DenyReason::NodeInactive => "node_inactive",
            DenyReason::NodeUnavailable => "node_unavailable",
            DenyReason::PolicyDenied => "policy_denied",
            DenyReason::Revoked => "revoked",
            DenyReason::SessionUnknown => "session_unknown",
            DenyReason::WrongNode => "wrong_node",
            DenyReason::SessionExpired => "session_expired",
            DenyReason::SessionUsed => "session_used",
            DenyReason::UserMismatch => "user_mismatch",
            DenyReason::SerialMismatch => "serial_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCaller(pub String);

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeRequest {
    pub session_id: String,
    pub user_id: String,
    pub serial: u64,
    pub key_id: String,
    pub login: String,
    pub client_addr: String,
}

impl fmt::Debug for AuthorizeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizeRequest")
            .field("session_id", &self.session_id)
            .field("user_id", &self.user_id)
            .field("serial", &self.serial)
            .field("key_id", &REDACTED)
            .field("login", &self.login)
            .field("client_addr", &self.client_addr)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionPermissions {
    pub pty: bool,
    pub port_forwarding: bool,
    pub record_input: bool,
    pub max_duration_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeDecision {
    Allow { permissions: SessionPermissions },
    Deny { reason: DenyReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthorizeResponse {
    Allow { permissions: SessionPermissions },
    Deny,
}

impl From<&AuthorizeDecision> for AuthorizeResponse {
    fn from(decision: &AuthorizeDecision) -> AuthorizeResponse {
        match decision {
            AuthorizeDecision::Allow { permissions } => AuthorizeResponse::Allow {
                permissions: *permissions,
            },
            AuthorizeDecision::Deny { .. } => AuthorizeResponse::Deny,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEnd {
    pub session_id: String,
    pub exit_status: Option<i32>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub recording_incomplete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SessionEndOutcome {
    Recorded,
    Rejected,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        AuthorizeDecision, AuthorizeRequest, AuthorizeResponse, DenyReason, RouteRequest,
        SessionEnd, SessionEndOutcome, SessionPermissions,
    };
    use crate::plane::ControlPlane;

    fn permissions() -> SessionPermissions {
        SessionPermissions {
            pty: true,
            port_forwarding: false,
            record_input: true,
            max_duration_secs: 43_200,
        }
    }

    #[test]
    fn a_deny_on_the_wire_carries_no_reason() {
        let deny = AuthorizeDecision::Deny {
            reason: DenyReason::WrongNode,
        };
        let wire = serde_json::to_value(AuthorizeResponse::from(&deny)).unwrap();
        assert_eq!(wire, json!({"decision": "deny"}));

        let allow = AuthorizeDecision::Allow {
            permissions: permissions(),
        };
        let wire = serde_json::to_value(AuthorizeResponse::from(&allow)).unwrap();
        assert_eq!(
            wire,
            json!({"decision": "allow", "permissions": {
                "pty": true, "port_forwarding": false, "record_input": true,
                "max_duration_secs": 43_200,
            }})
        );
        let back: AuthorizeResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(
            back,
            AuthorizeResponse::Allow {
                permissions: permissions()
            }
        );
    }

    #[test]
    fn agent_bodies_reject_a_node_id_and_any_other_unknown_field() {
        let authorize = json!({
            "session_id": "s", "user_id": "u", "serial": 7, "key_id": "k",
            "login": "deploy", "client_addr": "203.0.113.5:4000",
        });
        let parsed: AuthorizeRequest = serde_json::from_value(authorize.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), authorize);
        let mut with_term = authorize.clone();
        with_term["term"] = json!(false);
        assert!(serde_json::from_value::<AuthorizeRequest>(with_term).is_err());
        let mut with_node = authorize;
        with_node["node_id"] = json!("other-node");
        assert!(serde_json::from_value::<AuthorizeRequest>(with_node).is_err());

        let end = json!({
            "session_id": "s", "bytes_in": 1, "bytes_out": 2, "recording_incomplete": false,
        });
        let parsed: SessionEnd = serde_json::from_value(end.clone()).unwrap();
        assert_eq!(parsed.exit_status, None);
        let mut with_node = end;
        with_node["node_id"] = json!("other-node");
        assert!(serde_json::from_value::<SessionEnd>(with_node).is_err());
    }

    #[test]
    fn session_end_outcomes_and_reason_codes_are_stable() {
        assert_eq!(
            serde_json::to_value(SessionEndOutcome::Recorded).unwrap(),
            json!({"outcome": "recorded"})
        );
        assert_eq!(
            serde_json::to_value(SessionEndOutcome::Rejected).unwrap(),
            json!({"outcome": "rejected"})
        );
        assert_eq!(DenyReason::WrongNode.code(), "wrong_node");
        assert_eq!(DenyReason::NodeInactive.code(), "node_inactive");
        assert_eq!(
            DenyReason::CertificateNotIssued.code(),
            "certificate_not_issued"
        );
    }

    #[test]
    fn debug_output_hides_the_key_id_and_its_email() {
        let key_id = "jaunt:alice@example.com:7";
        let route = RouteRequest {
            user_id: "user-1".to_owned(),
            serial: 7,
            key_id: key_id.to_owned(),
            node_name: "web-01".to_owned(),
            client_addr: "203.0.113.5:4000".to_owned(),
        };
        let authorize = AuthorizeRequest {
            session_id: "session-1".to_owned(),
            user_id: "user-1".to_owned(),
            serial: 7,
            key_id: key_id.to_owned(),
            login: "deploy".to_owned(),
            client_addr: "203.0.113.5:4000".to_owned(),
        };
        let end = SessionEnd {
            session_id: "session-1".to_owned(),
            exit_status: Some(0),
            bytes_in: 1,
            bytes_out: 2,
            recording_incomplete: false,
        };
        let shown = format!("{route:?} {authorize:?} {end:?}");
        assert!(!shown.contains("alice@example.com"), "{shown}");
        for visible in ["user-1", "session-1", "web-01", "deploy"] {
            assert!(shown.contains(visible), "{visible} missing: {shown}");
        }
    }

    #[test]
    fn the_control_plane_is_object_safe_and_shareable() {
        fn shareable<T: Send + Sync + ?Sized>() {}
        shareable::<dyn ControlPlane>();
    }
}
