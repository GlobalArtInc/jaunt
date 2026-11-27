use std::fmt;

use serde::{Deserialize, Serialize};

use crate::service::ServiceKind;
use crate::session::DenyReason;

pub const AGENT_SERVICE_AUTHORIZE_PATH: &str = "/v1/agent/service/authorize";
pub const AGENT_SERVICE_END_PATH: &str = "/v1/agent/service/end";
pub const SERVICE_LOCATION_CACHE_SECS: u64 = 10;
pub const KUBE_SESSION_ID_PREFIX: &str = "k-";
pub const KUBE_SESSION_ID_HEX_LEN: usize = 32;

const REDACTED: &str = "[redacted]";

pub fn is_kube_session_id(value: &str) -> bool {
    value
        .strip_prefix(KUBE_SESSION_ID_PREFIX)
        .is_some_and(|hex| {
            hex.len() == KUBE_SESSION_ID_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocateServiceRequest {
    pub kind: ServiceKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLocation {
    pub node_id: String,
    pub kind: ServiceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIdentity {
    pub user_id: String,
    pub serial: u64,
    pub subject_fingerprint: String,
    pub issuer_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRouteRequest {
    pub identity: ServiceIdentity,
    pub kind: ServiceKind,
    pub service: String,
    pub client_addr: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbAccessRequest {
    pub user: String,
    pub name: String,
    pub agent_key: String,
}

impl fmt::Debug for DbAccessRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbAccessRequest")
            .field("user", &self.user)
            .field("name", &self.name)
            .field("agent_key", &REDACTED)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAuthorizeRequest {
    pub session_id: String,
    pub kind: ServiceKind,
    pub service: String,
    pub identity: ServiceIdentity,
    pub client_addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db: Option<DbAccessRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubeAccess {
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub record_exec: bool,
    pub record_input: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbAccess {
    pub user: String,
    pub name: String,
    pub certificate_der: String,
    pub serial: i64,
    pub valid_after: i64,
    pub valid_before: i64,
}

impl fmt::Debug for DbAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DbAccess")
            .field("user", &self.user)
            .field("name", &self.name)
            .field("certificate_der_len", &self.certificate_der.len())
            .field("serial", &self.serial)
            .field("valid_after", &self.valid_after)
            .field("valid_before", &self.valid_before)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServiceAccess {
    Kube(KubeAccess),
    Db(DbAccess),
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceGrant {
    pub access: ServiceAccess,
    pub max_duration_secs: u64,
    pub roles: Vec<String>,
    pub policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAuthorizeDecision {
    Allow(Box<ServiceGrant>),
    Deny { reason: DenyReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ServiceAuthorizeResponse {
    Allow {
        access: ServiceAccess,
        max_duration_secs: u64,
    },
    Deny,
}

impl From<&ServiceAuthorizeDecision> for ServiceAuthorizeResponse {
    fn from(decision: &ServiceAuthorizeDecision) -> ServiceAuthorizeResponse {
        match decision {
            ServiceAuthorizeDecision::Allow(grant) => ServiceAuthorizeResponse::Allow {
                access: grant.access.clone(),
                max_duration_secs: grant.max_duration_secs,
            },
            ServiceAuthorizeDecision::Deny { .. } => ServiceAuthorizeResponse::Deny,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceOutcome {
    Closed,
    IdleTimeout,
    MaxDuration,
    ProtocolError,
    UpstreamError,
}

impl ServiceOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            ServiceOutcome::Closed => "closed",
            ServiceOutcome::IdleTimeout => "idle_timeout",
            ServiceOutcome::MaxDuration => "max_duration",
            ServiceOutcome::ProtocolError => "protocol_error",
            ServiceOutcome::UpstreamError => "upstream_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEnd {
    pub session_id: String,
    pub outcome: ServiceOutcome,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[cfg(test)]
mod tests {
    use std::task::{Context, Poll, Waker};

    use serde_json::json;

    use super::{
        DbAccess, DbAccessRequest, KubeAccess, LocateServiceRequest, ServiceAccess,
        ServiceAuthorizeDecision, ServiceAuthorizeRequest, ServiceAuthorizeResponse, ServiceEnd,
        ServiceGrant, ServiceIdentity, ServiceOutcome, ServiceRouteRequest, is_kube_session_id,
    };
    use crate::plane::{BoxFuture, ControlError, ControlPlane};
    use crate::service::ServiceKind;
    use crate::session::{
        AuthorizeDecision, AuthorizeRequest, DenyReason, NodeCaller, RouteDecision, RouteRequest,
        SessionEnd, SessionEndOutcome,
    };

    fn identity() -> serde_json::Value {
        json!({
            "user_id": "u", "serial": 7,
            "subject_fingerprint": "aa", "issuer_fingerprint": "bb",
        })
    }

    #[test]
    fn kube_session_ids_are_the_prefix_and_exactly_32_lowercase_hex_digits() {
        let hex = "0123456789abcdef0123456789abcdef";
        assert!(is_kube_session_id(&format!("k-{hex}")));
        for bad in [
            String::new(),
            hex.to_owned(),
            format!("k-{}", &hex[..31]),
            format!("k-{hex}0"),
            format!("k-{}", hex.to_uppercase()),
            format!("K-{hex}"),
            format!("k-{}g", &hex[..31]),
            "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned(),
        ] {
            assert!(!is_kube_session_id(&bad), "{bad}");
        }
    }

    #[test]
    fn service_requests_are_strict_and_round_trip() {
        let route = json!({
            "identity": identity(), "kind": "postgres", "service": "lk",
            "client_addr": "203.0.113.5:4000",
        });
        let parsed: ServiceRouteRequest = serde_json::from_value(route.clone()).unwrap();
        assert_eq!(parsed.kind, ServiceKind::Postgres);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), route);
        let mut extra = route.clone();
        extra["node_id"] = json!("n");
        assert!(serde_json::from_value::<ServiceRouteRequest>(extra).is_err());
        let mut nested = route;
        nested["identity"]["email"] = json!("a@b");
        assert!(serde_json::from_value::<ServiceRouteRequest>(nested).is_err());

        let authorize = json!({
            "session_id": "s", "kind": "postgres", "service": "lk", "identity": identity(),
            "client_addr": "203.0.113.5:4000",
            "db": {"user": "app", "name": "main", "agent_key": "AAAA"},
        });
        let parsed: ServiceAuthorizeRequest = serde_json::from_value(authorize.clone()).unwrap();
        assert_eq!(parsed.db.as_ref().unwrap().user, "app");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), authorize);
        let mut without_db = authorize.clone();
        without_db.as_object_mut().unwrap().remove("db");
        let parsed: ServiceAuthorizeRequest = serde_json::from_value(without_db.clone()).unwrap();
        assert_eq!(parsed.db, None);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), without_db);
        let mut extra_db = authorize;
        extra_db["db"]["role"] = json!("postgres");
        assert!(serde_json::from_value::<ServiceAuthorizeRequest>(extra_db).is_err());

        let end = json!({
            "session_id": "s", "outcome": "idle_timeout", "bytes_in": 1, "bytes_out": 2,
        });
        let parsed: ServiceEnd = serde_json::from_value(end.clone()).unwrap();
        assert_eq!(parsed.outcome, ServiceOutcome::IdleTimeout);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), end);
        let mut unknown = end;
        unknown["outcome"] = json!("exploded");
        assert!(serde_json::from_value::<ServiceEnd>(unknown).is_err());
    }

    #[test]
    fn a_deny_on_the_wire_carries_no_reason_and_an_allow_carries_only_the_access() {
        let deny = ServiceAuthorizeDecision::Deny {
            reason: DenyReason::ServiceMismatch,
        };
        assert_eq!(
            serde_json::to_value(ServiceAuthorizeResponse::from(&deny)).unwrap(),
            json!({"decision": "deny"})
        );

        let kube = ServiceAuthorizeDecision::Allow(Box::new(ServiceGrant {
            access: ServiceAccess::Kube(KubeAccess {
                users: vec!["alice@example.com".to_owned()],
                groups: vec!["view".to_owned()],
                record_exec: true,
                record_input: false,
            }),
            max_duration_secs: 3600,
            roles: vec!["platform".to_owned()],
            policy_hash: "hash".to_owned(),
        }));
        let wire = serde_json::to_value(ServiceAuthorizeResponse::from(&kube)).unwrap();
        assert_eq!(
            wire,
            json!({"decision": "allow", "max_duration_secs": 3600, "access": {
                "kind": "kube", "users": ["alice@example.com"], "groups": ["view"],
                "record_exec": true, "record_input": false,
            }})
        );
        let back: ServiceAuthorizeResponse = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(back, ServiceAuthorizeResponse::from(&kube));
        let mut stray = wire;
        stray["access"]["impersonate"] = json!("system:masters");
        assert!(serde_json::from_value::<ServiceAuthorizeResponse>(stray).is_err());

        let tcp = json!({"decision": "allow", "max_duration_secs": 60, "access": {"kind": "tcp"}});
        let parsed: ServiceAuthorizeResponse = serde_json::from_value(tcp.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), tcp);
    }

    struct SshOnly;

    impl ControlPlane for SshOnly {
        fn route(&self, _: RouteRequest) -> BoxFuture<'_, Result<RouteDecision, ControlError>> {
            Box::pin(async { Err(ControlError::Store) })
        }

        fn authorize(
            &self,
            _: NodeCaller,
            _: AuthorizeRequest,
        ) -> BoxFuture<'_, Result<AuthorizeDecision, ControlError>> {
            Box::pin(async { Err(ControlError::Store) })
        }

        fn session_end(
            &self,
            _: NodeCaller,
            _: SessionEnd,
        ) -> BoxFuture<'_, Result<SessionEndOutcome, ControlError>> {
            Box::pin(async { Err(ControlError::Store) })
        }
    }

    fn ready<T>(future: BoxFuture<'_, T>) -> T {
        let mut context = Context::from_waker(Waker::noop());
        let mut future = future;
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("the default answer must be immediate"),
        }
    }

    #[test]
    fn a_plane_that_predates_services_refuses_every_service_call() {
        let plane = SshOnly;
        let identity: ServiceIdentity = serde_json::from_value(identity()).unwrap();
        let node = || NodeCaller("node-1".to_owned());
        assert_eq!(
            ready(plane.locate_service(LocateServiceRequest {
                kind: ServiceKind::Kubernetes,
                name: "prod".to_owned(),
            })),
            Err(ControlError::InvalidRequest)
        );
        assert_eq!(
            ready(plane.route_service(ServiceRouteRequest {
                identity: identity.clone(),
                kind: ServiceKind::Tcp,
                service: "grafana".to_owned(),
                client_addr: "203.0.113.5:4000".to_owned(),
            })),
            Err(ControlError::InvalidRequest)
        );
        assert_eq!(
            ready(plane.authorize_service(
                node(),
                ServiceAuthorizeRequest {
                    session_id: "s".to_owned(),
                    kind: ServiceKind::Tcp,
                    service: "grafana".to_owned(),
                    identity,
                    client_addr: "203.0.113.5:4000".to_owned(),
                    db: None,
                },
            )),
            Err(ControlError::InvalidRequest)
        );
        assert_eq!(
            ready(plane.service_end(
                node(),
                ServiceEnd {
                    session_id: "s".to_owned(),
                    outcome: ServiceOutcome::Closed,
                    bytes_in: 0,
                    bytes_out: 0,
                },
            )),
            Err(ControlError::InvalidRequest)
        );
    }

    #[test]
    fn debug_output_hides_the_agent_key_and_the_certificate() {
        let request = DbAccessRequest {
            user: "app".to_owned(),
            name: "main".to_owned(),
            agent_key: "MCowBQYDK2VwAyEAkeymaterial".to_owned(),
        };
        let access = DbAccess {
            user: "app".to_owned(),
            name: "main".to_owned(),
            certificate_der: "MIIBcertificatebytes".to_owned(),
            serial: 9,
            valid_after: 1,
            valid_before: 2,
        };
        let shown = format!("{request:?} {access:?}");
        assert!(!shown.contains("keymaterial"), "{shown}");
        assert!(!shown.contains("certificatebytes"), "{shown}");
        assert!(shown.contains("app") && shown.contains("main"), "{shown}");
    }
}
