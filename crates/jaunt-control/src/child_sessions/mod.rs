mod audit;

use std::time::Duration;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};
use jaunt_limits::{Decision, Rate, RateLimiter};
use jaunt_proto::{
    ChildSessionGrant, ChildSessionRefusal, ChildSessionRequest, KUBE_CHILD_SESSION_ID_PREFIX,
};
use jaunt_store::{
    ChildOpened, MAX_SESSION_TARGET_LEN, OpenChildSession, Session, SessionKind, SessionState,
    Subjects,
};

use crate::agent::{AuthenticatedNode, active_node};
use crate::agent_events::notices::Notices;
use crate::authorize::DEFAULT_MAX_SESSION_SECS;
use crate::control::Control;
use crate::http::{
    BodyFailure, empty_response, error_response, json_body, json_response, server_error,
};
use crate::limits::retry_after_secs;
use crate::revocation::{is_identifier, revoked};

pub(crate) const REQUESTS_PER_NODE: Rate = Rate::clamped(60, 30 * 60);
pub(crate) const MAX_CHILDREN_PER_PARENT: i64 = 64;
pub(crate) const MAX_CHILDREN_PER_NODE: i64 = 512;
const NODES_TRACKED: usize = 10_000;
const CHILD_ID_BYTES: usize = 16;

pub(crate) struct ChildSessions {
    requests: RateLimiter<String>,
    notices: Notices,
}

impl ChildSessions {
    pub(crate) fn new() -> ChildSessions {
        ChildSessions {
            requests: RateLimiter::new(REQUESTS_PER_NODE, NODES_TRACKED),
            notices: Notices::new(),
        }
    }

    pub(crate) fn sweep(&self, tick: Duration) {
        self.requests.sweep(tick);
        self.notices.sweep(tick);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Malformed,
    TooLarge,
    InvalidParent,
    InvalidName,
    RateLimited,
    UnknownParent,
    ForeignParent,
    NotAuthorized,
    NotKube,
    NestedParent,
    ParentEnded,
    ParentExpired,
    Revoked,
    ParentCap,
    NodeCap,
}

impl Refusal {
    const fn reason(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::TooLarge => "too_large",
            Refusal::InvalidParent => "invalid_parent",
            Refusal::InvalidName => "invalid_name",
            Refusal::RateLimited => "rate_limited",
            Refusal::UnknownParent => "unknown_parent",
            Refusal::ForeignParent => "foreign_parent",
            Refusal::NotAuthorized => "not_authorized",
            Refusal::NotKube => "not_kube",
            Refusal::NestedParent => "nested_parent",
            Refusal::ParentEnded => "parent_ended",
            Refusal::ParentExpired => "parent_expired",
            Refusal::Revoked => "revoked",
            Refusal::ParentCap => "parent_cap",
            Refusal::NodeCap => "node_cap",
        }
    }

    const fn outward(self) -> ChildSessionRefusal {
        match self {
            Refusal::Malformed
            | Refusal::TooLarge
            | Refusal::InvalidParent
            | Refusal::InvalidName => ChildSessionRefusal::Invalid,
            Refusal::RateLimited => ChildSessionRefusal::RateLimited,
            Refusal::UnknownParent | Refusal::ForeignParent | Refusal::NotAuthorized => {
                ChildSessionRefusal::UnknownParent
            }
            Refusal::NotKube | Refusal::NestedParent => ChildSessionRefusal::NotKube,
            Refusal::ParentEnded | Refusal::ParentExpired | Refusal::Revoked => {
                ChildSessionRefusal::ParentEnded
            }
            Refusal::ParentCap | Refusal::NodeCap => ChildSessionRefusal::TooManyChildren,
        }
    }
}

fn refuse(control: &Control, node_id: &str, refusal: Refusal, parent: Option<&str>) -> Response {
    refuse_waiting(control, node_id, refusal, parent, None)
}

fn refuse_waiting(
    control: &Control,
    node_id: &str,
    refusal: Refusal,
    parent: Option<&str>,
    wait: Option<Duration>,
) -> Response {
    let notices = &control.child_sessions.notices;
    if let Some(suppressed) = notices.admit(node_id, refusal.reason(), control.tick()) {
        audit::refused(
            node_id,
            refusal.reason(),
            parent.filter(|id| is_identifier(id)),
            suppressed,
        );
    }
    let outward = refusal.outward();
    let status = StatusCode::from_u16(outward.status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = error_response(status, outward.code());
    if let Some(wait) = wait {
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from(retry_after_secs(wait)),
        );
    }
    response
}

pub(crate) async fn handle(
    State(control): State<Control>,
    authenticated: Option<Extension<AuthenticatedNode>>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let Some(Extension(AuthenticatedNode(node_id))) = authenticated else {
        return empty_response(StatusCode::UNAUTHORIZED);
    };
    if let Decision::Limited { retry_after } = control
        .child_sessions
        .requests
        .check(&node_id, control.tick())
    {
        return refuse_waiting(
            &control,
            &node_id,
            Refusal::RateLimited,
            None,
            Some(retry_after),
        );
    }
    let request = match json_body::<ChildSessionRequest>(&headers, body) {
        Ok(request) => request,
        Err(BodyFailure::TooLarge) => return refuse(&control, &node_id, Refusal::TooLarge, None),
        Err(BodyFailure::Malformed) => {
            return refuse(&control, &node_id, Refusal::Malformed, None);
        }
    };
    if !is_identifier(&request.parent_session_id) {
        return refuse(&control, &node_id, Refusal::InvalidParent, None);
    }
    if !request.is_well_formed() {
        return refuse(
            &control,
            &node_id,
            Refusal::InvalidName,
            Some(&request.parent_session_id),
        );
    }
    let task = tokio::spawn(async move { create(&control, &node_id, &request).await });
    task.await.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "creating a child session did not finish");
        server_error()
    })
}

fn standing(parent: Option<&Session>, node_id: &str, now: i64) -> Result<(), Refusal> {
    let parent = parent.ok_or(Refusal::UnknownParent)?;
    if parent.node_id != node_id {
        return Err(Refusal::ForeignParent);
    }
    if parent.kind != SessionKind::Kube {
        return Err(Refusal::NotKube);
    }
    if parent.parent_session_id.is_some() {
        return Err(Refusal::NestedParent);
    }
    let Some(authorized_at) = parent.authorized_at else {
        return Err(Refusal::NotAuthorized);
    };
    if parent.state != SessionState::Active {
        return Err(Refusal::ParentEnded);
    }
    let longest = parent
        .max_duration_secs
        .unwrap_or_else(|| i64::try_from(DEFAULT_MAX_SESSION_SECS).unwrap_or(i64::MAX));
    if authorized_at.saturating_add(longest) <= now {
        return Err(Refusal::ParentExpired);
    }
    Ok(())
}

fn target_of(request: &ChildSessionRequest) -> String {
    let mut target = format!("{}/{}", request.namespace, request.pod);
    if !request.container.is_empty() {
        target.push('/');
        target.push_str(&request.container);
    }
    let mut end = MAX_SESSION_TARGET_LEN.min(target.len());
    while !target.is_char_boundary(end) {
        end -= 1;
    }
    target.truncate(end);
    target
}

fn child_id() -> Option<String> {
    let mut bytes = [0_u8; CHILD_ID_BYTES];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Some(format!("{KUBE_CHILD_SESSION_ID_PREFIX}{hex}"))
}

async fn create(control: &Control, node_id: &str, request: &ChildSessionRequest) -> Response {
    if let Err(refusal) = active_node(control, node_id).await {
        return refusal.into_response();
    }
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let parent_id = request.parent_session_id.as_str();
    let parent = match control.store.sessions().get(parent_id).await {
        Ok(parent) => parent,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the parent of a child session failed");
            return server_error();
        }
    };
    if let Err(refusal) = standing(parent.as_ref(), node_id, now.secs) {
        return refuse(control, node_id, refusal, Some(parent_id));
    }
    let Some(parent) = parent else {
        return refuse(control, node_id, Refusal::UnknownParent, Some(parent_id));
    };
    let subjects = Subjects {
        user_id: &parent.user_id,
        serial: Some(parent.serial),
        node_id: Some(node_id),
    };
    match revoked(control, subjects).await {
        Ok(false) => {}
        Ok(true) => return refuse(control, node_id, Refusal::Revoked, Some(parent_id)),
        Err(_) => return server_error(),
    }
    let Some(id) = child_id() else {
        tracing::error!(target: "jaunt::control", "the operating system gave no randomness for a child session id");
        return server_error();
    };
    let target = target_of(request);
    let opened = control
        .store
        .service_sessions()
        .open_child(&OpenChildSession {
            id: &id,
            parent_id,
            node_id,
            target: &target,
            tty: request.tty,
            max_per_parent: MAX_CHILDREN_PER_PARENT,
            max_per_node: MAX_CHILDREN_PER_NODE,
            now: now.secs,
        })
        .await;
    let child = match opened {
        Ok(ChildOpened::Opened(child)) => *child,
        Ok(ChildOpened::ParentNotLive) => {
            return refuse(control, node_id, Refusal::ParentEnded, Some(parent_id));
        }
        Ok(ChildOpened::TooManyForParent) => {
            return refuse(control, node_id, Refusal::ParentCap, Some(parent_id));
        }
        Ok(ChildOpened::TooManyForNode) => {
            return refuse(control, node_id, Refusal::NodeCap, Some(parent_id));
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "opening a child session failed");
            return server_error();
        }
    };
    audit::created(&child, request);
    json_response(
        StatusCode::OK,
        &ChildSessionGrant {
            session_id: child.id,
            record: child.record == Some(true),
            record_input: child.record_input == Some(true),
        },
    )
}

#[cfg(test)]
mod tests {
    use jaunt_proto::{
        ChildSessionKind, ChildSessionRefusal, ChildSessionRequest, is_kube_child_session_id,
    };
    use jaunt_store::{Session, SessionKind, SessionOrigin, SessionState};

    use super::{Refusal, child_id, standing, target_of};

    const NOW: i64 = 1_800_000_000;

    fn parent() -> Session {
        Session {
            id: "k-0123456789abcdef0123456789abcdef".to_owned(),
            user_id: "u".to_owned(),
            serial: 1,
            node_id: "n".to_owned(),
            state: SessionState::Active,
            created_at: NOW - 10,
            expires_at: NOW - 10,
            authorized_at: Some(NOW - 10),
            ended_at: None,
            login: None,
            exit_status: None,
            bytes_in: None,
            bytes_out: None,
            recording_incomplete: None,
            end_reason: None,
            max_duration_secs: Some(3600),
            origin: SessionOrigin::Ssh,
            record_input: Some(false),
            kind: SessionKind::Kube,
            service_id: Some("svc".to_owned()),
            target: None,
            roles: Vec::new(),
            grant_ids: Vec::new(),
            db_client_serial: None,
            outcome: None,
            decision_hash: Some("ab".repeat(32)),
            service_name: Some("prod".to_owned()),
            audit_incomplete: false,
            parent_session_id: None,
            record: Some(true),
        }
    }

    #[test]
    fn only_a_live_authorized_kube_connection_of_this_node_can_have_children() {
        let cases = [
            (None, "n", Err(Refusal::UnknownParent)),
            (Some(parent()), "other", Err(Refusal::ForeignParent)),
            (
                Some(Session {
                    kind: SessionKind::Ssh,
                    ..parent()
                }),
                "other",
                Err(Refusal::ForeignParent),
            ),
            (
                Some(Session {
                    kind: SessionKind::Ssh,
                    ..parent()
                }),
                "n",
                Err(Refusal::NotKube),
            ),
            (
                Some(Session {
                    kind: SessionKind::Db,
                    ..parent()
                }),
                "n",
                Err(Refusal::NotKube),
            ),
            (
                Some(Session {
                    kind: SessionKind::Tcp,
                    ..parent()
                }),
                "n",
                Err(Refusal::NotKube),
            ),
            (
                Some(Session {
                    parent_session_id: Some("k-1".to_owned()),
                    ..parent()
                }),
                "n",
                Err(Refusal::NestedParent),
            ),
            (
                Some(Session {
                    authorized_at: None,
                    state: SessionState::Routed,
                    ..parent()
                }),
                "n",
                Err(Refusal::NotAuthorized),
            ),
            (
                Some(Session {
                    state: SessionState::Ended,
                    ..parent()
                }),
                "n",
                Err(Refusal::ParentEnded),
            ),
            (
                Some(Session {
                    authorized_at: Some(NOW - 3600),
                    ..parent()
                }),
                "n",
                Err(Refusal::ParentExpired),
            ),
            (
                Some(Session {
                    authorized_at: Some(NOW - 3599),
                    ..parent()
                }),
                "n",
                Ok(()),
            ),
            (Some(parent()), "n", Ok(())),
        ];
        for (stored, node, expected) in cases {
            assert_eq!(
                standing(stored.as_ref(), node, NOW),
                expected,
                "{stored:?} {node}"
            );
        }
    }

    #[test]
    fn precise_reasons_stay_in_the_audit_and_the_agent_sees_only_the_generic_code() {
        let outward: Vec<(&str, ChildSessionRefusal)> = [
            Refusal::Malformed,
            Refusal::TooLarge,
            Refusal::InvalidParent,
            Refusal::InvalidName,
            Refusal::RateLimited,
            Refusal::UnknownParent,
            Refusal::ForeignParent,
            Refusal::NotAuthorized,
            Refusal::NotKube,
            Refusal::NestedParent,
            Refusal::ParentEnded,
            Refusal::ParentExpired,
            Refusal::Revoked,
            Refusal::ParentCap,
            Refusal::NodeCap,
        ]
        .into_iter()
        .map(|refusal| (refusal.reason(), refusal.outward()))
        .collect();
        use ChildSessionRefusal as Code;
        assert_eq!(
            outward,
            [
                ("malformed", Code::Invalid),
                ("too_large", Code::Invalid),
                ("invalid_parent", Code::Invalid),
                ("invalid_name", Code::Invalid),
                ("rate_limited", Code::RateLimited),
                ("unknown_parent", Code::UnknownParent),
                ("foreign_parent", Code::UnknownParent),
                ("not_authorized", Code::UnknownParent),
                ("not_kube", Code::NotKube),
                ("nested_parent", Code::NotKube),
                ("parent_ended", Code::ParentEnded),
                ("parent_expired", Code::ParentEnded),
                ("revoked", Code::ParentEnded),
                ("parent_cap", Code::TooManyChildren),
                ("node_cap", Code::TooManyChildren),
            ]
        );
    }

    fn request(namespace: &str, pod: &str, container: &str) -> ChildSessionRequest {
        ChildSessionRequest {
            parent_session_id: "k-0123456789abcdef0123456789abcdef".to_owned(),
            namespace: namespace.to_owned(),
            pod: pod.to_owned(),
            container: container.to_owned(),
            tty: true,
            kind: ChildSessionKind::Exec,
        }
    }

    #[test]
    fn the_target_names_namespace_pod_and_container_and_fits_the_column() {
        assert_eq!(
            target_of(&request("default", "web-0", "app")),
            "default/web-0/app"
        );
        assert_eq!(target_of(&request("default", "web-0", "")), "default/web-0");
        let longest = request(&"n".repeat(63), &"p".repeat(253), &"c".repeat(63));
        let target = target_of(&longest);
        assert_eq!(target.len(), jaunt_store::MAX_SESSION_TARGET_LEN);
        assert!(target.starts_with(&format!("{}/{}", "n".repeat(63), "p".repeat(253))));
    }

    #[test]
    fn child_ids_are_made_by_control_from_fresh_randomness() {
        let first = child_id().unwrap();
        let second = child_id().unwrap();
        assert!(is_kube_child_session_id(&first), "{first}");
        assert!(is_kube_child_session_id(&second), "{second}");
        assert_ne!(first, second);
    }
}
