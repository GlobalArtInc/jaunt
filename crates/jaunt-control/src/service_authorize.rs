use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use jaunt_limits::{DEFAULT_CAPACITY, Decision, Rate, RateLimiter};
use jaunt_policy::PolicySet;
use jaunt_proto::{
    ControlError as PlaneError, DbAccess, DbAccessRequest, DenyReason, KubeAccess, NodeCaller,
    ServiceAccess, ServiceAuthorizeDecision, ServiceAuthorizeRequest, ServiceGrant,
    ServiceKind as WireKind, is_kube_session_id,
};
use jaunt_store::{
    ActivateService, KubeOpened, MAX_SESSION_LIST_BYTES, MAX_SESSION_ROLES, OpenKubeSession,
    Service, Session, SessionKind, SessionState, Subjects,
};

use crate::access_review::kube_decision_hash;
use crate::authorize::{DEFAULT_MAX_SESSION_SECS, recorded_duration};
use crate::clock::Moment;
use crate::control::Control;
use crate::db_client;
use crate::identity::policy_identity;
use crate::plane::{check_fields, clock_failure, store_failure};
use crate::revocation::revoked;
use crate::service_identity::{self, ServiceHolder};
use crate::service_route::{
    abandon_unreachable, db_refusal, kube_refusal, resource_of, session_kind, tcp_refusal,
    valid_service_name,
};
use crate::service_session_audit::{
    self, DbClientIssued, ServiceDenied, ServicePhase, ServiceStarted,
};
use crate::services::store_kind;

const ROLE_LIST_OVERHEAD: usize = 2;
pub(crate) const AUTHORIZATIONS_PER_NODE_AND_USER: Rate = Rate::clamped(30, 300);
pub(crate) const AUTHORIZATIONS_PER_NODE: Rate = Rate::clamped(1000, 3000);
pub(crate) const MAX_KUBE_SESSIONS_PER_USER_AND_CLUSTER: i64 = 64;
pub(crate) const MAX_KUBE_SESSIONS_PER_CLUSTER: i64 = 512;
const NODES_TRACKED: usize = 10_000;

pub(crate) fn user_authorization_limiter() -> RateLimiter<(String, String)> {
    RateLimiter::new(AUTHORIZATIONS_PER_NODE_AND_USER, DEFAULT_CAPACITY)
}

pub(crate) fn authorization_limiter() -> RateLimiter<String> {
    RateLimiter::new(AUTHORIZATIONS_PER_NODE, NODES_TRACKED)
}

pub(crate) async fn authorize_service(
    control: &Control,
    caller: NodeCaller,
    request: ServiceAuthorizeRequest,
) -> Result<ServiceAuthorizeDecision, PlaneError> {
    let control = control.clone();
    match tokio::spawn(async move { decide(&control, caller, request).await }).await {
        Ok(decision) => decision,
        Err(err) if err.is_cancelled() => {
            tracing::warn!(target: "jaunt::control", "authorizing a service session was cancelled by the runtime shutting down");
            Err(PlaneError::Store)
        }
        Err(_) => {
            tracing::error!(target: "jaunt::control", "authorizing a service session panicked");
            Err(PlaneError::Store)
        }
    }
}

struct Asked<'a> {
    request: &'a ServiceAuthorizeRequest,
    node_id: &'a str,
    kind: SessionKind,
    policy_hash: &'a str,
}

impl Asked<'_> {
    fn deny(&self, reason: DenyReason) -> ServiceAuthorizeDecision {
        self.deny_for(reason, &self.request.identity.user_id)
    }

    fn deny_for(&self, reason: DenyReason, user_id: &str) -> ServiceAuthorizeDecision {
        let db = self.request.db.as_ref();
        service_session_audit::denied(&ServiceDenied {
            phase: ServicePhase::Authorize,
            kind: self.kind,
            service: &self.request.service,
            reason,
            policy_hash: self.policy_hash,
            user_id,
            serial: self.request.identity.serial,
            node_id: Some(self.node_id),
            session_id: Some(&self.request.session_id),
            login: db.map(|db| db.user.as_str()),
            db_name: db.map(|db| db.name.as_str()),
            client_addr: &self.request.client_addr,
        });
        ServiceAuthorizeDecision::Deny { reason }
    }
}

fn check_request(node_id: &str, request: &ServiceAuthorizeRequest) -> Result<(), PlaneError> {
    check_fields(&[
        node_id,
        &request.session_id,
        &request.service,
        &request.identity.user_id,
        &request.identity.subject_fingerprint,
        &request.identity.issuer_fingerprint,
        &request.client_addr,
    ])?;
    if let Some(db) = &request.db {
        check_fields(&[&db.user, &db.name, &db.agent_key])?;
    }
    match (request.kind, request.db.is_some()) {
        (WireKind::Postgres, true) | (WireKind::Kubernetes | WireKind::Tcp, false) => {}
        _ => return Err(PlaneError::InvalidRequest),
    }
    valid_service_name(&request.service)
}

async fn decide(
    control: &Control,
    caller: NodeCaller,
    request: ServiceAuthorizeRequest,
) -> Result<ServiceAuthorizeDecision, PlaneError> {
    let NodeCaller(node_id) = caller;
    check_request(&node_id, &request)?;
    let now = control.now().ok_or_else(clock_failure)?;
    let policy = control.policy_snapshot();
    let asked = Asked {
        request: &request,
        node_id: &node_id,
        kind: session_kind(request.kind),
        policy_hash: policy.hash(),
    };
    let tick = control.tick();
    let caller_and_user = (node_id.clone(), request.identity.user_id.clone());
    if let Decision::Limited { .. } = control
        .service_user_authorizations
        .check(&caller_and_user, tick)
    {
        return Ok(asked.deny(DenyReason::RateLimited));
    }
    if let Decision::Limited { .. } = control.service_authorizations.check(&node_id, tick) {
        return Ok(asked.deny(DenyReason::RateLimited));
    }

    if control
        .store
        .nodes()
        .get_active(&node_id)
        .await
        .map_err(store_failure("loading the node"))?
        .is_none()
    {
        return Ok(asked.deny(DenyReason::NodeInactive));
    }
    let Some(service) = control
        .store
        .services()
        .serving_on(&node_id, store_kind(request.kind), &request.service)
        .await
        .map_err(store_failure("loading the service"))?
    else {
        return Ok(asked.deny(DenyReason::ServiceUnknown));
    };
    match request.kind {
        WireKind::Kubernetes => kube(control, &asked, &policy, &service, now).await,
        WireKind::Postgres | WireKind::Tcp => routed(control, &asked, &policy, &service, now).await,
    }
}

async fn holder_of(
    control: &Control,
    asked: &Asked<'_>,
    now: Moment,
) -> Result<Result<ServiceHolder, DenyReason>, PlaneError> {
    let holder = match service_identity::verify(control, &asked.request.identity, now.secs).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(Err(reason)),
    };
    let subjects = Subjects {
        user_id: &holder.user.id,
        serial: Some(holder.serial),
        node_id: Some(asked.node_id),
    };
    if revoked(control, subjects).await? {
        return Ok(Err(DenyReason::Revoked));
    }
    Ok(Ok(holder))
}

fn binding_refusal(
    binding: &Session,
    asked: &Asked<'_>,
    service: &Service,
    now: i64,
) -> Option<DenyReason> {
    let identity = &asked.request.identity;
    if binding.node_id != asked.node_id {
        return Some(DenyReason::WrongNode);
    }
    if binding.kind != asked.kind {
        return Some(DenyReason::KindMismatch);
    }
    if binding.service_id.as_deref() != Some(service.id.as_str()) {
        return Some(DenyReason::ServiceMismatch);
    }
    if binding.state != SessionState::Routed {
        return Some(DenyReason::SessionUsed);
    }
    if binding.expires_at <= now {
        return Some(DenyReason::SessionExpired);
    }
    if binding.user_id != identity.user_id {
        return Some(DenyReason::UserMismatch);
    }
    if i64::try_from(identity.serial).ok() != Some(binding.serial) {
        return Some(DenyReason::SerialMismatch);
    }
    None
}

async fn routed(
    control: &Control,
    asked: &Asked<'_>,
    policy: &PolicySet,
    service: &Service,
    now: Moment,
) -> Result<ServiceAuthorizeDecision, PlaneError> {
    let request = asked.request;
    let Some(binding) = control
        .store
        .sessions()
        .get(&request.session_id)
        .await
        .map_err(store_failure("loading the session"))?
    else {
        return Ok(asked.deny(DenyReason::SessionUnknown));
    };
    let owner = binding.user_id.as_str();
    if let Some(reason) = binding_refusal(&binding, asked, service, now.secs) {
        return Ok(asked.deny_for(reason, owner));
    }
    let holder = match holder_of(control, asked, now).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(asked.deny_for(reason, owner)),
    };
    let identity = policy_identity(&holder.user);
    let resource = resource_of(service);
    let max_duration_secs = DEFAULT_MAX_SESSION_SECS;
    let (roles, access, certificate) =
        match (asked.kind, &request.db) {
            (SessionKind::Tcp, None) => {
                let decision = policy.authorize_tcp(&identity, &resource);
                if !decision.allowed {
                    return Ok(asked.deny_for(tcp_refusal(&decision), owner));
                }
                (bounded_roles(&decision.roles), ServiceAccess::Tcp, None)
            }
            (SessionKind::Db, Some(db)) => {
                let decision = policy.authorize_db(&identity, &resource, &db.user, &db.name);
                if !decision.allowed {
                    return Ok(asked.deny_for(db_refusal(&decision), owner));
                }
                let issued =
                    match db_client::issue(control, &holder.user.id, &db.user, &db.agent_key, now)
                        .await
                    {
                        Ok(issued) => issued,
                        Err(reason) => return Ok(asked.deny_for(reason, owner)),
                    };
                let access = db_access(db, &issued);
                (bounded_roles(&decision.roles), access, Some(issued))
            }
            _ => return Err(PlaneError::InvalidRequest),
        };
    let activated = control
        .store
        .service_sessions()
        .activate(&ActivateService {
            id: &binding.id,
            node_id: asked.node_id,
            user_id: &holder.user.id,
            serial: holder.serial,
            kind: asked.kind,
            service_id: &service.id,
            login: request.db.as_ref().map(|db| db.user.as_str()),
            target: request.db.as_ref().map(|db| db.name.as_str()),
            roles: &roles,
            max_duration_secs: recorded_duration(max_duration_secs),
            db_client_serial: certificate.as_ref().map(|issued| issued.serial),
            now: now.secs,
        })
        .await
        .map_err(store_failure("activating the service session"))?;
    let Some(session) = activated else {
        return Ok(asked.deny_for(DenyReason::SessionUsed, owner));
    };
    if let (Some(issued), Some(db)) = (&certificate, &request.db) {
        service_session_audit::db_client_issued(&DbClientIssued {
            session: &session,
            serial: issued.serial,
            db_user: &db.user,
            valid_before: issued.valid_before,
        });
    }
    service_session_audit::started(&ServiceStarted {
        session: &session,
        service: &service.name,
        users: &[],
        groups: &[],
        record_exec: None,
        record_input: None,
        client_addr: &request.client_addr,
        policy_hash: policy.hash(),
    });
    Ok(ServiceAuthorizeDecision::Allow(Box::new(ServiceGrant {
        access,
        max_duration_secs,
        roles,
        policy_hash: policy.hash().to_owned(),
    })))
}

fn db_access(db: &DbAccessRequest, issued: &db_client::DbClientCertificate) -> ServiceAccess {
    ServiceAccess::Db(DbAccess {
        user: db.user.clone(),
        name: db.name.clone(),
        certificate_der: STANDARD.encode(&issued.certificate_der),
        serial: issued.serial,
        valid_after: issued.valid_after,
        valid_before: issued.valid_before,
    })
}

async fn kube(
    control: &Control,
    asked: &Asked<'_>,
    policy: &PolicySet,
    service: &Service,
    now: Moment,
) -> Result<ServiceAuthorizeDecision, PlaneError> {
    let request = asked.request;
    if !is_kube_session_id(&request.session_id) {
        return Ok(asked.deny(DenyReason::SessionUnknown));
    }
    let holder = match holder_of(control, asked, now).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(asked.deny(reason)),
    };
    let owner = holder.user.id.as_str();
    let decision = policy.authorize_kube(&policy_identity(&holder.user), &resource_of(service));
    if !decision.allowed {
        return Ok(asked.deny_for(kube_refusal(&decision), owner));
    }
    let roles = bounded_roles(&decision.roles);
    let max_duration_secs = DEFAULT_MAX_SESSION_SECS;
    let decision_hash = kube_decision_hash(&decision);
    let opening = OpenKubeSession {
        id: &request.session_id,
        user_id: owner,
        serial: holder.serial,
        node_id: asked.node_id,
        service_id: &service.id,
        service_name: &service.name,
        roles: &roles,
        max_duration_secs: recorded_duration(max_duration_secs),
        decision_hash: &decision_hash,
        max_per_user: MAX_KUBE_SESSIONS_PER_USER_AND_CLUSTER,
        max_per_service: MAX_KUBE_SESSIONS_PER_CLUSTER,
        now: now.secs,
    };
    let sessions = control.store.service_sessions();
    let mut opened = sessions
        .open_kube(&opening)
        .await
        .map_err(store_failure("opening the kube session"))?;
    if opened == KubeOpened::TooMany
        && abandon_unreachable(control, owner, SessionKind::Kube, &service.name, now.secs).await?
    {
        opened = sessions
            .open_kube(&opening)
            .await
            .map_err(store_failure("opening the kube session"))?;
    }
    let session = match opened {
        KubeOpened::Opened(session) => session,
        KubeOpened::Repeated => return Ok(asked.deny_for(DenyReason::SessionUsed, owner)),
        KubeOpened::NodeInactive => return Ok(asked.deny_for(DenyReason::NodeInactive, owner)),
        KubeOpened::ServiceGone => return Ok(asked.deny_for(DenyReason::ServiceUnknown, owner)),
        KubeOpened::TooMany => return Ok(asked.deny_for(DenyReason::TooManySessions, owner)),
    };
    service_session_audit::started(&ServiceStarted {
        session: &session,
        service: &service.name,
        users: &decision.users,
        groups: &decision.groups,
        record_exec: Some(decision.record_exec),
        record_input: Some(decision.record_input),
        client_addr: &request.client_addr,
        policy_hash: policy.hash(),
    });
    Ok(ServiceAuthorizeDecision::Allow(Box::new(ServiceGrant {
        access: ServiceAccess::Kube(KubeAccess {
            users: decision.users,
            groups: decision.groups,
            record_exec: decision.record_exec,
            record_input: decision.record_input,
        }),
        max_duration_secs,
        roles,
        policy_hash: policy.hash().to_owned(),
    })))
}

pub(crate) fn bounded_roles(roles: &[String]) -> Vec<String> {
    let mut kept = Vec::new();
    let mut bytes = ROLE_LIST_OVERHEAD;
    for role in roles {
        let Ok(quoted) = serde_json::to_string(role) else {
            break;
        };
        let needed = quoted.len() + usize::from(!kept.is_empty());
        if kept.len() == MAX_SESSION_ROLES || bytes.saturating_add(needed) > MAX_SESSION_LIST_BYTES
        {
            break;
        }
        bytes += needed;
        kept.push(role.clone());
    }
    kept
}

#[cfg(test)]
mod tests {
    use jaunt_store::{MAX_SESSION_LIST_BYTES, MAX_SESSION_ROLES};

    use super::bounded_roles;

    #[test]
    fn the_recorded_roles_fit_the_column_whatever_the_policy_names() {
        let few: Vec<String> = ["a", "b"].iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(bounded_roles(&few), few);
        let many: Vec<String> = (0..100).map(|index| format!("role-{index}")).collect();
        assert_eq!(bounded_roles(&many).len(), MAX_SESSION_ROLES);
        let quoted = vec!["\"\\".repeat(700); 4];
        let kept = bounded_roles(&quoted);
        assert!(serde_json::to_string(&kept).unwrap().len() <= MAX_SESSION_LIST_BYTES);
        assert_eq!(kept.len(), 1);
        let huge = vec!["r".repeat(MAX_SESSION_LIST_BYTES)];
        assert!(bounded_roles(&huge).is_empty());
    }
}
