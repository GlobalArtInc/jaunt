use jaunt_policy::{DbDecision, Identity, KubeDecision, PolicySet, ResourceInfo, TcpDecision};
use jaunt_proto::{
    ControlError as PlaneError, DenyReason, LocateServiceRequest, RouteDecision,
    ServiceKind as WireKind, ServiceLocation, ServiceRouteRequest,
};
use jaunt_store::{
    NewServiceRoute, Service, ServiceKind, ServiceRouted, SessionEndReason, SessionKind, Subjects,
};
use jaunt_tunnel::ServiceName;

use crate::control::Control;
use crate::identity::policy_identity;
use crate::killer::{KillReason, KillScope};
use crate::plane::{check_fields, clock_failure, store_failure};
use crate::revocation::revoked;
use crate::service_identity;
use crate::service_session_audit::{self, ServiceDenied, ServicePhase};
use crate::services::store_kind;
use crate::session_audit;

pub(crate) const SERVICE_ROUTE_WINDOW_SECS: i64 = 30;
pub(crate) const MAX_DB_SESSIONS_PER_USER_AND_SERVER: i64 = 16;
pub(crate) const MAX_TCP_SESSIONS_PER_USER_AND_SERVICE: i64 = 16;

pub(crate) const fn session_kind(kind: WireKind) -> SessionKind {
    match kind {
        WireKind::Kubernetes => SessionKind::Kube,
        WireKind::Postgres => SessionKind::Db,
        WireKind::Tcp => SessionKind::Tcp,
    }
}

pub(crate) fn valid_service_name(name: &str) -> Result<(), PlaneError> {
    ServiceName::new(name)
        .map(|_| ())
        .map_err(|_| PlaneError::InvalidRequest)
}

pub(crate) fn resource_of(service: &Service) -> ResourceInfo {
    ResourceInfo {
        name: service.name.clone(),
        labels: service.labels.clone(),
    }
}

pub(crate) async fn locate(
    control: &Control,
    request: LocateServiceRequest,
) -> Result<Option<ServiceLocation>, PlaneError> {
    valid_service_name(&request.name)?;
    let candidates = control
        .store
        .services()
        .serving(store_kind(request.kind), &request.name)
        .await
        .map_err(store_failure("locating the service"))?;
    Ok(candidates
        .into_iter()
        .find(|service| control.presence.connected_since(&service.node_id).is_some())
        .map(|service| ServiceLocation {
            node_id: service.node_id,
            kind: request.kind,
        }))
}

pub(crate) fn tcp_refusal(decision: &TcpDecision) -> DenyReason {
    if decision.denied_by.is_empty() {
        DenyReason::NoMatchingRole
    } else {
        DenyReason::DeniedByRule
    }
}

pub(crate) fn db_refusal(decision: &DbDecision) -> DenyReason {
    if !decision.denied_by.is_empty() {
        DenyReason::DeniedByRule
    } else if decision.trait_not_valid {
        DenyReason::TraitNotValid
    } else {
        DenyReason::NoMatchingRole
    }
}

pub(crate) fn kube_refusal(decision: &KubeDecision) -> DenyReason {
    if !decision.denied_by.is_empty() || !decision.subtracted_by.is_empty() {
        DenyReason::DeniedByRule
    } else if decision.trait_not_valid {
        DenyReason::TraitNotValid
    } else {
        DenyReason::NoMatchingRole
    }
}

fn route_refusal(policy: &PolicySet, identity: &Identity, service: &Service) -> Option<DenyReason> {
    let resource = resource_of(service);
    match service.kind {
        ServiceKind::Postgres => (!policy.reaches_database_server(identity, &resource))
            .then_some(DenyReason::PolicyDenied),
        ServiceKind::Tcp => {
            let decision = policy.authorize_tcp(identity, &resource);
            (!decision.allowed).then(|| tcp_refusal(&decision))
        }
        ServiceKind::Kubernetes => Some(DenyReason::PolicyDenied),
    }
}

pub(crate) async fn abandon_unreachable(
    control: &Control,
    user_id: &str,
    kind: SessionKind,
    service_name: &str,
    now: i64,
) -> Result<bool, PlaneError> {
    if !control.presence.is_installed() {
        return Ok(false);
    }
    let sessions = control.store.service_sessions();
    let candidates = sessions
        .active_of_user(user_id, kind, service_name)
        .await
        .map_err(store_failure("listing the open sessions of a user"))?;
    let Some(stale) = candidates
        .into_iter()
        .find(|session| control.presence.connected_since(&session.node_id).is_none())
    else {
        return Ok(false);
    };
    let closed = sessions
        .close_active(&stale.id, stale.kind, SessionEndReason::AgentGone, now)
        .await
        .map_err(store_failure("closing an unreachable session"))?;
    if let Some(closed) = closed {
        session_audit::closed(&closed, SessionEndReason::AgentGone);
        sessions
            .mark_abandoned(&closed.id)
            .await
            .map_err(store_failure("marking an unreachable session abandoned"))?;
        control
            .killer
            .order(KillScope::Sessions, KillReason::AgentGone, &[closed])
            .await;
    }
    Ok(true)
}

const fn cap_of(kind: SessionKind) -> i64 {
    match kind {
        SessionKind::Db => MAX_DB_SESSIONS_PER_USER_AND_SERVER,
        SessionKind::Tcp => MAX_TCP_SESSIONS_PER_USER_AND_SERVICE,
        SessionKind::Kube | SessionKind::Ssh => 0,
    }
}

pub(crate) async fn route(
    control: &Control,
    request: ServiceRouteRequest,
) -> Result<RouteDecision, PlaneError> {
    check_fields(&[
        &request.identity.user_id,
        &request.identity.subject_fingerprint,
        &request.identity.issuer_fingerprint,
        &request.service,
        &request.client_addr,
    ])?;
    let kind = session_kind(request.kind);
    if !matches!(kind, SessionKind::Db | SessionKind::Tcp) {
        return Err(PlaneError::InvalidRequest);
    }
    valid_service_name(&request.service)?;
    let now = control.now().ok_or_else(clock_failure)?;
    let policy = control.policy_snapshot();
    let deny =
        |reason, node_id: Option<&str>| denied(&request, kind, policy.hash(), reason, node_id);

    let holder = match service_identity::verify(control, &request.identity, now.secs).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(deny(reason, None)),
    };
    let candidates = control
        .store
        .services()
        .serving(store_kind(request.kind), &request.service)
        .await
        .map_err(store_failure("loading the service"))?;
    let chosen = candidates
        .iter()
        .find(|service| control.presence.connected_since(&service.node_id).is_some())
        .or_else(|| candidates.first());
    let Some(service) = chosen else {
        return Ok(deny(DenyReason::ServiceUnknown, None));
    };
    let subjects = Subjects {
        user_id: &holder.user.id,
        serial: Some(holder.serial),
        node_id: Some(&service.node_id),
    };
    if revoked(control, subjects).await? {
        return Ok(deny(DenyReason::Revoked, Some(&service.node_id)));
    }
    if let Some(reason) = route_refusal(&policy, &policy_identity(&holder.user), service) {
        return Ok(deny(reason, Some(&service.node_id)));
    }
    let binding = NewServiceRoute {
        user_id: &holder.user.id,
        serial: holder.serial,
        node_id: &service.node_id,
        kind,
        service_id: &service.id,
        service_name: &service.name,
        ttl_secs: SERVICE_ROUTE_WINDOW_SECS,
        max_open: cap_of(kind),
        now: now.secs,
    };
    let sessions = control.store.service_sessions();
    let mut routed = sessions
        .route(&binding)
        .await
        .map_err(store_failure("binding the service session"))?;
    if routed == ServiceRouted::TooMany
        && abandon_unreachable(control, &holder.user.id, kind, &service.name, now.secs).await?
    {
        routed = sessions
            .route(&binding)
            .await
            .map_err(store_failure("binding the service session"))?;
    }
    let session = match routed {
        ServiceRouted::Routed(session) => session,
        ServiceRouted::TooMany => {
            return Ok(deny(DenyReason::TooManySessions, Some(&service.node_id)));
        }
    };
    service_session_audit::routed(&service_session_audit::ServiceRouted {
        session: &session,
        service: &service.name,
        client_addr: &request.client_addr,
        policy_hash: policy.hash(),
    });
    Ok(RouteDecision::Allow {
        session_id: session.id.clone(),
        node_id: session.node_id.clone(),
    })
}

fn denied(
    request: &ServiceRouteRequest,
    kind: SessionKind,
    policy_hash: &str,
    reason: DenyReason,
    node_id: Option<&str>,
) -> RouteDecision {
    service_session_audit::denied(&ServiceDenied {
        phase: ServicePhase::Route,
        kind,
        service: &request.service,
        reason,
        policy_hash,
        user_id: &request.identity.user_id,
        serial: request.identity.serial,
        node_id,
        session_id: None,
        login: None,
        db_name: None,
        client_addr: &request.client_addr,
    });
    RouteDecision::Deny { reason }
}
