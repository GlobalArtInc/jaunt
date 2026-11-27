use jaunt_policy::SshDecision;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError as PlaneError, DenyReason, NodeCaller,
    SessionPermissions,
};
use jaunt_store::{ActivateSession, SessionOrigin, SessionState, Subjects};

use crate::control::Control;
use crate::holder::{self, Absent, Presented};
use crate::identity::policy_identity;
use crate::plane::{check_fields, clock_failure, node_info, store_failure};
use crate::revocation::revoked;
use crate::session_audit::{self, Denied, Phase, Started};

pub(crate) const DEFAULT_MAX_SESSION_SECS: u64 = 12 * 60 * 60;
pub(crate) const MAX_RECORDED_DURATION_SECS: u64 = 366 * 24 * 60 * 60;

pub(crate) fn recorded_duration(max_duration_secs: u64) -> i64 {
    i64::try_from(max_duration_secs.min(MAX_RECORDED_DURATION_SECS)).unwrap_or(0)
}

pub(crate) async fn authorize(
    control: &Control,
    caller: NodeCaller,
    request: AuthorizeRequest,
) -> Result<AuthorizeDecision, PlaneError> {
    let NodeCaller(node_id) = caller;
    check_fields(&[
        &node_id,
        &request.session_id,
        &request.user_id,
        &request.key_id,
        &request.login,
        &request.client_addr,
        request.subject_fingerprint.as_deref().unwrap_or_default(),
    ])?;
    let now = control.now().ok_or_else(clock_failure)?;
    let policy = control.policy_snapshot();
    let deny = |reason| denied(&request, &node_id, policy.hash(), reason);

    let Some(node) = control
        .store
        .nodes()
        .get_active(&node_id)
        .await
        .map_err(store_failure("loading the node"))?
    else {
        return Ok(deny(DenyReason::NodeInactive));
    };
    let sessions = control.store.sessions();
    let binding = match sessions
        .get(&request.session_id)
        .await
        .map_err(store_failure("loading the session"))?
    {
        None => return Ok(deny(DenyReason::SessionUnknown)),
        Some(binding) if binding.node_id != node_id => return Ok(deny(DenyReason::WrongNode)),
        Some(binding) => binding,
    };
    if binding.state != SessionState::Routed {
        return Ok(deny(DenyReason::SessionUsed));
    }
    if binding.expires_at <= now.secs {
        return Ok(deny(DenyReason::SessionExpired));
    }
    if binding.user_id != request.user_id {
        return Ok(deny(DenyReason::UserMismatch));
    }
    if i64::try_from(request.serial).ok() != Some(binding.serial) {
        return Ok(deny(DenyReason::SerialMismatch));
    }

    let presented = Presented {
        user_id: &request.user_id,
        serial: request.serial,
        key_id: &request.key_id,
        subject_fingerprint: request.subject_fingerprint.as_deref(),
        absent: Absent::Accepted,
    };
    let holder = match holder::verify(control, &presented, now.secs).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(deny(reason)),
    };
    let subjects = Subjects {
        user_id: &holder.user.id,
        serial: Some(holder.serial),
        node_id: Some(&node_id),
    };
    if revoked(control, subjects).await? {
        return Ok(deny(DenyReason::Revoked));
    }
    let decision = policy.authorize_ssh(
        &policy_identity(&holder.user),
        &node_info(&node),
        &request.login,
    );
    if !decision.allowed {
        return Ok(deny(DenyReason::PolicyDenied));
    }
    let permissions = permissions_of(&decision);
    let origin = origin_of(control, &holder.user.id, request.serial);

    let activated = sessions
        .activate_as(
            ActivateSession {
                id: &binding.id,
                node_id: &node_id,
                user_id: &holder.user.id,
                serial: holder.serial,
                login: &request.login,
                max_duration_secs: recorded_duration(permissions.max_duration_secs),
                pty: permissions.pty,
                record_input: permissions.record_input,
                now: now.secs,
            },
            origin,
        )
        .await
        .map_err(store_failure("activating the session"))?;
    if activated.is_none() {
        return Ok(deny(DenyReason::SessionUsed));
    }
    session_audit::started(&Started {
        session_id: &binding.id,
        user_id: &holder.user.id,
        serial: holder.serial,
        node_id: &node_id,
        login: &request.login,
        permissions,
        roles: &decision.roles,
        client_addr: &request.client_addr,
        policy_hash: policy.hash(),
    });
    Ok(AuthorizeDecision::Allow { permissions })
}

fn origin_of(control: &Control, user_id: &str, serial: u64) -> SessionOrigin {
    if control
        .web
        .terminals
        .live
        .holds_certificate(user_id, serial)
    {
        SessionOrigin::Web
    } else {
        SessionOrigin::Ssh
    }
}

fn permissions_of(decision: &SshDecision) -> SessionPermissions {
    SessionPermissions {
        pty: true,
        port_forwarding: decision.port_forwarding,
        record_input: decision.record_input,
        max_duration_secs: DEFAULT_MAX_SESSION_SECS,
    }
}

fn denied(
    request: &AuthorizeRequest,
    node_id: &str,
    policy_hash: &str,
    reason: DenyReason,
) -> AuthorizeDecision {
    session_audit::denied(&Denied {
        phase: Phase::Authorize,
        reason,
        policy_hash,
        user_id: &request.user_id,
        serial: request.serial,
        node_id: Some(node_id),
        node_name: None,
        session_id: Some(&request.session_id),
        login: Some(&request.login),
        client_addr: &request.client_addr,
    });
    AuthorizeDecision::Deny { reason }
}

#[cfg(test)]
mod tests {
    use super::{MAX_RECORDED_DURATION_SECS, recorded_duration};

    #[test]
    fn the_recorded_duration_is_clamped_so_the_deadline_sum_cannot_overflow() {
        let ceiling = i64::try_from(MAX_RECORDED_DURATION_SECS).unwrap();
        assert_eq!(recorded_duration(43_200), 43_200);
        assert_eq!(recorded_duration(u64::MAX), ceiling);
        assert_eq!(recorded_duration(MAX_RECORDED_DURATION_SECS + 1), ceiling);
        assert!(i64::from(u32::MAX).checked_add(ceiling + 300).is_some());
    }
}
