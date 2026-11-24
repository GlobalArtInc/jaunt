use jaunt_policy::SshDecision;
use jaunt_proto::{
    AuthorizeDecision, AuthorizeRequest, ControlError as PlaneError, DenyReason, NodeCaller,
    SessionPermissions,
};
use jaunt_store::{ActivateSession, SessionState};

use crate::control::Control;
use crate::holder::{self, Presented};
use crate::identity::policy_identity;
use crate::plane::{check_fields, clock_failure, node_info, store_failure};
use crate::session_audit::{self, Denied, Phase, Started};

pub(crate) const DEFAULT_MAX_SESSION_SECS: u64 = 12 * 60 * 60;

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
    };
    let holder = match holder::verify(control, &presented, now.secs).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(deny(reason)),
    };
    let decision = policy.authorize_ssh(
        &policy_identity(&holder.user),
        &node_info(&node),
        &request.login,
    );
    if !decision.allowed {
        return Ok(deny(DenyReason::PolicyDenied));
    }
    let permissions = permissions_of(&decision);

    let activated = sessions
        .activate(ActivateSession {
            id: &binding.id,
            node_id: &node_id,
            user_id: &holder.user.id,
            serial: holder.serial,
            login: &request.login,
            now: now.secs,
        })
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
