use jaunt_proto::{ControlError as PlaneError, DenyReason, RouteDecision, RouteRequest};
use jaunt_store::{NewSession, Subjects};

use crate::control::Control;
use crate::holder::{self, Absent, Presented};
use crate::identity::policy_identity;
use crate::nodes::is_ssh_target;
use crate::plane::{check_fields, clock_failure, node_info, store_failure};
use crate::revocation::revoked;
use crate::session_audit::{self, Denied, Phase, Routed};

pub(crate) const ROUTED_SESSION_TTL_SECS: i64 = 60;

pub(crate) async fn route(
    control: &Control,
    request: RouteRequest,
) -> Result<RouteDecision, PlaneError> {
    check_fields(&[
        &request.user_id,
        &request.key_id,
        &request.node_name,
        &request.client_addr,
        request.subject_fingerprint.as_deref().unwrap_or_default(),
    ])?;
    let now = control.now().ok_or_else(clock_failure)?;
    let policy = control.policy_snapshot();
    let presented = Presented {
        user_id: &request.user_id,
        serial: request.serial,
        key_id: &request.key_id,
        subject_fingerprint: request.subject_fingerprint.as_deref(),
        absent: Absent::Refused,
    };
    let holder = match holder::verify(control, &presented, now.secs).await? {
        Ok(holder) => holder,
        Err(reason) => return Ok(denied(&request, policy.hash(), reason, None)),
    };
    let Some(node) = control
        .store
        .nodes()
        .get_active_by_name(&request.node_name)
        .await
        .map_err(store_failure("loading the node"))?
        .filter(is_ssh_target)
    else {
        return Ok(denied(
            &request,
            policy.hash(),
            DenyReason::NodeUnknown,
            None,
        ));
    };
    let subjects = Subjects {
        user_id: &holder.user.id,
        serial: Some(holder.serial),
        node_id: Some(&node.id),
    };
    if revoked(control, subjects).await? {
        return Ok(denied(
            &request,
            policy.hash(),
            DenyReason::Revoked,
            Some(&node.id),
        ));
    }
    if !policy.route(&policy_identity(&holder.user), &node_info(&node)) {
        return Ok(denied(
            &request,
            policy.hash(),
            DenyReason::PolicyDenied,
            Some(&node.id),
        ));
    }
    let session = control
        .store
        .sessions()
        .create(
            &NewSession {
                user_id: holder.user.id.clone(),
                serial: holder.serial,
                node_id: node.id.clone(),
                ttl_secs: ROUTED_SESSION_TTL_SECS,
            },
            now.secs,
        )
        .await
        .map_err(store_failure("binding the session"))?;
    session_audit::routed(&Routed {
        session_id: &session.id,
        user_id: &holder.user.id,
        serial: holder.serial,
        node_id: &node.id,
        node_name: &node.name,
        client_addr: &request.client_addr,
        policy_hash: policy.hash(),
    });
    Ok(RouteDecision::Allow {
        session_id: session.id,
        node_id: node.id,
    })
}

fn denied(
    request: &RouteRequest,
    policy_hash: &str,
    reason: DenyReason,
    node_id: Option<&str>,
) -> RouteDecision {
    session_audit::denied(&Denied {
        phase: Phase::Route,
        reason,
        policy_hash,
        user_id: &request.user_id,
        serial: request.serial,
        node_id,
        node_name: Some(&request.node_name),
        session_id: None,
        login: None,
        client_addr: &request.client_addr,
    });
    RouteDecision::Deny { reason }
}
