use axum::http::StatusCode;
use axum::response::Response;
use jaunt_proto::EnrollResponse;
use jaunt_store::{JoinEnrollment, JoinOutcome, JoinToken, Joined};

use crate::clock::Moment;
use crate::control::Control;
use crate::enroll::{ENROLLMENT_TTL_SECS, POLL_INTERVAL_SECS, ValidEnroll};
use crate::enroll_secrets;
use crate::http::{error_response, json_response, server_error};
use crate::join_secrets;
use crate::join_token_audit::{self, Refused, Used};
use crate::join_tokens::{Refusal, admits};
use crate::node_audit::{self, EnrollRequested};
use crate::node_removal;
use crate::source_ip::Source;

pub(crate) const REFUSED: &str = "join_token_refused";
const APPROVER_PREFIX: &str = "join-token:";

pub(crate) async fn enroll(
    control: &Control,
    valid: &ValidEnroll,
    source: &Source,
    now: Moment,
    presented: &str,
) -> Response {
    let refuse = |reason: Refusal, token_id: Option<&str>| {
        join_token_audit::refused(&Refused {
            reason,
            join_id: token_id,
            name: &valid.name,
            source_ip: &source.address,
            source_network: &source.network,
        });
        error_response(StatusCode::FORBIDDEN, REFUSED)
    };
    let Some(hash) = join_secrets::hash_presented(presented) else {
        return refuse(Refusal::Malformed, None);
    };
    let tokens = control.store.join_tokens();
    let token = match tokens.find_usable(&hash, now.secs).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return match tokens.classify(&hash, now.secs).await {
                Ok(Some(unusable)) => refuse(unusable.failure.into(), unusable.token_id.as_deref()),
                Ok(None) => {
                    tracing::error!(target: "jaunt::control", "a join token was unusable and usable at one instant");
                    server_error()
                }
                Err(err) => {
                    tracing::error!(target: "jaunt::control", error = %err, "classifying the join token failed");
                    server_error()
                }
            };
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the join token failed");
            return server_error();
        }
    };
    if let Err(reason) = admits(&token, &valid.name, valid.labels.as_map()) {
        return refuse(reason, Some(&token.id));
    }
    let Ok(handle) = enroll_secrets::issue_handle() else {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        return server_error();
    };
    let approved_by = format!("{APPROVER_PREFIX}{}", token.id);
    let outcome = tokens
        .enroll(JoinEnrollment {
            token_id: &token.id,
            token_hash: &hash,
            handle_hash: &handle.hash,
            name: &valid.name,
            labels: &token.labels,
            hostname: &valid.hostname,
            source_ip: &source.network,
            peer_addr: &source.address,
            tls_public_key: &valid.tls.canonical,
            ssh_host_public_key: &valid.ssh.canonical,
            tls_spki_sha256: &valid.tls.sha256,
            ssh_host_key_fingerprint: &valid.ssh.fingerprint,
            replace_existing: valid.replace && token.allow_replace,
            agent_version: &valid.agent_version,
            approved_by: &approved_by,
            ttl_secs: ENROLLMENT_TTL_SECS,
            now: now.secs,
        })
        .await;
    match outcome {
        Ok(JoinOutcome::Joined(joined)) => {
            record_join(&token, &joined, valid, source, &approved_by);
            if let Some(old) = &joined.replaced {
                cut_off_replaced(control, &old.id).await;
            }
            json_response(
                StatusCode::OK,
                &EnrollResponse {
                    handle: handle.secret,
                    code: None,
                    expires_at: joined.enrollment.expires_at,
                    poll_interval: POLL_INTERVAL_SECS,
                },
            )
        }
        Ok(JoinOutcome::Unusable(unusable)) => {
            refuse(unusable.failure.into(), unusable.token_id.as_deref())
        }
        Ok(JoinOutcome::NameTaken) if valid.replace => {
            refuse(Refusal::ReplaceNotAllowed, Some(&token.id))
        }
        Ok(JoinOutcome::NameTaken) => error_response(StatusCode::CONFLICT, "name_taken"),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "creating the enrollment for a join token failed");
            server_error()
        }
    }
}

async fn cut_off_replaced(control: &Control, node_id: &str) {
    let task_control = control.clone();
    let task_node = node_id.to_owned();
    let finished =
        tokio::spawn(async move { node_removal::cut_off(&task_control, &task_node).await }).await;
    match finished {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => {
            tracing::error!(
                target: "jaunt::control",
                error = %err,
                node_id,
                "the replaced node's sessions were not closed at once; the session sweep closes them"
            );
        }
        Err(err) => {
            tracing::error!(
                target: "jaunt::control",
                error = %err,
                node_id,
                "closing the replaced node's sessions ended abnormally; the session sweep closes them"
            );
        }
    }
}

fn record_join(
    token: &JoinToken,
    joined: &Joined,
    valid: &ValidEnroll,
    source: &Source,
    approved_by: &str,
) {
    let enrollment = &joined.enrollment;
    node_audit::enroll_requested(&EnrollRequested {
        enrollment_id: &enrollment.id,
        name: &enrollment.name,
        hostname: &enrollment.hostname,
        source_ip: &enrollment.peer_addr,
        source_network: &enrollment.source_ip,
        agent_version: &enrollment.agent_version,
        replace: valid.replace,
    });
    join_token_audit::used(&Used {
        join_id: &token.id,
        enrollment_id: &enrollment.id,
        node_id: &joined.node.id,
        name: &joined.node.name,
        uses_left: joined.uses_left,
        replaced_node_id: joined.replaced.as_ref().map(|node| node.id.as_str()),
        source_ip: &source.address,
        source_network: &source.network,
    });
    if let Some(old) = &joined.replaced {
        node_audit::node_removed(&old.id, &old.name, "replaced", approved_by);
    }
}
