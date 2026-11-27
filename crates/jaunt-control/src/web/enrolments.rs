use std::collections::BTreeMap;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use crate::admin::{ApproveError, ApprovedNode, PendingEnrollment};
use crate::control::Control;
use crate::http::{json_body, json_response, server_error};
use crate::labels::Labels;
use crate::limits::too_many_requests;
use crate::node_audit;

use super::admin_common::{conflict, invalid_value, known_id, not_found};
use super::intents::Binding;
use super::session::{NodesApprove, RequireAdmin};

const FOUND: &str = "found";
const FAILED: &str = "failed";
const LIMITED: &str = "limited";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    intent: String,
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectBody {
    intent: String,
}

#[derive(Serialize)]
struct PreviewBody {
    id: String,
    name: String,
    labels: BTreeMap<String, String>,
    hostname: String,
    peer_addr: String,
    source_network: String,
    agent_version: String,
    requested_at: i64,
    expires_at: i64,
    tls_key_sha256: String,
    ssh_host_key_fingerprint: String,
    replace_existing: bool,
}

impl From<PendingEnrollment> for PreviewBody {
    fn from(pending: PendingEnrollment) -> PreviewBody {
        PreviewBody {
            id: pending.id,
            name: pending.name,
            labels: pending.labels.into_map(),
            hostname: pending.hostname,
            peer_addr: pending.peer_addr,
            source_network: pending.source_network,
            agent_version: pending.agent_version,
            requested_at: pending.requested_at,
            expires_at: pending.expires_at,
            tls_key_sha256: pending.tls_key_sha256,
            ssh_host_key_fingerprint: pending.ssh_host_key_fingerprint,
            replace_existing: pending.replace_existing,
        }
    }
}

#[derive(Serialize)]
struct LookedUpBody {
    enrolment: PreviewBody,
    intent: String,
    intent_expires_at: i64,
}

#[derive(Serialize)]
struct NodeRef {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct ApprovedBody {
    enrolment_id: String,
    node: NodeRef,
    labels: BTreeMap<String, String>,
    replaced: Option<NodeRef>,
}

impl From<ApprovedNode> for ApprovedBody {
    fn from(approved: ApprovedNode) -> ApprovedBody {
        ApprovedBody {
            enrolment_id: approved.enrollment_id,
            labels: approved.node.labels.into_map(),
            node: NodeRef {
                id: approved.node.id,
                name: approved.node.name,
            },
            replaced: approved.replaced.map(|old| NodeRef {
                id: old.id,
                name: old.name,
            }),
        }
    }
}

#[derive(Serialize)]
struct RejectedBody {
    enrolment_id: String,
    name: String,
}

pub(crate) async fn lookup(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: LookupBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let task = tokio::spawn(run_lookup(control, admin, body.code)).await;
    task.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the enrolment lookup task did not finish");
        server_error()
    })
}

async fn run_lookup(control: Control, admin: RequireAdmin<NodesApprove>, code: String) -> Response {
    let actor = admin.principal.actor();
    let session_hash = admin.principal.binding();
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let attempt = match control.web.lookups.admit(&session_hash, now.secs) {
        Ok(attempt) => attempt,
        Err(wait_secs) => {
            node_audit::enrolment_looked_up(&actor, LIMITED, None);
            let wait = Duration::from_secs(u64::try_from(wait_secs).unwrap_or(1));
            return too_many_requests(wait);
        }
    };
    let found = control.node_admin().pending_with_hash(&code).await;
    let (pending, code_hash) = match found {
        Ok(found) => found,
        Err(err) => match lookup_refusal(&err) {
            Some(refused) => {
                node_audit::enrolment_looked_up(&actor, FAILED, None);
                return refused;
            }
            None => {
                control.web.lookups.succeeded(&session_hash, attempt);
                tracing::error!(target: "jaunt::control", error = %err, "looking up an enrolment failed");
                return server_error();
            }
        },
    };
    control.web.lookups.succeeded(&session_hash, attempt);
    let binding = Binding {
        session_hash: &session_hash,
        enrollment_id: &pending.id,
    };
    let issued = match control
        .web
        .intents
        .issue(&binding, &code_hash, pending.expires_at, now.secs)
    {
        Ok(issued) => issued,
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the system entropy source failed");
            return server_error();
        }
    };
    node_audit::enrolment_looked_up(&actor, FOUND, Some(&pending.id));
    json_response(
        StatusCode::OK,
        &LookedUpBody {
            enrolment: pending.into(),
            intent: issued.token,
            intent_expires_at: issued.expires_at,
        },
    )
}

fn lookup_refusal(err: &ApproveError) -> Option<Response> {
    match err {
        ApproveError::UnknownCode
        | ApproveError::Expired
        | ApproveError::Rejected
        | ApproveError::AlreadyApproved => Some(invalid_value("no_pending_enrolment")),
        ApproveError::NameTaken(_)
        | ApproveError::InvalidApprover
        | ApproveError::Clock
        | ApproveError::CorruptEnrollment
        | ApproveError::InvalidLabels
        | ApproveError::Store(_) => None,
    }
}

fn decision_refusal(err: &ApproveError) -> Option<Response> {
    match err {
        ApproveError::UnknownCode | ApproveError::Expired => {
            Some(conflict("enrolment_not_pending"))
        }
        ApproveError::Rejected => Some(conflict("enrolment_rejected")),
        ApproveError::AlreadyApproved => Some(conflict("already_approved")),
        ApproveError::NameTaken(_) => Some(conflict("name_taken")),
        ApproveError::InvalidLabels => Some(invalid_value("invalid_labels")),
        ApproveError::InvalidApprover
        | ApproveError::Clock
        | ApproveError::CorruptEnrollment
        | ApproveError::Store(_) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unredeemed {
    Invalid,
    Clock,
}

impl Unredeemed {
    fn into_response(self) -> Response {
        match self {
            Unredeemed::Invalid => invalid_value("invalid_intent"),
            Unredeemed::Clock => {
                tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
                server_error()
            }
        }
    }
}

fn redeem(
    control: &Control,
    admin: &RequireAdmin<NodesApprove>,
    enrollment_id: &str,
    intent: &str,
) -> Result<String, Unredeemed> {
    let now = control.now().ok_or(Unredeemed::Clock)?;
    let session_hash = admin.principal.binding();
    let binding = Binding {
        session_hash: &session_hash,
        enrollment_id,
    };
    control
        .web
        .intents
        .redeem(intent, &binding, now.secs)
        .map_err(|_| Unredeemed::Invalid)
}

pub(crate) async fn approve(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: ApproveBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let Some(id) = known_id(&id).map(str::to_owned) else {
        return not_found();
    };
    let labels = match body.labels.map(Labels::new).transpose() {
        Ok(labels) => labels,
        Err(_) => return invalid_value("invalid_labels"),
    };
    let code_hash = match redeem(&control, &admin, &id, &body.intent) {
        Ok(code_hash) => code_hash,
        Err(refused) => return refused.into_response(),
    };
    let actor = admin.principal.actor();
    let node_admin = control.node_admin();
    let finished = tokio::spawn(async move {
        node_admin
            .approve_hashed(&code_hash, Some(&id), &actor, labels)
            .await
    })
    .await;
    match finished {
        Ok(Ok(approved)) => json_response(StatusCode::OK, &ApprovedBody::from(approved)),
        Ok(Err(err)) => decision_refusal(&err).unwrap_or_else(|| {
            tracing::error!(target: "jaunt::control", error = %err, "approving an enrolment failed");
            server_error()
        }),
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the approval task did not finish");
            server_error()
        }
    }
}

pub(crate) async fn reject(
    State(control): State<Control>,
    admin: RequireAdmin<NodesApprove>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: RejectBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let Some(id) = known_id(&id).map(str::to_owned) else {
        return not_found();
    };
    let code_hash = match redeem(&control, &admin, &id, &body.intent) {
        Ok(code_hash) => code_hash,
        Err(refused) => return refused.into_response(),
    };
    let actor = admin.principal.actor();
    let node_admin = control.node_admin();
    let finished = tokio::spawn(async move {
        node_admin
            .reject_hashed(&code_hash, Some(&id), &actor)
            .await
    })
    .await;
    match finished {
        Ok(Ok(rejected)) => json_response(
            StatusCode::OK,
            &RejectedBody {
                enrolment_id: rejected.id,
                name: rejected.name,
            },
        ),
        Ok(Err(err)) => decision_refusal(&err).unwrap_or_else(|| {
            tracing::error!(target: "jaunt::control", error = %err, "rejecting an enrolment failed");
            server_error()
        }),
        Err(_) => {
            tracing::error!(target: "jaunt::control", "the rejection task did not finish");
            server_error()
        }
    }
}
