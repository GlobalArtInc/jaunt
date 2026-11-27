use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use jaunt_store::{Node, PinOutcome};

use crate::control::Control;
use crate::http::{empty_response, error_response, server_error};
use crate::identity::policy_identity;
use crate::naming::is_dns_label;
use crate::nodes::is_ssh_target;
use crate::web::session::WebSession;

use super::open::{is_visible, node_logins};

pub(crate) const MAX_PINS_PER_USER: u32 = 50;

fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not_found")
}

enum Lookup {
    Found { node: Box<Node>, visible: bool },
    Absent,
    Failed,
}

async fn lookup(control: &Control, session: &WebSession, name: &str) -> Lookup {
    if control.web.terminals.installed().is_none() || !is_dns_label(name) {
        return Lookup::Absent;
    }
    let node = match control.store.nodes().get_active_by_name(name).await {
        Ok(Some(node)) if is_ssh_target(&node) => node,
        Ok(_) => return Lookup::Absent,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading a node to pin failed");
            return Lookup::Failed;
        }
    };
    let policy = control.policy_snapshot();
    let visible = is_visible(&node_logins(
        &policy,
        &policy_identity(session.user()),
        &node,
    ));
    Lookup::Found {
        node: Box::new(node),
        visible,
    }
}

pub(crate) async fn pin(
    State(control): State<Control>,
    session: WebSession,
    Path(name): Path<String>,
) -> Response {
    let node = match lookup(&control, &session, &name).await {
        Lookup::Found {
            node,
            visible: true,
        } => node,
        Lookup::Found { visible: false, .. } | Lookup::Absent => return not_found(),
        Lookup::Failed => return server_error(),
    };
    let Some(now) = control.now() else {
        return server_error();
    };
    match control
        .store
        .user_pins()
        .pin(&session.user().id, &node.id, now.secs, MAX_PINS_PER_USER)
        .await
    {
        Ok(PinOutcome::Pinned | PinOutcome::AlreadyPinned) => {
            empty_response(StatusCode::NO_CONTENT)
        }
        Ok(PinOutcome::Full) => error_response(StatusCode::CONFLICT, "too_many_pins"),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "pinning a node failed");
            server_error()
        }
    }
}

pub(crate) async fn unpin(
    State(control): State<Control>,
    session: WebSession,
    Path(name): Path<String>,
) -> Response {
    let (node, visible) = match lookup(&control, &session, &name).await {
        Lookup::Found { node, visible } => (node, visible),
        Lookup::Absent => return not_found(),
        Lookup::Failed => return server_error(),
    };
    let pins = control.store.user_pins();
    let user_id = &session.user().id;
    let removed = match pins.unpin(user_id, &node.id).await {
        Ok(removed) => removed,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "unpinning a node failed");
            return server_error();
        }
    };
    if removed || visible {
        empty_response(StatusCode::NO_CONTENT)
    } else {
        not_found()
    }
}
