use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_policy::AdminPermission;
use serde::Serialize;

use crate::audit::{self, SessionEnd};
use crate::control::Control;
use crate::http::{empty_response, json_response, server_error};
use crate::identity::policy_identity;
use crate::token;

use super::cookies::{self, SESSION_COOKIE};
use super::csrf;
use super::session::{NodesApprove, RequireAdmin, WebSession};
use super::terminal::End;

#[derive(Serialize)]
struct SessionBody {
    user_id: String,
    email: String,
    display_name: Option<String>,
    groups: Vec<String>,
    permissions: Vec<&'static str>,
    expires_at: i64,
    csrf_token: String,
}

#[derive(Serialize)]
struct AdminWhoamiBody {
    user_id: String,
    email: String,
    display_name: Option<String>,
    groups: Vec<String>,
}

pub(crate) async fn session(
    State(control): State<Control>,
    session: WebSession,
    headers: HeaderMap,
) -> Response {
    let Some(secret) = cookies::presented(&headers, SESSION_COOKIE) else {
        tracing::error!(target: "jaunt::control", "an authenticated web session lost its cookie");
        return server_error();
    };
    let csrf_token = csrf::token_for(secret);
    if token::hash_secret(&csrf_token) != session.0.session.csrf_token_hash {
        tracing::error!(target: "jaunt::control", "the web session csrf token does not match its stored hash");
        return server_error();
    }
    let policy = control.policy_snapshot();
    let identity = policy_identity(session.user());
    let permissions = AdminPermission::ALL
        .into_iter()
        .filter(|permission| policy.admin_can(&identity, *permission))
        .map(|permission| permission.as_str())
        .collect();
    let valid = session.0;
    json_response(
        StatusCode::OK,
        &SessionBody {
            user_id: valid.user.id,
            email: valid.user.email,
            display_name: valid.user.display_name,
            groups: valid.user.groups,
            permissions,
            expires_at: valid.session.expires_at,
            csrf_token,
        },
    )
}

pub(crate) async fn logout(State(control): State<Control>, session: WebSession) -> Response {
    let id_hash = &session.0.session.id_hash;
    control
        .web
        .terminals
        .live
        .stop_web_session(id_hash, End::WebSessionEnded);
    match control.store.web_sessions().delete(id_hash).await {
        Ok(Some(user_id)) => audit::web_session_ended(&user_id, SessionEnd::Logout),
        Ok(None) => {}
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "deleting the web session failed");
            return server_error();
        }
    }
    let mut response = empty_response(StatusCode::NO_CONTENT);
    cookies::clear_session(&mut response);
    response
}

pub(crate) async fn whoami(admin: RequireAdmin<NodesApprove>) -> Response {
    let user = admin.principal.user().clone();
    json_response(
        StatusCode::OK,
        &AdminWhoamiBody {
            user_id: user.id,
            email: user.email,
            display_name: user.display_name,
            groups: user.groups,
        },
    )
}
