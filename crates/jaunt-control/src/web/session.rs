use std::marker::PhantomData;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jaunt_policy::AdminPermission;
use jaunt_store::{User, ValidWebSession, WebSessions};

use crate::audit::{self, SessionEnd};
use crate::completion;
use crate::control::Control;
use crate::http::{empty_response, error_response, server_error};
use crate::identity::policy_identity;
use crate::token;

use super::cookies::{self, SESSION_COOKIE};
use super::csrf;

const LOGIN_PATH: &str = "/v1/web/login";
const API_PREFIX: &str = "/v1/";
const WEB_PREFIX: &str = "/v1/web";
const ADMIN_PREFIX: &str = "/v1/admin";
const TOUCH_INTERVAL_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Unauthenticated,
    Refused,
    Server,
}

pub(crate) struct Rejection {
    failure: Failure,
    api: bool,
}

impl Rejection {
    fn new(failure: Failure, uri: &Uri) -> Rejection {
        Rejection {
            failure,
            api: uri.path().starts_with(API_PREFIX),
        }
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        match (self.failure, self.api) {
            (Failure::Unauthenticated, true) => {
                error_response(StatusCode::UNAUTHORIZED, "unauthorized")
            }
            (Failure::Unauthenticated, false) => {
                let mut response = empty_response(StatusCode::FOUND);
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static(LOGIN_PATH));
                response
            }
            (Failure::Refused, _) => error_response(StatusCode::FORBIDDEN, "forbidden"),
            (Failure::Server, _) => server_error(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct WebSession(pub(crate) ValidWebSession);

impl WebSession {
    pub(crate) fn user(&self) -> &User {
        &self.0.user
    }
}

async fn authenticate(
    control: &Control,
    method: &Method,
    headers: &HeaderMap,
) -> Result<ValidWebSession, Failure> {
    let Some(secret) = cookies::presented(headers, SESSION_COOKIE)
        .filter(|value| completion::is_well_formed(value))
    else {
        return Err(Failure::Unauthenticated);
    };
    let id_hash = token::hash_secret(secret);
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(Failure::Server);
    };
    let sessions = control.store.web_sessions();
    let found = match sessions.find_valid(&id_hash, now.secs).await {
        Ok(found) => found,
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "looking up the web session failed");
            return Err(Failure::Server);
        }
    };
    let Some(valid) = found else {
        end_if_expired(&sessions, &id_hash, now.secs).await;
        return Err(Failure::Unauthenticated);
    };
    if csrf::is_state_changing(method)
        && let Err(refusal) = csrf::verify(
            headers,
            &valid.session.csrf_token_hash,
            control.public_origin(),
        )
    {
        audit::web_csrf_denied(&valid.user.id, refusal.code());
        return Err(Failure::Refused);
    }
    if now.secs.saturating_sub(valid.session.last_seen_at) >= TOUCH_INTERVAL_SECS
        && let Err(err) = sessions
            .touch(&id_hash, now.secs, TOUCH_INTERVAL_SECS)
            .await
    {
        tracing::warn!(target: "jaunt::control", error = %err, "recording web session activity failed");
    }
    Ok(valid)
}

async fn end_if_expired(sessions: &WebSessions, id_hash: &str, now: i64) {
    let stored = match sessions.get(id_hash).await {
        Ok(stored) => stored,
        Err(err) => {
            tracing::warn!(target: "jaunt::control", error = %err, "looking up an unusable web session failed");
            return;
        }
    };
    if !stored.is_some_and(|stored| stored.expires_at <= now) {
        return;
    }
    match sessions.delete_expired(id_hash, now).await {
        Ok(Some(user_id)) => audit::web_session_ended(&user_id, SessionEnd::Expired),
        Ok(None) => {}
        Err(err) => {
            tracing::warn!(target: "jaunt::control", error = %err, "removing an expired web session failed");
        }
    }
}

impl FromRequestParts<Control> for WebSession {
    type Rejection = Rejection;

    async fn from_request_parts(
        parts: &mut Parts,
        control: &Control,
    ) -> Result<WebSession, Rejection> {
        if let Some(already) = parts.extensions.get::<WebSession>() {
            return Ok(already.clone());
        }
        authenticate(control, &parts.method, &parts.headers)
            .await
            .map(WebSession)
            .map_err(|failure| Rejection::new(failure, &parts.uri))
    }
}

fn is_under(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

async fn ensure_session(control: &Control, request: &mut Request) -> Result<(), Rejection> {
    if request.extensions().get::<WebSession>().is_some() {
        return Ok(());
    }
    let valid = authenticate(control, request.method(), request.headers())
        .await
        .map_err(|failure| Rejection::new(failure, request.uri()))?;
    request.extensions_mut().insert(WebSession(valid));
    Ok(())
}

pub(crate) async fn guard(
    State(control): State<Control>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let session_required = is_under(path, ADMIN_PREFIX)
        || (is_under(path, WEB_PREFIX) && csrf::is_state_changing(request.method()));
    if session_required && let Err(rejection) = ensure_session(&control, &mut request).await {
        return rejection.into_response();
    }
    next.run(request).await
}

pub(crate) trait Permission {
    const REQUIRED: AdminPermission;
}

pub(crate) struct NodesApprove;

impl Permission for NodesApprove {
    const REQUIRED: AdminPermission = AdminPermission::NodesApprove;
}

pub(crate) struct RequireAdmin<P: Permission> {
    pub(crate) session: WebSession,
    permission: PhantomData<P>,
}

impl<P: Permission> FromRequestParts<Control> for RequireAdmin<P> {
    type Rejection = Rejection;

    async fn from_request_parts(
        parts: &mut Parts,
        control: &Control,
    ) -> Result<RequireAdmin<P>, Rejection> {
        let session = WebSession::from_request_parts(parts, control).await?;
        let policy = control.policy_snapshot();
        if !policy.admin_can(&policy_identity(session.user()), P::REQUIRED) {
            audit::admin_denied(&session.user().id, P::REQUIRED.as_str(), policy.hash());
            return Err(Rejection::new(Failure::Refused, &parts.uri));
        }
        Ok(RequireAdmin {
            session,
            permission: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{StatusCode, Uri, header};
    use axum::response::IntoResponse;

    use super::{Failure, Rejection, is_under};

    fn answer(failure: Failure, uri: &'static str) -> axum::response::Response {
        Rejection::new(failure, &Uri::from_static(uri)).into_response()
    }

    #[test]
    fn api_requests_get_json_statuses_and_pages_are_sent_to_sign_in() {
        let api = answer(Failure::Unauthenticated, "/v1/web/session");
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(api.headers()[header::CONTENT_TYPE], "application/json");
        assert!(api.headers().get(header::LOCATION).is_none());

        let page = answer(Failure::Unauthenticated, "/nodes");
        assert_eq!(page.status(), StatusCode::FOUND);
        assert_eq!(page.headers()[header::LOCATION], "/v1/web/login");
    }

    #[test]
    fn the_admin_and_web_namespaces_are_matched_by_whole_path_segments() {
        for path in [
            "/v1/admin",
            "/v1/admin/",
            "/v1/admin/whoami",
            "/v1/admin/a/b",
        ] {
            assert!(is_under(path, "/v1/admin"), "{path}");
        }
        for path in [
            "/v1/administrator",
            "/v1/admin2/x",
            "/v1/web/x",
            "/V1/ADMIN/x",
            "/v1/%61dmin/x",
            "/",
            "",
        ] {
            assert!(!is_under(path, "/v1/admin"), "{path}");
        }
        assert!(is_under("/v1/web/session", "/v1/web"));
        assert!(!is_under("/v1/webx", "/v1/web"));
    }

    #[test]
    fn refusals_and_server_errors_are_generic() {
        for uri in ["/v1/admin/whoami", "/nodes"] {
            assert_eq!(
                answer(Failure::Refused, uri).status(),
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                answer(Failure::Server, uri).status(),
                StatusCode::INTERNAL_SERVER_ERROR
            );
        }
    }
}
