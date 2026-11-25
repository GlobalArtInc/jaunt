mod api;
mod assets;
mod audit_log;
mod ca_status;
mod cookies;
mod csrf;
mod headers;
mod login;
pub(crate) mod pages;
mod revocations;
mod session;

use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, post};

use crate::control::Control;

pub(crate) use self::cookies::login_binding_matches;
pub(crate) use self::headers::SecurityHeaders;
pub(crate) use self::login::establish;

pub(crate) const SESSION_TTL_SECS: i64 = 28_800;
pub(crate) const MAX_SESSIONS_PER_USER: u32 = 20;

pub(crate) struct WebState {
    pub(crate) enabled: bool,
    pub(crate) headers: SecurityHeaders,
}

impl WebState {
    pub(crate) fn new(enabled: bool, public_origin: &str) -> WebState {
        WebState {
            enabled,
            headers: SecurityHeaders::new(public_origin),
        }
    }
}

pub(crate) fn mount(
    routes: Router<Control>,
    control: &Control,
    extra: Router<Control>,
) -> Router<Control> {
    if !control.web.enabled {
        return routes;
    }
    let site = Router::new()
        .route("/v1/web/login", get(login::start))
        .route("/v1/web/session", get(api::session))
        .route("/v1/web/logout", post(api::logout))
        .route("/v1/admin/whoami", get(api::whoami))
        .route("/v1/admin/audit", get(audit_log::list))
        .route("/v1/admin/ca", get(ca_status::show))
        .route(
            "/v1/admin/revocations",
            get(revocations::list).post(revocations::create),
        )
        .route("/v1/admin/revocations/{id}", delete(revocations::remove))
        .merge(extra)
        .fallback(assets::serve)
        .layer(middleware::from_fn_with_state(
            control.clone(),
            session::guard,
        ))
        .layer(middleware::from_fn_with_state(
            control.clone(),
            headers::apply_to_response,
        ));
    routes.merge(site)
}
