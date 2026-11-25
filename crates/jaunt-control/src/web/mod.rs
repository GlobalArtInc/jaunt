mod admin_common;
mod admin_sessions;
mod api;
mod assets;
mod audit_log;
mod ca_status;
mod cookies;
mod csrf;
mod enrolments;
mod headers;
mod intents;
mod login;
mod lookup_limit;
mod nodes;
pub(crate) mod pages;
mod recording_view;
mod revocations;
mod session;
pub(crate) mod terminal;
#[cfg(feature = "test-support")]
pub use self::terminal::WebTerminalCounters;

use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, post};

use crate::control::Control;

pub(crate) use self::cookies::login_binding_matches;
pub(crate) use self::headers::SecurityHeaders;
pub(crate) use self::login::establish;
pub use self::recording_view::DEFAULT_PLAYBACK_LIMIT_BYTES;
pub use self::terminal::{
    DEFAULT_MAX_TERMINAL_TICKETS, DEFAULT_MAX_TERMINALS, DEFAULT_MAX_TERMINALS_PER_USER,
    DEFAULT_TERMINAL_IDLE_TIMEOUT, GateEvent, GateEvents, GateLink, GateRefusal, GateRequest,
    TERMINAL_DEAD_PEER_TIMEOUT, TERMINAL_MAX_FRAME_BYTES, TERMINAL_PING_INTERVAL,
    TERMINAL_SUBPROTOCOL, TERMINAL_TICKET_PREFIX, TERMINAL_TICKET_TTL_SECS, TERMINAL_WEDGE_TIMEOUT,
    TerminalGate, WEB_CERTIFICATE_VALIDITY, WebTerminalSettings,
};

pub(crate) const SESSION_TTL_SECS: i64 = 28_800;
pub(crate) const MAX_SESSIONS_PER_USER: u32 = 20;

pub(crate) struct WebState {
    pub(crate) enabled: bool,
    pub(crate) headers: SecurityHeaders,
    pub(crate) intents: intents::IntentTable,
    pub(crate) lookups: lookup_limit::LookupLimiter,
    pub(crate) views: recording_view::ViewLog,
    pub(crate) playback: recording_view::PlaybackLimit,
    pub(crate) terminals: terminal::TerminalState,
}

impl WebState {
    pub(crate) fn new(enabled: bool, public_origin: &str) -> WebState {
        WebState {
            enabled,
            headers: SecurityHeaders::new(public_origin),
            intents: intents::IntentTable::default(),
            lookups: lookup_limit::LookupLimiter::default(),
            views: recording_view::ViewLog::default(),
            playback: recording_view::PlaybackLimit::default(),
            terminals: terminal::TerminalState::default(),
        }
    }
}

#[cfg(feature = "test-support")]
pub struct TestWebSession {
    pub cookie: String,
    pub csrf_token: String,
}

#[cfg(feature = "test-support")]
pub(crate) async fn open_for_tests(control: &Control, user_id: &str) -> Option<TestWebSession> {
    let issued = crate::completion::issue().ok()?;
    let csrf_token = csrf::token_for(&issued.secret);
    let now = control.now()?;
    control
        .store
        .web_sessions()
        .create(
            &jaunt_store::NewWebSession {
                id_hash: issued.hash,
                user_id: user_id.to_owned(),
                csrf_token_hash: crate::token::hash_secret(&csrf_token),
                created_at: now.secs,
                expires_at: now.secs.saturating_add(SESSION_TTL_SECS),
                source_ip: None,
                user_agent: None,
            },
            MAX_SESSIONS_PER_USER,
        )
        .await
        .ok()?;
    Some(TestWebSession {
        cookie: format!("{}={}", cookies::SESSION_COOKIE, issued.secret),
        csrf_token,
    })
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
        .route("/v1/admin/nodes", get(nodes::list))
        .route(
            "/v1/admin/nodes/{id}",
            get(nodes::detail).delete(nodes::remove),
        )
        .route("/v1/admin/nodes/{id}/access", get(nodes::access))
        .route("/v1/admin/enrolments/lookup", post(enrolments::lookup))
        .route(
            "/v1/admin/enrolments/{id}/approve",
            post(enrolments::approve),
        )
        .route("/v1/admin/enrolments/{id}/reject", post(enrolments::reject))
        .route("/v1/admin/sessions", get(admin_sessions::list))
        .route("/v1/admin/sessions/{id}", get(admin_sessions::detail))
        .route("/v1/web/terminal", get(terminal::open))
        .route("/v1/web/terminal/ticket", post(terminal::ticket))
        .route("/v1/web/terminal/targets", get(terminal::targets))
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
    let recordings = Router::new()
        .route(
            "/v1/admin/sessions/{id}/recording",
            get(recording_view::stream),
        )
        .route(
            "/v1/admin/sessions/{id}/recording/manifest",
            get(recording_view::manifest),
        )
        .layer(middleware::from_fn_with_state(
            control.clone(),
            session::guard,
        ))
        .layer(middleware::from_fn_with_state(
            control.clone(),
            headers::apply_sandboxed_to_response,
        ));
    routes.merge(site).merge(recordings)
}
