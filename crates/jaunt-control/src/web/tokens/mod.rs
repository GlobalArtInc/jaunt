mod audit;
mod guard;
mod request;
mod secret;

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_limits::{DEFAULT_CAPACITY, Rate, RateLimiter};
use jaunt_proto::{
    ADMIN_TOKEN_MAX_CREATED_PER_HOUR, ADMIN_TOKEN_MAX_DEAD_PER_CREATOR,
    ADMIN_TOKEN_MAX_LIVE_PER_CREATOR, is_admin_token_id,
};
use jaunt_store::{
    AdminToken, AdminTokenCaps, AdminTokenCreated, AdminTokenRevoked, NewAdminToken, SecretHash,
};
use serde::Serialize;

use crate::control::Control;
use crate::http::{empty_response, error_response, json_body, json_response, server_error};
use crate::identity::policy_identity;
use crate::limits::{NoiseLog, too_many_requests};

use super::admin_common::{conflict, invalid_value, not_found};
use super::admin_principal::{AdminPrincipal, TokenAdmin};
use super::session::{NodesApprove, Rejection, RequireAdmin, TokensWrite};

use self::audit::RefusalLog;
use self::request::{CreateBody, TokenRequest, scope_names, validate};

pub(crate) use self::guard::{authenticate, permits, refuse_ambiguous};
pub(crate) use self::secret::presents_token;

const USES_PER_TOKEN: Rate = Rate::clamped(60, 60);
const SCOPE_NOT_HELD: &str = "scope_not_held";
const CREATION_WINDOW_SECS: i64 = 3_600;
const LIST_DEAD_WINDOW_SECS: i64 = 7 * 86_400;
const LIST_MAX_ROWS: u32 = 500;
const SCOPE_WARNING_INTERVAL: Duration = Duration::from_secs(3_600);
const CAPS: AdminTokenCaps = AdminTokenCaps {
    max_live_per_creator: ADMIN_TOKEN_MAX_LIVE_PER_CREATOR,
    max_dead_per_creator: ADMIN_TOKEN_MAX_DEAD_PER_CREATOR,
    max_created_per_window: ADMIN_TOKEN_MAX_CREATED_PER_HOUR,
    window_secs: CREATION_WINDOW_SECS,
};

pub(crate) struct TokenState {
    pub(crate) uses: RateLimiter<String>,
    pub(crate) unproven: NoiseLog,
    pub(crate) refusals: RefusalLog,
    pub(crate) scope_warnings: WarningLog,
}

impl Default for TokenState {
    fn default() -> Self {
        TokenState {
            uses: RateLimiter::new(USES_PER_TOKEN, DEFAULT_CAPACITY),
            unproven: NoiseLog::new(),
            refusals: RefusalLog::default(),
            scope_warnings: WarningLog::default(),
        }
    }
}

impl TokenState {
    pub(crate) fn sweep(&self, now: Duration) {
        self.uses.sweep(now);
        self.refusals.sweep(now);
        self.scope_warnings.sweep(now);
    }
}

#[derive(Default)]
pub(crate) struct WarningLog {
    last: Mutex<HashMap<String, Duration>>,
}

impl WarningLog {
    pub(crate) fn admit(&self, id: &str, now: Duration) -> bool {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last
            .get(id)
            .is_some_and(|at| now.saturating_sub(*at) < SCOPE_WARNING_INTERVAL)
        {
            return false;
        }
        last.insert(id.to_owned(), now);
        true
    }

    fn sweep(&self, now: Duration) {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, at| now.saturating_sub(*at) < SCOPE_WARNING_INTERVAL);
    }
}

#[derive(Serialize)]
struct TokenBody {
    id: String,
    name: String,
    creator: String,
    scope: Vec<String>,
    cidrs: Vec<String>,
    created_at: i64,
    expires_at: i64,
    revoked_at: Option<i64>,
    last_used_at: Option<i64>,
}

impl From<AdminToken> for TokenBody {
    fn from(token: AdminToken) -> TokenBody {
        TokenBody {
            id: token.id,
            name: token.name,
            creator: token.creator_user_id,
            scope: token.scope,
            cidrs: token.cidrs,
            created_at: token.created_at,
            expires_at: token.expires_at,
            revoked_at: token.revoked_at,
            last_used_at: token.last_used_at,
        }
    }
}

#[derive(Serialize)]
struct CreatedBody {
    #[serde(flatten)]
    token: TokenBody,
    secret: String,
}

#[derive(Serialize)]
struct ListBody {
    tokens: Vec<TokenBody>,
    truncated: bool,
}

#[derive(Serialize)]
struct SelfBody {
    id: String,
    name: String,
    scope: Vec<String>,
    rights: Vec<String>,
    expires_at: i64,
}

#[derive(Serialize)]
struct WhoamiBody {
    token: SelfBody,
}

pub(crate) enum WhoamiCaller {
    Person(AdminPrincipal),
    Token(TokenAdmin),
}

impl FromRequestParts<Control> for WhoamiCaller {
    type Rejection = Rejection;

    async fn from_request_parts(
        parts: &mut Parts,
        control: &Control,
    ) -> Result<WhoamiCaller, Rejection> {
        if let Some(AdminPrincipal::Token(token)) = parts.extensions.get::<AdminPrincipal>() {
            audit::used(token, None, true);
            return Ok(WhoamiCaller::Token(token.clone()));
        }
        let admin = RequireAdmin::<NodesApprove>::from_request_parts(parts, control).await?;
        Ok(WhoamiCaller::Person(admin.principal))
    }
}

pub(crate) fn whoami(control: &Control, token: TokenAdmin) -> Response {
    let rights = guard::effective_rights(&token, &control.policy_snapshot());
    json_response(
        StatusCode::OK,
        &WhoamiBody {
            token: SelfBody {
                rights: scope_names(&rights),
                scope: scope_names(&token.scope),
                id: token.id,
                name: token.name,
                expires_at: token.expires_at,
            },
        },
    )
}

pub(crate) async fn create(
    State(control): State<Control>,
    admin: RequireAdmin<TokensWrite>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body: CreateBody = match json_body(&headers, body) {
        Ok(body) => body,
        Err(failure) => return failure.into_response(),
    };
    let request = match validate(body) {
        Ok(request) => request,
        Err(invalid) => return invalid_value(invalid.code()),
    };
    let principal = admin.principal;
    let policy = control.policy_snapshot();
    let identity = policy_identity(principal.user());
    if !request
        .scope
        .iter()
        .all(|permission| policy.admin_can(&identity, *permission))
    {
        return error_response(StatusCode::FORBIDDEN, SCOPE_NOT_HELD);
    }
    let creator = principal.user().id.clone();
    let created_by = principal.actor();
    let finished = tokio::spawn(store_new(control, request, creator, created_by)).await;
    finished.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the admin token creation task did not finish");
        server_error()
    })
}

async fn store_new(
    control: Control,
    request: TokenRequest,
    creator: String,
    created_by: String,
) -> Response {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let Ok(issued) = secret::issue() else {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        return server_error();
    };
    let new = NewAdminToken {
        id: issued.id,
        name: request.name,
        creator_user_id: creator,
        secret_hash: SecretHash::new(issued.hash),
        scope: scope_names(&request.scope),
        cidrs: request.cidrs.iter().map(ToString::to_string).collect(),
        ttl_secs: request.ttl_secs,
    };
    let outcome = control
        .store
        .admin_tokens()
        .create(&new, now.secs, CAPS)
        .await;
    match outcome {
        Ok(AdminTokenCreated::Created(token)) => {
            audit::created(&token, &created_by);
            json_response(
                StatusCode::CREATED,
                &CreatedBody {
                    token: token.into(),
                    secret: issued.text.expose().to_owned(),
                },
            )
        }
        Ok(AdminTokenCreated::NameTaken) => conflict("name_taken"),
        Ok(AdminTokenCreated::TooMany) => conflict("too_many_tokens"),
        Ok(AdminTokenCreated::TooFrequent { retry_after_secs }) => too_many_requests(
            Duration::from_secs(u64::try_from(retry_after_secs).unwrap_or(1)),
        ),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "storing an admin token failed");
            server_error()
        }
    }
}

pub(crate) async fn list(
    State(control): State<Control>,
    _admin: RequireAdmin<TokensWrite>,
) -> Response {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let listed = control
        .store
        .admin_tokens()
        .list(
            now.secs,
            now.secs.saturating_sub(LIST_DEAD_WINDOW_SECS),
            LIST_MAX_ROWS,
        )
        .await;
    match listed {
        Ok(page) => json_response(
            StatusCode::OK,
            &ListBody {
                tokens: page.tokens.into_iter().map(TokenBody::from).collect(),
                truncated: page.truncated,
            },
        ),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "listing admin tokens failed");
            server_error()
        }
    }
}

pub(crate) async fn revoke(
    State(control): State<Control>,
    admin: RequireAdmin<TokensWrite>,
    Path(id): Path<String>,
) -> Response {
    if !is_admin_token_id(&id) {
        return not_found();
    }
    let revoked_by = admin.principal.actor();
    let finished = tokio::spawn(revoke_stored(control, id, revoked_by)).await;
    finished.unwrap_or_else(|_| {
        tracing::error!(target: "jaunt::control", "the admin token revocation task did not finish");
        server_error()
    })
}

async fn revoke_stored(control: Control, id: String, revoked_by: String) -> Response {
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return server_error();
    };
    let revoked = control
        .store
        .admin_tokens()
        .revoke(&id, now.secs, ADMIN_TOKEN_MAX_DEAD_PER_CREATOR)
        .await;
    match revoked {
        Ok(AdminTokenRevoked::Revoked(token)) => {
            audit::revoked(&token, &revoked_by);
            empty_response(StatusCode::NO_CONTENT)
        }
        Ok(AdminTokenRevoked::AlreadyRevoked) => conflict("already_revoked"),
        Ok(AdminTokenRevoked::Unknown) => not_found(),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "revoking an admin token failed");
            server_error()
        }
    }
}
