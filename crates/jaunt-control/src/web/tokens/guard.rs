use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use jaunt_limits::Decision;
use jaunt_policy::{AdminPermission, PolicySet};
use jaunt_proto::admin_token_id;
use jaunt_store::AdminToken;

use crate::control::Control;
use crate::device::net::ClientAddress;
use crate::http::{error_response, server_error};
use crate::identity::policy_identity;
use crate::limits::too_many_requests;
use crate::revocation::holder_revoked;
use crate::web::admin_principal::{AdminPrincipal, TokenAdmin};

use super::audit::{self, Refused, Unproven};
use super::request::{TOKEN_RIGHTS, admits_address, parse_networks, stored_scope};
use super::secret::{presented, secret_matches};

const TOUCH_INTERVAL_SECS: i64 = 60;
const AMBIGUOUS: &str = "ambiguous_credentials";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TokenDenied {
    Unauthorized,
    TooMany { retry_after: Duration },
    Server,
}

impl TokenDenied {
    pub(crate) fn into_response(self) -> Response {
        match self {
            TokenDenied::Unauthorized => error_response(StatusCode::UNAUTHORIZED, "unauthorized"),
            TokenDenied::TooMany { retry_after } => too_many_requests(retry_after),
            TokenDenied::Server => server_error(),
        }
    }
}

fn client_of(request: &Request) -> Option<IpAddr> {
    request
        .extensions()
        .get::<ClientAddress>()
        .map(|ClientAddress(ip)| *ip)
}

pub(crate) fn refuse_ambiguous(control: &Control, request: &Request) -> Response {
    audit::unproven(control, Unproven::Ambiguous, client_of(request));
    error_response(StatusCode::BAD_REQUEST, AMBIGUOUS)
}

pub(crate) async fn authenticate(
    control: &Control,
    mut request: Request,
) -> Result<Request, TokenDenied> {
    let client = client_of(&request);
    let admin = admit(control, request.headers(), client).await?;
    request
        .extensions_mut()
        .insert(AdminPrincipal::Token(admin));
    Ok(request)
}

async fn admit(
    control: &Control,
    headers: &HeaderMap,
    client: Option<IpAddr>,
) -> Result<TokenAdmin, TokenDenied> {
    let Some((text, id)) = presented(headers).and_then(|text| Some((text, admin_token_id(text)?)))
    else {
        audit::unproven(control, Unproven::Malformed, client);
        return Err(TokenDenied::Unauthorized);
    };
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return Err(TokenDenied::Server);
    };
    let stored = match control.store.admin_tokens().get_for_use(id).await {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            audit::unproven(control, Unproven::UnknownId, client);
            return Err(TokenDenied::Unauthorized);
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading an admin token failed");
            return Err(TokenDenied::Server);
        }
    };
    if !secret_matches(text, stored.secret_hash.expose()) {
        audit::unproven(control, Unproven::BadSecret, client);
        return Err(TokenDenied::Unauthorized);
    }
    let token = stored.token;
    let refuse = |reason: Refused| {
        audit::refused(control, &token, reason, client);
        TokenDenied::Unauthorized
    };
    if token.revoked_at.is_some() {
        return Err(refuse(Refused::Revoked));
    }
    if token.expires_at <= now.secs {
        return Err(refuse(Refused::Expired));
    }
    let Some(networks) = parse_networks(&token.cidrs) else {
        return Err(corrupt(&token, "cidrs"));
    };
    if !admits_address(&networks, client) {
        return Err(refuse(Refused::Address));
    }
    let creator = match control.store.users().get(&token.creator_user_id).await {
        Ok(Some(creator)) => creator,
        Ok(None) => return Err(refuse(Refused::CreatorUnknown)),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the creator of an admin token failed");
            return Err(TokenDenied::Server);
        }
    };
    match holder_revoked(&control.store, &creator.id, None).await {
        Ok(false) => {}
        Ok(true) => return Err(refuse(Refused::CreatorRevoked)),
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "checking the revocation of an admin token creator failed");
            return Err(TokenDenied::Server);
        }
    }
    let scope = stored_scope(&token.scope);
    if scope.dropped > 0
        && control
            .web
            .tokens
            .scope_warnings
            .admit(&token.id, control.tick())
    {
        tracing::warn!(
            target: "jaunt::control",
            jat_id = token.id.as_str(),
            dropped = scope.dropped,
            "a stored admin token names rights a token cannot hold; they are ignored"
        );
    }
    if let Decision::Limited { retry_after } =
        control.web.tokens.uses.check(&token.id, control.tick())
    {
        audit::refused(control, &token, Refused::RateLimited, client);
        return Err(TokenDenied::TooMany { retry_after });
    }
    let stale = token
        .last_used_at
        .is_none_or(|at| at < now.secs.saturating_sub(TOUCH_INTERVAL_SECS));
    if stale
        && let Err(err) = control
            .store
            .admin_tokens()
            .touch(&token.id, now.secs, TOUCH_INTERVAL_SECS)
            .await
    {
        tracing::warn!(target: "jaunt::control", error = %err, "recording the last use of an admin token failed");
    }
    Ok(TokenAdmin {
        id: token.id,
        name: token.name,
        creator,
        scope: scope.rights,
        expires_at: token.expires_at,
        client,
    })
}

fn corrupt(token: &AdminToken, column: &'static str) -> TokenDenied {
    tracing::error!(
        target: "jaunt::control",
        jat_id = token.id.as_str(),
        column,
        "a stored admin token is corrupt"
    );
    TokenDenied::Server
}

pub(crate) fn permits(token: &TokenAdmin, policy: &PolicySet, permission: AdminPermission) -> bool {
    let allowed = TOKEN_RIGHTS.contains(&permission)
        && token.scope.contains(&permission)
        && policy.admin_can(&policy_identity(&token.creator), permission);
    audit::used(token, Some(permission), allowed);
    allowed
}

pub(crate) fn effective_rights(
    token: &TokenAdmin,
    policy: &PolicySet,
) -> BTreeSet<AdminPermission> {
    let identity = policy_identity(&token.creator);
    token
        .scope
        .iter()
        .copied()
        .filter(|permission| {
            TOKEN_RIGHTS.contains(permission) && policy.admin_can(&identity, *permission)
        })
        .collect()
}
