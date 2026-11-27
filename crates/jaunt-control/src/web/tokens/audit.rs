use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use jaunt_limits::{ClientKey, Rate, RateLimiter};
use jaunt_policy::AdminPermission;
use jaunt_store::AdminToken;

use crate::control::Control;
use crate::web::admin_principal::TokenAdmin;

const REFUSALS_PER_TOKEN: Rate = Rate::clamped(5, 6);
const REFUSAL_TOKENS_TRACKED: usize = 4096;
const ALLOWED: &str = "allowed";
const DENIED: &str = "denied";
const REFUSED: &str = "refused";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unproven {
    Malformed,
    UnknownId,
    BadSecret,
    Ambiguous,
}

impl Unproven {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Unproven::Malformed => "malformed",
            Unproven::UnknownId => "unknown_id",
            Unproven::BadSecret => "bad_secret",
            Unproven::Ambiguous => "ambiguous",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Revoked,
    Expired,
    Address,
    CreatorUnknown,
    CreatorRevoked,
    RateLimited,
}

impl Refused {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Refused::Revoked => "revoked",
            Refused::Expired => "expired",
            Refused::Address => "address",
            Refused::CreatorUnknown => "creator_unknown",
            Refused::CreatorRevoked => "creator_revoked",
            Refused::RateLimited => "rate_limited",
        }
    }
}

pub(crate) struct RefusalLog {
    per_token: RateLimiter<String>,
    held_back: AtomicU64,
}

impl Default for RefusalLog {
    fn default() -> Self {
        RefusalLog {
            per_token: RateLimiter::new(REFUSALS_PER_TOKEN, REFUSAL_TOKENS_TRACKED),
            held_back: AtomicU64::new(0),
        }
    }
}

impl RefusalLog {
    fn admit(&self, id: &str, now: Duration) -> Option<u64> {
        if self.per_token.check(&id.to_owned(), now).is_allowed() {
            Some(self.held_back.swap(0, Ordering::Relaxed))
        } else {
            self.held_back.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    pub(crate) fn sweep(&self, now: Duration) {
        self.per_token.sweep(now);
    }
}

pub(crate) fn unproven(control: &Control, reason: Unproven, client: Option<IpAddr>) {
    let address = client.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let Some(suppressed) = control
        .web
        .tokens
        .unproven
        .admit(ClientKey::of(address), control.tick())
    else {
        return;
    };
    tracing::info!(
        target: "jaunt::audit",
        event = "token.refused",
        reason = reason.code(),
        client_addr = %address,
        suppressed
    );
}

pub(crate) fn refused(
    control: &Control,
    token: &AdminToken,
    reason: Refused,
    client: Option<IpAddr>,
) {
    let Some(suppressed) = control.web.tokens.refusals.admit(&token.id, control.tick()) else {
        return;
    };
    let client_addr = client.map(|ip| ip.to_canonical().to_string());
    tracing::info!(
        target: "jaunt::audit",
        event = "token.used",
        jat_id = token.id.as_str(),
        user_id = token.creator_user_id.as_str(),
        decision = REFUSED,
        reason = reason.code(),
        client_addr = client_addr.as_deref(),
        suppressed
    );
}

pub(crate) fn used(token: &TokenAdmin, permission: Option<AdminPermission>, allowed: bool) {
    let client_addr = token.client.map(|ip| ip.to_canonical().to_string());
    let decision = if allowed { ALLOWED } else { DENIED };
    tracing::info!(
        target: "jaunt::audit",
        event = "token.used",
        jat_id = token.id.as_str(),
        user_id = token.creator.id.as_str(),
        permission = permission.map(|permission| permission.as_str()),
        decision,
        client_addr = client_addr.as_deref()
    );
}

pub(crate) fn created(token: &AdminToken, created_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "token.created",
        jat_id = token.id.as_str(),
        name = token.name.as_str(),
        scope = token.scope.join(",").as_str(),
        cidrs = token.cidrs.join(",").as_str(),
        expires_at = token.expires_at,
        created_by
    );
}

pub(crate) fn revoked(token: &AdminToken, revoked_by: &str) {
    tracing::info!(
        target: "jaunt::audit",
        event = "token.revoked",
        jat_id = token.id.as_str(),
        name = token.name.as_str(),
        creator = token.creator_user_id.as_str(),
        revoked_by
    );
}
