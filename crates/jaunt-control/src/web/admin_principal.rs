use std::collections::BTreeSet;
use std::net::IpAddr;

use jaunt_policy::AdminPermission;
use jaunt_store::User;

use super::session::WebSession;

const WEB_ACTOR_PREFIX: &str = "web:";
const SIGNED_ACTOR_PREFIX: &str = "signed:";
const SIGNED_BINDING_PREFIX: &str = "serial:";
const TOKEN_ACTOR_PREFIX: &str = "token:";

#[derive(Clone)]
pub(crate) struct SignedAdmin {
    pub(crate) user: User,
    pub(crate) serial: i64,
}

#[derive(Clone)]
pub(crate) struct TokenAdmin {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) creator: User,
    pub(crate) scope: BTreeSet<AdminPermission>,
    pub(crate) expires_at: i64,
    pub(crate) client: Option<IpAddr>,
}

#[derive(Clone)]
pub(crate) enum AdminPrincipal {
    WebSession(WebSession),
    SignedRequest(SignedAdmin),
    Token(TokenAdmin),
}

impl AdminPrincipal {
    pub(crate) fn user(&self) -> &User {
        match self {
            AdminPrincipal::WebSession(session) => session.user(),
            AdminPrincipal::SignedRequest(signed) => &signed.user,
            AdminPrincipal::Token(token) => &token.creator,
        }
    }

    pub(crate) fn actor(&self) -> String {
        match self {
            AdminPrincipal::WebSession(session) => {
                format!("{WEB_ACTOR_PREFIX}{}", session.user().id)
            }
            AdminPrincipal::SignedRequest(signed) => {
                format!("{SIGNED_ACTOR_PREFIX}{}", signed.user.id)
            }
            AdminPrincipal::Token(token) => format!("{TOKEN_ACTOR_PREFIX}{}", token.id),
        }
    }

    pub(crate) fn binding(&self) -> String {
        match self {
            AdminPrincipal::WebSession(session) => session.0.session.id_hash.clone(),
            AdminPrincipal::SignedRequest(signed) => {
                format!("{SIGNED_BINDING_PREFIX}{}", signed.serial)
            }
            AdminPrincipal::Token(token) => format!("{TOKEN_ACTOR_PREFIX}{}", token.id),
        }
    }

    pub(crate) fn token_id(&self) -> Option<&str> {
        match self {
            AdminPrincipal::WebSession(_) | AdminPrincipal::SignedRequest(_) => None,
            AdminPrincipal::Token(token) => Some(&token.id),
        }
    }

    pub(crate) fn serial(&self) -> Option<i64> {
        match self {
            AdminPrincipal::WebSession(_) | AdminPrincipal::Token(_) => None,
            AdminPrincipal::SignedRequest(signed) => Some(signed.serial),
        }
    }
}
