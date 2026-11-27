use jaunt_store::User;

use super::session::WebSession;

const WEB_ACTOR_PREFIX: &str = "web:";
const SIGNED_ACTOR_PREFIX: &str = "signed:";
const SIGNED_BINDING_PREFIX: &str = "serial:";

#[derive(Clone)]
pub(crate) struct SignedAdmin {
    pub(crate) user: User,
    pub(crate) serial: i64,
}

#[derive(Clone)]
pub(crate) enum AdminPrincipal {
    WebSession(WebSession),
    SignedRequest(SignedAdmin),
}

impl AdminPrincipal {
    pub(crate) fn user(&self) -> &User {
        match self {
            AdminPrincipal::WebSession(session) => session.user(),
            AdminPrincipal::SignedRequest(signed) => &signed.user,
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
        }
    }

    pub(crate) fn binding(&self) -> String {
        match self {
            AdminPrincipal::WebSession(session) => session.0.session.id_hash.clone(),
            AdminPrincipal::SignedRequest(signed) => {
                format!("{SIGNED_BINDING_PREFIX}{}", signed.serial)
            }
        }
    }

    pub(crate) fn serial(&self) -> Option<i64> {
        match self {
            AdminPrincipal::WebSession(_) => None,
            AdminPrincipal::SignedRequest(signed) => Some(signed.serial),
        }
    }
}
