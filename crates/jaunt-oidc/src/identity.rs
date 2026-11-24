use serde_json::{Map, Value};

use crate::error::OidcError;

pub(crate) type Claims = Map<String, Value>;

const MAX_VALUE_BYTES: usize = 256;
const MAX_GROUPS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub username: String,
    pub groups: Vec<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct IdentityRules {
    pub(crate) username_claim: String,
    pub(crate) groups_claim: String,
    pub(crate) require_verified_email: bool,
}

impl IdentityRules {
    pub(crate) fn needs_userinfo(&self, id_token_claims: &Claims) -> bool {
        let mut wanted = vec![
            "email",
            self.username_claim.as_str(),
            self.groups_claim.as_str(),
        ];
        if self.require_verified_email {
            wanted.push("email_verified");
        }
        wanted
            .into_iter()
            .any(|name| non_null(id_token_claims.get(name)).is_none())
    }

    pub(crate) fn build(
        &self,
        issuer: &str,
        subject: &str,
        id_token_claims: &Claims,
        userinfo_claims: Option<&Claims>,
    ) -> Result<OidcIdentity, OidcError> {
        if subject.is_empty() {
            return Err(OidcError::MissingClaim("sub".to_owned()));
        }

        let id = id_token_claims;
        let ui = userinfo_claims;

        let id_email = non_null(id.get("email"));
        let ui_email = ui.and_then(|claims| non_null(claims.get("email")));
        let (email_value, email_from_userinfo) = match (id_email, ui_email) {
            (Some(value), _) => (value, false),
            (None, Some(value)) => (value, true),
            (None, None) => return Err(OidcError::MissingClaim("email".to_owned())),
        };
        let email = text_claim("email", email_value)?;
        let local_part = match email.split_once('@') {
            Some((local, domain))
                if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
            {
                local.to_owned()
            }
            _ => return Err(OidcError::InvalidClaim("email".to_owned())),
        };

        let verified_value = if email_from_userinfo {
            ui.and_then(|claims| non_null(claims.get("email_verified")))
        } else {
            non_null(id.get("email_verified")).or_else(|| {
                ui.filter(|claims| userinfo_email_matches(claims, &email))
                    .and_then(|claims| non_null(claims.get("email_verified")))
            })
        };
        let email_verified = match verified_value {
            None => false,
            Some(Value::Bool(flag)) => *flag,
            Some(_) => return Err(OidcError::InvalidClaim("email_verified".to_owned())),
        };
        if self.require_verified_email && !email_verified {
            return Err(OidcError::EmailNotVerified);
        }

        let username = match lookup(&self.username_claim, id, ui) {
            Some(value) => text_claim(&self.username_claim, value)?,
            None => local_part,
        };

        let groups = groups_claim(&self.groups_claim, lookup(&self.groups_claim, id, ui))?;

        let display_name = lookup("name", id, ui).and_then(|value| text_claim("name", value).ok());

        Ok(OidcIdentity {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
            email,
            email_verified,
            username,
            groups,
            display_name,
        })
    }
}

fn non_null(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| !v.is_null())
}

fn lookup<'a>(name: &str, id: &'a Claims, userinfo: Option<&'a Claims>) -> Option<&'a Value> {
    non_null(id.get(name)).or_else(|| userinfo.and_then(|claims| non_null(claims.get(name))))
}

fn userinfo_email_matches(userinfo: &Claims, email: &str) -> bool {
    userinfo
        .get("email")
        .and_then(Value::as_str)
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(email))
}

fn text_claim(name: &str, value: &Value) -> Result<String, OidcError> {
    match value.as_str() {
        Some(text)
            if !text.is_empty()
                && text.len() <= MAX_VALUE_BYTES
                && !text.chars().any(char::is_control) =>
        {
            Ok(text.to_owned())
        }
        _ => Err(OidcError::InvalidClaim(name.to_owned())),
    }
}

fn groups_claim(name: &str, value: Option<&Value>) -> Result<Vec<String>, OidcError> {
    match value {
        None => Ok(Vec::new()),
        Some(single @ Value::String(_)) => Ok(vec![text_claim(name, single)?]),
        Some(Value::Array(items)) if items.len() <= MAX_GROUPS => {
            items.iter().map(|item| text_claim(name, item)).collect()
        }
        Some(_) => Err(OidcError::InvalidClaim(name.to_owned())),
    }
}
