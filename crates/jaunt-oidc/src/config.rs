use std::time::Duration;

use openidconnect::reqwest::Certificate;
use openidconnect::url::{Host, Url};
use openidconnect::{IssuerUrl, RedirectUrl, Scope};

use crate::error::OidcError;
use crate::secret::ClientSecret;

pub const DEFAULT_SCOPES: [&str; 4] = ["openid", "email", "profile", "groups"];
pub const DEFAULT_USERNAME_CLAIM: &str = "preferred_username";
pub const DEFAULT_GROUPS_CLAIM: &str = "groups";
pub const DEFAULT_PENDING_TTL_SECS: u64 = 600;

const OPENID_SCOPE: &str = "openid";

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: ClientSecret,
    pub redirect_url: String,
    pub scopes: Vec<String>,
    pub username_claim: String,
    pub groups_claim: String,
    pub require_verified_email: bool,
    pub pending_ttl_secs: u64,
    pub extra_root_certificates_pem: Vec<String>,
}

impl OidcConfig {
    pub fn new(
        issuer_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: ClientSecret,
        redirect_url: impl Into<String>,
    ) -> Self {
        Self {
            issuer_url: issuer_url.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_url: redirect_url.into(),
            scopes: DEFAULT_SCOPES.iter().map(|s| (*s).to_owned()).collect(),
            username_claim: DEFAULT_USERNAME_CLAIM.to_owned(),
            groups_claim: DEFAULT_GROUPS_CLAIM.to_owned(),
            require_verified_email: true,
            pending_ttl_secs: DEFAULT_PENDING_TTL_SECS,
            extra_root_certificates_pem: Vec::new(),
        }
    }

    pub(crate) fn validate(&self) -> Result<ValidatedConfig, OidcError> {
        let issuer_url = parse_url("issuer_url", &self.issuer_url)?;
        if issuer_url.query().is_some() {
            return Err(invalid("issuer_url", "must not contain a query"));
        }
        parse_url("redirect_url", &self.redirect_url)?;

        require_non_empty("client_id", &self.client_id)?;
        require_non_empty("client_secret", self.client_secret.expose())?;
        require_non_empty("username_claim", &self.username_claim)?;
        require_non_empty("groups_claim", &self.groups_claim)?;
        if self.pending_ttl_secs == 0 {
            return Err(invalid("pending_ttl_secs", "must be greater than zero"));
        }

        let mut scopes: Vec<Scope> = Vec::new();
        for scope in &self.scopes {
            if !is_scope_token(scope) {
                return Err(invalid("scopes", "contains an invalid scope token"));
            }
            if scope == OPENID_SCOPE || scopes.iter().any(|known| known.as_str() == scope) {
                continue;
            }
            scopes.push(Scope::new(scope.clone()));
        }

        let mut extra_roots = Vec::new();
        for pem in &self.extra_root_certificates_pem {
            let certificates = Certificate::from_pem_bundle(pem.as_bytes()).map_err(|_| {
                invalid(
                    "extra_root_certificates_pem",
                    "contains an invalid certificate",
                )
            })?;
            if certificates.is_empty() {
                return Err(invalid(
                    "extra_root_certificates_pem",
                    "contains no certificate",
                ));
            }
            extra_roots.extend(certificates);
        }

        Ok(ValidatedConfig {
            issuer: IssuerUrl::new(self.issuer_url.clone())
                .map_err(|_| invalid("issuer_url", "is not a valid url"))?,
            redirect: RedirectUrl::new(self.redirect_url.clone())
                .map_err(|_| invalid("redirect_url", "is not a valid url"))?,
            scopes,
            pending_ttl: Duration::from_secs(self.pending_ttl_secs),
            extra_roots,
        })
    }
}

pub(crate) struct ValidatedConfig {
    pub(crate) issuer: IssuerUrl,
    pub(crate) redirect: RedirectUrl,
    pub(crate) scopes: Vec<Scope>,
    pub(crate) pending_ttl: Duration,
    pub(crate) extra_roots: Vec<Certificate>,
}

pub(crate) fn require_secure(
    field: &'static str,
    url: &Url,
    allow_plain_loopback: bool,
) -> Result<(), OidcError> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(OidcError::InsecureUrl { field });
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => Ok(()),
        ("http", Some(host)) if allow_plain_loopback && is_loopback(&host) => Ok(()),
        _ => Err(OidcError::InsecureUrl { field }),
    }
}

fn parse_url(field: &'static str, raw: &str) -> Result<Url, OidcError> {
    let url = Url::parse(raw).map_err(|_| invalid(field, "is not a valid url"))?;
    require_secure(field, &url, true)?;
    if url.fragment().is_some() {
        return Err(invalid(field, "must not contain a fragment"));
    }
    Ok(url)
}

fn is_loopback(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
        Host::Ipv4(addr) => addr.is_loopback(),
        Host::Ipv6(addr) => addr.is_loopback(),
    }
}

fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), OidcError> {
    if value.trim().is_empty() {
        return Err(invalid(field, "must not be empty"));
    }
    Ok(())
}

fn invalid(field: &'static str, reason: &'static str) -> OidcError {
    OidcError::InvalidConfig { field, reason }
}
