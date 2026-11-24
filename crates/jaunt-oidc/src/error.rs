use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DiscoveryFailure {
    #[error("request to the provider failed")]
    Request,
    #[error("provider returned an unexpected response")]
    BadResponse,
    #[error("provider metadata could not be parsed")]
    Malformed,
    #[error("issuer in the provider metadata does not match the configured issuer")]
    IssuerMismatch,
    #[error("provider does not support the authorization code flow")]
    CodeFlowUnsupported,
    #[error("provider does not support PKCE with S256")]
    PkceUnsupported,
    #[error("provider offers no supported id token signing algorithm")]
    NoSupportedSigningAlgorithm,
    #[error("provider metadata has no token endpoint")]
    MissingTokenEndpoint,
    #[error("provider signing keys could not be fetched")]
    Jwks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExchangeFailure {
    #[error("authorization code is empty")]
    EmptyCode,
    #[error("pending authorization is incomplete")]
    InvalidPendingAuth,
    #[error("token endpoint is not available")]
    NoTokenEndpoint,
    #[error("request to the token endpoint failed")]
    Request,
    #[error("token endpoint rejected the request")]
    Rejected,
    #[error("token endpoint returned an unexpected response")]
    BadResponse,
    #[error("token response has no id token")]
    MissingIdToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TokenCheck {
    #[error("signature is invalid or the signing key is unknown")]
    Signature,
    #[error("signing algorithm is not allowed")]
    Algorithm,
    #[error("issuer does not match")]
    Issuer,
    #[error("audience does not include this client")]
    Audience,
    #[error("authorized party does not match this client")]
    AuthorizedParty,
    #[error("nonce does not match")]
    Nonce,
    #[error("token has expired")]
    Expired,
    #[error("token was issued in the future")]
    IssuedInFuture,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token uses an unsupported feature")]
    Unsupported,
    #[error("token is not acceptable")]
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UserInfoFailure {
    #[error("user info endpoint is not available")]
    NotAvailable,
    #[error("request to the user info endpoint failed")]
    Request,
    #[error("user info endpoint returned an unexpected response")]
    BadResponse,
    #[error("user info subject does not match the id token subject")]
    SubjectMismatch,
    #[error("user info response failed verification")]
    Verification,
}

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("invalid configuration: {field}: {reason}")]
    InvalidConfig {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} must use https, or http with a loopback host")]
    InsecureUrl { field: &'static str },
    #[error("http client could not be created")]
    HttpClient,
    #[error("provider discovery failed: {0}")]
    Discovery(DiscoveryFailure),
    #[error("state does not match the pending authorization")]
    StateMismatch,
    #[error("pending authorization has expired")]
    PendingExpired,
    #[error("authorization code exchange failed: {0}")]
    Exchange(ExchangeFailure),
    #[error("id token validation failed: {0}")]
    TokenValidation(TokenCheck),
    #[error("user info lookup failed: {0}")]
    UserInfo(UserInfoFailure),
    #[error("required claim is missing: {0}")]
    MissingClaim(String),
    #[error("claim has an invalid value: {0}")]
    InvalidClaim(String),
    #[error("email address is not verified")]
    EmailNotVerified,
}
