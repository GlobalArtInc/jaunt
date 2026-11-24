use std::fmt;
use std::time::{Duration, Instant, SystemTime};

use chrono::{TimeDelta, Utc};
use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClaimName, CoreClaimType,
    CoreClientAuthMethod, CoreErrorResponseType, CoreGenderClaim, CoreGrantType, CoreJsonWebKey,
    CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJwsSigningAlgorithm, CoreResponseMode, CoreResponseType, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreSubjectIdentifierType, CoreTokenIntrospectionResponse,
    CoreTokenType,
};
use openidconnect::reqwest;
use openidconnect::{
    AdditionalClaims, AdditionalProviderMetadata, AsyncHttpClient, AuthType, AuthorizationCode,
    ClaimsVerificationError, ClientId, ClientSecret as ProviderClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, ErrorResponse, IdToken,
    IdTokenClaims, IdTokenFields, IdTokenVerifier, IssuerUrl, JsonWebKeySetUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, RequestTokenError,
    Scope, SignatureVerificationError, StandardErrorResponse, StandardTokenResponse, TokenResponse,
    UserInfoClaims, UserInfoError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, RwLock};

use crate::config::{OidcConfig, require_secure};
use crate::error::{DiscoveryFailure, ExchangeFailure, OidcError, TokenCheck, UserInfoFailure};
use crate::identity::{Claims, IdentityRules, OidcIdentity};
use crate::secret::Secret;

const CLOCK_SKEW_SECONDS: i64 = 60;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const PKCE_METHOD: &str = "S256";
const DISCOVERY_PATH: &str = ".well-known/openid-configuration";

const ALLOWED_ALGORITHMS: [CoreJwsSigningAlgorithm; 3] = [
    CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
    CoreJwsSigningAlgorithm::EcdsaP256Sha256,
    CoreJwsSigningAlgorithm::EdDsa,
];

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct ExtraClaims {
    #[serde(flatten)]
    values: Claims,
}

impl AdditionalClaims for ExtraClaims {}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct PkceMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code_challenge_methods_supported: Option<Vec<String>>,
}

impl AdditionalProviderMetadata for PkceMetadata {}

type Metadata = ProviderMetadata<
    PkceMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

type ProviderIdToken = IdToken<
    ExtraClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

type ProviderIdTokenClaims = IdTokenClaims<ExtraClaims, CoreGenderClaim>;

type ProviderTokenResponse = StandardTokenResponse<
    IdTokenFields<
        ExtraClaims,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

type ProviderClient = openidconnect::Client<
    ExtraClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    ProviderTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct PendingAuth {
    pub authorize_url: String,
    pub state: String,
    pub nonce: Secret,
    pub pkce_verifier: Secret,
    pub created_at: SystemTime,
}

impl fmt::Debug for PendingAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = self
            .authorize_url
            .split(['?', '#'])
            .next()
            .unwrap_or_default();
        f.debug_struct("PendingAuth")
            .field("authorize_url", &location)
            .field("state", &"[redacted]")
            .field("nonce", &self.nonce)
            .field("pkce_verifier", &self.pkce_verifier)
            .finish()
    }
}

pub struct OidcClient {
    http: reqwest::Client,
    provider: ProviderClient,
    issuer: IssuerUrl,
    client_id: ClientId,
    jwks_url: JsonWebKeySetUrl,
    jwks: RwLock<CoreJsonWebKeySet>,
    last_jwks_refresh: Mutex<Option<Instant>>,
    scopes: Vec<Scope>,
    pending_ttl: Duration,
    rules: IdentityRules,
}

impl fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OidcClient")
            .field("issuer", &self.issuer.as_str())
            .field("client_id", &self.client_id.as_str())
            .finish_non_exhaustive()
    }
}

impl OidcClient {
    pub async fn discover(config: OidcConfig) -> Result<Self, OidcError> {
        let validated = config.validate()?;
        let http = build_http_client(validated.extra_roots)?;

        let metadata = fetch_metadata(&http, &validated.issuer).await?;

        let client_id = ClientId::new(config.client_id.clone());
        let provider = ProviderClient::from_provider_metadata(
            metadata.clone(),
            client_id.clone(),
            Some(ProviderClientSecret::new(
                config.client_secret.expose().to_owned(),
            )),
        )
        .set_redirect_uri(validated.redirect)
        .set_auth_type(select_auth_type(&metadata));

        Ok(Self {
            http,
            provider,
            issuer: validated.issuer,
            client_id,
            jwks_url: metadata.jwks_uri().clone(),
            jwks: RwLock::new(metadata.jwks().clone()),
            last_jwks_refresh: Mutex::new(None),
            scopes: validated.scopes,
            pending_ttl: validated.pending_ttl,
            rules: IdentityRules {
                username_claim: config.username_claim,
                groups_claim: config.groups_claim,
                require_verified_email: config.require_verified_email,
            },
        })
    }

    pub fn begin(&self) -> PendingAuth {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut request = self
            .provider
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            request = request.add_scope(scope.clone());
        }
        let (url, state, nonce) = request.url();
        PendingAuth {
            authorize_url: url.to_string(),
            state: state.secret().clone(),
            nonce: Secret::new(nonce.secret().clone()),
            pkce_verifier: Secret::new(verifier.secret().clone()),
            created_at: SystemTime::now(),
        }
    }

    pub async fn complete(
        &self,
        pending: PendingAuth,
        code: &str,
        returned_state: &str,
    ) -> Result<OidcIdentity, OidcError> {
        if pending.state.is_empty() || !constant_time_eq(&pending.state, returned_state) {
            return Err(OidcError::StateMismatch);
        }
        if self.is_expired(pending.created_at) {
            return Err(OidcError::PendingExpired);
        }
        if pending.nonce.expose().is_empty() || pending.pkce_verifier.expose().is_empty() {
            return Err(OidcError::Exchange(ExchangeFailure::InvalidPendingAuth));
        }
        if code.is_empty() {
            return Err(OidcError::Exchange(ExchangeFailure::EmptyCode));
        }

        let token_response = self
            .provider
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|_| OidcError::Exchange(ExchangeFailure::NoTokenEndpoint))?
            .set_pkce_verifier(PkceCodeVerifier::new(
                pending.pkce_verifier.expose().to_owned(),
            ))
            .request_async(&self.http)
            .await
            .map_err(map_token_error)?;

        let id_token = token_response
            .id_token()
            .ok_or(OidcError::Exchange(ExchangeFailure::MissingIdToken))?;
        let nonce = Nonce::new(pending.nonce.expose().to_owned());
        let claims = self.verified_claims(id_token, &nonce).await?;
        self.check_issue_time_and_party(claims)?;

        let id_token_claims = to_claims(claims)?;
        check_not_before(&id_token_claims)?;
        let userinfo_claims = if self.rules.needs_userinfo(&id_token_claims) {
            self.fetch_userinfo(&token_response, claims).await?
        } else {
            None
        };

        self.rules.build(
            self.issuer.as_str(),
            claims.subject().as_str(),
            &id_token_claims,
            userinfo_claims.as_ref(),
        )
    }

    async fn verified_claims<'t>(
        &self,
        id_token: &'t ProviderIdToken,
        nonce: &Nonce,
    ) -> Result<&'t ProviderIdTokenClaims, OidcError> {
        let current = self.jwks.read().await.clone();
        match self.verify(id_token, nonce, current) {
            Ok(claims) => Ok(claims),
            Err(ClaimsVerificationError::SignatureVerification(
                SignatureVerificationError::NoMatchingKey,
            )) => {
                let fresh = self.refresh_jwks().await?;
                self.verify(id_token, nonce, fresh)
                    .map_err(map_verification_error)
            }
            Err(other) => Err(map_verification_error(other)),
        }
    }

    fn verify<'t>(
        &self,
        id_token: &'t ProviderIdToken,
        nonce: &Nonce,
        jwks: CoreJsonWebKeySet,
    ) -> Result<&'t ProviderIdTokenClaims, ClaimsVerificationError> {
        let verifier =
            IdTokenVerifier::new_public_client(self.client_id.clone(), self.issuer.clone(), jwks)
                .set_allowed_algs(ALLOWED_ALGORITHMS)
                .set_other_audience_verifier_fn(|_| true)
                .set_time_fn(|| Utc::now() - TimeDelta::seconds(CLOCK_SKEW_SECONDS));
        id_token.claims(&verifier, nonce)
    }

    async fn refresh_jwks(&self) -> Result<CoreJsonWebKeySet, OidcError> {
        let mut last_refresh = self.last_jwks_refresh.lock().await;
        if last_refresh.is_some_and(|at| at.elapsed() < JWKS_REFRESH_INTERVAL) {
            return Ok(self.jwks.read().await.clone());
        }
        *last_refresh = Some(Instant::now());
        let fresh = CoreJsonWebKeySet::fetch_async(&self.jwks_url, &self.http)
            .await
            .map_err(|_| OidcError::Discovery(DiscoveryFailure::Jwks))?;
        *self.jwks.write().await = fresh.clone();
        Ok(fresh)
    }

    fn is_expired(&self, created_at: SystemTime) -> bool {
        match SystemTime::now().duration_since(created_at) {
            Ok(age) => age > self.pending_ttl,
            Err(ahead) => ahead.duration() > Duration::from_secs(CLOCK_SKEW_SECONDS.unsigned_abs()),
        }
    }

    fn check_issue_time_and_party(&self, claims: &ProviderIdTokenClaims) -> Result<(), OidcError> {
        if claims.issue_time() > Utc::now() + TimeDelta::seconds(CLOCK_SKEW_SECONDS) {
            return Err(OidcError::TokenValidation(TokenCheck::IssuedInFuture));
        }
        match claims.authorized_party() {
            Some(party) if *party != self.client_id => {
                Err(OidcError::TokenValidation(TokenCheck::AuthorizedParty))
            }
            None if claims.audiences().len() > 1 => {
                Err(OidcError::TokenValidation(TokenCheck::AuthorizedParty))
            }
            _ => Ok(()),
        }
    }

    async fn fetch_userinfo(
        &self,
        token_response: &ProviderTokenResponse,
        claims: &ProviderIdTokenClaims,
    ) -> Result<Option<Claims>, OidcError> {
        if self.provider.user_info_url().is_none() {
            return Ok(None);
        }
        let userinfo: UserInfoClaims<ExtraClaims, CoreGenderClaim> = self
            .provider
            .user_info(
                token_response.access_token().clone(),
                Some(claims.subject().clone()),
            )
            .map_err(|_| OidcError::UserInfo(UserInfoFailure::NotAvailable))?
            .request_async(&self.http)
            .await
            .map_err(map_userinfo_error)?;
        to_claims(&userinfo).map(Some)
    }
}

fn build_http_client(extra_roots: Vec<reqwest::Certificate>) -> Result<reqwest::Client, OidcError> {
    let has_extra_roots = !extra_roots.is_empty();
    let mut builder = reqwest::ClientBuilder::new()
        .use_rustls_tls()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);
    for root in extra_roots {
        builder = builder.add_root_certificate(root);
    }
    builder.build().map_err(|_| {
        if has_extra_roots {
            OidcError::InvalidConfig {
                field: "extra_root_certificates_pem",
                reason: "contains a certificate that cannot be trusted",
            }
        } else {
            OidcError::HttpClient
        }
    })
}

fn check_not_before(claims: &Claims) -> Result<(), OidcError> {
    let Some(value) = claims.get("nbf").filter(|v| !v.is_null()) else {
        return Ok(());
    };
    let not_before = value
        .as_f64()
        .ok_or_else(|| OidcError::InvalidClaim("nbf".to_owned()))?;
    let latest_allowed = Utc::now().timestamp() + CLOCK_SKEW_SECONDS;
    if not_before > latest_allowed as f64 {
        return Err(OidcError::TokenValidation(TokenCheck::NotYetValid));
    }
    Ok(())
}

fn discovery_error(failure: DiscoveryFailure) -> OidcError {
    OidcError::Discovery(failure)
}

async fn fetch_metadata(http: &reqwest::Client, issuer: &IssuerUrl) -> Result<Metadata, OidcError> {
    let url = issuer
        .join(DISCOVERY_PATH)
        .map_err(|_| discovery_error(DiscoveryFailure::Malformed))?;
    let request = openidconnect::http::Request::builder()
        .method(openidconnect::http::Method::GET)
        .uri(url.as_str())
        .header(openidconnect::http::header::ACCEPT, "application/json")
        .body(Vec::new())
        .map_err(|_| discovery_error(DiscoveryFailure::Malformed))?;
    let response = http
        .call(request)
        .await
        .map_err(|_| discovery_error(DiscoveryFailure::Request))?;
    if response.status() != openidconnect::http::StatusCode::OK {
        return Err(discovery_error(DiscoveryFailure::BadResponse));
    }
    let metadata: Metadata = serde_json::from_slice(response.body())
        .map_err(|_| discovery_error(DiscoveryFailure::Malformed))?;
    if metadata.issuer() != issuer {
        return Err(discovery_error(DiscoveryFailure::IssuerMismatch));
    }
    check_metadata(&metadata, issuer.url().scheme() == "http")?;
    let jwks = CoreJsonWebKeySet::fetch_async(metadata.jwks_uri(), http)
        .await
        .map_err(|_| discovery_error(DiscoveryFailure::Jwks))?;
    Ok(metadata.set_jwks(jwks))
}

fn check_metadata(metadata: &Metadata, allow_plain_loopback: bool) -> Result<(), OidcError> {
    require_secure(
        "authorization_endpoint",
        metadata.authorization_endpoint().url(),
        allow_plain_loopback,
    )?;
    require_secure("jwks_uri", metadata.jwks_uri().url(), allow_plain_loopback)?;
    if let Some(userinfo) = metadata.userinfo_endpoint() {
        require_secure("userinfo_endpoint", userinfo.url(), allow_plain_loopback)?;
    }
    let token_endpoint = metadata
        .token_endpoint()
        .ok_or(OidcError::Discovery(DiscoveryFailure::MissingTokenEndpoint))?;
    require_secure("token_endpoint", token_endpoint.url(), allow_plain_loopback)?;

    let code_response = metadata
        .response_types_supported()
        .iter()
        .any(|types| matches!(types.as_slice(), [CoreResponseType::Code]));
    let code_grant = metadata
        .grant_types_supported()
        .is_none_or(|grants| grants.contains(&CoreGrantType::AuthorizationCode));
    if !code_response || !code_grant {
        return Err(OidcError::Discovery(DiscoveryFailure::CodeFlowUnsupported));
    }

    if let Some(methods) = &metadata
        .additional_metadata()
        .code_challenge_methods_supported
        && !methods.iter().any(|method| method == PKCE_METHOD)
    {
        return Err(OidcError::Discovery(DiscoveryFailure::PkceUnsupported));
    }

    let usable_algorithm = metadata
        .id_token_signing_alg_values_supported()
        .iter()
        .any(|alg| ALLOWED_ALGORITHMS.contains(alg));
    if !usable_algorithm {
        return Err(OidcError::Discovery(
            DiscoveryFailure::NoSupportedSigningAlgorithm,
        ));
    }
    Ok(())
}

fn select_auth_type(metadata: &Metadata) -> AuthType {
    match metadata.token_endpoint_auth_methods_supported() {
        Some(methods)
            if !methods.contains(&CoreClientAuthMethod::ClientSecretBasic)
                && methods.contains(&CoreClientAuthMethod::ClientSecretPost) =>
        {
            AuthType::RequestBody
        }
        _ => AuthType::BasicAuth,
    }
}

fn constant_time_eq(expected: &str, actual: &str) -> bool {
    expected.as_bytes().ct_eq(actual.as_bytes()).into()
}

fn to_claims<T: Serialize>(source: &T) -> Result<Claims, OidcError> {
    match serde_json::to_value(source) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(OidcError::InvalidClaim("claims".to_owned())),
    }
}

fn map_token_error<E, T>(err: RequestTokenError<E, T>) -> OidcError
where
    E: std::error::Error + 'static,
    T: ErrorResponse + 'static,
{
    OidcError::Exchange(match err {
        RequestTokenError::Request(_) => ExchangeFailure::Request,
        RequestTokenError::ServerResponse(_) => ExchangeFailure::Rejected,
        _ => ExchangeFailure::BadResponse,
    })
}

fn map_userinfo_error<E: std::error::Error + 'static>(err: UserInfoError<E>) -> OidcError {
    OidcError::UserInfo(match err {
        UserInfoError::Request(_) => UserInfoFailure::Request,
        UserInfoError::ClaimsVerification(ClaimsVerificationError::InvalidSubject(_)) => {
            UserInfoFailure::SubjectMismatch
        }
        UserInfoError::ClaimsVerification(_) => UserInfoFailure::Verification,
        _ => UserInfoFailure::BadResponse,
    })
}

fn map_verification_error(err: ClaimsVerificationError) -> OidcError {
    OidcError::TokenValidation(match err {
        ClaimsVerificationError::Expired(_) => TokenCheck::Expired,
        ClaimsVerificationError::InvalidAudience(_) => TokenCheck::Audience,
        ClaimsVerificationError::InvalidIssuer(_) => TokenCheck::Issuer,
        ClaimsVerificationError::InvalidNonce(_) => TokenCheck::Nonce,
        ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::DisallowedAlg(_)
            | SignatureVerificationError::UnsupportedAlg(_)
            | SignatureVerificationError::NoSignature,
        ) => TokenCheck::Algorithm,
        ClaimsVerificationError::SignatureVerification(_) => TokenCheck::Signature,
        ClaimsVerificationError::Unsupported(_) => TokenCheck::Unsupported,
        _ => TokenCheck::Other,
    })
}
