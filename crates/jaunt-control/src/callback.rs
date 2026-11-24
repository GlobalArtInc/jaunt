use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{ConnectInfo, Extension, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_oidc::{ExchangeFailure, OidcError, PendingAuth, UserInfoFailure};
use jaunt_store::{LoginRequest, LoginRequestState, NewUser, User};

use crate::audit::{self, DenyReason};
use crate::clock::Moment;
use crate::completion;
use crate::control::Control;
use crate::device;
use crate::http::server_error;
use crate::pending::{PendingKind, PendingLogin};
use crate::start::LOGIN_KIND;
use crate::web;

const MAX_QUERY_LEN: usize = 8 * 1024;
const LOOPBACK_HOST: &str = "127.0.0.1";

#[derive(Default)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn parse_query(query: &str) -> Option<CallbackParams> {
    if query.len() > MAX_QUERY_LEN {
        return None;
    }
    let mut params = CallbackParams::default();
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "code" => &mut params.code,
            "state" => &mut params.state,
            "error" => &mut params.error,
            _ => continue,
        };
        if slot.is_some() {
            return None;
        }
        *slot = Some(value.into_owned());
    }
    Some(params)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopbackError {
    AccessDenied,
    InvalidRequest,
    ServerError,
}

impl LoopbackError {
    const fn code(self) -> &'static str {
        match self {
            LoopbackError::AccessDenied => "access_denied",
            LoopbackError::InvalidRequest => "invalid_request",
            LoopbackError::ServerError => "server_error",
        }
    }
}

struct Denial {
    error: LoopbackError,
    reason: DenyReason,
}

fn denial(error: LoopbackError, reason: DenyReason) -> Denial {
    Denial { error, reason }
}

fn internal() -> Denial {
    denial(LoopbackError::ServerError, DenyReason::Internal)
}

fn loopback_redirect(port: u16, pairs: &[(&str, &str)]) -> Response {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    let query = serializer.finish();
    let location = format!("http://{LOOPBACK_HOST}:{port}/callback?{query}");
    match HeaderValue::try_from(location) {
        Ok(location) => {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::FOUND;
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => server_error(),
    }
}

fn oidc_denial(err: &OidcError) -> Denial {
    match err {
        OidcError::EmailNotVerified => {
            denial(LoopbackError::AccessDenied, DenyReason::EmailNotVerified)
        }
        OidcError::StateMismatch | OidcError::PendingExpired => {
            denial(LoopbackError::InvalidRequest, DenyReason::RequestExpired)
        }
        OidcError::InvalidConfig { .. }
        | OidcError::InsecureUrl { .. }
        | OidcError::HttpClient
        | OidcError::Discovery(_)
        | OidcError::Exchange(
            ExchangeFailure::NoTokenEndpoint
            | ExchangeFailure::Request
            | ExchangeFailure::BadResponse,
        )
        | OidcError::UserInfo(
            UserInfoFailure::NotAvailable | UserInfoFailure::Request | UserInfoFailure::BadResponse,
        ) => denial(LoopbackError::ServerError, DenyReason::ProviderUnavailable),
        _ => denial(LoopbackError::AccessDenied, DenyReason::IdentityRejected),
    }
}

pub(crate) async fn handle(
    State(control): State<Control>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some(params) = query.as_deref().and_then(parse_query) else {
        audit::login_denied(None, DenyReason::MalformedQuery);
        return device::page::sign_in_failed();
    };
    let Some(state) = params.state.as_deref().filter(|state| !state.is_empty()) else {
        audit::login_denied(None, DenyReason::MalformedQuery);
        return device::page::sign_in_failed();
    };
    let Some(entry) = control.pending.take(state) else {
        audit::login_denied(None, DenyReason::UnknownState);
        return device::page::sign_in_failed();
    };
    let kind = entry.kind.clone();
    let login_id = entry.login_id.clone();
    let error_reported = params.error.is_some();

    match kind {
        PendingKind::Loopback { port } => {
            match approve(&control, entry, params.code, error_reported, state).await {
                Ok(completion_code) => {
                    loopback_redirect(port, &[("login_id", &login_id), ("code", &completion_code)])
                }
                Err(denied) => {
                    audit::login_denied(Some(&login_id), denied.reason);
                    loopback_redirect(
                        port,
                        &[("error", denied.error.code()), ("login_id", &login_id)],
                    )
                }
            }
        }
        PendingKind::Device { browser_hash } => {
            if !device::browser::matches(&headers, &browser_hash) {
                audit::login_denied(Some(&login_id), DenyReason::BrowserMismatch);
                return device::page::sign_in_failed();
            }
            let signed_in = sign_in(
                &control,
                entry,
                params.code,
                error_reported,
                state,
                device::DEVICE_KIND,
            )
            .await;
            match signed_in {
                Ok(signed_in) => device::approval::offer(
                    &control,
                    &signed_in.request,
                    &signed_in.user,
                    signed_in.now.secs,
                ),
                Err(denied) => {
                    audit::login_denied(Some(&login_id), denied.reason);
                    device::page::sign_in_failed()
                }
            }
        }
        PendingKind::Web {
            return_to,
            browser_hash,
        } => {
            let mut response = match peer {
                Some(Extension(ConnectInfo(peer))) => {
                    let request = WebCallback {
                        return_to: &return_to,
                        browser_hash: &browser_hash,
                        code: params.code,
                        provider_error: error_reported,
                        state,
                        headers: &headers,
                        peer,
                    };
                    complete_web(&control, entry, request).await
                }
                None => {
                    tracing::error!(target: "jaunt::control", "the connection address is unavailable for a web sign-in");
                    web::pages::server_error()
                }
            };
            control.web.headers.apply(response.headers_mut());
            response
        }
    }
}

struct WebCallback<'a> {
    return_to: &'a str,
    browser_hash: &'a str,
    code: Option<String>,
    provider_error: bool,
    state: &'a str,
    headers: &'a HeaderMap,
    peer: SocketAddr,
}

async fn complete_web(
    control: &Control,
    entry: PendingLogin,
    request: WebCallback<'_>,
) -> Response {
    let login_id = entry.login_id.clone();
    if !web::login_binding_matches(request.headers, request.browser_hash) {
        audit::login_denied(Some(&login_id), DenyReason::BrowserMismatch);
        return web::pages::sign_in_failed();
    }
    let signed_in = sign_in_web(
        control,
        entry,
        request.code,
        request.provider_error,
        request.state,
    )
    .await;
    match signed_in {
        Ok((user, now)) => {
            web::establish(
                control,
                &login_id,
                request.return_to,
                &user,
                now,
                request.headers,
                request.peer,
            )
            .await
        }
        Err(denied) => {
            audit::login_denied(Some(&login_id), denied.reason);
            web::pages::sign_in_failed()
        }
    }
}

async fn sign_in_web(
    control: &Control,
    entry: PendingLogin,
    code: Option<String>,
    provider_error: bool,
    state: &str,
) -> Result<(User, Moment), Denial> {
    let PendingLogin {
        auth, expires_at, ..
    } = entry;
    if provider_error {
        return Err(denial(
            LoopbackError::AccessDenied,
            DenyReason::ProviderError,
        ));
    }
    let Some(code) = code.filter(|code| !code.is_empty()) else {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::MissingCode,
        ));
    };
    let now = control.now().ok_or_else(internal)?;
    if expires_at <= now.secs {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::RequestExpired,
        ));
    }
    exchange_and_store_user(control, auth, &code, state).await
}

struct SignedIn {
    request: LoginRequest,
    user: User,
    now: Moment,
}

async fn approve(
    control: &Control,
    entry: PendingLogin,
    code: Option<String>,
    provider_error: bool,
    state: &str,
) -> Result<String, Denial> {
    let signed_in = sign_in(control, entry, code, provider_error, state, LOGIN_KIND).await?;
    let SignedIn { request, user, now } = signed_in;
    let completion = completion::issue().map_err(|_| {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        internal()
    })?;
    let approved = control
        .store
        .login_requests()
        .approve(&request.id, &user.id, Some(&completion.hash), now.secs)
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "approving the login request failed");
            internal()
        })?;
    if !approved {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::ApproveLost,
        ));
    }
    audit::login_approved(&request.id, &user.id, &user.email, LOGIN_KIND);
    Ok(completion.secret)
}

async fn sign_in(
    control: &Control,
    entry: PendingLogin,
    code: Option<String>,
    provider_error: bool,
    state: &str,
    expected_kind: &str,
) -> Result<SignedIn, Denial> {
    let PendingLogin { auth, login_id, .. } = entry;
    if provider_error {
        return Err(denial(
            LoopbackError::AccessDenied,
            DenyReason::ProviderError,
        ));
    }
    let Some(code) = code.filter(|code| !code.is_empty()) else {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::MissingCode,
        ));
    };

    let requests = control.store.login_requests();
    let now = control.now().ok_or_else(internal)?;
    let request = match requests.get(&login_id).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            tracing::error!(target: "jaunt::control", "a pending login has no stored request");
            return Err(denial(
                LoopbackError::ServerError,
                DenyReason::RequestMissing,
            ));
        }
        Err(err) => {
            tracing::error!(target: "jaunt::control", error = %err, "loading the login request failed");
            return Err(internal());
        }
    };
    if request.kind != expected_kind || request.state != LoginRequestState::Pending {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::RequestNotPending,
        ));
    }
    if request.expires_at <= now.secs {
        return Err(denial(
            LoopbackError::InvalidRequest,
            DenyReason::RequestExpired,
        ));
    }

    let (user, now) = exchange_and_store_user(control, auth, &code, state).await?;
    Ok(SignedIn { request, user, now })
}

async fn exchange_and_store_user(
    control: &Control,
    auth: PendingAuth,
    code: &str,
    state: &str,
) -> Result<(User, Moment), Denial> {
    let identity = match control.oidc.complete(auth, code, state).await {
        Ok(identity) => identity,
        Err(err) => {
            tracing::warn!(target: "jaunt::control", error = %err, "the provider sign-in was not accepted");
            return Err(oidc_denial(&err));
        }
    };

    let now = control.now().ok_or_else(internal)?;
    let user = control
        .store
        .users()
        .upsert(
            &NewUser {
                issuer: identity.issuer,
                subject: identity.subject,
                email: identity.email,
                username: identity.username,
                display_name: identity.display_name,
                groups: identity.groups,
            },
            now.secs,
        )
        .await
        .map_err(|err| {
            tracing::error!(target: "jaunt::control", error = %err, "storing the user failed");
            internal()
        })?;
    Ok((user, now))
}
