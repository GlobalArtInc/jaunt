use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use jaunt_oidc::{ExchangeFailure, OidcError, UserInfoFailure};
use jaunt_store::{LoginRequestState, NewUser};

use crate::audit::{self, DenyReason};
use crate::completion;
use crate::control::Control;
use crate::http::server_error;
use crate::pending::PendingLogin;
use crate::start::LOGIN_KIND;

const MAX_QUERY_LEN: usize = 8 * 1024;
const LOOPBACK_HOST: &str = "127.0.0.1";

const FAILURE_PAGE: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Sign-in failed</title><style>body{font-family:sans-serif;margin:3rem}</style></head>\
<body><h1>Sign-in failed</h1><p>The sign-in could not be completed. \
You can close this tab and start again from the terminal.</p></body></html>";

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

fn failure_page() -> Response {
    let mut response = Response::new(Body::from(FAILURE_PAGE));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
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

pub(crate) async fn handle(State(control): State<Control>, RawQuery(query): RawQuery) -> Response {
    let Some(params) = query.as_deref().and_then(parse_query) else {
        audit::login_denied(None, DenyReason::MalformedQuery);
        return failure_page();
    };
    let Some(state) = params.state.as_deref().filter(|state| !state.is_empty()) else {
        audit::login_denied(None, DenyReason::MalformedQuery);
        return failure_page();
    };
    let Some(entry) = control.pending.take(state) else {
        audit::login_denied(None, DenyReason::UnknownState);
        return failure_page();
    };
    let port = entry.redirect_port;
    let login_id = entry.login_id.clone();

    match approve(&control, entry, params.code, params.error.is_some(), state).await {
        Ok(completion_code) => {
            loopback_redirect(port, &[("login_id", &login_id), ("code", &completion_code)])
        }
        Err(denied) => {
            audit::login_denied(Some(&login_id), denied.reason);
            loopback_redirect(port, &[("error", denied.error.code())])
        }
    }
}

async fn approve(
    control: &Control,
    entry: PendingLogin,
    code: Option<String>,
    provider_error: bool,
    state: &str,
) -> Result<String, Denial> {
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
    if request.kind != LOGIN_KIND || request.state != LoginRequestState::Pending {
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

    let identity = match control.oidc.complete(auth, &code, state).await {
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
    let completion = completion::issue().map_err(|_| {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        internal()
    })?;
    let approved = requests
        .approve(&login_id, &user.id, Some(&completion.hash), now.secs)
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
    audit::login_approved(&login_id, &user.id, &user.email);
    Ok(completion.secret)
}
