use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, State as AxumState};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Header};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::key::KEY_ID;
use crate::settings::User;
use crate::state::{Grant, ID_TOKEN_TTL_SECS, State};

const SESSION_COOKIE: &str = "fake_idp_session";

type Shared = Arc<State>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(state)
}

async fn discovery(AxumState(state): AxumState<Shared>) -> Json<Value> {
    let base = &state.settings.issuer;
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
    }))
}

async fn jwks(AxumState(state): AxumState<Shared>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        state.key.jwks().to_owned(),
    )
        .into_response()
}

fn refuse_request(reason: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, reason).into_response()
}

fn redirect_with(redirect_uri: &str, pairs: &[(&str, &str)]) -> Option<(String, Response)> {
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        query.append_pair(name, value);
    }
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let location = format!("{redirect_uri}{separator}{}", query.finish());
    let header_value = HeaderValue::try_from(location.as_str()).ok()?;
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, header_value);
    Some((location, response))
}

fn redirect_error(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut pairs = vec![("error", error)];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    redirect_with(redirect_uri, &pairs)
        .map(|(_, response)| response)
        .unwrap_or_else(|| refuse_request("the redirect target cannot be used"))
}

fn session_cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|line| line.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(name, value)| (name == SESSION_COOKIE).then_some(value))
}

async fn authorize(
    AxumState(state): AxumState<Shared>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let field = |name: &str| query.get(name).map(String::as_str);
    if field("client_id") != Some(state.settings.client_id.as_str()) {
        return refuse_request("unknown client");
    }
    let Some(redirect_uri) = field("redirect_uri").filter(|uri| {
        state
            .settings
            .redirect_uris
            .iter()
            .any(|known| known == uri)
    }) else {
        return refuse_request("redirect_uri is not registered for this client");
    };
    let echoed_state = field("state");
    if field("response_type") != Some("code") {
        return redirect_error(redirect_uri, "unsupported_response_type", echoed_state);
    }
    let challenge = field("code_challenge").filter(|value| !value.is_empty());
    if field("code_challenge_method") != Some("S256") || challenge.is_none() {
        return redirect_error(redirect_uri, "invalid_request", echoed_state);
    }
    let now = Instant::now();
    let mut new_session = None;
    let user = match field("login_hint") {
        Some(hint) => match state.user_for_hint(hint) {
            Some(user) => {
                new_session = Some(state.open_session(user.clone(), now));
                user
            }
            None => return redirect_error(redirect_uri, "access_denied", echoed_state),
        },
        None => match session_cookie_value(&headers).and_then(|id| state.session_user(id, now)) {
            Some(user) => user,
            None => return redirect_error(redirect_uri, "login_required", echoed_state),
        },
    };
    let code = state.issue_code(
        Grant {
            challenge: challenge.unwrap_or_default().to_owned(),
            nonce: field("nonce").map(str::to_owned),
            redirect_uri: redirect_uri.to_owned(),
            user,
        },
        now,
    );
    let mut pairs = vec![("code", code.as_str())];
    if let Some(echoed) = echoed_state {
        pairs.push(("state", echoed));
    }
    let Some((_, mut response)) = redirect_with(redirect_uri, &pairs) else {
        return refuse_request("the redirect target cannot be used");
    };
    if let Some(id) = new_session
        && let Ok(cookie) = HeaderValue::try_from(format!(
            "{SESSION_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax"
        ))
    {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

fn client_authenticated(
    state: &State,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> bool {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|value| STANDARD.decode(value).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok());
    let settings = &state.settings;
    match basic {
        Some(pair) => pair == format!("{}:{}", settings.client_id, settings.client_secret),
        None => {
            form.get("client_id") == Some(&settings.client_id)
                && form.get("client_secret") == Some(&settings.client_secret)
        }
    }
}

async fn token(
    AxumState(state): AxumState<Shared>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !client_authenticated(&state, &headers, &form) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let field = |name: &str| form.get(name).map(String::as_str);
    if field("grant_type") != Some("authorization_code") {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let grant = field("code").and_then(|code| state.take_code(code, Instant::now()));
    let Some(grant) = grant else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let derived = field("code_verifier")
        .map(|verifier| URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())));
    if derived.as_deref() != Some(grant.challenge.as_str())
        || field("redirect_uri") != Some(grant.redirect_uri.as_str())
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let Some(id_token) = mint_id_token(&state, &grant) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let mut response = Json(json!({
        "access_token": "fake-idp-access-token",
        "token_type": "Bearer",
        "expires_in": ID_TOKEN_TTL_SECS,
        "id_token": id_token,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn claims_for(state: &State, user: &User, nonce: Option<&str>, issued: u64) -> Value {
    let mut claims = json!({
        "iss": state.settings.issuer,
        "aud": state.settings.client_id,
        "sub": user.subject,
        "iat": issued,
        "exp": issued + ID_TOKEN_TTL_SECS,
        "email": user.email,
        "email_verified": user.email_verified,
        "preferred_username": user.username,
        "name": user.name,
        "groups": user.groups,
    });
    if let (Some(nonce), Some(object)) = (nonce, claims.as_object_mut()) {
        object.insert("nonce".to_owned(), json!(nonce));
    }
    claims
}

fn mint_id_token(state: &State, grant: &Grant) -> Option<String> {
    let issued = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let claims = claims_for(state, &grant.user, grant.nonce.as_deref(), issued);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KEY_ID.to_owned());
    jsonwebtoken::encode(&header, &claims, state.key.encoding()).ok()
}

#[cfg(test)]
mod tests;
