use std::net::IpAddr;

use axum::body::Body;
use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};
use jaunt_store::{NewWebSession, User};

use crate::audit;
use crate::clock::Moment;
use crate::completion;
use crate::control::Control;
use crate::http::empty_response;
use crate::pending::{InsertError, PendingKind, PendingLogin};
use crate::start::LOGIN_TTL_SECS;
use crate::token;

use super::cookies;
use super::csrf;
use super::pages;
use super::{MAX_SESSIONS_PER_USER, SESSION_TTL_SECS};

const MAX_QUERY_LEN: usize = 2 * 1024;
const MAX_RETURN_TO_BYTES: usize = 256;
const MAX_USER_AGENT_CHARS: usize = 200;
const ROOT: &str = "/";

fn return_to_parameter(query: Option<&str>) -> Option<String> {
    let query = query.filter(|query| query.len() <= MAX_QUERY_LEN)?;
    let mut found = None;
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        if name != "return_to" {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.into_owned());
    }
    found
}

fn sanitized_return_to(candidate: Option<String>) -> String {
    candidate
        .filter(|path| is_same_origin_path(path))
        .unwrap_or_else(|| ROOT.to_owned())
}

fn is_same_origin_path(path: &str) -> bool {
    path.len() <= MAX_RETURN_TO_BYTES
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'\\')
}

fn redirect(location: &str) -> Option<Response> {
    let navigable = location.starts_with("https://") || location.starts_with("http://");
    if !navigable || !location.is_ascii() || location.chars().any(char::is_control) {
        return None;
    }
    let location = HeaderValue::try_from(location).ok()?;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(header::LOCATION, location);
    Some(response)
}

fn new_login_id() -> Option<String> {
    let mut bytes = [0_u8; 16];
    OsRng.try_fill_bytes(&mut bytes).ok()?;
    Some(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    let text: String = headers
        .get(header::USER_AGENT)?
        .as_bytes()
        .iter()
        .copied()
        .filter(|byte| (0x20..=0x7e).contains(byte))
        .take(MAX_USER_AGENT_CHARS)
        .map(char::from)
        .collect();
    (!text.is_empty()).then_some(text)
}

pub(crate) async fn start(
    State(control): State<Control>,
    method: Method,
    RawQuery(query): RawQuery,
) -> Response {
    if method != Method::GET {
        let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET"));
        return response;
    }
    let return_to = sanitized_return_to(return_to_parameter(query.as_deref()));
    let Some(now) = control.now() else {
        tracing::error!(target: "jaunt::control", "the clock is before the unix epoch");
        return pages::server_error();
    };
    if !control.pending.has_room(now.secs) {
        return pages::busy();
    }
    let Some(binding) = cookies::issue_login_binding() else {
        tracing::error!(target: "jaunt::control", "the browser binding could not be issued");
        return pages::server_error();
    };
    let Some(login_id) = new_login_id() else {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        return pages::server_error();
    };

    let auth = control.oidc.begin();
    let state = auth.state.clone();
    let Some(mut response) = redirect(&auth.authorize_url) else {
        tracing::error!(target: "jaunt::control", "the provider authorize url cannot be used in a redirect");
        return pages::server_error();
    };
    let entry = PendingLogin {
        auth,
        login_id: login_id.clone(),
        kind: PendingKind::Web {
            return_to,
            browser_hash: binding.hash,
        },
        expires_at: now.secs.saturating_add(LOGIN_TTL_SECS),
    };
    match control.pending.insert(state, entry, now.secs) {
        Ok(()) => {}
        Err(InsertError::Full) => return pages::busy(),
        Err(InsertError::Duplicate) => {
            tracing::error!(target: "jaunt::control", "the provider state collided with a pending login");
            return pages::server_error();
        }
    }

    audit::web_login_started(&login_id);
    response
        .headers_mut()
        .append(header::SET_COOKIE, binding.set_cookie);
    response
}

pub(crate) async fn establish(
    control: &Control,
    login_id: &str,
    return_to: &str,
    user: &User,
    now: Moment,
    headers: &HeaderMap,
    ip: IpAddr,
) -> Response {
    let Some(mut response) = pages::signed_in(return_to) else {
        tracing::error!(target: "jaunt::control", "the sign-in page cannot be built for the return path");
        return pages::server_error();
    };
    let Ok(issued) = completion::issue() else {
        tracing::error!(target: "jaunt::control", "the system entropy source failed");
        return pages::server_error();
    };
    let Some(set_session) = cookies::session_cookie(&issued.secret) else {
        tracing::error!(target: "jaunt::control", "the session cookie could not be built");
        return pages::server_error();
    };
    let expires_at = now.secs.saturating_add(SESSION_TTL_SECS);
    let stored = control
        .store
        .web_sessions()
        .create(
            &NewWebSession {
                id_hash: issued.hash,
                user_id: user.id.clone(),
                csrf_token_hash: token::hash_secret(&csrf::token_for(&issued.secret)),
                created_at: now.secs,
                expires_at,
                source_ip: Some(ip.to_string()),
                user_agent: user_agent(headers),
            },
            MAX_SESSIONS_PER_USER,
        )
        .await;
    if let Err(err) = stored {
        tracing::error!(target: "jaunt::control", error = %err, "storing the web session failed");
        return pages::server_error();
    }

    audit::login_approved(login_id, &user.id, &user.email, WEB_KIND);
    audit::web_session_created(login_id, &user.id, ip, expires_at);
    response
        .headers_mut()
        .append(header::SET_COOKIE, set_session);
    cookies::clear_login_binding(&mut response);
    response
}

const WEB_KIND: &str = "web";

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{
        MAX_RETURN_TO_BYTES, redirect, return_to_parameter, sanitized_return_to, user_agent,
    };

    fn sanitized(candidate: &str) -> String {
        sanitized_return_to(Some(candidate.to_owned()))
    }

    #[test]
    fn only_same_origin_relative_paths_survive_as_the_return_target() {
        let long_ok = format!("/{}", "a".repeat(MAX_RETURN_TO_BYTES - 1));
        let too_long = format!("/{}", "a".repeat(MAX_RETURN_TO_BYTES));
        for kept in [
            "/",
            "/a",
            "/nodes?name=web-01&page=2",
            "/a/b%2Fc#frag",
            long_ok.as_str(),
        ] {
            assert_eq!(sanitized(kept), kept);
        }
        for replaced in [
            "",
            "a",
            "//evil",
            "//evil.example/path",
            "https://evil.example",
            "http://evil.example",
            "javascript:alert(1)",
            "/\\evil",
            "/a\\b",
            "/a\nb",
            "/a\rb",
            "/a\tb",
            "/a\0b",
            "/a\u{7f}b",
            "/a b",
            "/caf\u{e9}",
            too_long.as_str(),
        ] {
            assert_eq!(sanitized(replaced), "/", "{replaced:?}");
        }
        assert_eq!(sanitized_return_to(None), "/");
    }

    #[test]
    fn the_return_target_is_read_once_from_the_query_and_decoded() {
        assert_eq!(
            return_to_parameter(Some("return_to=%2Fnodes%3Fa%3D1")).as_deref(),
            Some("/nodes?a=1")
        );
        assert_eq!(
            return_to_parameter(Some("x=1&return_to=%2Fa")).as_deref(),
            Some("/a")
        );
        assert_eq!(return_to_parameter(None), None);
        assert_eq!(return_to_parameter(Some("other=1")), None);
        assert_eq!(
            return_to_parameter(Some("return_to=%2Fa&return_to=%2Fb")),
            None
        );
        assert_eq!(
            sanitized(&return_to_parameter(Some("return_to=%2F%2Fevil")).unwrap()),
            "/"
        );
        let oversized = format!("return_to=%2F{}", "a".repeat(4096));
        assert_eq!(return_to_parameter(Some(&oversized)), None);
    }

    #[test]
    fn only_navigable_provider_urls_without_control_characters_become_redirects() {
        assert!(redirect("https://idp.example/authorize?x=1").is_some());
        for refused in [
            "javascript:alert(1)",
            "//idp.example/a",
            "/relative",
            "https://idp.example/a\r\nSet-Cookie: x=1",
            "https://idp.example/\u{e9}",
            "",
        ] {
            assert!(redirect(refused).is_none(), "{refused:?}");
        }
    }

    #[test]
    fn the_user_agent_keeps_printable_ascii_and_at_most_two_hundred_characters() {
        let mut headers = HeaderMap::new();
        assert_eq!(user_agent(&headers), None);
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static("Mozilla/5.0 (X11)"),
        );
        assert_eq!(user_agent(&headers).as_deref(), Some("Mozilla/5.0 (X11)"));
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_bytes(b"caf\xc3\xa9\t agent").unwrap(),
        );
        assert_eq!(user_agent(&headers).as_deref(), Some("caf agent"));
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&"x".repeat(500)).unwrap(),
        );
        assert_eq!(user_agent(&headers).unwrap().len(), 200);
        headers.insert(header::USER_AGENT, HeaderValue::from_static(""));
        assert_eq!(user_agent(&headers), None);
    }
}
