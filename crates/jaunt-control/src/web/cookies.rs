use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;

use crate::completion;
use crate::start::LOGIN_TTL_SECS;

use super::SESSION_TTL_SECS;

pub(crate) const SESSION_COOKIE: &str = "__Host-jaunt";
pub(crate) const LOGIN_COOKIE: &str = "__Host-jaunt-web-login";

const CLEARED_SESSION: &str = "__Host-jaunt=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";
const CLEARED_LOGIN: &str =
    "__Host-jaunt-web-login=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";

pub(crate) struct LoginBinding {
    pub(crate) set_cookie: HeaderValue,
    pub(crate) hash: String,
}

pub(crate) fn issue_login_binding() -> Option<LoginBinding> {
    let issued = completion::issue().ok()?;
    let set_cookie = HeaderValue::try_from(format!(
        "{LOGIN_COOKIE}={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age={LOGIN_TTL_SECS}",
        issued.secret
    ))
    .ok()?;
    Some(LoginBinding {
        set_cookie,
        hash: issued.hash,
    })
}

pub(crate) fn session_cookie(secret: &str) -> Option<HeaderValue> {
    HeaderValue::try_from(format!(
        "{SESSION_COOKIE}={secret}; Secure; HttpOnly; SameSite=Strict; Path=/; \
         Max-Age={SESSION_TTL_SECS}"
    ))
    .ok()
}

pub(crate) fn clear_session(response: &mut Response) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_static(CLEARED_SESSION),
    );
}

pub(crate) fn clear_login_binding(response: &mut Response) {
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_static(CLEARED_LOGIN));
}

pub(crate) fn presented<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found: Option<&str> = None;
    for line in headers.get_all(header::COOKIE) {
        let Ok(text) = line.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((cookie_name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if cookie_name != name {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

pub(crate) fn carries(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|line| line.to_str().ok())
        .flat_map(|text| text.split(';'))
        .any(|pair| {
            pair.trim()
                .split_once('=')
                .is_some_and(|(cookie_name, _)| cookie_name == name)
        })
}

pub(crate) fn login_binding_matches(headers: &HeaderMap, stored_hash: &str) -> bool {
    completion::matches(presented(headers, LOGIN_COOKIE), stored_hash)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, header};
    use axum::response::Response;

    use super::{
        LOGIN_COOKIE, SESSION_COOKIE, clear_login_binding, clear_session, issue_login_binding,
        login_binding_matches, presented, session_cookie,
    };

    fn jar(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(header::COOKIE, HeaderValue::from_str(line).unwrap());
        }
        headers
    }

    #[test]
    fn the_cookies_carry_exactly_the_agreed_attributes() {
        assert_eq!(
            session_cookie("abc").unwrap().to_str().unwrap(),
            "__Host-jaunt=abc; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
        );
        let binding = issue_login_binding().unwrap();
        let text = binding.set_cookie.to_str().unwrap();
        let (pair, attributes) = text.split_once("; ").unwrap();
        assert_eq!(
            attributes,
            "Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
        );
        let secret = pair.strip_prefix("__Host-jaunt-web-login=").unwrap();
        assert_eq!(secret.len(), 43);
        assert_eq!(binding.hash.len(), 64);
        assert!(!binding.hash.contains(secret));
    }

    #[test]
    fn clearing_repeats_the_attributes_with_a_zero_lifetime() {
        let mut response = Response::new(Body::empty());
        clear_session(&mut response);
        clear_login_binding(&mut response);
        let cleared: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            cleared,
            [
                "__Host-jaunt=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                "__Host-jaunt-web-login=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
            ]
        );
    }

    #[test]
    fn a_cookie_is_read_by_exact_name_and_only_when_it_appears_once() {
        let single = jar(&["a=b; __Host-jaunt=one ;c=d"]);
        assert_eq!(presented(&single, SESSION_COOKIE), Some("one"));
        assert_eq!(presented(&single, LOGIN_COOKIE), None);
        let split = jar(&["a=b", "__Host-jaunt=two"]);
        assert_eq!(presented(&split, SESSION_COOKIE), Some("two"));
        for duplicated in [
            jar(&["__Host-jaunt=x; __Host-jaunt=y"]),
            jar(&["__Host-jaunt=x", "__Host-jaunt=x"]),
        ] {
            assert_eq!(presented(&duplicated, SESSION_COOKIE), None);
        }
        for absent in [
            jar(&[]),
            jar(&["__Host-jaunt-web-login=x"]),
            jar(&["x__Host-jaunt=x"]),
            jar(&["__host-jaunt=x"]),
        ] {
            assert_eq!(presented(&absent, SESSION_COOKIE), None);
        }
    }

    #[test]
    fn only_the_cookie_that_was_issued_matches_the_stored_hash() {
        let binding = issue_login_binding().unwrap();
        let other = issue_login_binding().unwrap();
        let secret = binding
            .set_cookie
            .to_str()
            .unwrap()
            .strip_prefix("__Host-jaunt-web-login=")
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let own = format!("{LOGIN_COOKIE}={secret}");

        assert!(login_binding_matches(&jar(&[&own]), &binding.hash));
        assert!(login_binding_matches(
            &jar(&[&format!("theme=dark; {own}; lang=en")]),
            &binding.hash
        ));
        assert!(!login_binding_matches(&jar(&[&own]), &other.hash));
        for refused in [
            jar(&[]),
            jar(&[&format!("{LOGIN_COOKIE}=")]),
            jar(&[&format!("{LOGIN_COOKIE}={}", &secret[1..])]),
            jar(&[&format!("{own}; {own}")]),
            jar(&[&own, &own]),
            jar(&[&format!("{SESSION_COOKIE}={secret}")]),
        ] {
            assert!(
                !login_binding_matches(&refused, &binding.hash),
                "{refused:?}"
            );
        }
    }
}
