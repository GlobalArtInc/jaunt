use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::Response;

use crate::completion;

pub(crate) const COOKIE_NAME: &str = "__Host-jaunt-device";

const CLEARED_COOKIE: &str =
    "__Host-jaunt-device=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";

pub(crate) struct Binding {
    pub(crate) set_cookie: HeaderValue,
    pub(crate) hash: String,
}

pub(crate) fn issue() -> Option<Binding> {
    let issued = completion::issue().ok()?;
    let set_cookie = HeaderValue::try_from(format!(
        "{COOKIE_NAME}={}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300",
        issued.secret
    ))
    .ok()?;
    Some(Binding {
        set_cookie,
        hash: issued.hash,
    })
}

pub(crate) fn clear(response: &mut Response) {
    response
        .headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_static(CLEARED_COOKIE));
}

pub(crate) fn matches(headers: &HeaderMap, stored_hash: &str) -> bool {
    let mut presented: Option<&str> = None;
    for line in headers.get_all(header::COOKIE) {
        let Ok(text) = line.to_str() else {
            continue;
        };
        for pair in text.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name != COOKIE_NAME {
                continue;
            }
            if presented.is_some() {
                return false;
            }
            presented = Some(value);
        }
    }
    completion::matches(presented, stored_hash)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, header};
    use axum::response::Response;

    use super::{COOKIE_NAME, clear, issue, matches};

    fn cookie_headers(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(header::COOKIE, HeaderValue::from_str(line).unwrap());
        }
        headers
    }

    fn secret_of(set_cookie: &HeaderValue) -> String {
        let text = set_cookie.to_str().unwrap();
        text.strip_prefix(&format!("{COOKIE_NAME}="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn the_cookie_has_exactly_the_agreed_attributes_and_only_its_hash_is_kept() {
        let binding = issue().unwrap();
        let secret = secret_of(&binding.set_cookie);

        assert_eq!(secret.len(), 43);
        assert_eq!(
            binding.set_cookie.to_str().unwrap(),
            format!(
                "__Host-jaunt-device={secret}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"
            )
        );
        assert_eq!(binding.hash.len(), 64);
        assert!(!binding.hash.contains(&secret));
        assert_ne!(secret_of(&issue().unwrap().set_cookie), secret);
    }

    #[test]
    fn clearing_repeats_the_attributes_with_a_zero_lifetime() {
        let mut response = Response::new(Body::empty());

        clear(&mut response);

        let cleared: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert_eq!(
            cleared,
            ["__Host-jaunt-device=; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"]
        );
    }

    #[test]
    fn only_the_one_cookie_that_was_issued_matches() {
        let binding = issue().unwrap();
        let other = issue().unwrap();
        let secret = secret_of(&binding.set_cookie);
        let other_secret = secret_of(&other.set_cookie);
        let own = format!("{COOKIE_NAME}={secret}");

        assert!(matches(&cookie_headers(&[&own]), &binding.hash));
        assert!(matches(
            &cookie_headers(&[&format!("a=b; {own}; c=d")]),
            &binding.hash
        ));
        assert!(matches(&cookie_headers(&["a=b", &own]), &binding.hash));
        assert!(matches(
            &cookie_headers(&[&format!("{own} ;x=1")]),
            &binding.hash
        ));

        let refused = [
            cookie_headers(&[]),
            cookie_headers(&["a=b"]),
            cookie_headers(&[&format!("{COOKIE_NAME}={other_secret}")]),
            cookie_headers(&[&format!("{COOKIE_NAME}=")]),
            cookie_headers(&[&format!("{COOKIE_NAME}={}", &secret[1..])]),
            cookie_headers(&[&format!("{}={secret}", COOKIE_NAME.to_lowercase())]),
            cookie_headers(&[&format!("x{COOKIE_NAME}={secret}")]),
            cookie_headers(&[&format!("{own}; {COOKIE_NAME}={other_secret}")]),
            cookie_headers(&[&own, &format!("{COOKIE_NAME}={other_secret}")]),
            cookie_headers(&[&format!("{own}; {own}")]),
        ];
        for headers in refused {
            assert!(!matches(&headers, &binding.hash), "{headers:?}");
        }
        assert!(!matches(&cookie_headers(&[&own]), &other.hash));
    }
}
