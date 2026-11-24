use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::completion;

const TOKEN_HEADER: HeaderName = HeaderName::from_static("x-jaunt-csrf");
const FETCH_SITE_HEADER: HeaderName = HeaderName::from_static("sec-fetch-site");
const SAME_ORIGIN: &[u8] = b"same-origin";
const TOKEN_DOMAIN: &[u8] = b"jaunt-web-csrf-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    Origin,
    Token,
}

impl Refusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Refusal::Origin => "origin",
            Refusal::Token => "csrf",
        }
    }
}

pub(crate) fn is_state_changing(method: &Method) -> bool {
    method != Method::GET && method != Method::HEAD
}

pub(crate) fn token_for(session_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(TOKEN_DOMAIN);
    hasher.update(session_secret.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub(crate) fn verify(
    headers: &HeaderMap,
    stored_token_hash: &str,
    public_origin: &str,
) -> Result<(), Refusal> {
    if !origin_allowed(headers, public_origin) {
        return Err(Refusal::Origin);
    }
    let presented = match single(headers, &TOKEN_HEADER) {
        Single::One(value) => value.to_str().ok(),
        Single::Absent | Single::Many => None,
    };
    if completion::matches(presented, stored_token_hash) {
        Ok(())
    } else {
        Err(Refusal::Token)
    }
}

fn origin_allowed(headers: &HeaderMap, public_origin: &str) -> bool {
    match single(headers, &header::ORIGIN) {
        Single::One(value) => value.as_bytes() == public_origin.as_bytes(),
        Single::Absent => matches!(
            single(headers, &FETCH_SITE_HEADER),
            Single::One(value) if value.as_bytes() == SAME_ORIGIN
        ),
        Single::Many => false,
    }
}

enum Single<'a> {
    Absent,
    One(&'a HeaderValue),
    Many,
}

fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Single<'a> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (None, _) => Single::Absent,
        (Some(value), None) => Single::One(value),
        (Some(_), Some(_)) => Single::Many,
    }
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use sha2::{Digest, Sha256};

    use crate::token::hash_secret;

    use super::{Refusal, is_state_changing, token_for, verify};

    const ORIGIN: &str = "https://jaunt.example";

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn only_get_and_head_are_safe_methods() {
        for (method, changing) in [
            (Method::GET, false),
            (Method::HEAD, false),
            (Method::POST, true),
            (Method::PUT, true),
            (Method::PATCH, true),
            (Method::DELETE, true),
            (Method::OPTIONS, true),
            (Method::TRACE, true),
        ] {
            assert_eq!(is_state_changing(&method), changing, "{method}");
        }
    }

    #[test]
    fn the_token_is_derived_per_session_and_has_the_shape_of_a_random_one() {
        let first = token_for("session-secret-one");
        assert_eq!(first, token_for("session-secret-one"));
        assert_ne!(first, token_for("session-secret-two"));
        assert_ne!(first, "session-secret-one");
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn the_token_is_domain_separated_from_plain_hashes_of_the_session_secret() {
        let secret = "session-secret-one";
        let token = token_for(secret);
        let plain = URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()));
        let id_hash = hash_secret(secret);

        assert_ne!(token, plain);
        assert_ne!(token, id_hash);
        assert_ne!(token, token_for(&id_hash));
        assert_ne!(
            token,
            URL_SAFE_NO_PAD.encode(Sha256::digest(id_hash.as_bytes()))
        );
        assert_ne!(hash_secret(&token), id_hash);
    }

    #[test]
    fn the_origin_must_match_exactly_or_be_absent_with_a_same_origin_fetch() {
        let token = token_for("secret");
        let stored = hash_secret(&token);
        let with = |extra: &[(&'static str, &str)]| {
            let mut pairs = vec![("x-jaunt-csrf", token.as_str())];
            pairs.extend_from_slice(extra);
            verify(&headers(&pairs), &stored, ORIGIN)
        };

        assert_eq!(with(&[("origin", ORIGIN)]), Ok(()));
        assert_eq!(with(&[("sec-fetch-site", "same-origin")]), Ok(()));
        assert_eq!(
            with(&[("origin", ORIGIN), ("sec-fetch-site", "cross-site")]),
            Ok(())
        );
        for refused in [
            vec![],
            vec![("origin", "https://evil.example")],
            vec![("origin", "null")],
            vec![("origin", "")],
            vec![("origin", "http://jaunt.example")],
            vec![("origin", "https://jaunt.example:8443")],
            vec![("origin", ORIGIN), ("origin", ORIGIN)],
            vec![("sec-fetch-site", "cross-site")],
            vec![("sec-fetch-site", "same-site")],
            vec![("sec-fetch-site", "none")],
            vec![
                ("sec-fetch-site", "same-origin"),
                ("sec-fetch-site", "same-origin"),
            ],
            vec![("origin", "null"), ("sec-fetch-site", "same-origin")],
        ] {
            assert_eq!(with(&refused), Err(Refusal::Origin), "{refused:?}");
        }
    }

    #[test]
    fn the_token_must_be_present_once_and_equal_to_the_stored_one() {
        let token = token_for("secret");
        let stored = hash_secret(&token);
        let other = token_for("another");
        let good = [("origin", ORIGIN)];

        let attempt = |extra: &[(&'static str, &str)]| {
            let mut pairs = good.to_vec();
            pairs.extend_from_slice(extra);
            verify(&headers(&pairs), &stored, ORIGIN)
        };

        assert_eq!(attempt(&[("x-jaunt-csrf", &token)]), Ok(()));
        for refused in [
            vec![],
            vec![("x-jaunt-csrf", other.as_str())],
            vec![("x-jaunt-csrf", "")],
            vec![("x-jaunt-csrf", &token[1..])],
            vec![
                ("x-jaunt-csrf", token.as_str()),
                ("x-jaunt-csrf", token.as_str()),
            ],
        ] {
            assert_eq!(attempt(&refused), Err(Refusal::Token), "{refused:?}");
        }
        assert_eq!(Refusal::Origin.code(), "origin");
        assert_eq!(Refusal::Token.code(), "csrf");
    }
}
