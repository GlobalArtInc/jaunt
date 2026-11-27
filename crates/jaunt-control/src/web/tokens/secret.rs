use std::fmt;

use axum::http::{HeaderMap, header};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};
use jaunt_proto::{ADMIN_TOKEN_ID_BYTES, ADMIN_TOKEN_PREFIX, ADMIN_TOKEN_SECRET_BYTES};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::token::{EntropyUnavailable, hash_secret};

const BEARER: &str = "Bearer";
const REDACTED: &str = "TokenText([redacted])";

pub(crate) struct TokenText(Zeroizing<String>);

impl TokenText {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TokenText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

pub(crate) struct IssuedAdminToken {
    pub(crate) id: String,
    pub(crate) text: TokenText,
    pub(crate) hash: String,
}

pub(crate) fn issue() -> Result<IssuedAdminToken, EntropyUnavailable> {
    let mut id_bytes = [0_u8; ADMIN_TOKEN_ID_BYTES];
    let mut secret_bytes = Zeroizing::new([0_u8; ADMIN_TOKEN_SECRET_BYTES]);
    OsRng
        .try_fill_bytes(&mut id_bytes)
        .and_then(|()| OsRng.try_fill_bytes(secret_bytes.as_mut_slice()))
        .map_err(|_| EntropyUnavailable)?;
    let id = URL_SAFE_NO_PAD.encode(id_bytes);
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(secret_bytes.as_slice()));
    let text = Zeroizing::new(format!("{ADMIN_TOKEN_PREFIX}{id}_{}", encoded.as_str()));
    let hash = hash_secret(&text);
    Ok(IssuedAdminToken {
        id,
        text: TokenText(text),
        hash,
    })
}

pub(crate) fn secret_matches(presented: &str, stored_hash: &str) -> bool {
    hash_secret(presented)
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into()
}

pub(crate) fn presents_token(headers: &HeaderMap) -> bool {
    headers.get_all(header::AUTHORIZATION).iter().any(|value| {
        let bytes = value.as_bytes();
        let scheme = bytes.get(..BEARER.len());
        let after = bytes.get(BEARER.len());
        scheme.is_some_and(|scheme| scheme.eq_ignore_ascii_case(BEARER.as_bytes()))
            && after.is_none_or(|byte| *byte == b' ')
    })
}

pub(crate) fn presented(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().ok()?,
        _ => return None,
    };
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case(BEARER).then_some(token)
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use jaunt_proto::admin_token_id;

    use super::{issue, presented, presents_token, secret_matches};
    use crate::token::hash_secret;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn an_issued_token_has_the_public_id_inside_and_only_its_hash_is_kept() {
        let first = issue().unwrap();
        let second = issue().unwrap();
        assert!(!format!("{:?}", second.text).contains("jat_"));
        let text = first.text.expose().to_owned();
        assert_ne!(text, second.text.expose());
        assert_ne!(first.id, second.id);
        assert_eq!(admin_token_id(&text), Some(first.id.as_str()));
        assert_eq!(first.hash, hash_secret(&text));
        assert_eq!(first.hash.len(), 64);
        assert!(!text.contains(&first.hash));
    }

    #[test]
    fn only_the_whole_issued_text_matches_its_hash() {
        let issued = issue().unwrap();
        let hash = issued.hash.clone();
        let text = issued.text.expose().to_owned();
        let other = issue().unwrap();
        let other_text = other.text.expose().to_owned();
        let foreign_secret = format!("{}{}", &text[..16], &other_text[16..]);
        assert!(secret_matches(&text, &hash));
        for wrong in [
            other_text.as_str(),
            foreign_secret.as_str(),
            &text[..text.len() - 1],
            &format!("{text}A"),
            "",
            hash.as_str(),
        ] {
            assert!(!secret_matches(wrong, &hash), "{wrong:?}");
        }
        assert!(!secret_matches(&text, ""));
        assert!(!secret_matches(&text, &other.hash));
    }

    #[test]
    fn a_bearer_header_is_recognised_and_read_only_when_it_is_the_single_one() {
        for (values, presents, read) in [
            (vec!["Bearer jat_x"], true, Some("jat_x")),
            (vec!["bearer jat_x"], true, Some("jat_x")),
            (vec!["BEARER  jat_x"], true, Some(" jat_x")),
            (vec!["Bearer"], true, None),
            (vec!["Bearer jat_x", "Bearer jat_y"], true, None),
            (vec!["Basic dXNlcjpwYXNz", "Bearer jat_x"], true, None),
            (vec!["Basic dXNlcjpwYXNz"], false, None),
            (vec!["Bearerjat_x"], false, None),
            (vec![], false, None),
        ] {
            let map = headers(&values);
            assert_eq!(presents_token(&map), presents, "{values:?}");
            assert_eq!(presented(&map), read, "{values:?}");
        }
    }
}
