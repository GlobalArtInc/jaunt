use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};

use crate::token::{EntropyUnavailable, hash_secret};

pub(crate) const PREFIX: &str = "jt1.";
const SECRET_BYTES: usize = 32;
const ENCODED_LEN: usize = 43;

pub(crate) struct IssuedJoinToken {
    pub(crate) secret: String,
    pub(crate) hash: String,
}

pub(crate) fn issue() -> Result<IssuedJoinToken, EntropyUnavailable> {
    let mut bytes = [0_u8; SECRET_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| EntropyUnavailable)?;
    let secret = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    bytes.fill(0);
    let hash = hash_secret(&secret);
    Ok(IssuedJoinToken { secret, hash })
}

pub(crate) fn hash_presented(presented: &str) -> Option<String> {
    let encoded = presented.strip_prefix(PREFIX)?;
    let well_formed = encoded.len() == ENCODED_LEN
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    well_formed.then(|| hash_secret(presented))
}

#[cfg(test)]
mod tests {
    use super::{hash_presented, issue};
    use crate::token::hash_secret;

    #[test]
    fn a_join_token_is_the_prefix_and_forty_three_url_safe_characters_and_only_its_hash_is_kept() {
        let first = issue().unwrap();
        let second = issue().unwrap();
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.secret.len(), 47);
        assert!(first.secret.starts_with("jt1."));
        assert_eq!(first.hash, hash_secret(&first.secret));
        assert_eq!(first.hash.len(), 64);
        assert!(!first.secret.contains(&first.hash));
        assert_eq!(hash_presented(&first.secret), Some(first.hash));
    }

    #[test]
    fn malformed_presented_tokens_are_not_hashed() {
        let valid = issue().unwrap().secret;
        let encoded = &valid[4..];
        for presented in [
            String::new(),
            "jt1.".to_owned(),
            format!("jt_{encoded}"),
            format!("jt2.{encoded}"),
            encoded.to_owned(),
            valid[..46].to_owned(),
            format!("{valid}A"),
            format!("{valid}="),
            format!("jt1.{}+", &encoded[..42]),
            format!("jt1.{}/", &encoded[..42]),
            format!(" {valid}"),
            format!("jt1.{}\u{e9}", &encoded[..41]),
        ] {
            assert_eq!(hash_presented(&presented), None, "{presented:?}");
        }
    }
}
