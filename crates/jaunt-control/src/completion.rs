use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;

use crate::token::{EntropyUnavailable, hash_secret};

const SECRET_BYTES: usize = 32;
const ENCODED_LEN: usize = 43;

pub(crate) struct IssuedCode {
    pub(crate) secret: String,
    pub(crate) hash: String,
}

pub(crate) fn issue() -> Result<IssuedCode, EntropyUnavailable> {
    let mut bytes = [0_u8; SECRET_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| EntropyUnavailable)?;
    let secret = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_secret(&secret);
    Ok(IssuedCode { secret, hash })
}

fn is_well_formed(value: &str) -> bool {
    value.len() == ENCODED_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn matches(presented: Option<&str>, stored_hash: &str) -> bool {
    let Some(presented) = presented.filter(|value| is_well_formed(value)) else {
        return false;
    };
    hash_secret(presented)
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::{issue, matches};

    #[test]
    fn issued_code_is_forty_three_url_safe_characters_and_only_its_hash_is_kept() {
        let first = issue().unwrap();
        let second = issue().unwrap();
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.secret.len(), 43);
        assert!(
            first
                .secret
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        assert_eq!(first.hash.len(), 64);
        assert!(first.hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.secret.contains(&first.hash));
    }

    #[test]
    fn only_the_exact_issued_code_matches_its_hash() {
        let code = issue().unwrap();
        let other = issue().unwrap();
        assert!(matches(Some(&code.secret), &code.hash));
        assert!(!matches(Some(&other.secret), &code.hash));
        assert!(!matches(None, &code.hash));
        assert!(!matches(Some(""), &code.hash));
        assert!(!matches(Some(&code.secret[1..]), &code.hash));
        assert!(!matches(Some(&format!("{}A", code.secret)), &code.hash));
        assert!(!matches(Some(&code.secret), ""));
        assert!(!matches(Some(&code.secret), &other.hash));
        assert!(!matches(Some(&code.hash), &code.hash));
    }
}
