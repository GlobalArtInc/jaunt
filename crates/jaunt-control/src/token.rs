use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jaunt_ca::ssh_key::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

const PREFIX: &str = "jt_";
const SECRET_BYTES: usize = 32;
const ENCODED_LEN: usize = 43;

pub(crate) struct IssuedToken {
    pub(crate) secret: String,
    pub(crate) hash: String,
}

#[derive(Debug)]
pub(crate) struct EntropyUnavailable;

pub(crate) fn issue() -> Result<IssuedToken, EntropyUnavailable> {
    let mut bytes = [0_u8; SECRET_BYTES];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| EntropyUnavailable)?;
    let secret = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hash_secret(&secret);
    Ok(IssuedToken { secret, hash })
}

pub(crate) fn hash_presented(presented: &str) -> Option<String> {
    let encoded = presented.strip_prefix(PREFIX)?;
    let well_formed = encoded.len() == ENCODED_LEN
        && encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    well_formed.then(|| hash_secret(presented))
}

pub(crate) fn hash_secret(secret: &str) -> String {
    hex_digest(secret.as_bytes())
}

pub(crate) fn hex_digest(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest.as_slice() {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{hash_presented, hash_secret, issue};

    #[test]
    fn issued_token_has_the_documented_shape_and_stores_only_its_hash() {
        let first = issue().unwrap();
        let second = issue().unwrap();
        assert_ne!(first.secret, second.secret);
        assert_eq!(first.secret.len(), 46);
        assert!(first.secret.starts_with("jt_"));
        assert_eq!(first.hash.len(), 64);
        assert!(first.hash.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!first.hash.bytes().any(|byte| byte.is_ascii_uppercase()));
        assert!(!first.secret.contains(&first.hash));
        assert_eq!(hash_presented(&first.secret), Some(first.hash));
    }

    #[test]
    fn hash_is_sha256_in_lowercase_hex() {
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn malformed_presented_tokens_are_not_hashed() {
        let valid = issue().unwrap().secret;
        for presented in [
            "",
            "jt_",
            "jt_short",
            &valid[1..],
            &valid[..45],
            &format!("{valid}A"),
            &format!("Jt_{}", &valid[3..]),
            &format!("jt_{}=", &valid[3..45]),
            &format!("jt_{}+", &valid[3..45]),
            &format!("{valid} "),
        ] {
            assert_eq!(hash_presented(presented), None, "{presented}");
        }
    }
}
