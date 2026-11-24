use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const CHALLENGE_LEN: usize = 43;
const VERIFIER_MIN_LEN: usize = 43;
const VERIFIER_MAX_LEN: usize = 128;

pub(crate) fn is_valid_challenge(value: &str) -> bool {
    value.len() == CHALLENGE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

pub(crate) fn is_valid_verifier(value: &str) -> bool {
    (VERIFIER_MIN_LEN..=VERIFIER_MAX_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}

pub(crate) fn verifier_matches(verifier: &str, challenge: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    computed.as_bytes().ct_eq(challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::{is_valid_challenge, is_valid_verifier, verifier_matches};

    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc_7636_vector_matches() {
        assert!(verifier_matches(RFC_VERIFIER, RFC_CHALLENGE));
        assert!(!verifier_matches("x".repeat(43).as_str(), RFC_CHALLENGE));
        assert!(!verifier_matches(RFC_VERIFIER, &RFC_CHALLENGE[1..]));
    }

    #[test]
    fn challenge_shape_is_exactly_forty_three_url_safe_characters() {
        assert!(is_valid_challenge(RFC_CHALLENGE));
        assert!(!is_valid_challenge(&RFC_CHALLENGE[1..]));
        assert!(!is_valid_challenge(&format!("{RFC_CHALLENGE}A")));
        assert!(!is_valid_challenge(&format!("{}=", &RFC_CHALLENGE[1..])));
        assert!(!is_valid_challenge(&format!("{}+", &RFC_CHALLENGE[1..])));
    }

    #[test]
    fn verifier_shape_is_forty_three_to_one_hundred_twenty_eight_unreserved_characters() {
        assert!(is_valid_verifier(RFC_VERIFIER));
        assert!(is_valid_verifier(&"a".repeat(128)));
        assert!(is_valid_verifier(&format!("{}-._~", "a".repeat(40))));
        assert!(!is_valid_verifier(&"a".repeat(42)));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&format!("{}+", "a".repeat(42))));
        assert!(!is_valid_verifier(&format!("{} ", "a".repeat(42))));
    }
}
