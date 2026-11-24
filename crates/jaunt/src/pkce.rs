use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use ssh_key::rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::secret::Secret;

const VERIFIER_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the system entropy source failed")]
pub struct EntropyError;

pub struct Pkce {
    verifier: Secret,
    challenge: String,
}

impl Pkce {
    pub fn generate() -> Result<Pkce, EntropyError> {
        let mut bytes = Zeroizing::new([0_u8; VERIFIER_BYTES]);
        OsRng
            .try_fill_bytes(bytes.as_mut())
            .map_err(|_| EntropyError)?;
        Ok(Pkce::from_bytes(&bytes))
    }

    pub fn from_bytes(bytes: &[u8; VERIFIER_BYTES]) -> Pkce {
        let verifier = URL_SAFE_NO_PAD.encode(bytes);
        let challenge = challenge_for(&verifier);
        Pkce {
            verifier: Secret::new(verifier),
            challenge,
        }
    }

    pub fn verifier(&self) -> &Secret {
        &self.verifier
    }

    pub fn challenge(&self) -> &str {
        &self.challenge
    }
}

pub fn challenge_for(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{Pkce, challenge_for};

    const RFC_OCTETS: [u8; 32] = [
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37,
        77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
    ];
    const RFC_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RFC_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    #[test]
    fn rfc_7636_appendix_b_vectors_match() {
        let pkce = Pkce::from_bytes(&RFC_OCTETS);
        assert_eq!(pkce.verifier().expose(), RFC_VERIFIER);
        assert_eq!(pkce.challenge(), RFC_CHALLENGE);
        assert_eq!(challenge_for(RFC_VERIFIER), RFC_CHALLENGE);
    }

    #[test]
    fn generated_pairs_are_forty_three_url_safe_characters_and_differ() {
        let first = Pkce::generate().unwrap();
        let second = Pkce::generate().unwrap();
        for pkce in [&first, &second] {
            for value in [pkce.verifier().expose(), pkce.challenge()] {
                assert_eq!(value.len(), 43);
                assert!(
                    value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
                );
            }
            assert_eq!(challenge_for(pkce.verifier().expose()), pkce.challenge());
        }
        assert_ne!(first.verifier().expose(), second.verifier().expose());
    }
}
