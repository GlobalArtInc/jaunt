use std::fmt;

use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::public::KeyData;
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use crate::profile::ProfileName;
use crate::secret::Secret;

const SEED_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("cannot generate a key: the system entropy source failed")]
    Entropy,
    #[error("cannot encode the generated key")]
    Encode,
}

pub struct SessionKey {
    private: PrivateKey,
    public_line: String,
}

impl SessionKey {
    pub fn generate(profile: &ProfileName) -> Result<SessionKey, KeyError> {
        let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
        OsRng
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| KeyError::Entropy)?;
        SessionKey::from_seed(&seed, profile)
    }

    pub fn from_seed(
        seed: &[u8; SEED_BYTES],
        profile: &ProfileName,
    ) -> Result<SessionKey, KeyError> {
        let keypair = Ed25519Keypair::from_seed(seed);
        let private = PrivateKey::new(KeypairData::Ed25519(keypair), format!("jaunt:{profile}"))
            .map_err(|_| KeyError::Encode)?;
        let public_line = PublicKey::from(private.public_key().key_data().clone())
            .to_openssh()
            .map_err(|_| KeyError::Encode)?;
        Ok(SessionKey {
            private,
            public_line,
        })
    }

    pub fn public_line(&self) -> &str {
        &self.public_line
    }

    pub fn key_data(&self) -> &KeyData {
        self.private.public_key().key_data()
    }

    pub fn private_openssh(&self) -> Result<Secret, KeyError> {
        let pem = self
            .private
            .to_openssh(LineEnding::LF)
            .map_err(|_| KeyError::Encode)?;
        Ok(Secret::new(pem))
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKey")
            .field("public", &self.public_line)
            .field("private", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use ssh_key::PrivateKey;

    use super::SessionKey;
    use crate::profile::ProfileName;

    #[test]
    fn generated_key_is_ed25519_with_a_comment_free_public_line_and_a_redacted_debug() {
        let profile = ProfileName::default_name();
        let first = SessionKey::generate(&profile).unwrap();
        let second = SessionKey::generate(&profile).unwrap();
        assert!(first.public_line().starts_with("ssh-ed25519 "));
        assert_eq!(first.public_line().split(' ').count(), 2);
        assert_ne!(first.public_line(), second.public_line());

        let pem = first.private_openssh().unwrap();
        assert!(
            pem.expose()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );
        let parsed = PrivateKey::from_openssh(pem.expose()).unwrap();
        assert_eq!(parsed.public_key().key_data(), first.key_data());
        assert_eq!(parsed.comment(), "jaunt:default");

        let shown = format!("{first:?}");
        assert!(shown.contains("[redacted]"));
        assert!(!shown.contains("PRIVATE KEY"));
    }
}
