use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::iter;
use std::path::{Path, PathBuf};

use age::secrecy::ExposeSecret;
use age::x25519;
use age::{Decryptor, Encryptor};
use zeroize::Zeroizing;

use crate::error::CaError;
use crate::fsutil::{ensure_private_dir, read_limited, write_new};

pub const IDENTITY_VAR: &str = "JAUNT_CA_KEY";
pub const IDENTITY_FILE_VAR: &str = "JAUNT_CA_KEY_FILE";

const MAX_IDENTITY_FILE_LEN: u64 = 4096;

pub type AgeRecipient = x25519::Recipient;

pub struct AgeIdentity(x25519::Identity);

impl AgeIdentity {
    pub fn generate() -> Self {
        Self(x25519::Identity::generate())
    }

    pub fn parse(secret: &str) -> Result<Self, CaError> {
        secret
            .trim()
            .parse::<x25519::Identity>()
            .map(Self)
            .map_err(|_| CaError::IdentityInvalid)
    }

    pub fn from_env() -> Result<Self, CaError> {
        Self::from_sources(
            std::env::var_os(IDENTITY_VAR),
            std::env::var_os(IDENTITY_FILE_VAR),
        )
    }

    pub fn read_file(path: &Path) -> Result<Self, CaError> {
        let bytes = read_limited(path, MAX_IDENTITY_FILE_LEN)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CaError::IdentityInvalid)?;
        let mut keys = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'));
        match (keys.next(), keys.next()) {
            (Some(key), None) => Self::parse(key),
            _ => Err(CaError::IdentityInvalid),
        }
    }

    pub fn write_new_file(&self, path: &Path) -> Result<(), CaError> {
        let secret = self.0.to_string();
        let recipient = self.recipient().to_string();
        let mut contents = Zeroizing::new(String::with_capacity(
            recipient.len() + secret.expose_secret().len() + 32,
        ));
        contents.push_str("# public key: ");
        contents.push_str(&recipient);
        contents.push('\n');
        contents.push_str(secret.expose_secret());
        contents.push('\n');

        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            ensure_private_dir(parent, false).map_err(CaError::io("create directory", parent))?;
        }
        write_new(path, contents.as_bytes()).map_err(CaError::io("write", path))
    }

    pub fn recipient(&self) -> AgeRecipient {
        self.0.to_public()
    }

    pub fn from_sources(
        key: Option<OsString>,
        key_file: Option<OsString>,
    ) -> Result<Self, CaError> {
        match (key, key_file) {
            (Some(_), Some(_)) => Err(CaError::IdentityConflict),
            (None, None) => Err(CaError::IdentityMissing),
            (Some(key), None) => {
                let key = Zeroizing::new(key.into_string().map_err(|_| CaError::IdentityInvalid)?);
                Self::parse(&key)
            }
            (None, Some(path)) => Self::read_file(&PathBuf::from(path)),
        }
    }

    pub(crate) fn decrypt(
        &self,
        ciphertext: &[u8],
        max_plaintext: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CaError> {
        let decryptor = Decryptor::new_buffered(ciphertext).map_err(|_| CaError::Decrypt)?;
        let mut reader = decryptor
            .decrypt(iter::once(&self.0 as &dyn age::Identity))
            .map_err(|_| CaError::Decrypt)?;
        let limit = u64::try_from(max_plaintext)
            .map_err(|_| CaError::Decrypt)?
            .saturating_add(1);
        let mut plaintext = Zeroizing::new(Vec::with_capacity(max_plaintext.saturating_add(1)));
        (&mut reader)
            .take(limit)
            .read_to_end(&mut plaintext)
            .map_err(|_| CaError::Decrypt)?;
        if plaintext.len() > max_plaintext {
            return Err(CaError::Decrypt);
        }
        Ok(plaintext)
    }
}

pub(crate) fn encrypt(recipient: &AgeRecipient, plaintext: &[u8]) -> Result<Vec<u8>, CaError> {
    let encryptor = Encryptor::with_recipients(iter::once(recipient as &dyn age::Recipient))
        .map_err(|_| CaError::Encrypt)?;
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|_| CaError::Encrypt)?;
    writer.write_all(plaintext).map_err(|_| CaError::Encrypt)?;
    writer.finish().map_err(|_| CaError::Encrypt)?;
    Ok(ciphertext)
}

impl fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgeIdentity").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::AgeIdentity;
    use crate::error::CaError;

    #[test]
    fn debug_hides_the_secret() {
        let identity = AgeIdentity::generate();
        let secret = {
            use age::secrecy::ExposeSecret;
            identity.0.to_string().expose_secret().to_owned()
        };
        let printed = format!("{identity:?} {identity:#?}");
        assert!(!printed.to_uppercase().contains("AGE-SECRET-KEY"));
        assert!(!printed.contains(&secret));
        assert!(
            !printed
                .to_lowercase()
                .contains(&secret[16..].to_lowercase())
        );
    }

    #[test]
    fn exactly_one_source_is_required() {
        let secret = {
            use age::secrecy::ExposeSecret;
            AgeIdentity::generate()
                .0
                .to_string()
                .expose_secret()
                .to_owned()
        };
        let key = || Some(OsString::from(&secret));
        let file = || Some(OsString::from("/nonexistent/jaunt-identity"));
        assert!(matches!(
            AgeIdentity::from_sources(key(), file()),
            Err(CaError::IdentityConflict)
        ));
        assert!(matches!(
            AgeIdentity::from_sources(None, None),
            Err(CaError::IdentityMissing)
        ));
        assert!(AgeIdentity::from_sources(key(), None).is_ok());
        assert!(matches!(
            AgeIdentity::from_sources(Some(OsString::from("not-a-key")), None),
            Err(CaError::IdentityInvalid)
        ));
    }

    #[test]
    fn identity_file_round_trips_and_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.txt");
        let identity = AgeIdentity::generate();
        identity.write_new_file(&path).unwrap();
        let read = AgeIdentity::read_file(&path).unwrap();
        assert_eq!(read.recipient(), identity.recipient());
        assert!(AgeIdentity::generate().write_new_file(&path).is_err());
        let read_again = AgeIdentity::from_sources(None, Some(path.into_os_string())).unwrap();
        assert_eq!(read_again.recipient(), identity.recipient());
    }
}
