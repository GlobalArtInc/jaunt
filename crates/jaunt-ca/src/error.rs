use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::kind::CaKind;

#[derive(Debug)]
pub enum CaError {
    InvalidValidity {
        max: Duration,
    },
    InvalidEmail,
    InvalidUserId,
    InvalidHostnames,
    WrongAuthorityKind {
        expected: CaKind,
    },
    InvalidTime,
    UnsupportedKeyAlgorithm,
    SshKey(ssh_key::Error),
    Sign,
    DuplicateTrustedKey,
    ActiveKeyNotTrusted,
    AlreadyInitialized(CaKind),
    NotInitialized(CaKind),
    CorruptStore {
        path: PathBuf,
        reason: &'static str,
    },
    Encrypt,
    Decrypt,
    IdentityConflict,
    IdentityMissing,
    IdentityInvalid,
    Io {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl CaError {
    pub(crate) fn io(op: &'static str, path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> Self {
        let path = path.into();
        move |source| CaError::Io { op, path, source }
    }
}

impl fmt::Display for CaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaError::InvalidValidity { max } => write!(
                f,
                "validity must be at least one second and at most {} seconds",
                max.as_secs()
            ),
            CaError::InvalidEmail => f.write_str(
                "email must be 1 to 254 printable ASCII characters without ':' and '\"'",
            ),
            CaError::InvalidUserId => f.write_str("the user id must not be the nil UUID"),
            CaError::WrongAuthorityKind { expected } => write!(
                f,
                "this certificate type must be signed by the {expected} certificate authority"
            ),
            CaError::InvalidHostnames => {
                f.write_str("hostnames must be 1 to 64 distinct exact names of at most 253 bytes without whitespace, control or pattern characters")
            }
            CaError::InvalidTime => f.write_str("certificate time is out of range"),
            CaError::UnsupportedKeyAlgorithm => {
                f.write_str("certificate authority keys must be Ed25519")
            }
            CaError::SshKey(err) => write!(f, "ssh key error: {err}"),
            CaError::Sign => f.write_str("signing failed"),
            CaError::DuplicateTrustedKey => f.write_str("trust set contains a duplicate key"),
            CaError::ActiveKeyNotTrusted => f.write_str("active key is not in the trust set"),
            CaError::AlreadyInitialized(kind) => {
                write!(f, "the {kind} certificate authority is already initialized")
            }
            CaError::NotInitialized(kind) => {
                write!(f, "the {kind} certificate authority is not initialized")
            }
            CaError::CorruptStore { path, reason } => {
                write!(f, "{}: {reason}", path.display())
            }
            CaError::Encrypt => f.write_str("could not encrypt the key"),
            CaError::Decrypt => f.write_str("could not decrypt the key with this identity"),
            CaError::IdentityConflict => {
                f.write_str("set exactly one of JAUNT_CA_KEY and JAUNT_CA_KEY_FILE, not both")
            }
            CaError::IdentityMissing => {
                f.write_str("set one of JAUNT_CA_KEY and JAUNT_CA_KEY_FILE")
            }
            CaError::IdentityInvalid => f.write_str("the age identity is not valid"),
            CaError::Io { op, path, source } => {
                write!(f, "{op} {}: {source}", path.display())
            }
        }
    }
}

impl Error for CaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CaError::SshKey(err) => Some(err),
            CaError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
