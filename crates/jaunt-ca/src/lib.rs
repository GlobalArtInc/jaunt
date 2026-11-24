mod cert;
mod error;
mod file;
mod fsutil;
mod identity;
mod kind;
mod signer;
mod staging;
mod trust;

#[cfg(test)]
mod test_support;

pub use ssh_key;
pub use uuid::{self, Uuid};

pub use cert::{
    BACKDATE, DEFAULT_HOST_VALIDITY, DEFAULT_USER_VALIDITY, HostCertParams, MAX_HOST_VALIDITY,
    MAX_USER_VALIDITY, UserCertParams, sign_host_certificate, sign_user_certificate,
};
pub use error::CaError;
pub use file::FileBackend;
pub use identity::{AgeIdentity, AgeRecipient, IDENTITY_FILE_VAR, IDENTITY_VAR};
pub use kind::CaKind;
pub use signer::Signer;
pub use staging::{Committed, StagingDir};
pub use trust::TrustSet;
