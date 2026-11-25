mod cert;
mod error;
mod file;
mod fsutil;
mod identity;
mod kind;
mod rotation;
mod signer;
mod staging;
mod trust;
mod x509;

#[cfg(test)]
mod test_support;

pub use ssh_key;
pub use uuid::{self, Uuid};

pub use cert::{
    BACKDATE, DEFAULT_HOST_VALIDITY, DEFAULT_USER_VALIDITY, HostCertParams, MAX_HOST_VALIDITY,
    MAX_USER_VALIDITY, UserCertParams, sign_host_certificate, sign_user_certificate,
};
pub use error::CaError;
pub use file::{FileBackend, SlotListing};
pub use fsutil::fingerprint_hex;
pub use identity::{AgeIdentity, AgeRecipient, IDENTITY_FILE_VAR, IDENTITY_VAR};
pub use kind::CaKind;
pub use rotation::{CaLock, Promoted};
pub use signer::Signer;
pub use staging::{Committed, StagingDir};
pub use trust::{KeyRole, TrustSet};
pub use x509::{
    DEFAULT_NODE_VALIDITY, DEFAULT_SERVER_VALIDITY, InternalCa, IssuedCertificate,
    MAX_NODE_VALIDITY, MAX_SERVER_VALIDITY, NodeCertParams, NodeIdentity, ROOT_VALIDITY,
    ServerCertParams, SubjectPublicKey, parse_node_identity,
};
