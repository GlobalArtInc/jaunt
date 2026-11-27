mod cert;
mod client_slot;
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
    MAX_USER_VALIDITY, ORIGIN_EXTENSION, UserCertParams, WEB_ORIGIN, is_user_key_id,
    sign_host_certificate, sign_user_certificate, sign_web_user_certificate,
};
pub use client_slot::{ClientInitialized, ClientKeyAdded, ClientSlot, TrustedRoot};
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
    CLIENT_ROOT_VALIDITY, ClientCa, DB_CLIENT_BACKDATE, DB_CLIENT_VALIDITY, DEFAULT_NODE_VALIDITY,
    DEFAULT_SERVER_VALIDITY, DEFAULT_SERVICE_VALIDITY, DbClientParams, InternalCa,
    IssuedCertificate, MAX_NODE_VALIDITY, MAX_SERVER_VALIDITY, MAX_USER_X509_VALIDITY,
    NodeCertParams, NodeIdentity, ROOT_VALIDITY, ServerCertParams, SubjectPublicKey,
    UserX509Params, parse_node_identity,
};
