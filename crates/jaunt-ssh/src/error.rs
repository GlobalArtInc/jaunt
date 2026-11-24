use std::path::PathBuf;

use russh::keys::ssh_key;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("the user CA trust set is empty")]
    EmptyTrustSet,
    #[error("user CA key {index} is not a valid OpenSSH public key")]
    InvalidCaKey {
        index: usize,
        #[source]
        source: ssh_key::Error,
    },
    #[error("user CA key {index} is not an Ed25519 key")]
    CaKeyAlgorithm { index: usize },
    #[error("user CA key {index} repeats an earlier key")]
    DuplicateCaKey { index: usize },
    #[error("cannot read {path}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is larger than {limit} bytes")]
    FileTooLarge { path: PathBuf, limit: usize },
    #[error("{path} is accessible by group or others (mode {mode:o}); allow the owner only")]
    KeyFilePermissions { path: PathBuf, mode: u32 },
    #[error("the host key is not an unencrypted OpenSSH private key")]
    InvalidHostKey,
    #[error("the host key is not an Ed25519 key")]
    HostKeyAlgorithm,
    #[error("the host certificate is not usable: {0}")]
    HostCertificate(HostCertProblem),
    #[error("cannot generate an Ed25519 key")]
    KeyGeneration(#[source] ssh_key::Error),
    #[error("cannot encode a key in OpenSSH format")]
    KeyEncoding(#[source] ssh_key::Error),
    #[error("cannot sign the inner certificate")]
    CertificateSigning(#[source] ssh_key::Error),
    #[error("the login is not a portable POSIX user name")]
    InvalidLogin,
    #[error("the session id or email cannot be placed in a certificate key id")]
    InvalidKeyIdPart,
    #[error("the certificate validity window does not fit in a timestamp")]
    InvalidTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostCertProblem {
    #[error("not an OpenSSH certificate")]
    Malformed,
    #[error("not a host certificate")]
    NotHostCertificate,
    #[error("certified for a different key")]
    KeyMismatch,
    #[error("the signature does not verify")]
    Signature,
    #[error("not valid yet")]
    NotYetValid,
    #[error("expired")]
    Expired,
}
