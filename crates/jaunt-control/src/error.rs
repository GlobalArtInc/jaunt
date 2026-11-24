use jaunt_ca::CaError;
use jaunt_store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("the signing authority is not a user certificate authority")]
    NotUserAuthority,
    #[error("the certificate lifetime must be at least one second")]
    CertificateTtlTooShort,
    #[error("the pending login capacity must be at least one")]
    NoPendingCapacity,
    #[error("the public origin must be an https origin without a path, query or credentials")]
    InvalidPublicOrigin,
    #[error("the client address header is not a valid http header name")]
    InvalidClientIpHeader,
    #[error("the host authority keys cannot be listed: {0}")]
    HostKeys(#[source] CaError),
    #[error("the http server failed: {0}")]
    Serve(#[source] std::io::Error),
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("purging stored login requests failed: {0}")]
    Purge(#[source] StoreError),
}
