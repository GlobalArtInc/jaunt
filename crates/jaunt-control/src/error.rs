use jaunt_ca::CaError;
use jaunt_limits::UnusableProxy;
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
    #[error(
        "the public origin must be written as a browser sends it: lowercase host and no default port"
    )]
    NonCanonicalPublicOrigin,
    #[error("the client address header is not a valid http header name")]
    InvalidClientIpHeader,
    #[error(
        "the client address header is set but no trusted proxy network is: the header would be \
         believed from anybody"
    )]
    ClientIpHeaderWithoutTrustedProxies,
    #[error("trusted proxy networks are set but no client address header is")]
    TrustedProxiesWithoutClientIpHeader,
    #[error(transparent)]
    UnusableTrustedProxy(UnusableProxy),
    #[error("the host signing authority is not a host certificate authority")]
    NotHostAuthority,
    #[error("the host signing authority is not the active key of the host trust set")]
    HostAuthorityNotTrusted,
    #[error("the host authority keys cannot be listed: {0}")]
    HostKeys(#[source] CaError),
    #[error("the user signing authority is not the active key of the user trust set")]
    UserAuthorityNotTrusted,
    #[error("the user authority keys cannot be listed: {0}")]
    UserKeys(#[source] CaError),
    #[error("the clock is before the unix epoch")]
    Clock,
    #[error("purging stored login requests failed: {0}")]
    Purge(#[source] StoreError),
    #[error("recovering interrupted deliveries failed: {0}")]
    RecoverDeliveries(#[source] StoreError),
    #[error("purging stored enrollments failed: {0}")]
    PurgeEnrollments(#[source] StoreError),
    #[error("purging expired join tokens failed: {0}")]
    PurgeJoinTokens(#[source] StoreError),
    #[error("purging stale sessions failed: {0}")]
    PurgeSessions(#[source] StoreError),
    #[error("purging expired web sessions failed: {0}")]
    PurgeWebSessions(#[source] StoreError),
    #[error("closing ended sessions failed: {0}")]
    Sessions(#[source] StoreError),
    #[error("every recording limit must be positive")]
    RecordingLimits,
    #[error("recovering the recordings interrupted by the last stop failed: {0}")]
    RecoverRecordings(#[source] StoreError),
}
