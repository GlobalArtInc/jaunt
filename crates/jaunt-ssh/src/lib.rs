mod cert;
mod config;
mod error;
mod host;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the terminator issues inner certificates from S17a on"
    )
)]
mod inner_ca;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the outer hop and the terminator drive the intake from S16a and S17a on"
    )
)]
mod intake;
mod proxy;
mod target;
#[cfg(test)]
mod test_support;

pub use cert::{CertRejection, UserCaKeys, UserCaSource, UserIdentity, verify_user_certificate};
pub use config::{ServerConfigCell, ServerProfile};
pub use error::{HostCertProblem, SshError};
pub use host::{HostIdentity, HostKey};
pub use inner_ca::InnerCa;
pub use proxy::{MAX_PROXY_PAYLOAD, ProxiedAddr, ProxyError, decode_proxy_v2, read_proxy_v2};
pub use target::parse_node_target;
