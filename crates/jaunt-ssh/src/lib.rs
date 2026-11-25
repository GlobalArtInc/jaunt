mod cert;
mod config;
mod error;
mod host;
mod inner_ca;
mod intake;
mod limits;
mod outer;
mod proxy;
mod target;
#[cfg(test)]
mod test_support;

mod bridge;
mod forward;
mod inner;
mod observer;
mod output;
mod terminate;

pub use cert::{CertRejection, UserCaKeys, UserCaSource, UserIdentity, verify_user_certificate};
pub use config::{ServerConfigCell, ServerProfile};
pub use error::{HostCertProblem, SshError};
pub use host::{HostIdentity, HostKey, read_pinned_host_key};
pub use inner_ca::InnerCa;
pub use limits::OuterLimits;
pub use outer::{
    AuthDenial, ForwardRefusal, OuterEnd, OuterEndReason, OuterEvent, OuterHop, RouteBackend,
    RouteFuture, RouteRefusal, RouteTarget, RoutedStream, StreamEnd, TunnelStream,
};
pub use proxy::{MAX_PROXY_PAYLOAD, ProxiedAddr, ProxyError, decode_proxy_v2, read_proxy_v2};
pub use target::parse_node_target;

pub use inner::{InnerTarget, OUTPUT_WINDOW};
pub use observer::{
    ChannelExit, ChannelProgram, ChannelStart, ForwardTarget, NoObserver, ObserverFactory,
    OutputStream, Recording, SessionInfo, SessionObserver, Terminal, TerminalSize,
};
pub use terminate::{
    AgentLimits, AuthorityError, EndReason, SessionAuthority, SessionOutcome, StreamContext,
    Terminator,
};
