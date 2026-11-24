use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use ipnet::IpNet;
use jaunt_limits::{
    AddressGate, AddressLimits, AddressLimitsError, ClientKey, ConcurrencyGuard, DEFAULT_CAPACITY,
    LogThrottle, Rate, TrustedProxies, TrustedProxyProblem,
};
use jaunt_proto::ControlPlane;
use jaunt_ssh::{OuterEvent, OuterHop, OuterLimits, RouteBackend, UserCaSource, read_proxy_v2};
use jaunt_tunnel::AgentRegistry;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::host_cert::{Clock, HostCertError, HostCertIssuer, HostCertificate};
use crate::route::{ControlRoute, DEFAULT_MAX_STREAMS_PER_USER_NODE, StreamBook};

pub const DEFAULT_MAX_UNAUTHENTICATED: usize = 512;
pub const MAX_UNAUTHENTICATED_LIMIT: usize = 1 << 20;
pub const MAX_HOSTNAMES: usize = 64;
pub const DEFAULT_PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_SSH_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
pub const DEFAULT_RENEWAL_CHECK: Duration = Duration::from_secs(60);
pub const DEFAULT_RENEWAL_RETRY: Duration = Duration::from_secs(5);
pub const DEFAULT_SSH_CLIENT_LIMITS: AddressLimits = AddressLimits {
    rate: Rate::clamped(600, 600),
    concurrent: 128,
    tracked: DEFAULT_CAPACITY,
};
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(10);
const MAX_LABEL_LEN: usize = 63;
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_SUFFIX_LEN: usize = MAX_DNS_NAME_LEN - MAX_LABEL_LEN - 1;

#[derive(Debug, Clone)]
pub struct SshGateConfig {
    pub hostnames: Vec<String>,
    pub ssh_suffix: String,
    pub proxy_protocol: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub max_unauthenticated: usize,
    pub client_limits: AddressLimits,
    pub max_streams_per_user_node: usize,
    pub limits: OuterLimits,
    pub proxy_header_timeout: Duration,
    pub shutdown_grace: Duration,
    pub renewal_check: Duration,
    pub renewal_retry: Duration,
}

impl SshGateConfig {
    pub fn new(hostnames: Vec<String>, ssh_suffix: impl Into<String>) -> Self {
        Self {
            hostnames,
            ssh_suffix: ssh_suffix.into(),
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
            max_unauthenticated: DEFAULT_MAX_UNAUTHENTICATED,
            client_limits: DEFAULT_SSH_CLIENT_LIMITS,
            max_streams_per_user_node: DEFAULT_MAX_STREAMS_PER_USER_NODE,
            limits: OuterLimits::default(),
            proxy_header_timeout: DEFAULT_PROXY_HEADER_TIMEOUT,
            shutdown_grace: DEFAULT_SSH_SHUTDOWN_GRACE,
            renewal_check: DEFAULT_RENEWAL_CHECK,
            renewal_retry: DEFAULT_RENEWAL_RETRY,
        }
    }
}

#[derive(Debug, Error)]
pub enum SshGateError {
    #[error("the gate needs at least one host name")]
    NoHostnames,
    #[error("gate host name {0:?} is not a dns name")]
    InvalidHostname(String),
    #[error("gate host name {0:?} is listed twice")]
    DuplicateHostname(String),
    #[error("the ssh suffix is not a dns name")]
    InvalidSuffix,
    #[error("the gate takes at most {MAX_HOSTNAMES} host names")]
    TooManyHostnames,
    #[error("the PROXY protocol is on but no trusted proxy is configured")]
    NoTrustedProxies,
    #[error("trusted proxies are configured but the PROXY protocol is off")]
    TrustedProxiesWithoutProxyProtocol,
    #[error("trusted proxy network {index}: {problem}")]
    TrustedProxy {
        index: usize,
        problem: TrustedProxyProblem,
    },
    #[error("max_unauthenticated must be between 1 and {MAX_UNAUTHENTICATED_LIMIT}")]
    UnauthenticatedLimit,
    #[error("the per address limits are invalid: {0}")]
    ClientLimits(#[from] AddressLimitsError),
    #[error("the per user and node stream limit must be at least one")]
    StreamLimit,
    #[error("the renewal check and retry intervals must not be zero")]
    RenewalInterval,
    #[error(transparent)]
    HostCertificate(#[from] HostCertError),
    #[error("no tokio runtime is running")]
    NoRuntime,
}

fn check_trusted_proxies(
    proxy_protocol: bool,
    proxies: Vec<IpNet>,
) -> Result<Option<TrustedProxies>, SshGateError> {
    let proxies = TrustedProxies::new(proxies).map_err(|unusable| SshGateError::TrustedProxy {
        index: unusable.index,
        problem: unusable.problem,
    })?;
    match (proxy_protocol, proxies.is_empty()) {
        (false, true) => Ok(None),
        (false, false) => Err(SshGateError::TrustedProxiesWithoutProxyProtocol),
        (true, true) => Err(SshGateError::NoTrustedProxies),
        (true, false) => Ok(Some(proxies)),
    }
}

pub fn normalize_dns_name(name: &str) -> Option<String> {
    normalize(name, MAX_DNS_NAME_LEN)
}

fn normalize(name: &str, max_len: usize) -> Option<String> {
    let lowered = name.to_ascii_lowercase();
    let bare = lowered.strip_suffix('.').unwrap_or(&lowered);
    let valid = bare.len() <= max_len && bare.split('.').all(is_dns_label);
    valid.then(|| bare.to_owned())
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    bytes.len() <= MAX_LABEL_LEN
        && edge(*first)
        && edge(*last)
        && bytes.iter().all(|byte| edge(*byte) || *byte == b'-')
}

fn hostnames(given: &[String]) -> Result<Vec<String>, SshGateError> {
    if given.is_empty() {
        return Err(SshGateError::NoHostnames);
    }
    if given.len() > MAX_HOSTNAMES {
        return Err(SshGateError::TooManyHostnames);
    }
    let mut seen = HashSet::new();
    let mut names = Vec::with_capacity(given.len());
    for name in given {
        let normalized =
            normalize_dns_name(name).ok_or_else(|| SshGateError::InvalidHostname(name.clone()))?;
        if !seen.insert(normalized.clone()) {
            return Err(SshGateError::DuplicateHostname(normalized));
        }
        names.push(normalized);
    }
    Ok(names)
}

struct Shared {
    host: HostCertificate,
    cas: Arc<UserCaSource>,
    suffix: String,
    trusted_proxies: Option<TrustedProxies>,
    limits: OuterLimits,
    proxy_header_timeout: Duration,
    shutdown_grace: Duration,
    renewal_check: Duration,
    renewal_retry: Duration,
    backend: Arc<ControlRoute>,
    book: Arc<StreamBook>,
    pre_auth: Arc<Semaphore>,
    max_unauthenticated: usize,
    clients: AddressGate,
    refusals: LogThrottle,
    started: Instant,
}

pub struct SshGate {
    shared: Arc<Shared>,
}

impl SshGate {
    pub async fn new(
        config: SshGateConfig,
        issuer: Arc<dyn HostCertIssuer>,
        cas: Arc<UserCaSource>,
        control: Arc<dyn ControlPlane>,
        registry: AgentRegistry,
    ) -> Result<Self, SshGateError> {
        Self::new_with_clock(
            config,
            issuer,
            cas,
            control,
            registry,
            Arc::new(SystemTime::now),
        )
        .await
    }

    pub async fn new_with_clock(
        config: SshGateConfig,
        issuer: Arc<dyn HostCertIssuer>,
        cas: Arc<UserCaSource>,
        control: Arc<dyn ControlPlane>,
        registry: AgentRegistry,
        clock: Clock,
    ) -> Result<Self, SshGateError> {
        let names = hostnames(&config.hostnames)?;
        let suffix =
            normalize(&config.ssh_suffix, MAX_SUFFIX_LEN).ok_or(SshGateError::InvalidSuffix)?;
        if !(1..=MAX_UNAUTHENTICATED_LIMIT).contains(&config.max_unauthenticated) {
            return Err(SshGateError::UnauthenticatedLimit);
        }
        config.client_limits.validate()?;
        if config.max_streams_per_user_node == 0 {
            return Err(SshGateError::StreamLimit);
        }
        if config.renewal_check.is_zero() || config.renewal_retry.is_zero() {
            return Err(SshGateError::RenewalInterval);
        }
        let trusted_proxies = check_trusted_proxies(config.proxy_protocol, config.trusted_proxies)?;
        if let Some(proxies) = &trusted_proxies {
            tracing::info!(
                target: "jaunt::gate",
                networks = proxies.len(),
                "the ssh gate reads PROXY headers from trusted proxy networks"
            );
        }
        let host = HostCertificate::obtain(issuer, names, clock).await?;
        let book = StreamBook::new(config.max_streams_per_user_node);
        let backend = Arc::new(ControlRoute::new(control, registry, Arc::clone(&book)));
        Ok(Self {
            shared: Arc::new(Shared {
                host,
                cas,
                suffix,
                trusted_proxies,
                limits: config.limits,
                proxy_header_timeout: config.proxy_header_timeout,
                shutdown_grace: config.shutdown_grace,
                renewal_check: config.renewal_check,
                renewal_retry: config.renewal_retry,
                backend,
                book,
                pre_auth: Arc::new(Semaphore::new(config.max_unauthenticated)),
                max_unauthenticated: config.max_unauthenticated,
                clients: AddressGate::new(config.client_limits),
                refusals: LogThrottle::new(REFUSAL_LOG_INTERVAL),
                started: Instant::now(),
            }),
        })
    }

    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: CancellationToken,
    ) -> Result<(), SshGateError> {
        Handle::try_current().map_err(|_| SshGateError::NoRuntime)?;
        let shared = &self.shared;
        let renewal =
            shared
                .host
                .renew_forever(shared.renewal_check, shared.renewal_retry, shutdown.clone());
        tokio::join!(renewal, accept(Arc::clone(shared), listener, &shutdown));
        Ok(())
    }

    pub async fn reissue_host_certificate(&self) -> Result<(), SshGateError> {
        Ok(self.shared.host.reissue().await?)
    }

    pub fn open_streams(&self) -> usize {
        self.shared.book.total()
    }

    pub fn unauthenticated(&self) -> usize {
        self.shared
            .max_unauthenticated
            .saturating_sub(self.shared.pre_auth.available_permits())
    }
}

async fn accept(shared: Arc<Shared>, listener: TcpListener, shutdown: &CancellationToken) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            Some(finished) = connections.join_next() => {
                if finished.is_err_and(|error| error.is_panic()) {
                    tracing::error!(target: "jaunt::gate", "an ssh connection task panicked");
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((tcp, peer)) => {
                    let connection = Arc::clone(&shared).connection(tcp, peer, shutdown.child_token());
                    connections.spawn(connection);
                }
                Err(error) => {
                    tracing::warn!(target: "jaunt::gate", error = %error, "accepting an ssh connection failed");
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(ACCEPT_ERROR_PAUSE) => {}
                    }
                }
            },
        }
    }
    drop(listener);
    let drained = tokio::time::timeout(shared.shutdown_grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            target: "jaunt::gate",
            remaining = connections.len(),
            "ssh connections did not finish within the shutdown grace"
        );
        connections.shutdown().await;
    }
}

impl Shared {
    fn trusts(&self, peer: SocketAddr) -> bool {
        self.trusted_proxies
            .as_ref()
            .is_none_or(|proxies| proxies.contains(peer.ip()))
    }

    fn admit_client(&self, client: IpAddr) -> Option<ConcurrencyGuard<ClientKey>> {
        let now = self.started.elapsed();
        match self.clients.admit(client, now) {
            Ok(guard) => Some(guard),
            Err(refused) => {
                if let Some(suppressed) = self.refusals.admit(now) {
                    audit::ssh_limited(ClientKey::of(client), refused, suppressed);
                }
                None
            }
        }
    }

    async fn client_addr(
        &self,
        tcp: &mut TcpStream,
        peer: SocketAddr,
        token: &CancellationToken,
    ) -> Option<Client> {
        if self.trusted_proxies.is_none() {
            return Some(Client::Direct(peer));
        }
        let header = tokio::select! {
            biased;
            () = token.cancelled() => return None,
            header = tokio::time::timeout(self.proxy_header_timeout, read_proxy_v2(tcp)) => header,
        };
        match header {
            Ok(Ok(proxied)) if proxied.local => Some(Client::ProxyLocal(peer)),
            Ok(Ok(proxied)) => Some(Client::Proxied(proxied.client_or(peer))),
            Ok(Err(error)) => {
                tracing::debug!(target: "jaunt::gate", peer_addr = %peer, error = %error, "a PROXY header was refused");
                None
            }
            Err(_) => {
                tracing::debug!(target: "jaunt::gate", peer_addr = %peer, "no PROXY header arrived in time");
                None
            }
        }
    }

    async fn connection(
        self: Arc<Self>,
        mut tcp: TcpStream,
        peer: SocketAddr,
        token: CancellationToken,
    ) {
        if let Err(error) = tcp.set_nodelay(true) {
            tracing::debug!(target: "jaunt::gate", peer_addr = %peer, error = %error, "an ssh connection could not be tuned");
            return;
        }
        if !self.trusts(peer) {
            tracing::debug!(target: "jaunt::gate", peer_addr = %peer, "a connection from an untrusted proxy was closed");
            return;
        }
        let Ok(permit) = Arc::clone(&self.pre_auth).try_acquire_owned() else {
            tracing::debug!(target: "jaunt::gate", peer_addr = %peer, "too many unauthenticated ssh connections");
            return;
        };
        let Some(client) = self.client_addr(&mut tcp, peer, &token).await else {
            return;
        };
        let (client, proxied, slot) = match client {
            Client::ProxyLocal(addr) => (addr, false, None),
            Client::Direct(addr) | Client::Proxied(addr) => {
                let Some(guard) = self.admit_client(addr.ip()) else {
                    return;
                };
                (addr, matches!(client, Client::Proxied(_)), Some(guard))
            }
        };
        audit::ssh_connected(client, peer, proxied);
        let slot = Arc::new(Mutex::new(slot));
        let release = Arc::clone(&slot);
        let backend: Arc<dyn RouteBackend> = self.backend.clone();
        let hop = OuterHop::new(
            self.host.cell(),
            Arc::clone(&self.cas),
            self.suffix.clone(),
            self.limits,
            backend,
        )
        .with_events(move |event| {
            if matches!(event, OuterEvent::AuthAccepted { .. }) {
                take_slot(&release);
            }
            audit::ssh_event(client, event);
        });
        hop.serve(tcp, client, permit, token).await;
        take_slot(&slot);
    }
}

#[derive(Debug, Clone, Copy)]
enum Client {
    Direct(SocketAddr),
    Proxied(SocketAddr),
    ProxyLocal(SocketAddr),
}

fn take_slot(slot: &Mutex<Option<ConcurrencyGuard<ClientKey>>>) {
    drop(slot.lock().unwrap_or_else(PoisonError::into_inner).take());
}

#[cfg(test)]
mod tests {
    use ipnet::IpNet;

    use super::{
        MAX_SUFFIX_LEN, SshGateError, TrustedProxyProblem, check_trusted_proxies, hostnames,
        normalize, normalize_dns_name,
    };

    fn nets(given: &[&str]) -> Vec<IpNet> {
        given.iter().map(|net| net.parse().unwrap()).collect()
    }

    #[test]
    fn the_proxy_protocol_and_the_trusted_networks_go_together() {
        assert!(matches!(check_trusted_proxies(false, Vec::new()), Ok(None)));
        assert!(matches!(
            check_trusted_proxies(true, nets(&["10.0.0.0/8"])),
            Ok(Some(proxies)) if proxies.len() == 1
        ));
        assert!(matches!(
            check_trusted_proxies(false, nets(&["10.0.0.0/8"])),
            Err(SshGateError::TrustedProxiesWithoutProxyProtocol)
        ));
        assert!(matches!(
            check_trusted_proxies(true, Vec::new()),
            Err(SshGateError::NoTrustedProxies)
        ));
        assert!(matches!(
            check_trusted_proxies(true, nets(&["10.0.0.0/8", "::/0"])),
            Err(SshGateError::TrustedProxy {
                index: 1,
                problem: TrustedProxyProblem::Everything
            })
        ));
    }

    #[test]
    fn dns_names_are_lowercased_and_lose_one_trailing_dot() {
        let long_label = "a".repeat(63);
        let too_long_label = "a".repeat(64);
        let long_name = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        let too_long_name = format!("{long_name}e");
        for (given, expected) in [
            ("gate.example.com", Some("gate.example.com")),
            ("Gate.Example.COM.", Some("gate.example.com")),
            (long_label.as_str(), Some(long_label.as_str())),
            (long_name.as_str(), Some(long_name.as_str())),
            (too_long_name.as_str(), None),
            (too_long_label.as_str(), None),
            ("gate.example.com..", None),
            ("", None),
            (".", None),
            ("-gate.example.com", None),
            ("gate_1.example.com", None),
            ("*.example.com", None),
            ("gate example.com", None),
            ("gate.example.com:22", None),
            ("10.0.0.1", Some("10.0.0.1")),
        ] {
            assert_eq!(normalize_dns_name(given).as_deref(), expected, "{given:?}");
        }
        let suffix = format!("{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(61));
        assert_eq!(suffix.len(), MAX_SUFFIX_LEN);
        assert!(normalize(&suffix, MAX_SUFFIX_LEN).is_some());
        assert!(normalize(&format!("{suffix}d"), MAX_SUFFIX_LEN).is_none());
    }

    #[test]
    fn host_names_must_be_present_valid_and_distinct() {
        let names = |given: &[&str]| -> Vec<String> {
            given.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(
            hostnames(&names(&["gate.example.com", "Gate2.Example.com."])).unwrap(),
            ["gate.example.com", "gate2.example.com"]
        );
        assert!(matches!(hostnames(&[]), Err(SshGateError::NoHostnames)));
        let many: Vec<String> = (0..65)
            .map(|index| format!("g{index}.example.com"))
            .collect();
        assert_eq!(hostnames(&many[..64]).unwrap().len(), 64);
        assert!(matches!(
            hostnames(&many),
            Err(SshGateError::TooManyHostnames)
        ));
        assert!(matches!(
            hostnames(&names(&["gate.example.com", "GATE.example.com"])),
            Err(SshGateError::DuplicateHostname(name)) if name == "gate.example.com"
        ));
        assert!(matches!(
            hostnames(&names(&["bad name"])),
            Err(SshGateError::InvalidHostname(name)) if name == "bad name"
        ));
    }
}
