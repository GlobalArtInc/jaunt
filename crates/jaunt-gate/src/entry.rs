mod hello;
mod names;
mod refusal;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use jaunt_limits::{
    AddressGate, AddressLimits, AddressLimitsError, ClientKey, ConcurrencyGuard, TrustedProxies,
    TrustedProxyProblem,
};
use jaunt_ssh::read_proxy_v2;
pub use jaunt_tunnel::Replay;
use jaunt_tunnel::{BoxFuture, DEFAULT_MAX_HANDSHAKING, MAX_HANDSHAKING_LIMIT, MAX_TIMER};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;

pub use hello::{
    CapturedHello, HelloError, HelloInfo, MAX_CLIENT_HELLO_BYTES, capture_client_hello,
    parse_client_hello,
};
pub use names::{EntryNames, EntryNamesError, SniClass};
pub use refusal::TlsRefusal;

use crate::ssh::DEFAULT_PROXY_HEADER_TIMEOUT;
use refusal::Refusals;

pub const ALPN_SSH: &[u8] = b"jaunt-ssh/1";
pub const ALPN_SVC: &[u8] = b"jaunt-svc/1";
pub const DEFAULT_ENTRY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub trait EntryIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> EntryIo for T {}

pub type EntryStream = Replay<Box<dyn EntryIo>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateProtocol {
    Ssh,
    Svc,
}

impl GateProtocol {
    const PREFERENCE: [Self; 2] = [Self::Ssh, Self::Svc];

    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Ssh => ALPN_SSH,
            Self::Svc => ALPN_SVC,
        }
    }

    fn chosen(hello: &HelloInfo) -> Option<Self> {
        Self::PREFERENCE
            .into_iter()
            .find(|protocol| match protocol {
                Self::Ssh => hello.offers_ssh(),
                Self::Svc => hello.offers_svc(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryClass {
    Agents,
    Main,
    Gate(GateProtocol),
    Kube(String),
}

#[derive(Debug, Clone)]
pub struct Route {
    pub class: EntryClass,
    pub hello: HelloInfo,
    pub client_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub proxied: bool,
    pub handshake_deadline: Instant,
}

pub struct HandshakeSlot {
    _permit: OwnedSemaphorePermit,
    _address: Option<ConcurrencyGuard<ClientKey>>,
}

pub struct Admitted<IO> {
    pub route: Route,
    pub stream: Replay<IO>,
    pub handshake: HandshakeSlot,
    pub stream_slot: Option<ConcurrencyGuard<ClientKey>>,
}

pub struct ClassConnection<IO> {
    pub route: Route,
    pub stream: Replay<IO>,
    pub stream_slot: Option<ConcurrencyGuard<ClientKey>>,
}

pub trait ClassHandler: Send + Sync {
    fn serve(
        &self,
        connection: ClassConnection<Box<dyn EntryIo>>,
        shutdown: CancellationToken,
    ) -> BoxFuture<'static, ()>;
}

#[derive(Clone, Default)]
pub struct ClassHandlers {
    pub gate: Option<Arc<dyn ClassHandler>>,
    pub kube: Option<Arc<dyn ClassHandler>>,
}

pub struct TlsEntryConfig {
    pub agent_names: Vec<String>,
    pub domain: Option<String>,
    pub proxy_protocol: bool,
    pub trusted_proxies: Vec<IpNet>,
    pub proxy_header_timeout: Duration,
    pub handshake_timeout: Duration,
    pub max_handshaking: usize,
    pub front_limits: AddressLimits,
    pub kube_limits: AddressLimits,
    pub handlers: ClassHandlers,
}

impl TlsEntryConfig {
    pub fn new(
        agent_names: Vec<String>,
        domain: Option<String>,
        front_limits: AddressLimits,
        kube_limits: AddressLimits,
    ) -> Self {
        Self {
            agent_names,
            domain,
            proxy_protocol: false,
            trusted_proxies: Vec::new(),
            proxy_header_timeout: DEFAULT_PROXY_HEADER_TIMEOUT,
            handshake_timeout: DEFAULT_ENTRY_HANDSHAKE_TIMEOUT,
            max_handshaking: DEFAULT_MAX_HANDSHAKING,
            front_limits,
            kube_limits,
            handlers: ClassHandlers::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TlsEntryError {
    #[error(transparent)]
    Names(#[from] EntryNamesError),
    #[error("the PROXY protocol is on but no trusted proxy is configured")]
    NoTrustedProxies,
    #[error("trusted proxies are configured but the PROXY protocol is off")]
    TrustedProxiesWithoutProxyProtocol,
    #[error("trusted proxy network {index}: {problem}")]
    TrustedProxy {
        index: usize,
        problem: TrustedProxyProblem,
    },
    #[error("the PROXY header and handshake timeouts must be longer than zero and at most a day")]
    Timeout,
    #[error("max_handshaking must be between 1 and {MAX_HANDSHAKING_LIMIT}")]
    HandshakeLimit,
    #[error("the per address limits are invalid: {0}")]
    ClientLimits(#[from] AddressLimitsError),
}

#[derive(Debug, Clone, Copy)]
struct Origin {
    client: SocketAddr,
    proxied: bool,
    local: bool,
}

pub struct TlsEntry {
    names: EntryNames,
    proxies: Option<TrustedProxies>,
    proxy_header_timeout: Duration,
    handshake_timeout: Duration,
    max_handshaking: usize,
    handshakes: Arc<Semaphore>,
    front: AddressGate,
    kube: AddressGate,
    handlers: ClassHandlers,
    refusals: Refusals,
    started: Instant,
}

impl TlsEntry {
    pub fn new(config: TlsEntryConfig) -> Result<Self, TlsEntryError> {
        let names = EntryNames::new(&config.agent_names, config.domain.as_deref())?;
        let proxies = trusted_proxies(config.proxy_protocol, config.trusted_proxies)?;
        if !timer_in_range(config.proxy_header_timeout) || !timer_in_range(config.handshake_timeout)
        {
            return Err(TlsEntryError::Timeout);
        }
        if !(1..=MAX_HANDSHAKING_LIMIT).contains(&config.max_handshaking) {
            return Err(TlsEntryError::HandshakeLimit);
        }
        config.front_limits.validate()?;
        config.kube_limits.validate()?;
        Ok(Self {
            names,
            proxies,
            proxy_header_timeout: config.proxy_header_timeout,
            handshake_timeout: config.handshake_timeout,
            max_handshaking: config.max_handshaking,
            handshakes: Arc::new(Semaphore::new(config.max_handshaking)),
            front: AddressGate::new(config.front_limits),
            kube: AddressGate::new(config.kube_limits),
            handlers: config.handlers,
            refusals: Refusals::new(),
            started: Instant::now(),
        })
    }

    pub fn names(&self) -> &EntryNames {
        &self.names
    }

    pub fn refused(&self, reason: TlsRefusal) -> u64 {
        self.refusals.count(reason)
    }

    pub fn handshaking(&self) -> usize {
        self.max_handshaking
            .saturating_sub(self.handshakes.available_permits())
    }

    pub async fn admit<IO>(&self, mut io: IO, peer: SocketAddr) -> Result<Admitted<IO>, TlsRefusal>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        if self
            .proxies
            .as_ref()
            .is_some_and(|proxies| !proxies.contains(peer.ip()))
        {
            return Err(self.refuse(TlsRefusal::ProxyUntrusted, peer));
        }
        let Ok(permit) = Arc::clone(&self.handshakes).try_acquire_owned() else {
            return Err(self.refuse(TlsRefusal::Limit, peer));
        };
        let origin = match self.origin(&mut io, peer).await {
            Ok(origin) => origin,
            Err(reason) => return Err(self.refuse(reason, peer)),
        };
        let handshake = HandshakeSlot {
            _permit: permit,
            _address: self.hold(&self.front, origin)?,
        };
        let handshake_deadline = Instant::now() + self.handshake_timeout;
        let (bytes, hello) = match capture_client_hello(&mut io, handshake_deadline).await {
            Ok(captured) => captured.into_parts(),
            Err(error) => return Err(self.refuse(error.into(), origin.client)),
        };
        let class = self
            .class_of(&hello)
            .map_err(|reason| self.refuse(reason, origin.client))?;
        let stream_slot = match class {
            EntryClass::Kube(_) => self.hold(&self.kube, origin)?,
            EntryClass::Agents | EntryClass::Main | EntryClass::Gate(_) => None,
        };
        Ok(Admitted {
            route: Route {
                class,
                hello,
                client_addr: origin.client,
                peer_addr: peer,
                proxied: origin.proxied,
                handshake_deadline,
            },
            stream: Replay::new(bytes, io),
            handshake,
            stream_slot,
        })
    }

    pub async fn serve_class<IO>(
        &self,
        admitted: Admitted<IO>,
        shutdown: CancellationToken,
    ) -> Option<Admitted<IO>>
    where
        IO: EntryIo + 'static,
    {
        let handler = match &admitted.route.class {
            EntryClass::Agents | EntryClass::Main => return Some(admitted),
            EntryClass::Gate(_) => self.handlers.gate.clone(),
            EntryClass::Kube(_) => self.handlers.kube.clone(),
        };
        let Some(handler) = handler else {
            self.refuse(TlsRefusal::UnsupportedClass, admitted.route.client_addr);
            return None;
        };
        let Admitted {
            route,
            stream,
            handshake,
            stream_slot,
        } = admitted;
        drop(handshake);
        let connection = ClassConnection {
            route,
            stream: stream.map(|io| Box::new(io) as Box<dyn EntryIo>),
            stream_slot,
        };
        handler.serve(connection, shutdown).await;
        None
    }

    async fn origin<IO>(&self, io: &mut IO, peer: SocketAddr) -> Result<Origin, TlsRefusal>
    where
        IO: AsyncRead + Unpin,
    {
        if self.proxies.is_none() {
            return Ok(Origin {
                client: peer,
                proxied: false,
                local: false,
            });
        }
        match timeout(self.proxy_header_timeout, read_proxy_v2(io)).await {
            Ok(Ok(header)) if header.local => Ok(Origin {
                client: peer,
                proxied: false,
                local: true,
            }),
            Ok(Ok(header)) => Ok(Origin {
                client: header.client,
                proxied: true,
                local: false,
            }),
            Ok(Err(_)) => Err(TlsRefusal::ProxyMalformed),
            Err(_) => Err(TlsRefusal::ProxyTimeout),
        }
    }

    fn hold(
        &self,
        gate: &AddressGate,
        origin: Origin,
    ) -> Result<Option<ConcurrencyGuard<ClientKey>>, TlsRefusal> {
        if origin.local {
            return Ok(None);
        }
        gate.admit(origin.client.ip(), self.started.elapsed())
            .map(Some)
            .map_err(|_| self.refuse(TlsRefusal::Limit, origin.client))
    }

    fn class_of(&self, hello: &HelloInfo) -> Result<EntryClass, TlsRefusal> {
        let services = self.names.domain().is_some();
        match self.names.classify(hello.server_name()) {
            SniClass::Agents => Ok(EntryClass::Agents),
            SniClass::Gate => GateProtocol::chosen(hello)
                .map(EntryClass::Gate)
                .ok_or(TlsRefusal::AlpnUnsupported),
            SniClass::Kube(cluster) => Ok(EntryClass::Kube(cluster)),
            SniClass::Missing if services => Err(TlsRefusal::NoSni),
            SniClass::Unknown if services => Err(TlsRefusal::UnknownSni),
            SniClass::Missing | SniClass::Unknown => Ok(EntryClass::Main),
        }
    }

    fn refuse(&self, reason: TlsRefusal, client: SocketAddr) -> TlsRefusal {
        self.refusals.record(reason, client);
        reason
    }
}

fn trusted_proxies(
    proxy_protocol: bool,
    networks: Vec<IpNet>,
) -> Result<Option<TrustedProxies>, TlsEntryError> {
    let proxies =
        TrustedProxies::new(networks).map_err(|unusable| TlsEntryError::TrustedProxy {
            index: unusable.index,
            problem: unusable.problem,
        })?;
    match (proxy_protocol, proxies.is_empty()) {
        (false, true) => Ok(None),
        (false, false) => Err(TlsEntryError::TrustedProxiesWithoutProxyProtocol),
        (true, true) => Err(TlsEntryError::NoTrustedProxies),
        (true, false) => Ok(Some(proxies)),
    }
}

fn timer_in_range(value: Duration) -> bool {
    !value.is_zero() && value <= MAX_TIMER
}
