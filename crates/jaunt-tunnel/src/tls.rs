use std::collections::HashSet;
use std::fmt;
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use rustls::client::{ResolvesClientCert, Resumption};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{
    Acceptor, ClientHello, NoServerSessionStorage, ResolvesServerCert, VerifierBuilderError,
    WantsServerCert, WebPkiClientVerifier,
};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ConfigBuilder, RootCertStore, ServerConfig, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout_at};
use tokio_rustls::LazyConfigAcceptor;
use tokio_rustls::server::TlsStream;

use crate::options::{MAX_HANDSHAKING_LIMIT, OptionsError, timer_in_range};
use crate::proto::{ALPN_AGENT_API, ALPN_TUNNEL};
use crate::stats::GateStats;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_HANDSHAKING: usize = 1024;

#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("tls configuration is invalid")]
    Tls(#[from] rustls::Error),
    #[error("client certificate verifier could not be built")]
    Verifier(#[from] VerifierBuilderError),
}

pub fn agent_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    client_roots: RootCertStore,
) -> Result<ServerConfig, TlsConfigError> {
    let mut config = agent_config_builder(client_roots)?.with_single_cert(cert_chain, key)?;
    finish_agent_config(&mut config);
    Ok(config)
}

pub fn rotating_agent_server_config(
    certificate: Arc<RotatingCertificate>,
    client_roots: RootCertStore,
) -> Result<ServerConfig, TlsConfigError> {
    let mut config = agent_config_builder(client_roots)?.with_cert_resolver(certificate);
    finish_agent_config(&mut config);
    Ok(config)
}

pub fn refusing_server_config() -> Result<ServerConfig, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCertificate));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

fn agent_config_builder(
    client_roots: RootCertStore,
) -> Result<ConfigBuilder<ServerConfig, WantsServerCert>, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), provider.clone())
            .build()?;
    Ok(ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier))
}

fn finish_agent_config(config: &mut ServerConfig) {
    config.alpn_protocols = vec![ALPN_TUNNEL.to_vec(), ALPN_AGENT_API.to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
}

pub struct RotatingCertificate {
    current: RwLock<Arc<CertifiedKey>>,
    provider: Arc<CryptoProvider>,
}

impl RotatingCertificate {
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsConfigError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let certified = CertifiedKey::from_der(cert_chain, key, &provider)?;
        Ok(Self {
            current: RwLock::new(Arc::new(certified)),
            provider,
        })
    }

    pub fn replace(
        &self,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<(), TlsConfigError> {
        let certified = Arc::new(CertifiedKey::from_der(cert_chain, key, &self.provider)?);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = certified;
        Ok(())
    }

    fn current(&self) -> Arc<CertifiedKey> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl fmt::Debug for RotatingCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotatingCertificate")
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for RotatingCertificate {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

#[derive(Debug)]
struct NoCertificate;

impl ResolvesServerCert for NoCertificate {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

pub fn main_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(config)
}

pub fn agent_client_config(
    roots: RootCertStore,
    client_cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert_chain, key)?;
    config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
    config.resumption = Resumption::disabled();
    Ok(config)
}

pub fn agent_client_config_swappable(
    roots: RootCertStore,
    identity: Arc<SwappableClientCert>,
) -> Result<ClientConfig, TlsConfigError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_cert_resolver(identity);
    config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
    config.resumption = Resumption::disabled();
    Ok(config)
}

pub struct SwappableClientCert {
    current: RwLock<Arc<CertifiedKey>>,
}

impl SwappableClientCert {
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, TlsConfigError> {
        Ok(Self {
            current: RwLock::new(certified_key(cert_chain, key)?),
        })
    }

    pub fn replace_certificate(
        &self,
        cert_chain: Vec<CertificateDer<'static>>,
    ) -> Result<(), TlsConfigError> {
        let next = CertifiedKey::new(cert_chain, self.current().key.clone());
        next.keys_match()?;
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(next);
        Ok(())
    }

    pub fn end_entity(&self) -> Option<CertificateDer<'static>> {
        self.current()
            .cert
            .first()
            .map(|cert| cert.clone().into_owned())
    }

    fn current(&self) -> Arc<CertifiedKey> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl fmt::Debug for SwappableClientCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SwappableClientCert")
            .finish_non_exhaustive()
    }
}

impl ResolvesClientCert for SwappableClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn certified_key(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, TlsConfigError> {
    let provider = rustls::crypto::ring::default_provider();
    Ok(Arc::new(CertifiedKey::from_der(
        cert_chain, key, &provider,
    )?))
}

#[derive(Debug, Error)]
pub enum AcceptError {
    #[error("too many connections are handshaking")]
    TooManyHandshakes,
    #[error("handshake timed out")]
    Timeout,
    #[error("client hello could not be read")]
    ClientHello(#[source] io::Error),
    #[error("tls handshake failed")]
    Handshake(#[source] io::Error),
    #[error("no usable application protocol was negotiated")]
    NoApplicationProtocol,
    #[error("client certificate is missing after the handshake")]
    NoPeerCertificate,
}

impl AcceptError {
    pub fn is_missing_peer_certificate(&self) -> bool {
        match self {
            Self::NoPeerCertificate => true,
            Self::Handshake(error) => error
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .is_some_and(|inner| matches!(inner, rustls::Error::NoCertificatesPresented)),
            _ => false,
        }
    }
}

pub struct AcceptorConfig {
    pub agent_names: Vec<String>,
    pub agent: Arc<ServerConfig>,
    pub main: Arc<ServerConfig>,
    pub handshake_timeout: Duration,
    pub max_handshaking: usize,
}

impl AcceptorConfig {
    pub fn new(
        agent_names: Vec<String>,
        agent: Arc<ServerConfig>,
        main: Arc<ServerConfig>,
    ) -> Self {
        Self {
            agent_names,
            agent,
            main,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_handshaking: DEFAULT_MAX_HANDSHAKING,
        }
    }

    pub fn validate(&self) -> Result<(), OptionsError> {
        if !timer_in_range(self.handshake_timeout) {
            return Err(OptionsError::HandshakeTimeout);
        }
        if self.max_handshaking == 0 || self.max_handshaking > MAX_HANDSHAKING_LIMIT {
            return Err(OptionsError::HandshakeLimit);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct HandshakePermit {
    _permit: OwnedSemaphorePermit,
    deadline: Instant,
}

impl HandshakePermit {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}

pub struct PeerStream<IO> {
    pub stream: TlsStream<IO>,
    pub peer_cert: CertificateDer<'static>,
}

pub enum Accepted<IO> {
    Tunnel(PeerStream<IO>),
    AgentApi(PeerStream<IO>),
    Main(TlsStream<IO>),
}

pub struct GateAcceptor {
    agent_names: HashSet<String>,
    agent: Arc<ServerConfig>,
    main: Arc<ServerConfig>,
    handshake_timeout: Duration,
    max_handshaking: usize,
    permits: Arc<Semaphore>,
    stats: Arc<GateStats>,
}

impl GateAcceptor {
    pub fn new(config: AcceptorConfig, stats: Arc<GateStats>) -> Result<Self, OptionsError> {
        config.validate()?;
        Ok(Self {
            agent_names: config
                .agent_names
                .iter()
                .map(|name| normalize_server_name(name))
                .collect(),
            agent: config.agent,
            main: config.main,
            handshake_timeout: config.handshake_timeout,
            max_handshaking: config.max_handshaking,
            permits: Arc::new(Semaphore::new(config.max_handshaking)),
            stats,
        })
    }

    pub fn stats(&self) -> &Arc<GateStats> {
        &self.stats
    }

    pub fn handshake_timeout(&self) -> Duration {
        self.handshake_timeout
    }

    pub fn handshaking(&self) -> usize {
        self.max_handshaking
            .saturating_sub(self.permits.available_permits())
    }

    pub async fn accept<IO>(&self, io: IO) -> Result<(Accepted<IO>, HandshakePermit), AcceptError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            self.stats.record_refused_busy();
            return Err(AcceptError::TooManyHandshakes);
        };
        let deadline = Instant::now() + self.handshake_timeout;
        match self.handshake(io, deadline).await {
            Ok(accepted) => Ok((
                accepted,
                HandshakePermit {
                    _permit: permit,
                    deadline,
                },
            )),
            Err(error) => {
                match &error {
                    AcceptError::Timeout => self.stats.record_handshake_timeout(),
                    AcceptError::NoApplicationProtocol => {
                        self.stats.record_no_application_protocol();
                    }
                    _ => self.stats.record_handshake_failure(),
                }
                Err(error)
            }
        }
    }

    async fn handshake<IO>(&self, io: IO, deadline: Instant) -> Result<Accepted<IO>, AcceptError>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let start = timeout_at(deadline, LazyConfigAcceptor::new(Acceptor::default(), io))
            .await
            .map_err(|_| AcceptError::Timeout)?
            .map_err(AcceptError::ClientHello)?;
        let for_agents = start
            .client_hello()
            .server_name()
            .is_some_and(|name| self.agent_names.contains(&normalize_server_name(name)));
        let config = if for_agents {
            self.agent.clone()
        } else {
            self.main.clone()
        };
        let stream = timeout_at(deadline, start.into_stream(config))
            .await
            .map_err(|_| AcceptError::Timeout)?
            .map_err(AcceptError::Handshake)?;
        if !for_agents {
            return Ok(Accepted::Main(stream));
        }
        let (_, connection) = stream.get_ref();
        let peer_cert = connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .cloned()
            .ok_or(AcceptError::NoPeerCertificate)?;
        let protocol = connection.alpn_protocol().map(<[u8]>::to_vec);
        match protocol.as_deref() {
            Some(selected) if selected == ALPN_TUNNEL => {
                Ok(Accepted::Tunnel(PeerStream { stream, peer_cert }))
            }
            Some(selected) if selected == ALPN_AGENT_API => {
                Ok(Accepted::AgentApi(PeerStream { stream, peer_cert }))
            }
            _ => {
                let mut stream = stream;
                drop(timeout_at(deadline, stream.shutdown()).await);
                Err(AcceptError::NoApplicationProtocol)
            }
        }
    }
}

fn normalize_server_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    use super::*;

    fn certificate_for(key: &rcgen::KeyPair, name: &str) -> CertificateDer<'static> {
        rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(key)
            .unwrap()
            .der()
            .clone()
    }

    #[test]
    fn a_swappable_identity_keeps_its_key_and_refuses_a_certificate_for_another_key() {
        let key = rcgen::KeyPair::generate().unwrap();
        let first = certificate_for(&key, "first.test");
        let identity = SwappableClientCert::new(
            vec![first.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
        let resolved = identity.resolve(&[], &[]).unwrap();
        assert_eq!(resolved.cert, std::slice::from_ref(&first));
        assert!(identity.has_certs());

        let unrelated = certificate_for(&rcgen::KeyPair::generate().unwrap(), "other.test");
        assert!(identity.replace_certificate(vec![unrelated]).is_err());
        assert_eq!(identity.end_entity(), Some(first));

        let second = certificate_for(&key, "second.test");
        identity.replace_certificate(vec![second.clone()]).unwrap();
        assert_eq!(identity.end_entity(), Some(second));
        assert_eq!(format!("{identity:?}"), "SwappableClientCert { .. }");
    }

    #[test]
    fn server_names_compare_case_insensitively_without_trailing_dot() {
        assert_eq!(
            normalize_server_name("Agents.Example.COM."),
            "agents.example.com"
        );
        assert_eq!(
            normalize_server_name("agents.example.com"),
            "agents.example.com"
        );
    }
}
